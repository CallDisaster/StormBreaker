#include "pch.h"
#include "MiMallocPool.h"
#include <Windows.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cassert>
#include <iostream>
#include "Storm/StormHook.h"
#include "Base/MemorySafety.h"
#include <mimalloc.h>

// MiMallocPool类实现
namespace {
    // mimalloc堆实例
    mi_heap_t* g_mainHeap = nullptr;
    mi_heap_t* g_safeHeap = nullptr;  // 安全操作专用堆

    // 控制标志
    std::atomic<bool> g_inMiMallocOperation{ false };
    std::atomic<bool> g_disableMemoryReleasing{ false };
    std::atomic<bool> g_miMallocDisableMemoryReleasing{ false };

    // 池统计
    std::atomic<size_t> g_totalPoolSize{ 0 };
    std::atomic<size_t> g_usedSize{ 0 };
}

MiMallocPool::MiMallocPool()
    : m_initialized(false)
{
}

MiMallocPool::~MiMallocPool()
{
    Shutdown();
}

bool MiMallocPool::Initialize(size_t initialSize)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        LogMessage("[MiMallocPool] 已初始化");
        return true;
    }

    // 1. 禁用急于提交内存 - 这有助于减少虚拟内存占用
    mi_option_set(mi_option_arena_eager_commit, 0);

    // 2. 减少内存归还延迟 - 让未使用内存更快归还系统
    mi_option_set(mi_option_purge_delay, 10);

    // 3. 设置较小的预留空间 - 如果总虚拟内存过高，这很关键
    mi_option_set(mi_option_arena_reserve, 16 * 1024);

    // 延迟提交 - 这可能会改善内存分配模式
    mi_option_set(mi_option_eager_commit_delay, 8);

    mi_option_set(mi_option_reset_decommits, 1);

    // 创建主要mimalloc堆
    g_mainHeap = mi_heap_new();
    if (!g_mainHeap) {
        LogMessage("[MiMallocPool] 无法创建mimalloc主堆");
        return false;
    }

    // 创建安全操作专用堆
    g_safeHeap = mi_heap_new();
    if (!g_safeHeap) {
        LogMessage("[MiMallocPool] 无法创建mimalloc安全堆");
        mi_heap_delete(g_mainHeap);
        g_mainHeap = nullptr;
        return false;
    }

    // 设置初始池大小
    g_totalPoolSize.store(initialSize);
    m_initialized = true;

    LogMessage("[MiMallocPool] mimalloc初始化完成，预留大小: %zu 字节", initialSize);
    return true;
}

void MiMallocPool::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        return;
    }

    if (g_miMallocDisableMemoryReleasing.load()) {
        LogMessage("[MiMallocPool] 保留所有内存块，仅清理管理数据");
        g_mainHeap = nullptr;
        g_safeHeap = nullptr;
        m_initialized = false;
        return;
    }

    if (g_mainHeap) {
        mi_heap_destroy(g_mainHeap);
        g_mainHeap = nullptr;
    }

    if (g_safeHeap) {
        mi_heap_destroy(g_safeHeap);
        g_safeHeap = nullptr;
    }

    m_initialized = false;
    LogMessage("[MiMallocPool] mimalloc关闭完成");
}

void* MiMallocPool::Allocate(size_t size)
{
    if (!g_mainHeap) {
        // 懒初始化
        if (!Initialize(64 * 1024 * 1024)) {  // 默认64MB
            return nullptr;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    void* ptr = mi_heap_malloc(g_mainHeap, size);
    if (ptr) {
        g_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    g_inMiMallocOperation.store(false);
    return ptr;
}

void* MiMallocPool::AllocateSafe(size_t size)
{
    if (!g_mainHeap) {
        // 懒初始化
        if (!Initialize(64 * 1024 * 1024)) {  // 默认64MB
            return nullptr;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 在不安全期直接用系统分配
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_inMiMallocOperation.store(false);

        if (!sysPtr) {
            LogMessage("[MiMallocPool] 不安全期间系统内存分配失败: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[MiMallocPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
        return sysPtr;
    }

    if (!g_safeHeap) {
        if (!g_mainHeap) {
            Initialize(64 * 1024 * 1024);
        }
        if (!g_safeHeap) {
            g_inMiMallocOperation.store(false);
            return nullptr;
        }
    }

    void* ptr = mi_heap_malloc(g_safeHeap, size);
    if (ptr) {
        g_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    g_inMiMallocOperation.store(false);
    return ptr;
}

void MiMallocPool::Free(void* ptr)
{
    if (!g_mainHeap || !ptr) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] 尝试释放永久块: %p，已忽略", ptr);
        g_inMiMallocOperation.store(false);
        return;
    }

    // 检查是否是mimalloc管理的内存
    bool isMainHeapPtr = mi_heap_check_owned(g_mainHeap, ptr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        g_inMiMallocOperation.store(false);
        return;
    }

    // 获取大小并更新统计
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        g_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 根据所属堆选择释放方式
    mi_free(ptr);  // mimalloc会自动将指针路由到正确的堆

    g_inMiMallocOperation.store(false);
}

void MiMallocPool::FreeSafe(void* ptr)
{
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] 尝试释放永久块: %p，已忽略", ptr);
        g_inMiMallocOperation.store(false);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 将指针加入延迟释放队列
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        g_inMiMallocOperation.store(false);
        return;
    }

    // 检查是否是mimalloc管理的内存
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(g_mainHeap, ptr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        g_inMiMallocOperation.store(false);
        return;
    }

    // 获取大小并更新统计
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        g_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 释放内存
    mi_free(ptr);  // mimalloc会自动将指针路由到正确的堆

    g_inMiMallocOperation.store(false);
}

void* MiMallocPool::Realloc(void* oldPtr, size_t newSize)
{
    if (!g_mainHeap) return nullptr;
    if (!oldPtr) return Allocate(newSize);
    if (newSize == 0) {
        Free(oldPtr);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    // 检查指针所有权
    bool isMainHeapPtr = mi_heap_check_owned(g_mainHeap, oldPtr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, oldPtr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // 不是我们管理的内存，分配新内存并返回
        g_inMiMallocOperation.store(false);
        void* newPtr = Allocate(newSize);
        if (newPtr) {
            // 尝试拷贝一些数据，但我们不知道原块大小，只能保守估计
            try {
                memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
            }
            catch (...) {}
        }
        return newPtr;
    }

    size_t oldSize = mi_usable_size(oldPtr);
    void* newPtr = mi_heap_realloc(g_mainHeap, oldPtr, newSize);

    if (newPtr) {
        if (oldSize > 0) {
            g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
        }
        g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    g_inMiMallocOperation.store(false);
    return newPtr;
}

void* MiMallocPool::ReallocSafe(void* oldPtr, size_t newSize)
{
    if (!g_mainHeap) return nullptr;
    if (!oldPtr) return AllocateSafe(newSize);
    if (newSize == 0) {
        FreeSafe(oldPtr);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inMiMallocOperation.store(true);

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 分配+复制+延迟释放
        void* newPtr = AllocateSafe(newSize);
        g_inMiMallocOperation.store(false);

        if (!newPtr) return nullptr;

        // 检查指针所有权
        bool isOurPtr = false;

        // 尝试获取mimalloc所有权
        if (g_mainHeap) {
            isOurPtr = mi_heap_check_owned(g_mainHeap, oldPtr);
        }
        if (!isOurPtr && g_safeHeap) {
            isOurPtr = mi_heap_check_owned(g_safeHeap, oldPtr);
        }

        // 尝试复制数据
        size_t oldSize = 0;
        try {
            if (isOurPtr) {
                oldSize = mi_usable_size(oldPtr);
            }
            else {
                // 尝试获取 Storm 头部信息
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                if (oldHeader->Magic == STORM_MAGIC) {
                    oldSize = oldHeader->Size;
                }
            }
        }
        catch (...) {
            oldSize = min(newSize, (size_t)64); // 无法确定大小，保守复制
        }

        size_t copySize = min(oldSize, newSize);
        try {
            memcpy(newPtr, oldPtr, copySize);
        }
        catch (...) {
            LogMessage("[MiMallocPool] 不安全期间复制数据失败");
            FreeSafe(newPtr);
            return nullptr;
        }

        // 不释放旧指针，而是放入延迟队列
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        return newPtr;
    }

    // 检查指针所有权
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(g_mainHeap, oldPtr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, oldPtr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // 不是我们管理的内存，分配新内存并返回
        g_inMiMallocOperation.store(false);
        void* newPtr = AllocateSafe(newSize);
        if (newPtr) {
            // 尝试拷贝一些数据，但我们不知道原块大小，只能保守估计
            try {
                memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
            }
            catch (...) {}
        }
        return newPtr;
    }

    // 直接使用mimalloc的realloc功能
    void* newPtr = mi_heap_realloc(g_mainHeap, oldPtr, newSize);

    if (newPtr) {
        // 更新统计信息
        size_t oldSize = 0;
        if (oldPtr != newPtr) {
            oldSize = mi_usable_size(oldPtr);
            if (oldSize > 0) {
                g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
        }
        g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    g_inMiMallocOperation.store(false);
    return newPtr;
}

bool MiMallocPool::IsFromPool(void* ptr)
{
    if (!ptr) return false;

    __try {
        // 检查是否为mimalloc管理的内存
        if (g_mainHeap && mi_heap_check_owned(g_mainHeap, ptr)) {
            return true;
        }

        if (g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr)) {
            return true;
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 访问指针出现异常
        return false;
    }
}

size_t MiMallocPool::GetBlockSize(void* ptr)
{
    if (!ptr) return 0;

    __try {
        // 检查是否为mimalloc管理的内存
        bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(g_mainHeap, ptr);
        bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr);

        if (isMainHeapPtr || isSafeHeapPtr) {
            return mi_usable_size(ptr);
        }

        // 尝试获取StormHeader信息
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 指针访问异常
    }

    return 0;
}

size_t MiMallocPool::GetUsedSize()
{
    return g_usedSize.load(std::memory_order_relaxed);
}

size_t MiMallocPool::GetTotalSize()
{
    // 确保总大小始终大于已用大小
    size_t currentUsed = GetUsedSize();
    size_t calculatedTotal = g_totalPoolSize.load(std::memory_order_relaxed);

    // 如果使用量超过了记录的总量
    if (currentUsed > calculatedTotal) {
        // 更新总大小为当前使用量的150%
        size_t newTotal = currentUsed * 3 / 2;
        g_totalPoolSize.store(newTotal, std::memory_order_relaxed);
        return newTotal;
    }

    return calculatedTotal;
}

void MiMallocPool::DisableMemoryReleasing()
{
    g_miMallocDisableMemoryReleasing.store(true);
    LogMessage("[MiMallocPool] 已禁用内存释放，所有内存将保留到进程结束");
}

void MiMallocPool::CheckAndFreeUnusedPools()
{
    if (g_mainHeap) {
        mi_heap_collect(g_mainHeap, true);
    }

    if (g_safeHeap) {
        mi_heap_collect(g_safeHeap, true);
    }
}

void MiMallocPool::HeapCollect()
{
    if (g_mainHeap) {
        mi_heap_collect(g_mainHeap, true);
    }
}

void MiMallocPool::PrintStats()
{
    if (!g_mainHeap) {
        LogMessage("[MiMallocPool] mimalloc未初始化");
        return;
    }

    LogMessage("[MiMallocPool] === mimalloc内存池统计 ===");
    LogMessage("[MiMallocPool] 已用内存: %zu KB", g_usedSize.load() / 1024);

    // 收集mimalloc的统计信息 (mimalloc本身也有统计功能)
    // 打印mimalloc自己的统计信息
    mi_stats_print(NULL);

    LogMessage("[MiMallocPool] mimalloc统计完成");
}