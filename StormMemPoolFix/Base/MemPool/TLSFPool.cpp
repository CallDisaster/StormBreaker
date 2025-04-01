#include "pch.h"
#include "TLSFPool.h"
#include <Windows.h>
#include <mutex>
#include <vector>
#include <algorithm>
#include <cassert>
#include <iostream>
#include "Storm/StormHook.h"
#include "Base/MemorySafety.h"
#include "Base/MemPool/tlsf.h"

namespace {
    // TLSF相关
    tlsf_t g_tlsfInstance = nullptr;
    pool_t g_initialPool = nullptr;
    std::vector<std::pair<void*, size_t>> g_additionalPools;

    // 控制标志
    std::atomic<bool> g_inTLSFOperation{ false };
    std::atomic<bool> g_tlsfDisableMemoryReleasing{ false };

    // 统计
    std::atomic<size_t> g_totalPoolSize{ 0 };
    std::atomic<size_t> g_usedSize{ 0 };

    // 锁
    std::mutex g_poolMutex;
}

TLSFPool::TLSFPool()
    : m_initialized(false)
{
}

TLSFPool::~TLSFPool()
{
    Shutdown();
}

bool TLSFPool::Initialize(size_t initialSize)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        LogMessage("[TLSFPool] 已初始化");
        return true;
    }

    // 确保初始大小是有效的
    if (initialSize < 1024 * 1024) {
        initialSize = 1024 * 1024; // 最小1MB
    }

    // 分配TLSF控制结构内存
    void* tlsfMem = VirtualAlloc(NULL, tlsf_size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tlsfMem) {
        LogMessage("[TLSFPool] 无法分配TLSF控制结构内存");
        return false;
    }

    // 创建TLSF实例
    g_tlsfInstance = tlsf_create(tlsfMem);
    if (!g_tlsfInstance) {
        LogMessage("[TLSFPool] TLSF实例创建失败");
        VirtualFree(tlsfMem, 0, MEM_RELEASE);
        return false;
    }

    // 分配初始内存池
    void* poolMem = VirtualAlloc(NULL, initialSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!poolMem) {
        LogMessage("[TLSFPool] 无法分配初始内存池");
        tlsf_destroy(g_tlsfInstance);
        VirtualFree(tlsfMem, 0, MEM_RELEASE);
        g_tlsfInstance = nullptr;
        return false;
    }

    // 添加初始池
    g_initialPool = tlsf_add_pool(g_tlsfInstance, poolMem, initialSize);
    if (!g_initialPool) {
        LogMessage("[TLSFPool] 无法添加初始内存池到TLSF");
        VirtualFree(poolMem, 0, MEM_RELEASE);
        tlsf_destroy(g_tlsfInstance);
        VirtualFree(tlsfMem, 0, MEM_RELEASE);
        g_tlsfInstance = nullptr;
        return false;
    }

    // 记录初始池大小
    g_totalPoolSize.store(initialSize);
    m_initialized = true;

    LogMessage("[TLSFPool] TLSF初始化完成，初始池大小: %zu 字节", initialSize);
    return true;
}

void TLSFPool::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        return;
    }

    // 如果设置了不释放内存，则只清理管理结构
    if (g_tlsfDisableMemoryReleasing.load()) {
        LogMessage("[TLSFPool] 保留所有内存块，仅清理管理数据");
        g_tlsfInstance = nullptr;
        g_initialPool = nullptr;
        g_additionalPools.clear();
        m_initialized = false;
        return;
    }

    // 正常清理 - 先清理额外池
    for (const auto& pool : g_additionalPools) {
        if (pool.first) {
            // 从TLSF移除池
            tlsf_remove_pool(g_tlsfInstance, pool.first);
            // 释放系统内存
            VirtualFree(pool.first, 0, MEM_RELEASE);
        }
    }
    g_additionalPools.clear();

    // 清理初始池
    if (g_initialPool) {
        void* poolMem = g_initialPool;
        tlsf_remove_pool(g_tlsfInstance, g_initialPool);
        VirtualFree(poolMem, 0, MEM_RELEASE);
        g_initialPool = nullptr;
    }

    // 清理TLSF实例
    if (g_tlsfInstance) {
        void* tlsfMem = g_tlsfInstance;
        tlsf_destroy(g_tlsfInstance);
        VirtualFree(tlsfMem, 0, MEM_RELEASE);
        g_tlsfInstance = nullptr;
    }

    m_initialized = false;
    LogMessage("[TLSFPool] TLSF内存池关闭完成");
}

void* TLSFPool::Allocate(size_t size)
{
    if (!g_tlsfInstance) {
        // 懒初始化
        if (!Initialize(64 * 1024 * 1024)) {  // 默认64MB
            return nullptr;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    void* ptr = tlsf_malloc(g_tlsfInstance, size);

    // 如果分配失败且size比较大，可能需要扩展内存池
    if (!ptr && size > 1024) {
        if (ExpandPool(size * 2)) {
            // 再次尝试分配
            ptr = tlsf_malloc(g_tlsfInstance, size);
        }
    }

    if (ptr) {
        g_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    g_inTLSFOperation.store(false);
    return ptr;
}

void* TLSFPool::AllocateSafe(size_t size)
{
    if (!g_tlsfInstance) {
        // 懒初始化
        if (!Initialize(64 * 1024 * 1024)) {  // 默认64MB
            return nullptr;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 在不安全期直接用系统分配
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_inTLSFOperation.store(false);

        if (!sysPtr) {
            LogMessage("[TLSFPool] 不安全期间系统内存分配失败: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[TLSFPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
        return sysPtr;
    }

    void* ptr = tlsf_malloc(g_tlsfInstance, size);

    // 如果分配失败且size比较大，可能需要扩展内存池
    if (!ptr && size > 1024) {
        if (ExpandPool(size * 2)) {
            // 再次尝试分配
            ptr = tlsf_malloc(g_tlsfInstance, size);
        }
    }

    if (ptr) {
        g_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    g_inTLSFOperation.store(false);
    return ptr;
}

void TLSFPool::Free(void* ptr)
{
    if (!g_tlsfInstance || !ptr) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] 尝试释放永久块: %p，已忽略", ptr);
        g_inTLSFOperation.store(false);
        return;
    }

    // 获取大小并更新统计
    size_t size = tlsf_block_size(ptr);
    if (size > 0) {
        g_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 释放内存
    tlsf_free(g_tlsfInstance, ptr);

    g_inTLSFOperation.store(false);
}

void TLSFPool::FreeSafe(void* ptr)
{
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] 尝试释放永久块: %p，已忽略", ptr);
        g_inTLSFOperation.store(false);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 将指针加入延迟释放队列
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        g_inTLSFOperation.store(false);
        return;
    }

    // 获取大小并更新统计
    size_t size = tlsf_block_size(ptr);
    if (size > 0) {
        g_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 释放内存
    tlsf_free(g_tlsfInstance, ptr);

    g_inTLSFOperation.store(false);
}

void* TLSFPool::Realloc(void* oldPtr, size_t newSize)
{
    if (!g_tlsfInstance) return nullptr;
    if (!oldPtr) return Allocate(newSize);
    if (newSize == 0) {
        Free(oldPtr);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    // 获取旧块大小
    size_t oldSize = tlsf_block_size(oldPtr);

    // 使用TLSF的重分配功能
    void* newPtr = tlsf_realloc(g_tlsfInstance, oldPtr, newSize);

    // 如果重分配失败，尝试扩展池并重新分配
    if (!newPtr && newSize > oldSize) {
        if (ExpandPool(newSize * 2)) {
            newPtr = tlsf_realloc(g_tlsfInstance, oldPtr, newSize);
        }
    }

    if (newPtr) {
        // 更新统计
        if (oldSize > 0) {
            g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
        }
        g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    g_inTLSFOperation.store(false);
    return newPtr;
}

void* TLSFPool::ReallocSafe(void* oldPtr, size_t newSize)
{
    if (!g_tlsfInstance) return nullptr;
    if (!oldPtr) return AllocateSafe(newSize);
    if (newSize == 0) {
        FreeSafe(oldPtr);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    g_inTLSFOperation.store(true);

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 分配+复制+延迟释放
        void* newPtr = AllocateSafe(newSize);
        g_inTLSFOperation.store(false);

        if (!newPtr) return nullptr;

        // 尝试获取大小并复制数据
        size_t oldSize = tlsf_block_size(oldPtr);
        if (oldSize == 0) {
            // 无法确定大小，保守复制
            try {
                memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
            }
            catch (...) {
                LogMessage("[TLSFPool] 不安全期间复制数据失败");
                FreeSafe(newPtr);
                return nullptr;
            }
        }
        else {
            // 正常复制
            try {
                memcpy(newPtr, oldPtr, min(oldSize, newSize));
            }
            catch (...) {
                LogMessage("[TLSFPool] 不安全期间复制数据失败");
                FreeSafe(newPtr);
                return nullptr;
            }
        }

        // 不释放旧指针，而是放入延迟队列
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        return newPtr;
    }

    // 获取旧块大小
    size_t oldSize = tlsf_block_size(oldPtr);

    // 使用TLSF的重分配功能
    void* newPtr = tlsf_realloc(g_tlsfInstance, oldPtr, newSize);

    // 如果重分配失败，尝试扩展池并重新分配
    if (!newPtr && newSize > oldSize) {
        if (ExpandPool(newSize * 2)) {
            newPtr = tlsf_realloc(g_tlsfInstance, oldPtr, newSize);
        }
    }

    if (newPtr) {
        // 更新统计
        if (oldSize > 0) {
            g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
        }
        g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    g_inTLSFOperation.store(false);
    return newPtr;
}

bool TLSFPool::IsFromPool(void* ptr)
{
    if (!ptr || !g_tlsfInstance) return false;

    __try {
        // TLSF没有直接的方法检查指针所有权，所以我们尝试获取块大小
        // 如果能获取大小，说明是我们的块
        size_t size = tlsf_block_size(ptr);
        return size > 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 访问指针出现异常
        return false;
    }
}

size_t TLSFPool::GetBlockSize(void* ptr)
{
    if (!ptr) return 0;

    __try {
        if (g_tlsfInstance) {
            return tlsf_block_size(ptr);
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

size_t TLSFPool::GetUsedSize()
{
    return g_usedSize.load(std::memory_order_relaxed);
}

size_t TLSFPool::GetTotalSize()
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

void TLSFPool::DisableMemoryReleasing()
{
    g_tlsfDisableMemoryReleasing.store(true);
    LogMessage("[TLSFPool] 已禁用内存释放，所有内存将保留到进程结束");
}

void TLSFPool::CheckAndFreeUnusedPools()
{
    // TLSF本身不支持收缩内存池，这里只做日志
    LogMessage("[TLSFPool] TLSF不支持动态收缩内存池");
}

void TLSFPool::HeapCollect()
{
    // TLSF本身不支持垃圾收集，这里只做日志
    LogMessage("[TLSFPool] TLSF不支持垃圾收集");
}

bool TLSFPool::ExpandPool(size_t additionalSize)
{
    // 确保大小有效
    if (additionalSize < 1024 * 1024) {
        additionalSize = 1024 * 1024;  // 最小1MB
    }

    // 分配新池内存
    void* poolMem = VirtualAlloc(NULL, additionalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!poolMem) {
        LogMessage("[TLSFPool] 无法分配额外内存池: %zu 字节", additionalSize);
        return false;
    }

    // 添加到TLSF
    pool_t newPool = tlsf_add_pool(g_tlsfInstance, poolMem, additionalSize);
    if (!newPool) {
        LogMessage("[TLSFPool] 无法添加额外内存池到TLSF");
        VirtualFree(poolMem, 0, MEM_RELEASE);
        return false;
    }

    // 记录新池
    g_additionalPools.push_back(std::make_pair(newPool, additionalSize));

    // 更新总池大小
    g_totalPoolSize.fetch_add(additionalSize, std::memory_order_relaxed);

    LogMessage("[TLSFPool] 成功扩展内存池: %zu 字节", additionalSize);
    return true;
}

void TLSFPool::PrintStats()
{
    if (!g_tlsfInstance) {
        LogMessage("[TLSFPool] TLSF未初始化");
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    LogMessage("[TLSFPool] === TLSF内存池统计 ===");
    LogMessage("[TLSFPool] 已用内存: %zu KB", g_usedSize.load() / 1024);
    LogMessage("[TLSFPool] 总内存池: %zu KB", g_totalPoolSize.load() / 1024);
    LogMessage("[TLSFPool] 额外内存池数量: %zu", g_additionalPools.size());

    // 检查TLSF内部一致性
    int check_result = tlsf_check(g_tlsfInstance);
    LogMessage("[TLSFPool] TLSF健康检查: %s", check_result == 0 ? "通过" : "失败");

    LogMessage("[TLSFPool] TLSF内部信息:");
    LogMessage("[TLSFPool] - 最小块大小: %zu", tlsf_block_size_min());
    LogMessage("[TLSFPool] - 最大块大小: %zu", tlsf_block_size_max());
    LogMessage("[TLSFPool] - 对齐大小: %zu", tlsf_align_size());
    LogMessage("[TLSFPool] - 分配开销: %zu", tlsf_alloc_overhead());

    LogMessage("[TLSFPool] =====================");
}