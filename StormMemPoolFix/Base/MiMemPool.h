// MiMemPool.h
#pragma once
#include <mimalloc.h>
#include <atomic>
#include <mutex>
#include "SafeExecutionGuard.h"
#include "Base/Logger.h"
#include "Storm/StormHook.h"

extern class MemorySafety& g_MemSafety;

// mimalloc封装命名空间
namespace MiMemPool {
    // 全局状态
    namespace {
        std::atomic<bool> g_initialized{ false };
        std::atomic<bool> g_inOperation{ false };
        std::mutex g_mutex;

        // 当前堆和其他堆
        mi_heap_t* g_defaultHeap = nullptr;

        // 特殊类型的内存预留
        mi_heap_t* g_jassVMHeap = nullptr;

        // 统计信息
        std::atomic<size_t> g_totalAllocated{ 0 };
        std::atomic<size_t> g_totalFreed{ 0 };
        std::atomic<size_t> g_totalMiVsSystem{ 0 }; // mimalloc vs 系统分配对比
    }

    // 初始化mimalloc
    void Initialize() {
        SafeExecutionGuard guard(g_inOperation, "MiMemPool::Initialize");
        if (!guard.CanProceed()) {
            return;
        }

        if (g_initialized.load()) {
            LogMessage("[MiMemPool] 已初始化");
            return;
        }

        std::lock_guard<std::mutex> lock(g_mutex);

        // 配置全局选项 - 使用mi_option_set
        mi_option_set(mi_option_show_errors, 1);
        mi_option_set(mi_option_show_stats, 1);
        mi_option_set(mi_option_eager_commit, 0);
        mi_option_set(mi_option_reset_decommits, 1);
        mi_option_set(mi_option_large_os_pages, 0);

        // 创建默认堆
        g_defaultHeap = mi_heap_new();

        // 创建专用JassVM堆
        g_jassVMHeap = mi_heap_new();

        g_initialized.store(true);
        LogMessage("[MiMemPool] 初始化完成");
    }

    // 关闭mimalloc
    void Shutdown() {
        SafeExecutionGuard guard(g_inOperation, "MiMemPool::Shutdown");
        if (!guard.CanProceed()) {
            return;
        }

        if (!g_initialized.load()) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_mutex);

        // 输出最终统计
        LogMessage("[MiMemPool] 关闭统计: 已分配=%zu MB, 已释放=%zu MB, 系统备用=%zu",
            g_totalAllocated.load() / (1024 * 1024),
            g_totalFreed.load() / (1024 * 1024),
            g_totalMiVsSystem.load());

        // 销毁专用堆
        if (g_jassVMHeap) {
            mi_heap_destroy(g_jassVMHeap);
            g_jassVMHeap = nullptr;
        }

        // 销毁默认堆
        if (g_defaultHeap) {
            mi_heap_destroy(g_defaultHeap);
            g_defaultHeap = nullptr;
        }

        // 输出统计信息
        mi_stats_print(nullptr);

        g_initialized.store(false);
        LogMessage("[MiMemPool] 已关闭");
    }

    // 确保已初始化
    void EnsureInitialized() {
        if (!g_initialized.load()) {
            Initialize();
        }
    }

    // 安全分配
    void* AllocateSafe(size_t size) {
        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间使用系统分配
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) {
                LogMessage("[MiMemPool] 不安全期间系统内存分配失败: %zu", size);
                return nullptr;
            }

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            g_totalMiVsSystem.fetch_add(1, std::memory_order_relaxed);
            LogMessage("[MiMemPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
            return userPtr;
        }

        SafeExecutionGuard guard(g_inOperation, "MiMemPool::AllocateSafe");
        if (!guard.CanProceed()) {
            // 使用系统分配作为备选
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) return nullptr;

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            g_totalMiVsSystem.fetch_add(1, std::memory_order_relaxed);
            return userPtr;
        }

        EnsureInitialized();

        // 改用 SEH 替代 __try
        void* ptr = nullptr;
        DWORD exceptionCode = 0;

        __try {
            if (g_defaultHeap) {
                ptr = mi_heap_malloc(g_defaultHeap, size);

                if (ptr) {
                    g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
                }
            }
            else {
                ptr = mi_malloc(size);

                if (ptr) {
                    g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
                }
            }
        }
        __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 分配异常: %zu, 错误=0x%X", size, exceptionCode);
            ptr = nullptr;
        }

        if (!ptr) {
            LogMessage("[MiMemPool] 分配失败，使用系统备选: %zu", size);
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) return nullptr;

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            g_totalMiVsSystem.fetch_add(1, std::memory_order_relaxed);
            return userPtr;
        }

        return ptr;
    }

    // 标准分配
    void* Allocate(size_t size) {
        EnsureInitialized();

        void* ptr = nullptr;
        if (g_defaultHeap) {
            ptr = mi_heap_malloc(g_defaultHeap, size);
        }
        else {
            ptr = mi_malloc(size);
        }

        if (ptr) {
            g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
        }

        return ptr;
    }

    // JassVM专用分配
    void* AllocateJassVM(size_t size) {
        EnsureInitialized();

        void* ptr = nullptr;
        if (g_jassVMHeap) {
            ptr = mi_heap_malloc(g_jassVMHeap, size);
        }
        else {
            ptr = mi_malloc(size);
        }

        if (ptr) {
            g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
        }

        return ptr;
    }

    // 检查是否系统分配的备用内存
    bool IsSystemBackupMemory(void* ptr) {
        if (!ptr) return false;

        bool result = false;
        __try {
            StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                static_cast<char*>(ptr) - sizeof(StormAllocHeader));

            // 简单检查指针有效性
            if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
                return false;
            }

            if (header->Magic == STORM_MAGIC &&
                header->HeapId == SPECIAL_MARKER) {
                result = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            result = false;
        }

        return result;
    }

    // 获取 Storm 块大小
    size_t GetStormBlockSize(void* ptr) {
        if (!ptr) return 0;

        size_t size = 0;
        __try {
            StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                static_cast<char*>(ptr) - sizeof(StormAllocHeader));

            // 简单检查指针有效性
            if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
                return 0;
            }

            if (header->Magic == STORM_MAGIC) {
                size_t total = header->Size;
                size = total - sizeof(StormAllocHeader) - header->AlignPadding;
                if (header->Flags & 0x1) size -= 2;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            size = 0;
        }

        return size;
    }

    // 安全释放
    void FreeSafe(void* ptr) {
        if (!ptr) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间加入延迟释放队列而不是直接释放
            size_t blockSize = GetStormBlockSize(ptr);
            g_MemSafety.EnqueueDeferredFree(ptr, blockSize);
            return;
        }

        SafeExecutionGuard guard(g_inOperation, "MiMemPool::FreeSafe");
        if (!guard.CanProceed()) {
            return;
        }

        // 检查是否系统分配的备用内存
        if (IsSystemBackupMemory(ptr)) {
            // 获取块大小用于统计
            size_t blockSize = GetStormBlockSize(ptr);
            if (blockSize > 0) {
                g_totalFreed.fetch_add(blockSize, std::memory_order_relaxed);
            }

            // 系统备用内存，直接释放
            void* basePtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
            VirtualFree(basePtr, 0, MEM_RELEASE);
            return;
        }

        // 使用mimalloc释放
        __try {
            // 使用mi_usable_size获取大小用于统计
            size_t size = mi_usable_size(ptr);
            if (size > 0) {
                g_totalFreed.fetch_add(size, std::memory_order_relaxed);
            }

            mi_free(ptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 释放异常: %p", ptr);
        }
    }

    // 标准释放
    void Free(void* ptr) {
        if (!ptr) return;

        __try {
            // 尝试获取大小用于统计
            size_t size = mi_usable_size(ptr);
            if (size > 0) {
                g_totalFreed.fetch_add(size, std::memory_order_relaxed);
            }

            mi_free(ptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 标准释放异常: %p", ptr);
        }
    }

    // 安全重分配
    void* ReallocSafe(void* oldPtr, size_t newSize) {
        if (!oldPtr) return AllocateSafe(newSize);
        if (newSize == 0) {
            FreeSafe(oldPtr);
            return nullptr;
        }

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期，分配+复制+不立即释放
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试复制数据
            size_t oldSize = GetStormBlockSize(oldPtr);

            // 使用安全拷贝
            if (oldSize > 0) {
                // 使用memcpy自行实现安全复制
                __try {
                    size_t copySize = min(oldSize, newSize);
                    memcpy(newPtr, oldPtr, copySize);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    LogMessage("[MiMemPool] 复制数据失败");
                }
            }
            else {
                // 保守复制
                __try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)128));
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    LogMessage("[MiMemPool] 保守复制失败");
                }
            }

            // 将旧指针放入延迟释放队列
            g_MemSafety.EnqueueDeferredFree(oldPtr, oldSize);

            return newPtr;
        }

        SafeExecutionGuard guard(g_inOperation, "MiMemPool::ReallocSafe");
        if (!guard.CanProceed()) {
            // 使用备选策略: 分配+复制+释放
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 复制数据
            size_t oldSize = GetStormBlockSize(oldPtr);
            __try {
                if (oldSize > 0) {
                    memcpy(newPtr, oldPtr, min(oldSize, newSize));
                }
                else {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)128));
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[MiMemPool] 复制数据异常");
            }

            FreeSafe(oldPtr);
            return newPtr;
        }

        // 检查是否系统分配的备用内存
        if (IsSystemBackupMemory(oldPtr)) {
            // 系统备用内存，使用分配+复制+释放
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 获取旧块大小
            size_t oldSize = GetStormBlockSize(oldPtr);

            // 复制
            __try {
                if (oldSize > 0) {
                    memcpy(newPtr, oldPtr, min(oldSize, newSize));
                }
                else {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)128));
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[MiMemPool] 复制数据异常");
            }

            // 释放旧块
            void* basePtr = static_cast<char*>(oldPtr) - sizeof(StormAllocHeader);
            VirtualFree(basePtr, 0, MEM_RELEASE);

            if (oldSize > 0) {
                g_totalFreed.fetch_add(oldSize, std::memory_order_relaxed);
            }

            return newPtr;
        }

        // 使用mimalloc重分配
        void* newPtr = nullptr;

        __try {
            // 获取旧大小用于统计
            size_t oldMiSize = mi_usable_size(oldPtr);

            if (g_defaultHeap) {
                newPtr = mi_heap_realloc(g_defaultHeap, oldPtr, newSize);
            }
            else {
                newPtr = mi_realloc(oldPtr, newSize);
            }

            if (newPtr) {
                // 调整统计信息
                g_totalFreed.fetch_add(oldMiSize, std::memory_order_relaxed);
                g_totalAllocated.fetch_add(newSize, std::memory_order_relaxed);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 重分配异常: %p, 大小=%zu", oldPtr, newSize);
            newPtr = nullptr;
        }

        if (!newPtr) {
            // 重分配失败，尝试备选方案
            LogMessage("[MiMemPool] 重分配失败，使用备选: %p, 大小=%zu", oldPtr, newSize);

            newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            __try {
                // 复制数据
                size_t oldSize = mi_usable_size(oldPtr);
                if (oldSize > 0) {
                    memcpy(newPtr, oldPtr, min(oldSize, newSize));
                }
                else {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)128));
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[MiMemPool] 备选复制数据异常");
            }

            FreeSafe(oldPtr);
        }

        return newPtr;
    }

    // 标准重分配
    void* Realloc(void* oldPtr, size_t newSize) {
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        // 获取旧大小用于统计
        size_t oldSize = 0;
        __try {
            oldSize = mi_usable_size(oldPtr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            oldSize = 0;
        }

        void* newPtr = nullptr;
        __try {
            newPtr = mi_realloc(oldPtr, newSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 标准重分配异常: %p", oldPtr);
            return nullptr;
        }

        if (newPtr) {
            if (oldSize > 0) {
                g_totalFreed.fetch_add(oldSize, std::memory_order_relaxed);
            }
            g_totalAllocated.fetch_add(newSize, std::memory_order_relaxed);
        }

        return newPtr;
    }

    // 检查指针是否来自我们的池
    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        // 先检查是否系统分配的备用内存
        if (IsSystemBackupMemory(ptr)) {
            return true;
        }

        // 检查是否来自mimalloc
        __try {
            return mi_is_in_heap_region(ptr) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // 获取使用大小
    size_t GetUsedSize() {
        if (!g_initialized.load()) return 0;

        __try {
            // 使用内部统计
            return g_totalAllocated.load() - g_totalFreed.load();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    // 获取总大小
    size_t GetTotalSize() {
        if (!g_initialized.load()) return 0;

        __try {
            // 大致估计为已用大小的1.5倍
            return GetUsedSize() * 3 / 2;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    // 打印统计
    void PrintStats() {
        if (!g_initialized.load()) {
            LogMessage("[MiMemPool] 未初始化");
            return;
        }

        __try {
            // 输出简化版统计信息
            size_t allocated = g_totalAllocated.load();
            size_t freed = g_totalFreed.load();
            size_t used = (allocated > freed) ? (allocated - freed) : 0;

            LogMessage("[MiMemPool] 统计摘要: 已分配=%zu KB, 已释放=%zu KB, 使用中=%zu KB",
                allocated / 1024, freed / 1024, used / 1024);

            // 输出内部计数器
            LogMessage("[MiMemPool] 内部计数: 总分配=%zu MB, 总释放=%zu MB, 系统备选次数=%zu",
                allocated / (1024 * 1024),
                freed / (1024 * 1024),
                g_totalMiVsSystem.load());
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 获取统计信息时发生异常");
        }
    }

    // 清理未使用的内存
    void CollectUnused() {
        if (!g_initialized.load()) return;

        __try {
            LogMessage("[MiMemPool] 开始收集未使用内存");

            // 执行垃圾收集
            mi_collect(true);

            LogMessage("[MiMemPool] 收集完成");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MiMemPool] 收集未使用内存时发生异常");
        }
    }
};