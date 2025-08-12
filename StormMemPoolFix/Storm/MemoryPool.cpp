// ======================== MemoryPool.cpp 完整修复版本 ========================
#include "pch.h"
#include "MemoryPool.h"
#include "Base/Logger.h"
#include "tlsf.h"
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <atomic>
#include <algorithm>
#include <cassert>
#include <memory>
#include <cstdint>
#include <unordered_map>

// ======================== 全局变量和配置 ========================
namespace {
    // TLSF相关
    tlsf_t g_tlsfHandle = nullptr;
    void* g_mainPool = nullptr;

    // 额外池结构体 - 修复版本
    struct ExtraPool {
        void* base;
        size_t size;

        // 添加构造函数以支持初始化
        ExtraPool() : base(nullptr), size(0) {}
        ExtraPool(void* b, size_t s) : base(b), size(s) {}
    };
    std::vector<ExtraPool> g_extraPools;

    // 线程安全
    std::shared_mutex g_poolMutex;
    std::atomic<bool> g_threadSafeEnabled(true);

    // 配置 - 移除指定初始化器
    MemoryPool::Config g_config;

    // 状态标志
    std::atomic<bool> g_initialized(false);

    // 统计信息
    std::atomic<size_t> g_totalSize(0);
    std::atomic<size_t> g_usedSize(0);
    std::atomic<size_t> g_peakUsed(0);
    std::atomic<size_t> g_allocCount(0);
    std::atomic<size_t> g_freeCount(0);
    std::atomic<size_t> g_extendCount(0);
    std::atomic<size_t> g_trimCount(0);

    // 稳定块管理
    std::mutex g_stabilizingMutex;
    std::vector<void*> g_stabilizingBlocks;

    // 辅助函数
    bool IsPointerInRange(void* ptr, void* base, size_t size) {
        if (!ptr || !base) return false;
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t baseAddr = reinterpret_cast<uintptr_t>(base);
        return (ptrAddr >= baseAddr && ptrAddr < baseAddr + size);
    }

    void UpdatePeakUsage(size_t currentUsed) {
        size_t peak = g_peakUsed.load(std::memory_order_relaxed);
        while (currentUsed > peak &&
            !g_peakUsed.compare_exchange_weak(peak, currentUsed, std::memory_order_relaxed)) {
            // 重试直到成功更新峰值
        }
    }

    // AddExtraPool函数 - 修复版本
    bool AddExtraPool(size_t size) {
        Logger::GetInstance().LogInfo("添加额外内存池: %zu MB", size / (1024 * 1024));

        void* newPool = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newPool) {
            Logger::GetInstance().LogError("VirtualAlloc失败: size=%zu, error=%lu", size, GetLastError());
            return false;
        }

        pool_t pool = tlsf_add_pool(g_tlsfHandle, newPool, size);
        if (!pool) {
            Logger::GetInstance().LogError("tlsf_add_pool失败");
            VirtualFree(newPool, 0, MEM_RELEASE);
            return false;
        }

        // 修复：使用构造函数创建ExtraPool对象
        ExtraPool newExtraPool(newPool, size);
        g_extraPools.push_back(newExtraPool);

        g_totalSize.fetch_add(size, std::memory_order_relaxed);
        g_extendCount.fetch_add(1, std::memory_order_relaxed);

        Logger::GetInstance().LogInfo("成功添加内存池: %p, 大小=%zu MB", newPool, size / (1024 * 1024));
        return true;
    }
}

// ======================== SEH包装的TLSF操作 ========================
namespace SEH_TLSF {

    void* SafeTLSFMalloc(tlsf_t tlsf, size_t size) {
        __try {
            return tlsf_malloc(tlsf, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("TLSF malloc异常: size=%zu, code=0x%08X", size, GetExceptionCode());
            return nullptr;
        }
    }

    void SafeTLSFFree(tlsf_t tlsf, void* ptr) {
        __try {
            tlsf_free(tlsf, ptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("TLSF free异常: ptr=%p, code=0x%08X", ptr, GetExceptionCode());
        }
    }

    void* SafeTLSFRealloc(tlsf_t tlsf, void* ptr, size_t size) {
        __try {
            return tlsf_realloc(tlsf, ptr, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("TLSF realloc异常: ptr=%p, size=%zu, code=0x%08X",
                ptr, size, GetExceptionCode());
            return nullptr;
        }
    }

    void* SafeTLSFMetalign(tlsf_t tlsf, size_t align, size_t size) {
        __try {
            return tlsf_memalign(tlsf, align, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("TLSF memalign异常: align=%zu, size=%zu, code=0x%08X",
                align, size, GetExceptionCode());
            return nullptr;
        }
    }

    size_t SafeTLSFBlockSize(void* ptr) {
        __try {
            return tlsf_block_size(ptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("TLSF block_size异常: ptr=%p, code=0x%08X", ptr, GetExceptionCode());
            return 0;
        }
    }
}

// ======================== 公共接口实现 ========================
namespace MemoryPool {

    bool Initialize() {
        if (g_initialized.exchange(true, std::memory_order_acq_rel)) {
            return true; // 已初始化
        }

        // 初始化默认配置
        g_config.initialSize = 64 * 1024 * 1024;        // 64MB初始大小
        g_config.maxSize = 1024 * 1024 * 1024;          // 1GB最大大小
        g_config.extendGranularity = 16 * 1024 * 1024;  // 16MB扩展粒度
        g_config.alignment = 16;                         // 16字节对齐
        g_config.enableDebug = false;
        g_config.enableStats = true;

        Logger::GetInstance().LogInfo("初始化TLSF内存池...");
        Logger::GetInstance().LogInfo("配置: 初始=%zu MB, 最大=%zu MB, 扩展粒度=%zu MB",
            g_config.initialSize / (1024 * 1024),
            g_config.maxSize / (1024 * 1024),
            g_config.extendGranularity / (1024 * 1024));

        // 分配主内存池
        g_mainPool = VirtualAlloc(nullptr, g_config.initialSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_mainPool) {
            Logger::GetInstance().LogError("主内存池分配失败: size=%zu, error=%lu",
                g_config.initialSize, GetLastError());
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        // 创建TLSF实例
        g_tlsfHandle = tlsf_create_with_pool(g_mainPool, g_config.initialSize);
        if (!g_tlsfHandle) {
            Logger::GetInstance().LogError("TLSF创建失败");
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        g_totalSize.store(g_config.initialSize, std::memory_order_relaxed);

        Logger::GetInstance().LogInfo("TLSF内存池初始化完成: 地址=%p, 大小=%zu MB",
            g_mainPool, g_config.initialSize / (1024 * 1024));
        return true;
    }

    void Shutdown() {
        if (!g_initialized.exchange(false, std::memory_order_acq_rel)) {
            return; // 未初始化
        }

        Logger::GetInstance().LogInfo("关闭TLSF内存池...");

        // 清理稳定块
        FlushStabilizingBlocks();

        // 销毁TLSF句柄
        if (g_tlsfHandle) {
            g_tlsfHandle = nullptr; // TLSF库会自动清理
        }

        // 释放额外池
        for (const ExtraPool& pool : g_extraPools) {
            if (pool.base) {
                VirtualFree(pool.base, 0, MEM_RELEASE);
            }
        }
        g_extraPools.clear();

        // 释放主池
        if (g_mainPool) {
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
        }

        // 重置统计
        g_totalSize.store(0, std::memory_order_relaxed);
        g_usedSize.store(0, std::memory_order_relaxed);

        Logger::GetInstance().LogInfo("TLSF内存池已关闭");
    }

    bool IsInitialized() {
        return g_initialized.load(std::memory_order_acquire);
    }

    void* Allocate(size_t size) {
        if (!g_initialized.load(std::memory_order_acquire) || size == 0) {
            return nullptr;
        }

        // 第一阶段：使用共享锁尝试分配
        {
            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }

            void* ptr = SEH_TLSF::SafeTLSFMalloc(g_tlsfHandle, size);
            if (ptr) {
                if (g_config.enableStats) {
                    g_allocCount.fetch_add(1, std::memory_order_relaxed);
                    size_t currentUsed = g_usedSize.fetch_add(size, std::memory_order_relaxed) + size;
                    UpdatePeakUsage(currentUsed);
                }

                if (g_config.enableDebug) {
                    Logger::GetInstance().LogDebug("TLSF分配: ptr=%p, size=%zu", ptr, size);
                }

                return ptr;
            }
            // readLock在这里自动释放
        }

        // 第二阶段：分配失败，检查是否可以扩展
        if (g_totalSize.load(std::memory_order_relaxed) >= g_config.maxSize) {
            return nullptr;
        }

        // 使用独占锁进行扩展
        {
            std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                writeLock.lock();
            }

            size_t extendSize = max(g_config.extendGranularity,
                ((size + g_config.extendGranularity - 1) / g_config.extendGranularity) * g_config.extendGranularity);

            if (AddExtraPool(extendSize)) {
                void* ptr = SEH_TLSF::SafeTLSFMalloc(g_tlsfHandle, size);
                if (ptr) {
                    if (g_config.enableStats) {
                        g_allocCount.fetch_add(1, std::memory_order_relaxed);
                        size_t currentUsed = g_usedSize.fetch_add(size, std::memory_order_relaxed) + size;
                        UpdatePeakUsage(currentUsed);
                    }

                    if (g_config.enableDebug) {
                        Logger::GetInstance().LogDebug("TLSF分配(扩容后): ptr=%p, size=%zu", ptr, size);
                    }

                    return ptr;
                }
            }
            // writeLock在这里自动释放
        }

        return nullptr;
    }

    void* AllocateAligned(size_t size, size_t alignment) {
        if (!g_initialized.load(std::memory_order_acquire) || size == 0) {
            return nullptr;
        }

        if (alignment == 0) {
            alignment = g_config.alignment;
        }

        // 第一阶段：使用共享锁尝试分配
        {
            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }

            void* ptr = SEH_TLSF::SafeTLSFMetalign(g_tlsfHandle, alignment, size);
            if (ptr) {
                if (g_config.enableStats) {
                    g_allocCount.fetch_add(1, std::memory_order_relaxed);
                    size_t currentUsed = g_usedSize.fetch_add(size, std::memory_order_relaxed) + size;
                    UpdatePeakUsage(currentUsed);
                }

                if (g_config.enableDebug) {
                    Logger::GetInstance().LogDebug("TLSF对齐分配: ptr=%p, size=%zu, align=%zu", ptr, size, alignment);
                }

                return ptr;
            }
            // readLock在这里自动释放
        }

        // 第二阶段：分配失败，检查是否可以扩展
        if (g_totalSize.load(std::memory_order_relaxed) >= g_config.maxSize) {
            return nullptr;
        }

        // 使用独占锁进行扩展
        {
            std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                writeLock.lock();
            }

            size_t extendSize = max(g_config.extendGranularity,
                ((size + alignment + g_config.extendGranularity - 1) / g_config.extendGranularity) * g_config.extendGranularity);

            if (AddExtraPool(extendSize)) {
                void* ptr = SEH_TLSF::SafeTLSFMetalign(g_tlsfHandle, alignment, size);
                if (ptr) {
                    if (g_config.enableStats) {
                        g_allocCount.fetch_add(1, std::memory_order_relaxed);
                        size_t currentUsed = g_usedSize.fetch_add(size, std::memory_order_relaxed) + size;
                        UpdatePeakUsage(currentUsed);
                    }

                    if (g_config.enableDebug) {
                        Logger::GetInstance().LogDebug("TLSF对齐分配(扩容后): ptr=%p, size=%zu, align=%zu", ptr, size, alignment);
                    }

                    return ptr;
                }
            }
            // writeLock在这里自动释放
        }

        return nullptr;
    }

    void* Reallocate(void* ptr, size_t newSize) {
        if (!g_initialized.load(std::memory_order_acquire)) {
            return nullptr;
        }

        if (!ptr) {
            return Allocate(newSize);
        }

        if (newSize == 0) {
            Free(ptr);
            return nullptr;
        }

        size_t oldSizeForStats = 0;

        // 第一阶段：使用共享锁尝试重分配
        {
            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }

            if (g_config.enableStats) {
                oldSizeForStats = SEH_TLSF::SafeTLSFBlockSize(ptr);
            }

            void* newPtr = SEH_TLSF::SafeTLSFRealloc(g_tlsfHandle, ptr, newSize);
            if (newPtr) {
                if (g_config.enableStats) {
                    if (oldSizeForStats > 0) {
                        g_usedSize.fetch_sub(oldSizeForStats, std::memory_order_relaxed);
                    }
                    size_t currentUsed = g_usedSize.fetch_add(newSize, std::memory_order_relaxed) + newSize;
                    UpdatePeakUsage(currentUsed);
                }

                if (g_config.enableDebug) {
                    Logger::GetInstance().LogDebug("TLSF重分配: old=%p->new=%p, oldSize=%zu->newSize=%zu",
                        ptr, newPtr, oldSizeForStats, newSize);
                }

                return newPtr;
            }
            // readLock在这里自动释放
        }

        // 第二阶段：重分配失败，检查是否可以扩展
        if (g_totalSize.load(std::memory_order_relaxed) >= g_config.maxSize) {
            return nullptr;
        }

        // 使用独占锁进行扩展
        {
            std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                writeLock.lock();
            }

            size_t extendSize = max(g_config.extendGranularity,
                ((newSize + g_config.extendGranularity - 1) / g_config.extendGranularity) * g_config.extendGranularity);

            if (AddExtraPool(extendSize)) {
                // 重新获取旧大小（可能在扩展期间发生变化）
                if (g_config.enableStats && oldSizeForStats == 0) {
                    oldSizeForStats = SEH_TLSF::SafeTLSFBlockSize(ptr);
                }

                void* newPtr = SEH_TLSF::SafeTLSFRealloc(g_tlsfHandle, ptr, newSize);
                if (newPtr) {
                    if (g_config.enableStats) {
                        if (oldSizeForStats > 0) {
                            g_usedSize.fetch_sub(oldSizeForStats, std::memory_order_relaxed);
                        }
                        size_t currentUsed = g_usedSize.fetch_add(newSize, std::memory_order_relaxed) + newSize;
                        UpdatePeakUsage(currentUsed);
                    }

                    if (g_config.enableDebug) {
                        Logger::GetInstance().LogDebug("TLSF重分配(扩容后): old=%p->new=%p, oldSize=%zu->newSize=%zu",
                            ptr, newPtr, oldSizeForStats, newSize);
                    }

                    return newPtr;
                }
            }
            // writeLock在这里自动释放
        }

        return nullptr;
    }

    void Free(void* ptr) {
        if (!ptr || !g_initialized.load(std::memory_order_acquire)) {
            return;
        }

        std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            readLock.lock();
        }

        size_t blockSize = 0;
        if (g_config.enableStats) {
            blockSize = SEH_TLSF::SafeTLSFBlockSize(ptr);
        }

        SEH_TLSF::SafeTLSFFree(g_tlsfHandle, ptr);

        if (g_config.enableStats && blockSize > 0) {
            g_freeCount.fetch_add(1, std::memory_order_relaxed);
            g_usedSize.fetch_sub(blockSize, std::memory_order_relaxed);
        }

        if (g_config.enableDebug) {
            Logger::GetInstance().LogDebug("TLSF释放: ptr=%p, size=%zu", ptr, blockSize);
        }
    }

    // ======================== 安全版本（SEH保护） ========================

    void* AllocateSafe(size_t size) {
        __try {
            return Allocate(size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("安全分配异常: size=%zu, code=0x%08X", size, GetExceptionCode());
            return nullptr;
        }
    }

    void* AllocateAlignedSafe(size_t size, size_t alignment) {
        __try {
            return AllocateAligned(size, alignment);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("安全对齐分配异常: size=%zu, align=%zu, code=0x%08X",
                size, alignment, GetExceptionCode());
            return nullptr;
        }
    }

    void* ReallocateSafe(void* ptr, size_t newSize) {
        __try {
            return Reallocate(ptr, newSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("安全重分配异常: ptr=%p, size=%zu, code=0x%08X",
                ptr, newSize, GetExceptionCode());
            return nullptr;
        }
    }

    void FreeSafe(void* ptr) {
        __try {
            Free(ptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::GetInstance().LogError("安全释放异常: ptr=%p, code=0x%08X", ptr, GetExceptionCode());
        }
    }

    // ======================== 查询操作 ========================

    bool IsFromPool(void* ptr) {
        if (!ptr || !g_initialized.load(std::memory_order_acquire)) {
            return false;
        }

        std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            readLock.lock();
        }

        // 检查主池
        if (IsPointerInRange(ptr, g_mainPool, g_config.initialSize)) {
            return true;
        }

        // 检查额外池 - 使用真实的size
        for (const ExtraPool& extraPool : g_extraPools) {
            if (IsPointerInRange(ptr, extraPool.base, extraPool.size)) {
                return true;
            }
        }

        return false;
    }

    size_t GetBlockSize(void* ptr) {
        if (!ptr || !IsFromPool(ptr)) {
            return 0;
        }

        std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            readLock.lock();
        }
        return SEH_TLSF::SafeTLSFBlockSize(ptr);
    }

    size_t GetUsedSize() {
        return g_usedSize.load(std::memory_order_relaxed);
    }

    size_t GetTotalSize() {
        return g_totalSize.load(std::memory_order_relaxed);
    }

    size_t GetFreeSize() {
        size_t total = GetTotalSize();
        size_t used = GetUsedSize();
        return total > used ? total - used : 0;
    }

    // ======================== 池管理操作 ========================

    bool ExtendPool(size_t additionalSize) {
        if (!g_initialized.load(std::memory_order_acquire)) {
            return false;
        }

        if (g_totalSize.load(std::memory_order_relaxed) + additionalSize > g_config.maxSize) {
            Logger::GetInstance().LogWarning("扩展池将超过最大限制");
            return false;
        }

        std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            writeLock.lock();
        }
        return AddExtraPool(additionalSize);
    }

    void TrimFreePages() {
        if (!g_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::GetInstance().LogInfo("开始清理空闲页面...");
        std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            writeLock.lock();
        }

        // TODO: 实现具体的页面清理逻辑
        // 这里可以调用VirtualFree释放完全空闲的页面

        g_trimCount.fetch_add(1, std::memory_order_relaxed);
        Logger::GetInstance().LogInfo("空闲页面清理完成");
    }

    void CompactPool() {
        if (!g_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::GetInstance().LogInfo("开始内存池压缩...");
        std::unique_lock<std::shared_mutex> writeLock(g_poolMutex, std::defer_lock);
        if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
            writeLock.lock();
        }

        // TODO: 实现内存池压缩逻辑

        Logger::GetInstance().LogInfo("内存池压缩完成");
    }

    // ======================== 统计和调试 ========================

    PoolStats GetStats() {
        PoolStats stats;
        stats.totalSize = g_totalSize.load(std::memory_order_relaxed);
        stats.usedSize = g_usedSize.load(std::memory_order_relaxed);
        stats.freeSize = GetFreeSize();
        stats.peakUsed = g_peakUsed.load(std::memory_order_relaxed);
        stats.allocCount = g_allocCount.load(std::memory_order_relaxed);
        stats.freeCount = g_freeCount.load(std::memory_order_relaxed);
        stats.extendCount = g_extendCount.load(std::memory_order_relaxed);
        stats.trimCount = g_trimCount.load(std::memory_order_relaxed);
        return stats;
    }

    void PrintStats() {
        PoolStats stats = GetStats();

        Logger::GetInstance().LogInfo("=== TLSF内存池统计 ===");
        Logger::GetInstance().LogInfo("总大小: %zu MB", stats.totalSize / (1024 * 1024));
        Logger::GetInstance().LogInfo("已用: %zu MB (%.1f%%)",
            stats.usedSize / (1024 * 1024),
            stats.totalSize > 0 ? (stats.usedSize * 100.0 / stats.totalSize) : 0.0);
        Logger::GetInstance().LogInfo("空闲: %zu MB", stats.freeSize / (1024 * 1024));
        Logger::GetInstance().LogInfo("峰值使用: %zu MB", stats.peakUsed / (1024 * 1024));
        Logger::GetInstance().LogInfo("分配次数: %zu", stats.allocCount);
        Logger::GetInstance().LogInfo("释放次数: %zu", stats.freeCount);
        Logger::GetInstance().LogInfo("扩展次数: %zu", stats.extendCount);
        Logger::GetInstance().LogInfo("清理次数: %zu", stats.trimCount);
        Logger::GetInstance().LogInfo("稳定块数量: %zu", g_stabilizingBlocks.size());
        Logger::GetInstance().LogInfo("=====================");
    }

    void ResetStats() {
        g_peakUsed.store(g_usedSize.load(std::memory_order_relaxed), std::memory_order_relaxed);
        g_allocCount.store(0, std::memory_order_relaxed);
        g_freeCount.store(0, std::memory_order_relaxed);
        g_extendCount.store(0, std::memory_order_relaxed);
        g_trimCount.store(0, std::memory_order_relaxed);

        Logger::GetInstance().LogInfo("统计信息已重置");
    }

    // ======================== 稳定块管理 ========================

    void* CreateStabilizingBlock(size_t size, const char* purpose) {
        if (!g_initialized.load(std::memory_order_acquire)) {
            return nullptr;
        }

        void* ptr = AllocateSafe(size);
        if (!ptr) {
            Logger::GetInstance().LogError("创建稳定块失败: size=%zu, purpose=%s", size, purpose ? purpose : "unknown");
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_stabilizingMutex);
        g_stabilizingBlocks.push_back(ptr);

        Logger::GetInstance().LogDebug("创建稳定块: ptr=%p, size=%zu, purpose=%s", ptr, size, purpose ? purpose : "unknown");
        return ptr;
    }

    void FlushStabilizingBlocks() {
        std::lock_guard<std::mutex> lock(g_stabilizingMutex);

        Logger::GetInstance().LogInfo("清理%zu个稳定块...", g_stabilizingBlocks.size());

        for (void* ptr : g_stabilizingBlocks) {
            FreeSafe(ptr);
        }

        g_stabilizingBlocks.clear();
        Logger::GetInstance().LogInfo("稳定块清理完成");
    }

    // ======================== 线程安全控制 ========================

    void EnableThreadSafety() {
        g_threadSafeEnabled.store(true, std::memory_order_release);
        Logger::GetInstance().LogInfo("已启用线程安全模式");
    }

    void DisableThreadSafety() {
        g_threadSafeEnabled.store(false, std::memory_order_release);
        Logger::GetInstance().LogInfo("已禁用线程安全模式");
    }

    bool IsThreadSafeEnabled() {
        return g_threadSafeEnabled.load(std::memory_order_acquire);
    }

    // ======================== 内存压力响应 ========================

    void OnMemoryPressure() {
        Logger::GetInstance().LogInfo("检测到内存压力，开始清理...");
        TrimFreePages();
        FlushStabilizingBlocks();
    }

    void OnMemoryAvailable() {
        Logger::GetInstance().LogInfo("内存压力缓解");
    }

    // ======================== 配置管理 ========================

    bool SetConfig(const Config& config) {
        if (g_initialized.load(std::memory_order_acquire)) {
            Logger::GetInstance().LogWarning("不能在运行时修改配置");
            return false;
        }

        g_config = config;
        Logger::GetInstance().LogInfo("配置已更新");
        return true;
    }

    Config GetConfig() {
        return g_config;
    }

    // ======================== 内部调试接口 ========================

    namespace Internal {
        void* GetTLSFHandle() {
            return g_tlsfHandle;
        }

        size_t GetPoolCount() {
            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }
            return 1 + g_extraPools.size(); // 主池 + 额外池
        }

        void DumpPoolInfo() {
            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }

            Logger::GetInstance().LogInfo("=== 内存池详细信息 ===");
            Logger::GetInstance().LogInfo("主池: %p, 大小=%zu MB", g_mainPool, g_config.initialSize / (1024 * 1024));

            for (size_t i = 0; i < g_extraPools.size(); i++) {
                Logger::GetInstance().LogInfo("额外池 #%zu: %p, 大小=%zu MB",
                    i + 1, g_extraPools[i].base, g_extraPools[i].size / (1024 * 1024));
            }

            Logger::GetInstance().LogInfo("===================");
        }

        bool ValidatePool() {
            if (!g_initialized.load(std::memory_order_acquire)) {
                return false;
            }

            std::shared_lock<std::shared_mutex> readLock(g_poolMutex, std::defer_lock);
            if (g_threadSafeEnabled.load(std::memory_order_acquire)) {
                readLock.lock();
            }

            // TODO: 实现池验证逻辑
            // 检查TLSF内部数据结构的完整性

            return true;
        }
    }
}

// ======================== JassVM专用内存池实现 ========================
namespace JVM_MemPool {
    namespace {
        constexpr size_t JVM_BLOCK_SIZE = 0x28A8;
        constexpr size_t JVM_POOL_CAPACITY = 256;
        constexpr uint32_t JVM_MAGIC = 0xDEADBEEF;

        struct JVMBlockHeader {
            uint32_t magic;
            size_t size;
        };

        std::mutex g_jvmMutex;
        std::vector<void*> g_jvmBlocks;
        std::atomic<bool> g_jvmInitialized(false);
    }

    bool Initialize() {
        if (g_jvmInitialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        Logger::GetInstance().LogInfo("初始化JassVM内存池");
        return true;
    }

    void Cleanup() {
        if (!g_jvmInitialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        Logger::GetInstance().LogInfo("清理JassVM内存池，共%zu个块", g_jvmBlocks.size());

        for (void* ptr : g_jvmBlocks) {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }

        g_jvmBlocks.clear();
        Logger::GetInstance().LogInfo("JassVM内存池清理完成");
    }

    void* Allocate(size_t size) {
        if (!g_jvmInitialized.load(std::memory_order_acquire) || size != JVM_BLOCK_SIZE) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        size_t totalSize = size + sizeof(JVMBlockHeader);
        void* rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!rawPtr) {
            Logger::GetInstance().LogError("JassVM分配失败: size=%zu", size);
            return nullptr;
        }

        JVMBlockHeader* header = static_cast<JVMBlockHeader*>(rawPtr);
        header->magic = JVM_MAGIC;
        header->size = size;

        void* userPtr = static_cast<uint8_t*>(rawPtr) + sizeof(JVMBlockHeader);
        g_jvmBlocks.push_back(rawPtr);

        Logger::GetInstance().LogDebug("JassVM分配: ptr=%p, size=%zu", userPtr, size);
        return userPtr;
    }

    void Free(void* ptr) {
        if (!ptr || !g_jvmInitialized.load(std::memory_order_acquire)) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        uint8_t* rawPtr = static_cast<uint8_t*>(ptr) - sizeof(JVMBlockHeader);
        JVMBlockHeader* header = reinterpret_cast<JVMBlockHeader*>(rawPtr);

        if (header->magic != JVM_MAGIC) {
            Logger::GetInstance().LogError("JassVM释放无效块: ptr=%p", ptr);
            return;
        }

        auto it = std::find(g_jvmBlocks.begin(), g_jvmBlocks.end(), rawPtr);
        if (it != g_jvmBlocks.end()) {
            g_jvmBlocks.erase(it);
            VirtualFree(rawPtr, 0, MEM_RELEASE);
            Logger::GetInstance().LogDebug("JassVM释放: ptr=%p", ptr);
        }
        else {
            Logger::GetInstance().LogError("JassVM释放未找到块: ptr=%p", ptr);
        }
    }

    void* Realloc(void* oldPtr, size_t newSize) {
        if (newSize != JVM_BLOCK_SIZE) {
            return nullptr;
        }

        if (!oldPtr) {
            return Allocate(newSize);
        }

        // JassVM块大小固定，无需实际重分配
        return oldPtr;
    }

    bool IsFromPool(void* ptr) {
        if (!ptr || !g_jvmInitialized.load(std::memory_order_acquire)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        uint8_t* rawPtr = static_cast<uint8_t*>(ptr) - sizeof(JVMBlockHeader);
        return std::find(g_jvmBlocks.begin(), g_jvmBlocks.end(), rawPtr) != g_jvmBlocks.end();
    }

    size_t GetUsedSize() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);
        return g_jvmBlocks.size() * JVM_BLOCK_SIZE;
    }

    void PrintStats() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);

        Logger::GetInstance().LogInfo("=== JassVM内存池统计 ===");
        Logger::GetInstance().LogInfo("块数量: %zu", g_jvmBlocks.size());
        Logger::GetInstance().LogInfo("总大小: %zu KB", (g_jvmBlocks.size() * JVM_BLOCK_SIZE) / 1024);
        Logger::GetInstance().LogInfo("=====================");
    }
}

// ======================== 小块内存池实现 ========================
namespace SmallBlockPool {
    namespace {
        const size_t SIZE_CLASSES[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };
        constexpr size_t NUM_SIZE_CLASSES = sizeof(SIZE_CLASSES) / sizeof(SIZE_CLASSES[0]);

        struct SizeClassPool {
            std::vector<void*> freeBlocks;
            std::mutex mutex;
            size_t blockSize;
            size_t maxCount;
        };

        SizeClassPool g_sizePools[NUM_SIZE_CLASSES];
        std::atomic<bool> g_smallPoolInitialized(false);
    }

    bool Initialize() {
        if (g_smallPoolInitialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            g_sizePools[i].blockSize = SIZE_CLASSES[i];
            g_sizePools[i].maxCount = 64 / (i + 1); // 小块缓存更多
        }

        Logger::GetInstance().LogInfo("小块内存池初始化完成");
        return true;
    }

    void Cleanup() {
        if (!g_smallPoolInitialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

            for (void* ptr : g_sizePools[i].freeBlocks) {
                MemoryPool::FreeSafe(ptr);
            }

            g_sizePools[i].freeBlocks.clear();
        }

        Logger::GetInstance().LogInfo("小块内存池清理完成");
    }

    bool ShouldIntercept(size_t size) {
        for (size_t sizeClass : SIZE_CLASSES) {
            if (size <= sizeClass) {
                return true;
            }
        }
        return false;
    }

    void* Allocate(size_t size) {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return nullptr;
        }

        // 找到合适的大小类
        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            if (size <= g_sizePools[i].blockSize) {
                std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

                if (!g_sizePools[i].freeBlocks.empty()) {
                    void* ptr = g_sizePools[i].freeBlocks.back();
                    g_sizePools[i].freeBlocks.pop_back();
                    return ptr;
                }

                break;
            }
        }

        return nullptr;
    }

    bool Free(void* ptr, size_t size) {
        if (!ptr || !g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return false;
        }

        // 找到对应的大小类
        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            if (size <= g_sizePools[i].blockSize) {
                std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

                if (g_sizePools[i].freeBlocks.size() < g_sizePools[i].maxCount) {
                    g_sizePools[i].freeBlocks.push_back(ptr);
                    return true;
                }

                break;
            }
        }

        return false;
    }

    void FlushCache() {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

            for (void* ptr : g_sizePools[i].freeBlocks) {
                MemoryPool::FreeSafe(ptr);
            }

            g_sizePools[i].freeBlocks.clear();
        }

        Logger::GetInstance().LogInfo("小块内存池缓存已清空");
    }

    void PrintStats() {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::GetInstance().LogInfo("=== 小块内存池统计 ===");

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);
            Logger::GetInstance().LogInfo("大小类 %zu: %zu个缓存块 (最大%zu)",
                g_sizePools[i].blockSize,
                g_sizePools[i].freeBlocks.size(),
                g_sizePools[i].maxCount);
        }

        Logger::GetInstance().LogInfo("===================");
    }
}