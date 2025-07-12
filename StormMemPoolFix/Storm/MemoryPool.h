// MemoryPool.h - 基于修复后MemorySafety的简化版本
#pragma once

#include "pch.h"
#include "StormCommon.h"
#include "../Base/SafeExecute.h"
#include "../Base/MemorySafety.h"
#include <Windows.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <memory>

///////////////////////////////////////////////////////////////////////////////
// 简化的小块内存池（用于小于大块阈值的分配）
///////////////////////////////////////////////////////////////////////////////

namespace SmallBlockPool {
    constexpr size_t SMALL_BLOCK_SIZES[] = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };
    constexpr size_t SMALL_BLOCK_COUNT = sizeof(SMALL_BLOCK_SIZES) / sizeof(SMALL_BLOCK_SIZES[0]);

    bool Initialize() noexcept;
    void Shutdown() noexcept;
    bool ShouldIntercept(size_t size) noexcept;
    void* Allocate(size_t size) noexcept;
    bool Free(void* ptr, size_t size) noexcept;
    void* Realloc(void* ptr, size_t oldSize, size_t newSize) noexcept;
}

///////////////////////////////////////////////////////////////////////////////
// JassVM专用内存池（保持兼容性）
///////////////////////////////////////////////////////////////////////////////

namespace JVM_MemPool {
    constexpr size_t JVM_BLOCK_SIZE = 0x28A8;  // JassVM特定大小

    bool Initialize() noexcept;
    void Shutdown() noexcept;
    void* Allocate(size_t size) noexcept;
    void Free(void* ptr) noexcept;
    void* Realloc(void* oldPtr, size_t newSize) noexcept;
    bool IsFromPool(void* ptr) noexcept;
    void Cleanup() noexcept;
}

///////////////////////////////////////////////////////////////////////////////
// 内存池统计信息
///////////////////////////////////////////////////////////////////////////////

struct MemoryPoolStats {
    // 基础统计
    size_t totalAllocated = 0;
    size_t totalFreed = 0;
    size_t currentInUse = 0;
    size_t peakUsage = 0;
    size_t allocCount = 0;
    size_t freeCount = 0;
    size_t reallocCount = 0;

    // 分配策略统计
    size_t smallBlockCount = 0;    // 小块分配次数
    size_t largeBlockCount = 0;    // 大块分配次数
    size_t jvmBlockCount = 0;      // JVM块分配次数
    size_t stormFallbackCount = 0; // Storm回退次数

    // 缓存统计
    size_t cacheHits = 0;
    size_t cacheMisses = 0;
    size_t stormCleanupTriggers = 0;
    size_t pressureCleanups = 0;

    // 从原子变量复制数据的辅助方法
    static MemoryPoolStats FromAtomics(
        const std::atomic<size_t>& alloc,
        const std::atomic<size_t>& freed,
        const std::atomic<size_t>& inUse,
        const std::atomic<size_t>& peak,
        const std::atomic<size_t>& allocCnt,
        const std::atomic<size_t>& freeCnt,
        const std::atomic<size_t>& reallocCnt,
        const std::atomic<size_t>& smallCnt,
        const std::atomic<size_t>& largeCnt,
        const std::atomic<size_t>& jvmCnt,
        const std::atomic<size_t>& stormCnt,
        const std::atomic<size_t>& hits,
        const std::atomic<size_t>& misses,
        const std::atomic<size_t>& stormCleanups,
        const std::atomic<size_t>& pressureClnps
    ) noexcept;

    void Reset() noexcept;
};

///////////////////////////////////////////////////////////////////////////////
// 内存池配置参数
///////////////////////////////////////////////////////////////////////////////

struct MemoryPoolConfig {
    size_t bigBlockThreshold = 8192;              // 8KB以上使用MemorySafety管理
    size_t workingSetLimitMB = 1200;              // 工作集限制：1.2GB
    size_t maxCacheSizeMB = 64;                   // 最大缓存：64MB
    DWORD holdBufferTimeMs = 2000;                // 缓冲时间：2秒
    DWORD cleanupIntervalMs = 15000;              // 清理间隔：15秒
    DWORD statsIntervalMs = 30000;                // 统计间隔：30秒
    bool enablePeriodicCleanup = true;            // 启用定期清理
    bool enableMemoryPressureMonitoring = true;   // 启用内存压力监控
    bool enableDetailedLogging = false;           // 启用详细日志
    bool enableSmallBlockPool = true;             // 启用小块池
    bool enableJVMPool = true;                    // 启用JVM池
};

///////////////////////////////////////////////////////////////////////////////
// 主内存池类 - 简化版本
///////////////////////////////////////////////////////////////////////////////

class MemoryPool {
public:
    // 获取单例实例
    static MemoryPool& GetInstance() noexcept;

    // 生命周期管理
    bool Initialize(const MemoryPoolConfig& config = {}) noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept { return m_initialized.load(); }

    // 主要内存操作接口
    void* Allocate(size_t size, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool Free(void* ptr) noexcept;
    void* Realloc(void* oldPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 安全版本（在不安全期间使用保守策略）
    void* AllocateSafe(size_t size, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool FreeSafe(void* ptr) noexcept;
    void* ReallocSafe(void* oldPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 块验证和查询
    bool IsFromPool(void* ptr) const noexcept;
    size_t GetBlockSize(void* ptr) const noexcept;
    bool IsLargeBlock(size_t size) const noexcept;

    // 内存压力管理
    void CheckMemoryPressure() noexcept;
    void ForceCleanup() noexcept;
    void TriggerStormCleanup() noexcept;

    // 配置管理
    void UpdateConfig(const MemoryPoolConfig& config) noexcept;
    MemoryPoolConfig GetConfig() const noexcept;
    void SetStormCleanupFunction(StormHeap_CleanupAll_t func) noexcept;

    // 统计信息
    MemoryPoolStats GetStats() const noexcept;
    void PrintStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // 手动触发处理
    void ProcessHoldQueue() noexcept;
    void RunPeriodicTasks() noexcept;

    // 获取内存使用信息
    size_t GetCurrentMemoryUsage() const noexcept;
    size_t GetPeakMemoryUsage() const noexcept;
    size_t GetCacheSize() const noexcept;
    double GetCacheHitRate() const noexcept;

private:
    MemoryPool() noexcept;
    ~MemoryPool() noexcept;

    // 禁止拷贝
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;

    // 内部实现
    void* InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine, bool useSafeMode) noexcept;
    bool InternalFree(void* ptr, bool useSafeMode) noexcept;
    void* InternalRealloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine, bool useSafeMode) noexcept;

    // 分配策略选择
    enum class AllocationStrategy {
        SmallBlock,    // 小块池
        JVMBlock,      // JVM池
        LargeBlock,    // MemorySafety大块
        StormFallback  // Storm原生回退
    };

    AllocationStrategy SelectStrategy(size_t size, const char* sourceName) const noexcept;

    // 后台任务
    void StartBackgroundTasks() noexcept;
    void StopBackgroundTasks() noexcept;
    void BackgroundTaskLoop() noexcept;

    // 内存监控
    void UpdateMemoryStats(size_t size, bool isAllocation, AllocationStrategy strategy) noexcept;
    bool IsMemoryUnderPressure() const noexcept;

    // 日志记录
    void LogMessage(const char* format, ...) const noexcept;
    void LogError(const char* format, ...) const noexcept;
    void LogDebug(const char* format, ...) const noexcept;

private:
    // 初始化状态
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    // 配置参数
    MemoryPoolConfig m_config;
    mutable std::mutex m_configMutex;

    // 核心内存管理器引用
    MemorySafety& m_memorySafety;

    // Storm函数指针
    StormHeap_CleanupAll_t m_stormCleanupFunc{ nullptr };

    // 统计信息（原子变量，避免拷贝构造问题）
    std::atomic<size_t> m_totalAllocated{ 0 };
    std::atomic<size_t> m_totalFreed{ 0 };
    std::atomic<size_t> m_currentInUse{ 0 };
    std::atomic<size_t> m_peakUsage{ 0 };
    std::atomic<size_t> m_allocCount{ 0 };
    std::atomic<size_t> m_freeCount{ 0 };
    std::atomic<size_t> m_reallocCount{ 0 };

    // 分配策略统计
    std::atomic<size_t> m_smallBlockCount{ 0 };
    std::atomic<size_t> m_largeBlockCount{ 0 };
    std::atomic<size_t> m_jvmBlockCount{ 0 };
    std::atomic<size_t> m_stormFallbackCount{ 0 };

    std::atomic<size_t> m_cacheHits{ 0 };
    std::atomic<size_t> m_cacheMisses{ 0 };
    std::atomic<size_t> m_stormCleanupTriggers{ 0 };
    std::atomic<size_t> m_pressureCleanups{ 0 };

    // 后台任务
    std::unique_ptr<std::thread> m_backgroundThread;
    std::atomic<bool> m_backgroundTaskRunning{ false };
    std::mutex m_backgroundMutex;
    std::condition_variable m_backgroundCondition;

    // 最后执行时间（避免频繁操作）
    std::atomic<DWORD> m_lastCleanupTime{ 0 };
    std::atomic<DWORD> m_lastStormCleanupTime{ 0 };
    std::atomic<DWORD> m_lastStatsTime{ 0 };

    // 日志文件
    mutable std::mutex m_logMutex;
    HANDLE m_logFile{ INVALID_HANDLE_VALUE };
};

// 全局访问宏
#define g_MemoryPool MemoryPool::GetInstance()

///////////////////////////////////////////////////////////////////////////////
// 便利函数（保持与原MemPool命名空间兼容）
///////////////////////////////////////////////////////////////////////////////

namespace MemPool {
    // 初始化和清理
    bool Initialize(size_t initialSize = 0) noexcept;
    void Shutdown() noexcept;

    // 基本内存操作
    void* Allocate(size_t size) noexcept;
    void Free(void* ptr) noexcept;
    void* Realloc(void* oldPtr, size_t newSize) noexcept;

    // 安全版本
    void* AllocateSafe(size_t size) noexcept;
    void FreeSafe(void* ptr) noexcept;
    void* ReallocSafe(void* oldPtr, size_t newSize) noexcept;

    // 查询函数
    bool IsFromPool(void* ptr) noexcept;
    size_t GetUsedSize() noexcept;
    size_t GetTotalSize() noexcept;

    // 统计和维护
    void PrintStats() noexcept;
    void CheckAndFreeUnusedPools() noexcept;
    void DisableActualFree() noexcept;
    void DisableMemoryReleasing() noexcept;

    // 稳定化块创建（向后兼容）
    void* CreateStabilizingBlock(size_t size, const char* purpose) noexcept;
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

namespace MemoryPoolUtils {
    // 获取系统内存信息（使用MemorySafety的实现）
    size_t GetProcessWorkingSetSize() noexcept;
    size_t GetProcessCommittedSize() noexcept;
    size_t GetProcessVirtualSize() noexcept;
    size_t GetSystemMemoryPressure() noexcept;

    // 地址验证
    bool IsValidPointer(void* ptr) noexcept;
    bool IsValidMemoryRange(void* ptr, size_t size) noexcept;

    // 大小对齐
    size_t AlignSize(size_t size, size_t alignment = 16) noexcept;
    size_t GetPageAlignedSize(size_t size) noexcept;

    // 时间相关
    DWORD GetTickCount() noexcept;
    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept;
}