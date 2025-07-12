// MemoryPool.h - 修复版本，统一使用MemorySafety
#pragma once

#include "pch.h"
#include "StormCommon.h"
#include "../Base/SafeExecute.h"
#include "../Base/MemorySafety.h"
#include <Windows.h>
#include <psapi.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <memory>

// 内存池统计信息
struct MemoryPoolStats {
    // 基础统计
    size_t totalAllocated = 0;
    size_t totalFreed = 0;
    size_t currentInUse = 0;
    size_t peakUsage = 0;
    size_t allocCount = 0;
    size_t freeCount = 0;
    size_t reallocCount = 0;

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
        const std::atomic<size_t>& hits,
        const std::atomic<size_t>& misses,
        const std::atomic<size_t>& stormCleanups,
        const std::atomic<size_t>& pressureClnps
    );

    void Reset() noexcept;
};

// 内存池配置参数
struct MemoryPoolConfig {
    size_t bigBlockThreshold = 128 * 1024;        // 大块阈值：128KB
    size_t memoryWatermarkMB = 1400;              // 内存水位：1.4GB
    size_t maxCacheSizeMB = 256;                  // 最大缓存：256MB
    DWORD holdBufferTimeMs = 500;                 // 缓冲时间：500ms
    DWORD cleanupIntervalMs = 10000;              // 清理间隔：10秒
    DWORD statsIntervalMs = 30000;                // 统计间隔：30秒
    bool enablePeriodicCleanup = true;            // 启用定期清理
    bool enableMemoryPressureMonitoring = true;   // 启用内存压力监控
    bool enableDetailedLogging = false;           // 启用详细日志
};

// JassVM专用内存池（基于MemorySafety实现）
namespace JVM_MemPool {
    void Initialize();
    void* Allocate(std::size_t size);
    void Free(void* p);
    void* Realloc(void* oldPtr, std::size_t newSize);
    bool IsFromPool(void* p);
    void Cleanup();
}

// 小块内存池（基于MemorySafety实现）  
namespace SmallBlockPool {
    void Initialize();
    bool ShouldIntercept(std::size_t size);
    void* Allocate(std::size_t size);
    bool Free(void* ptr, std::size_t size);
}

// 主内存池类
class MemoryPool {
public:
    // 获取单例实例
    static MemoryPool& GetInstance() noexcept;

    // 生命周期管理
    bool Initialize(const MemoryPoolConfig& config = {}) noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept;

    // 主要内存操作接口
    void* Allocate(size_t size, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool Free(void* ptr) noexcept;
    void* Realloc(void* oldPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 安全版本（在不安全期间使用备选策略）
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
    void* InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept;
    bool InternalFree(void* ptr, bool useFallback) noexcept;
    void* InternalRealloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept;

    // 后台任务
    void StartBackgroundTasks() noexcept;
    void StopBackgroundTasks() noexcept;
    void BackgroundTaskLoop() noexcept;

    // 内存监控
    void UpdateMemoryStats(size_t allocSize, bool isAllocation) noexcept;
    void CheckAndTriggerCleanup() noexcept;
    bool IsMemoryUnderPressure() const noexcept;

    // 日志记录
    void LogMessage(const char* format, ...) const noexcept;
    void LogError(const char* format, ...) const noexcept;
    void LogDebug(const char* format, ...) const noexcept;

private:
    // 初始化状态
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_shutdownRequested;

    // 配置参数
    MemoryPoolConfig m_config;
    mutable CRITICAL_SECTION m_configCs;

    // 核心内存管理器引用
    MemorySafety& m_memorySafety;

    // Storm函数指针
    StormHeap_CleanupAll_t m_stormCleanupFunc;

    // 统计信息（原子变量，避免拷贝构造问题）
    std::atomic<size_t> m_totalAllocated;
    std::atomic<size_t> m_totalFreed;
    std::atomic<size_t> m_currentInUse;
    std::atomic<size_t> m_peakUsage;
    std::atomic<size_t> m_allocCount;
    std::atomic<size_t> m_freeCount;
    std::atomic<size_t> m_reallocCount;
    std::atomic<size_t> m_cacheHits;
    std::atomic<size_t> m_cacheMisses;
    std::atomic<size_t> m_stormCleanupTriggers;
    std::atomic<size_t> m_pressureCleanups;

    // 后台任务
    std::unique_ptr<std::thread> m_backgroundThread;
    std::atomic<bool> m_backgroundTaskRunning;
    CRITICAL_SECTION m_backgroundCs;

    // 最后清理时间（避免频繁清理）
    std::atomic<DWORD> m_lastCleanupTime;
    std::atomic<DWORD> m_lastStormCleanupTime;
    std::atomic<DWORD> m_lastStatsTime;

    // 日志文件
    mutable CRITICAL_SECTION m_logCs;
    HANDLE m_logFile;
};

// 全局访问宏
#define g_MemoryPool MemoryPool::GetInstance()

// 便利函数（保持与原MemPool命名空间兼容）
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

// 工具函数
namespace MemoryPoolUtils {
    // 获取系统内存信息
    size_t GetProcessVirtualMemoryUsage() noexcept;
    size_t GetProcessWorkingSetSize() noexcept;
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