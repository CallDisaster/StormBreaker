// MemoryPool.cpp - 修复版本，统一使用MemorySafety
#include "pch.h"
#include "MemoryPool.h"
#include "StormCommon.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <algorithm>
#include <cassert>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

// 常量定义
namespace {
    constexpr size_t JVM_BLOCK_SIZE = 0x28A8;
    constexpr size_t SMALL_BLOCK_SIZES[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };
    constexpr size_t SMALL_BLOCK_COUNT = sizeof(SMALL_BLOCK_SIZES) / sizeof(SMALL_BLOCK_SIZES[0]);
    constexpr DWORD MIN_CLEANUP_INTERVAL = 5000;
    constexpr DWORD MIN_STORM_CLEANUP_INTERVAL = 15000;
}

///////////////////////////////////////////////////////////////////////////////
// JVM内存池实现（基于MemorySafety）
///////////////////////////////////////////////////////////////////////////////

namespace JVM_MemPool {
    static std::atomic<bool> s_initialized{ false };
    static std::atomic<size_t> s_allocatedCount{ 0 };

    void Initialize() {
        s_initialized.store(true);
        LogMessage("[JVM_MemPool] 初始化完成，使用MemorySafety后端");
    }

    void* Allocate(std::size_t size) {
        if (size != JVM_BLOCK_SIZE) {
            return nullptr;
        }

        // 使用MemorySafety分配，而不是VirtualAlloc
        void* ptr = g_MemorySafety.AllocateBlock(size, "JVM_MemPool", 0);
        if (ptr) {
            s_allocatedCount.fetch_add(1);
            // 可以设置一些特殊的标记来识别JVM块
            memset(ptr, 0, size);
        }

        return ptr;
    }

    void Free(void* p) {
        if (!p) return;

        if (g_MemorySafety.IsOurBlock(p)) {
            g_MemorySafety.FreeBlock(p);
            s_allocatedCount.fetch_sub(1);
        }
    }

    void* Realloc(void* oldPtr, std::size_t newSize) {
        if (!oldPtr) {
            return Allocate(newSize);
        }

        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        if (newSize == JVM_BLOCK_SIZE) {
            return oldPtr; // 同样大小，直接返回
        }

        // 使用MemorySafety的重分配
        return g_MemorySafety.ReallocateBlock(oldPtr, newSize, "JVM_MemPool", 0);
    }

    bool IsFromPool(void* p) {
        if (!p || !s_initialized.load()) {
            return false;
        }

        // 检查是否是MemorySafety管理的块，且大小为JVM_BLOCK_SIZE
        if (g_MemorySafety.IsOurBlock(p)) {
            size_t blockSize = g_MemorySafety.GetBlockSize(p);
            return blockSize == JVM_BLOCK_SIZE;
        }

        return false;
    }

    void Cleanup() {
        size_t leakedBlocks = s_allocatedCount.load();
        if (leakedBlocks > 0) {
            LogMessage("[JVM_MemPool] 清理完成，检测到%zu个可能泄漏的块", leakedBlocks);
        }
        s_allocatedCount.store(0);
        s_initialized.store(false);
    }
}

///////////////////////////////////////////////////////////////////////////////
// 小块内存池实现（基于MemorySafety）
///////////////////////////////////////////////////////////////////////////////

namespace SmallBlockPool {
    static std::atomic<bool> s_initialized{ false };

    void Initialize() {
        s_initialized.store(true);
        LogMessage("[SmallBlockPool] 初始化完成，使用MemorySafety后端");
    }

    bool ShouldIntercept(std::size_t size) {
        for (size_t blockSize : SMALL_BLOCK_SIZES) {
            if (size <= blockSize) return true; // 改为<=，允许更好的匹配
        }
        return false;
    }

    void* Allocate(std::size_t size) {
        if (!ShouldIntercept(size)) {
            return nullptr;
        }

        // 关键修复：使用MemorySafety分配，而不是VirtualAlloc！
        void* ptr = g_MemorySafety.AllocateBlock(size, "SmallBlockPool", 0);

        return ptr; // MemorySafety已经处理了Storm头部
    }

    bool Free(void* ptr, std::size_t size) {
        if (!ptr || !ShouldIntercept(size)) {
            return false;
        }

        // 检查是否是我们管理的块
        if (g_MemorySafety.IsOurBlock(ptr)) {
            return g_MemorySafety.FreeBlock(ptr);
        }

        return false;
    }
}

///////////////////////////////////////////////////////////////////////////////
// MemoryPoolStats实现
///////////////////////////////////////////////////////////////////////////////

MemoryPoolStats MemoryPoolStats::FromAtomics(
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
) {
    MemoryPoolStats stats;
    stats.totalAllocated = alloc.load();
    stats.totalFreed = freed.load();
    stats.currentInUse = inUse.load();
    stats.peakUsage = peak.load();
    stats.allocCount = allocCnt.load();
    stats.freeCount = freeCnt.load();
    stats.reallocCount = reallocCnt.load();
    stats.cacheHits = hits.load();
    stats.cacheMisses = misses.load();
    stats.stormCleanupTriggers = stormCleanups.load();
    stats.pressureCleanups = pressureClnps.load();
    return stats;
}

void MemoryPoolStats::Reset() noexcept {
    totalAllocated = 0;
    totalFreed = 0;
    currentInUse = 0;
    peakUsage = 0;
    allocCount = 0;
    freeCount = 0;
    reallocCount = 0;
    cacheHits = 0;
    cacheMisses = 0;
    stormCleanupTriggers = 0;
    pressureCleanups = 0;
}

///////////////////////////////////////////////////////////////////////////////
// MemoryPool实现
///////////////////////////////////////////////////////////////////////////////

MemoryPool& MemoryPool::GetInstance() noexcept {
    static MemoryPool instance;
    return instance;
}

MemoryPool::MemoryPool() noexcept
    : m_initialized(false), m_shutdownRequested(false),
    m_memorySafety(MemorySafety::GetInstance()),
    m_stormCleanupFunc(nullptr),
    m_totalAllocated(0), m_totalFreed(0), m_currentInUse(0), m_peakUsage(0),
    m_allocCount(0), m_freeCount(0), m_reallocCount(0),
    m_cacheHits(0), m_cacheMisses(0), m_stormCleanupTriggers(0), m_pressureCleanups(0),
    m_backgroundTaskRunning(false),
    m_lastCleanupTime(0), m_lastStormCleanupTime(0), m_lastStatsTime(0),
    m_logFile(INVALID_HANDLE_VALUE) {

    InitializeCriticalSection(&m_configCs);
    InitializeCriticalSection(&m_backgroundCs);
    InitializeCriticalSection(&m_logCs);
}

MemoryPool::~MemoryPool() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
    DeleteCriticalSection(&m_configCs);
    DeleteCriticalSection(&m_backgroundCs);
    DeleteCriticalSection(&m_logCs);
}

bool MemoryPool::Initialize(const MemoryPoolConfig& config) noexcept {
    bool expected = false;
    if (!m_initialized.compare_exchange_strong(expected, true)) {
        return true; // 已初始化
    }

    // 保存配置
    EnterCriticalSection(&m_configCs);
    m_config = config;
    LeaveCriticalSection(&m_configCs);

    // 初始化日志文件
    m_logFile = CreateFileA(
        "MemoryPool.log",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    LogMessage("[MemoryPool] 初始化开始");

    // 首先初始化MemorySafety
    MemorySafetyConfig safetyConfig;
    safetyConfig.holdBufferTimeMs = m_config.holdBufferTimeMs;
    safetyConfig.memoryWatermarkMB = m_config.memoryWatermarkMB;
    safetyConfig.enableDetailedLogging = m_config.enableDetailedLogging;

    if (!m_memorySafety.Initialize(safetyConfig)) {
        LogError("[MemoryPool] MemorySafety初始化失败");
        m_initialized.store(false);
        return false;
    }

    // 初始化兼容池（现在都基于MemorySafety）
    JVM_MemPool::Initialize();
    SmallBlockPool::Initialize();

    // 启动后台任务
    StartBackgroundTasks();

    // 重置统计
    ResetStatistics();

    LogMessage("[MemoryPool] 初始化完成，所有分配现在使用TLSF池");
    return true;
}

void MemoryPool::Shutdown() noexcept {
    bool expected = true;
    if (!m_initialized.compare_exchange_strong(expected, false)) {
        return; // 已关闭
    }

    LogMessage("[MemoryPool] 开始关闭");

    // 停止后台任务
    StopBackgroundTasks();

    // 强制处理剩余的Hold队列
    m_memorySafety.DrainHoldQueue();

    // 打印最终统计
    PrintStatistics();

    // 清理兼容池
    JVM_MemPool::Cleanup();

    // 关闭MemorySafety
    m_memorySafety.Shutdown();

    // 关闭日志文件
    if (m_logFile != INVALID_HANDLE_VALUE) {
        LogMessage("[MemoryPool] 关闭完成");
        CloseHandle(m_logFile);
        m_logFile = INVALID_HANDLE_VALUE;
    }
}

bool MemoryPool::IsInitialized() const noexcept {
    return m_initialized.load();
}

///////////////////////////////////////////////////////////////////////////////
// 内存分配接口
///////////////////////////////////////////////////////////////////////////////

void* MemoryPool::Allocate(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    return InternalAllocate(size, sourceName, sourceLine, false);
}

void* MemoryPool::AllocateSafe(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    return InternalAllocate(size, sourceName, sourceLine, true);
}

bool MemoryPool::Free(void* ptr) noexcept {
    return InternalFree(ptr, false);
}

bool MemoryPool::FreeSafe(void* ptr) noexcept {
    return InternalFree(ptr, true);
}

void* MemoryPool::Realloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    return InternalRealloc(oldPtr, newSize, sourceName, sourceLine, false);
}

void* MemoryPool::ReallocSafe(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    return InternalRealloc(oldPtr, newSize, sourceName, sourceLine, true);
}

///////////////////////////////////////////////////////////////////////////////
// 内部实现
///////////////////////////////////////////////////////////////////////////////

void* MemoryPool::InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept {
    if (!m_initialized.load()) {
        return nullptr;
    }

    m_allocCount.fetch_add(1);

    // 特殊处理JVM块
    if (size == JVM_BLOCK_SIZE) {
        void* jvmPtr = JVM_MemPool::Allocate(size);
        if (jvmPtr) {
            UpdateMemoryStats(size, true);
            m_cacheHits.fetch_add(1); // JVM池算命中
            if (m_config.enableDetailedLogging) {
                LogDebug("[MemoryPool] JVM分配: %p, 大小:%zu", jvmPtr, size);
            }
            return jvmPtr;
        }
    }

    // 小块处理
    if (SmallBlockPool::ShouldIntercept(size)) {
        void* smallPtr = SmallBlockPool::Allocate(size);
        if (smallPtr) {
            UpdateMemoryStats(size, true);
            m_cacheHits.fetch_add(1); // 小块池算命中
            if (m_config.enableDetailedLogging) {
                LogDebug("[MemoryPool] 小块分配: %p, 大小:%zu", smallPtr, size);
            }
            return smallPtr;
        }
    }

    // 大块处理 - 直接使用MemorySafety
    if (IsLargeBlock(size)) {
        void* largePtr = m_memorySafety.AllocateBlock(size, sourceName, sourceLine);
        if (largePtr) {
            m_cacheHits.fetch_add(1);
            UpdateMemoryStats(size, true);
            if (m_config.enableDetailedLogging) {
                LogDebug("[MemoryPool] 大块分配: %p, 大小:%zu, 来源:%s:%u",
                    largePtr, size, sourceName ? sourceName : "null", sourceLine);
            }
            return largePtr;
        }
        m_cacheMisses.fetch_add(1);
    }

    // 最后回退：也使用MemorySafety，但不分类
    if (useFallback) {
        void* fallbackPtr = m_memorySafety.AllocateBlock(size, sourceName, sourceLine);
        if (fallbackPtr) {
            UpdateMemoryStats(size, true);
            LogMessage("[MemoryPool] 回退分配: %p, 大小:%zu", fallbackPtr, size);
            return fallbackPtr;
        }
    }

    LogError("[MemoryPool] 分配失败: 大小:%zu, 来源:%s:%u",
        size, sourceName ? sourceName : "null", sourceLine);
    return nullptr;
}

bool MemoryPool::InternalFree(void* ptr, bool useFallback) noexcept {
    if (!ptr || !m_initialized.load()) {
        return false;
    }

    m_freeCount.fetch_add(1);

    // 检查JVM池
    if (JVM_MemPool::IsFromPool(ptr)) {
        JVM_MemPool::Free(ptr);
        UpdateMemoryStats(JVM_BLOCK_SIZE, false);
        if (m_config.enableDetailedLogging) {
            LogDebug("[MemoryPool] JVM释放: %p", ptr);
        }
        return true;
    }

    // 检查是否是MemorySafety管理的块
    if (m_memorySafety.IsOurBlock(ptr)) {
        size_t blockSize = m_memorySafety.GetBlockSize(ptr);
        bool success = m_memorySafety.FreeBlock(ptr);
        if (success) {
            UpdateMemoryStats(blockSize, false);
            if (m_config.enableDetailedLogging) {
                // 判断是小块还是大块
                if (SmallBlockPool::ShouldIntercept(blockSize)) {
                    LogDebug("[MemoryPool] 小块释放: %p, 大小:%zu", ptr, blockSize);
                }
                else {
                    LogDebug("[MemoryPool] 大块释放: %p, 大小:%zu", ptr, blockSize);
                }
            }
            return true;
        }
    }

    LogError("[MemoryPool] 释放失败: %p", ptr);
    return false;
}

void* MemoryPool::InternalRealloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept {
    if (!m_initialized.load()) {
        return nullptr;
    }

    m_reallocCount.fetch_add(1);

    if (!oldPtr) {
        return InternalAllocate(newSize, sourceName, sourceLine, useFallback);
    }

    if (newSize == 0) {
        InternalFree(oldPtr, useFallback);
        return nullptr;
    }

    // JVM池处理
    if (JVM_MemPool::IsFromPool(oldPtr)) {
        void* newPtr = JVM_MemPool::Realloc(oldPtr, newSize);
        if (newPtr && m_config.enableDetailedLogging) {
            LogDebug("[MemoryPool] JVM重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
        }
        return newPtr;
    }

    // MemorySafety管理的块
    if (m_memorySafety.IsOurBlock(oldPtr)) {
        void* newPtr = m_memorySafety.ReallocateBlock(oldPtr, newSize, sourceName, sourceLine);
        if (newPtr) {
            if (m_config.enableDetailedLogging) {
                if (SmallBlockPool::ShouldIntercept(newSize)) {
                    LogDebug("[MemoryPool] 小块重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
                }
                else {
                    LogDebug("[MemoryPool] 大块重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
                }
            }
            return newPtr;
        }
    }

    // 回退策略：分配新块，复制数据，释放旧块
    if (useFallback) {
        void* newPtr = InternalAllocate(newSize, sourceName, sourceLine, true);
        if (newPtr) {
            // 尝试复制数据（保守大小）
            size_t oldSize = m_memorySafety.GetBlockSize(oldPtr);
            if (oldSize == 0) oldSize = 1024; // 保守估计

            size_t copySize = (oldSize < newSize) ? oldSize : newSize;
            memcpy(newPtr, oldPtr, copySize);

            InternalFree(oldPtr, true);
            LogMessage("[MemoryPool] 回退重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
            return newPtr;
        }
    }

    LogError("[MemoryPool] 重分配失败: %p, 大小:%zu", oldPtr, newSize);
    return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// 块验证和查询
///////////////////////////////////////////////////////////////////////////////

bool MemoryPool::IsFromPool(void* ptr) const noexcept {
    if (!ptr || !m_initialized.load()) {
        return false;
    }

    return JVM_MemPool::IsFromPool(ptr) || m_memorySafety.IsOurBlock(ptr);
}

size_t MemoryPool::GetBlockSize(void* ptr) const noexcept {
    if (!ptr || !m_initialized.load()) {
        return 0;
    }

    if (JVM_MemPool::IsFromPool(ptr)) {
        return JVM_BLOCK_SIZE;
    }

    return m_memorySafety.GetBlockSize(ptr);
}

bool MemoryPool::IsLargeBlock(size_t size) const noexcept {
    EnterCriticalSection(&m_configCs);
    bool isLarge = size >= m_config.bigBlockThreshold;
    LeaveCriticalSection(&m_configCs);
    return isLarge;
}

///////////////////////////////////////////////////////////////////////////////
// 内存压力管理
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::CheckMemoryPressure() noexcept {
    if (!m_config.enableMemoryPressureMonitoring) {
        return;
    }

    DWORD currentTime = MemoryPoolUtils::GetTickCount();
    DWORD lastCleanup = m_lastCleanupTime.load();

    if (currentTime - lastCleanup < MIN_CLEANUP_INTERVAL) {
        return; // 太频繁
    }

    if (IsMemoryUnderPressure()) {
        LogMessage("[MemoryPool] 检测到内存压力，触发清理");
        ForceCleanup();
        m_pressureCleanups.fetch_add(1);
    }
}

void MemoryPool::ForceCleanup() noexcept {
    LogMessage("[MemoryPool] 开始强制清理");

    DWORD currentTime = MemoryPoolUtils::GetTickCount();
    m_lastCleanupTime.store(currentTime);

    // 清理MemorySafety缓存
    m_memorySafety.ForceCleanup();

    // 触发Storm清理
    TriggerStormCleanup();

    LogMessage("[MemoryPool] 强制清理完成");
}

void MemoryPool::TriggerStormCleanup() noexcept {
    if (!m_stormCleanupFunc) {
        return;
    }

    DWORD currentTime = MemoryPoolUtils::GetTickCount();
    DWORD lastStormCleanup = m_lastStormCleanupTime.load();

    if (currentTime - lastStormCleanup < MIN_STORM_CLEANUP_INTERVAL) {
        return; // 避免太频繁调用Storm清理
    }

    LogMessage("[MemoryPool] 触发Storm清理");
    m_lastStormCleanupTime.store(currentTime);

    __try {
        m_stormCleanupFunc();
        m_stormCleanupTriggers.fetch_add(1);
        LogMessage("[MemoryPool] Storm清理完成");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogError("[MemoryPool] Storm清理异常: 0x%08X", GetExceptionCode());
    }
}

///////////////////////////////////////////////////////////////////////////////
// 后台任务
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::StartBackgroundTasks() noexcept {
    bool expected = false;
    if (!m_backgroundTaskRunning.compare_exchange_strong(expected, true)) {
        return; // 已在运行
    }

    m_backgroundThread = std::make_unique<std::thread>(&MemoryPool::BackgroundTaskLoop, this);
    LogMessage("[MemoryPool] 后台任务已启动");
}

void MemoryPool::StopBackgroundTasks() noexcept {
    m_shutdownRequested.store(true);
    m_backgroundTaskRunning.store(false);

    if (m_backgroundThread && m_backgroundThread->joinable()) {
        m_backgroundThread->join();
    }

    LogMessage("[MemoryPool] 后台任务已停止");
}

void MemoryPool::BackgroundTaskLoop() noexcept {
    LogMessage("[MemoryPool] 后台任务循环开始");

    while (m_backgroundTaskRunning.load() && !m_shutdownRequested.load()) {
        try {
            // 等待一段时间
            std::this_thread::sleep_for(std::chrono::milliseconds(m_config.cleanupIntervalMs));

            if (m_shutdownRequested.load()) {
                break;
            }

            // 执行定期任务
            RunPeriodicTasks();
        }
        catch (...) {
            LogError("[MemoryPool] 后台任务异常");
        }
    }

    LogMessage("[MemoryPool] 后台任务循环结束");
}

void MemoryPool::RunPeriodicTasks() noexcept {
    DWORD currentTime = MemoryPoolUtils::GetTickCount();

    // 处理Hold队列
    if (m_config.enablePeriodicCleanup) {
        ProcessHoldQueue();
    }

    // 内存压力检查
    CheckMemoryPressure();

    // 定期统计报告
    DWORD lastStats = m_lastStatsTime.load();
    if (currentTime - lastStats >= m_config.statsIntervalMs) {
        m_lastStatsTime.store(currentTime);

        if (m_config.enableDetailedLogging) {
            PrintStatistics();
        }
    }
}

void MemoryPool::ProcessHoldQueue() noexcept {
    m_memorySafety.ProcessHoldQueue();
}

///////////////////////////////////////////////////////////////////////////////
// 统计和配置
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::UpdateMemoryStats(size_t size, bool isAllocation) noexcept {
    if (isAllocation) {
        m_totalAllocated.fetch_add(size);
        m_currentInUse.fetch_add(size);

        // 更新峰值
        size_t currentUsage = m_currentInUse.load();
        size_t peakUsage = m_peakUsage.load();
        while (currentUsage > peakUsage) {
            if (m_peakUsage.compare_exchange_weak(peakUsage, currentUsage)) {
                break;
            }
        }
    }
    else {
        m_totalFreed.fetch_add(size);
        m_currentInUse.fetch_sub(size);
    }
}

bool MemoryPool::IsMemoryUnderPressure() const noexcept {
    size_t currentVM = MemoryPoolUtils::GetProcessVirtualMemoryUsage();

    EnterCriticalSection(&m_configCs);
    size_t watermarkBytes = m_config.memoryWatermarkMB * 1024 * 1024;
    LeaveCriticalSection(&m_configCs);

    return currentVM > watermarkBytes;
}

MemoryPoolStats MemoryPool::GetStats() const noexcept {
    return MemoryPoolStats::FromAtomics(
        m_totalAllocated, m_totalFreed, m_currentInUse, m_peakUsage,
        m_allocCount, m_freeCount, m_reallocCount,
        m_cacheHits, m_cacheMisses, m_stormCleanupTriggers, m_pressureCleanups
    );
}

void MemoryPool::PrintStatistics() const noexcept {
    MemoryPoolStats stats = GetStats();

    LogMessage("[MemoryPool] === 统计报告 ===");
    LogMessage("  分配: 总计=%zuMB, 次数=%zu",
        stats.totalAllocated / (1024 * 1024), stats.allocCount);
    LogMessage("  释放: 总计=%zuMB, 次数=%zu",
        stats.totalFreed / (1024 * 1024), stats.freeCount);
    LogMessage("  使用中: %zuMB (峰值: %zuMB)",
        stats.currentInUse / (1024 * 1024), stats.peakUsage / (1024 * 1024));
    LogMessage("  重分配: %zu次", stats.reallocCount);
    LogMessage("  缓存: 命中=%zu, 未命中=%zu, 命中率=%.1f%%",
        stats.cacheHits, stats.cacheMisses, GetCacheHitRate());
    LogMessage("  清理: Storm=%zu次, 压力=%zu次",
        stats.stormCleanupTriggers, stats.pressureCleanups);

    // MemorySafety统计
    LogMessage("  MemorySafety: 缓存=%zuMB, 队列=%zu",
        m_memorySafety.GetTotalCached() / (1024 * 1024),
        m_memorySafety.GetHoldQueueSize());

    size_t processVM = MemoryPoolUtils::GetProcessVirtualMemoryUsage();
    LogMessage("  进程虚拟内存: %zuMB", processVM / (1024 * 1024));
    LogMessage("========================");
}

double MemoryPool::GetCacheHitRate() const noexcept {
    size_t hits = m_cacheHits.load();
    size_t misses = m_cacheMisses.load();
    size_t total = hits + misses;

    return total > 0 ? (hits * 100.0 / total) : 0.0;
}

void MemoryPool::SetStormCleanupFunction(StormHeap_CleanupAll_t func) noexcept {
    m_stormCleanupFunc = func;
}

void MemoryPool::UpdateConfig(const MemoryPoolConfig& config) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config = config;
    LeaveCriticalSection(&m_configCs);

    // 更新MemorySafety配置
    m_memorySafety.SetHoldTimeMs(config.holdBufferTimeMs);
    m_memorySafety.SetWatermarkMB(config.memoryWatermarkMB);
    m_memorySafety.SetMaxCacheSize(config.maxCacheSizeMB);
}

MemoryPoolConfig MemoryPool::GetConfig() const noexcept {
    EnterCriticalSection(&m_configCs);
    MemoryPoolConfig config = m_config;
    LeaveCriticalSection(&m_configCs);
    return config;
}

void MemoryPool::ResetStatistics() noexcept {
    m_totalAllocated.store(0);
    m_totalFreed.store(0);
    m_currentInUse.store(0);
    m_peakUsage.store(0);
    m_allocCount.store(0);
    m_freeCount.store(0);
    m_reallocCount.store(0);
    m_cacheHits.store(0);
    m_cacheMisses.store(0);
    m_stormCleanupTriggers.store(0);
    m_pressureCleanups.store(0);
}

size_t MemoryPool::GetCurrentMemoryUsage() const noexcept {
    return m_currentInUse.load();
}

size_t MemoryPool::GetPeakMemoryUsage() const noexcept {
    return m_peakUsage.load();
}

size_t MemoryPool::GetCacheSize() const noexcept {
    return m_memorySafety.GetTotalCached();
}

///////////////////////////////////////////////////////////////////////////////
// 日志函数实现
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::LogMessage(const char* format, ...) const noexcept {
    EnterCriticalSection(&m_logCs);

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // 控制台输出
    printf("%s\n", buffer);

    // 文件输出
    if (m_logFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        char timeBuffer[64];
        sprintf_s(timeBuffer, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

        DWORD written;
        WriteFile(m_logFile, timeBuffer, static_cast<DWORD>(strlen(timeBuffer)), &written, nullptr);
        WriteFile(m_logFile, buffer, static_cast<DWORD>(strlen(buffer)), &written, nullptr);
        WriteFile(m_logFile, "\r\n", 2, &written, nullptr);
        FlushFileBuffers(m_logFile);
    }

    LeaveCriticalSection(&m_logCs);
}

void MemoryPool::LogError(const char* format, ...) const noexcept {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogMessage("[ERROR] %s", buffer);
}

void MemoryPool::LogDebug(const char* format, ...) const noexcept {
    if (!m_config.enableDetailedLogging) return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogMessage("[DEBUG] %s", buffer);
}

///////////////////////////////////////////////////////////////////////////////
// MemPool命名空间兼容实现
///////////////////////////////////////////////////////////////////////////////

namespace MemPool {
    bool Initialize(size_t initialSize) noexcept {
        MemoryPoolConfig config;
        if (initialSize > 0) {
            config.maxCacheSizeMB = initialSize / (1024 * 1024);
        }
        return g_MemoryPool.Initialize(config);
    }

    void Shutdown() noexcept {
        g_MemoryPool.Shutdown();
    }

    void* Allocate(size_t size) noexcept {
        return g_MemoryPool.Allocate(size);
    }

    void Free(void* ptr) noexcept {
        g_MemoryPool.Free(ptr);
    }

    void* Realloc(void* oldPtr, size_t newSize) noexcept {
        return g_MemoryPool.Realloc(oldPtr, newSize);
    }

    void* AllocateSafe(size_t size) noexcept {
        return g_MemoryPool.AllocateSafe(size);
    }

    void FreeSafe(void* ptr) noexcept {
        g_MemoryPool.FreeSafe(ptr);
    }

    void* ReallocSafe(void* oldPtr, size_t newSize) noexcept {
        return g_MemoryPool.ReallocSafe(oldPtr, newSize);
    }

    bool IsFromPool(void* ptr) noexcept {
        return g_MemoryPool.IsFromPool(ptr);
    }

    size_t GetUsedSize() noexcept {
        return g_MemoryPool.GetCurrentMemoryUsage();
    }

    size_t GetTotalSize() noexcept {
        return g_MemoryPool.GetPeakMemoryUsage();
    }

    void PrintStats() noexcept {
        g_MemoryPool.PrintStatistics();
    }

    void CheckAndFreeUnusedPools() noexcept {
        g_MemoryPool.CheckMemoryPressure();
    }

    void DisableActualFree() noexcept {
        MemoryPoolConfig config = g_MemoryPool.GetConfig();
        config.holdBufferTimeMs = MAXDWORD; // 永不超时
        g_MemoryPool.UpdateConfig(config);
    }

    void DisableMemoryReleasing() noexcept {
        MemoryPoolConfig config = g_MemoryPool.GetConfig();
        config.enablePeriodicCleanup = false;
        config.enableMemoryPressureMonitoring = false;
        g_MemoryPool.UpdateConfig(config);
    }

    void* CreateStabilizingBlock(size_t size, const char* purpose) noexcept {
        void* ptr = g_MemoryPool.AllocateSafe(size, purpose, 0);
        if (ptr) {
            printf("[MemPool] 创建稳定化块: %p (大小:%zu, 用途:%s)\n",
                ptr, size, purpose ? purpose : "未知");
        }
        return ptr;
    }
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数实现
///////////////////////////////////////////////////////////////////////////////

namespace MemoryPoolUtils {
    size_t GetProcessVirtualMemoryUsage() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PrivateUsage;
        }
        return 0;
    }

    size_t GetProcessWorkingSetSize() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }

    size_t GetSystemMemoryPressure() noexcept {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        if (GlobalMemoryStatusEx(&ms)) {
            return ms.dwMemoryLoad; // 0-100的百分比
        }
        return 0;
    }

    bool IsValidPointer(void* ptr) noexcept {
        if (!ptr) return false;

        __try {
            volatile char test = *static_cast<char*>(ptr);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool IsValidMemoryRange(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return false;

        __try {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
                return false;
            }

            return (mbi.State & MEM_COMMIT) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    size_t AlignSize(size_t size, size_t alignment) noexcept {
        return (size + alignment - 1) & ~(alignment - 1);
    }

    size_t GetPageAlignedSize(size_t size) noexcept {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return AlignSize(size, si.dwPageSize);
    }

    DWORD GetTickCount() noexcept {
        return static_cast<DWORD>(::GetTickCount64() & 0xFFFFFFFF);
    }

    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept {
        DWORD currentTime = GetTickCount();
        return (currentTime - startTime) >= intervalMs;
    }
}