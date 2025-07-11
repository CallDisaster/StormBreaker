// MemoryPool.cpp - 修复后的内存池实现
#include "pch.h"
#include "MemoryPool.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <algorithm>
#include <cassert>

#pragma comment(lib, "psapi.lib")

// 常量定义
namespace {
    constexpr size_t JVM_BLOCK_SIZE = 0x28A8;
    constexpr size_t JVM_POOL_CAPACITY = 256;
    constexpr uint32_t JVM_MAGIC = 0xBEEFCAFE;
    constexpr uint32_t JVM_MAGIC_FREED = 0xDEADDEAD;

    constexpr size_t SMALL_BLOCK_SIZES[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };
    constexpr size_t SMALL_BLOCK_COUNT = sizeof(SMALL_BLOCK_SIZES) / sizeof(SMALL_BLOCK_SIZES[0]);

    constexpr DWORD MIN_CLEANUP_INTERVAL = 5000;  // 最小5秒清理间隔
    constexpr DWORD MIN_STORM_CLEANUP_INTERVAL = 15000; // 最小15秒Storm清理间隔
}

// JVM内存池简化实现（基于静态数组）
namespace JVM_MemPool {
    struct JVMBlock {
        uint32_t magic;
        uint32_t size;
        uint32_t index;
        uint32_t checksum;
    };

    static alignas(64) char s_poolMemory[JVM_POOL_CAPACITY][JVM_BLOCK_SIZE + sizeof(JVMBlock)];
    static bool s_usedFlags[JVM_POOL_CAPACITY];
    static CRITICAL_SECTION s_poolCs;
    static std::atomic<bool> s_initialized{ false };
    static std::atomic<size_t> s_allocatedCount{ 0 };

    uint32_t CalculateChecksum(const JVMBlock* block) noexcept {
        return block->magic ^ block->size ^ block->index ^ 0xA5A5A5A5;
    }

    void Initialize() {
        if (s_initialized.exchange(true)) return;

        InitializeCriticalSection(&s_poolCs);
        memset(s_usedFlags, 0, sizeof(s_usedFlags));
        s_allocatedCount = 0;
    }

    void* Allocate(std::size_t size) {
        if (size != JVM_BLOCK_SIZE) return nullptr;

        EnterCriticalSection(&s_poolCs);

        void* result = nullptr;
        for (size_t i = 0; i < JVM_POOL_CAPACITY; i++) {
            if (!s_usedFlags[i]) {
                s_usedFlags[i] = true;

                JVMBlock* header = reinterpret_cast<JVMBlock*>(&s_poolMemory[i][0]);
                header->magic = JVM_MAGIC;
                header->size = static_cast<uint32_t>(size);
                header->index = static_cast<uint32_t>(i);
                header->checksum = CalculateChecksum(header);

                result = &s_poolMemory[i][sizeof(JVMBlock)];
                memset(result, 0, JVM_BLOCK_SIZE);
                s_allocatedCount.fetch_add(1);
                break;
            }
        }

        LeaveCriticalSection(&s_poolCs);
        return result;
    }

    void Free(void* p) {
        if (!p || !IsFromPool(p)) return;

        EnterCriticalSection(&s_poolCs);

        JVMBlock* header = reinterpret_cast<JVMBlock*>(static_cast<char*>(p) - sizeof(JVMBlock));

        if (header->magic == JVM_MAGIC && header->checksum == CalculateChecksum(header)) {
            size_t index = header->index;
            if (index < JVM_POOL_CAPACITY && s_usedFlags[index]) {
                header->magic = JVM_MAGIC_FREED;
                header->checksum = 0;
                memset(p, 0xDD, JVM_BLOCK_SIZE);
                s_usedFlags[index] = false;
                s_allocatedCount.fetch_sub(1);
            }
        }

        LeaveCriticalSection(&s_poolCs);
    }

    void* Realloc(void* oldPtr, std::size_t newSize) {
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) { Free(oldPtr); return nullptr; }
        if (newSize == JVM_BLOCK_SIZE) return oldPtr;

        void* newPtr = Allocate(newSize);
        if (newPtr) {
            memcpy(newPtr, oldPtr, min(newSize, JVM_BLOCK_SIZE));
            Free(oldPtr);
        }
        return newPtr;
    }

    bool IsFromPool(void* p) {
        if (!p) return false;

        uintptr_t ptr = reinterpret_cast<uintptr_t>(p);
        uintptr_t poolStart = reinterpret_cast<uintptr_t>(&s_poolMemory[0][0]) + sizeof(JVMBlock);
        uintptr_t poolEnd = poolStart + JVM_POOL_CAPACITY * (JVM_BLOCK_SIZE + sizeof(JVMBlock));

        if (ptr < poolStart || ptr >= poolEnd) return false;

        // 检查对齐
        uintptr_t offset = ptr - poolStart;
        return (offset % (JVM_BLOCK_SIZE + sizeof(JVMBlock))) == 0;
    }

    void Cleanup() {
        if (!s_initialized.exchange(false)) return;

        EnterCriticalSection(&s_poolCs);
        size_t leakedBlocks = s_allocatedCount.load();
        if (leakedBlocks > 0) {
            printf("[JVM_MemPool] 清理完成，检测到%zu个泄漏块\n", leakedBlocks);
        }
        memset(s_usedFlags, 0, sizeof(s_usedFlags));
        s_allocatedCount = 0;
        LeaveCriticalSection(&s_poolCs);

        DeleteCriticalSection(&s_poolCs);
    }
}

// 小块内存池简化实现
namespace SmallBlockPool {
    static std::atomic<bool> s_initialized{ false };

    void Initialize() {
        s_initialized = true;
    }

    bool ShouldIntercept(std::size_t size) {
        for (size_t blockSize : SMALL_BLOCK_SIZES) {
            if (size == blockSize) return true;
        }
        return false;
    }

    void* Allocate(std::size_t size) {
        if (!ShouldIntercept(size)) return nullptr;

        size_t totalSize = size + 16; // 简单头部
        void* ptr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ptr) return nullptr;

        *reinterpret_cast<size_t*>(ptr) = size;
        return static_cast<char*>(ptr) + 16;
    }

    bool Free(void* ptr, std::size_t size) {
        if (!ptr || !ShouldIntercept(size)) return false;

        void* basePtr = static_cast<char*>(ptr) - 16;
        size_t storedSize = *reinterpret_cast<size_t*>(basePtr);

        if (storedSize != size) return false;

        VirtualFree(basePtr, 0, MEM_RELEASE);
        return true;
    }
}

// MemoryPool实现
MemoryPool& MemoryPool::GetInstance() noexcept {
    static MemoryPool instance;
    return instance;
}

MemoryPool::MemoryPool() noexcept
    : m_memorySafety(MemorySafety::GetInstance()) {
}

MemoryPool::~MemoryPool() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
}

bool MemoryPool::Initialize(const MemoryPoolConfig& config) noexcept {
    return SafeExecuteNonConst([this, &config]() -> bool {
        bool expected = false;
        if (!m_initialized.compare_exchange_strong(expected, true)) {
            return true; // 已初始化
        }

        // 保存配置
        {
            std::lock_guard<std::mutex> lock(m_configMutex);
            m_config = config;
        }

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
        LogMessage("[MemoryPool] 配置 - 大块阈值:%zuKB, 内存水位:%zuMB, 最大缓存:%zuMB",
            m_config.bigBlockThreshold / 1024,
            m_config.memoryWatermarkMB,
            m_config.maxCacheSizeMB);

        // 初始化MemorySafety
        if (!m_memorySafety.Initialize()) {
            LogError("[MemoryPool] MemorySafety初始化失败");
            m_initialized = false;
            return false;
        }

        // 配置MemorySafety参数
        m_memorySafety.SetHoldTimeMs(m_config.holdBufferTimeMs);
        m_memorySafety.SetWatermarkMB(m_config.memoryWatermarkMB);
        m_memorySafety.SetMaxCacheSize(m_config.maxCacheSizeMB);

        // 初始化兼容池
        JVM_MemPool::Initialize();
        SmallBlockPool::Initialize();

        // 启动后台任务
        StartBackgroundTasks();

        // 重置统计
        ResetStatistics();

        LogMessage("[MemoryPool] 初始化完成");
        return true;

        }, "Initialize");
}

void MemoryPool::Shutdown() noexcept {
    SafeExecuteNonConst([this]() -> void {
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

        }, "Shutdown");
}

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

void* MemoryPool::InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept {
    return SafeExecuteNonConst([this, size, sourceName, sourceLine, useFallback]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        m_allocCount.fetch_add(1);

        // 特殊处理JVM块
        if (size == JVM_BLOCK_SIZE) {
            void* jvmPtr = JVM_MemPool::Allocate(size);
            if (jvmPtr) {
                UpdateMemoryStats(size, true);
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
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 小块分配: %p, 大小:%zu", smallPtr, size);
                }
                return smallPtr;
            }
        }

        // 大块处理
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

        // 回退到系统分配
        if (useFallback) {
            void* sysPtr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (sysPtr) {
                UpdateMemoryStats(size, true);
                LogMessage("[MemoryPool] 系统回退分配: %p, 大小:%zu", sysPtr, size);
                return sysPtr;
            }
        }

        LogError("[MemoryPool] 分配失败: 大小:%zu, 来源:%s:%u",
            size, sourceName ? sourceName : "null", sourceLine);
        return nullptr;

        }, "InternalAllocate");
}

bool MemoryPool::InternalFree(void* ptr, bool useFallback) noexcept {
    return SafeExecuteNonConst([this, ptr, useFallback]() -> bool {
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

        // 检查小块池
        for (size_t blockSize : SMALL_BLOCK_SIZES) {
            if (SmallBlockPool::Free(ptr, blockSize)) {
                UpdateMemoryStats(blockSize, false);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 小块释放: %p, 大小:%zu", ptr, blockSize);
                }
                return true;
            }
        }

        // 检查MemorySafety管理的块
        if (m_memorySafety.IsOurBlock(ptr)) {
            size_t blockSize = m_memorySafety.GetBlockSize(ptr);
            bool success = m_memorySafety.FreeBlock(ptr);
            if (success) {
                UpdateMemoryStats(blockSize, false);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 大块释放: %p, 大小:%zu", ptr, blockSize);
                }
                return true;
            }
        }

        // 尝试系统释放（回退）
        if (useFallback) {
            __try {
                VirtualFree(ptr, 0, MEM_RELEASE);
                LogMessage("[MemoryPool] 系统回退释放: %p", ptr);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogError("[MemoryPool] 系统释放失败: %p, 异常:0x%08X", ptr, GetExceptionCode());
            }
        }

        LogError("[MemoryPool] 释放失败: %p", ptr);
        return false;

        }, "InternalFree");
}

void* MemoryPool::InternalRealloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine, bool useFallback) noexcept {
    return SafeExecuteNonConst([this, oldPtr, newSize, sourceName, sourceLine, useFallback]() -> void* {
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
                    LogDebug("[MemoryPool] 大块重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
                }
                return newPtr;
            }
        }

        // 回退策略：分配新块，复制数据，释放旧块
        if (useFallback) {
            void* newPtr = InternalAllocate(newSize, sourceName, sourceLine, true);
            if (newPtr) {
                __try {
                    // 尝试复制数据（保守大小）
                    size_t copySize = min(newSize, (size_t)1024);
                    memcpy(newPtr, oldPtr, copySize);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    LogError("[MemoryPool] 重分配数据复制失败: %p->%p", oldPtr, newPtr);
                }

                InternalFree(oldPtr, true);
                LogMessage("[MemoryPool] 回退重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
                return newPtr;
            }
        }

        LogError("[MemoryPool] 重分配失败: %p, 大小:%zu", oldPtr, newSize);
        return nullptr;

        }, "InternalRealloc");
}

bool MemoryPool::IsFromPool(void* ptr) const noexcept {
    return SafeExecuteNonConst([this, ptr]() -> bool {
        if (!ptr || !m_initialized.load()) {
            return false;
        }

        return JVM_MemPool::IsFromPool(ptr) || m_memorySafety.IsOurBlock(ptr);

        }, "IsFromPool");
}

size_t MemoryPool::GetBlockSize(void* ptr) const noexcept {
    return SafeExecuteNonConst([this, ptr]() -> size_t {
        if (!ptr || !m_initialized.load()) {
            return 0;
        }

        if (JVM_MemPool::IsFromPool(ptr)) {
            return JVM_BLOCK_SIZE;
        }

        return m_memorySafety.GetBlockSize(ptr);

        }, "GetBlockSize");
}

bool MemoryPool::IsLargeBlock(size_t size) const noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    return size >= m_config.bigBlockThreshold;
}

void MemoryPool::CheckMemoryPressure() noexcept {
    SafeExecuteNonConst([this]() -> void {
        if (!m_config.enableMemoryPressureMonitoring) {
            return;
        }

        DWORD currentTime = MemorySafetyUtils::GetTickCount();
        DWORD lastCleanup = m_lastCleanupTime.load();

        if (currentTime - lastCleanup < MIN_CLEANUP_INTERVAL) {
            return; // 太频繁
        }

        if (IsMemoryUnderPressure()) {
            LogMessage("[MemoryPool] 检测到内存压力，触发清理");
            ForceCleanup();
            m_pressureCleanups.fetch_add(1);
        }

        }, "CheckMemoryPressure");
}

void MemoryPool::ForceCleanup() noexcept {
    SafeExecuteNonConst([this]() -> void {
        LogMessage("[MemoryPool] 开始强制清理");

        DWORD currentTime = MemorySafetyUtils::GetTickCount();
        m_lastCleanupTime.store(currentTime);

        // 清理MemorySafety缓存
        m_memorySafety.ForceCleanup();

        // 触发Storm清理
        TriggerStormCleanup();

        LogMessage("[MemoryPool] 强制清理完成");

        }, "ForceCleanup");
}

void MemoryPool::TriggerStormCleanup() noexcept {
    SafeExecuteNonConst([this]() -> void {
        if (!m_stormCleanupFunc) {
            return;
        }

        DWORD currentTime = MemorySafetyUtils::GetTickCount();
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

        }, "TriggerStormCleanup");
}

void MemoryPool::StartBackgroundTasks() noexcept {
    SafeExecuteNonConst([this]() -> void {
        if (m_backgroundTaskRunning.exchange(true)) {
            return; // 已在运行
        }

        m_backgroundThread = std::make_unique<std::thread>(&MemoryPool::BackgroundTaskLoop, this);
        LogMessage("[MemoryPool] 后台任务已启动");

        }, "StartBackgroundTasks");
}

void MemoryPool::StopBackgroundTasks() noexcept {
    SafeExecuteNonConst([this]() -> void {
        m_shutdownRequested.store(true);
        m_backgroundTaskRunning.store(false);

        {
            std::lock_guard<std::mutex> lock(m_backgroundMutex);
            m_backgroundCondition.notify_all();
        }

        if (m_backgroundThread && m_backgroundThread->joinable()) {
            m_backgroundThread->join();
        }

        LogMessage("[MemoryPool] 后台任务已停止");

        }, "StopBackgroundTasks");
}

void MemoryPool::BackgroundTaskLoop() noexcept {
    LogMessage("[MemoryPool] 后台任务循环开始");

    while (m_backgroundTaskRunning.load() && !m_shutdownRequested.load()) {
        try {
            // 等待一段时间或收到通知
            std::unique_lock<std::mutex> lock(m_backgroundMutex);
            bool notified = m_backgroundCondition.wait_for(lock,
                std::chrono::milliseconds(m_config.cleanupIntervalMs),
                [this] { return m_shutdownRequested.load(); });

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
    SafeExecuteNonConst([this]() -> void {
        DWORD currentTime = MemorySafetyUtils::GetTickCount();

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

        }, "RunPeriodicTasks");
}

void MemoryPool::ProcessHoldQueue() noexcept {
    SafeExecuteNonConst([this]() -> void {
        m_memorySafety.ProcessHoldQueue();
        }, "ProcessHoldQueue");
}

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
    return SafeExecuteNonConst([this]() -> bool {
        size_t currentVM = MemoryPoolUtils::GetProcessVirtualMemoryUsage();
        size_t watermarkBytes = m_config.memoryWatermarkMB * 1024 * 1024;

        return currentVM > watermarkBytes;

        }, "IsMemoryUnderPressure");
}

MemoryPoolStats MemoryPool::GetStats() const noexcept {
    return MemoryPoolStats::FromAtomics(
        m_totalAllocated, m_totalFreed, m_currentInUse, m_peakUsage,
        m_allocCount, m_freeCount, m_reallocCount,
        m_cacheHits, m_cacheMisses, m_stormCleanupTriggers, m_pressureCleanups
    );
}

void MemoryPool::PrintStatistics() const noexcept {
    SafeExecuteNonConst([this]() -> void {
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

        }, "PrintStatistics");
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
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_config = config;

    // 更新MemorySafety配置
    m_memorySafety.SetHoldTimeMs(config.holdBufferTimeMs);
    m_memorySafety.SetWatermarkMB(config.memoryWatermarkMB);
    m_memorySafety.SetMaxCacheSize(config.maxCacheSizeMB);
}

MemoryPoolConfig MemoryPool::GetConfig() const noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    return m_config;
}

void MemoryPool::ResetStatistics() noexcept {
    m_totalAllocated = 0;
    m_totalFreed = 0;
    m_currentInUse = 0;
    m_peakUsage = 0;
    m_allocCount = 0;
    m_freeCount = 0;
    m_reallocCount = 0;
    m_cacheHits = 0;
    m_cacheMisses = 0;
    m_stormCleanupTriggers = 0;
    m_pressureCleanups = 0;
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

// 日志函数实现
void MemoryPool::LogMessage(const char* format, ...) const noexcept {
    std::lock_guard<std::mutex> lock(m_logMutex);

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

// MemPool命名空间兼容实现
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

// 工具函数实现
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