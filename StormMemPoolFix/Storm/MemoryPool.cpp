// MemoryPool.cpp - 基于修复后MemorySafety的简化实现
#include "pch.h"
#include "MemoryPool.h"
#include "StormCommon.h"
#include <iostream>
#include <psapi.h>
#include <algorithm>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

///////////////////////////////////////////////////////////////////////////////
// 小块内存池实现
///////////////////////////////////////////////////////////////////////////////

namespace SmallBlockPool {
    static std::atomic<bool> s_initialized{ false };
    static CRITICAL_SECTION s_poolCs;
    static constexpr size_t POOL_SIZE = 1024;  // 每种大小预分配1024个块

    struct PoolEntry {
        void* blocks[POOL_SIZE];
        std::atomic<size_t> allocatedCount{ 0 };
        std::atomic<size_t> freeCount{ 0 };
    };

    static PoolEntry s_pools[SMALL_BLOCK_COUNT];

    bool Initialize() noexcept {
        bool expected = false;
        if (!s_initialized.compare_exchange_strong(expected, true)) {
            return true;
        }

        InitializeCriticalSection(&s_poolCs);

        // 预分配小块池
        for (size_t i = 0; i < SMALL_BLOCK_COUNT; ++i) {
            size_t blockSize = SMALL_BLOCK_SIZES[i];
            size_t totalSize = blockSize * POOL_SIZE;

            void* poolMemory = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (poolMemory) {
                for (size_t j = 0; j < POOL_SIZE; ++j) {
                    s_pools[i].blocks[j] = static_cast<char*>(poolMemory) + j * blockSize;
                }
            }
        }

        return true;
    }

    void Shutdown() noexcept {
        bool expected = true;
        if (!s_initialized.compare_exchange_strong(expected, false)) {
            return;
        }

        // 清理预分配的内存池
        for (size_t i = 0; i < SMALL_BLOCK_COUNT; ++i) {
            if (s_pools[i].blocks[0]) {
                VirtualFree(s_pools[i].blocks[0], 0, MEM_RELEASE);
            }
        }

        DeleteCriticalSection(&s_poolCs);
    }

    bool ShouldIntercept(size_t size) noexcept {
        for (size_t blockSize : SMALL_BLOCK_SIZES) {
            if (size <= blockSize) return true;
        }
        return false;
    }

    void* Allocate(size_t size) noexcept {
        if (!s_initialized.load() || !ShouldIntercept(size)) {
            return nullptr;
        }

        // 找到合适的块大小
        size_t poolIndex = SIZE_MAX;
        for (size_t i = 0; i < SMALL_BLOCK_COUNT; ++i) {
            if (size <= SMALL_BLOCK_SIZES[i]) {
                poolIndex = i;
                break;
            }
        }

        if (poolIndex == SIZE_MAX) {
            return nullptr;
        }

        auto& pool = s_pools[poolIndex];
        EnterCriticalSection(&s_poolCs);

        if (pool.allocatedCount.load() < POOL_SIZE) {
            size_t index = pool.allocatedCount.fetch_add(1);
            if (index < POOL_SIZE) {
                LeaveCriticalSection(&s_poolCs);
                return pool.blocks[index];
            }
        }

        LeaveCriticalSection(&s_poolCs);

        // 池耗尽，使用VirtualAlloc
        void* ptr = VirtualAlloc(nullptr, SMALL_BLOCK_SIZES[poolIndex], MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return ptr;
    }

    bool Free(void* ptr, size_t size) noexcept {
        if (!ptr || !s_initialized.load()) {
            return false;
        }

        // 简化实现：对于小块，我们不回收到池中，直接释放
        // 这避免了复杂的指针验证逻辑
        return VirtualFree(ptr, 0, MEM_RELEASE) != 0;
    }

    void* Realloc(void* ptr, size_t oldSize, size_t newSize) noexcept {
        if (!ptr) {
            return Allocate(newSize);
        }

        if (newSize == 0) {
            Free(ptr, oldSize);
            return nullptr;
        }

        void* newPtr = Allocate(newSize);
        if (newPtr) {
            memcpy(newPtr, ptr, min(oldSize, newSize));
            Free(ptr, oldSize);
        }

        return newPtr;
    }
}

///////////////////////////////////////////////////////////////////////////////
// JassVM内存池实现
///////////////////////////////////////////////////////////////////////////////

namespace JVM_MemPool {
    static std::atomic<bool> s_initialized{ false };
    static CRITICAL_SECTION s_poolCs;
    static constexpr size_t JVM_POOL_CAPACITY = 256;
    static constexpr uint32_t JVM_MAGIC = 0xBEEFCAFE;
    static constexpr uint32_t JVM_MAGIC_FREED = 0xDEADDEAD;

    struct JVMBlock {
        uint32_t magic;
        uint32_t size;
        uint32_t index;
        uint32_t checksum;
    };

    static alignas(64) char s_poolMemory[JVM_POOL_CAPACITY][JVM_BLOCK_SIZE + sizeof(JVMBlock)];
    static bool s_usedFlags[JVM_POOL_CAPACITY];
    static std::atomic<size_t> s_allocatedCount{ 0 };

    uint32_t CalculateChecksum(const JVMBlock* block) noexcept {
        return block->magic ^ block->size ^ block->index ^ 0xA5A5A5A5;
    }

    bool Initialize() noexcept {
        bool expected = false;
        if (!s_initialized.compare_exchange_strong(expected, true)) {
            return true;
        }

        InitializeCriticalSection(&s_poolCs);
        memset(s_usedFlags, 0, sizeof(s_usedFlags));
        s_allocatedCount = 0;
        return true;
    }

    void Shutdown() noexcept {
        bool expected = true;
        if (!s_initialized.compare_exchange_strong(expected, false)) {
            return;
        }

        DeleteCriticalSection(&s_poolCs);
    }

    void* Allocate(size_t size) noexcept {
        if (size != JVM_BLOCK_SIZE || !s_initialized.load()) {
            return nullptr;
        }

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

    void Free(void* p) noexcept {
        if (!p || !IsFromPool(p) || !s_initialized.load()) {
            return;
        }

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

    void* Realloc(void* oldPtr, size_t newSize) noexcept {
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

    bool IsFromPool(void* p) noexcept {
        if (!p) return false;

        uintptr_t ptr = reinterpret_cast<uintptr_t>(p);
        uintptr_t poolStart = reinterpret_cast<uintptr_t>(&s_poolMemory[0][0]) + sizeof(JVMBlock);
        uintptr_t poolEnd = poolStart + JVM_POOL_CAPACITY * (JVM_BLOCK_SIZE + sizeof(JVMBlock));

        if (ptr < poolStart || ptr >= poolEnd) return false;

        // 检查对齐
        uintptr_t offset = ptr - poolStart;
        return (offset % (JVM_BLOCK_SIZE + sizeof(JVMBlock))) == 0;
    }

    void Cleanup() noexcept {
        if (!s_initialized.load()) return;

        EnterCriticalSection(&s_poolCs);
        size_t leakedBlocks = s_allocatedCount.load();
        if (leakedBlocks > 0) {
            LogMessage("[JVM_MemPool] 清理完成，检测到%zu个泄漏块", leakedBlocks);
        }
        memset(s_usedFlags, 0, sizeof(s_usedFlags));
        s_allocatedCount = 0;
        LeaveCriticalSection(&s_poolCs);
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
    const std::atomic<size_t>& smallCnt,
    const std::atomic<size_t>& largeCnt,
    const std::atomic<size_t>& jvmCnt,
    const std::atomic<size_t>& stormCnt,
    const std::atomic<size_t>& hits,
    const std::atomic<size_t>& misses,
    const std::atomic<size_t>& stormCleanups,
    const std::atomic<size_t>& pressureClnps
) noexcept {
    MemoryPoolStats stats;
    stats.totalAllocated = alloc.load();
    stats.totalFreed = freed.load();
    stats.currentInUse = inUse.load();
    stats.peakUsage = peak.load();
    stats.allocCount = allocCnt.load();
    stats.freeCount = freeCnt.load();
    stats.reallocCount = reallocCnt.load();
    stats.smallBlockCount = smallCnt.load();
    stats.largeBlockCount = largeCnt.load();
    stats.jvmBlockCount = jvmCnt.load();
    stats.stormFallbackCount = stormCnt.load();
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
    smallBlockCount = 0;
    largeBlockCount = 0;
    jvmBlockCount = 0;
    stormFallbackCount = 0;
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

MemoryPool::MemoryPool() noexcept : m_memorySafety(MemorySafety::GetInstance()) {
}

MemoryPool::~MemoryPool() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
}

bool MemoryPool::Initialize(const MemoryPoolConfig& config) noexcept {
    return SafeExecuteBool([this, &config]() -> bool {
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

        // 初始化MemorySafety
        MemorySafetyConfig safetyConfig;
        safetyConfig.holdBufferTimeMs = m_config.holdBufferTimeMs;
        safetyConfig.workingSetLimitMB = m_config.workingSetLimitMB;
        safetyConfig.maxCacheSizeMB = m_config.maxCacheSizeMB;
        safetyConfig.enableDetailedLogging = m_config.enableDetailedLogging;
        safetyConfig.enableConservativeCleanup = true;

        if (!m_memorySafety.Initialize(safetyConfig)) {
            LogError("[MemoryPool] MemorySafety初始化失败");
            m_initialized = false;
            return false;
        }

        // 初始化小块池和JVM池
        if (m_config.enableSmallBlockPool) {
            SmallBlockPool::Initialize();
        }

        if (m_config.enableJVMPool) {
            JVM_MemPool::Initialize();
        }

        // 启动后台任务
        StartBackgroundTasks();

        // 重置统计
        ResetStatistics();

        LogMessage("[MemoryPool] 初始化完成");
        LogMessage("[MemoryPool] 配置: 大块阈值=%zuKB, 工作集限制=%zuMB, 缓存限制=%zuMB",
            m_config.bigBlockThreshold / 1024, m_config.workingSetLimitMB, m_config.maxCacheSizeMB);

        return true;
        }, "MemoryPool::Initialize");
}

void MemoryPool::Shutdown() noexcept {
    SafeExecuteVoid([this]() {
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

        // 清理子系统
        if (m_config.enableJVMPool) {
            JVM_MemPool::Cleanup();
        }

        if (m_config.enableSmallBlockPool) {
            SmallBlockPool::Shutdown();
        }

        // 关闭MemorySafety
        m_memorySafety.Shutdown();

        // 关闭日志文件
        if (m_logFile != INVALID_HANDLE_VALUE) {
            LogMessage("[MemoryPool] 关闭完成");
            CloseHandle(m_logFile);
            m_logFile = INVALID_HANDLE_VALUE;
        }
        }, "MemoryPool::Shutdown");
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

MemoryPool::AllocationStrategy MemoryPool::SelectStrategy(size_t size, const char* sourceName) const noexcept {
    // JVM特殊分配
    if (m_config.enableJVMPool && size == JVM_MemPool::JVM_BLOCK_SIZE &&
        sourceName && strstr(sourceName, "Instance.cpp") != nullptr) {
        return AllocationStrategy::JVMBlock;
    }

    // 小块分配
    if (m_config.enableSmallBlockPool && SmallBlockPool::ShouldIntercept(size)) {
        return AllocationStrategy::SmallBlock;
    }

    // 大块分配
    if (size >= m_config.bigBlockThreshold) {
        return AllocationStrategy::LargeBlock;
    }

    // 回退到Storm
    return AllocationStrategy::StormFallback;
}

void* MemoryPool::InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine, bool useSafeMode) noexcept {
    return SafeExecutePtr([this, size, sourceName, sourceLine, useSafeMode]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        m_allocCount.fetch_add(1);

        AllocationStrategy strategy = SelectStrategy(size, sourceName);
        void* result = nullptr;

        switch (strategy) {
        case AllocationStrategy::JVMBlock:
            result = JVM_MemPool::Allocate(size);
            if (result) {
                UpdateMemoryStats(size, true, strategy);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] JVM分配: %p, 大小:%zu", result, size);
                }
            }
            break;

        case AllocationStrategy::SmallBlock:
            result = SmallBlockPool::Allocate(size);
            if (result) {
                UpdateMemoryStats(size, true, strategy);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 小块分配: %p, 大小:%zu", result, size);
                }
            }
            break;

        case AllocationStrategy::LargeBlock:
            result = m_memorySafety.AllocateBlock(size, sourceName, sourceLine);
            if (result) {
                UpdateMemoryStats(size, true, strategy);
                m_cacheHits.fetch_add(1);  // MemorySafety内部管理命中率
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 大块分配: %p, 大小:%zu, 来源:%s:%u",
                        result, size, sourceName ? sourceName : "null", sourceLine);
                }
            }
            else {
                m_cacheMisses.fetch_add(1);
            }
            break;

        case AllocationStrategy::StormFallback:
            // 这里应该调用原始Storm分配，但为了简化，使用VirtualAlloc
            result = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (result) {
                UpdateMemoryStats(size, true, strategy);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] Storm回退分配: %p, 大小:%zu", result, size);
                }
            }
            break;
        }

        if (!result) {
            LogError("[MemoryPool] 分配失败: 大小:%zu, 策略:%d, 来源:%s:%u",
                size, static_cast<int>(strategy), sourceName ? sourceName : "null", sourceLine);
        }

        return result;
        }, "MemoryPool::InternalAllocate");
}

bool MemoryPool::InternalFree(void* ptr, bool useSafeMode) noexcept {
    return SafeExecuteBool([this, ptr, useSafeMode]() -> bool {
        if (!ptr || !m_initialized.load()) {
            return false;
        }

        m_freeCount.fetch_add(1);

        // 检查JVM池
        if (m_config.enableJVMPool && JVM_MemPool::IsFromPool(ptr)) {
            JVM_MemPool::Free(ptr);
            UpdateMemoryStats(JVM_MemPool::JVM_BLOCK_SIZE, false, AllocationStrategy::JVMBlock);
            if (m_config.enableDetailedLogging) {
                LogDebug("[MemoryPool] JVM释放: %p", ptr);
            }
            return true;
        }

        // 检查MemorySafety管理的块
        if (m_memorySafety.IsOurBlock(ptr)) {
            size_t blockSize = m_memorySafety.GetBlockSize(ptr);
            bool success = m_memorySafety.FreeBlock(ptr);
            if (success) {
                UpdateMemoryStats(blockSize, false, AllocationStrategy::LargeBlock);
                if (m_config.enableDetailedLogging) {
                    LogDebug("[MemoryPool] 大块释放: %p, 大小:%zu", ptr, blockSize);
                }
                return true;
            }
        }

        // 尝试小块池释放（需要估算大小）
        if (m_config.enableSmallBlockPool) {
            for (size_t blockSize : SmallBlockPool::SMALL_BLOCK_SIZES) {
                if (SmallBlockPool::Free(ptr, blockSize)) {
                    UpdateMemoryStats(blockSize, false, AllocationStrategy::SmallBlock);
                    if (m_config.enableDetailedLogging) {
                        LogDebug("[MemoryPool] 小块释放: %p, 估算大小:%zu", ptr, blockSize);
                    }
                    return true;
                }
            }
        }

        // 回退到VirtualFree
        if (useSafeMode) {
            __try {
                bool success = VirtualFree(ptr, 0, MEM_RELEASE) != 0;
                if (success) {
                    UpdateMemoryStats(0, false, AllocationStrategy::StormFallback);  // 大小未知
                    LogMessage("[MemoryPool] Storm回退释放: %p", ptr);
                }
                return success;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogError("[MemoryPool] 释放异常: %p, 异常:0x%08X", ptr, GetExceptionCode());
            }
        }

        LogError("[MemoryPool] 释放失败: %p", ptr);
        return false;
        }, "MemoryPool::InternalFree");
}

void* MemoryPool::InternalRealloc(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine, bool useSafeMode) noexcept {
    return SafeExecutePtr([this, oldPtr, newSize, sourceName, sourceLine, useSafeMode]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        m_reallocCount.fetch_add(1);

        if (!oldPtr) {
            return InternalAllocate(newSize, sourceName, sourceLine, useSafeMode);
        }

        if (newSize == 0) {
            InternalFree(oldPtr, useSafeMode);
            return nullptr;
        }

        // JVM池处理
        if (m_config.enableJVMPool && JVM_MemPool::IsFromPool(oldPtr)) {
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
        void* newPtr = InternalAllocate(newSize, sourceName, sourceLine, useSafeMode);
        if (newPtr) {
            __try {
                // 保守地复制数据
                size_t copySize = min(newSize, static_cast<size_t>(4096));  // 最多复制4KB
                memcpy(newPtr, oldPtr, copySize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogError("[MemoryPool] 重分配数据复制失败: %p->%p", oldPtr, newPtr);
            }

            InternalFree(oldPtr, useSafeMode);
            LogMessage("[MemoryPool] 回退重分配: %p->%p, 大小:%zu", oldPtr, newPtr, newSize);
            return newPtr;
        }

        LogError("[MemoryPool] 重分配失败: %p, 大小:%zu", oldPtr, newSize);
        return nullptr;
        }, "MemoryPool::InternalRealloc");
}

///////////////////////////////////////////////////////////////////////////////
// 块验证和查询
///////////////////////////////////////////////////////////////////////////////

bool MemoryPool::IsFromPool(void* ptr) const noexcept {
    return SafeExecuteBool([this, ptr]() -> bool {
        if (!ptr || !m_initialized.load()) {
            return false;
        }

        return (m_config.enableJVMPool && JVM_MemPool::IsFromPool(ptr)) ||
            m_memorySafety.IsOurBlock(ptr);
        }, "MemoryPool::IsFromPool");
}

size_t MemoryPool::GetBlockSize(void* ptr) const noexcept {
    return SafeExecuteValue([this, ptr]() -> size_t {
        if (!ptr || !m_initialized.load()) {
            return 0;
        }

        if (m_config.enableJVMPool && JVM_MemPool::IsFromPool(ptr)) {
            return JVM_MemPool::JVM_BLOCK_SIZE;
        }

        return m_memorySafety.GetBlockSize(ptr);
        }, "MemoryPool::GetBlockSize");
}

bool MemoryPool::IsLargeBlock(size_t size) const noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    return size >= m_config.bigBlockThreshold;
}

///////////////////////////////////////////////////////////////////////////////
// 内存压力管理
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::CheckMemoryPressure() noexcept {
    SafeExecuteVoid([this]() {
        if (!m_config.enableMemoryPressureMonitoring) {
            return;
        }

        DWORD currentTime = MemoryPoolUtils::GetTickCount();
        DWORD lastCleanup = m_lastCleanupTime.load();

        if (currentTime - lastCleanup < 5000) {  // 5秒检查一次
            return;
        }

        if (IsMemoryUnderPressure()) {
            LogMessage("[MemoryPool] 检测到内存压力，触发清理");
            ForceCleanup();
            m_pressureCleanups.fetch_add(1);
        }
        }, "MemoryPool::CheckMemoryPressure");
}

void MemoryPool::ForceCleanup() noexcept {
    SafeExecuteVoid([this]() {
        LogMessage("[MemoryPool] 开始强制清理");

        DWORD currentTime = MemoryPoolUtils::GetTickCount();
        m_lastCleanupTime.store(currentTime);

        // 清理MemorySafety缓存
        m_memorySafety.ForceCleanup();

        // 触发Storm清理
        TriggerStormCleanup();

        LogMessage("[MemoryPool] 强制清理完成");
        }, "MemoryPool::ForceCleanup");
}

void MemoryPool::TriggerStormCleanup() noexcept {
    SafeExecuteVoid([this]() {
        if (!m_stormCleanupFunc) {
            return;
        }

        DWORD currentTime = MemoryPoolUtils::GetTickCount();
        DWORD lastStormCleanup = m_lastStormCleanupTime.load();

        if (currentTime - lastStormCleanup < 15000) {  // 15秒间隔
            return;
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
        }, "MemoryPool::TriggerStormCleanup");
}

bool MemoryPool::IsMemoryUnderPressure() const noexcept {
    return m_memorySafety.IsMemoryUnderPressure();
}

///////////////////////////////////////////////////////////////////////////////
// 后台任务
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::StartBackgroundTasks() noexcept {
    SafeExecuteVoid([this]() {
        if (m_backgroundTaskRunning.exchange(true)) {
            return; // 已在运行
        }

        m_backgroundThread = std::make_unique<std::thread>(&MemoryPool::BackgroundTaskLoop, this);
        LogMessage("[MemoryPool] 后台任务已启动");
        }, "MemoryPool::StartBackgroundTasks");
}

void MemoryPool::StopBackgroundTasks() noexcept {
    SafeExecuteVoid([this]() {
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
        }, "MemoryPool::StopBackgroundTasks");
}

void MemoryPool::BackgroundTaskLoop() noexcept {
    LogMessage("[MemoryPool] 后台任务循环开始");

    while (m_backgroundTaskRunning.load() && !m_shutdownRequested.load()) {
        try {
            // 等待一段时间或收到通知
            std::unique_lock<std::mutex> lock(m_backgroundMutex);
            m_backgroundCondition.wait_for(lock,
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
    SafeExecuteVoid([this]() {
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
        }, "MemoryPool::RunPeriodicTasks");
}

void MemoryPool::ProcessHoldQueue() noexcept {
    SafeExecuteVoid([this]() {
        m_memorySafety.ProcessHoldQueue();
        }, "MemoryPool::ProcessHoldQueue");
}

///////////////////////////////////////////////////////////////////////////////
// 统计管理
///////////////////////////////////////////////////////////////////////////////

void MemoryPool::UpdateMemoryStats(size_t size, bool isAllocation, AllocationStrategy strategy) noexcept {
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

        // 更新策略统计
        switch (strategy) {
        case AllocationStrategy::SmallBlock:
            m_smallBlockCount.fetch_add(1);
            break;
        case AllocationStrategy::LargeBlock:
            m_largeBlockCount.fetch_add(1);
            break;
        case AllocationStrategy::JVMBlock:
            m_jvmBlockCount.fetch_add(1);
            break;
        case AllocationStrategy::StormFallback:
            m_stormFallbackCount.fetch_add(1);
            break;
        }
    }
    else {
        m_totalFreed.fetch_add(size);
        if (size <= m_currentInUse.load()) {
            m_currentInUse.fetch_sub(size);
        }
    }
}

MemoryPoolStats MemoryPool::GetStats() const noexcept {
    return MemoryPoolStats::FromAtomics(
        m_totalAllocated, m_totalFreed, m_currentInUse, m_peakUsage,
        m_allocCount, m_freeCount, m_reallocCount,
        m_smallBlockCount, m_largeBlockCount, m_jvmBlockCount, m_stormFallbackCount,
        m_cacheHits, m_cacheMisses, m_stormCleanupTriggers, m_pressureCleanups
    );
}

void MemoryPool::PrintStatistics() const noexcept {
    SafeExecuteVoid([this]() {
        MemoryPoolStats stats = GetStats();

        LogMessage("[MemoryPool] === 统计报告 ===");
        LogMessage("  分配: 总计=%zuMB, 次数=%zu",
            stats.totalAllocated / (1024 * 1024), stats.allocCount);
        LogMessage("  释放: 总计=%zuMB, 次数=%zu",
            stats.totalFreed / (1024 * 1024), stats.freeCount);
        LogMessage("  使用中: %zuMB (峰值: %zuMB)",
            stats.currentInUse / (1024 * 1024), stats.peakUsage / (1024 * 1024));
        LogMessage("  重分配: %zu次", stats.reallocCount);

        LogMessage("  分配策略:");
        LogMessage("    小块: %zu次", stats.smallBlockCount);
        LogMessage("    大块: %zu次", stats.largeBlockCount);
        LogMessage("    JVM块: %zu次", stats.jvmBlockCount);
        LogMessage("    Storm回退: %zu次", stats.stormFallbackCount);

        LogMessage("  缓存: 命中=%zu, 未命中=%zu, 命中率=%.1f%%",
            stats.cacheHits, stats.cacheMisses, GetCacheHitRate());
        LogMessage("  清理: Storm=%zu次, 压力=%zu次",
            stats.stormCleanupTriggers, stats.pressureCleanups);

        // MemorySafety统计
        LogMessage("  MemorySafety: 缓存=%zuMB, 队列=%zu",
            m_memorySafety.GetTotalCached() / (1024 * 1024),
            m_memorySafety.GetHoldQueueSize());

        // 真实内存使用情况
        size_t workingSet = MemoryPoolUtils::GetProcessWorkingSetSize();
        size_t committed = MemoryPoolUtils::GetProcessCommittedSize();
        size_t virtual_size = MemoryPoolUtils::GetProcessVirtualSize();
        LogMessage("  内存使用: 工作集=%zuMB, 已提交=%zuMB, 虚拟内存=%zuMB",
            workingSet / (1024 * 1024), committed / (1024 * 1024), virtual_size / (1024 * 1024));
        LogMessage("========================");
        }, "MemoryPool::PrintStatistics");
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
    m_memorySafety.SetWorkingSetLimit(config.workingSetLimitMB);
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
    m_smallBlockCount = 0;
    m_largeBlockCount = 0;
    m_jvmBlockCount = 0;
    m_stormFallbackCount = 0;
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

///////////////////////////////////////////////////////////////////////////////
// 日志函数实现
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
// MemPool命名空间兼容实现
///////////////////////////////////////////////////////////////////////////////

namespace MemPool {
    bool Initialize(size_t initialSize) noexcept {
        MemoryPoolConfig config;
        if (initialSize > 0) {
            config.maxCacheSizeMB = max(initialSize / (1024 * 1024), 64UL);
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
    size_t GetProcessWorkingSetSize() noexcept {
        return MemorySafetyUtils::GetProcessWorkingSetSize();
    }

    size_t GetProcessCommittedSize() noexcept {
        return MemorySafetyUtils::GetProcessCommittedSize();
    }

    size_t GetProcessVirtualSize() noexcept {
        return MemorySafetyUtils::GetProcessVirtualSize();
    }

    size_t GetSystemMemoryPressure() noexcept {
        return MemorySafetyUtils::GetSystemMemoryLoad();
    }

    bool IsValidPointer(void* ptr) noexcept {
        return MemorySafetyUtils::IsValidMemoryRange(ptr, sizeof(void*));
    }

    bool IsValidMemoryRange(void* ptr, size_t size) noexcept {
        return MemorySafetyUtils::IsValidMemoryRange(ptr, size);
    }

    size_t AlignSize(size_t size, size_t alignment) noexcept {
        return MemorySafetyUtils::AlignSize(size, alignment);
    }

    size_t GetPageAlignedSize(size_t size) noexcept {
        return MemorySafetyUtils::GetPageAlignedSize(size);
    }

    DWORD GetTickCount() noexcept {
        return MemorySafetyUtils::GetTickCount();
    }

    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept {
        return MemorySafetyUtils::HasTimeElapsed(startTime, intervalMs);
    }
}