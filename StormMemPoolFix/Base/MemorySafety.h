// MemorySafety.h - 修复版本：解决虚拟内存过度使用和清理策略问题
#pragma once

#include "pch.h"
#include "SafeExecute.h"
#include "../Storm/StormCommon.h"
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <deque>

///////////////////////////////////////////////////////////////////////////////
// 修复后的配置常量 - 大幅减少预分配
///////////////////////////////////////////////////////////////////////////////

// 改为完全按需分配，不预分配大池
constexpr size_t INITIAL_CACHE_SIZE = 8 * 1024 * 1024;      // 初始8MB缓存
constexpr size_t MAX_CACHE_SIZE = 64 * 1024 * 1024;         // 最大64MB缓存  
constexpr size_t CACHE_BLOCK_SIZE = 2 * 1024 * 1024;        // 2MB为单位扩展

constexpr size_t SIZE_CLASS_COUNT = 8;                       // 8个大小分档
constexpr size_t SIZE_CLASS_UNIT = 128 * 1024;              // 128KB为单位
constexpr size_t SIZE_CLASS_THRESHOLDS[] = {                // 各档阈值
    64 * 1024,      // 64KB
    128 * 1024,     // 128KB  
    256 * 1024,     // 256KB
    512 * 1024,     // 512KB
    1024 * 1024,    // 1MB
    2 * 1024 * 1024,   // 2MB
    4 * 1024 * 1024,   // 4MB
    SIZE_MAX           // 其余
};

// 增加缓冲时间，降低清理频率
constexpr DWORD DEFAULT_HOLD_TIME_MS = 2000;                // 2秒缓冲时间
constexpr size_t MAX_HOLD_QUEUE_SIZE = 500;                 // 最大500个持有项
constexpr DWORD MIN_CLEANUP_INTERVAL_MS = 10000;            // 最小10秒清理间隔

///////////////////////////////////////////////////////////////////////////////
// 简化的缓存块结构
///////////////////////////////////////////////////////////////////////////////

struct CacheBlock {
    void* rawPtr;           // VirtualAlloc返回的指针
    size_t totalSize;       // 总分配大小
    size_t userSize;        // 用户请求大小
    DWORD allocTime;        // 分配时间
    DWORD lastUsedTime;     // 最后使用时间
    size_t sizeClass;       // 大小分档
    bool isInUse;           // 是否正在使用

    CacheBlock(void* raw, size_t total, size_t user, size_t sc)
        : rawPtr(raw), totalSize(total), userSize(user),
        allocTime(GetTickCount()), lastUsedTime(GetTickCount()),
        sizeClass(sc), isInUse(true) {
    }
};

// Hold队列中的延迟释放项
struct HoldItem {
    void* userPtr;          // 用户指针
    void* rawPtr;           // 原始分配指针
    size_t userSize;        // 用户请求大小
    size_t sizeClass;       // 大小分档
    DWORD queueTime;        // 入队时间

    HoldItem(void* user, void* raw, size_t userSz, size_t sc)
        : userPtr(user), rawPtr(raw), userSize(userSz), sizeClass(sc),
        queueTime(GetTickCount()) {
    }
};

// 内存块信息
struct BlockInfo {
    void* rawPtr;           // 原始分配指针
    void* userPtr;          // 用户指针
    size_t totalSize;       // 总分配大小
    size_t userSize;        // 用户请求大小
    size_t sizeClass;       // 大小分档
    DWORD allocTime;        // 分配时间
    const char* sourceName; // 分配来源
    DWORD sourceLine;       // 分配行号
    bool isInHoldQueue;     // 是否在Hold队列中

    BlockInfo() : rawPtr(nullptr), userPtr(nullptr), totalSize(0), userSize(0),
        sizeClass(0), allocTime(0), sourceName(nullptr),
        sourceLine(0), isInHoldQueue(false) {
    }

    BlockInfo(void* raw, void* user, size_t total, size_t userSz, size_t sc,
        const char* name, DWORD line)
        : rawPtr(raw), userPtr(user), totalSize(total), userSize(userSz),
        sizeClass(sc), allocTime(GetTickCount()), sourceName(name),
        sourceLine(line), isInHoldQueue(false) {
    }
};

// 大小分档缓存
struct SizeClassCache {
    std::vector<CacheBlock> freeBlocks;    // 空闲块列表
    size_t totalCached;                    // 缓存的总字节数
    size_t hitCount;                       // 命中次数
    size_t missCount;                      // 未命中次数
    CRITICAL_SECTION cs;                   // 线程保护

    SizeClassCache() : totalCached(0), hitCount(0), missCount(0) {
        InitializeCriticalSection(&cs);
    }

    ~SizeClassCache() {
        DeleteCriticalSection(&cs);
    }
};

// 配置参数
struct MemorySafetyConfig {
    DWORD holdBufferTimeMs = DEFAULT_HOLD_TIME_MS;
    size_t maxHoldQueueSize = MAX_HOLD_QUEUE_SIZE;
    size_t workingSetLimitMB = DEFAULT_WORKING_SET_LIMIT / (1024 * 1024);
    size_t commitLimitMB = DEFAULT_COMMIT_LIMIT / (1024 * 1024);
    size_t maxCacheSizeMB = MAX_CACHE_SIZE / (1024 * 1024);
    bool enableDetailedLogging = false;
    bool enableHoldQueue = true;
    bool enablePressureMonitoring = true;
    bool enableConservativeCleanup = true;  // 启用保守清理策略
};

///////////////////////////////////////////////////////////////////////////////
// 主内存安全管理器 - 修复版本
///////////////////////////////////////////////////////////////////////////////

class MemorySafety {
public:
    // 获取单例
    static MemorySafety& GetInstance() noexcept;

    // 生命周期管理
    bool Initialize(const MemorySafetyConfig& config = {}) noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept { return m_initialized.load(); }

    // 内存分配接口
    void* AllocateBlock(size_t userSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool FreeBlock(void* userPtr) noexcept;
    void* ReallocateBlock(void* userPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 块信息查询
    bool IsOurBlock(void* userPtr) const noexcept;
    size_t GetBlockSize(void* userPtr) const noexcept;
    BlockInfo GetBlockInfo(void* userPtr) const noexcept;

    // Hold队列管理
    void ProcessHoldQueue() noexcept;
    void DrainHoldQueue() noexcept;
    size_t GetHoldQueueSize() const noexcept;

    // 内存压力管理 - 修复版本
    bool IsMemoryUnderPressure() const noexcept;
    void ForceCleanup() noexcept;
    void TriggerPressureCleanup() noexcept;

    // 配置管理
    void SetHoldTimeMs(DWORD timeMs) noexcept;
    void SetWorkingSetLimit(size_t limitMB) noexcept;
    void SetMaxCacheSize(size_t maxSizeMB) noexcept;

    // 兼容性方法（为MemoryPool提供）
    size_t GetTotalCached() const noexcept;
    void SetWatermarkMB(size_t watermarkMB) noexcept;  // 兼容接口

    // 获取真实内存使用情况
    size_t GetWorkingSetSize() const noexcept;
    size_t GetCommittedSize() const noexcept;
    size_t GetVirtualSize() const noexcept;
    void PrintMemoryUsage() const noexcept;

    // 统计信息
    struct Statistics {
        size_t totalAllocated = 0;
        size_t totalFreed = 0;
        size_t currentCached = 0;
        size_t holdQueueSize = 0;
        size_t forceCleanups = 0;
        size_t conservativeCleanups = 0;   // 新增：保守清理次数

        // 各分档统计
        struct SizeClassStats {
            size_t totalCached = 0;
            size_t hitCount = 0;
            size_t missCount = 0;
            double hitRate = 0.0;
        } sizeClassStats[SIZE_CLASS_COUNT];

        // 内存使用统计
        size_t workingSetSize = 0;
        size_t committedSize = 0;
        size_t virtualSize = 0;
    };

    Statistics GetStatistics() const noexcept;
    void PrintStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    MemorySafety() noexcept;
    ~MemorySafety() noexcept;

    // 禁止拷贝
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;

    // 内部实现
    void* InternalAllocate(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept;
    bool InternalFree(void* userPtr) noexcept;
    void* InternalRealloc(void* userPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept;

    // 缓存管理 - 简化版本
    size_t GetSizeClass(size_t size) const noexcept;
    void* TryGetFromCache(size_t sizeClass, size_t minSize) noexcept;
    void AddToCache(void* rawPtr, size_t totalSize, size_t userSize, size_t sizeClass) noexcept;
    void CleanupCache(bool aggressiveCleanup = false) noexcept;

    // Hold队列管理
    void AddToHoldQueue(void* userPtr, void* rawPtr, size_t userSize, size_t sizeClass) noexcept;
    void ProcessExpiredItems() noexcept;
    void FlushHoldQueue() noexcept;

    // 直接VirtualAlloc分配（超大块）
    void* DirectVirtualAlloc(size_t size, const char* sourceName, DWORD sourceLine) noexcept;
    bool DirectVirtualFree(void* ptr) noexcept;

    // Storm兼容性
    void SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 内存压力检测 - 修复版本
    bool CheckWorkingSetPressure() const noexcept;
    bool CheckCommittedMemoryPressure() const noexcept;
    void ConservativeCleanup() noexcept;  // 保守清理策略

    // 工具函数
    size_t CalculateTotalSize(size_t userSize) const noexcept;
    void* GetUserPtrFromRaw(void* rawPtr) const noexcept;
    void* GetRawPtrFromUser(void* userPtr) const noexcept;
    size_t AlignSize(size_t size, size_t alignment = 16) const noexcept;
    void UpdateStatistics(size_t size, bool isAllocation, size_t sizeClass = SIZE_MAX) noexcept;

private:
    // 状态变量
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    // 配置参数
    MemorySafetyConfig m_config;
    mutable CRITICAL_SECTION m_configCs;

    // 大小分档缓存（简化版本）
    std::unique_ptr<SizeClassCache> m_sizeClassCaches[SIZE_CLASS_COUNT];

    // 块跟踪
    std::unordered_map<void*, BlockInfo> m_blockMap;  // userPtr -> BlockInfo
    mutable CRITICAL_SECTION m_blockMapCs;

    // Hold队列
    std::deque<HoldItem> m_holdQueue;
    mutable CRITICAL_SECTION m_holdQueueCs;

    // 统计数据
    std::atomic<size_t> m_totalAllocated{ 0 };
    std::atomic<size_t> m_totalFreed{ 0 };
    std::atomic<size_t> m_currentCached{ 0 };
    std::atomic<size_t> m_forceCleanups{ 0 };
    std::atomic<size_t> m_conservativeCleanups{ 0 };

    // 时间跟踪
    std::atomic<DWORD> m_lastCleanupTime{ 0 };
    std::atomic<DWORD> m_lastPressureCheckTime{ 0 };
};

// 全局访问宏
#define g_MemorySafety MemorySafety::GetInstance()

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    // 获取真实内存信息（修复版本）
    size_t GetProcessWorkingSetSize() noexcept;     // 工作集大小
    size_t GetProcessCommittedSize() noexcept;      // 已提交内存
    size_t GetProcessVirtualSize() noexcept;        // 虚拟内存总大小
    size_t GetSystemMemoryLoad() noexcept;          // 系统内存负载

    // 时间工具
    DWORD GetTickCount() noexcept;
    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept;

    // 大小对齐
    size_t AlignSize(size_t size, size_t alignment = 16) noexcept;
    size_t GetPageAlignedSize(size_t size) noexcept;

    // 内存验证
    bool IsValidMemoryRange(void* ptr, size_t size) noexcept;
    bool IsMemoryCommitted(void* ptr, size_t size) noexcept;
}