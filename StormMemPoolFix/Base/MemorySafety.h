// MemorySafety.h - 基于TLSF的高效内存管理系统（完整重写）
#pragma once

#include "pch.h"
#include "SafeExecute.h"
#include "../Storm/StormCommon.h"
#include <Storm/tlsf.h>
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <deque>

///////////////////////////////////////////////////////////////////////////////
// 配置常量
///////////////////////////////////////////////////////////////////////////////

constexpr size_t POOL_COUNT = 4;                    // TLSF池数量
constexpr size_t POOL_SIZES[] = {                   // 各池大小
    16 * 1024 * 1024,   // 16MB - 小块池
    64 * 1024 * 1024,   // 64MB - 中块池  
    256 * 1024 * 1024,  // 256MB - 大块池
    512 * 1024 * 1024   // 512MB - 超大块池
};
constexpr size_t POOL_THRESHOLDS[] = {              // 各池大小阈值
    64 * 1024,          // 64KB以下用小块池
    512 * 1024,         // 512KB以下用中块池
    4 * 1024 * 1024,    // 4MB以下用大块池
    SIZE_MAX            // 其余用超大块池
};

constexpr DWORD DEFAULT_HOLD_TIME_MS = 500;         // 缓冲时间
constexpr size_t MAX_HOLD_QUEUE_SIZE = 1000;        // Hold队列最大大小
constexpr DWORD MIN_CLEANUP_INTERVAL_MS = 5000;     // 最小清理间隔

///////////////////////////////////////////////////////////////////////////////
// 前向声明和结构定义
///////////////////////////////////////////////////////////////////////////////

// TLSF池实例
struct TLSFPoolInstance {
    void* baseMemory;                   // VirtualAlloc的大块内存
    size_t totalSize;                   // 池总大小
    tlsf_t tlsfHandle;                  // TLSF句柄
    std::atomic<size_t> usedBytes;      // 已使用字节数
    std::atomic<size_t> allocCount;     // 分配次数
    std::atomic<size_t> freeCount;      // 释放次数
    CRITICAL_SECTION cs;               // 线程保护

    TLSFPoolInstance();
    ~TLSFPoolInstance();
};

// Hold队列中的延迟释放项
struct HoldItem {
    void* userPtr;              // 用户指针
    void* rawPtr;               // 原始分配指针
    size_t userSize;            // 用户请求大小
    size_t poolIndex;           // 来源池索引
    DWORD queueTime;            // 入队时间

    HoldItem(void* user, void* raw, size_t size, size_t pool);
};

// 内存块信息
struct BlockInfo {
    void* rawPtr;               // 原始分配指针
    void* userPtr;              // 用户指针
    size_t totalSize;           // 总分配大小
    size_t userSize;            // 用户请求大小
    size_t poolIndex;           // 来源池索引
    DWORD allocTime;            // 分配时间
    const char* sourceName;     // 分配来源
    DWORD sourceLine;           // 分配行号
    bool isInHoldQueue;         // 是否在Hold队列中

    BlockInfo();
    BlockInfo(void* raw, void* user, size_t total, size_t userSz, size_t pool,
        const char* name, DWORD line);
};

// 配置参数
struct MemorySafetyConfig {
    DWORD holdBufferTimeMs = DEFAULT_HOLD_TIME_MS;
    size_t maxHoldQueueSize = MAX_HOLD_QUEUE_SIZE;
    size_t memoryWatermarkMB = 1400;
    bool enableDetailedLogging = false;
    bool enableHoldQueue = true;
    bool enablePressureMonitoring = true;
};

///////////////////////////////////////////////////////////////////////////////
// 主内存安全管理器
///////////////////////////////////////////////////////////////////////////////

class MemorySafety {
public:
    // 获取单例
    static MemorySafety& GetInstance() noexcept;

    // 生命周期管理
    bool Initialize(const MemorySafetyConfig& config = {}) noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept;

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

    // 内存压力管理
    bool IsMemoryUnderPressure() const noexcept;
    void ForceCleanup() noexcept;
    void TriggerPressureCleanup() noexcept;

    // 配置管理
    void SetHoldTimeMs(DWORD timeMs) noexcept;
    void SetWatermarkMB(size_t watermarkMB) noexcept;
    void SetMaxHoldQueueSize(size_t maxSize) noexcept;

    // 兼容性方法（为MemoryPool提供）
    size_t GetTotalCached() const noexcept;
    void SetMaxCacheSize(size_t maxSizeMB) noexcept;

    // 统计信息
    struct Statistics {
        size_t totalAllocated = 0;
        size_t totalFreed = 0;
        size_t currentUsed = 0;
        size_t holdQueueSize = 0;
        size_t forceCleanups = 0;

        // 各池统计
        struct PoolStats {
            size_t totalSize = 0;
            size_t usedBytes = 0;
            size_t allocCount = 0;
            size_t freeCount = 0;
            double utilization = 0.0;
        } poolStats[POOL_COUNT];

        size_t directVirtualAllocCount = 0;     // 直接VirtualAlloc次数
        size_t directVirtualAllocBytes = 0;     // 直接VirtualAlloc字节数
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

    // TLSF池管理
    bool InitializePools() noexcept;
    void DestroyPools() noexcept;
    size_t SelectPool(size_t size) const noexcept;
    void* AllocateFromPool(size_t poolIndex, size_t totalSize) noexcept;
    bool FreeToPool(size_t poolIndex, void* ptr) noexcept;

    // 大块直接分配（超过池限制的）
    void* DirectVirtualAlloc(size_t size) noexcept;
    bool DirectVirtualFree(void* ptr) noexcept;

    // Hold队列管理
    void AddToHoldQueue(void* userPtr, void* rawPtr, size_t userSize, size_t poolIndex) noexcept;
    void ProcessExpiredItems() noexcept;
    void FlushHoldQueue() noexcept;

    // Storm兼容性
    void SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 工具函数
    size_t CalculateTotalSize(size_t userSize) const noexcept;
    void* GetUserPtrFromRaw(void* rawPtr) const noexcept;
    void* GetRawPtrFromUser(void* userPtr) const noexcept;
    size_t AlignSize(size_t size, size_t alignment = 16) const noexcept;
    void UpdateStatistics(size_t size, bool isAllocation, size_t poolIndex = SIZE_MAX) noexcept;

private:
    // 状态变量
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_shutdownRequested;

    // 配置参数
    MemorySafetyConfig m_config;
    mutable CRITICAL_SECTION m_configCs;

    // TLSF池数组（使用裸指针）
    TLSFPoolInstance* m_pools[POOL_COUNT];

    // 块跟踪
    std::unordered_map<void*, BlockInfo> m_blockMap;  // userPtr -> BlockInfo
    mutable CRITICAL_SECTION m_blockMapCs;

    // Hold队列
    std::deque<HoldItem> m_holdQueue;
    mutable CRITICAL_SECTION m_holdQueueCs;

    // 统计数据
    std::atomic<size_t> m_totalAllocated;
    std::atomic<size_t> m_totalFreed;
    std::atomic<size_t> m_forceCleanups;
    std::atomic<size_t> m_directVirtualAllocCount;
    std::atomic<size_t> m_directVirtualAllocBytes;

    // 时间跟踪
    std::atomic<DWORD> m_lastCleanupTime;
};

// 全局访问宏
#define g_MemorySafety MemorySafety::GetInstance()

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    // 获取系统内存信息
    size_t GetProcessVirtualMemoryUsage() noexcept;
    size_t GetSystemMemoryLoad() noexcept;

    // 时间工具
    DWORD GetTickCount() noexcept;
    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept;

    // 大小对齐
    size_t AlignSize(size_t size, size_t alignment = 16) noexcept;
    size_t GetPageAlignedSize(size_t size) noexcept;

    // TLSF工具
    bool IsTLSFPointer(const void* ptr, const TLSFPoolInstance& pool) noexcept;
    size_t GetTLSFBlockSize(tlsf_t tlsf, void* ptr) noexcept;
}