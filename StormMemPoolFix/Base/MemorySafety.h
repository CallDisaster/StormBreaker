// MemorySafety.h - 完整的内存安全管理器头文件
#pragma once

#include "pch.h"
#include "SafeExecute.h"
#include "../Storm/StormCommon.h"  // 使用共享定义
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <mutex>

///////////////////////////////////////////////////////////////////////////////
// 常量定义
///////////////////////////////////////////////////////////////////////////////

constexpr size_t MAX_SIZE_CLASSES = 16;           // 最大分档数
constexpr size_t SIZE_CLASS_UNIT = 64 * 1024;     // 分档单位：64KB
constexpr DWORD MIN_CLEANUP_INTERVAL_MS = 5000;   // 最小清理间隔

///////////////////////////////////////////////////////////////////////////////
// 内存安全管理器 - 基于GPT研究的缓冲窗口+大小分档方案
///////////////////////////////////////////////////////////////////////////////

// 配置参数结构
struct MemorySafetyConfig {
    DWORD holdBufferTimeMs = 500;          // 缓冲时间：500ms
    size_t maxCacheSizeMB = 256;           // 最大缓存：256MB
    size_t memoryWatermarkMB = 1400;       // 内存水位：1.4GB
    size_t sizeClassUnit = 64 * 1024;      // 分档单位：64KB
    size_t maxSizeClasses = 16;            // 最大分档数：16档
    bool enableDetailedLogging = false;    // 详细日志
};

// 内存块信息
struct BlockInfo {
    void* rawPtr;               // 原始分配指针（VirtualAlloc返回的）
    void* userPtr;              // 用户指针（rawPtr + sizeof(StormAllocHeader)）
    size_t totalSize;           // 总分配大小
    size_t userSize;            // 用户请求大小
    DWORD allocTime;            // 分配时间
    const char* sourceName;     // 分配来源
    DWORD sourceLine;           // 分配行号
    bool isHeld;                // 是否在Hold队列中

    BlockInfo() : rawPtr(nullptr), userPtr(nullptr), totalSize(0), userSize(0),
        allocTime(0), sourceName(nullptr), sourceLine(0), isHeld(false) {
    }

    BlockInfo(void* raw, void* user, size_t total, size_t userSz,
        const char* name, DWORD line)
        : rawPtr(raw), userPtr(user), totalSize(total), userSize(userSz),
        allocTime(GetTickCount()), sourceName(name), sourceLine(line), isHeld(false) {
    }
};

// Hold队列中的延迟释放项
struct HoldItem {
    void* rawPtr;
    size_t totalSize;
    DWORD queueTime;
    size_t sizeClass;

    HoldItem(void* ptr, size_t size, DWORD time, size_t sc)
        : rawPtr(ptr), totalSize(size), queueTime(time), sizeClass(sc) {
    }
};

// 缓存项
struct CacheItem {
    void* rawPtr;
    size_t totalSize;
    DWORD cacheTime;

    CacheItem(void* ptr, size_t size)
        : rawPtr(ptr), totalSize(size), cacheTime(GetTickCount()) {
    }
};

// 大小分档缓存
struct SizeClassCache {
    std::vector<CacheItem> freeBlocks;    // 空闲块列表
    size_t totalCached;                   // 缓存的总字节数
    size_t hitCount;                      // 命中次数
    size_t missCount;                     // 未命中次数
    std::mutex mutex;                     // 线程保护

    SizeClassCache() : totalCached(0), hitCount(0), missCount(0) {}
};

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

    // Hold队列处理
    void ProcessHoldQueue() noexcept;
    void DrainHoldQueue() noexcept;
    size_t GetHoldQueueSize() const noexcept;

    // 内存压力管理
    bool IsMemoryUnderPressure() const noexcept;
    void ForceCleanup() noexcept;
    size_t GetTotalCached() const noexcept;

    // 配置和统计
    void SetHoldTimeMs(DWORD timeMs) noexcept;
    void SetWatermarkMB(size_t watermarkMB) noexcept;
    void SetMaxCacheSize(size_t maxSizeMB) noexcept;

    // 统计信息
    struct Statistics {
        size_t totalAllocated = 0;
        size_t totalFreed = 0;
        size_t currentCached = 0;
        size_t holdQueueSize = 0;
        size_t cacheHits = 0;
        size_t cacheMisses = 0;
        size_t forceCleanups = 0;
        double hitRate = 0.0;
    };

    Statistics GetStatistics() const noexcept;
    void PrintStatistics() const noexcept;

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

    // 缓存管理
    size_t GetSizeClass(size_t size) const noexcept;
    void* TryGetFromCache(size_t sizeClass, size_t minSize) noexcept;
    void AddToCache(void* rawPtr, size_t totalSize) noexcept;
    void CleanupCache(size_t targetSizeClass = SIZE_MAX) noexcept;

    // Hold队列管理
    void AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept;
    void ProcessExpiredItems() noexcept;
    void FlushCacheByPressure() noexcept;
    void TriggerPressureCleanup() noexcept;

    // Storm兼容性
    void SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 工具函数
    size_t CalculateTotalSize(size_t userSize) const noexcept;
    void UpdateStatistics(size_t size, bool isAllocation) noexcept;
    bool IsValidPointer(void* ptr) const noexcept;
    void* GetUserPtrFromRaw(void* rawPtr) const noexcept;
    void* GetRawPtrFromUser(void* userPtr) const noexcept;
    size_t AlignSize(size_t size, size_t alignment = 16) const noexcept;

private:
    // 状态变量
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    // 配置参数
    DWORD m_holdTimeMs{ 500 };
    size_t m_watermarkMB{ 1400 };
    size_t m_maxCacheSizeMB{ 256 };
    mutable std::mutex m_configMutex;

    // 块跟踪
    std::unordered_map<void*, BlockInfo> m_blockMap;  // userPtr -> BlockInfo
    mutable std::mutex m_blockMapMutex;

    // Hold队列
    std::vector<HoldItem> m_holdQueue;
    mutable std::mutex m_holdQueueMutex;

    // 大小分档缓存
    std::vector<std::unique_ptr<SizeClassCache>> m_sizeClassCaches;

    // 统计数据
    std::atomic<size_t> m_totalAllocated{ 0 };
    std::atomic<size_t> m_totalFreed{ 0 };
    std::atomic<size_t> m_currentCached{ 0 };
    std::atomic<size_t> m_cacheHits{ 0 };
    std::atomic<size_t> m_cacheMisses{ 0 };
    std::atomic<size_t> m_forceCleanups{ 0 };

    // 时间跟踪
    std::atomic<DWORD> m_lastCleanupTime{ 0 };
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
}