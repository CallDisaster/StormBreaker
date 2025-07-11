// MemorySafety.h - 完整重写的内存安全管理器
// 基于GPT研究的"缓冲窗口+大小分档+内存压力监控"方案
#pragma once

#include <Windows.h>
#include <psapi.h>
#include <atomic>
#include <unordered_map>
#include <queue>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <chrono>

// 确保只定义一次StormAllocHeader
#ifndef STORM_ALLOC_HEADER_DEFINED
#define STORM_ALLOC_HEADER_DEFINED

#pragma pack(push, 1)
struct StormAllocHeader {
    DWORD HeapPtr;      // 指向所属堆结构 (我们使用0xC0DEFEED特殊标记)
    DWORD Size;         // 用户数据区大小
    BYTE  AlignPadding; // 对齐填充字节数
    BYTE  Flags;        // 标志位: 0x1=魔数校验, 0x2=已释放, 0x4=大块VirtualAlloc, 0x8=特殊指针
    WORD  Magic;        // 前魔数 (0x6F6D)
    // 用户数据从这里开始
    // 如果 Flags & 1，则在用户数据末尾还有 WORD tailMagic = 0x12B1
};
#pragma pack(pop)

#endif // STORM_ALLOC_HEADER_DEFINED

///////////////////////////////////////////////////////////////////////////////
// 核心常量定义
///////////////////////////////////////////////////////////////////////////////

// Storm魔数常量（基于逆向文档）
constexpr WORD STORM_FRONT_MAGIC = 0x6F6D;
constexpr WORD STORM_TAIL_MAGIC = 0x12B1;
constexpr DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

// 核心配置常量
constexpr size_t DEFAULT_HOLD_TIME_MS = 500;         // 缓冲窗口：500ms
constexpr size_t DEFAULT_WATERMARK_MB = 1400;        // 内存水位：1.4GB
constexpr size_t DEFAULT_MAX_CACHE_SIZE_MB = 256;    // 最大缓存：256MB
constexpr size_t SIZE_CLASS_UNIT = 64 * 1024;        // Size Class单位：64KB
constexpr size_t MAX_SIZE_CLASSES = 16;              // 最大分档数：16档
constexpr size_t MIN_CLEANUP_INTERVAL_MS = 5000;     // 最小清理间隔：5秒

// 内存对齐工具函数
inline size_t AlignSize(size_t size, size_t alignment = 16) noexcept {
    return (size + alignment - 1) & ~(alignment - 1);
}

inline size_t GetPageAlignedSize(size_t size) noexcept {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return AlignSize(size, si.dwPageSize);
}

///////////////////////////////////////////////////////////////////////////////
// 时间和系统工具函数
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    // 使用GetTickCount64避免49.7天回绕问题
    inline DWORD GetTickCount() noexcept {
        return static_cast<DWORD>(::GetTickCount64() & 0xFFFFFFFF);
    }

    inline bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept {
        DWORD currentTime = GetTickCount();
        // 处理可能的回绕
        if (currentTime >= startTime) {
            return (currentTime - startTime) >= intervalMs;
        }
        else {
            // 发生回绕的情况
            return ((0xFFFFFFFF - startTime) + currentTime + 1) >= intervalMs;
        }
    }

    inline size_t GetProcessVirtualMemoryUsage() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PrivateUsage;
        }
        return 0;
    }

    // 检查指针有效性
    inline bool IsValidPointer(void* ptr) noexcept {
        if (!ptr) return false;
        __try {
            volatile char test = *static_cast<char*>(ptr);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// SEH安全执行模板
///////////////////////////////////////////////////////////////////////////////

template<typename Func>
auto SafeExecute(Func&& func, const char* operation) noexcept {
    using ReturnType = decltype(func());

    __try {
        if constexpr (std::is_same_v<ReturnType, void>) {
            func();
            return;
        }
        else {
            return func();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[MemorySafety SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);

        if constexpr (std::is_same_v<ReturnType, void>) {
            return;
        }
        else if constexpr (std::is_pointer_v<ReturnType>) {
            return nullptr;
        }
        else if constexpr (std::is_same_v<ReturnType, bool>) {
            return false;
        }
        else if constexpr (std::is_arithmetic_v<ReturnType>) {
            return static_cast<ReturnType>(0);
        }
        else {
            return ReturnType{};
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// 数据结构定义
///////////////////////////////////////////////////////////////////////////////

// 内存块信息
struct BlockInfo {
    void* rawPtr;           // 原始VirtualAlloc指针
    void* userPtr;          // 用户数据指针
    size_t totalSize;       // 总分配大小
    size_t userSize;        // 用户数据大小
    DWORD allocTime;        // 分配时间
    const char* sourceName; // 分配来源
    DWORD sourceLine;       // 源代码行号
    bool isValid;           // 是否有效

    BlockInfo() noexcept
        : rawPtr(nullptr), userPtr(nullptr), totalSize(0), userSize(0)
        , allocTime(0), sourceName(nullptr), sourceLine(0), isValid(false) {
    }

    BlockInfo(void* raw, void* user, size_t total, size_t userSz,
        const char* name, DWORD line) noexcept
        : rawPtr(raw), userPtr(user), totalSize(total), userSize(userSz)
        , allocTime(MemorySafetyUtils::GetTickCount()), sourceName(name)
        , sourceLine(line), isValid(true) {
    }
};

// Hold队列项
struct HoldQueueItem {
    void* rawPtr;
    size_t totalSize;
    DWORD releaseTime;

    HoldQueueItem(void* ptr, size_t size) noexcept
        : rawPtr(ptr), totalSize(size)
        , releaseTime(MemorySafetyUtils::GetTickCount()) {
    }
};

// Size Class缓存项
struct CacheItem {
    void* rawPtr;
    size_t totalSize;
    DWORD cacheTime;

    CacheItem(void* ptr, size_t size) noexcept
        : rawPtr(ptr), totalSize(size)
        , cacheTime(MemorySafetyUtils::GetTickCount()) {
    }
};

///////////////////////////////////////////////////////////////////////////////
// 主要的MemorySafety类
///////////////////////////////////////////////////////////////////////////////

class MemorySafety {
public:
    // 获取单例实例
    static MemorySafety& GetInstance() noexcept {
        static MemorySafety instance;
        return instance;
    }

    // 生命周期管理
    bool Initialize() noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept { return m_initialized.load(); }

    // 主要内存接口
    void* AllocateBlock(size_t size, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool FreeBlock(void* userPtr) noexcept;
    void* ReallocateBlock(void* oldUserPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 查询接口
    bool IsOurBlock(void* userPtr) const noexcept;
    size_t GetBlockSize(void* userPtr) const noexcept;
    BlockInfo GetBlockInfo(void* userPtr) const noexcept;

    // Hold队列管理
    void ProcessHoldQueue() noexcept;
    void DrainHoldQueue() noexcept;
    size_t GetHoldQueueSize() const noexcept;

    // 压力清理
    void ForceCleanup() noexcept;
    size_t FlushCacheByPressure(int pressureLevel) noexcept;

    // 配置管理
    void SetHoldTimeMs(DWORD holdTimeMs) noexcept { m_holdTimeMs.store(holdTimeMs); }
    void SetWatermarkMB(size_t watermarkMB) noexcept { m_watermarkMB.store(watermarkMB); }
    void SetMaxCacheSize(size_t maxCacheMB) noexcept { m_maxCacheSizeMB.store(maxCacheMB); }

    // 统计信息
    size_t GetTotalCached() const noexcept;
    size_t GetCacheHitCount() const noexcept { return m_cacheHits.load(); }
    size_t GetCacheMissCount() const noexcept { return m_cacheMisses.load(); }
    size_t GetTotalAllocated() const noexcept { return m_totalAllocated.load(); }
    size_t GetTotalFreed() const noexcept { return m_totalFreed.load(); }

private:
    MemorySafety() noexcept = default;
    ~MemorySafety() noexcept = default;

    // 禁止拷贝
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;

    // 内部实现
    void* InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine) noexcept;
    bool InternalFree(void* userPtr) noexcept;
    void* InternalRealloc(void* oldUserPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept;

    // Storm兼容头部管理
    void SetupStormHeader(void* userPtr, size_t userSize) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 缓存管理
    void* TryGetFromCache(size_t size) noexcept;
    void AddToCache(void* rawPtr, size_t totalSize) noexcept;
    size_t GetSizeClass(size_t size) const noexcept;

    // Hold队列管理
    void AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept;
    void ProcessExpiredItems() noexcept;

    // 内存压力检查
    bool IsMemoryUnderPressure() const noexcept;
    void TriggerPressureCleanup() noexcept;

    // 工具函数
    size_t CalculateTotalSize(size_t userSize) const noexcept;
    void* GetRawPtrFromUser(void* userPtr) const noexcept;
    void* GetUserPtrFromRaw(void* rawPtr, size_t userSize) const noexcept;

private:
    // 基本状态
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    // 配置参数
    std::atomic<DWORD> m_holdTimeMs{ DEFAULT_HOLD_TIME_MS };
    std::atomic<size_t> m_watermarkMB{ DEFAULT_WATERMARK_MB };
    std::atomic<size_t> m_maxCacheSizeMB{ DEFAULT_MAX_CACHE_SIZE_MB };

    // 块追踪
    mutable std::mutex m_blockMapMutex;
    std::unordered_map<void*, BlockInfo> m_blockMap;

    // Hold队列
    mutable std::mutex m_holdQueueMutex;
    std::queue<HoldQueueItem> m_holdQueue;

    // Size Class缓存
    struct SizeClassCache {
        mutable std::mutex mutex;
        std::vector<CacheItem> items;
        std::atomic<size_t> totalSize{ 0 };
    };
    SizeClassCache m_sizeClassCaches[MAX_SIZE_CLASSES];

    // 统计数据
    std::atomic<size_t> m_cacheHits{ 0 };
    std::atomic<size_t> m_cacheMisses{ 0 };
    std::atomic<size_t> m_totalAllocated{ 0 };
    std::atomic<size_t> m_totalFreed{ 0 };
    std::atomic<size_t> m_currentCached{ 0 };

    // 最后清理时间
    std::atomic<DWORD> m_lastCleanupTime{ 0 };
};

// 设置Storm兼容头部的独立函数
void SetupCompatibleHeader(void* userPtr, size_t userSize) noexcept;