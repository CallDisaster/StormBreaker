// MemorySafety.h - 修复SEH+RAII混用问题的版本
#pragma once

#include <Windows.h>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <cstring>

///////////////////////////////////////////////////////////////////////////////
// Storm兼容结构体 - 基于逆向文档
///////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
// 标准Storm块头 (8字节)
struct StormAllocHeader {
    DWORD  HeapPtr;         // 指向所属堆结构 (我们使用0xC0DEFEED标记)
    DWORD  Size;            // 块总大小 (32位，支持大块)
    BYTE   AlignPadding;    // 对齐填充字节数
    BYTE   Flags;           // 标志位: 0x1=尾魔数, 0x2=已释放, 0x4=大块, 0x8=特殊指针
    WORD   Magic;           // 前魔数 0x6F6D
};

// Storm大块页头 (16字节) - 完全按照逆向文档
struct StormLargePageHeader {
    DWORD  userSize;        // 0x00: 用户请求字节数
    void* blockPtr;        // 0x04: 对应BlockHeader指针
    WORD   pageCount;       // 0x08: (userSize+0xFFFF)>>16
    WORD   pageFlags;       // 0x0A: 固定0x0C00 (MEM_COMMIT)
    void* ownerHeap;       // 0x0C: 创建时的StormHeap指针
};
#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////
// SEH安全包装 - 完全分离C++对象和SEH
///////////////////////////////////////////////////////////////////////////////

// 纯C回调函数类型，避免C++对象
typedef int(__stdcall* SafeCallbackFn)(void* context);

// 纯C SEH包装函数，不包含任何C++对象
extern "C" int __stdcall SafeWrapper(void* context, SafeCallbackFn callback);

// C++模板包装器，C++对象在SEH外部
template<typename Func>
auto SafeExecute(Func&& func, const char* operation) noexcept -> decltype(func()) {
    using ReturnType = decltype(func());

    // 准备上下文结构
    struct CallContext {
        Func* function;
        ReturnType result;
        bool success;
        const char* operation;
    } context = { &func, {}, false, operation };

    // 纯C回调，在SEH内部执行
    auto callback = [](void* ctx) -> int {
        auto* callCtx = static_cast<CallContext*>(ctx);
        try {
            callCtx->result = (*(callCtx->function))();
            callCtx->success = true;
            return 1;
        }
        catch (...) {
            callCtx->success = false;
            return 0;
        }
        };

    // SEH包装调用
    int sehResult = SafeWrapper(&context,
        reinterpret_cast<SafeCallbackFn>(
            static_cast<int(__stdcall*)(void*)>(callback)
            )
    );

    if (sehResult && context.success) {
        return context.result;
    }

    // 异常时的默认值
    if constexpr (std::is_pointer_v<ReturnType>) {
        return nullptr;
    }
    else if constexpr (std::is_same_v<ReturnType, bool>) {
        return false;
    }
    else if constexpr (std::is_arithmetic_v<ReturnType>) {
        return static_cast<ReturnType>(0);
    }
    else if constexpr (std::is_same_v<ReturnType, void>) {
        return;
    }
    else {
        return ReturnType{};
    }
}

///////////////////////////////////////////////////////////////////////////////
// 常量定义
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyConst {
    // Storm魔数
    constexpr WORD STORM_FRONT_MAGIC = 0x6F6D;
    constexpr WORD STORM_TAIL_MAGIC = 0x12B1;
    constexpr DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

    // 大小常量
    constexpr size_t STANDARD_HEADER_SIZE = sizeof(StormAllocHeader);
    constexpr size_t LARGE_PAGE_HEADER_SIZE = sizeof(StormLargePageHeader);
    constexpr size_t TAIL_MAGIC_SIZE = 2;

    // 分档配置
    constexpr size_t SIZE_CLASS_SHIFT = 16;     // 64KB档位
    constexpr size_t SIZE_CLASS_COUNT = 16;     // 16个档位
    constexpr size_t MAX_CACHE_PER_CLASS = 8;   // 每档最多8个块

    // 时间配置
    constexpr DWORD DEFAULT_HOLD_TIME_MS = 500;
    constexpr DWORD MIN_CLEANUP_INTERVAL_MS = 5000;

    // 内存水位
    constexpr size_t DEFAULT_MEMORY_WATERMARK = 1400ULL * 1024 * 1024; // 1.4GB
    constexpr size_t DEFAULT_MAX_CACHE_SIZE = 256ULL * 1024 * 1024;     // 256MB
}

///////////////////////////////////////////////////////////////////////////////
// MemorySafety类声明
///////////////////////////////////////////////////////////////////////////////

class MemorySafety {
public:
    // 单例获取
    static MemorySafety& GetInstance() noexcept;

    // 生命周期
    bool Initialize() noexcept;
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept;

    // 内存操作
    void* AllocateBlock(size_t size, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;
    bool FreeBlock(void* ptr) noexcept;
    void* ReallocateBlock(void* oldPtr, size_t newSize, const char* sourceName = nullptr, DWORD sourceLine = 0) noexcept;

    // 查询
    bool IsOurBlock(void* ptr) const noexcept;
    size_t GetBlockSize(void* ptr) const noexcept;

    // 队列处理
    void ProcessHoldQueue() noexcept;
    void DrainHoldQueue() noexcept;
    size_t GetHoldQueueSize() const noexcept;

    // 内存压力管理
    void ForceCleanup() noexcept;
    bool IsMemoryUnderPressure() const noexcept;
    size_t GetTotalCached() const noexcept;

    // 配置
    void SetHoldTimeMs(DWORD timeMs) noexcept;
    void SetWatermarkMB(size_t watermarkMB) noexcept;
    void SetMaxCacheSize(size_t maxCacheMB) noexcept;

    // 统计
    struct Stats {
        std::atomic<size_t> totalAllocated{ 0 };
        std::atomic<size_t> totalFreed{ 0 };
        std::atomic<size_t> cacheHits{ 0 };
        std::atomic<size_t> cacheMisses{ 0 };
        std::atomic<size_t> holdQueueSize{ 0 };
        std::atomic<size_t> forceCleanups{ 0 };
    } stats;

private:
    MemorySafety() noexcept;
    ~MemorySafety() noexcept;
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;

    // 内部结构
    struct BlockInfo {
        void* rawPtr;           // VirtualAlloc返回的原始指针
        size_t totalSize;       // 包含头部的总大小
        size_t userSize;        // 用户请求的大小
        DWORD allocTime;        // 分配时间
        const char* sourceName; // 分配来源
        DWORD sourceLine;       // 分配行号
    };

    struct HoldQueueEntry {
        void* rawPtr;
        size_t totalSize;
        DWORD queueTime;
    };

    struct SizeClassCache {
        std::vector<HoldQueueEntry> freeBlocks;
        size_t totalCached;

        SizeClassCache() : totalCached(0) {}
    };

    // 内部实现
    void* InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine) noexcept;
    bool InternalFree(void* ptr) noexcept;
    void* InternalReallocate(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept;

    // 块管理
    void* CreateBlock(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept;
    bool DestroyBlock(void* rawPtr) noexcept;
    void SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 缓存管理
    size_t GetSizeClass(size_t size) const noexcept;
    void* TryGetFromCache(size_t sizeClass, size_t minSize) noexcept;
    void AddToCache(size_t sizeClass, void* rawPtr, size_t totalSize) noexcept;
    void CleanupSizeClass(size_t sizeClass, size_t maxRemove) noexcept;

    // 持有队列
    void AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept;
    void ProcessExpiredEntries() noexcept;

    // 哈希表管理
    void AddToHashTable(void* userPtr, const BlockInfo& info) noexcept;
    bool RemoveFromHashTable(void* userPtr, BlockInfo* outInfo = nullptr) noexcept;
    bool FindInHashTable(void* userPtr, BlockInfo* outInfo = nullptr) const noexcept;

    // 内存压力
    size_t GetProcessVirtualMemoryUsage() const noexcept;
    bool ShouldTriggerCleanup() const noexcept;

    // 日志
    void LogMessage(const char* format, ...) const noexcept;
    void LogError(const char* format, ...) const noexcept;

private:
    // 状态
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    // 配置
    std::atomic<DWORD> m_holdTimeMs{ MemorySafetyConst::DEFAULT_HOLD_TIME_MS };
    std::atomic<size_t> m_memoryWatermark{ MemorySafetyConst::DEFAULT_MEMORY_WATERMARK };
    std::atomic<size_t> m_maxCacheSize{ MemorySafetyConst::DEFAULT_MAX_CACHE_SIZE };

    // 同步对象
    mutable CRITICAL_SECTION m_hashTableCs;
    mutable CRITICAL_SECTION m_holdQueueCs;
    mutable CRITICAL_SECTION m_cacheCs[MemorySafetyConst::SIZE_CLASS_COUNT];
    mutable CRITICAL_SECTION m_logCs;

    // 数据结构
    std::unordered_map<void*, BlockInfo> m_blockHashTable;
    std::vector<HoldQueueEntry> m_holdQueue;
    SizeClassCache m_sizeClassCaches[MemorySafetyConst::SIZE_CLASS_COUNT];

    // 时间追踪
    std::atomic<DWORD> m_lastCleanupTime{ 0 };

    // 日志文件
    HANDLE m_logFile{ INVALID_HANDLE_VALUE };
};

///////////////////////////////////////////////////////////////////////////////
// 全局访问
///////////////////////////////////////////////////////////////////////////////

#define g_MemorySafety MemorySafety::GetInstance()

///////////////////////////////////////////////////////////////////////////////
// 实用函数
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    // 时间函数
    DWORD GetTickCount() noexcept;
    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept;

    // 大小对齐
    size_t AlignSize(size_t size, size_t alignment = 16) noexcept;
    size_t GetPageAlignedSize(size_t size) noexcept;

    // 指针验证
    bool IsValidPointer(void* ptr) noexcept;
    bool IsValidMemoryRange(void* ptr, size_t size) noexcept;
}