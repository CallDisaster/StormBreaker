#pragma once
#include "pch.h"
#include <Windows.h>
#include <stdint.h>
#include <atomic>

// ======================== TLSF内存池管理 ========================
namespace MemoryPool {

    enum class BackendKind : uint32_t {
        Tlsf = 0,
        Mimalloc = 1,
        TlsfSharded = 2,
        Hybrid = 3
    };

    // Routes are persisted by the Storm allocation header. Automatic is only
    // an API input/sentinel and is never returned for a successful operation.
    // Concrete values match LeakProfiler::BackendRoute for direct telemetry.
    enum class BackendRoute : uint8_t {
        Tlsf = 2,
        Mimalloc = 3,
        Automatic = 0xFF
    };
    static_assert(sizeof(BackendRoute) == sizeof(uint8_t));

    static constexpr size_t kHybridTlsfThreshold = 0xFE7B;

    struct RoutedAllocation {
        void* pointer;
        size_t usableSize;
        BackendRoute route;
    };

    enum class InPlaceReallocateStatus : uint8_t {
        Succeeded,
        Failed,
        NotOwned,
        InvalidArgument,
        BudgetExceeded
    };

    struct AllocationOwnership {
        BackendRoute route;
        size_t usableSize;
    };

    struct BatchFreeEntry {
        void* pointer;
        size_t requestedCharge;
    };

    struct BatchFreeResult {
        size_t freedCount;
        uint64_t usableBytes;
    };

    static_assert(sizeof(BatchFreeEntry) == 8,
        "BatchFreeEntry must retain its Win32 layout");

    using AllocationVisitor = bool (*)(
        void* pointer, size_t usableSize, BackendRoute route, void* context);
    using FreeValidator = bool (*)(
        void* pointer, size_t usableSize, void* context);

    // ======================== 初始化和清理 ========================
    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // ======================== 基本分配操作 ========================
    void* Allocate(size_t size);
    void* AllocateAligned(size_t size, size_t alignment);
    // Fast path for callers that persist the requested size in their own ABI
    // header and pair the allocation with FreeKnownSize.
    void* AllocateAlignedKnownSize(size_t size, size_t alignment);
    void* Reallocate(void* ptr, size_t newSize);
    void  Free(void* ptr);
    void  FreeKnownSize(void* ptr, size_t knownSize);
    void  FreeKnownSizeUntracked(void* ptr, size_t knownSize);

    // Full-takeover fast path. These calls never touch the legacy allocation
    // metadata map. The four-argument AllocateRouted overload separates the
    // physical backend allocation from its requested-live budget charge. This
    // permits Storm's non-null zero-size allocations: physicalSize includes
    // the header/canary while requestedCharge is zero.
    BackendRoute SelectRoute(size_t stormRequestedSize);
    RoutedAllocation AllocateRouted(
        size_t size, size_t alignment = 0,
        BackendRoute route = BackendRoute::Automatic);
    RoutedAllocation AllocateRouted(
        size_t physicalSize, size_t requestedCharge, size_t alignment,
        BackendRoute route);
    // The short realloc overload assumes new physical bytes equal the new
    // requested charge. Use the split overload for Storm headers/canaries and
    // especially for realloc(ptr, 0), where newRequestedCharge is zero but
    // newPhysicalSize remains nonzero.
    InPlaceReallocateStatus ReallocateInPlaceRouted(
        void* ptr, size_t oldRequestedSize, size_t newRequestedSize,
        BackendRoute route, size_t* newUsableSize = nullptr);
    InPlaceReallocateStatus ReallocateInPlaceRouted(
        void* ptr, size_t oldRequestedCharge, size_t newPhysicalSize,
        size_t newRequestedCharge, BackendRoute route,
        size_t* newUsableSize = nullptr);
    bool FreeRouted(
        void* ptr, size_t knownRequestedCharge, BackendRoute route,
        size_t* freedUsableSize = nullptr);
    bool FreeRoutedConditional(
        void* ptr, size_t knownRequestedCharge, BackendRoute route,
        FreeValidator validator, void* context,
        size_t* freedUsableSize = nullptr);
    // Bulk-destroy path for a caller-owned snapshot. Entries must all belong
    // to the explicit route; the backend validates exact allocation starts
    // while holding one operation lock and reports the successfully freed
    // prefix. This does not touch the legacy allocation metadata map.
    BatchFreeResult FreeRoutedBatch(
        const BatchFreeEntry* entries, size_t count, BackendRoute route);

    // OwnsAddress is deliberately conservative and remains true for an
    // interior/corrupted address inside a managed backend region.
    // QueryAllocation resolves the route and usable size for a caller-validated
    // raw pointer; only VisitAllocations is a definitive live-block snapshot.
    bool OwnsAddress(
        const void* ptr, BackendRoute* route = nullptr);
    bool QueryAllocation(
        void* ptr, AllocationOwnership* ownership);
    bool QueryAllocation(
        void* ptr, BackendRoute route, AllocationOwnership* ownership);

    // The callback receives each exact, currently-live raw backend allocation
    // while that route is protected against allocation/free. It may inspect the
    // Storm header and append matching pointers to pre-reserved caller storage,
    // but must not allocate, re-enter MemoryPool, or free during the callback.
    // The snapshot can be selectively freed after VisitAllocations returns.
    // Automatic visits every active route; false from the callback stops early.
    bool VisitAllocations(
        BackendRoute route, AllocationVisitor visitor, void* context);

    // ======================== 安全分配操作（SEH保护） ========================
    void* AllocateSafe(size_t size);
    void* AllocateAlignedSafe(size_t size, size_t alignment);
    void* ReallocateSafe(void* ptr, size_t newSize);
    void  FreeSafe(void* ptr);

    // ======================== 池状态查询 ========================
    bool  IsFromPool(void* ptr);
    size_t GetBlockSize(void* ptr);
    size_t GetUsedSize();
    size_t GetTotalSize();
    size_t GetFreeSize();

    // ======================== 池管理操作 ========================
    bool  ExtendPool(size_t additionalSize);
    void  TrimRoute(BackendRoute route);
    void  TrimFreePages();
    void  CompactPool();

    // ======================== 调试和统计 ========================
    struct PoolStats {
        size_t totalSize;
        size_t usedSize;
        size_t freeSize;
        size_t peakUsed;
        size_t allocCount;
        size_t freeCount;
        size_t extendCount;
        size_t trimCount;
    };

    static constexpr size_t kLatencyHistogramBucketCount = 12;

    struct LatencyHistogramStats {
        uint64_t upperBoundsNanoseconds[kLatencyHistogramBucketCount];
        uint64_t bucketCounts[kLatencyHistogramBucketCount + 1];
        uint64_t sampleCount;
        uint64_t totalNanoseconds;
        uint64_t maxNanoseconds;
    };

    struct ExtendedPoolStats {
        BackendKind backendKind;
        bool initialized;
        uint64_t requestedLiveBytes;
        uint64_t requestedLiveBudgetBytes;
        uint64_t usableLiveBytes;
        uint64_t reservedBytes;
        uint64_t committedBytes;
        uint64_t peakRequestedLiveBytes;
        uint64_t peakUsableLiveBytes;
        uint64_t peakReservedBytes;
        uint64_t peakCommittedBytes;
        uint64_t allocCount;
        uint64_t freeCount;
        uint64_t reallocCount;
        uint64_t failureCount;
        uint64_t extendCount;
        uint64_t trimCount;
        uint64_t lockWaitCount;
        uint64_t lockWaitNanoseconds;
        uint64_t maxLockWaitNanoseconds;
        LatencyHistogramStats lockWaitLatency;
        LatencyHistogramStats operationLatency;
        LatencyHistogramStats allocateLatency;
        LatencyHistogramStats freeLatency;
        LatencyHistogramStats reallocateLatency;
        LatencyHistogramStats copyLatency;
        LatencyHistogramStats growthLatency;
    };

    PoolStats GetStats();
    ExtendedPoolStats GetExtendedStats();
    // Lock-free hot-path counters for Storm exported accounting APIs.
    uint64_t GetRequestedLiveBytes();
    uint64_t GetUsableLiveBytes();
    BackendKind GetBackendKind();
    const char* GetBackendName();
    const char* GetBuildBackendIdentity();
    void PrintStats();
    void ResetStats();
    void SetLatencyTrackingEnabled(bool enabled);
    bool IsLatencyTrackingEnabled();
    void RecordCopyLatency(uint64_t nanoseconds);
    void RecordGrowthLatency(uint64_t nanoseconds);

    // ======================== 高级操作 ========================
    void* CreateStabilizingBlock(size_t size, const char* purpose = nullptr);
    void  FlushStabilizingBlocks();

    // ======================== 线程安全保证 ========================
    void EnableThreadSafety();
    void DisableThreadSafety();
    bool IsThreadSafeEnabled();

    // ======================== 内存压力响应 ========================
    void OnMemoryPressure();
    void OnMemoryAvailable();

    // ======================== 配置参数 ========================
    struct Config {
        size_t initialSize;        // 初始池大小
        size_t maxSize;           // 最大池大小
        size_t extendGranularity; // 扩展粒度
        size_t alignment;         // 默认对齐
        bool   enableDebug;       // 调试模式
        bool   enableStats;       // 统计模式
    };

    bool SetConfig(const Config& config);
    Config GetConfig();

    // ======================== 内部状态（测试用） ========================
    namespace Internal {
        void* GetTLSFHandle();
        size_t GetPoolCount();
        void DumpPoolInfo();
        bool ValidatePool();
#if defined(STORMBREAKER_TESTING)
        void SetTlsfRangeIndexEnabledForTesting(bool enabled);
        void SetTlsfMainPoolDecommitEnabledForTesting(bool enabled);
        void SetTlsfTopDownEnabledForTesting(bool enabled);
        void SetTlsfConstantTimeEmptyCheckEnabledForTesting(bool enabled);
        void SetTlsfShardAffinityForTesting(size_t shardIndex);
        void SetTlsfShardExtendFailureForTesting(size_t shardIndex);
        void SetDetailedCounterBatchingEnabledForTesting(bool enabled);
#endif
    }
}

// ======================== JassVM专用内存池 ========================
namespace JVM_MemPool {
    bool Initialize();
    void Cleanup();

    void* Allocate(size_t size);
    void  Free(void* ptr);
    void* Realloc(void* oldPtr, size_t newSize);
    bool  IsFromPool(void* ptr);

    size_t GetUsedSize();
    void PrintStats();
}

// ======================== 小块内存池 ========================
namespace SmallBlockPool {
    bool Initialize();
    void Cleanup();

    bool ShouldIntercept(size_t size);
    void* Allocate(size_t size);
    bool Free(void* ptr, size_t size);

    void FlushCache();
    void PrintStats();
}
