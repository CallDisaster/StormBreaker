#include "pch.h"

#include "MemoryPool.h"
#include "MemoryBackend.h"

#include "Base/Logger.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef STORMBREAKER_BENCHMARK_PINNED_HOTPATH
#define STORMBREAKER_BENCHMARK_PINNED_HOTPATH 0
#endif

static_assert(sizeof(size_t) == 4,
    "StormBreaker MemoryPool supports Win32/x86 only.");

#ifndef STORMBREAKER_DEFAULT_BACKEND
#define STORMBREAKER_DEFAULT_BACKEND 0
#endif
#ifndef STORMBREAKER_LOCK_MEMORY_BACKEND
#define STORMBREAKER_LOCK_MEMORY_BACKEND 0
#endif
#ifndef STORMBREAKER_PINNED_RUNTIME
#define STORMBREAKER_PINNED_RUNTIME 0
#endif
static_assert(STORMBREAKER_DEFAULT_BACKEND >= 0 &&
                  STORMBREAKER_DEFAULT_BACKEND <= 2,
    "STORMBREAKER_DEFAULT_BACKEND must be 0 (TLSF), 1 (mimalloc), "
    "or 2 (hybrid).");

namespace {

using Clock = std::chrono::steady_clock;
using MemoryPool::BackendKind;
using MemoryPool::BackendRoute;
using MemoryPool::ExtendedPoolStats;
using MemoryPool::Internal::BackendStats;
using MemoryPool::Internal::MemoryBackend;
using MemoryPool::LatencyHistogramStats;

constexpr BackendKind kCompiledDefaultBackend =
    STORMBREAKER_DEFAULT_BACKEND == 2
        ? BackendKind::Hybrid
        : (STORMBREAKER_DEFAULT_BACKEND == 1
            ? BackendKind::Mimalloc
            : BackendKind::Tlsf);
#if STORMBREAKER_LOCK_MEMORY_BACKEND
#if STORMBREAKER_DEFAULT_BACKEND == 2
constexpr char kBuildBackendIdentity[] = "locked-hybrid";
#elif STORMBREAKER_DEFAULT_BACKEND == 1
constexpr char kBuildBackendIdentity[] = "locked-mimalloc";
#else
constexpr char kBuildBackendIdentity[] = "locked-tlsf";
#endif
#else
#if STORMBREAKER_DEFAULT_BACKEND == 2
constexpr char kBuildBackendIdentity[] = "runtime-selectable-default-hybrid";
#elif STORMBREAKER_DEFAULT_BACKEND == 1
constexpr char kBuildBackendIdentity[] = "runtime-selectable-default-mimalloc";
#else
constexpr char kBuildBackendIdentity[] = "runtime-selectable-default-tlsf";
#endif
#endif

constexpr size_t kRequestedLiveBudgetBytes = size_t{1} << 30;
constexpr uint64_t kLatencyUpperBounds[] = {
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    25000,
    50000,
    100000,
    250000,
    1000000
};
static_assert(
    sizeof(kLatencyUpperBounds) / sizeof(kLatencyUpperBounds[0]) ==
        MemoryPool::kLatencyHistogramBucketCount,
    "Latency histogram bounds must match the public snapshot.");

template <typename T>
void UpdateMaximum(std::atomic<T>& target, T value) {
    T current = target.load(std::memory_order_relaxed);
    while (value > current &&
        !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
    }
}

template <typename T>
void SaturatingSubtract(std::atomic<T>& target, T value) {
    T current = target.load(std::memory_order_relaxed);
    for (;;) {
        const T next = current > value ? current - value : 0;
        if (target.compare_exchange_weak(
                current, next, std::memory_order_relaxed)) {
            return;
        }
    }
}

struct AtomicHistogram {
    void Record(uint64_t nanoseconds) {
        size_t bucket = 0;
        while (bucket < MemoryPool::kLatencyHistogramBucketCount &&
            nanoseconds > kLatencyUpperBounds[bucket]) {
            ++bucket;
        }

        bucketCounts[bucket].fetch_add(1, std::memory_order_relaxed);
        sampleCount.fetch_add(1, std::memory_order_relaxed);
        totalNanoseconds.fetch_add(nanoseconds, std::memory_order_relaxed);
        UpdateMaximum(maxNanoseconds, nanoseconds);
    }

    LatencyHistogramStats Snapshot() const {
        LatencyHistogramStats result{};
        for (size_t i = 0; i < MemoryPool::kLatencyHistogramBucketCount; ++i) {
            result.upperBoundsNanoseconds[i] = kLatencyUpperBounds[i];
        }
        for (size_t i = 0;
            i < MemoryPool::kLatencyHistogramBucketCount + 1; ++i) {
            result.bucketCounts[i] =
                bucketCounts[i].load(std::memory_order_relaxed);
        }
        result.sampleCount = sampleCount.load(std::memory_order_relaxed);
        result.totalNanoseconds =
            totalNanoseconds.load(std::memory_order_relaxed);
        result.maxNanoseconds = maxNanoseconds.load(std::memory_order_relaxed);
        return result;
    }

    void Reset() {
        for (std::atomic<uint64_t>& bucket : bucketCounts) {
            bucket.store(0, std::memory_order_relaxed);
        }
        sampleCount.store(0, std::memory_order_relaxed);
        totalNanoseconds.store(0, std::memory_order_relaxed);
        maxNanoseconds.store(0, std::memory_order_relaxed);
    }

    std::atomic<uint64_t>
        bucketCounts[MemoryPool::kLatencyHistogramBucketCount + 1]{};
    std::atomic<uint64_t> sampleCount{0};
    std::atomic<uint64_t> totalNanoseconds{0};
    std::atomic<uint64_t> maxNanoseconds{0};
};

enum class OperationKind {
    Allocate,
    Free,
    Reallocate
};

struct BackendSet {
    BackendKind kind = BackendKind::Tlsf;
    MemoryBackend* tlsf = nullptr;
    MemoryBackend* mimalloc = nullptr;
};

std::mutex g_lifecycleMutex;
// Deliberately raw: a pinned ASI must not let CRT global destruction tear down
// the allocator during process-detach ordering. The published route set is
// immutable. Explicit Shutdown is valid only after callers are quiesced; the
// release process-exit path intentionally leaves it for the OS.
std::atomic<BackendSet*> g_backendSet{nullptr};
std::atomic<bool> g_backendClosing{false};
std::atomic<uint32_t> g_activeBackendOperations{0};
thread_local uint32_t tls_backendOperationDepth = 0;
std::atomic<bool> g_threadSafeEnabled{true};
std::atomic<bool> g_latencyTrackingEnabled{false};
std::atomic<BackendKind> g_selectedBackend{kCompiledDefaultBackend};

class BackendOperationPin final {
public:
    BackendOperationPin() {
#if STORMBREAKER_PINNED_RUNTIME || STORMBREAKER_BENCHMARK_PINNED_HOTPATH
        active_ = true;
#else
        if (tls_backendOperationDepth != 0) {
            ++tls_backendOperationDepth;
            active_ = true;
            return;
        }
        if (g_backendClosing.load(std::memory_order_acquire)) {
            return;
        }
        g_activeBackendOperations.fetch_add(1, std::memory_order_acq_rel);
        if (g_backendClosing.load(std::memory_order_acquire)) {
            g_activeBackendOperations.fetch_sub(1, std::memory_order_release);
            return;
        }
        tls_backendOperationDepth = 1;
        active_ = true;
        outermost_ = true;
#endif
    }

    ~BackendOperationPin() {
#if STORMBREAKER_PINNED_RUNTIME || STORMBREAKER_BENCHMARK_PINNED_HOTPATH
        return;
#else
        if (!active_) {
            return;
        }
        --tls_backendOperationDepth;
        if (outermost_) {
            g_activeBackendOperations.fetch_sub(1, std::memory_order_release);
        }
#endif
    }

    explicit operator bool() const { return active_; }

private:
    bool active_ = false;
    bool outermost_ = false;
};

MemoryPool::Config g_config = {
    64u * 1024u * 1024u,
    1024u * 1024u * 1024u,
    16u * 1024u * 1024u,
    16u,
    false,
    true
};

struct AllocationRecord {
    size_t requestedBytes;
    size_t usableBytes;
    BackendRoute route;
};

std::mutex g_allocationMutex;
std::unordered_map<void*, AllocationRecord> g_allocations;
std::atomic<uint64_t> g_metadataLockWaitCount{0};
std::atomic<uint64_t> g_metadataLockWaitNanoseconds{0};
std::atomic<uint64_t> g_metadataMaxLockWaitNanoseconds{0};

std::atomic<size_t> g_budgetInUseBytes{0};
std::atomic<size_t> g_usableLiveBytes{0};
std::atomic<size_t> g_peakRequestedLiveBytes{0};
std::atomic<size_t> g_peakUsableLiveBytes{0};
// Diagnostic operation totals do not participate in allocator correctness.
// Keep them as lock-free Win32 counters; public snapshots widen to uint64_t.
std::atomic<uint32_t> g_allocCount{0};
std::atomic<uint32_t> g_freeCount{0};
std::atomic<uint32_t> g_reallocCount{0};
std::atomic<uint64_t> g_failureCount{0};

enum class DetailedOperationCounter : uint8_t {
    Allocate,
    Free,
    Reallocate
};

#if defined(STORMBREAKER_TESTING)
constexpr uint32_t kDetailedCounterBatchSize = 256u;
std::atomic<bool> g_testingDetailedCounterBatchingEnabled{false};

struct DetailedCounterBatch {
    ~DetailedCounterBatch() noexcept { Flush(); }

    void Flush() noexcept {
        if (allocates != 0) {
            g_allocCount.fetch_add(allocates, std::memory_order_relaxed);
            allocates = 0;
        }
        if (frees != 0) {
            g_freeCount.fetch_add(frees, std::memory_order_relaxed);
            frees = 0;
        }
        if (reallocates != 0) {
            g_reallocCount.fetch_add(reallocates, std::memory_order_relaxed);
            reallocates = 0;
        }
    }

    uint32_t allocates = 0;
    uint32_t frees = 0;
    uint32_t reallocates = 0;
};

thread_local DetailedCounterBatch tls_detailedCounterBatch;
#endif

template <typename T>
void IncrementDetailedCounter(std::atomic<T>& counter) {
    if (g_config.enableStats) {
        counter.fetch_add(1, std::memory_order_relaxed);
    }
}

void FlushDetailedCountersForCurrentThread() noexcept {
#if defined(STORMBREAKER_TESTING)
    tls_detailedCounterBatch.Flush();
#endif
}

void AddDetailedOperationCounter(
    DetailedOperationCounter kind, uint32_t amount = 1u) noexcept {
    if (!g_config.enableStats || amount == 0) {
        return;
    }

    std::atomic<uint32_t>* target = nullptr;
#if defined(STORMBREAKER_TESTING)
    uint32_t* pending = nullptr;
#endif
    switch (kind) {
    case DetailedOperationCounter::Allocate:
        target = &g_allocCount;
#if defined(STORMBREAKER_TESTING)
        pending = &tls_detailedCounterBatch.allocates;
#endif
        break;
    case DetailedOperationCounter::Free:
        target = &g_freeCount;
#if defined(STORMBREAKER_TESTING)
        pending = &tls_detailedCounterBatch.frees;
#endif
        break;
    case DetailedOperationCounter::Reallocate:
        target = &g_reallocCount;
#if defined(STORMBREAKER_TESTING)
        pending = &tls_detailedCounterBatch.reallocates;
#endif
        break;
    }

#if defined(STORMBREAKER_TESTING)
    if (g_testingDetailedCounterBatchingEnabled.load(
            std::memory_order_relaxed)) {
        if (amount >= kDetailedCounterBatchSize) {
            target->fetch_add(amount, std::memory_order_relaxed);
            return;
        }
        *pending += amount;
        if (*pending >= kDetailedCounterBatchSize) {
            target->fetch_add(*pending, std::memory_order_relaxed);
            *pending = 0;
        }
        return;
    }
#endif
    target->fetch_add(amount, std::memory_order_relaxed);
}

AtomicHistogram g_operationLatency;
AtomicHistogram g_allocateLatency;
AtomicHistogram g_freeLatency;
AtomicHistogram g_reallocateLatency;
AtomicHistogram g_copyLatency;
AtomicHistogram g_growthLatency;

std::mutex g_stabilizingMutex;
std::vector<void*> g_stabilizingBlocks;

const char* BackendName(BackendKind kind) {
    switch (kind) {
    case BackendKind::Tlsf:
        return "tlsf";
    case BackendKind::Mimalloc:
        return "mimalloc";
    case BackendKind::TlsfSharded:
        return "tlsf-sharded";
    case BackendKind::Hybrid:
        return "hybrid";
    default:
        return "unknown";
    }
}

bool ParseBackendEnvironment(BackendKind& kind) {
#if STORMBREAKER_LOCK_MEMORY_BACKEND
    kind = kCompiledDefaultBackend;
    Logger::GetInstance().LogInfo(
        "Memory backend is locked by this build: %s (%s)", BackendName(kind),
        kBuildBackendIdentity);
    return true;
#else
    char value[32] = {};
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_MEMORY_BACKEND", value,
        static_cast<DWORD>(sizeof(value)));
    if (length == 0) {
        if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
            kind = kCompiledDefaultBackend;
            return true;
        }

        Logger::GetInstance().LogError(
            "STORMBREAKER_MEMORY_BACKEND is empty; expected "
            "tlsf, mimalloc, hybrid, or tlsf-sharded");
        return false;
    }
    if (length >= sizeof(value)) {
        Logger::GetInstance().LogError(
            "STORMBREAKER_MEMORY_BACKEND value is too long");
        return false;
    }

    if (std::strcmp(value, "tlsf") == 0) {
        kind = BackendKind::Tlsf;
        return true;
    }
    if (std::strcmp(value, "mimalloc") == 0) {
        kind = BackendKind::Mimalloc;
        return true;
    }
    if (std::strcmp(value, "hybrid") == 0) {
        kind = BackendKind::Hybrid;
        return true;
    }
    if (std::strcmp(value, "tlsf-sharded") == 0) {
        kind = BackendKind::TlsfSharded;
        return true;
    }

    Logger::GetInstance().LogError(
        "Invalid STORMBREAKER_MEMORY_BACKEND='%s'; expected "
        "tlsf, mimalloc, hybrid, or tlsf-sharded",
        value);
    return false;
#endif
}

bool HybridNeedsMimallocForCurrentTakeover() {
    char mode[32]{};
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_TAKEOVER_MODE", mode,
        static_cast<DWORD>(sizeof(mode)));
    // Missing mode means the production-compatible large threshold. In that
    // mode every managed request routes to TLSF, so reserving a mimalloc arena
    // only consumes VA and adds ownership probes.
    if (length == 0) {
        return false;
    }
    if (length >= sizeof(mode)) {
        return true;
    }
    return _stricmp(mode, "large") != 0;
}

bool IsValidConfig(const MemoryPool::Config& config) {
    if (config.initialSize == 0 || config.maxSize == 0 ||
        config.extendGranularity == 0 ||
        config.initialSize > config.maxSize) {
        return false;
    }
    return config.alignment >= sizeof(void*) &&
        (config.alignment & (config.alignment - 1)) == 0;
}

BackendSet* PublishedBackendSet() {
    return g_backendSet.load(std::memory_order_acquire);
}

MemoryBackend* BackendForRoute(
    BackendSet* backends, BackendRoute route) {
    if (!backends) {
        return nullptr;
    }
    switch (route) {
    case BackendRoute::Tlsf:
        return backends->tlsf;
    case BackendRoute::Mimalloc:
        return backends->mimalloc;
    default:
        return nullptr;
    }
}

BackendRoute ResolveRoute(
    const BackendSet* backends, size_t requestedSize,
    BackendRoute requestedRoute) {
    if (!backends) {
        return BackendRoute::Automatic;
    }
    if (requestedRoute != BackendRoute::Automatic) {
        return requestedRoute;
    }
    switch (backends->kind) {
    case BackendKind::Tlsf:
    case BackendKind::TlsfSharded:
        return BackendRoute::Tlsf;
    case BackendKind::Mimalloc:
        return BackendRoute::Mimalloc;
    case BackendKind::Hybrid:
        return requestedSize > MemoryPool::kHybridTlsfThreshold
            ? BackendRoute::Tlsf
            : BackendRoute::Mimalloc;
    default:
        return BackendRoute::Automatic;
    }
}

bool LocateOwningBackend(
    BackendSet* backends, const void* ptr, BackendRoute requestedRoute,
    MemoryBackend** backend, BackendRoute* actualRoute) {
    if (backend) {
        *backend = nullptr;
    }
    if (actualRoute) {
        *actualRoute = BackendRoute::Automatic;
    }
    if (!backends || !ptr) {
        return false;
    }

    const auto tryRoute = [&](BackendRoute route) {
        MemoryBackend* candidate = BackendForRoute(backends, route);
        if (!candidate ||
            !candidate->IsFromBackend(const_cast<void*>(ptr))) {
            return false;
        }
        if (backend) {
            *backend = candidate;
        }
        if (actualRoute) {
            *actualRoute = route;
        }
        return true;
    };

    if (requestedRoute != BackendRoute::Automatic) {
        return tryRoute(requestedRoute);
    }
    return tryRoute(BackendRoute::Tlsf) ||
        tryRoute(BackendRoute::Mimalloc);
}

void DestroyBackendSet(BackendSet* backends) {
    if (!backends) {
        return;
    }
    if (backends->mimalloc) {
        backends->mimalloc->Shutdown();
        delete backends->mimalloc;
    }
    if (backends->tlsf) {
        backends->tlsf->Shutdown();
        delete backends->tlsf;
    }
    delete backends;
}

std::unique_lock<std::mutex> AcquireAllocationLock() {
    std::unique_lock<std::mutex> lock(g_allocationMutex, std::defer_lock);
    if (lock.try_lock()) {
        return lock;
    }
    if (!g_latencyTrackingEnabled.load(std::memory_order_relaxed)) {
        lock.lock();
        return lock;
    }

    const Clock::time_point start = Clock::now();
    lock.lock();
    const uint64_t waitNanoseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - start).count());
    g_metadataLockWaitCount.fetch_add(1, std::memory_order_relaxed);
    g_metadataLockWaitNanoseconds.fetch_add(
        waitNanoseconds, std::memory_order_relaxed);
    UpdateMaximum(g_metadataMaxLockWaitNanoseconds, waitNanoseconds);
    return lock;
}

bool InsertAllocation(
    void* ptr, size_t requested, size_t usable, BackendRoute route) {
    std::unique_lock<std::mutex> lock = AcquireAllocationLock();
    try {
        return g_allocations.emplace(
            ptr, AllocationRecord{requested, usable, route}).second;
    }
    catch (const std::bad_alloc&) {
        return false;
    }
}

bool FindAllocation(void* ptr, AllocationRecord& record) {
    std::unique_lock<std::mutex> lock = AcquireAllocationLock();
    const auto it = g_allocations.find(ptr);
    if (it == g_allocations.end()) {
        return false;
    }
    record = it->second;
    return true;
}

bool RemoveAllocation(void* ptr, AllocationRecord& record) {
    std::unique_lock<std::mutex> lock = AcquireAllocationLock();
    const auto it = g_allocations.find(ptr);
    if (it == g_allocations.end()) {
        return false;
    }
    record = it->second;
    g_allocations.erase(it);
    return true;
}

bool UpdateAllocation(
    void* oldPtr, void* newPtr, size_t requested, size_t usable,
    BackendRoute route) {
    std::unique_lock<std::mutex> lock = AcquireAllocationLock();
    auto node = g_allocations.extract(oldPtr);
    if (node.empty()) {
        return false;
    }
    node.key() = newPtr;
    node.mapped() = {requested, usable, route};
    g_allocations.insert(std::move(node));
    return true;
}

bool TryReserveBudget(size_t bytes) {
    if (bytes == 0) {
        return true;
    }
    size_t current = g_budgetInUseBytes.load(std::memory_order_relaxed);
    for (;;) {
        if (bytes > kRequestedLiveBudgetBytes - current) {
            return false;
        }
        if (g_budgetInUseBytes.compare_exchange_weak(
                current, current + bytes, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
    }
}

void ReleaseBudget(size_t bytes) {
    if (bytes == 0) {
        return;
    }
    SaturatingSubtract(g_budgetInUseBytes, bytes);
}

void CaptureLivePeaks() {
    if (!g_config.enableStats) {
        return;
    }
    UpdateMaximum(
        g_peakRequestedLiveBytes,
        g_budgetInUseBytes.load(std::memory_order_relaxed));
    UpdateMaximum(
        g_peakUsableLiveBytes,
        g_usableLiveBytes.load(std::memory_order_relaxed));
}

void AddLiveBytes(size_t requested, size_t usable) {
    (void)requested;
    g_usableLiveBytes.fetch_add(usable, std::memory_order_relaxed);
}

void RemoveLiveBytes(size_t requested, size_t usable) {
    (void)requested;
    SaturatingSubtract(g_usableLiveBytes, usable);
}

void AdjustLiveBytes(
    size_t oldRequested, size_t oldUsable,
    size_t newRequested, size_t newUsable) {
    (void)oldRequested;
    (void)newRequested;

    if (newUsable >= oldUsable) {
        g_usableLiveBytes.fetch_add(
            newUsable - oldUsable, std::memory_order_relaxed);
    }
    else {
        SaturatingSubtract(g_usableLiveBytes, oldUsable - newUsable);
    }
}

void RecordOperationLatency(
    OperationKind operation, const Clock::time_point& start) {
    if (start == Clock::time_point{}) {
        return;
    }
    const uint64_t nanoseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - start).count());
    g_operationLatency.Record(nanoseconds);
    switch (operation) {
    case OperationKind::Allocate:
        g_allocateLatency.Record(nanoseconds);
        break;
    case OperationKind::Free:
        g_freeLatency.Record(nanoseconds);
        break;
    case OperationKind::Reallocate:
        g_reallocateLatency.Record(nanoseconds);
        break;
    }
}

Clock::time_point BeginOperationTiming() {
    return g_latencyTrackingEnabled.load(std::memory_order_relaxed)
        ? Clock::now()
        : Clock::time_point{};
}

void ResetCoreStats() {
    FlushDetailedCountersForCurrentThread();
    const size_t requested =
        g_budgetInUseBytes.load(std::memory_order_relaxed);
    const size_t usable = g_usableLiveBytes.load(std::memory_order_relaxed);
    g_peakRequestedLiveBytes.store(requested, std::memory_order_relaxed);
    g_peakUsableLiveBytes.store(usable, std::memory_order_relaxed);
    g_allocCount.store(0, std::memory_order_relaxed);
    g_freeCount.store(0, std::memory_order_relaxed);
    g_reallocCount.store(0, std::memory_order_relaxed);
    g_failureCount.store(0, std::memory_order_relaxed);
    g_metadataLockWaitCount.store(0, std::memory_order_relaxed);
    g_metadataLockWaitNanoseconds.store(0, std::memory_order_relaxed);
    g_metadataMaxLockWaitNanoseconds.store(0, std::memory_order_relaxed);
    g_operationLatency.Reset();
    g_allocateLatency.Reset();
    g_freeLatency.Reset();
    g_reallocateLatency.Reset();
    g_copyLatency.Reset();
    g_growthLatency.Reset();
}

size_t ToLegacySize(uint64_t value) {
    const uint64_t maximum = (std::numeric_limits<size_t>::max)();
    return static_cast<size_t>(value > maximum ? maximum : value);
}

BackendStats EmptyBackendStats() {
    return {};
}

void AddHistogram(
    LatencyHistogramStats& total,
    const LatencyHistogramStats& value) {
    for (size_t i = 0; i < MemoryPool::kLatencyHistogramBucketCount; ++i) {
        total.upperBoundsNanoseconds[i] = kLatencyUpperBounds[i];
    }
    for (size_t i = 0;
        i < MemoryPool::kLatencyHistogramBucketCount + 1; ++i) {
        total.bucketCounts[i] += value.bucketCounts[i];
    }
    total.sampleCount += value.sampleCount;
    total.totalNanoseconds += value.totalNanoseconds;
    total.maxNanoseconds = (std::max)(
        total.maxNanoseconds, value.maxNanoseconds);
}

void AddBackendStats(BackendStats& total, const BackendStats& value) {
    total.reservedBytes += value.reservedBytes;
    total.committedBytes += value.committedBytes;
    // The route peaks are independently sampled, so their sum is a safe
    // conservative aggregate peak for the hybrid backend.
    total.peakReservedBytes += value.peakReservedBytes;
    total.peakCommittedBytes += value.peakCommittedBytes;
    total.growthCount += value.growthCount;
    total.trimCount += value.trimCount;
    total.lockWaitCount += value.lockWaitCount;
    total.lockWaitNanoseconds += value.lockWaitNanoseconds;
    total.maxLockWaitNanoseconds = (std::max)(
        total.maxLockWaitNanoseconds, value.maxLockWaitNanoseconds);
    AddHistogram(total.lockWaitLatency, value.lockWaitLatency);
}

BackendStats SnapshotBackendStats(BackendSet* backends) {
    BackendStats result{};
    if (!backends) {
        return result;
    }
    if (backends->tlsf) {
        AddBackendStats(result, backends->tlsf->GetStats());
    }
    if (backends->mimalloc) {
        AddBackendStats(result, backends->mimalloc->GetStats());
    }
    return result;
}

MemoryPool::RoutedAllocation AllocateRoutedImpl(
    size_t physicalSize, size_t requestedCharge, size_t alignment,
    BackendRoute requestedRoute, bool trackAllocation) {
    const Clock::time_point start = BeginOperationTiming();
    MemoryPool::RoutedAllocation result{
        nullptr, 0, BackendRoute::Automatic};
    BackendOperationPin operation;
    if (!operation) {
        return result;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends || physicalSize == 0) {
        RecordOperationLatency(OperationKind::Allocate, start);
        return result;
    }
    if (alignment != 0 &&
        (alignment < sizeof(void*) ||
            (alignment & (alignment - 1)) != 0)) {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Allocate, start);
        return result;
    }

    const BackendRoute route =
        ResolveRoute(backends, requestedCharge, requestedRoute);
    MemoryBackend* backend = BackendForRoute(backends, route);
    if (!backend || !TryReserveBudget(requestedCharge)) {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Allocate, start);
        return result;
    }

    size_t usableSize = 0;
    void* ptr = alignment == 0
        ? backend->Allocate(physicalSize, &usableSize)
        : backend->AllocateAligned(physicalSize, alignment, &usableSize);
    if (!ptr) {
        ReleaseBudget(requestedCharge);
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Allocate, start);
        return result;
    }
    if (usableSize < physicalSize) {
        usableSize = physicalSize;
    }
    if (trackAllocation &&
        !InsertAllocation(ptr, requestedCharge, usableSize, route)) {
        backend->Free(ptr);
        ReleaseBudget(requestedCharge);
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Allocate, start);
        return result;
    }

    AddLiveBytes(requestedCharge, usableSize);
    AddDetailedOperationCounter(DetailedOperationCounter::Allocate);
    if (g_config.enableDebug) {
        Logger::GetInstance().LogDebug(
            "%s allocate: ptr=%p, physical=%zu, charge=%zu, usable=%zu, "
            "align=%zu",
            backend->GetName(), ptr, physicalSize, requestedCharge,
            usableSize, alignment);
    }
    result = {ptr, usableSize, route};
    RecordOperationLatency(OperationKind::Allocate, start);
    return result;
}

struct RoutedVisitContext {
    MemoryPool::AllocationVisitor visitor;
    void* context;
    BackendRoute route;
};

bool ForwardRoutedVisit(
    void* ptr, size_t usableSize, void* user) {
    RoutedVisitContext* visit = static_cast<RoutedVisitContext*>(user);
    return visit->visitor(
        ptr, usableSize, visit->route, visit->context);
}

} // namespace

namespace MemoryPool {

bool Initialize() {
    std::lock_guard<std::mutex> lifecycleLock(g_lifecycleMutex);
    if (PublishedBackendSet()) {
        return true;
    }
    if (!IsValidConfig(g_config)) {
        Logger::GetInstance().LogError("MemoryPool configuration is invalid");
        return false;
    }

    BackendKind selected = BackendKind::Tlsf;
    if (!ParseBackendEnvironment(selected)) {
        return false;
    }
    std::unique_ptr<BackendSet> backends(new (std::nothrow) BackendSet{});
    if (!backends) {
        Logger::GetInstance().LogError(
            "Failed to allocate the immutable backend route set");
        return false;
    }
    backends->kind = selected;

    std::unique_ptr<MemoryBackend> tlsf;
    std::unique_ptr<MemoryBackend> mimalloc;
    try {
        if (selected == BackendKind::Tlsf ||
            selected == BackendKind::TlsfSharded ||
            selected == BackendKind::Hybrid) {
            tlsf = selected == BackendKind::TlsfSharded
                ? Internal::CreateTlsfShardedBackend()
                : Internal::CreateTlsfBackend();
        }
        if (selected == BackendKind::Mimalloc ||
            (selected == BackendKind::Hybrid &&
             HybridNeedsMimallocForCurrentTakeover())) {
            mimalloc = Internal::CreateMimallocBackend();
        }
    }
    catch (const std::bad_alloc&) {
        Logger::GetInstance().LogError(
            "Failed to allocate memory backend state");
        return false;
    }

    const bool threadSafe =
        g_threadSafeEnabled.load(std::memory_order_acquire);
    if (tlsf) {
        tlsf->SetThreadSafety(threadSafe);
        if (!tlsf->Initialize(g_config)) {
            Logger::GetInstance().LogError(
                "TLSF backend initialization failed");
            return false;
        }
    }
    if (mimalloc) {
        mimalloc->SetThreadSafety(threadSafe);
        if (!mimalloc->Initialize(g_config)) {
            Logger::GetInstance().LogError(
                "mimalloc backend initialization failed");
            if (tlsf) {
                tlsf->Shutdown();
            }
            return false;
        }
    }
    else if (selected == BackendKind::Hybrid) {
        Logger::GetInstance().LogInfo(
            "Hybrid large mode: mimalloc route deferred because all managed "
            "requests route to TLSF");
    }

    {
        std::unique_lock<std::mutex> allocationLock = AcquireAllocationLock();
        g_allocations.clear();
    }
    g_budgetInUseBytes.store(0, std::memory_order_relaxed);
    g_usableLiveBytes.store(0, std::memory_order_relaxed);
    ResetCoreStats();

    g_backendClosing.store(false, std::memory_order_release);
    backends->tlsf = tlsf.release();
    backends->mimalloc = mimalloc.release();
    g_selectedBackend.store(selected, std::memory_order_release);
    g_backendSet.store(backends.release(), std::memory_order_release);
    Logger::GetInstance().LogInfo(
        "MemoryPool initialized with backend=%s, requested-live budget=1024 MB",
        BackendName(selected));
    return true;
}

void Shutdown() {
    std::lock_guard<std::mutex> lifecycleLock(g_lifecycleMutex);
    bool expectedClosing = false;
    if (!g_backendClosing.compare_exchange_strong(
            expectedClosing, true, std::memory_order_acq_rel)) {
        return;
    }
    const ULONGLONG drainDeadline = GetTickCount64() + 20000u;
    for (uint32_t wait = 0;
         g_activeBackendOperations.load(std::memory_order_acquire) != 0;
         ++wait) {
        if (GetTickCount64() >= drainDeadline) {
            Logger::GetInstance().LogError(
                "MemoryPool shutdown timed out waiting for active operations");
            g_backendClosing.store(false, std::memory_order_release);
            return;
        }
        if ((wait & 63u) == 63u) {
            Sleep(wait >= 256u ? 1u : 0u);
        }
        else {
            YieldProcessor();
        }
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        g_backendClosing.store(false, std::memory_order_release);
        return;
    }
    FlushDetailedCountersForCurrentThread();
    const uint64_t requestedLiveBytes =
        g_budgetInUseBytes.load(std::memory_order_acquire);
    const uint64_t usableLiveBytes =
        g_usableLiveBytes.load(std::memory_order_acquire);
    if (requestedLiveBytes != 0 || usableLiveBytes != 0) {
        Logger::GetInstance().LogWarning(
            "MemoryPool shutdown refused with requested=%llu, usable=%llu "
            "bytes still live",
            static_cast<unsigned long long>(requestedLiveBytes),
            static_cast<unsigned long long>(usableLiveBytes));
        g_backendClosing.store(false, std::memory_order_release);
        return;
    }
    // Clean Shutdown is a test/init-rollback facility. Its caller must have
    // detached hooks and quiesced worker threads before the route set is
    // unpublished. Release process detach never calls this path.
    g_backendSet.store(nullptr, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(g_stabilizingMutex);
        g_stabilizingBlocks.clear();
    }
    DestroyBackendSet(backends);
    {
        std::unique_lock<std::mutex> allocationLock = AcquireAllocationLock();
        g_allocations.clear();
    }
    g_budgetInUseBytes.store(0, std::memory_order_relaxed);
    g_usableLiveBytes.store(0, std::memory_order_relaxed);
    g_backendClosing.store(false, std::memory_order_release);
    Logger::GetInstance().LogInfo("MemoryPool shutdown complete");
}

bool IsInitialized() {
    return PublishedBackendSet() != nullptr;
}

void* Allocate(size_t size) {
    return AllocateRoutedImpl(
        size, size, 0, BackendRoute::Automatic, true).pointer;
}

void* AllocateAligned(size_t size, size_t alignment) {
    if (alignment == 0) {
        alignment = g_config.alignment;
    }
    return AllocateRoutedImpl(
        size, size, alignment, BackendRoute::Automatic, true).pointer;
}

void* AllocateAlignedKnownSize(size_t size, size_t alignment) {
    if (alignment == 0) {
        alignment = g_config.alignment;
    }
    return AllocateRoutedImpl(
        size, size, alignment, BackendRoute::Automatic, false).pointer;
}

BackendRoute SelectRoute(size_t stormRequestedSize) {
    BackendOperationPin operation;
    if (!operation) {
        return BackendRoute::Automatic;
    }
    BackendSet* backends = PublishedBackendSet();
    return ResolveRoute(
        backends, stormRequestedSize, BackendRoute::Automatic);
}

RoutedAllocation AllocateRouted(
    size_t size, size_t alignment, BackendRoute route) {
    return AllocateRoutedImpl(size, size, alignment, route, false);
}

RoutedAllocation AllocateRouted(
    size_t physicalSize, size_t requestedCharge, size_t alignment,
    BackendRoute route) {
    return AllocateRoutedImpl(
        physicalSize, requestedCharge, alignment, route, false);
}

void* Reallocate(void* ptr, size_t newSize) {
    if (!ptr) {
        return Allocate(newSize);
    }
    if (newSize == 0) {
        Free(ptr);
        return nullptr;
    }

    const Clock::time_point start = BeginOperationTiming();
    BackendOperationPin operation;
    if (!operation) {
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }

    AllocationRecord oldRecord{};
    const bool tracked = FindAllocation(ptr, oldRecord);
    MemoryBackend* oldBackend = nullptr;
    if (tracked) {
        oldBackend = BackendForRoute(backends, oldRecord.route);
    }
    else {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }
    if (!oldBackend || oldRecord.usableBytes == 0) {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }

    const size_t requested = newSize;
    const size_t growth = requested > oldRecord.requestedBytes
        ? requested - oldRecord.requestedBytes
        : 0;
    if (growth != 0 && !TryReserveBudget(growth)) {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }

    const BackendRoute targetRoute =
        ResolveRoute(backends, requested, BackendRoute::Automatic);
    MemoryBackend* targetBackend =
        BackendForRoute(backends, targetRoute);
    if (!targetBackend) {
        if (growth != 0) {
            ReleaseBudget(growth);
        }
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }

    size_t usableSize = 0;
    void* newPtr = nullptr;
    if (targetBackend == oldBackend) {
        newPtr = oldBackend->Reallocate(ptr, newSize, &usableSize);
    }
    else {
        newPtr = targetBackend->Allocate(newSize, &usableSize);
        if (newPtr) {
            const Clock::time_point copyStart =
                g_latencyTrackingEnabled.load(std::memory_order_relaxed)
                    ? Clock::now()
                    : Clock::time_point{};
            std::memcpy(
                newPtr, ptr,
                (std::min)(oldRecord.requestedBytes, requested));
            if (copyStart != Clock::time_point{}) {
                RecordCopyLatency(static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now() - copyStart).count()));
            }
            if (oldBackend->Free(ptr) == 0) {
                targetBackend->Free(newPtr);
                newPtr = nullptr;
                usableSize = 0;
            }
        }
    }
    if (!newPtr) {
        if (growth != 0) {
            ReleaseBudget(growth);
        }
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return nullptr;
    }

    if (usableSize < newSize) {
        usableSize = newSize;
    }
    if (!UpdateAllocation(
            ptr, newPtr, requested, usableSize, targetRoute)) {
        if (!InsertAllocation(
                newPtr, requested, usableSize, targetRoute)) {
            Logger::GetInstance().LogError(
                "Failed to track reallocated block: ptr=%p", newPtr);
        }
    }

    CaptureLivePeaks();
    if (requested < oldRecord.requestedBytes) {
        ReleaseBudget(oldRecord.requestedBytes - requested);
    }
    AdjustLiveBytes(
        oldRecord.requestedBytes, oldRecord.usableBytes,
        requested, usableSize);
    AddDetailedOperationCounter(DetailedOperationCounter::Reallocate);
    RecordOperationLatency(OperationKind::Reallocate, start);
    return newPtr;
}

InPlaceReallocateStatus ReallocateInPlaceRouted(
    void* ptr, size_t oldRequestedSize, size_t newRequestedSize,
    BackendRoute route, size_t* newUsableSize) {
    return ReallocateInPlaceRouted(
        ptr, oldRequestedSize, newRequestedSize, newRequestedSize,
        route, newUsableSize);
}

InPlaceReallocateStatus ReallocateInPlaceRouted(
    void* ptr, size_t oldRequestedCharge, size_t newPhysicalSize,
    size_t newRequestedCharge, BackendRoute route,
    size_t* newUsableSize) {
    if (newUsableSize) {
        *newUsableSize = 0;
    }
    const Clock::time_point start = BeginOperationTiming();
    BackendOperationPin operation;
    if (!operation) {
        RecordOperationLatency(OperationKind::Reallocate, start);
        return InPlaceReallocateStatus::NotOwned;
    }
    if (!ptr || newPhysicalSize == 0) {
        RecordOperationLatency(OperationKind::Reallocate, start);
        return InPlaceReallocateStatus::InvalidArgument;
    }

    BackendSet* backends = PublishedBackendSet();
    MemoryBackend* backend = route == BackendRoute::Automatic
        ? nullptr
        : BackendForRoute(backends, route);
    if (!backend && !LocateOwningBackend(
            backends, ptr, route, &backend, nullptr)) {
        RecordOperationLatency(OperationKind::Reallocate, start);
        return InPlaceReallocateStatus::NotOwned;
    }
    const size_t growth = newRequestedCharge > oldRequestedCharge
        ? newRequestedCharge - oldRequestedCharge
        : 0;
    if (growth != 0 && !TryReserveBudget(growth)) {
        IncrementDetailedCounter(g_failureCount);
        RecordOperationLatency(OperationKind::Reallocate, start);
        return InPlaceReallocateStatus::BudgetExceeded;
    }

    size_t oldUsableSize = 0;
    size_t usableSize = 0;
    void* result = backend->ReallocateInPlace(
        ptr, newPhysicalSize, &oldUsableSize, &usableSize);
    if (result != ptr) {
      if (growth != 0) {
        ReleaseBudget(growth);
      }
        if (oldUsableSize == 0) {
            RecordOperationLatency(OperationKind::Reallocate, start);
            return InPlaceReallocateStatus::NotOwned;
        }
        // A backend being unable to grow this block in place is expected;
        // the Storm compatibility layer may immediately perform a moving
        // realloc. Do not report that normal branch as an allocator failure.
        RecordOperationLatency(OperationKind::Reallocate, start);
        return InPlaceReallocateStatus::Failed;
    }
    if (usableSize < newPhysicalSize) {
        usableSize = newPhysicalSize;
    }
    CaptureLivePeaks();
    if (newRequestedCharge < oldRequestedCharge) {
        ReleaseBudget(oldRequestedCharge - newRequestedCharge);
    }
    AdjustLiveBytes(
        oldRequestedCharge, oldUsableSize,
        newRequestedCharge, usableSize);
    AddDetailedOperationCounter(DetailedOperationCounter::Reallocate);
    if (newUsableSize) {
        *newUsableSize = usableSize;
    }
    RecordOperationLatency(OperationKind::Reallocate, start);
    return InPlaceReallocateStatus::Succeeded;
}

static void FreeKnownSizeImpl(
    void* ptr, size_t knownSize, bool lookupTrackedAllocation) {
    if (!ptr) {
        return;
    }

    const Clock::time_point start = BeginOperationTiming();
    BackendOperationPin operation;
    if (!operation) {
        RecordOperationLatency(OperationKind::Free, start);
        return;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        RecordOperationLatency(OperationKind::Free, start);
        return;
    }

    AllocationRecord record{};
    const bool tracked =
        lookupTrackedAllocation && RemoveAllocation(ptr, record);
    MemoryBackend* backend = nullptr;
    if (tracked) {
        backend = BackendForRoute(backends, record.route);
    }
    else if (!LocateOwningBackend(
            backends, ptr, BackendRoute::Automatic,
            &backend, &record.route)) {
        RecordOperationLatency(OperationKind::Free, start);
        return;
    }
    if (!backend) {
        if (tracked) {
            InsertAllocation(
                ptr, record.requestedBytes, record.usableBytes, record.route);
        }
        RecordOperationLatency(OperationKind::Free, start);
        return;
    }

    const size_t freedUsableSize = backend->Free(ptr);
    if (freedUsableSize == 0) {
        if (tracked) {
            InsertAllocation(
                ptr, record.requestedBytes, record.usableBytes, record.route);
        }
        RecordOperationLatency(OperationKind::Free, start);
        return;
    }
    if (!tracked) {
        record.requestedBytes = knownSize != 0 ? knownSize : freedUsableSize;
        record.usableBytes = freedUsableSize;
    }

    CaptureLivePeaks();
    ReleaseBudget(record.requestedBytes);
    RemoveLiveBytes(record.requestedBytes, record.usableBytes);
    AddDetailedOperationCounter(DetailedOperationCounter::Free);
    if (g_config.enableDebug) {
        Logger::GetInstance().LogDebug(
            "%s free: ptr=%p, requested=%llu",
            backend->GetName(), ptr,
            static_cast<unsigned long long>(record.requestedBytes));
    }
    RecordOperationLatency(OperationKind::Free, start);
}

void FreeKnownSize(void* ptr, size_t knownSize) {
    FreeKnownSizeImpl(ptr, knownSize, true);
}

void FreeKnownSizeUntracked(void* ptr, size_t knownSize) {
    FreeKnownSizeImpl(ptr, knownSize, false);
}

void Free(void* ptr) {
    FreeKnownSize(ptr, 0);
}

bool FreeRouted(
    void* ptr, size_t knownSize, BackendRoute route,
    size_t* freedUsableSize) {
    return FreeRoutedConditional(
        ptr, knownSize, route, nullptr, nullptr, freedUsableSize);
}

bool FreeRoutedConditional(
    void* ptr, size_t knownSize, BackendRoute route,
    FreeValidator validator, void* context,
    size_t* freedUsableSize) {
    if (freedUsableSize) {
        *freedUsableSize = 0;
    }
    if (!ptr) {
        return false;
    }

    const Clock::time_point start = BeginOperationTiming();
    BackendOperationPin operation;
    if (!operation) {
        RecordOperationLatency(OperationKind::Free, start);
        return false;
    }
    BackendSet* backends = PublishedBackendSet();
    MemoryBackend* backend = nullptr;
    BackendRoute actualRoute = route;
    if (route == BackendRoute::Automatic) {
        if (!LocateOwningBackend(
                backends, ptr, route, &backend, &actualRoute)) {
            RecordOperationLatency(OperationKind::Free, start);
            return false;
        }
    }
    else {
        backend = BackendForRoute(backends, route);
    }
    if (!backend) {
        RecordOperationLatency(OperationKind::Free, start);
        return false;
    }

    const size_t usableSize = validator
        ? backend->FreeConditional(ptr, validator, context)
        : backend->Free(ptr);
    if (usableSize == 0) {
        RecordOperationLatency(OperationKind::Free, start);
        return false;
    }
    CaptureLivePeaks();
    ReleaseBudget(knownSize);
    RemoveLiveBytes(knownSize, usableSize);
    AddDetailedOperationCounter(DetailedOperationCounter::Free);
    if (freedUsableSize) {
        *freedUsableSize = usableSize;
    }
    RecordOperationLatency(OperationKind::Free, start);
    return true;
}

BatchFreeResult FreeRoutedBatch(
    const BatchFreeEntry* entries, size_t count, BackendRoute route) {
    BatchFreeResult result{};
    if ((!entries && count != 0) || count == 0 ||
        route == BackendRoute::Automatic) {
        return result;
    }

    const Clock::time_point start = BeginOperationTiming();
    BackendOperationPin operation;
    if (!operation) {
        RecordOperationLatency(OperationKind::Free, start);
        return result;
    }
    BackendSet* backends = PublishedBackendSet();
    MemoryBackend* backend = BackendForRoute(backends, route);
    if (!backend) {
        RecordOperationLatency(OperationKind::Free, start);
        return result;
    }

    result = backend->FreeBatch(entries, count);
    if (result.freedCount > count ||
        result.usableBytes > (std::numeric_limits<size_t>::max)()) {
        IncrementDetailedCounter(g_failureCount);
        result = {};
        RecordOperationLatency(OperationKind::Free, start);
        return result;
    }
    if (result.freedCount != 0) {
        CaptureLivePeaks();
        for (size_t index = 0; index < result.freedCount; ++index) {
            ReleaseBudget(entries[index].requestedCharge);
        }
        RemoveLiveBytes(0, static_cast<size_t>(result.usableBytes));
        AddDetailedOperationCounter(
            DetailedOperationCounter::Free,
            static_cast<uint32_t>(result.freedCount));
    }
    RecordOperationLatency(OperationKind::Free, start);
    return result;
}

void* AllocateSafe(size_t size) {
    __try {
        return Allocate(size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "MemoryPool AllocateSafe exception: size=%zu, code=0x%08X",
            size, GetExceptionCode());
        return nullptr;
    }
}

void* AllocateAlignedSafe(size_t size, size_t alignment) {
    __try {
        return AllocateAligned(size, alignment);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "MemoryPool AllocateAlignedSafe exception: "
            "size=%zu, align=%zu, code=0x%08X",
            size, alignment, GetExceptionCode());
        return nullptr;
    }
}

void* ReallocateSafe(void* ptr, size_t newSize) {
    __try {
        return Reallocate(ptr, newSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "MemoryPool ReallocateSafe exception: "
            "ptr=%p, size=%zu, code=0x%08X",
            ptr, newSize, GetExceptionCode());
        return nullptr;
    }
}

void FreeSafe(void* ptr) {
    __try {
        Free(ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "MemoryPool FreeSafe exception: ptr=%p, code=0x%08X",
            ptr, GetExceptionCode());
    }
}

bool IsFromPool(void* ptr) {
    return OwnsAddress(ptr, nullptr);
}

size_t GetBlockSize(void* ptr) {
    AllocationOwnership ownership{};
    return QueryAllocation(ptr, &ownership) ? ownership.usableSize : 0;
}

bool OwnsAddress(const void* ptr, BackendRoute* route) {
    BackendOperationPin operation;
    if (!operation) {
        if (route) {
            *route = BackendRoute::Automatic;
        }
        return false;
    }
    MemoryBackend* backend = nullptr;
    BackendRoute actualRoute = BackendRoute::Automatic;
    const bool owned = LocateOwningBackend(
        PublishedBackendSet(), ptr, BackendRoute::Automatic,
        &backend, &actualRoute);
    if (route) {
        *route = owned ? actualRoute : BackendRoute::Automatic;
    }
    return owned;
}

bool QueryAllocation(
    void* ptr, AllocationOwnership* ownership) {
    return QueryAllocation(ptr, BackendRoute::Automatic, ownership);
}

bool QueryAllocation(
    void* ptr, BackendRoute requestedRoute,
    AllocationOwnership* ownership) {
    if (ownership) {
        *ownership = {BackendRoute::Automatic, 0};
    }
    BackendOperationPin operation;
    if (!operation) {
        return false;
    }
    BackendSet* backends = PublishedBackendSet();
    MemoryBackend* backend = nullptr;
    BackendRoute route = requestedRoute;
    size_t usableSize = 0;
    if (requestedRoute != BackendRoute::Automatic) {
        backend = BackendForRoute(backends, requestedRoute);
        if (!backend || !backend->QueryAllocation(ptr, &usableSize)) {
            return false;
        }
    }
    else {
        const BackendRoute candidates[] = {
            BackendRoute::Tlsf, BackendRoute::Mimalloc};
        for (BackendRoute candidateRoute : candidates) {
            MemoryBackend* candidate =
                BackendForRoute(backends, candidateRoute);
            if (candidate && candidate->QueryAllocation(ptr, &usableSize)) {
                backend = candidate;
                route = candidateRoute;
                break;
            }
        }
        if (!backend) {
            return false;
        }
    }
    if (ownership) {
        *ownership = {route, usableSize};
    }
    return usableSize != 0;
}

bool VisitAllocations(
    BackendRoute route, AllocationVisitor visitor, void* context) {
    if (!visitor) {
        return false;
    }
    BackendOperationPin operation;
    if (!operation) {
        return false;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        return false;
    }

    const auto visitRoute = [&](BackendRoute currentRoute) {
        MemoryBackend* backend = BackendForRoute(backends, currentRoute);
        if (!backend) {
            return route == BackendRoute::Automatic;
        }
        RoutedVisitContext visit{visitor, context, currentRoute};
        return backend->VisitAllocatedBlocks(ForwardRoutedVisit, &visit);
    };

    if (route != BackendRoute::Automatic) {
        return visitRoute(route);
    }
    return visitRoute(BackendRoute::Tlsf) &&
        visitRoute(BackendRoute::Mimalloc);
}

size_t GetUsedSize() {
    return ToLegacySize(
        g_budgetInUseBytes.load(std::memory_order_relaxed));
}

size_t GetTotalSize() {
    return ToLegacySize(GetExtendedStats().reservedBytes);
}

size_t GetFreeSize() {
    const ExtendedPoolStats stats = GetExtendedStats();
    return ToLegacySize(
        stats.reservedBytes > stats.requestedLiveBytes
            ? stats.reservedBytes - stats.requestedLiveBytes
            : 0);
}

bool ExtendPool(size_t additionalSize) {
    BackendOperationPin operation;
    if (!operation) {
        return false;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends || !backends->tlsf || additionalSize == 0) {
        return false;
    }
    return backends->tlsf->Extend(additionalSize);
}

void TrimRoute(BackendRoute route) {
    BackendOperationPin operation;
    if (!operation) {
        return;
    }
    BackendSet* backends = PublishedBackendSet();
    if (backends && backends->tlsf &&
        (route == BackendRoute::Automatic || route == BackendRoute::Tlsf)) {
        backends->tlsf->Trim();
    }
    if (backends && backends->mimalloc &&
        (route == BackendRoute::Automatic ||
         route == BackendRoute::Mimalloc)) {
        backends->mimalloc->Trim();
    }
}

void TrimFreePages() {
    TrimRoute(BackendRoute::Automatic);
}

void CompactPool() {
    BackendOperationPin operation;
    if (!operation) {
        return;
    }
    BackendSet* backends = PublishedBackendSet();
    if (backends && backends->tlsf) {
        backends->tlsf->Compact();
    }
    if (backends && backends->mimalloc) {
        backends->mimalloc->Compact();
    }
}

ExtendedPoolStats GetExtendedStats() {
    FlushDetailedCountersForCurrentThread();
    BackendOperationPin operation;
    BackendSet* backends = PublishedBackendSet();
    ExtendedPoolStats result{};
    result.backendKind =
        g_selectedBackend.load(std::memory_order_acquire);
    result.initialized = operation && backends != nullptr;
    result.requestedLiveBytes =
        g_budgetInUseBytes.load(std::memory_order_relaxed);
    result.requestedLiveBudgetBytes = kRequestedLiveBudgetBytes;
    result.usableLiveBytes =
        g_usableLiveBytes.load(std::memory_order_relaxed);
    result.peakRequestedLiveBytes = (std::max)(
        static_cast<uint64_t>(
            g_peakRequestedLiveBytes.load(std::memory_order_relaxed)),
        result.requestedLiveBytes);
    result.peakUsableLiveBytes = (std::max)(
        static_cast<uint64_t>(
            g_peakUsableLiveBytes.load(std::memory_order_relaxed)),
        result.usableLiveBytes);
    result.allocCount = g_allocCount.load(std::memory_order_relaxed);
    result.freeCount = g_freeCount.load(std::memory_order_relaxed);
    result.reallocCount = g_reallocCount.load(std::memory_order_relaxed);
    result.failureCount = g_failureCount.load(std::memory_order_relaxed);

    const BackendStats backendStats = operation && backends
        ? SnapshotBackendStats(backends)
        : EmptyBackendStats();
    result.reservedBytes = backendStats.reservedBytes;
    result.committedBytes = backendStats.committedBytes;
    result.peakReservedBytes = backendStats.peakReservedBytes;
    result.peakCommittedBytes = backendStats.peakCommittedBytes;
    result.extendCount = backendStats.growthCount;
    result.trimCount = backendStats.trimCount;
    result.lockWaitCount =
        backendStats.lockWaitCount +
        g_metadataLockWaitCount.load(std::memory_order_relaxed);
    result.lockWaitNanoseconds =
        backendStats.lockWaitNanoseconds +
        g_metadataLockWaitNanoseconds.load(std::memory_order_relaxed);
    result.maxLockWaitNanoseconds = (std::max)(
        backendStats.maxLockWaitNanoseconds,
        g_metadataMaxLockWaitNanoseconds.load(std::memory_order_relaxed));
    result.lockWaitLatency = backendStats.lockWaitLatency;
    result.operationLatency = g_operationLatency.Snapshot();
    result.allocateLatency = g_allocateLatency.Snapshot();
    result.freeLatency = g_freeLatency.Snapshot();
    result.reallocateLatency = g_reallocateLatency.Snapshot();
    result.copyLatency = g_copyLatency.Snapshot();
    result.growthLatency = g_growthLatency.Snapshot();
    return result;
}

uint64_t GetRequestedLiveBytes() {
    return g_budgetInUseBytes.load(std::memory_order_relaxed);
}

uint64_t GetUsableLiveBytes() {
    return g_usableLiveBytes.load(std::memory_order_relaxed);
}

BackendKind GetBackendKind() {
    return g_selectedBackend.load(std::memory_order_acquire);
}

const char* GetBackendName() {
    return BackendName(GetBackendKind());
}

const char* GetBuildBackendIdentity() {
    return kBuildBackendIdentity;
}

PoolStats GetStats() {
    const ExtendedPoolStats extended = GetExtendedStats();
    PoolStats result{};
    result.totalSize = ToLegacySize(extended.reservedBytes);
    result.usedSize = ToLegacySize(extended.requestedLiveBytes);
    result.freeSize = ToLegacySize(
        extended.reservedBytes > extended.requestedLiveBytes
            ? extended.reservedBytes - extended.requestedLiveBytes
            : 0);
    result.peakUsed = ToLegacySize(extended.peakRequestedLiveBytes);
    result.allocCount = ToLegacySize(extended.allocCount);
    result.freeCount = ToLegacySize(extended.freeCount);
    result.extendCount = ToLegacySize(extended.extendCount);
    result.trimCount = ToLegacySize(extended.trimCount);
    return result;
}

void PrintStats() {
    const ExtendedPoolStats stats = GetExtendedStats();
    Logger::GetInstance().LogInfo(
        "=== MemoryPool stats (%s) ===", BackendName(stats.backendKind));
    Logger::GetInstance().LogInfo(
        "requested-live=%llu MB, usable-live=%llu MB, peak=%llu MB",
        static_cast<unsigned long long>(
            stats.requestedLiveBytes / (1024 * 1024)),
        static_cast<unsigned long long>(
            stats.usableLiveBytes / (1024 * 1024)),
        static_cast<unsigned long long>(
            stats.peakRequestedLiveBytes / (1024 * 1024)));
    Logger::GetInstance().LogInfo(
        "reserved=%llu MB, committed=%llu MB",
        static_cast<unsigned long long>(
            stats.reservedBytes / (1024 * 1024)),
        static_cast<unsigned long long>(
            stats.committedBytes / (1024 * 1024)));
    Logger::GetInstance().LogInfo(
        "alloc=%llu, free=%llu, realloc=%llu, failures=%llu",
        static_cast<unsigned long long>(stats.allocCount),
        static_cast<unsigned long long>(stats.freeCount),
        static_cast<unsigned long long>(stats.reallocCount),
        static_cast<unsigned long long>(stats.failureCount));
    Logger::GetInstance().LogInfo(
        "growth=%llu, trim=%llu, lock-wait=%llu ns (%llu acquisitions)",
        static_cast<unsigned long long>(stats.extendCount),
        static_cast<unsigned long long>(stats.trimCount),
        static_cast<unsigned long long>(stats.lockWaitNanoseconds),
        static_cast<unsigned long long>(stats.lockWaitCount));
}

void ResetStats() {
    BackendOperationPin operation;
    if (!operation) {
        return;
    }
    ResetCoreStats();
    BackendSet* backends = PublishedBackendSet();
    if (backends && backends->tlsf) {
        backends->tlsf->ResetStats();
    }
    if (backends && backends->mimalloc) {
        backends->mimalloc->ResetStats();
    }
}

void SetLatencyTrackingEnabled(bool enabled) {
    g_latencyTrackingEnabled.store(enabled, std::memory_order_release);
}

bool IsLatencyTrackingEnabled() {
    return g_latencyTrackingEnabled.load(std::memory_order_acquire);
}

void RecordCopyLatency(uint64_t nanoseconds) {
    if (g_latencyTrackingEnabled.load(std::memory_order_relaxed)) {
        g_copyLatency.Record(nanoseconds);
    }
}

void RecordGrowthLatency(uint64_t nanoseconds) {
    if (g_latencyTrackingEnabled.load(std::memory_order_relaxed)) {
        g_growthLatency.Record(nanoseconds);
    }
}

void* CreateStabilizingBlock(size_t size, const char* purpose) {
    void* ptr = AllocateSafe(size);
    if (!ptr) {
        Logger::GetInstance().LogError(
            "Failed to create stabilizing block: size=%zu, purpose=%s",
            size, purpose ? purpose : "unknown");
        return nullptr;
    }

    try {
        std::lock_guard<std::mutex> lock(g_stabilizingMutex);
        g_stabilizingBlocks.push_back(ptr);
    }
    catch (const std::bad_alloc&) {
        FreeSafe(ptr);
        return nullptr;
    }
    return ptr;
}

void FlushStabilizingBlocks() {
    std::vector<void*> blocks;
    {
        std::lock_guard<std::mutex> lock(g_stabilizingMutex);
        blocks.swap(g_stabilizingBlocks);
    }
    for (void* ptr : blocks) {
        FreeSafe(ptr);
    }
}

void EnableThreadSafety() {
    if (PublishedBackendSet()) {
        Logger::GetInstance().LogWarning(
            "MemoryPool thread safety cannot change after initialization");
        return;
    }
    g_threadSafeEnabled.store(true, std::memory_order_release);
}

void DisableThreadSafety() {
    if (PublishedBackendSet()) {
        Logger::GetInstance().LogWarning(
            "MemoryPool thread safety cannot change after initialization");
        return;
    }
    g_threadSafeEnabled.store(false, std::memory_order_release);
}

bool IsThreadSafeEnabled() {
    return g_threadSafeEnabled.load(std::memory_order_acquire);
}

void OnMemoryPressure() {
    TrimFreePages();
    FlushStabilizingBlocks();
}

void OnMemoryAvailable() {
    Logger::GetInstance().LogInfo("Memory pressure relieved");
}

bool SetConfig(const Config& config) {
    std::lock_guard<std::mutex> lifecycleLock(g_lifecycleMutex);
    if (PublishedBackendSet()) {
        Logger::GetInstance().LogWarning(
            "MemoryPool configuration cannot change while initialized");
        return false;
    }
    if (!IsValidConfig(config)) {
        Logger::GetInstance().LogError("Rejected invalid MemoryPool configuration");
        return false;
    }
    g_config = config;
    return true;
}

Config GetConfig() {
    std::lock_guard<std::mutex> lifecycleLock(g_lifecycleMutex);
    return g_config;
}

namespace Internal {

void* GetTLSFHandle() {
    BackendOperationPin operation;
    if (!operation) {
        return nullptr;
    }
    BackendSet* backends = PublishedBackendSet();
    return backends && backends->tlsf
        ? backends->tlsf->GetNativeHandle()
        : nullptr;
}

size_t GetPoolCount() {
    BackendOperationPin operation;
    if (!operation) {
        return 0;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        return 0;
    }
    return (backends->tlsf ? backends->tlsf->GetPoolCount() : 0) +
        (backends->mimalloc ? backends->mimalloc->GetPoolCount() : 0);
}

void DumpPoolInfo() {
    BackendOperationPin operation;
    if (!operation) {
        return;
    }
    BackendSet* backends = PublishedBackendSet();
    if (backends && backends->tlsf) {
        backends->tlsf->DumpPoolInfo();
    }
    if (backends && backends->mimalloc) {
        backends->mimalloc->DumpPoolInfo();
    }
}

bool ValidatePool() {
    BackendOperationPin operation;
    if (!operation) {
        return false;
    }
    BackendSet* backends = PublishedBackendSet();
    if (!backends) {
        return false;
    }
    return (!backends->tlsf || backends->tlsf->Validate()) &&
        (!backends->mimalloc || backends->mimalloc->Validate());
}

#if defined(STORMBREAKER_TESTING)
void SetDetailedCounterBatchingEnabledForTesting(bool enabled) {
    FlushDetailedCountersForCurrentThread();
    g_testingDetailedCounterBatchingEnabled.store(
        enabled, std::memory_order_release);
}
#endif

} // namespace Internal
} // namespace MemoryPool

// ======================== JassVM专用内存池实现 ========================
namespace JVM_MemPool {
    namespace {
        constexpr size_t JVM_BLOCK_SIZE = 0x28A8;
        constexpr size_t JVM_POOL_CAPACITY = 256;
        constexpr uint32_t JVM_MAGIC = 0xDEADBEEF;

        struct JVMBlockHeader {
            uint32_t magic;
            size_t size;
        };

        std::mutex g_jvmMutex;
        std::vector<void*> g_jvmBlocks;
        std::atomic<bool> g_jvmInitialized(false);
    }

    bool Initialize() {
        if (g_jvmInitialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        Logger::GetInstance().LogInfo("初始化JassVM内存池");
        return true;
    }

    void Cleanup() {
        if (!g_jvmInitialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        Logger::GetInstance().LogInfo("清理JassVM内存池，共%zu个块", g_jvmBlocks.size());

        for (void* ptr : g_jvmBlocks) {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }

        g_jvmBlocks.clear();
        Logger::GetInstance().LogInfo("JassVM内存池清理完成");
    }

    void* Allocate(size_t size) {
        if (!g_jvmInitialized.load(std::memory_order_acquire) || size != JVM_BLOCK_SIZE) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        size_t totalSize = size + sizeof(JVMBlockHeader);
        void* rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!rawPtr) {
            Logger::GetInstance().LogError("JassVM分配失败: size=%zu", size);
            return nullptr;
        }

        JVMBlockHeader* header = static_cast<JVMBlockHeader*>(rawPtr);
        header->magic = JVM_MAGIC;
        header->size = size;

        void* userPtr = static_cast<uint8_t*>(rawPtr) + sizeof(JVMBlockHeader);
        g_jvmBlocks.push_back(rawPtr);

        Logger::GetInstance().LogDebug("JassVM分配: ptr=%p, size=%zu", userPtr, size);
        return userPtr;
    }

    void Free(void* ptr) {
        if (!ptr || !g_jvmInitialized.load(std::memory_order_acquire)) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        uint8_t* rawPtr = static_cast<uint8_t*>(ptr) - sizeof(JVMBlockHeader);
        JVMBlockHeader* header = reinterpret_cast<JVMBlockHeader*>(rawPtr);

        if (header->magic != JVM_MAGIC) {
            Logger::GetInstance().LogError("JassVM释放无效块: ptr=%p", ptr);
            return;
        }

        auto it = std::find(g_jvmBlocks.begin(), g_jvmBlocks.end(), rawPtr);
        if (it != g_jvmBlocks.end()) {
            g_jvmBlocks.erase(it);
            VirtualFree(rawPtr, 0, MEM_RELEASE);
            Logger::GetInstance().LogDebug("JassVM释放: ptr=%p", ptr);
        }
        else {
            Logger::GetInstance().LogError("JassVM释放未找到块: ptr=%p", ptr);
        }
    }

    void* Realloc(void* oldPtr, size_t newSize) {
        if (newSize != JVM_BLOCK_SIZE) {
            return nullptr;
        }

        if (!oldPtr) {
            return Allocate(newSize);
        }

        // JassVM块大小固定，无需实际重分配
        return oldPtr;
    }

    bool IsFromPool(void* ptr) {
        if (!ptr || !g_jvmInitialized.load(std::memory_order_acquire)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);

        uint8_t* rawPtr = static_cast<uint8_t*>(ptr) - sizeof(JVMBlockHeader);
        return std::find(g_jvmBlocks.begin(), g_jvmBlocks.end(), rawPtr) != g_jvmBlocks.end();
    }

    size_t GetUsedSize() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);
        return g_jvmBlocks.size() * JVM_BLOCK_SIZE;
    }

    void PrintStats() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);

        Logger::GetInstance().LogInfo("=== JassVM内存池统计 ===");
        Logger::GetInstance().LogInfo("块数量: %zu", g_jvmBlocks.size());
        Logger::GetInstance().LogInfo("总大小: %zu KB", (g_jvmBlocks.size() * JVM_BLOCK_SIZE) / 1024);
        Logger::GetInstance().LogInfo("=====================");
    }
}

// ======================== 小块内存池实现 ========================
namespace SmallBlockPool {
    namespace {
        const size_t SIZE_CLASSES[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };
        constexpr size_t NUM_SIZE_CLASSES = sizeof(SIZE_CLASSES) / sizeof(SIZE_CLASSES[0]);

        struct SizeClassPool {
            std::vector<void*> freeBlocks;
            std::mutex mutex;
            size_t blockSize;
            size_t maxCount;
        };

        SizeClassPool g_sizePools[NUM_SIZE_CLASSES];
        std::atomic<bool> g_smallPoolInitialized(false);
    }

    bool Initialize() {
        if (g_smallPoolInitialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            g_sizePools[i].blockSize = SIZE_CLASSES[i];
            g_sizePools[i].maxCount = 64 / (i + 1); // 小块缓存更多
        }

        Logger::GetInstance().LogInfo("小块内存池初始化完成");
        return true;
    }

    void Cleanup() {
        if (!g_smallPoolInitialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

            for (void* ptr : g_sizePools[i].freeBlocks) {
                MemoryPool::FreeSafe(ptr);
            }

            g_sizePools[i].freeBlocks.clear();
        }

        Logger::GetInstance().LogInfo("小块内存池清理完成");
    }

    bool ShouldIntercept(size_t size) {
        for (size_t sizeClass : SIZE_CLASSES) {
            if (size <= sizeClass) {
                return true;
            }
        }
        return false;
    }

    void* Allocate(size_t size) {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return nullptr;
        }

        // 找到合适的大小类
        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            if (size <= g_sizePools[i].blockSize) {
                std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

                if (!g_sizePools[i].freeBlocks.empty()) {
                    void* ptr = g_sizePools[i].freeBlocks.back();
                    g_sizePools[i].freeBlocks.pop_back();
                    return ptr;
                }

                break;
            }
        }

        return nullptr;
    }

    bool Free(void* ptr, size_t size) {
        if (!ptr || !g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return false;
        }

        // 找到对应的大小类
        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            if (size <= g_sizePools[i].blockSize) {
                std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

                if (g_sizePools[i].freeBlocks.size() < g_sizePools[i].maxCount) {
                    g_sizePools[i].freeBlocks.push_back(ptr);
                    return true;
                }

                break;
            }
        }

        return false;
    }

    void FlushCache() {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return;
        }

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);

            for (void* ptr : g_sizePools[i].freeBlocks) {
                MemoryPool::FreeSafe(ptr);
            }

            g_sizePools[i].freeBlocks.clear();
        }

        Logger::GetInstance().LogInfo("小块内存池缓存已清空");
    }

    void PrintStats() {
        if (!g_smallPoolInitialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::GetInstance().LogInfo("=== 小块内存池统计 ===");

        for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
            std::lock_guard<std::mutex> lock(g_sizePools[i].mutex);
            Logger::GetInstance().LogInfo("大小类 %zu: %zu个缓存块 (最大%zu)",
                g_sizePools[i].blockSize,
                g_sizePools[i].freeBlocks.size(),
                g_sizePools[i].maxCount);
        }

        Logger::GetInstance().LogInfo("===================");
    }
}
