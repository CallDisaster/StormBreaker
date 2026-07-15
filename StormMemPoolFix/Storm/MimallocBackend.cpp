#include "pch.h"

#include "MemoryBackend.h"

#include "Base/Logger.h"
#include "mimalloc.h"
#include "mimalloc-stats.h"
extern "C" {
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"
}

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>

static_assert(MI_MALLOC_VERSION == 30302,
    "StormBreaker requires the vendored mimalloc v3.3.2 sources.");

namespace {

using Clock = std::chrono::steady_clock;

void UpdateMaximum(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t current = target.load(std::memory_order_relaxed);
    while (value > current &&
        !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
    }
}

uint64_t NonNegative(int64_t value) {
    return value > 0 ? static_cast<uint64_t>(value) : 0;
}

constexpr long kDefaultPurgeDelayMilliseconds = -1;
constexpr long kMaximumPurgeDelayMilliseconds = 60L * 60L * 1000L;
constexpr long kDefaultArenaReserveMiB = 0;

bool ReadPurgeDelayMilliseconds(long* delay) {
    if (!delay) {
        return false;
    }
    char value[32]{};
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_MIMALLOC_PURGE_DELAY_MS", value,
        static_cast<DWORD>(sizeof(value)));
    if (length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        *delay = kDefaultPurgeDelayMilliseconds;
        return true;
    }
    if (length == 0 || length >= sizeof(value)) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PURGE_DELAY_MS; expected -1..%ld",
            kMaximumPurgeDelayMilliseconds);
        return false;
    }

    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' || parsed < -1 ||
        parsed > kMaximumPurgeDelayMilliseconds) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PURGE_DELAY_MS='%s'; expected "
            "-1..%ld", value, kMaximumPurgeDelayMilliseconds);
        return false;
    }
    *delay = parsed;
    return true;
}

bool ReadArenaReserveMiB(long* reserveMiB) {
    if (!reserveMiB) {
        return false;
    }
    char value[32]{};
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB", value,
        static_cast<DWORD>(sizeof(value)));
    if (length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        *reserveMiB = kDefaultArenaReserveMiB;
        return true;
    }
    if (length == 0 || length >= sizeof(value)) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB; expected "
            "0|8|16|32|64|128");
        return false;
    }

    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    const bool allowed = parsed == 0 || parsed == 8 || parsed == 16 ||
        parsed == 32 || parsed == 64 || parsed == 128;
    if (errno == ERANGE || end == value || *end != '\0' || !allowed) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB='%s'; "
            "expected 0|8|16|32|64|128", value);
        return false;
    }
    *reserveMiB = parsed;
    return true;
}

bool ReadPageFullRetain(long* retain) {
    if (!retain) {
        return false;
    }
    char value[32]{};
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN", value,
        static_cast<DWORD>(sizeof(value)));
    if (length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        *retain = 2;
        return true;
    }
    if (length == 0 || length >= sizeof(value)) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN; expected -1..8");
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' ||
        parsed < -1 || parsed > 8) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN='%s'; "
            "expected -1..8", value);
        return false;
    }
    *retain = parsed;
    return true;
}

bool ReadPageMaxCandidates(long* candidates) {
    if (!candidates) {
        return false;
    }
    char value[32]{};
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES", value,
        static_cast<DWORD>(sizeof(value)));
    if (length == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        *candidates = 4;
        return true;
    }
    if (length == 0 || length >= sizeof(value)) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES; "
            "expected 1..16");
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' ||
        parsed < 1 || parsed > 16) {
        Logger::GetInstance().LogError(
            "Invalid STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES='%s'; "
            "expected 1..16", value);
        return false;
    }
    *candidates = parsed;
    return true;
}

void ForceHeapCollection(mi_heap_t* heap, long configuredPurgeDelay) {
    if (!heap) {
        return;
    }
    const bool temporarilyEnablePurge = configuredPurgeDelay < 0;
    if (temporarilyEnablePurge) {
        mi_option_set(mi_option_purge_delay, 1);
    }
    mi_heap_collect(heap, true);
    if (temporarilyEnablePurge) {
        mi_option_set(mi_option_purge_delay, configuredPurgeDelay);
    }
}

constexpr uint64_t kLatencyUpperBounds[] = {
    100, 250, 500, 1000, 2500, 5000,
    10000, 25000, 50000, 100000, 250000, 1000000
};
static_assert(
    sizeof(kLatencyUpperBounds) / sizeof(kLatencyUpperBounds[0]) ==
        MemoryPool::kLatencyHistogramBucketCount);

class AtomicLatencyHistogram {
public:
    void Record(uint64_t nanoseconds) {
        size_t bucket = 0;
        while (bucket < MemoryPool::kLatencyHistogramBucketCount &&
            nanoseconds > kLatencyUpperBounds[bucket]) {
            ++bucket;
        }
        buckets_[bucket].fetch_add(1, std::memory_order_relaxed);
        samples_.fetch_add(1, std::memory_order_relaxed);
        total_.fetch_add(nanoseconds, std::memory_order_relaxed);
        UpdateMaximum(maximum_, nanoseconds);
    }

    MemoryPool::LatencyHistogramStats Snapshot() const {
        MemoryPool::LatencyHistogramStats result{};
        for (size_t i = 0; i < MemoryPool::kLatencyHistogramBucketCount; ++i) {
            result.upperBoundsNanoseconds[i] = kLatencyUpperBounds[i];
        }
        for (size_t i = 0;
            i < MemoryPool::kLatencyHistogramBucketCount + 1; ++i) {
            result.bucketCounts[i] =
                buckets_[i].load(std::memory_order_relaxed);
        }
        result.sampleCount = samples_.load(std::memory_order_relaxed);
        result.totalNanoseconds = total_.load(std::memory_order_relaxed);
        result.maxNanoseconds = maximum_.load(std::memory_order_relaxed);
        return result;
    }

    void Reset() {
        for (auto& bucket : buckets_) {
            bucket.store(0, std::memory_order_relaxed);
        }
        samples_.store(0, std::memory_order_relaxed);
        total_.store(0, std::memory_order_relaxed);
        maximum_.store(0, std::memory_order_relaxed);
    }

private:
    std::atomic<uint64_t>
        buckets_[MemoryPool::kLatencyHistogramBucketCount + 1]{};
    std::atomic<uint64_t> samples_{0};
    std::atomic<uint64_t> total_{0};
    std::atomic<uint64_t> maximum_{0};
};

struct LockWaitMetrics {
    std::atomic<uint64_t>* count = nullptr;
    std::atomic<uint64_t>* totalNanoseconds = nullptr;
    std::atomic<uint64_t>* maximumNanoseconds = nullptr;
    AtomicLatencyHistogram* histogram = nullptr;
};

void RecordLockWait(
    const LockWaitMetrics& metrics, const Clock::time_point& start) {
    if (!metrics.count) {
        return;
    }
    const uint64_t nanoseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - start).count());
    metrics.count->fetch_add(1, std::memory_order_relaxed);
    metrics.totalNanoseconds->fetch_add(
        nanoseconds, std::memory_order_relaxed);
    UpdateMaximum(*metrics.maximumNanoseconds, nanoseconds);
    metrics.histogram->Record(nanoseconds);
}

struct MimallocVisitContext {
    MemoryPool::Internal::BackendBlockVisitor visitor;
    void* context;
};

class SharedOperationLock {
public:
    explicit SharedOperationLock(
        SRWLOCK* lock, LockWaitMetrics metrics = {}) : lock_(lock) {
        if (TryAcquireSRWLockShared(lock_)) {
            return;
        }
        if (!MemoryPool::IsLatencyTrackingEnabled()) {
            AcquireSRWLockShared(lock_);
            return;
        }
        const Clock::time_point start = Clock::now();
        AcquireSRWLockShared(lock_);
        RecordLockWait(metrics, start);
    }
    ~SharedOperationLock() {
        ReleaseSRWLockShared(lock_);
    }

    SharedOperationLock(const SharedOperationLock&) = delete;
    SharedOperationLock& operator=(const SharedOperationLock&) = delete;

private:
    SRWLOCK* lock_;
};

class ExclusiveOperationLock {
public:
    explicit ExclusiveOperationLock(
        SRWLOCK* lock, LockWaitMetrics metrics = {}) : lock_(lock) {
        if (TryAcquireSRWLockExclusive(lock_)) {
            return;
        }
        if (!MemoryPool::IsLatencyTrackingEnabled()) {
            AcquireSRWLockExclusive(lock_);
            return;
        }
        const Clock::time_point start = Clock::now();
        AcquireSRWLockExclusive(lock_);
        RecordLockWait(metrics, start);
    }
    ~ExclusiveOperationLock() {
        ReleaseSRWLockExclusive(lock_);
    }

    ExclusiveOperationLock(const ExclusiveOperationLock&) = delete;
    ExclusiveOperationLock& operator=(const ExclusiveOperationLock&) = delete;

private:
    SRWLOCK* lock_;
};

bool mi_cdecl MimallocBlockVisitor(
    const mi_heap_t*, const mi_heap_area_t*, void* block,
    size_t blockSize, void* user) {
    MimallocVisitContext* visit =
        static_cast<MimallocVisitContext*>(user);
    const size_t measured = mi_usable_size(block);
    return visit->visitor(
        block, measured != 0 ? measured : blockSize, visit->context);
}

class MimallocBackend final : public MemoryPool::Internal::MemoryBackend {
public:
    ~MimallocBackend() override {
        Shutdown();
    }

    MemoryPool::BackendKind GetKind() const override {
        return MemoryPool::BackendKind::Mimalloc;
    }

    const char* GetName() const override {
        return "mimalloc";
    }

    bool Initialize(const MemoryPool::Config&) override {
        if (heap_) {
            return true;
        }

        if (mi_version() != MI_MALLOC_VERSION) {
            Logger::GetInstance().LogError(
                "mimalloc version mismatch: expected=%d, actual=%d",
                MI_MALLOC_VERSION, mi_version());
            return false;
        }

        long purgeDelay = kDefaultPurgeDelayMilliseconds;
        long arenaReserveMiB = kDefaultArenaReserveMiB;
        long pageFullRetain = 2;
        long pageMaxCandidates = 4;
        if (!ReadPurgeDelayMilliseconds(&purgeDelay) ||
            !ReadArenaReserveMiB(&arenaReserveMiB) ||
            !ReadPageFullRetain(&pageFullRetain) ||
            !ReadPageMaxCandidates(&pageMaxCandidates)) {
            return false;
        }
        mi_option_set(mi_option_purge_delay, purgeDelay);
        if (arenaReserveMiB != 0) {
            mi_option_set(
                mi_option_arena_reserve, arenaReserveMiB * 1024L);
        }
        mi_option_set(mi_option_page_full_retain, pageFullRetain);
        mi_option_set(mi_option_page_max_candidates, pageMaxCandidates);
        purgeDelayMilliseconds_ = purgeDelay;
        arenaReserveMiB_ = arenaReserveMiB;
        pageFullRetain_ = pageFullRetain;
        pageMaxCandidates_ = pageMaxCandidates;

        // v3 heaps are first-class and can be used safely from any thread.
        heap_ = mi_heap_new();
        if (!heap_) {
            Logger::GetInstance().LogError(
                "Failed to create the dedicated mimalloc heap");
            return false;
        }

        RefreshMemoryStats(false);
        Logger::GetInstance().LogInfo(
            "Initialized dedicated mimalloc v3.3.2 first-class heap: %p, "
            "arena-reserve=%s%ld MiB, full-retain=%ld, candidates=%ld",
            heap_, arenaReserveMiB_ == 0 ? "upstream-default/" : "",
            arenaReserveMiB_ == 0 ? 128L : arenaReserveMiB_,
            pageFullRetain_, pageMaxCandidates_);
        if (purgeDelayMilliseconds_ < 0) {
            Logger::GetInstance().LogInfo(
                "mimalloc automatic purge disabled on allocation threads; "
                "explicit memory-pressure collection remains enabled");
        } else {
            Logger::GetInstance().LogInfo(
                "mimalloc automatic purge delay: %ld ms",
                purgeDelayMilliseconds_);
        }
        return true;
    }

    void Shutdown() override {
        ExclusiveOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap) {
            return;
        }

        heap_ = nullptr;
        mi_heap_destroy(heap);
        reservedBytes_.store(0, std::memory_order_relaxed);
        committedBytes_.store(0, std::memory_order_relaxed);
        lastReservedBytes_.store(0, std::memory_order_relaxed);
    }

    void* Allocate(size_t size, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap) {
            return nullptr;
        }

        size_t measured = 0;
        void* ptr = _mi_theap_malloc_zero(
            _mi_heap_theap(heap), size, false, &measured);
        ForgetFreed(ptr);
        if (ptr && usableSize) {
            *usableSize = measured < size ? size : measured;
        }
        return ptr;
    }

    void* AllocateAligned(
        size_t size, size_t alignment, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap) {
            return nullptr;
        }

        size_t measured = 0;
        void* ptr = alignment <= MI_MAX_ALIGN_SIZE
            ? _mi_theap_malloc_zero(
                _mi_heap_theap(heap), size, false, &measured)
            : mi_heap_malloc_aligned(heap, size, alignment);
        ForgetFreed(ptr);
        if (ptr && usableSize) {
            if (alignment > MI_MAX_ALIGN_SIZE) {
                measured = mi_usable_size(ptr);
            }
            *usableSize = measured < size ? size : measured;
        }
        return ptr;
    }

    void* Reallocate(
        void* ptr, size_t newSize, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || (ptr && !IsExactAllocationStart(heap, ptr))) {
            return nullptr;
        }

        size_t previousUsable = 0;
        size_t measured = 0;
        void* newPtr = _mi_theap_realloc_zero(
            _mi_heap_theap(heap), ptr, newSize, false,
            &previousUsable, &measured);
        if (newPtr) {
            if (ptr && newPtr != ptr) {
                RememberFreed(ptr);
            }
            ForgetFreed(newPtr);
        }
        if (newPtr && usableSize) {
            *usableSize = measured < newSize ? newSize : measured;
        }
        return newPtr;
    }

    void* ReallocateInPlace(
        void* ptr, size_t newSize, size_t* oldUsableSize,
        size_t* newUsableSize) override {
        if (oldUsableSize) {
            *oldUsableSize = 0;
        }
        if (newUsableSize) {
            *newUsableSize = 0;
        }
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || !ptr || newSize == 0 ||
            !IsExactAllocationStart(heap, ptr)) {
            return nullptr;
        }

        const size_t previousUsable = mi_usable_size(ptr);
        if (previousUsable == 0) {
            return nullptr;
        }
        if (oldUsableSize) {
            *oldUsableSize = previousUsable;
        }

        void* result = mi_expand(ptr, newSize);
        ForgetFreed(result);
        if (result && newUsableSize) {
            const size_t measured = mi_usable_size(result);
            *newUsableSize = measured < newSize ? newSize : measured;
        }
        return result;
    }

    size_t Free(void* ptr) override {
        return FreeConditional(ptr, nullptr, nullptr);
    }

    size_t FreeConditional(
        void* ptr, MemoryPool::Internal::BackendFreeValidator validator,
        void* context) override {
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || !ptr || !IsExactAllocationStart(heap, ptr) ||
            !TryClaimFree(ptr)) {
            return 0;
        }
        const size_t usableSize = mi_usable_size(ptr);
        if (usableSize == 0 ||
            (validator && !validator(ptr, usableSize, context))) {
            ForgetFreed(ptr);
            return 0;
        }
        mi_free(ptr);
        return usableSize;
    }

    MemoryPool::BatchFreeResult FreeBatch(
        const MemoryPool::BatchFreeEntry* entries,
        size_t count) override {
        MemoryPool::BatchFreeResult result{};
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || (!entries && count != 0)) {
            return result;
        }
        for (; result.freedCount < count; ++result.freedCount) {
            void* const ptr = entries[result.freedCount].pointer;
            if (!ptr || !IsExactAllocationStart(heap, ptr) ||
                !TryClaimFree(ptr)) {
                break;
            }
            const size_t usable = mi_usable_size(ptr);
            if (usable == 0) {
                ForgetFreed(ptr);
                break;
            }
            mi_free(ptr);
            result.usableBytes += usable;
        }
        return result;
    }

    bool IsFromBackend(void* ptr) const override {
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        return heap && ptr && mi_heap_contains(heap, ptr);
    }

    bool QueryAllocation(void* ptr, size_t* usableSize) const override {
        if (usableSize) {
            *usableSize = 0;
        }
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || !ptr || !IsExactAllocationStart(heap, ptr)) {
            return false;
        }
        const size_t measured = mi_usable_size(ptr);
        if (measured == 0) {
            return false;
        }
        if (usableSize) {
            *usableSize = measured;
        }
        return true;
    }

    size_t GetBlockSize(void* ptr) const override {
        size_t usableSize = 0;
        return QueryAllocation(ptr, &usableSize) ? usableSize : 0;
    }

    bool VisitAllocatedBlocks(
        MemoryPool::Internal::BackendBlockVisitor visitor,
        void* context) const override {
        ExclusiveOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap || !visitor) {
            return false;
        }
        // Drain deferred cross-thread frees before taking the live snapshot.
        mi_heap_collect(heap, false);
        MimallocVisitContext visit{visitor, context};
        return mi_heap_visit_blocks(
            heap, true, MimallocBlockVisitor, &visit);
    }

    bool Extend(size_t) override {
        // A first-class mimalloc heap grows on demand and has no per-heap reserve API.
        return false;
    }

    void Trim() override {
        ExclusiveOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (!heap) {
            return;
        }

        ForceHeapCollection(heap, purgeDelayMilliseconds_);
        trimCount_.fetch_add(1, std::memory_order_relaxed);
        RefreshMemoryStats(false);
    }

    void Compact() override {
        ExclusiveOperationLock operationLock(&operationLock_, LockMetrics());
        mi_heap_t* heap = heap_;
        if (heap) {
            ForceHeapCollection(heap, purgeDelayMilliseconds_);
            RefreshMemoryStats(false);
        }
    }

    void SetThreadSafety(bool) override {
        // The dedicated v3 heap remains thread-safe by design.
    }

    MemoryPool::Internal::BackendStats GetStats() const override {
        // Per-heap stats collection is intentionally sampled by telemetry,
        // never by the allocation hot path.
        RefreshMemoryStats(true);
        return {
            reservedBytes_.load(std::memory_order_relaxed),
            committedBytes_.load(std::memory_order_relaxed),
            peakReservedBytes_.load(std::memory_order_relaxed),
            peakCommittedBytes_.load(std::memory_order_relaxed),
            growthCount_.load(std::memory_order_relaxed),
            trimCount_.load(std::memory_order_relaxed),
            lockWaitCount_.load(std::memory_order_relaxed),
            lockWaitNanoseconds_.load(std::memory_order_relaxed),
            maxLockWaitNanoseconds_.load(std::memory_order_relaxed),
            lockWaitLatency_.Snapshot()
        };
    }

    void ResetStats() override {
        RefreshMemoryStats(false);
        peakReservedBytes_.store(
            reservedBytes_.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        peakCommittedBytes_.store(
            committedBytes_.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        growthCount_.store(0, std::memory_order_relaxed);
        trimCount_.store(0, std::memory_order_relaxed);
        lockWaitCount_.store(0, std::memory_order_relaxed);
        lockWaitNanoseconds_.store(0, std::memory_order_relaxed);
        maxLockWaitNanoseconds_.store(0, std::memory_order_relaxed);
        lockWaitLatency_.Reset();
    }

    void* GetNativeHandle() const override {
        return heap_;
    }

    size_t GetPoolCount() const override {
        return heap_ ? 1 : 0;
    }

    void DumpPoolInfo() const override {
        const MemoryPool::Internal::BackendStats stats = GetStats();
        Logger::GetInstance().LogInfo(
            "mimalloc heap: handle=%p, reserved=%llu KB, committed=%llu KB",
            heap_,
            static_cast<unsigned long long>(stats.reservedBytes / 1024),
            static_cast<unsigned long long>(stats.committedBytes / 1024));
    }

    bool Validate() const override {
        SharedOperationLock operationLock(&operationLock_, LockMetrics());
        return heap_ != nullptr && mi_version() == MI_MALLOC_VERSION;
    }

private:
    static constexpr size_t kRecentFreedCapacity = 65536;

    static size_t FreedSlot(const void* pointer) {
        uintptr_t value = reinterpret_cast<uintptr_t>(pointer) >> 3;
        value ^= value >> 16;
        value *= 0x7FEB352Du;
        value ^= value >> 15;
        return static_cast<size_t>(value) & (kRecentFreedCapacity - 1u);
    }

    bool IsExactAllocationStart(mi_heap_t* heap, void* pointer) const {
        if (!heap || !pointer || WasRecentlyFreed(pointer)) {
            return false;
        }
        mi_page_t* page = _mi_safe_ptr_page(pointer);
        return page && mi_page_heap(page) == heap &&
            _mi_page_ptr_unalign(page, pointer) == pointer;
    }

    bool WasRecentlyFreed(const void* pointer) const {
        return pointer && recentFreed_[FreedSlot(pointer)].load(
            std::memory_order_acquire) ==
            reinterpret_cast<uintptr_t>(pointer);
    }

    bool TryClaimFree(const void* pointer) {
        const uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
        return recentFreed_[FreedSlot(pointer)].exchange(
            value, std::memory_order_acq_rel) != value;
    }

    void RememberFreed(const void* pointer) {
        if (pointer) {
            recentFreed_[FreedSlot(pointer)].store(
                reinterpret_cast<uintptr_t>(pointer),
                std::memory_order_release);
        }
    }

    void ForgetFreed(const void* pointer) {
        if (!pointer) {
            return;
        }
        auto& slot = recentFreed_[FreedSlot(pointer)];
        const uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
        uintptr_t expected = slot.load(std::memory_order_relaxed);
        if (expected == value) {
            slot.compare_exchange_strong(expected, 0,
                                         std::memory_order_relaxed);
        }
    }

    LockWaitMetrics LockMetrics() const {
        return {
            &lockWaitCount_,
            &lockWaitNanoseconds_,
            &maxLockWaitNanoseconds_,
            &lockWaitLatency_
        };
    }

    void RefreshMemoryStats(bool countGrowth) const {
        mi_heap_t* heap = heap_;
        if (!heap) {
            return;
        }

        mi_stats_t stats;
        mi_stats_init(&stats);
        // OS reserve/commit accounting lives at the mimalloc subprocess level
        // in v3, even for a first-class heap. StormBreaker is the only user of
        // the statically linked explicit mi_ API, so this is still backend-local.
        if (!mi_stats_get(&stats)) {
            return;
        }

        const uint64_t reserved = NonNegative(stats.reserved.current);
        const uint64_t committed = NonNegative(stats.committed.current);
        reservedBytes_.store(reserved, std::memory_order_relaxed);
        committedBytes_.store(committed, std::memory_order_relaxed);
        UpdateMaximum(peakReservedBytes_, reserved);
        UpdateMaximum(peakCommittedBytes_, committed);

        const uint64_t previous =
            lastReservedBytes_.exchange(reserved, std::memory_order_relaxed);
        if (countGrowth && reserved > previous) {
            growthCount_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    mi_heap_t* heap_ = nullptr;
    long purgeDelayMilliseconds_ = kDefaultPurgeDelayMilliseconds;
    long arenaReserveMiB_ = kDefaultArenaReserveMiB;
    long pageFullRetain_ = 2;
    long pageMaxCandidates_ = 4;
    mutable std::atomic<uintptr_t> recentFreed_[kRecentFreedCapacity]{};
    mutable SRWLOCK operationLock_ = SRWLOCK_INIT;
    mutable std::atomic<uint64_t> reservedBytes_{0};
    mutable std::atomic<uint64_t> committedBytes_{0};
    mutable std::atomic<uint64_t> peakReservedBytes_{0};
    mutable std::atomic<uint64_t> peakCommittedBytes_{0};
    mutable std::atomic<uint64_t> lastReservedBytes_{0};
    mutable std::atomic<uint64_t> growthCount_{0};
    mutable std::atomic<uint64_t> trimCount_{0};
    mutable std::atomic<uint64_t> lockWaitCount_{0};
    mutable std::atomic<uint64_t> lockWaitNanoseconds_{0};
    mutable std::atomic<uint64_t> maxLockWaitNanoseconds_{0};
    mutable AtomicLatencyHistogram lockWaitLatency_;
};

} // namespace

namespace MemoryPool {
namespace Internal {

std::unique_ptr<MemoryBackend> CreateMimallocBackend() {
    return std::make_unique<MimallocBackend>();
}

} // namespace Internal
} // namespace MemoryPool
