#include "pch.h"

#include "MemoryBackend.h"

#include "Base/Logger.h"
#include "tlsf.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

constexpr size_t kTlsfShardCount = 4;
constexpr size_t kTlsfShardBudgetAlignment = 64u * 1024u;
constexpr size_t kTlsfShardAutoGrowthMaximum = 4u * 1024u * 1024u;
constexpr size_t kTlsfShardDirectorySlots = size_t{1} << 16;
std::atomic<uint32_t> g_nextTlsfShardAffinity{0};
thread_local uint32_t g_tlsfShardAffinity = UINT32_MAX;

#if defined(STORMBREAKER_TESTING)
std::atomic<bool> g_tlsfRangeIndexEnabled{true};
std::atomic<int32_t> g_tlsfShardExtendFailure{-1};
std::atomic<bool> g_tlsfMainPoolDecommitEnabled{false};
std::atomic<bool> g_tlsfTopDownEnabled{false};
std::atomic<bool> g_tlsfConstantTimeEmptyCheckEnabled{true};
std::atomic<size_t> g_tlsfWarmEmptyPoolLimit{0};
thread_local int32_t g_tlsfShardAffinityOverride = -1;
#endif

size_t PreferredTlsfShard() noexcept {
#if defined(STORMBREAKER_TESTING)
    if (g_tlsfShardAffinityOverride >= 0) {
        return static_cast<size_t>(g_tlsfShardAffinityOverride);
    }
#endif
    if (g_tlsfShardAffinity == UINT32_MAX) {
        g_tlsfShardAffinity =
            g_nextTlsfShardAffinity.fetch_add(1, std::memory_order_relaxed) %
            kTlsfShardCount;
    }
    return g_tlsfShardAffinity;
}

void RememberPreferredTlsfShard(size_t shard) noexcept {
#if defined(STORMBREAKER_TESTING)
    if (g_tlsfShardAffinityOverride >= 0) {
        return;
    }
#endif
    g_tlsfShardAffinity = static_cast<uint32_t>(shard);
}

bool SplitTlsfShardBudget(
    size_t total, size_t minimumPerShard,
    std::array<size_t, kTlsfShardCount>& split) noexcept {
    if (total == 0 || total % kTlsfShardBudgetAlignment != 0) {
        return false;
    }

    const size_t minimumUnits =
        (minimumPerShard + kTlsfShardBudgetAlignment - 1) /
        kTlsfShardBudgetAlignment;
    const size_t totalUnits = total / kTlsfShardBudgetAlignment;
    if (minimumUnits == 0 ||
        totalUnits < minimumUnits * kTlsfShardCount) {
        return false;
    }

    const size_t baseUnits = totalUnits / kTlsfShardCount;
    const size_t remainder = totalUnits % kTlsfShardCount;
    for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
        const size_t units = baseUnits + (shard < remainder ? 1u : 0u);
        if (units < minimumUnits) {
            return false;
        }
        split[shard] = units * kTlsfShardBudgetAlignment;
    }
    return true;
}

class SharedTlsfReservationBudget {
public:
    void Configure(size_t maximumBytes) noexcept {
        maximumBytes_ = maximumBytes;
        reservedBytes_.store(0, std::memory_order_relaxed);
        peakReservedBytes_.store(0, std::memory_order_relaxed);
    }

    bool TryReserve(size_t bytes) noexcept {
        size_t current = reservedBytes_.load(std::memory_order_relaxed);
        for (;;) {
            if (current > maximumBytes_ || bytes > maximumBytes_ - current) {
                return false;
            }
            const size_t updated = current + bytes;
            if (reservedBytes_.compare_exchange_weak(
                    current, updated, std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                UpdatePeak(updated);
                return true;
            }
        }
    }

    void Release(size_t bytes) noexcept {
        if (bytes == 0) {
            return;
        }
        size_t current = reservedBytes_.load(std::memory_order_relaxed);
        for (;;) {
            // Keep the budget fail-closed if internal accounting is ever
            // inconsistent; undercounting would permit aggregate overcommit.
            if (bytes > current) {
                return;
            }
            if (reservedBytes_.compare_exchange_weak(
                    current, current - bytes, std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                return;
            }
        }
    }

    size_t GetReservedBytes() const noexcept {
        return reservedBytes_.load(std::memory_order_relaxed);
    }

    size_t GetAvailableBytes() const noexcept {
        const size_t reserved = GetReservedBytes();
        return reserved < maximumBytes_ ? maximumBytes_ - reserved : 0;
    }

    size_t GetPeakReservedBytes() const noexcept {
        return peakReservedBytes_.load(std::memory_order_relaxed);
    }

    void ResetPeak() noexcept {
        peakReservedBytes_.store(
            GetReservedBytes(), std::memory_order_relaxed);
    }

private:
    void UpdatePeak(size_t value) noexcept {
        size_t current = peakReservedBytes_.load(std::memory_order_relaxed);
        while (value > current &&
            !peakReservedBytes_.compare_exchange_weak(
                current, value, std::memory_order_relaxed)) {
        }
    }

    size_t maximumBytes_ = 0;
    std::atomic<size_t> reservedBytes_{0};
    std::atomic<size_t> peakReservedBytes_{0};
};

class TlsfShardDirectory {
public:
    bool RegisterRange(void* base, size_t size, size_t shard) noexcept {
        if (!base || size == 0 || shard >= kTlsfShardCount) {
            return false;
        }
        const uintptr_t begin = reinterpret_cast<uintptr_t>(base);
        if ((begin & (kTlsfShardBudgetAlignment - 1u)) != 0 ||
            size > UINTPTR_MAX - begin) {
            return false;
        }
        const uintptr_t end = begin + size;
        const size_t first = begin >> 16;
        const size_t last = (end - 1u) >> 16;
        if (last >= kTlsfShardDirectorySlots) {
            return false;
        }

        const uint8_t encoded = static_cast<uint8_t>(shard + 1u);
        size_t slot = first;
        for (; slot <= last; ++slot) {
            uint8_t expected = 0;
            if (!owners_[slot].compare_exchange_strong(
                    expected, encoded, std::memory_order_release,
                    std::memory_order_relaxed)) {
                while (slot != first) {
                    --slot;
                    expected = encoded;
                    owners_[slot].compare_exchange_strong(
                        expected, 0, std::memory_order_release,
                        std::memory_order_relaxed);
                }
                return false;
            }
        }
        return true;
    }

    void UnregisterRange(void* base, size_t size, size_t shard) noexcept {
        if (!base || size == 0 || shard >= kTlsfShardCount) {
            return;
        }
        const uintptr_t begin = reinterpret_cast<uintptr_t>(base);
        if ((begin & (kTlsfShardBudgetAlignment - 1u)) != 0 ||
            size > UINTPTR_MAX - begin) {
            return;
        }
        const uintptr_t end = begin + size;
        const size_t first = begin >> 16;
        const size_t last = (end - 1u) >> 16;
        if (last >= kTlsfShardDirectorySlots) {
            return;
        }
        const uint8_t encoded = static_cast<uint8_t>(shard + 1u);
        for (size_t slot = first; slot <= last; ++slot) {
            uint8_t expected = encoded;
            owners_[slot].compare_exchange_strong(
                expected, 0, std::memory_order_release,
                std::memory_order_relaxed);
        }
    }

    size_t Lookup(const void* pointer) const noexcept {
        if (!pointer) {
            return kTlsfShardCount;
        }
        const size_t slot =
            reinterpret_cast<uintptr_t>(pointer) >> 16;
        const uint8_t encoded =
            owners_[slot].load(std::memory_order_acquire);
        return encoded >= 1u && encoded <= kTlsfShardCount
            ? static_cast<size_t>(encoded - 1u)
            : kTlsfShardCount;
    }

    size_t CountRegisteredSlots() const noexcept {
        size_t count = 0;
        for (const auto& owner : owners_) {
            count += owner.load(std::memory_order_relaxed) != 0 ? 1u : 0u;
        }
        return count;
    }

    void Reset() noexcept {
        for (auto& owner : owners_) {
            owner.store(0, std::memory_order_relaxed);
        }
    }

private:
    static_assert(std::atomic<uint8_t>::is_always_lock_free);
    std::array<std::atomic<uint8_t>, kTlsfShardDirectorySlots> owners_{};
};

bool TlsfRangeIndexEnabled() noexcept {
#if defined(STORMBREAKER_TESTING)
    return g_tlsfRangeIndexEnabled.load(std::memory_order_relaxed);
#else
    return true;
#endif
}

bool TlsfMainPoolDecommitEnabled() noexcept {
#if defined(STORMBREAKER_TESTING)
    return g_tlsfMainPoolDecommitEnabled.load(std::memory_order_relaxed);
#else
    return false;
#endif
}

bool ResolveTlsfTopDownEnabled(bool* enabled) noexcept {
    if (!enabled) {
        return false;
    }
#if defined(STORMBREAKER_TESTING)
    *enabled = g_tlsfTopDownEnabled.load(std::memory_order_relaxed);
    return true;
#else
    char policy[24]{};
    const DWORD length = GetEnvironmentVariableA(
        "STORMBREAKER_TLSF_ADDRESS_POLICY", policy,
        static_cast<DWORD>(sizeof(policy)));
    if (length == 0) {
        // Some Warcraft III paths do not tolerate managed allocations in the
        // high half of the x86 address space. Keep clustering diagnostic-only.
        *enabled = false;
        return true;
    }
    if (length >= sizeof(policy)) {
        Logger::GetInstance().LogError(
            "STORMBREAKER_TLSF_ADDRESS_POLICY is too long");
        return false;
    }
    if (_stricmp(policy, "clustered") == 0 ||
        _stricmp(policy, "top-down") == 0 ||
        std::strcmp(policy, "1") == 0) {
        *enabled = true;
        return true;
    }
    if (_stricmp(policy, "system") == 0 ||
        _stricmp(policy, "bottom-up") == 0 ||
        std::strcmp(policy, "0") == 0) {
        *enabled = false;
        return true;
    }
    Logger::GetInstance().LogError(
        "Invalid STORMBREAKER_TLSF_ADDRESS_POLICY=%s; expected clustered or system",
        policy);
    return false;
#endif
}

DWORD TlsfReserveCommitFlags(bool topDown) noexcept {
    return MEM_COMMIT | MEM_RESERVE |
        (topDown ? MEM_TOP_DOWN : 0u);
}

constexpr uintptr_t kStormSignedAddressLimit = 0x80000000u;

bool IsStormCompatibleAddressRange(const void* base, size_t size) noexcept {
    if (!base || size == 0) {
        return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(base);
    return start < kStormSignedAddressLimit &&
        size <= kStormSignedAddressLimit - start;
}

void* EnforceStormCompatibleAddressRange(
    void* base, size_t size, const char* purpose) noexcept {
    if (!base || IsStormCompatibleAddressRange(base, size)) {
        return base;
    }
    Logger::GetInstance().LogWarning(
        "TLSF rejected >=0x80000000 address range: purpose=%s, base=%p, size=%zu",
        purpose ? purpose : "unknown", base, size);
    VirtualFree(base, 0, MEM_RELEASE);
    return nullptr;
}

bool TlsfConstantTimeEmptyCheckEnabled() noexcept {
#if defined(STORMBREAKER_TESTING)
    return g_tlsfConstantTimeEmptyCheckEnabled.load(
        std::memory_order_relaxed);
#else
    return true;
#endif
}

size_t TlsfWarmEmptyPoolLimit() noexcept {
#if defined(STORMBREAKER_TESTING)
    return g_tlsfWarmEmptyPoolLimit.load(std::memory_order_relaxed);
#else
    return 0;
#endif
}

void UpdateMaximum(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t current = target.load(std::memory_order_relaxed);
    while (value > current &&
        !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
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
        for (size_t index = 0;
             index < MemoryPool::kLatencyHistogramBucketCount; ++index) {
            result.upperBoundsNanoseconds[index] =
                kLatencyUpperBounds[index];
        }
        for (size_t index = 0;
             index < MemoryPool::kLatencyHistogramBucketCount + 1; ++index) {
            result.bucketCounts[index] =
                buckets_[index].load(std::memory_order_relaxed);
        }
        result.sampleCount = samples_.load(std::memory_order_relaxed);
        result.totalNanoseconds = total_.load(std::memory_order_relaxed);
        result.maxNanoseconds = maximum_.load(std::memory_order_relaxed);
        return result;
    }

    void Reset() {
        for (auto &bucket : buckets_) {
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

class GrowthLatencyScope {
public:
    GrowthLatencyScope()
        : enabled_(MemoryPool::IsLatencyTrackingEnabled()),
          start_(enabled_ ? Clock::now() : Clock::time_point{}) {
    }

    ~GrowthLatencyScope() {
        if (!enabled_) {
            return;
        }
        const uint64_t nanoseconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                Clock::now() - start_).count());
        MemoryPool::RecordGrowthLatency(nanoseconds);
    }

private:
    bool enabled_;
    Clock::time_point start_;
};

bool IsPointerInRange(void* ptr, void* base, size_t size) {
    if (!ptr || !base) {
        return false;
    }

    const uintptr_t address = reinterpret_cast<uintptr_t>(ptr);
    const uintptr_t start = reinterpret_cast<uintptr_t>(base);
    return address >= start && address - start < size;
}

void* SafeTlsfMalloc(tlsf_t tlsf, size_t size) {
    __try {
        return tlsf_malloc(tlsf, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF malloc exception: size=%zu, code=0x%08X",
            size, GetExceptionCode());
        return nullptr;
    }
}

void* SafeTlsfMemalign(tlsf_t tlsf, size_t alignment, size_t size) {
    __try {
        return tlsf_memalign(tlsf, alignment, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF memalign exception: align=%zu, size=%zu, code=0x%08X",
            alignment, size, GetExceptionCode());
        return nullptr;
    }
}

void* SafeTlsfRealloc(tlsf_t tlsf, void* ptr, size_t size) {
    __try {
        return tlsf_realloc(tlsf, ptr, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF realloc exception: ptr=%p, size=%zu, code=0x%08X",
            ptr, size, GetExceptionCode());
        return nullptr;
    }
}

void* SafeTlsfReallocInPlace(tlsf_t tlsf, void* ptr, size_t size) {
    __try {
        return tlsf_realloc_in_place(tlsf, ptr, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF in-place realloc exception: ptr=%p, size=%zu, code=0x%08X",
            ptr, size, GetExceptionCode());
        return nullptr;
    }
}

bool SafeTlsfFree(tlsf_t tlsf, void* ptr) {
    __try {
        tlsf_free(tlsf, ptr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF free exception: ptr=%p, code=0x%08X",
            ptr, GetExceptionCode());
        return false;
    }
}

size_t SafeTlsfBlockSize(void* ptr) {
    __try {
        return tlsf_block_size(ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF block_size exception: ptr=%p, code=0x%08X",
            ptr, GetExceptionCode());
        return 0;
    }
}

void TlsfUsedBlockWalker(void*, size_t, int used, void* user) {
    if (used) {
        *static_cast<bool*>(user) = true;
    }
}

bool SafeTlsfPoolIsEmpty(pool_t pool) {
    bool hasAllocatedBlocks = false;
    __try {
        if (TlsfConstantTimeEmptyCheckEnabled()) {
            return tlsf_pool_is_empty(pool) != 0;
        }
        tlsf_walk_pool(pool, TlsfUsedBlockWalker, &hasAllocatedBlocks);
        return !hasAllocatedBlocks;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF pool empty-check exception: pool=%p, code=0x%08X",
            pool, GetExceptionCode());
        return false;
    }
}

bool SafeTlsfExactBlock(void* ptr, void* rangeBase, size_t rangeSize) {
    __try {
        return tlsf_block_is_valid_in_range(ptr, rangeBase, rangeSize) != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError(
            "TLSF exact-block validation exception: ptr=%p, code=0x%08X",
            ptr, GetExceptionCode());
        return false;
    }
}

struct TlsfVisitContext {
    MemoryPool::Internal::BackendBlockVisitor visitor;
    void* context;
    bool keepVisiting;
};

void TlsfBlockWalker(void* ptr, size_t size, int used, void* user) {
    TlsfVisitContext* visit = static_cast<TlsfVisitContext*>(user);
    if (!used || !visit->keepVisiting) {
        return;
    }
    visit->keepVisiting = visit->visitor(ptr, size, visit->context);
}

class TlsfShardedBackend;

class TlsfBackend final : public MemoryPool::Internal::MemoryBackend {
public:
    explicit TlsfBackend(
        SharedTlsfReservationBudget* sharedReservationBudget = nullptr,
        TlsfShardDirectory* shardDirectory = nullptr,
        size_t shardIndex = 0)
        : sharedReservationBudget_(sharedReservationBudget),
          shardDirectory_(shardDirectory), shardIndex_(shardIndex) {
    }

    ~TlsfBackend() override {
        Shutdown();
    }

    MemoryPool::BackendKind GetKind() const override {
        return MemoryPool::BackendKind::Tlsf;
    }

    const char* GetName() const override {
        return "tlsf";
    }

    bool Initialize(const MemoryPool::Config& config) override {
        if (tlsfHandle_) {
            return true;
        }

        config_ = config;
        if (!ResolveTlsfTopDownEnabled(&topDownEnabled_)) {
            return false;
        }
        // The vendored locality cache is process-global, keeps freed blocks
        // marked as used, and cannot participate in ownership enumeration.
        // Backend locking already provides the required synchronization.
        tlsf_toggle_optimized_memory_locality(0);
        Logger::GetInstance().LogInfo(
            "Initializing TLSF backend: initial=%zu MB, max=%zu MB, growth=%zu MB, address=%s",
            config_.initialSize / (1024 * 1024),
            config_.maxSize / (1024 * 1024),
            config_.extendGranularity / (1024 * 1024),
            topDownEnabled_ ? "clustered" : "system");

        if (sharedReservationBudget_ &&
            !sharedReservationBudget_->TryReserve(config_.initialSize)) {
            Logger::GetInstance().LogError(
                "TLSF shard initial reservation exceeds aggregate budget: size=%zu",
                config_.initialSize);
            return false;
        }

        mainPool_ = EnforceStormCompatibleAddressRange(
            VirtualAlloc(nullptr, config_.initialSize,
                TlsfReserveCommitFlags(topDownEnabled_), PAGE_READWRITE),
            config_.initialSize, "main");
        if (!mainPool_ && topDownEnabled_) {
            Logger::GetInstance().LogWarning(
                "TLSF clustered main-pool allocation failed; retrying system placement");
            topDownEnabled_ = false;
            mainPool_ = EnforceStormCompatibleAddressRange(
                VirtualAlloc(nullptr, config_.initialSize,
                    TlsfReserveCommitFlags(false), PAGE_READWRITE),
                config_.initialSize, "main-system-fallback");
        }
        if (!mainPool_) {
            Logger::GetInstance().LogError(
                "TLSF main pool VirtualAlloc failed: size=%zu, error=%lu",
                config_.initialSize, GetLastError());
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(config_.initialSize);
            }
            return false;
        }

        tlsfHandle_ = tlsf_create_with_pool(mainPool_, config_.initialSize);
        if (!tlsfHandle_) {
            Logger::GetInstance().LogError("TLSF main pool creation failed");
            VirtualFree(mainPool_, 0, MEM_RELEASE);
            mainPool_ = nullptr;
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(config_.initialSize);
            }
            return false;
        }

        const bool localRangeRegistered = addressDirectory_.RegisterRange(
            mainPool_, config_.initialSize, 0);
        const bool shardRangeRegistered =
            !shardDirectory_ || shardDirectory_->RegisterRange(
                                    mainPool_, config_.initialSize, shardIndex_);
        if (!localRangeRegistered || !shardRangeRegistered) {
            Logger::GetInstance().LogError(
                "TLSF address directory rejected main pool: shard=%zu, base=%p, size=%zu",
                shardIndex_, mainPool_, config_.initialSize);
            if (localRangeRegistered) {
                addressDirectory_.UnregisterRange(
                    mainPool_, config_.initialSize, 0);
            }
            if (shardDirectory_ && shardRangeRegistered) {
                shardDirectory_->UnregisterRange(
                    mainPool_, config_.initialSize, shardIndex_);
            }
            tlsfHandle_ = nullptr;
            VirtualFree(mainPool_, 0, MEM_RELEASE);
            mainPool_ = nullptr;
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(config_.initialSize);
            }
            return false;
        }

        ConfigureMainPoolDecommitRange();
        reservedBytes_.store(config_.initialSize, std::memory_order_relaxed);
        committedBytes_.store(config_.initialSize, std::memory_order_relaxed);
        peakReservedBytes_.store(config_.initialSize, std::memory_order_relaxed);
        peakCommittedBytes_.store(config_.initialSize, std::memory_order_relaxed);
        return true;
    }

    void Shutdown() override {
        if (!mainPool_ && !tlsfHandle_) {
            return;
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);

        for (const ExtraPool& pool : extraPools_) {
            addressDirectory_.UnregisterRange(pool.base, pool.size, 0);
            if (shardDirectory_) {
                shardDirectory_->UnregisterRange(
                    pool.base, pool.size, shardIndex_);
            }
            if (pool.handle && tlsfHandle_) {
                tlsf_remove_pool(tlsfHandle_, pool.handle);
            }
            if (pool.base) {
                VirtualFree(pool.base, 0, MEM_RELEASE);
            }
        }
        extraPools_.clear();

        if (mainPool_) {
            addressDirectory_.UnregisterRange(
                mainPool_, config_.initialSize, 0);
            if (shardDirectory_) {
                shardDirectory_->UnregisterRange(
                    mainPool_, config_.initialSize, shardIndex_);
            }
            VirtualFree(mainPool_, 0, MEM_RELEASE);
            mainPool_ = nullptr;
        }
        tlsfHandle_ = nullptr;
        const size_t releasedBytes = static_cast<size_t>(
            reservedBytes_.exchange(0, std::memory_order_relaxed));
        committedBytes_.store(0, std::memory_order_relaxed);
        if (sharedReservationBudget_) {
            sharedReservationBudget_->Release(releasedBytes);
        }
    }

    void* Allocate(size_t size, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        {
            std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
            LockIfEnabled(lock);
            if (!EnsureMainPoolCommittedLocked()) {
                return nullptr;
            }
            void* ptr = SafeTlsfMalloc(tlsfHandle_, size);
            if (ptr) {
                SetUsableSize(ptr, size, usableSize);
                return ptr;
            }
        }

        // Retain the dirty baseline's locked retry before growing the pool.
        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }

        void* ptr = SafeTlsfMalloc(tlsfHandle_, size);
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
            return ptr;
        }

        if (ReclaimEmptyExtraPoolsLocked() != 0) {
            trimCount_.fetch_add(1, std::memory_order_relaxed);
        }
        const size_t extendSize = CalculateExtendSize(size, tlsf_align_size());
        void* addedPoolBase = nullptr;
        if (extendSize != 0 && AddExtraPool(extendSize, &addedPoolBase)) {
            ptr = SafeTlsfMalloc(tlsfHandle_, size);
            if (!ptr && addedPoolBase) {
                RemoveEmptyExtraPoolLocked(addedPoolBase);
            }
        }
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
        }
        return ptr;
    }

    void* AllocateAligned(
        size_t size, size_t alignment, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        {
            std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
            LockIfEnabled(lock);
            if (!EnsureMainPoolCommittedLocked()) {
                return nullptr;
            }
            void* ptr = SafeTlsfMemalign(tlsfHandle_, alignment, size);
            if (ptr) {
                SetUsableSize(ptr, size, usableSize);
                return ptr;
            }
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }

        void* ptr = SafeTlsfMemalign(tlsfHandle_, alignment, size);
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
            return ptr;
        }

        if (ReclaimEmptyExtraPoolsLocked() != 0) {
            trimCount_.fetch_add(1, std::memory_order_relaxed);
        }
        const size_t extendSize = CalculateExtendSize(size, alignment);
        void* addedPoolBase = nullptr;
        if (extendSize != 0 && AddExtraPool(extendSize, &addedPoolBase)) {
            ptr = SafeTlsfMemalign(tlsfHandle_, alignment, size);
            if (!ptr && addedPoolBase) {
                RemoveEmptyExtraPoolLocked(addedPoolBase);
            }
        }
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
        }
        return ptr;
    }

    void* Reallocate(
        void* ptr, size_t newSize, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        {
            std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
            LockIfEnabled(lock);
            if (!EnsureMainPoolCommittedLocked()) {
                return nullptr;
            }
            if (ptr && !IsExactAllocatedBlockLocked(ptr)) {
                return nullptr;
            }
            void* newPtr = SafeTlsfRealloc(tlsfHandle_, ptr, newSize);
            if (newPtr) {
                SetUsableSize(newPtr, newSize, usableSize);
                return newPtr;
            }
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }

        if (ptr && !IsExactAllocatedBlockLocked(ptr)) {
            return nullptr;
        }

        void* newPtr = SafeTlsfRealloc(tlsfHandle_, ptr, newSize);
        if (newPtr) {
            SetUsableSize(newPtr, newSize, usableSize);
            return newPtr;
        }

        if (ReclaimEmptyExtraPoolsLocked() != 0) {
            trimCount_.fetch_add(1, std::memory_order_relaxed);
        }
        const size_t extendSize = CalculateExtendSize(newSize, tlsf_align_size());
        void* addedPoolBase = nullptr;
        if (extendSize != 0 && AddExtraPool(extendSize, &addedPoolBase)) {
            newPtr = SafeTlsfRealloc(tlsfHandle_, ptr, newSize);
            if (!newPtr && addedPoolBase) {
                RemoveEmptyExtraPoolLocked(addedPoolBase);
            }
        }
        if (newPtr) {
            SetUsableSize(newPtr, newSize, usableSize);
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
        if (!ptr || newSize == 0) {
            return nullptr;
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }
        if (!tlsfHandle_ || !IsExactAllocatedBlockLocked(ptr)) {
            return nullptr;
        }

        const size_t previousUsable = SafeTlsfBlockSize(ptr);
        if (previousUsable == 0) {
            return nullptr;
        }
        if (oldUsableSize) {
            *oldUsableSize = previousUsable;
        }

        void* result = SafeTlsfReallocInPlace(tlsfHandle_, ptr, newSize);
        if (result) {
            SetUsableSize(result, newSize, newUsableSize);
        }
        return result;
    }

    size_t Free(void* ptr) override {
        return FreeConditional(ptr, nullptr, nullptr);
    }

    size_t FreeConditional(
        void* ptr, MemoryPool::Internal::BackendFreeValidator validator,
        void* context) override {
        if (!ptr) {
            return 0;
        }
        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!tlsfHandle_ || !IsExactAllocatedBlockLocked(ptr)) {
            return 0;
        }
        void* extraPoolBase = nullptr;
        if (!IsPointerInRange(ptr, mainPool_, config_.initialSize)) {
            const ExtraPool* extraPool = FindExtraPoolLocked(ptr);
            extraPoolBase = extraPool ? extraPool->base : nullptr;
        }
        const size_t usableSize = SafeTlsfBlockSize(ptr);
        if (usableSize == 0 ||
            (validator && !validator(ptr, usableSize, context))) {
            return 0;
        }
        if (!SafeTlsfFree(tlsfHandle_, ptr)) {
            return 0;
        }
        if (extraPoolBase &&
            ShouldReleaseEmptyExtraPoolLocked(extraPoolBase) &&
            RemoveEmptyExtraPoolLocked(extraPoolBase)) {
            trimCount_.fetch_add(1, std::memory_order_relaxed);
        }
        return usableSize;
    }

    MemoryPool::BatchFreeResult FreeBatch(
        const MemoryPool::BatchFreeEntry* entries,
        size_t count) override {
        MemoryPool::BatchFreeResult result{};
        if ((!entries && count != 0) || !tlsfHandle_) {
            return result;
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        for (; result.freedCount < count; ++result.freedCount) {
            void* const ptr = entries[result.freedCount].pointer;
            if (!ptr || !IsExactAllocatedBlockLocked(ptr)) {
                break;
            }
            const size_t usable = SafeTlsfBlockSize(ptr);
            if (usable == 0 || !SafeTlsfFree(tlsfHandle_, ptr)) {
                break;
            }
            result.usableBytes += usable;
        }
        if (result.freedCount != 0 &&
            ReclaimEmptyExtraPoolsLocked(TlsfWarmEmptyPoolLimit()) != 0) {
            trimCount_.fetch_add(1, std::memory_order_relaxed);
        }
        return result;
    }

    bool IsFromBackend(void* ptr) const override {
        if (!ptr || !mainPool_) {
            return false;
        }

        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        return IsFromBackendLocked(ptr);
    }

    bool MayContainAddress(const void* ptr) const override {
        return mainPool_ &&
            addressDirectory_.Lookup(ptr) != kTlsfShardCount;
    }

    bool QueryAllocation(void* ptr, size_t* usableSize) const override {
        if (usableSize) {
            *usableSize = 0;
        }
        if (!ptr || !mainPool_) {
            return false;
        }

        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!IsExactAllocatedBlockLocked(ptr)) {
            return false;
        }
        const size_t measured = SafeTlsfBlockSize(ptr);
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
        if (!visitor || !tlsfHandle_) {
            return false;
        }

        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        return VisitAllocatedBlocksLocked(visitor, context);
    }

    bool Extend(size_t additionalSize) override {
        if (!tlsfHandle_ || additionalSize == 0) {
            return false;
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        const size_t current = static_cast<size_t>(
            reservedBytes_.load(std::memory_order_relaxed));
        if (current >= config_.maxSize ||
            additionalSize > config_.maxSize - current) {
            return false;
        }
        return AddExtraPool(additionalSize);
    }

    void Trim() override {
        if (!tlsfHandle_) {
            return;
        }

        std::unique_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);

        ReclaimEmptyExtraPoolsLocked();
        DecommitEmptyMainPoolLocked();
        trimCount_.fetch_add(1, std::memory_order_relaxed);
    }

    void Compact() override {
        // TLSF coalesces adjacent free blocks during Free; there is no movable compaction.
    }

    void SetThreadSafety(bool enabled) override {
        threadSafeEnabled_.store(enabled, std::memory_order_release);
    }

    MemoryPool::Internal::BackendStats GetStats() const override {
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
        const uint64_t reserved = reservedBytes_.load(std::memory_order_relaxed);
        const uint64_t committed = committedBytes_.load(std::memory_order_relaxed);
        peakReservedBytes_.store(reserved, std::memory_order_relaxed);
        peakCommittedBytes_.store(committed, std::memory_order_relaxed);
        growthCount_.store(0, std::memory_order_relaxed);
        trimCount_.store(0, std::memory_order_relaxed);
        lockWaitCount_.store(0, std::memory_order_relaxed);
        lockWaitNanoseconds_.store(0, std::memory_order_relaxed);
        maxLockWaitNanoseconds_.store(0, std::memory_order_relaxed);
        lockWaitLatency_.Reset();
    }

    void* GetNativeHandle() const override {
        return tlsfHandle_;
    }

    size_t GetPoolCount() const override {
        if (!mainPool_) {
            return 0;
        }

        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        return 1 + extraPools_.size();
    }

    void DumpPoolInfo() const override {
        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);

        Logger::GetInstance().LogInfo(
            "TLSF main pool: base=%p, size=%zu MB",
            mainPool_, config_.initialSize / (1024 * 1024));
        for (size_t i = 0; i < extraPools_.size(); ++i) {
            Logger::GetInstance().LogInfo(
                "TLSF extra pool #%zu: base=%p, size=%zu MB",
                i + 1, extraPools_[i].base,
                extraPools_[i].size / (1024 * 1024));
        }
    }

    bool Validate() const override {
        if (!tlsfHandle_) {
            return false;
        }

        std::shared_lock<std::shared_mutex> lock(poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        return ValidateLocked();
    }

private:
    friend class TlsfShardedBackend;

    bool ValidateLocked() const {
        if (tlsf_check(tlsfHandle_) != 0) {
            return false;
        }
        for (const ExtraPool& pool : extraPools_) {
            if (tlsf_check_pool(pool.handle) != 0) {
                return false;
            }
        }
        return true;
    }

    bool VisitAllocatedBlocksLocked(
        MemoryPool::Internal::BackendBlockVisitor visitor,
        void* context) const {
        TlsfVisitContext visit{visitor, context, true};
        tlsf_walk_pool(tlsf_get_pool(tlsfHandle_), TlsfBlockWalker, &visit);
        for (const ExtraPool& pool : extraPools_) {
            if (!visit.keepVisiting) {
                break;
            }
            tlsf_walk_pool(pool.handle, TlsfBlockWalker, &visit);
        }
        return visit.keepVisiting;
    }

    void* AllocateWithoutGrowth(size_t size, size_t* usableSize) {
        if (usableSize) {
            *usableSize = 0;
        }
        std::unique_lock<std::shared_mutex> lock(
            poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }
        void* ptr = SafeTlsfMalloc(tlsfHandle_, size);
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
        }
        return ptr;
    }

    void* AllocateAlignedWithoutGrowth(
        size_t size, size_t alignment, size_t* usableSize) {
        if (usableSize) {
            *usableSize = 0;
        }
        std::unique_lock<std::shared_mutex> lock(
            poolMutex_, std::defer_lock);
        LockIfEnabled(lock);
        if (!EnsureMainPoolCommittedLocked()) {
            return nullptr;
        }
        void* ptr = SafeTlsfMemalign(tlsfHandle_, alignment, size);
        if (ptr) {
            SetUsableSize(ptr, size, usableSize);
        }
        return ptr;
    }

    struct ExtraPool {
        void* base;
        size_t size;
        pool_t handle;
    };

    template <typename Lock>
    void LockIfEnabled(Lock& lock) const {
        if (!threadSafeEnabled_.load(std::memory_order_acquire)) {
            return;
        }

        if (lock.try_lock()) {
            return;
        }
        if (!MemoryPool::IsLatencyTrackingEnabled()) {
            lock.lock();
            return;
        }

        const Clock::time_point start = Clock::now();
        lock.lock();
        const uint64_t waitNanoseconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                Clock::now() - start).count());
        lockWaitCount_.fetch_add(1, std::memory_order_relaxed);
        lockWaitNanoseconds_.fetch_add(waitNanoseconds, std::memory_order_relaxed);
        UpdateMaximum(maxLockWaitNanoseconds_, waitNanoseconds);
        lockWaitLatency_.Record(waitNanoseconds);
    }

    static void SetUsableSize(
        void* ptr, size_t requestedSize, size_t* usableSize) {
        if (!usableSize) {
            return;
        }
        const size_t measured = SafeTlsfBlockSize(ptr);
        *usableSize = measured < requestedSize ? requestedSize : measured;
    }

    void ConfigureMainPoolDecommitRange() {
        mainPoolDecommitBase_ = nullptr;
        mainPoolDecommitSize_ = 0;
        mainPoolInteriorDecommitted_ = false;
        if (!TlsfMainPoolDecommitEnabled() || shardDirectory_ ||
            !mainPool_ || !tlsfHandle_) {
            return;
        }

        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        const uintptr_t pageSize = systemInfo.dwPageSize;
        if (pageSize == 0 || (pageSize & (pageSize - 1u)) != 0u) {
            return;
        }
        const uintptr_t mask = pageSize - 1u;
        const uintptr_t poolStart =
            reinterpret_cast<uintptr_t>(tlsf_get_pool(tlsfHandle_));
        const uintptr_t allocationEnd =
            reinterpret_cast<uintptr_t>(mainPool_) + config_.initialSize;
        if (poolStart >= allocationEnd || allocationEnd == 0) {
            return;
        }
        const uintptr_t interiorBegin =
            (poolStart + pageSize) & ~mask;
        const uintptr_t lastPage = (allocationEnd - 1u) & ~mask;
        if (interiorBegin >= lastPage) {
            return;
        }
        mainPoolDecommitBase_ = reinterpret_cast<void*>(interiorBegin);
        mainPoolDecommitSize_ = lastPage - interiorBegin;
    }

    bool EnsureMainPoolCommittedLocked() {
        if (!mainPoolInteriorDecommitted_) {
            return true;
        }
        void* committed = VirtualAlloc(
            mainPoolDecommitBase_, mainPoolDecommitSize_, MEM_COMMIT,
            PAGE_READWRITE);
        if (committed != mainPoolDecommitBase_) {
            Logger::GetInstance().LogError(
                "TLSF main-pool recommit failed: base=%p, size=%zu, error=%lu",
                mainPoolDecommitBase_, mainPoolDecommitSize_, GetLastError());
            return false;
        }
        mainPoolInteriorDecommitted_ = false;
        committedBytes_.fetch_add(
            mainPoolDecommitSize_, std::memory_order_relaxed);
        return true;
    }

    bool DecommitEmptyMainPoolLocked() {
        if (!mainPoolDecommitBase_ || mainPoolDecommitSize_ == 0 ||
            mainPoolInteriorDecommitted_) {
            return false;
        }
        if (!SafeTlsfPoolIsEmpty(tlsf_get_pool(tlsfHandle_)) ||
            !VirtualFree(mainPoolDecommitBase_, mainPoolDecommitSize_,
                         MEM_DECOMMIT)) {
            return false;
        }
        mainPoolInteriorDecommitted_ = true;
        committedBytes_.fetch_sub(
            mainPoolDecommitSize_, std::memory_order_relaxed);
        return true;
    }

    bool IsFromBackendLocked(void* ptr) const {
        if (IsPointerInRange(ptr, mainPool_, config_.initialSize)) {
            return true;
        }
        if (TlsfRangeIndexEnabled()) {
            return FindExtraPoolLocked(ptr) != nullptr;
        }
        for (const ExtraPool& pool : extraPools_) {
            if (IsPointerInRange(ptr, pool.base, pool.size)) {
                return true;
            }
        }
        return false;
    }

    bool IsExactAllocatedBlockLocked(void* ptr) const {
        if (TlsfRangeIndexEnabled()) {
            if (IsPointerInRange(ptr, mainPool_, config_.initialSize)) {
                return SafeTlsfExactBlock(
                    ptr, mainPool_, config_.initialSize);
            }
            const ExtraPool* pool = FindExtraPoolLocked(ptr);
            return pool && SafeTlsfExactBlock(ptr, pool->base, pool->size);
        }
        if (SafeTlsfExactBlock(ptr, mainPool_, config_.initialSize)) {
            return true;
        }
        for (const ExtraPool& pool : extraPools_) {
            if (SafeTlsfExactBlock(ptr, pool.base, pool.size)) {
                return true;
            }
        }
        return false;
    }

    const ExtraPool* FindExtraPoolLocked(void* ptr) const {
        if (!ptr || extraPools_.empty()) {
            return nullptr;
        }
        const uintptr_t address = reinterpret_cast<uintptr_t>(ptr);
        auto candidate = std::upper_bound(
            extraPools_.begin(), extraPools_.end(), address,
            [](uintptr_t value, const ExtraPool& pool) {
                return value < reinterpret_cast<uintptr_t>(pool.base);
            });
        if (candidate == extraPools_.begin()) {
            return nullptr;
        }
        --candidate;
        return IsPointerInRange(ptr, candidate->base, candidate->size)
            ? &*candidate
            : nullptr;
    }

    size_t CalculateExtendSize(size_t requestSize, size_t alignment) const {
        constexpr size_t kGrowthSlack = 64 * 1024;
        const size_t minimumPoolSize =
            tlsf_allocation_pool_size(requestSize, alignment);
        if (minimumPoolSize == 0 || minimumPoolSize > SIZE_MAX - kGrowthSlack) {
            return 0;
        }
        const size_t required = minimumPoolSize + kGrowthSlack;
        const size_t granularity =
            required > config_.extendGranularity
                ? kTlsfShardBudgetAlignment
                : config_.extendGranularity;
        if (granularity == 0 || required > SIZE_MAX - (granularity - 1)) {
            return 0;
        }

        size_t extendSize =
            ((required + granularity - 1) / granularity) * granularity;
        const size_t totalSize = static_cast<size_t>(
            reservedBytes_.load(std::memory_order_relaxed));
        if (totalSize >= config_.maxSize) {
            return 0;
        }

        size_t remaining = config_.maxSize - totalSize;
        if (sharedReservationBudget_) {
            remaining = (std::min)(
                remaining,
                sharedReservationBudget_->GetAvailableBytes());
        }
        if (extendSize > remaining) {
            if (remaining < required) {
                return 0;
            }
            extendSize = remaining;
        }
        return extendSize;
    }

    size_t ReclaimEmptyExtraPoolsLocked(size_t warmRegularPoolLimit = 0) {
        size_t reclaimedBytes = 0;
        size_t warmRegularPools = 0;
        for (auto it = extraPools_.begin(); it != extraPools_.end();) {
            if (!SafeTlsfPoolIsEmpty(it->handle)) {
                ++it;
                continue;
            }
            if (IsWarmPoolEligible(it->size) &&
                warmRegularPools < warmRegularPoolLimit) {
                ++warmRegularPools;
                ++it;
                continue;
            }
            if (shardDirectory_) {
                shardDirectory_->UnregisterRange(
                    it->base, it->size, shardIndex_);
            }
            addressDirectory_.UnregisterRange(it->base, it->size, 0);
            tlsf_remove_pool(tlsfHandle_, it->handle);
            VirtualFree(it->base, 0, MEM_RELEASE);
            reclaimedBytes += it->size;
            it = extraPools_.erase(it);
        }
        if (reclaimedBytes != 0) {
            reservedBytes_.fetch_sub(reclaimedBytes, std::memory_order_relaxed);
            committedBytes_.fetch_sub(reclaimedBytes, std::memory_order_relaxed);
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(reclaimedBytes);
            }
        }
        return reclaimedBytes;
    }

    bool ShouldReleaseEmptyExtraPoolLocked(void* poolBase) const {
        const auto found = std::find_if(
            extraPools_.begin(), extraPools_.end(),
            [poolBase](const ExtraPool& pool) {
                return pool.base == poolBase;
            });
        if (found == extraPools_.end() ||
            !SafeTlsfPoolIsEmpty(found->handle)) {
            return false;
        }
        if (!IsWarmPoolEligible(found->size)) {
            return true;
        }

        size_t emptyRegularPools = 0;
        for (const ExtraPool& pool : extraPools_) {
            if (IsWarmPoolEligible(pool.size) &&
                SafeTlsfPoolIsEmpty(pool.handle)) {
                ++emptyRegularPools;
            }
        }
        return emptyRegularPools > TlsfWarmEmptyPoolLimit();
    }

    bool IsWarmPoolEligible(size_t size) const noexcept {
        constexpr size_t kWarmGranularityMultiplier = 4;
        const size_t maximumWarmSize =
            config_.extendGranularity >
                    SIZE_MAX / kWarmGranularityMultiplier
                ? SIZE_MAX
                : config_.extendGranularity * kWarmGranularityMultiplier;
        return size <= maximumWarmSize;
    }

    void* AllocateExtraPoolRegion(size_t size) const noexcept {
        if (topDownEnabled_ && mainPool_ && size != 0) {
            uintptr_t lowAddress = reinterpret_cast<uintptr_t>(mainPool_);
            if (!extraPools_.empty()) {
                lowAddress = (std::min)(
                    lowAddress,
                    reinterpret_cast<uintptr_t>(extraPools_.front().base));
            }
            if (lowAddress > size) {
                const uintptr_t candidate =
                    (lowAddress - size) &
                    ~(static_cast<uintptr_t>(kTlsfShardBudgetAlignment) - 1u);
                if (candidate >= kTlsfShardBudgetAlignment) {
                    void* exact = EnforceStormCompatibleAddressRange(
                        VirtualAlloc(reinterpret_cast<void*>(candidate), size,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE),
                        size, "growth-clustered");
                    if (exact != nullptr) {
                        return exact;
                    }
                }
            }
        }
        return EnforceStormCompatibleAddressRange(
            VirtualAlloc(nullptr, size,
                TlsfReserveCommitFlags(topDownEnabled_), PAGE_READWRITE),
            size, "growth");
    }

    bool AddExtraPool(size_t size, void** addedPoolBase = nullptr) {
        GrowthLatencyScope growthLatency;
        if (addedPoolBase) {
            *addedPoolBase = nullptr;
        }
        if (sharedReservationBudget_ &&
            !sharedReservationBudget_->TryReserve(size)) {
            return false;
        }
        void* newPool = AllocateExtraPoolRegion(size);
        if (!newPool) {
            Logger::GetInstance().LogError(
                "TLSF growth VirtualAlloc failed: size=%zu, error=%lu",
                size, GetLastError());
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(size);
            }
            return false;
        }

        pool_t poolHandle = tlsf_add_pool(tlsfHandle_, newPool, size);
        if (!poolHandle) {
            Logger::GetInstance().LogError(
                "tlsf_add_pool failed: base=%p, size=%zu", newPool, size);
            VirtualFree(newPool, 0, MEM_RELEASE);
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(size);
            }
            return false;
        }

        if (!addressDirectory_.RegisterRange(newPool, size, 0)) {
            Logger::GetInstance().LogError(
                "TLSF address directory rejected growth pool: base=%p, size=%zu",
                newPool, size);
            tlsf_remove_pool(tlsfHandle_, poolHandle);
            VirtualFree(newPool, 0, MEM_RELEASE);
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(size);
            }
            return false;
        }

        if (shardDirectory_ &&
            !shardDirectory_->RegisterRange(newPool, size, shardIndex_)) {
            Logger::GetInstance().LogError(
                "TLSF shard directory rejected growth pool: shard=%zu, base=%p, size=%zu",
                shardIndex_, newPool, size);
            addressDirectory_.UnregisterRange(newPool, size, 0);
            tlsf_remove_pool(tlsfHandle_, poolHandle);
            VirtualFree(newPool, 0, MEM_RELEASE);
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(size);
            }
            return false;
        }

        try {
            const uintptr_t address = reinterpret_cast<uintptr_t>(newPool);
            const auto insertion = std::lower_bound(
                extraPools_.begin(), extraPools_.end(), address,
                [](const ExtraPool& pool, uintptr_t value) {
                    return reinterpret_cast<uintptr_t>(pool.base) < value;
                });
            extraPools_.insert(insertion, {newPool, size, poolHandle});
        }
        catch (...) {
            addressDirectory_.UnregisterRange(newPool, size, 0);
            if (shardDirectory_) {
                shardDirectory_->UnregisterRange(
                    newPool, size, shardIndex_);
            }
            tlsf_remove_pool(tlsfHandle_, poolHandle);
            VirtualFree(newPool, 0, MEM_RELEASE);
            if (sharedReservationBudget_) {
                sharedReservationBudget_->Release(size);
            }
            return false;
        }

        const uint64_t reserved =
            reservedBytes_.fetch_add(size, std::memory_order_relaxed) + size;
        const uint64_t committed =
            committedBytes_.fetch_add(size, std::memory_order_relaxed) + size;
        UpdateMaximum(peakReservedBytes_, reserved);
        UpdateMaximum(peakCommittedBytes_, committed);
        growthCount_.fetch_add(1, std::memory_order_relaxed);
        if (addedPoolBase) {
            *addedPoolBase = newPool;
        }

        // This function runs under the allocator's exclusive pool lock. Keep
        // normal growth off the release file-I/O path; counters and telemetry
        // still expose every expansion.
        Logger::GetInstance().LogDebug(
            "TLSF pool extended: base=%p, size=%zu MB",
            newPool, size / (1024 * 1024));
        return true;
    }

    bool RemoveEmptyExtraPoolLocked(void* poolBase) {
        const auto found = std::find_if(
            extraPools_.begin(), extraPools_.end(),
            [poolBase](const ExtraPool& pool) {
                return pool.base == poolBase;
            });
        if (found == extraPools_.end()) {
            return false;
        }

        if (!SafeTlsfPoolIsEmpty(found->handle)) {
            return false;
        }

        const size_t size = found->size;
        if (shardDirectory_) {
            shardDirectory_->UnregisterRange(
                found->base, found->size, shardIndex_);
        }
        addressDirectory_.UnregisterRange(found->base, found->size, 0);
        tlsf_remove_pool(tlsfHandle_, found->handle);
        VirtualFree(found->base, 0, MEM_RELEASE);
        extraPools_.erase(found);
        reservedBytes_.fetch_sub(size, std::memory_order_relaxed);
        committedBytes_.fetch_sub(size, std::memory_order_relaxed);
        if (sharedReservationBudget_) {
            sharedReservationBudget_->Release(size);
        }

        uint64_t growthCount = growthCount_.load(std::memory_order_relaxed);
        while (growthCount != 0 &&
            !growthCount_.compare_exchange_weak(
                growthCount, growthCount - 1, std::memory_order_relaxed)) {
        }
        return true;
    }

    MemoryPool::Config config_{};
    tlsf_t tlsfHandle_ = nullptr;
    void* mainPool_ = nullptr;
    void* mainPoolDecommitBase_ = nullptr;
    size_t mainPoolDecommitSize_ = 0;
    bool mainPoolInteriorDecommitted_ = false;
    bool topDownEnabled_ = false;
    std::vector<ExtraPool> extraPools_;
    mutable std::shared_mutex poolMutex_;
    std::atomic<bool> threadSafeEnabled_{true};

    std::atomic<uint64_t> reservedBytes_{0};
    std::atomic<uint64_t> committedBytes_{0};
    std::atomic<uint64_t> peakReservedBytes_{0};
    std::atomic<uint64_t> peakCommittedBytes_{0};
    std::atomic<uint64_t> growthCount_{0};
    std::atomic<uint64_t> trimCount_{0};
    mutable std::atomic<uint64_t> lockWaitCount_{0};
    mutable std::atomic<uint64_t> lockWaitNanoseconds_{0};
    mutable std::atomic<uint64_t> maxLockWaitNanoseconds_{0};
    mutable AtomicLatencyHistogram lockWaitLatency_;
    SharedTlsfReservationBudget* sharedReservationBudget_ = nullptr;
    TlsfShardDirectory* shardDirectory_ = nullptr;
    TlsfShardDirectory addressDirectory_{};
    size_t shardIndex_ = 0;
};

class TlsfShardedBackend final : public MemoryPool::Internal::MemoryBackend {
public:
    ~TlsfShardedBackend() override {
        Shutdown();
    }

    MemoryPool::BackendKind GetKind() const override {
        return MemoryPool::BackendKind::TlsfSharded;
    }

    const char* GetName() const override {
        return "tlsf-sharded";
    }

    bool Initialize(const MemoryPool::Config& config) override {
        if (initialized_) {
            return true;
        }

        const size_t minimumPoolSize = tlsf_size() +
            tlsf_pool_overhead() + tlsf_block_size_min();
        std::array<size_t, kTlsfShardCount> initialSizes{};
        std::array<size_t, kTlsfShardCount> maximumValidation{};
        std::array<size_t, kTlsfShardCount> growthSizes{};
        if (!SplitTlsfShardBudget(
                config.initialSize, minimumPoolSize, initialSizes) ||
            !SplitTlsfShardBudget(
                config.maxSize, minimumPoolSize, maximumValidation) ||
            !SplitTlsfShardBudget(
                config.extendGranularity,
                tlsf_pool_overhead() + tlsf_block_size_min(), growthSizes)) {
            Logger::GetInstance().LogError(
                "Invalid 4-shard TLSF budget: initial=%zu, max=%zu, growth=%zu; "
                "each total must be 64 KiB aligned and large enough for four pools",
                config.initialSize, config.maxSize, config.extendGranularity);
            return false;
        }

        config_ = config;
        shardDirectory_.Reset();
        sharedReservationBudget_.Configure(config.maxSize);
        try {
            for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
                MemoryPool::Config shardConfig = config;
                shardConfig.initialSize = initialSizes[shard];
                // A shard may borrow any currently-unused aggregate capacity.
                // The shared reservation CAS enforces the real total maximum.
                shardConfig.maxSize = config.maxSize;
                // Smaller shard-local growth avoids multiplying a small
                // fragmentation shortfall by the process-wide granularity.
                // CalculateExtendSize still rounds a large request high enough
                // to fit in one new pool.
                shardConfig.extendGranularity = (std::min)(
                    growthSizes[shard], kTlsfShardAutoGrowthMaximum);
                shardConfigs_[shard] = shardConfig;

                shards_[shard] = std::make_unique<TlsfBackend>(
                    &sharedReservationBudget_, &shardDirectory_, shard);
                shards_[shard]->SetThreadSafety(
                    threadSafeEnabled_.load(std::memory_order_acquire));
                if (!shards_[shard]->Initialize(shardConfig)) {
                    Logger::GetInstance().LogError(
                        "TLSF shard initialization failed: shard=%zu", shard);
                    Shutdown();
                    return false;
                }
            }
        }
        catch (const std::bad_alloc&) {
            Logger::GetInstance().LogError(
                "Failed to allocate 4-shard TLSF backend state");
            Shutdown();
            return false;
        }

        initialized_ = true;
        Logger::GetInstance().LogInfo(
            "Initialized 4-shard TLSF backend: total initial=%zu MB, "
            "max=%zu MB, aggregate growth=%zu MB",
            config.initialSize / (1024 * 1024),
            config.maxSize / (1024 * 1024),
            config.extendGranularity / (1024 * 1024));
        return true;
    }

    void Shutdown() override {
        for (auto& shard : shards_) {
            shard.reset();
        }
        const size_t leakedReservation =
            sharedReservationBudget_.GetReservedBytes();
        if (leakedReservation != 0) {
            Logger::GetInstance().LogError(
                "4-shard TLSF reservation accounting leaked %zu bytes during shutdown",
                leakedReservation);
        }
        sharedReservationBudget_.Configure(0);
        shardDirectory_.Reset();
        initialized_ = false;
        trimCount_.store(0, std::memory_order_relaxed);
    }

    void* Allocate(size_t size, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        if (!initialized_) {
            return nullptr;
        }

        const size_t preferred = PreferredTlsfShard();
        for (size_t offset = 0; offset < kTlsfShardCount; ++offset) {
            const size_t shard = ProbeIndex(preferred, offset);
            void* ptr = shards_[shard]->AllocateWithoutGrowth(
                size, usableSize);
            if (ptr) {
                RememberPreferredTlsfShard(shard);
                return ptr;
            }
        }
        for (size_t offset = 0; offset < kTlsfShardCount; ++offset) {
            const size_t shard = ProbeIndex(preferred, offset);
            void* ptr = shards_[shard]->Allocate(size, usableSize);
            if (ptr) {
                RememberPreferredTlsfShard(shard);
                return ptr;
            }
        }
        return nullptr;
    }

    void* AllocateAligned(
        size_t size, size_t alignment, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        if (!initialized_) {
            return nullptr;
        }

        const size_t preferred = PreferredTlsfShard();
        for (size_t offset = 0; offset < kTlsfShardCount; ++offset) {
            const size_t shard = ProbeIndex(preferred, offset);
            void* ptr = shards_[shard]->AllocateAlignedWithoutGrowth(
                size, alignment, usableSize);
            if (ptr) {
                RememberPreferredTlsfShard(shard);
                return ptr;
            }
        }
        for (size_t offset = 0; offset < kTlsfShardCount; ++offset) {
            const size_t shard = ProbeIndex(preferred, offset);
            void* ptr = shards_[shard]->AllocateAligned(
                size, alignment, usableSize);
            if (ptr) {
                RememberPreferredTlsfShard(shard);
                return ptr;
            }
        }
        return nullptr;
    }

    void* Reallocate(
        void* ptr, size_t newSize, size_t* usableSize) override {
        if (usableSize) {
            *usableSize = 0;
        }
        if (!ptr) {
            return Allocate(newSize, usableSize);
        }
        if (newSize == 0) {
            Free(ptr);
            return nullptr;
        }
        if (!initialized_) {
            return nullptr;
        }

        size_t oldUsableSize = 0;
        const size_t owner = FindExactShard(ptr, &oldUsableSize);
        if (owner == kTlsfShardCount || oldUsableSize == 0) {
            return nullptr;
        }

        void* result = shards_[owner]->Reallocate(
            ptr, newSize, usableSize);
        if (result) {
            return result;
        }

        // A full owner shard may still be surrounded by free capacity. Move
        // only after another shard has succeeded; failed moves leave ptr live.
        const size_t preferred = PreferredTlsfShard();
        for (size_t offset = 0; offset < kTlsfShardCount; ++offset) {
            const size_t target = ProbeIndex(preferred, offset);
            if (target == owner) {
                continue;
            }

            size_t targetUsableSize = 0;
            void* moved = shards_[target]->Allocate(
                newSize, &targetUsableSize);
            if (!moved) {
                continue;
            }
            std::memcpy(moved, ptr, (std::min)(oldUsableSize, newSize));
            if (shards_[owner]->Free(ptr) == 0) {
                shards_[target]->Free(moved);
                return nullptr;
            }
            if (usableSize) {
                *usableSize = targetUsableSize;
            }
            return moved;
        }
        return nullptr;
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
        if (!initialized_ || !ptr || newSize == 0) {
            return nullptr;
        }

        const size_t owner = FindAddressShard(ptr, true);
        return owner == kTlsfShardCount
            ? nullptr
            : shards_[owner]->ReallocateInPlace(
                ptr, newSize, oldUsableSize, newUsableSize);
    }

    size_t Free(void* ptr) override {
        return FreeConditional(ptr, nullptr, nullptr);
    }

    size_t FreeConditional(
        void* ptr, MemoryPool::Internal::BackendFreeValidator validator,
        void* context) override {
        if (!initialized_ || !ptr) {
            return 0;
        }
        const size_t shard = shardDirectory_.Lookup(ptr);
        return shard == kTlsfShardCount
            ? 0
            : shards_[shard]->FreeConditional(ptr, validator, context);
    }

    bool IsFromBackend(void* ptr) const override {
        return initialized_ &&
            FindAddressShard(ptr, false) != kTlsfShardCount;
    }

    bool MayContainAddress(const void* ptr) const override {
        return initialized_ &&
            shardDirectory_.Lookup(ptr) != kTlsfShardCount;
    }

    bool QueryAllocation(void* ptr, size_t* usableSize) const override {
        if (usableSize) {
            *usableSize = 0;
        }
        return initialized_ &&
            FindExactShard(ptr, usableSize) != kTlsfShardCount;
    }

    size_t GetBlockSize(void* ptr) const override {
        size_t usableSize = 0;
        return QueryAllocation(ptr, &usableSize) ? usableSize : 0;
    }

    bool VisitAllocatedBlocks(
        MemoryPool::Internal::BackendBlockVisitor visitor,
        void* context) const override {
        if (!initialized_ || !visitor) {
            return false;
        }

        std::array<std::shared_lock<std::shared_mutex>, kTlsfShardCount> locks{
            std::shared_lock<std::shared_mutex>(
                shards_[0]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[1]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[2]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[3]->poolMutex_, std::defer_lock),
        };
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            shards_[shard]->LockIfEnabled(locks[shard]);
        }
        for (const auto& shard : shards_) {
            if (!shard->VisitAllocatedBlocksLocked(visitor, context)) {
                return false;
            }
        }
        return true;
    }

    bool Extend(size_t additionalSize) override {
        if (!initialized_ || additionalSize == 0 ||
            additionalSize % kTlsfShardBudgetAlignment != 0) {
            return false;
        }

        std::array<std::unique_lock<std::shared_mutex>, kTlsfShardCount> locks{
            std::unique_lock<std::shared_mutex>(
                shards_[0]->poolMutex_, std::defer_lock),
            std::unique_lock<std::shared_mutex>(
                shards_[1]->poolMutex_, std::defer_lock),
            std::unique_lock<std::shared_mutex>(
                shards_[2]->poolMutex_, std::defer_lock),
            std::unique_lock<std::shared_mutex>(
                shards_[3]->poolMutex_, std::defer_lock),
        };
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            shards_[shard]->LockIfEnabled(locks[shard]);
        }
        if (additionalSize >
            sharedReservationBudget_.GetAvailableBytes()) {
            return false;
        }

        std::array<size_t, kTlsfShardCount> extension{};
        std::array<size_t, kTlsfShardCount> capacityUnits{};
        size_t aggregateCapacity = 0;
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            const size_t reserved = static_cast<size_t>(
                shards_[shard]->reservedBytes_.load(
                    std::memory_order_relaxed));
            if (reserved > shardConfigs_[shard].maxSize) {
                return false;
            }
            const size_t capacity = shardConfigs_[shard].maxSize -
                reserved;
            capacityUnits[shard] = capacity / kTlsfShardBudgetAlignment;
            aggregateCapacity += capacityUnits[shard];
        }

        size_t remainingUnits =
            additionalSize / kTlsfShardBudgetAlignment;
        if (remainingUnits > aggregateCapacity) {
            return false;
        }
        while (remainingUnits != 0) {
            bool assigned = false;
            for (size_t shard = 0;
                 shard < kTlsfShardCount && remainingUnits != 0; ++shard) {
                const size_t assignedUnits =
                    extension[shard] / kTlsfShardBudgetAlignment;
                if (assignedUnits >= capacityUnits[shard]) {
                    continue;
                }
                extension[shard] += kTlsfShardBudgetAlignment;
                --remainingUnits;
                assigned = true;
            }
            if (!assigned) {
                return false;
            }
        }

        std::array<void*, kTlsfShardCount> addedPools{};
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            if (extension[shard] == 0) {
                continue;
            }
            bool forceFailure = false;
#if defined(STORMBREAKER_TESTING)
            forceFailure = g_tlsfShardExtendFailure.load(
                std::memory_order_relaxed) == static_cast<int32_t>(shard);
#endif
            if (forceFailure ||
                !shards_[shard]->AddExtraPool(
                    extension[shard], &addedPools[shard])) {
                bool rollbackSucceeded = true;
                for (size_t rollback = 0;
                     rollback < kTlsfShardCount; ++rollback) {
                    if (addedPools[rollback] &&
                        !shards_[rollback]->RemoveEmptyExtraPoolLocked(
                            addedPools[rollback])) {
                        rollbackSucceeded = false;
                    }
                }
                if (!rollbackSucceeded) {
                    Logger::GetInstance().LogError(
                        "4-shard TLSF exact Extend rollback failed");
                }
                return false;
            }
        }
        return true;
    }

    void Trim() override {
        if (!initialized_) {
            return;
        }
        for (auto& shard : shards_) {
            shard->Trim();
        }
        trimCount_.fetch_add(1, std::memory_order_relaxed);
    }

    void Compact() override {
        for (auto& shard : shards_) {
            if (shard) {
                shard->Compact();
            }
        }
    }

    void SetThreadSafety(bool enabled) override {
        threadSafeEnabled_.store(enabled, std::memory_order_release);
        for (auto& shard : shards_) {
            if (shard) {
                shard->SetThreadSafety(enabled);
            }
        }
    }

    MemoryPool::Internal::BackendStats GetStats() const override {
        MemoryPool::Internal::BackendStats aggregate{};
        aggregate.reservedBytes =
            sharedReservationBudget_.GetReservedBytes();
        aggregate.committedBytes = aggregate.reservedBytes;
        aggregate.peakReservedBytes =
            sharedReservationBudget_.GetPeakReservedBytes();
        aggregate.peakCommittedBytes = aggregate.peakReservedBytes;
        for (const auto& shard : shards_) {
            if (!shard) {
                continue;
            }
            const auto stats = shard->GetStats();
            aggregate.growthCount += stats.growthCount;
            aggregate.trimCount += stats.trimCount;
            aggregate.lockWaitCount += stats.lockWaitCount;
            aggregate.lockWaitNanoseconds += stats.lockWaitNanoseconds;
            aggregate.maxLockWaitNanoseconds = (std::max)(
                aggregate.maxLockWaitNanoseconds,
                stats.maxLockWaitNanoseconds);
            MergeHistogram(
                aggregate.lockWaitLatency, stats.lockWaitLatency);
        }
        aggregate.trimCount += trimCount_.load(std::memory_order_relaxed);
        return aggregate;
    }

    void ResetStats() override {
        for (auto& shard : shards_) {
            if (shard) {
                shard->ResetStats();
            }
        }
        sharedReservationBudget_.ResetPeak();
        trimCount_.store(0, std::memory_order_relaxed);
    }

    void* GetNativeHandle() const override {
        // Four independent controls have no safe singular tlsf_t identity.
        return nullptr;
    }

    size_t GetPoolCount() const override {
        size_t count = 0;
        for (const auto& shard : shards_) {
            if (shard) {
                count += shard->GetPoolCount();
            }
        }
        return count;
    }

    void DumpPoolInfo() const override {
        Logger::GetInstance().LogInfo(
            "4-shard TLSF pool state: pools=%zu", GetPoolCount());
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            if (!shards_[shard]) {
                continue;
            }
            Logger::GetInstance().LogInfo("TLSF shard #%zu", shard);
            shards_[shard]->DumpPoolInfo();
        }
    }

    bool Validate() const override {
        if (!initialized_) {
            return false;
        }

        std::array<std::shared_lock<std::shared_mutex>, kTlsfShardCount> locks{
            std::shared_lock<std::shared_mutex>(
                shards_[0]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[1]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[2]->poolMutex_, std::defer_lock),
            std::shared_lock<std::shared_mutex>(
                shards_[3]->poolMutex_, std::defer_lock),
        };
        for (size_t shard = 0; shard < kTlsfShardCount; ++shard) {
            shards_[shard]->LockIfEnabled(locks[shard]);
        }
        size_t childReservedBytes = 0;
        for (size_t shardIndex = 0;
             shardIndex < kTlsfShardCount; ++shardIndex) {
            const auto& shard = shards_[shardIndex];
            if (!shard || !shard->ValidateLocked()) {
                return false;
            }
            if (shardDirectory_.Lookup(shard->mainPool_) != shardIndex ||
                shardDirectory_.Lookup(
                    static_cast<const uint8_t*>(shard->mainPool_) +
                    shard->config_.initialSize - 1u) != shardIndex) {
                return false;
            }
            for (const auto& pool : shard->extraPools_) {
                if (shardDirectory_.Lookup(pool.base) != shardIndex ||
                    shardDirectory_.Lookup(
                        static_cast<const uint8_t*>(pool.base) +
                        pool.size - 1u) != shardIndex) {
                    return false;
                }
            }
            childReservedBytes += static_cast<size_t>(
                shard->reservedBytes_.load(std::memory_order_relaxed));
        }
        return childReservedBytes ==
                sharedReservationBudget_.GetReservedBytes() &&
            childReservedBytes <= config_.maxSize &&
            shardDirectory_.CountRegisteredSlots() ==
                childReservedBytes / kTlsfShardBudgetAlignment;
    }

private:
    static size_t ProbeIndex(size_t preferred, size_t offset) noexcept {
        return (preferred + offset) % kTlsfShardCount;
    }

    size_t FindAddressShard(void* ptr, bool exact) const {
        if (!ptr) {
            return kTlsfShardCount;
        }
        const size_t shard = shardDirectory_.Lookup(ptr);
        if (shard == kTlsfShardCount) {
            return kTlsfShardCount;
        }
        return !exact || shards_[shard]->QueryAllocation(ptr, nullptr)
            ? shard
            : kTlsfShardCount;
    }

    size_t FindExactShard(void* ptr, size_t* usableSize) const {
        if (usableSize) {
            *usableSize = 0;
        }
        if (!ptr) {
            return kTlsfShardCount;
        }
        const size_t shard = shardDirectory_.Lookup(ptr);
        if (shard == kTlsfShardCount) {
            return kTlsfShardCount;
        }
        size_t measured = 0;
        if (!shards_[shard]->QueryAllocation(ptr, &measured)) {
            return kTlsfShardCount;
        }
        if (usableSize) {
            *usableSize = measured;
        }
        return shard;
    }

    static void MergeHistogram(
        MemoryPool::LatencyHistogramStats& destination,
        const MemoryPool::LatencyHistogramStats& source) {
        for (size_t bucket = 0;
             bucket < MemoryPool::kLatencyHistogramBucketCount; ++bucket) {
            destination.upperBoundsNanoseconds[bucket] =
                source.upperBoundsNanoseconds[bucket];
        }
        for (size_t bucket = 0;
             bucket < MemoryPool::kLatencyHistogramBucketCount + 1; ++bucket) {
            destination.bucketCounts[bucket] += source.bucketCounts[bucket];
        }
        destination.sampleCount += source.sampleCount;
        destination.totalNanoseconds += source.totalNanoseconds;
        destination.maxNanoseconds = (std::max)(
            destination.maxNanoseconds, source.maxNanoseconds);
    }

    MemoryPool::Config config_{};
    std::array<MemoryPool::Config, kTlsfShardCount> shardConfigs_{};
    TlsfShardDirectory shardDirectory_{};
    SharedTlsfReservationBudget sharedReservationBudget_{};
    std::array<std::unique_ptr<TlsfBackend>, kTlsfShardCount> shards_{};
    std::atomic<bool> threadSafeEnabled_{true};
    std::atomic<uint64_t> trimCount_{0};
    bool initialized_ = false;
};

} // namespace

namespace MemoryPool {
namespace Internal {

std::unique_ptr<MemoryBackend> CreateTlsfBackend() {
    return std::make_unique<TlsfBackend>();
}

std::unique_ptr<MemoryBackend> CreateTlsfShardedBackend() {
    return std::make_unique<TlsfShardedBackend>();
}

#if defined(STORMBREAKER_TESTING)
void SetTlsfRangeIndexEnabledForTesting(bool enabled) {
    g_tlsfRangeIndexEnabled.store(enabled, std::memory_order_relaxed);
}

void SetTlsfMainPoolDecommitEnabledForTesting(bool enabled) {
    g_tlsfMainPoolDecommitEnabled.store(enabled, std::memory_order_relaxed);
}

void SetTlsfTopDownEnabledForTesting(bool enabled) {
    g_tlsfTopDownEnabled.store(enabled, std::memory_order_relaxed);
}

void SetTlsfConstantTimeEmptyCheckEnabledForTesting(bool enabled) {
    g_tlsfConstantTimeEmptyCheckEnabled.store(
        enabled, std::memory_order_relaxed);
}

void SetTlsfWarmEmptyPoolLimitForTesting(size_t limit) {
    g_tlsfWarmEmptyPoolLimit.store((std::min)(limit, size_t{8}),
                                   std::memory_order_relaxed);
}

void SetTlsfShardAffinityForTesting(size_t shardIndex) {
    g_tlsfShardAffinityOverride = shardIndex < kTlsfShardCount
        ? static_cast<int32_t>(shardIndex)
        : -1;
}

void SetTlsfShardExtendFailureForTesting(size_t shardIndex) {
    g_tlsfShardExtendFailure.store(
        shardIndex < kTlsfShardCount
            ? static_cast<int32_t>(shardIndex)
            : -1,
        std::memory_order_relaxed);
}
#endif

} // namespace Internal
} // namespace MemoryPool
