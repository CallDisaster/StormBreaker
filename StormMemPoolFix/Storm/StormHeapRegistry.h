#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#if !defined(_WIN32) || defined(_WIN64)
#error StormHeapRegistry supports Win32/x86 only.
#endif

namespace StormHeapRegistry {

constexpr uint32_t kHeapRegistryCapacity = 16u * 1024u;
constexpr uint32_t kHeapRegistryNameCapacity = 64u;
constexpr uint32_t kExplicitHeapIdBit = 0x80000000u;
constexpr uint32_t kInvalidHeapId = 0xFFFFFFFFu;
constexpr uint32_t kInvalidSlotHint = 0xFFFFFFFFu;

struct SlotHint {
  uint32_t slot = kInvalidSlotHint;
  uint32_t registryEpoch = 0;

  void Reset() noexcept {
    slot = kInvalidSlotHint;
    registryEpoch = 0;
  }
};

static_assert(sizeof(SlotHint) == 8, "SlotHint layout changed");

static_assert((kHeapRegistryCapacity & (kHeapRegistryCapacity - 1u)) == 0u,
              "Heap registry capacity must be a power of two");
static_assert(sizeof(void*) == 4 && sizeof(size_t) == 4,
              "StormHeapRegistry requires the Warcraft III Win32 ABI");
static_assert(std::atomic<uint32_t>::is_always_lock_free,
              "32-bit registry atomics must be lock-free");
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "64-bit registry counters must be lock-free on Win32/x86");

constexpr bool IsMainHeapId(uint32_t heapId) noexcept {
  return (heapId & kExplicitHeapIdBit) == 0u;
}

constexpr bool IsSyntheticExplicitHeapId(uint32_t heapId) noexcept {
  return (heapId & kExplicitHeapIdBit) != 0u && heapId != kInvalidHeapId;
}

enum class HeapState : uint32_t {
  Empty = 0,
  Active = 1,
  Destroying = 2,
  Tombstone = 3,
  Native = 4,
  // Transient publication state. Callers never acquire an Initializing entry.
  Initializing = 5,
};

enum class HeapKind : uint32_t {
  Main = 0,
  Explicit = 1,
};

enum class AccessResult : uint32_t {
  Managed = 0,
  Native = 1,
  NotFound = 2,
  Destroying = 3,
  Tombstone = 4,
  CapacityExhausted = 5,
  NotInitialized = 6,
  InvalidArgument = 7,
};

enum class CreateResult : uint32_t {
  CreatedManaged = 0,
  CreatedNative = 1,
  AlreadyManaged = 2,
  AlreadyNative = 3,
  Destroying = 4,
  Tombstone = 5,
  CapacityExhausted = 6,
  IdConflict = 7,
  NotInitialized = 8,
  InvalidArgument = 9,
};

enum class DestroyResult : uint32_t {
  BegunManaged = 0,
  BegunNative = 1,
  Finished = 2,
  Cancelled = 3,
  NotFound = 4,
  AlreadyDestroying = 5,
  Tombstone = 6,
  LiveAllocationsRemain = 7,
  StaleToken = 8,
  NotInitialized = 9,
  InvalidArgument = 10,
};

enum class FinishMode : uint32_t {
  RequireEmpty = 0,
  DiscardLiveStatistics = 1,
};

constexpr uint32_t HeapStateMask(HeapState state) noexcept {
  const uint32_t value = static_cast<uint32_t>(state);
  return value < 32u ? 1u << value : 0u;
}

constexpr uint32_t kDefaultSnapshotStateMask =
    HeapStateMask(HeapState::Active) |
    HeapStateMask(HeapState::Destroying) |
    HeapStateMask(HeapState::Native);

enum HeapSnapshotFlags : uint32_t {
  HeapSnapshotFlagNone = 0,
  HeapSnapshotFlagNameTruncated = 1u << 0,
};

// Stable, caller-owned representation used by the future ordinal 482 adapter.
// Counters are race-free but intentionally weakly consistent: a snapshot can
// observe concurrent allocation counters at adjacent instants.
struct alignas(8) HeapSnapshot {
  uint32_t heapId;
  HeapState state;
  HeapKind kind;
  uint32_t sourceLine;
  uint32_t generation;
  uint32_t operationReferences;
  uint64_t liveRequestedBytes;
  uint64_t liveUsableBytes;
  uint64_t peakRequestedBytes;
  uint64_t peakUsableBytes;
  uint64_t allocationCount;
  uint64_t freeCount;
  uint64_t reallocationCount;
  char name[kHeapRegistryNameCapacity];
  uint32_t flags;
};

struct SnapshotCopyResult {
  uint32_t written;
  uint32_t available;
  uint32_t truncated;
  uint32_t invalidArgument;
};

struct alignas(8) RegistryStats {
  uint32_t capacity;
  uint32_t occupiedSlots;
  uint32_t activeHeaps;
  uint32_t destroyingHeaps;
  uint32_t tombstoneHeaps;
  uint32_t nativeHeaps;
  uint32_t initializingHeaps;
  uint32_t reserved;
  uint64_t insertionCollisionProbes;
  uint64_t capacityFailures;
  uint64_t degradedEvents;
  uint64_t syntheticIdsIssued;
};

struct DestroyToken {
  uint32_t heapId;
  uint32_t slot;
  uint32_t generation;
  HeapState previousState;
  uint32_t valid;
};

static_assert(sizeof(HeapState) == 4 && sizeof(HeapKind) == 4,
              "Registry enums are part of the Win32 adapter ABI");
static_assert(offsetof(HeapSnapshot, liveRequestedBytes) == 24,
              "HeapSnapshot counter ABI changed");
static_assert(offsetof(HeapSnapshot, name) == 80,
              "HeapSnapshot name ABI changed");
static_assert(sizeof(HeapSnapshot) == 152,
              "HeapSnapshot must retain its Win32 ABI");
static_assert(sizeof(SnapshotCopyResult) == 16,
              "SnapshotCopyResult ABI changed");
static_assert(sizeof(RegistryStats) == 64, "RegistryStats ABI changed");
static_assert(sizeof(DestroyToken) == 20, "DestroyToken ABI changed");

// Thread-safety contract:
// - Initialize/Shutdown require external lifecycle serialization and must not
//   overlap any registry call.
// - After Initialize, lookup, creation, accounting, destruction of different
//   heaps, and snapshots may run concurrently.
// - An OperationGuard pins one heap generation. BeginDestroy first prevents
//   new guards and then waits until all previously acquired guards drain.
// - A DestroyToken has one owner; its walk callbacks must finish before
//   FinishDestroy or CancelDestroy is called.
// - Published identity metadata is immutable. Tombstones are never reused for
//   another ID; the same ID may reactivate as a new generation.
class Registry final {
public:
  class OperationGuard final {
  public:
    OperationGuard() noexcept = default;
    ~OperationGuard() noexcept;

    OperationGuard(OperationGuard&& other) noexcept;
    OperationGuard& operator=(OperationGuard&& other) noexcept;

    OperationGuard(const OperationGuard&) = delete;
    OperationGuard& operator=(const OperationGuard&) = delete;

    explicit operator bool() const noexcept { return owner_ != nullptr; }
    bool IsManaged() const noexcept {
      return acquiredState_ == HeapState::Active;
    }
    bool IsNative() const noexcept {
      return acquiredState_ == HeapState::Native;
    }

    uint32_t GetHeapId() const noexcept { return heapId_; }
    uint32_t GetGeneration() const noexcept { return generation_; }
    HeapKind GetKind() const noexcept { return kind_; }

    void RecordAllocation(uint64_t requestedBytes,
                          uint64_t usableBytes) noexcept;
    void RecordFree(uint64_t requestedBytes, uint64_t usableBytes) noexcept;
    void RecordReallocation(uint64_t oldRequestedBytes,
                            uint64_t oldUsableBytes,
                            uint64_t newRequestedBytes,
                            uint64_t newUsableBytes) noexcept;
    void Reset() noexcept;

  private:
    friend class Registry;
    Registry* owner_ = nullptr;
    uint32_t slot_ = 0;
    uint32_t heapId_ = kInvalidHeapId;
    uint32_t generation_ = 0;
    HeapKind kind_ = HeapKind::Main;
    HeapState acquiredState_ = HeapState::Empty;
    bool referenceHeld_ = false;
#if defined(STORMBREAKER_TESTING)
    std::atomic<uintptr_t>* hazardSlot_ = nullptr;
#endif
  };

  Registry() noexcept = default;
  ~Registry() noexcept;

  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  // Initialize and Shutdown allocate/free the fixed table. Shutdown also
  // rejects a caller-visible lifecycle error if an OperationGuard is live.
  bool Initialize() noexcept;
  bool Shutdown() noexcept;
  bool IsInitialized() const noexcept;

  AccessResult Acquire(uint32_t heapId, OperationGuard* outGuard,
                       bool pinGeneration = true) noexcept;

  // Main IDs must have bit 31 clear. A matching tombstone is reactivated as a
  // new generation. No allocation occurs after Initialize.
  AccessResult AcquireOrCreateMain(uint32_t heapId, const char* name,
                                   uint32_t sourceLine,
                                   OperationGuard* outGuard,
                                   bool* outCreated = nullptr,
                                   SlotHint* inOutSlotHint = nullptr,
                                   bool pinGeneration = true) noexcept;

  // Explicit managed IDs are generated in the high-bit namespace.
  CreateResult CreateExplicitManaged(const char* name, uint32_t sourceLine,
                                     uint32_t* outHeapId) noexcept;

  // Publishes an exact nonzero ID as managed. This is intended for an ID that
  // ordinal 486 reserved globally before its empty native shell was destroyed.
  // Native entries retain the ID returned by Storm; both registration methods
  // have identical collision, tombstone-reactivation, and capacity semantics.
  CreateResult RegisterManaged(uint32_t heapId, HeapKind kind,
                               const char* name,
                               uint32_t sourceLine) noexcept;
  CreateResult RegisterNative(uint32_t heapId, HeapKind kind,
                              const char* name,
                              uint32_t sourceLine) noexcept;

  // A zero-request persistent native block keeps the Storm explicit-heap
  // shell alive for Protect Memory and one-shot compatibility fallback.
  bool SetNativeSentinel(uint32_t heapId, void* pointer) noexcept;
  void* TakeNativeSentinel(uint32_t heapId) noexcept;
  bool RestoreNativeSentinel(const DestroyToken& token,
                             void* pointer) noexcept;

  // BeginDestroy changes the state first, then waits for all guards that
  // acquired the previous generation. The caller must not hold such a guard.
  // While Destroying, backend-walk callbacks can use RecordDestroyFree.
  DestroyResult BeginDestroy(uint32_t heapId,
                             DestroyToken* outToken) noexcept;
  bool RecordDestroyFree(const DestroyToken& token, uint64_t requestedBytes,
                         uint64_t usableBytes) noexcept;
  DestroyResult FinishDestroy(DestroyToken* token,
                              FinishMode mode = FinishMode::RequireEmpty) noexcept;

  // Cancel does not roll back RecordDestroyFree calls. It republishes the heap
  // with only its persistent survivors and their remaining live statistics.
  DestroyResult CancelDestroy(DestroyToken* token) noexcept;

  SnapshotCopyResult CopySnapshots(
      HeapSnapshot* output, uint32_t outputCapacity,
      uint32_t stateMask = kDefaultSnapshotStateMask) const noexcept;
  RegistryStats GetStats() const noexcept;

  // Integration layers call this for intentional native fallback or other
  // compatibility degradation. Registry-detected counter underflow also calls
  // it automatically.
  void MarkDegraded(uint64_t count = 1) noexcept;

private:
  struct Entry;

  enum class InsertResult : uint32_t {
    Created,
    ExistingActive,
    ExistingNative,
    ExistingDestroying,
    ExistingTombstone,
    CapacityExhausted,
    KindConflict,
  };

  static uint32_t HashHeapId(uint32_t heapId) noexcept;
  static void PauseForTransition(uint32_t iteration) noexcept;

  Entry* Entries() noexcept;
  const Entry* Entries() const noexcept;
  void RecordMembership(uint32_t heapId) noexcept;
  bool MembershipMayContain(uint32_t heapId) const noexcept;
  bool CanFastRejectMissing(uint32_t heapId) const noexcept;
  bool FindSlot(uint32_t heapId, uint32_t* outSlot) const noexcept;
  InsertResult InsertOrReactivate(uint32_t heapId, HeapKind kind,
                                  HeapState desiredState, const char* name,
                                  uint32_t sourceLine, bool allowReactivate,
                                  uint32_t* outSlot,
                                  bool* outCreated) noexcept;
  AccessResult AcquireSlot(uint32_t slot, uint32_t heapId,
                           OperationGuard* outGuard,
                           bool pinGeneration) noexcept;
  bool ValidateDestroyToken(const DestroyToken& token,
                            Entry** outEntry) noexcept;
  void ReleaseOperation(uint32_t slot) noexcept;
  void RecordAllocation(uint32_t slot, uint64_t requestedBytes,
                        uint64_t usableBytes) noexcept;
  void RecordFree(uint32_t slot, uint64_t requestedBytes,
                  uint64_t usableBytes) noexcept;
  void RecordReallocation(uint32_t slot, uint64_t oldRequestedBytes,
                          uint64_t oldUsableBytes,
                          uint64_t newRequestedBytes,
                          uint64_t newUsableBytes) noexcept;

  Entry* entries_ = nullptr;
  std::atomic<uint32_t>* membershipFilter_ = nullptr;
  std::atomic<uint32_t> lifecycle_{0};
  std::atomic<uint32_t> registryEpoch_{0};
  std::atomic<uint32_t> nextSyntheticSequence_{1};
  std::atomic<uint32_t> occupiedSlots_{0};
  alignas(8) std::atomic<uint64_t> insertionCollisionProbes_{0};
  alignas(8) std::atomic<uint64_t> capacityFailures_{0};
  alignas(8) std::atomic<uint64_t> degradedEvents_{0};
  alignas(8) std::atomic<uint64_t> syntheticIdsIssued_{0};
};

#if defined(STORMBREAKER_TESTING)
namespace Testing {
void SetMembershipFilterEnabled(bool enabled) noexcept;
void SetPredictedMainSlotEnabled(bool enabled) noexcept;
void SetHazardPinningEnabled(bool enabled) noexcept;
} // namespace Testing
#endif

} // namespace StormHeapRegistry
