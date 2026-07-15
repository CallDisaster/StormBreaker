#include "pch.h"
#include "StormHeapRegistry.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <cstring>
#include <new>

namespace StormHeapRegistry {
namespace {

constexpr uint32_t kLifecycleUninitialized = 0;
constexpr uint32_t kLifecycleInitializing = 1;
constexpr uint32_t kLifecycleReady = 2;
constexpr uint32_t kLifecycleShuttingDown = 3;
constexpr uint32_t kNameTruncated = 1u;
constexpr uint32_t kMembershipFilterWordCount = 8u * 1024u;
constexpr uint32_t kMembershipFilterBitMask =
    kMembershipFilterWordCount * 32u - 1u;

static_assert((kMembershipFilterWordCount &
               (kMembershipFilterWordCount - 1u)) == 0u,
              "Registry membership filter must use a power-of-two size");

#if defined(STORMBREAKER_TESTING)
std::atomic<bool> g_membershipFilterEnabled{true};
std::atomic<bool> g_predictedMainSlotEnabled{false};
std::atomic<bool> g_hazardPinningEnabled{false};
std::atomic<bool> g_hazardPinningEverUsed{false};

constexpr uint32_t kHazardThreadCapacity = 256u;
constexpr uint32_t kHazardSlotsPerThread = 8u;

struct alignas(64) HazardThreadSlots {
  std::atomic<uintptr_t> entries[kHazardSlotsPerThread]{};
};
static_assert(sizeof(HazardThreadSlots) == 64u);

HazardThreadSlots g_hazardThreads[kHazardThreadCapacity]{};
std::atomic<uint32_t> g_nextHazardThread{0};
thread_local HazardThreadSlots* tls_hazardThread = nullptr;
thread_local bool tls_hazardRegistrationAttempted = false;
#endif

bool MembershipFilterEnabled() noexcept {
#if defined(STORMBREAKER_TESTING)
  return g_membershipFilterEnabled.load(std::memory_order_relaxed);
#else
  return false;
#endif
}

bool PredictedMainSlotEnabled() noexcept {
#if defined(STORMBREAKER_TESTING)
  return g_predictedMainSlotEnabled.load(std::memory_order_relaxed);
#else
  return true;
#endif
}

#if defined(STORMBREAKER_TESTING)
bool HazardPinningEnabled() noexcept {
  return g_hazardPinningEnabled.load(std::memory_order_relaxed);
}

std::atomic<uintptr_t>* AcquireHazardSlot() noexcept {
  if (!tls_hazardRegistrationAttempted) {
    tls_hazardRegistrationAttempted = true;
    const uint32_t index =
        g_nextHazardThread.fetch_add(1, std::memory_order_relaxed);
    if (index < kHazardThreadCapacity) {
      tls_hazardThread = &g_hazardThreads[index];
    }
  }
  if (!tls_hazardThread) {
    return nullptr;
  }
  for (auto& slot : tls_hazardThread->entries) {
    if (slot.load(std::memory_order_relaxed) == 0) {
      return &slot;
    }
  }
  return nullptr;
}

bool HasHazardReference(uintptr_t target) noexcept {
  const uint32_t observed =
      g_nextHazardThread.load(std::memory_order_acquire);
  const uint32_t threadCount = observed < kHazardThreadCapacity
                                   ? observed
                                   : kHazardThreadCapacity;
  for (uint32_t threadIndex = 0; threadIndex < threadCount; ++threadIndex) {
    for (const auto& slot : g_hazardThreads[threadIndex].entries) {
      if (slot.load(std::memory_order_seq_cst) == target) {
        return true;
      }
    }
  }
  return false;
}

bool HasHazardInRange(uintptr_t begin, uintptr_t end) noexcept {
  const uint32_t observed =
      g_nextHazardThread.load(std::memory_order_acquire);
  const uint32_t threadCount = observed < kHazardThreadCapacity
                                   ? observed
                                   : kHazardThreadCapacity;
  for (uint32_t threadIndex = 0; threadIndex < threadCount; ++threadIndex) {
    for (const auto& slot : g_hazardThreads[threadIndex].entries) {
      const uintptr_t value = slot.load(std::memory_order_seq_cst);
      if (value >= begin && value < end) {
        return true;
      }
    }
  }
  return false;
}
#endif

void UpdatePeak(std::atomic<uint32_t>& peak, uint32_t candidate) noexcept {
  uint32_t observed = peak.load(std::memory_order_relaxed);
  while (observed < candidate &&
         !peak.compare_exchange_weak(observed, candidate,
                                     std::memory_order_relaxed,
                                     std::memory_order_relaxed)) {
  }
}

bool SaturatingSubtract(std::atomic<uint32_t>& value,
                        uint32_t amount) noexcept {
  const uint32_t previous = value.fetch_sub(amount, std::memory_order_relaxed);
  if (previous < amount) {
    // Unsigned arithmetic lets this correction compose with concurrent adds:
    // after restoring the underflow delta, only those concurrent adds remain.
    value.fetch_add(amount - previous, std::memory_order_relaxed);
    return false;
  }
  return true;
}

bool TryIncrementReference(std::atomic<uint32_t>& references) noexcept {
  if (references.load(std::memory_order_relaxed) == UINT32_MAX) {
    return false;
  }
  const uint32_t previous =
      references.fetch_add(1u, std::memory_order_acq_rel);
  if (previous != UINT32_MAX) {
    return true;
  }
  references.fetch_sub(1u, std::memory_order_release);
  return false;
}

bool TryDecrementReference(std::atomic<uint32_t>& references) noexcept {
  const uint32_t previous =
      references.fetch_sub(1u, std::memory_order_release);
  if (previous != 0) {
    return true;
  }
  references.fetch_add(1u, std::memory_order_relaxed);
  return false;
}

void CopyTruncatedName(char (&destination)[kHeapRegistryNameCapacity],
                       uint32_t* flags, const char* source) noexcept {
  std::memset(destination, 0, sizeof(destination));
  *flags = 0;
  if (source == nullptr) {
    return;
  }

  uint32_t index = 0;
  for (; index + 1u < kHeapRegistryNameCapacity && source[index] != '\0';
       ++index) {
    destination[index] = source[index];
  }
  destination[index] = '\0';

  if (index + 1u == kHeapRegistryNameCapacity && source[index] != '\0') {
    *flags |= kNameTruncated;
  }
}

uint32_t NextGeneration(uint32_t current) noexcept {
  ++current;
  return current == 0 ? 1u : current;
}

} // namespace

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4324) // Intentional cache-line tail padding.
#endif
struct alignas(64) Registry::Entry {
  std::atomic<uint32_t> state{static_cast<uint32_t>(HeapState::Empty)};
  std::atomic<uint32_t> generation{0};
  std::atomic<uint32_t> operationReferences{0};
  std::atomic<uintptr_t> nativeSentinel{0};
  uint32_t heapId = kInvalidHeapId;
  HeapKind kind = HeapKind::Main;
  uint32_t sourceLine = 0;
  uint32_t nameFlags = 0;
  char name[kHeapRegistryNameCapacity]{};
  // Live byte totals are bounded by the Win32 address space (and requested
  // bytes by the 1 GiB pool budget); snapshots widen them to the public ABI.
  std::atomic<uint32_t> liveRequestedBytes{0};
  std::atomic<uint32_t> liveUsableBytes{0};
  std::atomic<uint32_t> peakRequestedBytes{0};
  std::atomic<uint32_t> peakUsableBytes{0};
  // These are diagnostic totals. They intentionally use lock-free Win32
  // counters and are widened when copied into the public snapshot ABI.
  std::atomic<uint32_t> allocationCount{0};
  std::atomic<uint32_t> freeCount{0};
  std::atomic<uint32_t> reallocationCount{0};
};
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

Registry::OperationGuard::~OperationGuard() noexcept {
  Reset();
}

Registry::OperationGuard::OperationGuard(OperationGuard&& other) noexcept
    : owner_(other.owner_), slot_(other.slot_), heapId_(other.heapId_),
      generation_(other.generation_), kind_(other.kind_),
      acquiredState_(other.acquiredState_),
      referenceHeld_(other.referenceHeld_) {
#if defined(STORMBREAKER_TESTING)
  hazardSlot_ = other.hazardSlot_;
  other.hazardSlot_ = nullptr;
#endif
  other.owner_ = nullptr;
  other.heapId_ = kInvalidHeapId;
  other.generation_ = 0;
  other.acquiredState_ = HeapState::Empty;
  other.referenceHeld_ = false;
}

Registry::OperationGuard& Registry::OperationGuard::operator=(
    OperationGuard&& other) noexcept {
  if (this != &other) {
    Reset();
    owner_ = other.owner_;
    slot_ = other.slot_;
    heapId_ = other.heapId_;
    generation_ = other.generation_;
    kind_ = other.kind_;
    acquiredState_ = other.acquiredState_;
    referenceHeld_ = other.referenceHeld_;
#if defined(STORMBREAKER_TESTING)
    hazardSlot_ = other.hazardSlot_;
    other.hazardSlot_ = nullptr;
#endif
    other.owner_ = nullptr;
    other.heapId_ = kInvalidHeapId;
    other.generation_ = 0;
    other.acquiredState_ = HeapState::Empty;
    other.referenceHeld_ = false;
  }
  return *this;
}

void Registry::OperationGuard::RecordAllocation(
    uint64_t requestedBytes, uint64_t usableBytes) noexcept {
  if (owner_ != nullptr) {
    owner_->RecordAllocation(slot_, requestedBytes, usableBytes);
  }
}

void Registry::OperationGuard::RecordFree(uint64_t requestedBytes,
                                          uint64_t usableBytes) noexcept {
  if (owner_ != nullptr) {
    owner_->RecordFree(slot_, requestedBytes, usableBytes);
  }
}

void Registry::OperationGuard::RecordReallocation(
    uint64_t oldRequestedBytes, uint64_t oldUsableBytes,
    uint64_t newRequestedBytes, uint64_t newUsableBytes) noexcept {
  if (owner_ != nullptr) {
    owner_->RecordReallocation(slot_, oldRequestedBytes, oldUsableBytes,
                               newRequestedBytes, newUsableBytes);
  }
}

void Registry::OperationGuard::Reset() noexcept {
#if defined(STORMBREAKER_TESTING)
  if (hazardSlot_ != nullptr) {
    hazardSlot_->store(0, std::memory_order_release);
    hazardSlot_ = nullptr;
  }
#endif
  if (owner_ != nullptr && referenceHeld_) {
    owner_->ReleaseOperation(slot_);
  }
  owner_ = nullptr;
  heapId_ = kInvalidHeapId;
  generation_ = 0;
  acquiredState_ = HeapState::Empty;
  referenceHeld_ = false;
}

Registry::~Registry() noexcept {
  Shutdown();
}

bool Registry::Initialize() noexcept {
  static_assert(alignof(Entry) == 64,
                "Registry entries must remain cache-line aligned");
  static_assert(sizeof(Entry) == 128,
                "Registry entry footprint changed unexpectedly");
  static_assert(sizeof(Entry) * kHeapRegistryCapacity == 2u * 1024u * 1024u,
                "Registry fixed storage must remain exactly 2 MiB");

  uint32_t expected = kLifecycleUninitialized;
  if (!lifecycle_.compare_exchange_strong(expected, kLifecycleInitializing,
                                          std::memory_order_acq_rel,
                                          std::memory_order_acquire)) {
    if (expected == kLifecycleReady) {
      return true;
    }
    while (expected == kLifecycleInitializing) {
      PauseForTransition(64);
      expected = lifecycle_.load(std::memory_order_acquire);
    }
    return expected == kLifecycleReady;
  }

  const size_t entryStorageSize = sizeof(Entry) * kHeapRegistryCapacity;
  const size_t filterStorageSize =
      sizeof(std::atomic<uint32_t>) * kMembershipFilterWordCount;
  const size_t allocationSize = entryStorageSize + filterStorageSize;
  void* storage = VirtualAlloc(nullptr, allocationSize,
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (storage == nullptr) {
    lifecycle_.store(kLifecycleUninitialized, std::memory_order_release);
    return false;
  }

  entries_ = static_cast<Entry*>(storage);
  membershipFilter_ = reinterpret_cast<std::atomic<uint32_t>*>(
      static_cast<uint8_t*>(storage) + entryStorageSize);
  for (uint32_t index = 0; index < kHeapRegistryCapacity; ++index) {
    new (&entries_[index]) Entry();
  }
  for (uint32_t index = 0; index < kMembershipFilterWordCount; ++index) {
    new (&membershipFilter_[index]) std::atomic<uint32_t>(0);
  }

  nextSyntheticSequence_.store(1, std::memory_order_relaxed);
  occupiedSlots_.store(0, std::memory_order_relaxed);
  insertionCollisionProbes_.store(0, std::memory_order_relaxed);
  capacityFailures_.store(0, std::memory_order_relaxed);
  degradedEvents_.store(0, std::memory_order_relaxed);
  syntheticIdsIssued_.store(0, std::memory_order_relaxed);
  uint32_t nextEpoch =
      registryEpoch_.load(std::memory_order_relaxed) + 1u;
  if (nextEpoch == 0) {
    nextEpoch = 1;
  }
  registryEpoch_.store(nextEpoch, std::memory_order_release);
  lifecycle_.store(kLifecycleReady, std::memory_order_release);
  return true;
}

bool Registry::Shutdown() noexcept {
  uint32_t expected = kLifecycleReady;
  if (!lifecycle_.compare_exchange_strong(expected, kLifecycleShuttingDown,
                                          std::memory_order_acq_rel,
                                          std::memory_order_acquire)) {
    return expected == kLifecycleUninitialized;
  }

  for (uint32_t index = 0; index < kHeapRegistryCapacity; ++index) {
    if (entries_[index].operationReferences.load(std::memory_order_acquire) !=
        0) {
      lifecycle_.store(kLifecycleReady, std::memory_order_release);
      return false;
    }
  }
#if defined(STORMBREAKER_TESTING)
  const uintptr_t entriesBegin = reinterpret_cast<uintptr_t>(entries_);
  const uintptr_t entriesEnd =
      entriesBegin + sizeof(Entry) * kHeapRegistryCapacity;
  if (g_hazardPinningEverUsed.load(std::memory_order_relaxed) &&
      HasHazardInRange(entriesBegin, entriesEnd)) {
    lifecycle_.store(kLifecycleReady, std::memory_order_release);
    return false;
  }
#endif

  Entry* storage = entries_;
  entries_ = nullptr;
  membershipFilter_ = nullptr;
  for (uint32_t index = 0; index < kHeapRegistryCapacity; ++index) {
    storage[index].~Entry();
  }
  VirtualFree(storage, 0, MEM_RELEASE);
  lifecycle_.store(kLifecycleUninitialized, std::memory_order_release);
  return true;
}

bool Registry::IsInitialized() const noexcept {
  return lifecycle_.load(std::memory_order_acquire) == kLifecycleReady;
}

uint32_t Registry::HashHeapId(uint32_t heapId) noexcept {
  uint32_t value = heapId;
  value ^= value >> 16;
  value *= 0x7FEB352Du;
  value ^= value >> 15;
  value *= 0x846CA68Bu;
  value ^= value >> 16;
  return value;
}

void Registry::PauseForTransition(uint32_t iteration) noexcept {
  if (iteration < 64u) {
    YieldProcessor();
  } else if (iteration < 256u) {
    SwitchToThread();
  } else {
    Sleep(1);
  }
}

Registry::Entry* Registry::Entries() noexcept {
  return entries_;
}

const Registry::Entry* Registry::Entries() const noexcept {
  return entries_;
}

void Registry::RecordMembership(uint32_t heapId) noexcept {
  const uint32_t first = HashHeapId(heapId);
  const uint32_t stride = HashHeapId(heapId ^ 0x9E3779B9u) | 1u;
  for (uint32_t index = 0; index < 4u; ++index) {
    const uint32_t bit = (first + index * stride) & kMembershipFilterBitMask;
    membershipFilter_[bit >> 5u].fetch_or(1u << (bit & 31u),
                                          std::memory_order_relaxed);
  }
}

bool Registry::MembershipMayContain(uint32_t heapId) const noexcept {
  const uint32_t first = HashHeapId(heapId);
  const uint32_t stride = HashHeapId(heapId ^ 0x9E3779B9u) | 1u;
  for (uint32_t index = 0; index < 4u; ++index) {
    const uint32_t bit = (first + index * stride) & kMembershipFilterBitMask;
    if ((membershipFilter_[bit >> 5u].load(std::memory_order_relaxed) &
         (1u << (bit & 31u))) == 0) {
      return false;
    }
  }
  return true;
}

bool Registry::CanFastRejectMissing(uint32_t heapId) const noexcept {
  return MembershipFilterEnabled() &&
         occupiedSlots_.load(std::memory_order_acquire) ==
             kHeapRegistryCapacity &&
         !MembershipMayContain(heapId);
}

bool Registry::FindSlot(uint32_t heapId, uint32_t* outSlot) const noexcept {
  if (CanFastRejectMissing(heapId)) {
    return false;
  }
  const uint32_t start = HashHeapId(heapId) & (kHeapRegistryCapacity - 1u);
  for (uint32_t probe = 0; probe < kHeapRegistryCapacity; ++probe) {
    const uint32_t slot = (start + probe) & (kHeapRegistryCapacity - 1u);
    const Entry& entry = entries_[slot];
    uint32_t transitionWait = 0;
    HeapState state = static_cast<HeapState>(
        entry.state.load(std::memory_order_acquire));
    while (state == HeapState::Initializing) {
      PauseForTransition(transitionWait++);
      state = static_cast<HeapState>(
          entry.state.load(std::memory_order_acquire));
    }

    if (state == HeapState::Empty) {
      return false;
    }
    if (entry.heapId == heapId) {
      *outSlot = slot;
      return true;
    }
  }
  return false;
}

Registry::InsertResult Registry::InsertOrReactivate(
    uint32_t heapId, HeapKind kind, HeapState desiredState, const char* name,
    uint32_t sourceLine, bool allowReactivate, uint32_t* outSlot,
    bool* outCreated) noexcept {
  if (CanFastRejectMissing(heapId)) {
    capacityFailures_.fetch_add(1, std::memory_order_relaxed);
    return InsertResult::CapacityExhausted;
  }
  const uint32_t start = HashHeapId(heapId) & (kHeapRegistryCapacity - 1u);
  uint64_t collisionProbes = 0;

  for (uint32_t probe = 0; probe < kHeapRegistryCapacity; ++probe) {
    const uint32_t slot = (start + probe) & (kHeapRegistryCapacity - 1u);
    Entry& entry = entries_[slot];
    uint32_t transitionWait = 0;
    HeapState state = static_cast<HeapState>(
        entry.state.load(std::memory_order_acquire));
    while (state == HeapState::Initializing) {
      PauseForTransition(transitionWait++);
      state = static_cast<HeapState>(
          entry.state.load(std::memory_order_acquire));
    }

    if (state == HeapState::Empty) {
      uint32_t expected = static_cast<uint32_t>(HeapState::Empty);
      if (!entry.state.compare_exchange_strong(
              expected, static_cast<uint32_t>(HeapState::Initializing),
              std::memory_order_acq_rel, std::memory_order_acquire)) {
        --probe;
        continue;
      }

      entry.heapId = heapId;
      entry.kind = kind;
      entry.sourceLine = sourceLine;
      CopyTruncatedName(entry.name, &entry.nameFlags, name);
      entry.operationReferences.store(0, std::memory_order_relaxed);
      entry.nativeSentinel.store(0, std::memory_order_relaxed);
      entry.liveRequestedBytes.store(0, std::memory_order_relaxed);
      entry.liveUsableBytes.store(0, std::memory_order_relaxed);
      entry.peakRequestedBytes.store(0, std::memory_order_relaxed);
      entry.peakUsableBytes.store(0, std::memory_order_relaxed);
      entry.allocationCount.store(0, std::memory_order_relaxed);
      entry.freeCount.store(0, std::memory_order_relaxed);
      entry.reallocationCount.store(0, std::memory_order_relaxed);
      entry.generation.store(1, std::memory_order_relaxed);
      RecordMembership(heapId);
      entry.state.store(static_cast<uint32_t>(desiredState),
                        std::memory_order_release);

      // The acquire/release RMW chain makes every membership bit visible
      // before another thread can observe a completely full table.
      occupiedSlots_.fetch_add(1, std::memory_order_acq_rel);
      insertionCollisionProbes_.fetch_add(collisionProbes,
                                          std::memory_order_relaxed);
      *outSlot = slot;
      *outCreated = true;
      return InsertResult::Created;
    }

    if (entry.heapId != heapId) {
      ++collisionProbes;
      continue;
    }

    *outSlot = slot;
    *outCreated = false;
    if (entry.kind != kind) {
      return InsertResult::KindConflict;
    }
    if (state == HeapState::Active) {
      return InsertResult::ExistingActive;
    }
    if (state == HeapState::Native) {
      return InsertResult::ExistingNative;
    }
    if (state == HeapState::Destroying) {
      return InsertResult::ExistingDestroying;
    }
    if (state != HeapState::Tombstone || !allowReactivate) {
      return InsertResult::ExistingTombstone;
    }

    uint32_t expected = static_cast<uint32_t>(HeapState::Tombstone);
    if (!entry.state.compare_exchange_strong(
            expected, static_cast<uint32_t>(HeapState::Initializing),
            std::memory_order_acq_rel, std::memory_order_acquire)) {
      --probe;
      continue;
    }

    entry.liveRequestedBytes.store(0, std::memory_order_relaxed);
    entry.liveUsableBytes.store(0, std::memory_order_relaxed);
    entry.peakRequestedBytes.store(0, std::memory_order_relaxed);
    entry.peakUsableBytes.store(0, std::memory_order_relaxed);
    entry.allocationCount.store(0, std::memory_order_relaxed);
    entry.freeCount.store(0, std::memory_order_relaxed);
    entry.reallocationCount.store(0, std::memory_order_relaxed);
    entry.nativeSentinel.store(0, std::memory_order_relaxed);
    const uint32_t previousGeneration =
        entry.generation.load(std::memory_order_relaxed);
    entry.generation.store(NextGeneration(previousGeneration),
                           std::memory_order_relaxed);
    entry.state.store(static_cast<uint32_t>(desiredState),
                      std::memory_order_release);
    insertionCollisionProbes_.fetch_add(collisionProbes,
                                        std::memory_order_relaxed);
    *outCreated = true;
    return InsertResult::Created;
  }

  insertionCollisionProbes_.fetch_add(collisionProbes,
                                      std::memory_order_relaxed);
  capacityFailures_.fetch_add(1, std::memory_order_relaxed);
  return InsertResult::CapacityExhausted;
}

AccessResult Registry::AcquireSlot(uint32_t slot, uint32_t heapId,
                                   OperationGuard* outGuard,
                                   bool pinGeneration) noexcept {
  Entry& entry = entries_[slot];
  for (;;) {
    const HeapState state = static_cast<HeapState>(
        entry.state.load(std::memory_order_acquire));
    if (state == HeapState::Empty || state == HeapState::Initializing) {
      return AccessResult::NotFound;
    }
    const HeapKind expectedKind =
        IsMainHeapId(heapId) ? HeapKind::Main : HeapKind::Explicit;
    if (entry.heapId != heapId || entry.kind != expectedKind) {
      return AccessResult::NotFound;
    }
    if (state != HeapState::Active && state != HeapState::Native) {
      if (state == HeapState::Destroying) {
        return AccessResult::Destroying;
      }
      if (state == HeapState::Tombstone) {
        return AccessResult::Tombstone;
      }
      return AccessResult::NotFound;
    }

    const uint32_t generation =
        entry.generation.load(std::memory_order_acquire);
#if defined(STORMBREAKER_TESTING)
    std::atomic<uintptr_t>* hazardSlot = nullptr;
    if (pinGeneration && HazardPinningEnabled()) {
      hazardSlot = AcquireHazardSlot();
      if (hazardSlot != nullptr) {
        uintptr_t expectedHazard = 0;
        if (!hazardSlot->compare_exchange_strong(
                expectedHazard, reinterpret_cast<uintptr_t>(&entry),
                std::memory_order_seq_cst, std::memory_order_relaxed)) {
          hazardSlot = nullptr;
        } else {
          g_hazardPinningEverUsed.store(true, std::memory_order_relaxed);
        }
      }
    }
    const bool holdReference = pinGeneration && hazardSlot == nullptr;
#else
    const bool holdReference = pinGeneration;
#endif
    if (holdReference && !TryIncrementReference(entry.operationReferences)) {
      MarkDegraded();
      return AccessResult::Destroying;
    }

#if defined(STORMBREAKER_TESTING)
    const HeapState verifiedState = static_cast<HeapState>(
        hazardSlot != nullptr
            ? entry.state.load(std::memory_order_seq_cst)
            : entry.state.load(std::memory_order_acquire));
#else
    const HeapState verifiedState = static_cast<HeapState>(
        entry.state.load(std::memory_order_acquire));
#endif
    const uint32_t verifiedGeneration =
        entry.generation.load(std::memory_order_acquire);
    if (verifiedState == state && verifiedGeneration == generation &&
        entry.heapId == heapId) {
      outGuard->owner_ = this;
      outGuard->slot_ = slot;
      outGuard->heapId_ = heapId;
      outGuard->generation_ = generation;
      outGuard->kind_ = entry.kind;
      outGuard->acquiredState_ = state;
      outGuard->referenceHeld_ = holdReference;
#if defined(STORMBREAKER_TESTING)
      outGuard->hazardSlot_ = hazardSlot;
#endif
      return state == HeapState::Active ? AccessResult::Managed
                                        : AccessResult::Native;
    }

#if defined(STORMBREAKER_TESTING)
    if (hazardSlot != nullptr) {
      hazardSlot->store(0, std::memory_order_release);
    }
#endif
    if (holdReference && !TryDecrementReference(entry.operationReferences)) {
      MarkDegraded();
    }
    if (entry.heapId != heapId || entry.kind != expectedKind) {
      return AccessResult::NotFound;
    }
    if (verifiedState == HeapState::Active ||
        verifiedState == HeapState::Native) {
      continue;
    }
    if (verifiedState == HeapState::Tombstone) {
      return AccessResult::Tombstone;
    }
    return AccessResult::Destroying;
  }
}

AccessResult Registry::Acquire(uint32_t heapId,
                               OperationGuard* outGuard,
                               bool pinGeneration) noexcept {
  if (outGuard == nullptr) {
    return AccessResult::InvalidArgument;
  }
  outGuard->Reset();
  if (heapId == kInvalidHeapId) {
    return AccessResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return AccessResult::NotInitialized;
  }

  uint32_t slot = 0;
  if (!FindSlot(heapId, &slot)) {
    return AccessResult::NotFound;
  }
  return AcquireSlot(slot, heapId, outGuard, pinGeneration);
}

AccessResult Registry::AcquireOrCreateMain(
    uint32_t heapId, const char* name, uint32_t sourceLine,
    OperationGuard* outGuard, bool* outCreated,
    SlotHint* inOutSlotHint, bool pinGeneration) noexcept {
  if (outCreated != nullptr) {
    *outCreated = false;
  }
  if (outGuard == nullptr) {
    return AccessResult::InvalidArgument;
  }
  outGuard->Reset();
  if (!IsMainHeapId(heapId)) {
    return AccessResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return AccessResult::NotInitialized;
  }

  const uint32_t registryEpoch =
      registryEpoch_.load(std::memory_order_acquire);
  if (inOutSlotHint != nullptr &&
      inOutSlotHint->registryEpoch == registryEpoch &&
      inOutSlotHint->slot < kHeapRegistryCapacity) {
    const AccessResult hinted =
        AcquireSlot(inOutSlotHint->slot, heapId, outGuard, pinGeneration);
    if (hinted == AccessResult::Managed || hinted == AccessResult::Native ||
        hinted == AccessResult::Destroying) {
      return hinted;
    }
    // A main heap tombstone must be reactivated through the normal insertion
    // path. NotFound means the direct-mapped caller cache was replaced or the
    // registry was rebuilt, so the hint is simply refreshed below.
  }
  if (inOutSlotHint != nullptr) {
    inOutSlotHint->Reset();
  }

  if (PredictedMainSlotEnabled()) {
    const uint32_t predictedSlot =
        HashHeapId(heapId) & (kHeapRegistryCapacity - 1u);
    const AccessResult predicted =
        AcquireSlot(predictedSlot, heapId, outGuard, pinGeneration);
    if (predicted == AccessResult::Managed ||
        predicted == AccessResult::Native) {
      if (inOutSlotHint != nullptr) {
        inOutSlotHint->slot = predictedSlot;
        inOutSlotHint->registryEpoch = registryEpoch;
      }
      return predicted;
    }
    if (predicted == AccessResult::Destroying) {
      return predicted;
    }
  }

  uint32_t slot = 0;
  bool created = false;
  const InsertResult insert = InsertOrReactivate(
      heapId, HeapKind::Main, HeapState::Active, name, sourceLine, true,
      &slot, &created);
  if (outCreated != nullptr) {
    *outCreated = created;
  }
  if (inOutSlotHint != nullptr &&
      insert != InsertResult::CapacityExhausted) {
    inOutSlotHint->slot = slot;
    inOutSlotHint->registryEpoch = registryEpoch;
  }

  switch (insert) {
  case InsertResult::Created:
  case InsertResult::ExistingActive:
  case InsertResult::ExistingNative:
    return AcquireSlot(slot, heapId, outGuard, pinGeneration);
  case InsertResult::ExistingDestroying:
    return AccessResult::Destroying;
  case InsertResult::ExistingTombstone:
    return AccessResult::Tombstone;
  case InsertResult::CapacityExhausted:
    return AccessResult::CapacityExhausted;
  case InsertResult::KindConflict:
    return AccessResult::NotFound;
  }
  return AccessResult::NotFound;
}

CreateResult Registry::CreateExplicitManaged(const char* name,
                                             uint32_t sourceLine,
                                             uint32_t* outHeapId) noexcept {
  if (outHeapId == nullptr) {
    return CreateResult::InvalidArgument;
  }
  *outHeapId = kInvalidHeapId;
  if (!IsInitialized()) {
    return CreateResult::NotInitialized;
  }

  for (uint32_t attempt = 0; attempt < kHeapRegistryCapacity; ++attempt) {
    uint32_t sequence =
        nextSyntheticSequence_.fetch_add(1, std::memory_order_relaxed) &
        0x7FFFFFFFu;
    if (sequence == 0 || sequence == 0x7FFFFFFFu) {
      sequence = nextSyntheticSequence_.fetch_add(1,
                                                  std::memory_order_relaxed) &
                 0x7FFFFFFFu;
      if (sequence == 0 || sequence == 0x7FFFFFFFu) {
        continue;
      }
    }
    const uint32_t heapId = kExplicitHeapIdBit | sequence;

    uint32_t slot = 0;
    bool created = false;
    const InsertResult insert = InsertOrReactivate(
        heapId, HeapKind::Explicit, HeapState::Active, name, sourceLine, false,
        &slot, &created);
    if (insert == InsertResult::Created) {
      syntheticIdsIssued_.fetch_add(1, std::memory_order_relaxed);
      *outHeapId = heapId;
      return CreateResult::CreatedManaged;
    }
    if (insert == InsertResult::CapacityExhausted) {
      return CreateResult::CapacityExhausted;
    }
  }

  capacityFailures_.fetch_add(1, std::memory_order_relaxed);
  return CreateResult::CapacityExhausted;
}

CreateResult Registry::RegisterManaged(uint32_t heapId, HeapKind kind,
                                       const char* name,
                                       uint32_t sourceLine) noexcept {
  if (heapId == 0 || heapId == kInvalidHeapId) {
    return CreateResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return CreateResult::NotInitialized;
  }

  uint32_t slot = 0;
  bool created = false;
  const InsertResult insert = InsertOrReactivate(
      heapId, kind, HeapState::Active, name, sourceLine, true, &slot, &created);
  switch (insert) {
  case InsertResult::Created:
    return CreateResult::CreatedManaged;
  case InsertResult::ExistingActive:
    return CreateResult::AlreadyManaged;
  case InsertResult::ExistingNative:
    return CreateResult::AlreadyNative;
  case InsertResult::ExistingDestroying:
    return CreateResult::Destroying;
  case InsertResult::ExistingTombstone:
    return CreateResult::Tombstone;
  case InsertResult::CapacityExhausted:
    return CreateResult::CapacityExhausted;
  case InsertResult::KindConflict:
    return CreateResult::IdConflict;
  }
  return CreateResult::IdConflict;
}

CreateResult Registry::RegisterNative(uint32_t heapId, HeapKind kind,
                                      const char* name,
                                      uint32_t sourceLine) noexcept {
  if (heapId == kInvalidHeapId) {
    return CreateResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return CreateResult::NotInitialized;
  }

  uint32_t slot = 0;
  bool created = false;
  const InsertResult insert = InsertOrReactivate(
      heapId, kind, HeapState::Native, name, sourceLine, true, &slot, &created);
  switch (insert) {
  case InsertResult::Created:
    return CreateResult::CreatedNative;
  case InsertResult::ExistingActive:
    return CreateResult::AlreadyManaged;
  case InsertResult::ExistingNative:
    return CreateResult::AlreadyNative;
  case InsertResult::ExistingDestroying:
    return CreateResult::Destroying;
  case InsertResult::ExistingTombstone:
    return CreateResult::Tombstone;
  case InsertResult::CapacityExhausted:
    return CreateResult::CapacityExhausted;
  case InsertResult::KindConflict:
    return CreateResult::IdConflict;
  }
  return CreateResult::IdConflict;
}

bool Registry::SetNativeSentinel(uint32_t heapId, void* pointer) noexcept {
  if (!pointer || !IsInitialized()) {
    return false;
  }
  uint32_t slot = 0;
  if (!FindSlot(heapId, &slot)) {
    return false;
  }
  Entry& entry = entries_[slot];
  if (entry.state.load(std::memory_order_acquire) !=
      static_cast<uint32_t>(HeapState::Active)) {
    return false;
  }
  uintptr_t expected = 0;
  return entry.nativeSentinel.compare_exchange_strong(
      expected, reinterpret_cast<uintptr_t>(pointer),
      std::memory_order_release, std::memory_order_relaxed);
}

void* Registry::TakeNativeSentinel(uint32_t heapId) noexcept {
  if (!IsInitialized()) {
    return nullptr;
  }
  uint32_t slot = 0;
  if (!FindSlot(heapId, &slot)) {
    return nullptr;
  }
  return reinterpret_cast<void*>(
      entries_[slot].nativeSentinel.exchange(0, std::memory_order_acq_rel));
}

bool Registry::RestoreNativeSentinel(const DestroyToken& token,
                                     void* pointer) noexcept {
  if (!pointer) {
    return false;
  }
  Entry* entry = nullptr;
  if (!ValidateDestroyToken(token, &entry)) {
    return false;
  }
  uintptr_t expected = 0;
  return entry->nativeSentinel.compare_exchange_strong(
      expected, reinterpret_cast<uintptr_t>(pointer),
      std::memory_order_release, std::memory_order_relaxed);
}

DestroyResult Registry::BeginDestroy(uint32_t heapId,
                                     DestroyToken* outToken) noexcept {
  if (outToken == nullptr || heapId == kInvalidHeapId) {
    return DestroyResult::InvalidArgument;
  }
  std::memset(outToken, 0, sizeof(*outToken));
  outToken->heapId = kInvalidHeapId;
  if (!IsInitialized()) {
    return DestroyResult::NotInitialized;
  }

  uint32_t slot = 0;
  if (!FindSlot(heapId, &slot)) {
    return DestroyResult::NotFound;
  }

  Entry& entry = entries_[slot];
  for (;;) {
    const HeapState state = static_cast<HeapState>(
        entry.state.load(std::memory_order_acquire));
    if (state == HeapState::Destroying || state == HeapState::Initializing) {
      return DestroyResult::AlreadyDestroying;
    }
    if (state == HeapState::Tombstone) {
      return DestroyResult::Tombstone;
    }
    if (state != HeapState::Active && state != HeapState::Native) {
      return DestroyResult::NotFound;
    }

    uint32_t expected = static_cast<uint32_t>(state);
#if defined(STORMBREAKER_TESTING)
    const bool changed = entry.state.compare_exchange_weak(
        expected, static_cast<uint32_t>(HeapState::Destroying),
        std::memory_order_seq_cst, std::memory_order_acquire);
#else
    const bool changed = entry.state.compare_exchange_weak(
        expected, static_cast<uint32_t>(HeapState::Destroying),
        std::memory_order_acq_rel, std::memory_order_acquire);
#endif
    if (!changed) {
      continue;
    }

    const uint32_t oldGeneration =
        entry.generation.load(std::memory_order_relaxed);
    const uint32_t destroyGeneration = NextGeneration(oldGeneration);
    entry.generation.store(destroyGeneration, std::memory_order_release);

    uint32_t waitIteration = 0;
    while (entry.operationReferences.load(std::memory_order_acquire) != 0
#if defined(STORMBREAKER_TESTING)
           || (g_hazardPinningEverUsed.load(std::memory_order_relaxed) &&
               HasHazardReference(reinterpret_cast<uintptr_t>(&entry)))
#endif
    ) {
      if (waitIteration >= 5000u) {
        entry.state.store(static_cast<uint32_t>(state),
                          std::memory_order_release);
        return DestroyResult::AlreadyDestroying;
      }
      PauseForTransition(waitIteration++);
    }

    outToken->heapId = heapId;
    outToken->slot = slot;
    outToken->generation = destroyGeneration;
    outToken->previousState = state;
    outToken->valid = 1;
    return state == HeapState::Active ? DestroyResult::BegunManaged
                                      : DestroyResult::BegunNative;
  }
}

bool Registry::ValidateDestroyToken(const DestroyToken& token,
                                    Entry** outEntry) noexcept {
  if (!IsInitialized() || token.valid == 0 ||
      token.heapId == kInvalidHeapId || token.slot >= kHeapRegistryCapacity) {
    return false;
  }
  Entry& entry = entries_[token.slot];
  if (entry.heapId != token.heapId ||
      entry.state.load(std::memory_order_acquire) !=
          static_cast<uint32_t>(HeapState::Destroying) ||
      entry.generation.load(std::memory_order_acquire) != token.generation) {
    return false;
  }
  *outEntry = &entry;
  return true;
}

bool Registry::RecordDestroyFree(const DestroyToken& token,
                                 uint64_t requestedBytes,
                                 uint64_t usableBytes) noexcept {
  Entry* entry = nullptr;
  if (!ValidateDestroyToken(token, &entry)) {
    return false;
  }
  UpdatePeak(entry->peakRequestedBytes,
             entry->liveRequestedBytes.load(std::memory_order_relaxed));
  UpdatePeak(entry->peakUsableBytes,
             entry->liveUsableBytes.load(std::memory_order_relaxed));
  const bool requestedValid =
      SaturatingSubtract(entry->liveRequestedBytes,
                         static_cast<uint32_t>(requestedBytes));
  const bool usableValid =
      SaturatingSubtract(entry->liveUsableBytes,
                         static_cast<uint32_t>(usableBytes));
  entry->freeCount.fetch_add(1, std::memory_order_relaxed);
  if (!requestedValid || !usableValid) {
    MarkDegraded();
    return false;
  }
  return true;
}

DestroyResult Registry::FinishDestroy(DestroyToken* token,
                                      FinishMode mode) noexcept {
  if (token == nullptr) {
    return DestroyResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return DestroyResult::NotInitialized;
  }

  Entry* entry = nullptr;
  if (!ValidateDestroyToken(*token, &entry)) {
    return DestroyResult::StaleToken;
  }
  if (entry->operationReferences.load(std::memory_order_acquire) != 0) {
    return DestroyResult::AlreadyDestroying;
  }

  const uint64_t liveRequested =
      entry->liveRequestedBytes.load(std::memory_order_acquire);
  const uint64_t liveUsable =
      entry->liveUsableBytes.load(std::memory_order_acquire);
  if (mode == FinishMode::RequireEmpty &&
      (liveRequested != 0 || liveUsable != 0)) {
    entry->state.store(static_cast<uint32_t>(token->previousState),
                       std::memory_order_release);
    std::memset(token, 0, sizeof(*token));
    token->heapId = kInvalidHeapId;
    return DestroyResult::LiveAllocationsRemain;
  }

  if (mode == FinishMode::DiscardLiveStatistics) {
    entry->liveRequestedBytes.store(0, std::memory_order_relaxed);
    entry->liveUsableBytes.store(0, std::memory_order_relaxed);
    if (token->previousState == HeapState::Active &&
        (liveRequested != 0 || liveUsable != 0)) {
      MarkDegraded();
    }
  }

  entry->state.store(static_cast<uint32_t>(HeapState::Tombstone),
                     std::memory_order_release);
  std::memset(token, 0, sizeof(*token));
  token->heapId = kInvalidHeapId;
  return DestroyResult::Finished;
}

DestroyResult Registry::CancelDestroy(DestroyToken* token) noexcept {
  if (token == nullptr) {
    return DestroyResult::InvalidArgument;
  }
  if (!IsInitialized()) {
    return DestroyResult::NotInitialized;
  }

  Entry* entry = nullptr;
  if (!ValidateDestroyToken(*token, &entry)) {
    return DestroyResult::StaleToken;
  }
  if (entry->operationReferences.load(std::memory_order_acquire) != 0) {
    return DestroyResult::AlreadyDestroying;
  }
  if (token->previousState != HeapState::Active &&
      token->previousState != HeapState::Native) {
    return DestroyResult::StaleToken;
  }

  entry->state.store(static_cast<uint32_t>(token->previousState),
                     std::memory_order_release);
  std::memset(token, 0, sizeof(*token));
  token->heapId = kInvalidHeapId;
  return DestroyResult::Cancelled;
}

SnapshotCopyResult Registry::CopySnapshots(HeapSnapshot* output,
                                           uint32_t outputCapacity,
                                           uint32_t stateMask) const noexcept {
  SnapshotCopyResult result{};
  if ((output == nullptr && outputCapacity != 0) || !IsInitialized()) {
    result.invalidArgument = 1;
    return result;
  }

  for (uint32_t index = 0; index < kHeapRegistryCapacity; ++index) {
    const Entry& entry = entries_[index];
    HeapSnapshot snapshot{};
    bool captured = false;

    for (uint32_t attempt = 0; attempt < 4u && !captured; ++attempt) {
      const HeapState beforeState = static_cast<HeapState>(
          entry.state.load(std::memory_order_acquire));
      // Empty has no published metadata and Initializing is actively writing
      // immutable name/kind fields. Neither state is safe or useful to expose.
      if (beforeState == HeapState::Empty ||
          beforeState == HeapState::Initializing) {
        break;
      }
      const uint32_t stateValue = static_cast<uint32_t>(beforeState);
      if (stateValue >= 32u || (stateMask & (1u << stateValue)) == 0u) {
        break;
      }
      const uint32_t beforeGeneration =
          entry.generation.load(std::memory_order_acquire);

      snapshot.heapId = entry.heapId;
      snapshot.state = beforeState;
      snapshot.kind = entry.kind;
      snapshot.sourceLine = entry.sourceLine;
      snapshot.generation = beforeGeneration;
      snapshot.operationReferences =
          entry.operationReferences.load(std::memory_order_relaxed);
      snapshot.liveRequestedBytes =
          entry.liveRequestedBytes.load(std::memory_order_relaxed);
      snapshot.liveUsableBytes =
          entry.liveUsableBytes.load(std::memory_order_relaxed);
      snapshot.peakRequestedBytes =
          entry.peakRequestedBytes.load(std::memory_order_relaxed);
      snapshot.peakUsableBytes =
          entry.peakUsableBytes.load(std::memory_order_relaxed);
      snapshot.allocationCount =
          entry.allocationCount.load(std::memory_order_relaxed);
      snapshot.freeCount = entry.freeCount.load(std::memory_order_relaxed);
      snapshot.reallocationCount =
          entry.reallocationCount.load(std::memory_order_relaxed);
      std::memcpy(snapshot.name, entry.name, sizeof(snapshot.name));
      snapshot.flags = (entry.nameFlags & kNameTruncated) != 0
                           ? HeapSnapshotFlagNameTruncated
                           : HeapSnapshotFlagNone;

      const uint32_t afterGeneration =
          entry.generation.load(std::memory_order_acquire);
      const HeapState afterState = static_cast<HeapState>(
          entry.state.load(std::memory_order_acquire));
      captured = beforeState == afterState &&
                 beforeGeneration == afterGeneration;
    }

    if (!captured) {
      continue;
    }

    if (snapshot.peakRequestedBytes < snapshot.liveRequestedBytes) {
      snapshot.peakRequestedBytes = snapshot.liveRequestedBytes;
    }
    if (snapshot.peakUsableBytes < snapshot.liveUsableBytes) {
      snapshot.peakUsableBytes = snapshot.liveUsableBytes;
    }

    ++result.available;
    if (result.written < outputCapacity) {
      output[result.written++] = snapshot;
    }
  }

  result.truncated = result.available > result.written ? 1u : 0u;
  return result;
}

RegistryStats Registry::GetStats() const noexcept {
  RegistryStats stats{};
  stats.capacity = kHeapRegistryCapacity;
  stats.occupiedSlots = occupiedSlots_.load(std::memory_order_relaxed);
  stats.insertionCollisionProbes =
      insertionCollisionProbes_.load(std::memory_order_relaxed);
  stats.capacityFailures =
      capacityFailures_.load(std::memory_order_relaxed);
  stats.degradedEvents = degradedEvents_.load(std::memory_order_relaxed);
  stats.syntheticIdsIssued =
      syntheticIdsIssued_.load(std::memory_order_relaxed);

  if (!IsInitialized()) {
    return stats;
  }

  for (uint32_t index = 0; index < kHeapRegistryCapacity; ++index) {
    const HeapState state = static_cast<HeapState>(
        entries_[index].state.load(std::memory_order_acquire));
    switch (state) {
    case HeapState::Active:
      ++stats.activeHeaps;
      break;
    case HeapState::Destroying:
      ++stats.destroyingHeaps;
      break;
    case HeapState::Tombstone:
      ++stats.tombstoneHeaps;
      break;
    case HeapState::Native:
      ++stats.nativeHeaps;
      break;
    case HeapState::Initializing:
      ++stats.initializingHeaps;
      break;
    case HeapState::Empty:
      break;
    }
  }
  return stats;
}

void Registry::MarkDegraded(uint64_t count) noexcept {
  degradedEvents_.fetch_add(count, std::memory_order_relaxed);
}

void Registry::ReleaseOperation(uint32_t slot) noexcept {
  Entry& entry = entries_[slot];
  if (!TryDecrementReference(entry.operationReferences)) {
    MarkDegraded();
  }
}

void Registry::RecordAllocation(uint32_t slot, uint64_t requestedBytes,
                                uint64_t usableBytes) noexcept {
  Entry& entry = entries_[slot];
  entry.liveRequestedBytes.fetch_add(static_cast<uint32_t>(requestedBytes),
                                     std::memory_order_relaxed);
  entry.liveUsableBytes.fetch_add(static_cast<uint32_t>(usableBytes),
                                  std::memory_order_relaxed);
  entry.allocationCount.fetch_add(1, std::memory_order_relaxed);
}

void Registry::RecordFree(uint32_t slot, uint64_t requestedBytes,
                          uint64_t usableBytes) noexcept {
  Entry& entry = entries_[slot];
  UpdatePeak(entry.peakRequestedBytes,
             entry.liveRequestedBytes.load(std::memory_order_relaxed));
  UpdatePeak(entry.peakUsableBytes,
             entry.liveUsableBytes.load(std::memory_order_relaxed));
  const bool requestedValid =
      SaturatingSubtract(entry.liveRequestedBytes,
                         static_cast<uint32_t>(requestedBytes));
  const bool usableValid =
      SaturatingSubtract(entry.liveUsableBytes,
                         static_cast<uint32_t>(usableBytes));
  entry.freeCount.fetch_add(1, std::memory_order_relaxed);
  if (!requestedValid || !usableValid) {
    MarkDegraded();
  }
}

void Registry::RecordReallocation(uint32_t slot,
                                  uint64_t oldRequestedBytes,
                                  uint64_t oldUsableBytes,
                                  uint64_t newRequestedBytes,
                                  uint64_t newUsableBytes) noexcept {
  Entry& entry = entries_[slot];
  UpdatePeak(entry.peakRequestedBytes,
             entry.liveRequestedBytes.load(std::memory_order_relaxed));
  UpdatePeak(entry.peakUsableBytes,
             entry.liveUsableBytes.load(std::memory_order_relaxed));
  const bool requestedValid =
      SaturatingSubtract(entry.liveRequestedBytes,
                         static_cast<uint32_t>(oldRequestedBytes));
  const bool usableValid =
      SaturatingSubtract(entry.liveUsableBytes,
                         static_cast<uint32_t>(oldUsableBytes));
  entry.liveRequestedBytes.fetch_add(static_cast<uint32_t>(newRequestedBytes),
                                     std::memory_order_relaxed);
  entry.liveUsableBytes.fetch_add(static_cast<uint32_t>(newUsableBytes),
                                  std::memory_order_relaxed);
  entry.reallocationCount.fetch_add(1, std::memory_order_relaxed);
  if (!requestedValid || !usableValid) {
    MarkDegraded();
  }
}

#if defined(STORMBREAKER_TESTING)
namespace Testing {
void SetMembershipFilterEnabled(bool enabled) noexcept {
  g_membershipFilterEnabled.store(enabled, std::memory_order_release);
}

void SetPredictedMainSlotEnabled(bool enabled) noexcept {
  g_predictedMainSlotEnabled.store(enabled, std::memory_order_release);
}

void SetHazardPinningEnabled(bool enabled) noexcept {
  g_hazardPinningEnabled.store(enabled, std::memory_order_release);
}
} // namespace Testing
#endif

} // namespace StormHeapRegistry
