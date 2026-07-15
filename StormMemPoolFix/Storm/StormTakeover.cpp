#include "pch.h"
#include "StormTakeover.h"

#include "Base/Logger.h"
#include "MemoryPool.h"
#include "StormVersionProfile.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bcrypt.h>
#include <cstring>
#include <detours.h>
#include <limits>
#include <TlHelp32.h>
#include <vector>

#ifndef STORMBREAKER_PINNED_RUNTIME
#define STORMBREAKER_PINNED_RUNTIME 0
#endif

#ifndef STORMBREAKER_BENCHMARK_PINNED_HOTPATH
#define STORMBREAKER_BENCHMARK_PINNED_HOTPATH 0
#endif

namespace {

#pragma pack(push, 1)
struct SmallManagedHeader {
  uint32_t encodedHeapId;
  uint16_t requestedSize;
  uint8_t meta;
  uint8_t checksum;
};

struct LargeManagedHeader {
  uint32_t encodedHeapId;
  uint32_t requestedSize;
  uint32_t cookie;
  uint8_t meta;
  uint8_t checksum;
  uint16_t rejectTag;
};
#pragma pack(pop)

static_assert(sizeof(SmallManagedHeader) == 8,
              "small Storm takeover header must match native overhead");
static_assert(sizeof(LargeManagedHeader) == 16,
              "large Storm takeover header ABI changed");

constexpr uint8_t kMetaMarkerMask = 0xF0u;
constexpr uint8_t kSmallMarker = 0xA0u;
constexpr uint8_t kLargeMarker = 0xB0u;
constexpr uint8_t kMetaMimalloc = 0x01u;
constexpr uint8_t kMetaPersistent = 0x02u;
constexpr uint8_t kMetaSuppressLeak = 0x04u;
constexpr uint8_t kMetaCanary = 0x08u;
constexpr uint16_t kRejectTag = 0x4253u;
constexpr uint16_t kTailCanary = 0x12B1u;
constexpr uint32_t kAggregateHeapId = 0xFFFFFFFEu;
constexpr size_t kRecentFreedCapacity = 65536u;
static_assert(kRecentFreedCapacity == (1u << 16u));
// Keep ordinal 483 lookup cost bounded even when the workload has more unique
// callers than the cache can retain. Each key examines exactly one eight-way
// set; a full set bypasses caching instead of scanning the whole table.
constexpr size_t kCallerHeapCacheWays = 8u;
constexpr size_t kCallerHeapCacheSetCount = 2048u;
constexpr size_t kCallerHeapCacheCapacity =
    kCallerHeapCacheWays * kCallerHeapCacheSetCount;
constexpr size_t kCallerThreadCacheCapacity = 256u;
constexpr size_t kCallerThreadCacheMaximum = 1024u;
constexpr size_t kHeapIdSlotHintCapacity = 0u;
constexpr size_t kHeapIdSlotHintMaximum = 1024u;
constexpr uint32_t kCallerCacheCounterBatch = 4096u;
constexpr uint32_t kOptionDebug = 1u;
constexpr uint32_t kOptionErrorHandling = 2u;
constexpr uint32_t kOptionProtect = 4u;
constexpr uint32_t kOptionFillPattern = 8u;
constexpr std::array<uint32_t, 16> kStormCallerHashNibbleTable = {
    0x486E26EEu, 0xDCAA16B3u, 0xE1918EEFu, 0x202DAFDBu,
    0x341C7DC7u, 0x1C365303u, 0x40EF2D37u, 0x65FD5E49u,
    0xD6057177u, 0x904ECE93u, 0x1C38024Fu, 0x98FD323Bu,
    0xE3061AE7u, 0xA39B0FA1u, 0x9797F25Fu, 0xE4444563u,
};

constexpr std::array<uint32_t, 256> BuildStormCallerHashByteTable() noexcept {
  std::array<uint32_t, 256> table{};
  for (size_t value = 0; value < table.size(); ++value) {
    table[value] = kStormCallerHashNibbleTable[value >> 4u] -
                   kStormCallerHashNibbleTable[value & 0x0Fu];
  }
  return table;
}

constexpr auto kStormCallerHashByteTable = BuildStormCallerHashByteTable();
static_assert((kCallerHeapCacheSetCount &
               (kCallerHeapCacheSetCount - 1u)) == 0u);

struct ManagedBlock {
  void* raw = nullptr;
  void* user = nullptr;
  uint32_t heapId = 0;
  uint32_t requestedSize = 0;
  size_t physicalUsableSize = 0;
  size_t payloadUsableSize = 0;
  size_t headerSize = 0;
  MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
  uint8_t meta = 0;
  bool isSmall = false;
  bool persistent = false;
  bool suppressLeakWarning = false;
  bool canary = false;
};

struct ManagedAllocation {
  void* pointer = nullptr;
  ManagedBlock block{};
};

struct LegacyDestroySnapshotEntry {
  void* raw = nullptr;
  size_t usableSize = 0;
  MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
  uint8_t reserved[3]{};
};
static_assert(sizeof(LegacyDestroySnapshotEntry) == 12u);

struct TaggedDestroySnapshotEntry {
  uintptr_t taggedRaw = 0;
  uint32_t usableSize = 0;
  uint32_t requestedSize = 0;
};
static_assert(sizeof(TaggedDestroySnapshotEntry) == 12u);

union DestroySnapshotEntry {
  LegacyDestroySnapshotEntry legacy;
  TaggedDestroySnapshotEntry tagged;
};
static_assert(sizeof(DestroySnapshotEntry) == 12u);

struct LegacyDestroyBatchMetadata {
  void* user = nullptr;
  uint32_t requestedSize = 0;
  uint32_t payloadUsableSize = 0;
};
static_assert(sizeof(LegacyDestroyBatchMetadata) == 12u);

constexpr uintptr_t kDestroySnapshotMimallocTag = 0x1u;
constexpr uintptr_t kDestroySnapshotCanaryTag = 0x2u;
constexpr uintptr_t kDestroySnapshotLargeTag = 0x4u;
constexpr uintptr_t kDestroySnapshotTagMask = 0x7u;

struct NativeHeapSnapshot {
  uint32_t heapId = 0;
  StormApi::HeapInfo482 info{};
};

struct NativeHeapIndex {
  uint32_t heapId = 0;
  uint32_t snapshotIndex = 0;
};

struct CallerHeapCacheEntry {
  std::atomic<uint32_t> state{0};
  const char* sourceFile = nullptr;
  int32_t sourceLine = 0;
  uint32_t heapId = 0;
  // The registry epoch is the publication word. A reader that observes a
  // nonzero epoch may use registrySlot without taking the cache write lock.
  std::atomic<uint32_t> registrySlot{
      StormHeapRegistry::kInvalidSlotHint};
  std::atomic<uint32_t> registryEpoch{0};
};

struct CallerThreadCacheEntry {
  const char* sourceFile = nullptr;
  int32_t sourceLine = 0;
  uint32_t heapId = 0;
  CallerHeapCacheEntry* sharedEntry = nullptr;
};

struct CallerThreadCacheStorage {
  ~CallerThreadCacheStorage() noexcept { Release(); }

  bool Ensure(size_t requestedCapacity) noexcept {
    if (entries && capacity == requestedCapacity) {
      return true;
    }
    Release();
    if (requestedCapacity == 0 ||
        requestedCapacity > kCallerThreadCacheMaximum) {
      return false;
    }
    entries = static_cast<CallerThreadCacheEntry*>(VirtualAlloc(
        nullptr, sizeof(CallerThreadCacheEntry) * requestedCapacity,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!entries) {
      return false;
    }
    capacity = requestedCapacity;
    return true;
  }

  void Clear() noexcept {
    if (entries) {
      std::memset(entries, 0, sizeof(CallerThreadCacheEntry) * capacity);
    }
  }

  void Release() noexcept {
    if (entries) {
      VirtualFree(entries, 0, MEM_RELEASE);
      entries = nullptr;
    }
    capacity = 0;
  }

  CallerThreadCacheEntry* entries = nullptr;
  size_t capacity = 0;
};

struct HeapIdSlotHintEntry {
  uint32_t heapId = 0;
  StormHeapRegistry::SlotHint hint{};
};
static_assert(sizeof(HeapIdSlotHintEntry) == 12u);

struct HeapIdSlotHintStorage {
  ~HeapIdSlotHintStorage() noexcept { Release(); }

  bool Ensure(size_t requestedCapacity) noexcept {
    if (entries && capacity == requestedCapacity) {
      return true;
    }
    Release();
    if (requestedCapacity == 0 ||
        requestedCapacity > kHeapIdSlotHintMaximum ||
        (requestedCapacity & (requestedCapacity - 1u)) != 0) {
      return false;
    }
    entries = static_cast<HeapIdSlotHintEntry*>(VirtualAlloc(
        nullptr, sizeof(HeapIdSlotHintEntry) * requestedCapacity,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!entries) {
      return false;
    }
    capacity = requestedCapacity;
    return true;
  }

  void Clear() noexcept {
    if (entries) {
      std::memset(entries, 0, sizeof(HeapIdSlotHintEntry) * capacity);
    }
  }

  void Release() noexcept {
    if (entries) {
      VirtualFree(entries, 0, MEM_RELEASE);
      entries = nullptr;
    }
    capacity = 0;
  }

  HeapIdSlotHintEntry* entries = nullptr;
  size_t capacity = 0;
};

struct ModuleImageRange {
  uintptr_t begin = 0;
  uintptr_t end = 0;
};

struct ReallocResult {
  void* pointer = nullptr;
  ManagedBlock newBlock{};
  bool succeeded = false;
  bool oldFreed = false;
  bool newAllocated = false;
  bool inPlace = false;
  bool newManaged = false;
};

enum class FastFreeDisposition : uint8_t {
  NotCandidate,
  Freed,
  Rejected,
};

struct FastFreeResult {
  FastFreeDisposition disposition = FastFreeDisposition::NotCandidate;
  ManagedBlock block{};
};

struct ConditionalManagedFreeContext {
  const void* expectedUser = nullptr;
  MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
  ManagedBlock block{};
};

StormApi::ResolvedApi g_api{};
StormHeapRegistry::Registry g_registry;
StormHeapRegistry::HeapSnapshot* g_heapSnapshots = nullptr;
NativeHeapSnapshot* g_nativeHeapSnapshots = nullptr;
NativeHeapIndex* g_nativeHeapIndex = nullptr;
SRWLOCK g_snapshotLock = SRWLOCK_INIT;
SRWLOCK g_destroyLock = SRWLOCK_INIT;
uint32_t g_cachedManagedHeapCount = 0;
uint32_t g_cachedNativeHeapCount = 0;
uint64_t g_cachedBackendReservedBytes = 0;
uint64_t g_cachedBackendCommittedBytes = 0;
bool g_heapEnumerationCacheValid = false;

std::atomic<bool> g_initialized{false};
std::atomic<bool> g_installed{false};
std::atomic<bool> g_allExportsInstalled{false};
std::atomic<bool> g_hookClosing{false};
std::atomic<uint32_t> g_activeHookCalls{0};
std::atomic<uint32_t> g_processSecret{0};
std::atomic<StormTakeover::TakeoverMode> g_mode{
    StormTakeover::TakeoverMode::Large};
std::atomic<uint32_t> g_threshold{StormApi::kNativeLargeThreshold};
std::atomic<uint32_t> g_optionFlags{0};

std::atomic<uint64_t> g_apiCalls{0};
std::atomic<uint64_t> g_managedCalls{0};
std::atomic<uint64_t> g_nativeCalls{0};
std::atomic<uint64_t> g_fallbackCalls{0};
std::atomic<uint64_t> g_degradedCalls{0};
std::atomic<uint64_t> g_rejectedPointers{0};
std::atomic<uint64_t> g_failures{0};
std::atomic<uint32_t> g_liveBlocks{0};
std::atomic<uint64_t> g_blockEnumerationCalls{0};
std::atomic<uint64_t> g_blockEnumerationSnapshotBuilds{0};
std::atomic<uint64_t> g_heapEnumerationCalls{0};
std::atomic<uint64_t> g_heapEnumerationRebuilds{0};
std::atomic<uint64_t> g_heapDestroySnapshots{0};
std::atomic<uint64_t> g_heapDestroySnapshotBlocks{0};
std::atomic<uint64_t> g_heapDestroyBatchCalls{0};
std::atomic<uint64_t> g_heapDestroyBatchBlocks{0};
std::atomic<uint64_t> g_heapDestroyBatchFallbacks{0};
std::atomic<uint64_t> g_callerHeapCacheHits{0};
std::atomic<uint64_t> g_callerHeapCacheMisses{0};
std::atomic<uint64_t> g_callerHeapCacheBypasses{0};
std::atomic<uint64_t> g_callerHeapCacheSaturated{0};
std::atomic<uint64_t> g_heapIdSlotHintHits{0};
std::atomic<uint64_t> g_heapIdSlotHintMisses{0};
std::atomic<uint32_t> g_callerHeapCacheEntries{0};
std::atomic<uint32_t> g_lastHeapId{0};
std::atomic<uint32_t> g_lastStormFlags{0};
std::atomic<uint32_t> g_lastRequestedSize{0};
std::atomic<uint16_t> g_lastOrdinal{0};
std::atomic<uint8_t> g_lastRoute{0};
std::atomic<uint8_t> g_lastReason{0};
std::atomic<bool> g_directCallerHashEnabled{false};
std::atomic<uintptr_t> g_recentlyFreed[kRecentFreedCapacity]{};
#if defined(STORMBREAKER_TESTING)
std::atomic<bool> g_testingFastFreeEnabled{true};
std::atomic<bool> g_testingRegistryAccountingEnabled{true};
std::atomic<bool> g_testingMainRegistryAccountingEnabled{false};
std::atomic<bool> g_testingCallerSlotHintEnabled{true};
std::atomic<bool> g_testingDirectCallerByteTableEnabled{true};
std::atomic<bool> g_testingRecentFreedFibonacciHashEnabled{true};
std::atomic<uint32_t> g_testingCallerCacheWays{
    static_cast<uint32_t>(kCallerHeapCacheWays)};
std::atomic<uint32_t> g_testingCallerThreadCacheCapacity{
    static_cast<uint32_t>(kCallerThreadCacheCapacity)};
std::atomic<uint32_t> g_testingHeapIdSlotHintCapacity{
    static_cast<uint32_t>(kHeapIdSlotHintCapacity)};
std::atomic<bool> g_testingMainHeapPinEnabled{true};
std::atomic<bool> g_testingInPlaceReallocateEnabled{true};
std::atomic<uint32_t> g_testingHeapDestroyBatchSize{0};
std::atomic<bool> g_testingHeapDestroyTaggedSnapshotEnabled{false};
std::atomic<uint64_t> g_testingInPlaceReallocateAttempts{0};
std::atomic<uint64_t> g_testingInPlaceReallocateSuccesses{0};
std::atomic<uint64_t> g_testingInPlaceReallocateMisses{0};
#endif

thread_local uint32_t tls_hookDepth = 0;
CallerHeapCacheEntry g_callerHeapCache[kCallerHeapCacheCapacity]{};
SRWLOCK g_callerHeapCacheWriteLock = SRWLOCK_INIT;
thread_local uint32_t tls_callerHeapCachePendingHits = 0;
thread_local uint32_t tls_callerHeapCachePendingMisses = 0;
thread_local uint32_t tls_callerHeapCachePendingBypasses = 0;
thread_local uint32_t tls_callerHeapCachePendingSaturated = 0;
thread_local uint32_t tls_heapIdSlotHintPendingHits = 0;
thread_local uint32_t tls_heapIdSlotHintPendingMisses = 0;
thread_local CallerThreadCacheStorage tls_callerThreadCache;
thread_local HeapIdSlotHintStorage tls_heapIdSlotHints;
ModuleImageRange g_callerModuleRanges[3]{};

struct ManagedBlockEnumerationCache {
  void** pointers = nullptr;
  uint32_t capacity = 0;
  uint32_t count = 0;
  uint32_t heapId = 0;
  const void* exhaustedCursor = nullptr;
  bool valid = false;
};

thread_local ManagedBlockEnumerationCache tls_blockEnumeration{};

class ScopedHookDepth final {
public:
  ScopedHookDepth() noexcept {
#if STORMBREAKER_PINNED_RUNTIME || STORMBREAKER_BENCHMARK_PINNED_HOTPATH
    active_ = true;
    outermost_ = tls_hookDepth++ == 0;
#else
    if (g_hookClosing.load(std::memory_order_acquire)) {
      return;
    }
    g_activeHookCalls.fetch_add(1, std::memory_order_acq_rel);
    if (g_hookClosing.load(std::memory_order_acquire)) {
      g_activeHookCalls.fetch_sub(1, std::memory_order_release);
      return;
    }
    active_ = true;
    outermost_ = tls_hookDepth++ == 0;
#endif
  }
  ~ScopedHookDepth() noexcept {
    if (active_) {
      --tls_hookDepth;
#if !STORMBREAKER_PINNED_RUNTIME && !STORMBREAKER_BENCHMARK_PINNED_HOTPATH
      g_activeHookCalls.fetch_sub(1, std::memory_order_release);
#endif
    }
  }
  bool IsOutermost() const noexcept { return outermost_; }

private:
  bool active_ = false;
  bool outermost_ = false;
};

uint32_t Mix32(uint32_t value) noexcept {
  value ^= value >> 16;
  value *= 0x7FEB352Du;
  value ^= value >> 15;
  value *= 0x846CA68Bu;
  value ^= value >> 16;
  return value;
}

uint32_t PointerKey(const void* raw) noexcept {
  return Mix32(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(raw)) ^
               g_processSecret.load(std::memory_order_relaxed) ^
               0x51ED270Bu);
}

uint32_t DecodeHeapId(const void* raw, uint32_t encoded) noexcept {
  return encoded ^ PointerKey(raw);
}

uint8_t HeaderChecksum(const void* raw, uint32_t encodedHeapId,
                       uint32_t requestedSize, uint8_t meta) noexcept {
  const uint32_t pointerKey = PointerKey(raw);
  return static_cast<uint8_t>(Mix32(
      pointerKey ^ encodedHeapId ^ requestedSize ^
      (static_cast<uint32_t>(meta) << 24) ^ 0xA55A19C3u));
}

uint32_t LargeCookie(const void* raw, uint32_t encodedHeapId,
                     uint32_t requestedSize, uint8_t meta) noexcept {
  const uint32_t pointerKey = PointerKey(raw);
  return Mix32(pointerKey ^ encodedHeapId ^ requestedSize ^
               (static_cast<uint32_t>(meta) << 16) ^ 0xC001D00Du);
}

uint8_t HeaderChecksumWithKey(uint32_t pointerKey, uint32_t encodedHeapId,
                              uint32_t requestedSize, uint8_t meta) noexcept {
  return static_cast<uint8_t>(Mix32(
      pointerKey ^ encodedHeapId ^ requestedSize ^
      (static_cast<uint32_t>(meta) << 24) ^ 0xA55A19C3u));
}

uint32_t LargeCookieWithKey(uint32_t pointerKey, uint32_t encodedHeapId,
                            uint32_t requestedSize, uint8_t meta) noexcept {
  return Mix32(pointerKey ^ encodedHeapId ^ requestedSize ^
               (static_cast<uint32_t>(meta) << 16) ^ 0xC001D00Du);
}

uint8_t MetaFor(MemoryPool::BackendRoute route, uint32_t flags,
                bool canary, bool isSmall) noexcept {
  uint8_t meta = isSmall ? kSmallMarker : kLargeMarker;
  if (route == MemoryPool::BackendRoute::Mimalloc) {
    meta |= kMetaMimalloc;
  }
  if ((flags & StormApi::kFlagPersistent) != 0) {
    meta |= kMetaPersistent;
  }
  if ((flags & StormApi::kFlagSuppressLeakWarning) != 0) {
    meta |= kMetaSuppressLeak;
  }
  if (canary) {
    meta |= kMetaCanary;
  }
  return meta;
}

MemoryPool::BackendRoute RouteFromMeta(uint8_t meta) noexcept {
  return (meta & kMetaMimalloc) != 0
             ? MemoryPool::BackendRoute::Mimalloc
             : MemoryPool::BackendRoute::Tlsf;
}

StormBreaker::LeakProfiler::BackendRoute ProfilerRoute(
    MemoryPool::BackendRoute route) noexcept {
  switch (route) {
  case MemoryPool::BackendRoute::Tlsf:
    return StormBreaker::LeakProfiler::BackendRoute::Tlsf;
  case MemoryPool::BackendRoute::Mimalloc:
    return StormBreaker::LeakProfiler::BackendRoute::Mimalloc;
  default:
    return StormBreaker::LeakProfiler::BackendRoute::Unknown;
  }
}

void SaturatingSubtract(std::atomic<uint32_t>& value,
                        uint32_t amount) noexcept {
  uint32_t current = value.load(std::memory_order_relaxed);
  while (current != 0) {
    const uint32_t desired = current > amount ? current - amount : 0;
    if (value.compare_exchange_weak(current, desired,
                                    std::memory_order_relaxed)) {
      return;
    }
  }
}

size_t FreedSlot(const void* pointer) noexcept {
  const uintptr_t value = reinterpret_cast<uintptr_t>(pointer) >> 3;
#if defined(STORMBREAKER_TESTING)
  if (!g_testingRecentFreedFibonacciHashEnabled.load(
          std::memory_order_relaxed)) {
    return static_cast<size_t>(Mix32(static_cast<uint32_t>(value))) &
           (kRecentFreedCapacity - 1u);
  }
#endif
  return static_cast<size_t>(static_cast<uint32_t>(value) * 0x9E3779B9u >>
                             16u);
}

void RememberFreed(const void* pointer) noexcept {
  g_recentlyFreed[FreedSlot(pointer)].store(
      reinterpret_cast<uintptr_t>(pointer), std::memory_order_release);
}

void ForgetFreed(const void* pointer) noexcept {
  auto& slot = g_recentlyFreed[FreedSlot(pointer)];
  const uintptr_t value = reinterpret_cast<uintptr_t>(pointer);
  uintptr_t expected = slot.load(std::memory_order_relaxed);
  if (expected == value) {
    slot.compare_exchange_strong(expected, 0, std::memory_order_relaxed);
  }
}

bool WasRecentlyFreed(const void* pointer) noexcept {
  return pointer &&
         g_recentlyFreed[FreedSlot(pointer)].load(std::memory_order_acquire) ==
             reinterpret_cast<uintptr_t>(pointer);
}

bool IsSmallRequest(uint32_t requestedSize) noexcept {
  return requestedSize < StormApi::kNativeLargeThreshold;
}

bool IsProtectMemoryEnabled() noexcept {
  return (g_optionFlags.load(std::memory_order_relaxed) & kOptionProtect) != 0;
}

bool IsFillPatternEnabled() noexcept {
  return (g_optionFlags.load(std::memory_order_relaxed) &
          kOptionFillPattern) != 0;
}

bool IsDebugMemoryEnabled() noexcept {
  return (g_optionFlags.load(std::memory_order_relaxed) & kOptionDebug) != 0;
}

bool IsReallocShuffleEnabled() noexcept {
  if (!g_api.reallocShuffleEnabled) {
    return false;
  }
  __try {
    return *g_api.reallocShuffleEnabled != 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

bool DetailedAccountingEnabled() noexcept {
  return MemoryPool::IsLatencyTrackingEnabled() ||
         StormBreaker::LeakProfiler::IsEnabled();
}

bool MainRegistryAccountingEnabled() noexcept {
  bool enabled = DetailedAccountingEnabled();
#if defined(STORMBREAKER_TESTING)
  enabled = enabled || g_testingMainRegistryAccountingEnabled.load(
                           std::memory_order_relaxed);
#endif
  return enabled;
}

bool ShouldManage(uint32_t size) noexcept {
  return size >= g_threshold.load(std::memory_order_relaxed);
}

bool ParseTakeoverMode(StormTakeover::TakeoverMode* mode,
                       uint32_t* threshold) noexcept {
  char value[32]{};
  const DWORD length = GetEnvironmentVariableA(
      "STORMBREAKER_TAKEOVER_MODE", value, ARRAYSIZE(value));
  if (length == 0) {
    *mode = StormTakeover::TakeoverMode::Large;
    *threshold = StormApi::kNativeLargeThreshold;
    return true;
  }
  if (length >= ARRAYSIZE(value)) {
    return false;
  }
  if (_stricmp(value, "large") == 0) {
    *mode = StormTakeover::TakeoverMode::Large;
    *threshold = StormApi::kNativeLargeThreshold;
  } else if (_stricmp(value, "32k") == 0) {
    *mode = StormTakeover::TakeoverMode::Size32K;
    *threshold = 32u * 1024u;
  } else if (_stricmp(value, "8k") == 0) {
    *mode = StormTakeover::TakeoverMode::Size8K;
    *threshold = 8u * 1024u;
  } else if (_stricmp(value, "2k") == 0) {
    *mode = StormTakeover::TakeoverMode::Size2K;
    *threshold = 2u * 1024u;
  } else if (_stricmp(value, "256") == 0) {
    *mode = StormTakeover::TakeoverMode::Size256;
    *threshold = 256u;
  } else if (_stricmp(value, "full") == 0) {
    *mode = StormTakeover::TakeoverMode::Full;
    *threshold = 0;
  } else {
    return false;
  }
  return true;
}

uint32_t GenerateSecret() noexcept {
  uint32_t secret = 0;
  if (BCRYPT_SUCCESS(BCryptGenRandom(
          nullptr, reinterpret_cast<PUCHAR>(&secret), sizeof(secret),
          BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
      secret != 0) {
    return secret;
  }
  LARGE_INTEGER counter{};
  QueryPerformanceCounter(&counter);
  secret = Mix32(counter.LowPart ^ counter.HighPart ^ GetCurrentThreadId() ^
                 static_cast<uint32_t>(
                     reinterpret_cast<uintptr_t>(&GenerateSecret)));
  return secret != 0 ? secret : 0x6D2B79F5u;
}

void RefreshOptionsFromStorm() noexcept {
  uint32_t options = 0;
  __try {
    if (g_api.debugMemoryEnabled && *g_api.debugMemoryEnabled) {
      options |= kOptionDebug;
    }
    if (g_api.errorHandlingEnabled && *g_api.errorHandlingEnabled) {
      options |= kOptionErrorHandling;
    }
    if (g_api.protectMemoryEnabled && *g_api.protectMemoryEnabled) {
      options |= kOptionProtect;
    }
    if (g_api.fillPatternEnabled && *g_api.fillPatternEnabled) {
      options |= kOptionFillPattern;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    options = 0;
  }
  g_optionFlags.store(options, std::memory_order_release);
}

void NoteCall(uint16_t ordinal, uint32_t heapId, uint32_t flags,
              StormBreaker::LeakProfiler::BackendRoute route,
              StormBreaker::LeakProfiler::DegradedReason reason,
              bool managed, bool fallback, bool degraded,
              uint32_t requestedSize = 0) noexcept {
  if (!fallback && !degraded && !DetailedAccountingEnabled()) {
    return;
  }
  g_apiCalls.fetch_add(1, std::memory_order_relaxed);
  (managed ? g_managedCalls : g_nativeCalls)
      .fetch_add(1, std::memory_order_relaxed);
  if (fallback) {
    g_fallbackCalls.fetch_add(1, std::memory_order_relaxed);
  }
  if (degraded) {
    g_degradedCalls.fetch_add(1, std::memory_order_relaxed);
    g_registry.MarkDegraded();
  }
  g_lastHeapId.store(heapId, std::memory_order_relaxed);
  g_lastStormFlags.store(flags, std::memory_order_relaxed);
  g_lastRequestedSize.store(requestedSize, std::memory_order_relaxed);
  g_lastOrdinal.store(ordinal, std::memory_order_relaxed);
  g_lastRoute.store(static_cast<uint8_t>(route), std::memory_order_relaxed);
  g_lastReason.store(static_cast<uint8_t>(reason), std::memory_order_relaxed);
}

StormBreaker::LeakProfiler::EventMetadata MakeMetadata(
    uint32_t heapId, uint32_t flags, uint16_t ordinal,
    StormBreaker::LeakProfiler::BackendRoute route,
    StormBreaker::LeakProfiler::DegradedReason reason =
        StormBreaker::LeakProfiler::DegradedReason::None,
    bool fallback = false, bool degraded = false) noexcept {
  StormBreaker::LeakProfiler::EventMetadata metadata{};
  metadata.heapId = heapId;
  metadata.stormFlags = flags;
  metadata.exportedOrdinal = ordinal;
  metadata.route = route;
  metadata.reason = reason;
  const uint8_t disposition = static_cast<uint8_t>(fallback ? 1u : 0u) |
                              static_cast<uint8_t>(degraded ? 2u : 0u);
  metadata.disposition =
      static_cast<StormBreaker::LeakProfiler::EventDisposition>(disposition);
  return metadata;
}

bool DecodeRawHeader(void* raw, MemoryPool::BackendRoute route,
                     ManagedBlock* output) noexcept {
  if (!raw || !output) {
    return false;
  }
  ManagedBlock block{};
  block.raw = raw;
  block.route = route;

  __try {
    auto* smallHeader = static_cast<SmallManagedHeader*>(raw);
    if ((smallHeader->meta & kMetaMarkerMask) == kSmallMarker &&
        RouteFromMeta(smallHeader->meta) == route &&
        smallHeader->requestedSize < StormApi::kNativeLargeThreshold &&
        smallHeader->checksum ==
            HeaderChecksum(raw, smallHeader->encodedHeapId,
                           smallHeader->requestedSize, smallHeader->meta)) {
      block.user = smallHeader + 1;
      block.heapId = DecodeHeapId(raw, smallHeader->encodedHeapId);
      block.requestedSize = smallHeader->requestedSize;
      block.headerSize = sizeof(*smallHeader);
      block.meta = smallHeader->meta;
      block.isSmall = true;
    }

    if (!block.user) {
      auto* large = static_cast<LargeManagedHeader*>(raw);
      if ((large->meta & kMetaMarkerMask) != kLargeMarker ||
          RouteFromMeta(large->meta) != route ||
          large->requestedSize < StormApi::kNativeLargeThreshold ||
          large->rejectTag != kRejectTag ||
          large->cookie != LargeCookie(raw, large->encodedHeapId,
                                       large->requestedSize, large->meta) ||
          large->checksum != HeaderChecksum(raw, large->encodedHeapId,
                                             large->requestedSize,
                                             large->meta)) {
        return false;
      }
      block.user = large + 1;
      block.heapId = DecodeHeapId(raw, large->encodedHeapId);
      block.requestedSize = large->requestedSize;
      block.headerSize = sizeof(*large);
      block.meta = large->meta;
      block.isSmall = false;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }

  if (!block.user || block.heapId == 0 ||
      block.heapId == StormHeapRegistry::kInvalidHeapId) {
    return false;
  }
  block.persistent = (block.meta & kMetaPersistent) != 0;
  block.suppressLeakWarning = (block.meta & kMetaSuppressLeak) != 0;
  block.canary = (block.meta & kMetaCanary) != 0;
  *output = block;
  return true;
}

bool DecodeRawAllocation(void* raw, size_t usableSize,
                         MemoryPool::BackendRoute route,
                         ManagedBlock* output) noexcept {
  ManagedBlock block{};
  if (!DecodeRawHeader(raw, route, &block)) {
    return false;
  }
  const size_t tailSize = block.canary ? 2u : 0u;
  const size_t maximum = (std::numeric_limits<size_t>::max)();
  if (block.headerSize > maximum - tailSize ||
      block.requestedSize > maximum - block.headerSize - tailSize) {
    return false;
  }
  const size_t required =
      block.headerSize + block.requestedSize + tailSize;
  if (usableSize < required) {
    return false;
  }
  block.physicalUsableSize = usableSize;
  const size_t nonPayload = block.headerSize + (block.canary ? 2u : 0u);
  block.payloadUsableSize = usableSize > nonPayload
                                ? usableSize - nonPayload
                                : block.requestedSize;
  *output = block;
  return true;
}

bool TryDecodePointerHeader(const void* pointer,
                            ManagedBlock* output) noexcept {
  if (!pointer || !output || WasRecentlyFreed(pointer)) {
    return false;
  }
  const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
  const size_t headerSizes[] = {sizeof(SmallManagedHeader),
                                sizeof(LargeManagedHeader)};
  for (size_t headerSize : headerSizes) {
    if (address < headerSize) {
      continue;
    }
    void* raw = reinterpret_cast<void*>(address - headerSize);
    uint8_t meta = 0;
    bool markerMatches = false;
    __try {
      meta = headerSize == sizeof(SmallManagedHeader)
                 ? static_cast<SmallManagedHeader*>(raw)->meta
                 : static_cast<LargeManagedHeader*>(raw)->meta;
      const uint8_t expected = headerSize == sizeof(SmallManagedHeader)
                                   ? kSmallMarker
                                   : kLargeMarker;
      markerMatches = (meta & kMetaMarkerMask) == expected;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      markerMatches = false;
    }
    if (!markerMatches) {
      continue;
    }
    ManagedBlock candidate{};
    if (DecodeRawHeader(raw, RouteFromMeta(meta), &candidate) &&
        candidate.user == pointer) {
      *output = candidate;
      return true;
    }
  }
  return false;
}

StormTakeover::BlockQueryResult QueryPointerImpl(
    const void* pointer, ManagedBlock* output) noexcept {
  if (output) {
    *output = {};
  }
  if (!pointer) {
    return StormTakeover::BlockQueryResult::Native;
  }
  if (WasRecentlyFreed(pointer)) {
    return StormTakeover::BlockQueryResult::Rejected;
  }

  const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
  const size_t headerSizes[] = {sizeof(SmallManagedHeader),
                                sizeof(LargeManagedHeader)};
  bool sawOwnedCandidate = false;
  for (size_t headerSize : headerSizes) {
    if (address < headerSize) {
      continue;
    }
    void* raw = reinterpret_cast<void*>(address - headerSize);
    uint8_t meta = 0;
    bool markerMatches = false;
    __try {
      meta =
          headerSize == sizeof(SmallManagedHeader)
              ? static_cast<SmallManagedHeader*>(raw)->meta
              : static_cast<LargeManagedHeader*>(raw)->meta;
      const uint8_t expected = headerSize == sizeof(SmallManagedHeader)
                                   ? kSmallMarker
                                   : kLargeMarker;
      markerMatches = (meta & kMetaMarkerMask) == expected;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      markerMatches = false;
    }
    if (!markerMatches) {
      continue;
    }
    MemoryPool::AllocationOwnership ownership{};
    if (!MemoryPool::QueryAllocation(raw, RouteFromMeta(meta), &ownership)) {
      continue;
    }
    sawOwnedCandidate = true;
    ManagedBlock candidate{};
    if (DecodeRawAllocation(raw, ownership.usableSize, ownership.route,
                            &candidate) &&
        candidate.user == pointer) {
      if (output) {
        *output = candidate;
      }
      return StormTakeover::BlockQueryResult::Managed;
    }
  }

  if (sawOwnedCandidate || MemoryPool::OwnsAddress(pointer, nullptr)) {
    return StormTakeover::BlockQueryResult::Rejected;
  }
  return StormTakeover::BlockQueryResult::Native;
}

inline void WriteManagedHeaderUnchecked(
    ManagedBlock* block, bool isSmall, bool canary, uint32_t requestedSize,
    uint32_t encoded, uint32_t pointerKey, uint8_t meta) noexcept {
  if (isSmall) {
    auto* header = static_cast<SmallManagedHeader*>(block->raw);
    header->encodedHeapId = encoded;
    header->requestedSize = static_cast<uint16_t>(requestedSize);
    header->meta = meta;
    header->checksum =
        HeaderChecksumWithKey(pointerKey, encoded, requestedSize, meta);
    block->headerSize = sizeof(*header);
    block->user = header + 1;
  } else {
    auto* header = static_cast<LargeManagedHeader*>(block->raw);
    header->encodedHeapId = encoded;
    header->requestedSize = requestedSize;
    header->meta = meta;
    header->cookie =
        LargeCookieWithKey(pointerKey, encoded, requestedSize, meta);
    header->checksum =
        HeaderChecksumWithKey(pointerKey, encoded, requestedSize, meta);
    header->rejectTag = kRejectTag;
    block->headerSize = sizeof(*header);
    block->user = header + 1;
  }
  if (canary) {
    *reinterpret_cast<uint16_t*>(
        static_cast<uint8_t*>(block->user) + requestedSize) = kTailCanary;
  }
}

bool WriteManagedHeader(ManagedBlock* block, uint32_t heapId,
                        uint32_t requestedSize, uint32_t flags,
                        bool preserveMetaFlags) noexcept {
  if (!block || !block->raw) {
    return false;
  }
  const bool isSmall = IsSmallRequest(requestedSize);
  const bool canary = preserveMetaFlags
                          ? block->canary
                          : IsDebugMemoryEnabled();
  const uint32_t storedFlags = preserveMetaFlags
                                   ? ((block->persistent
                                           ? StormApi::kFlagPersistent
                                           : 0u) |
                                      (block->suppressLeakWarning
                                           ? StormApi::kFlagSuppressLeakWarning
                                           : 0u))
                                   : flags;
  const uint8_t meta =
      MetaFor(block->route, storedFlags, canary, isSmall);
  const uint32_t pointerKey = PointerKey(block->raw);
  const uint32_t encoded = heapId ^ pointerKey;

#if STORMBREAKER_PINNED_RUNTIME || STORMBREAKER_BENCHMARK_PINNED_HOTPATH
  WriteManagedHeaderUnchecked(block, isSmall, canary, requestedSize, encoded,
                              pointerKey, meta);
#else
  __try {
    WriteManagedHeaderUnchecked(block, isSmall, canary, requestedSize, encoded,
                                pointerKey, meta);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
#endif

  block->heapId = heapId;
  block->requestedSize = requestedSize;
  block->meta = meta;
  block->isSmall = isSmall;
  block->persistent = (meta & kMetaPersistent) != 0;
  block->suppressLeakWarning = (meta & kMetaSuppressLeak) != 0;
  block->canary = canary;
  const size_t nonPayload = block->headerSize + (canary ? 2u : 0u);
  block->payloadUsableSize = block->physicalUsableSize > nonPayload
                                 ? block->physicalUsableSize - nonPayload
                                 : requestedSize;
  return true;
}

ManagedAllocation AllocateManagedRaw(uint32_t heapId, uint32_t size,
                                     uint32_t flags) noexcept {
  ManagedAllocation result{};
  const bool isSmall = IsSmallRequest(size);
  const bool canary = IsDebugMemoryEnabled();
  const size_t headerSize =
      isSmall ? sizeof(SmallManagedHeader) : sizeof(LargeManagedHeader);
  const size_t tailSize = canary ? 2u : 0u;
  if (size > (std::numeric_limits<size_t>::max)() - headerSize - tailSize) {
    return result;
  }
  const size_t physicalSize = headerSize + size + tailSize;
  MemoryPool::RoutedAllocation allocation = MemoryPool::AllocateRouted(
      physicalSize, size, isSmall ? 8u : 16u,
      MemoryPool::BackendRoute::Automatic);
  if (!allocation.pointer) {
    return result;
  }

  ManagedBlock block{};
  block.raw = allocation.pointer;
  block.physicalUsableSize = allocation.usableSize;
  block.route = allocation.route;
  if (!WriteManagedHeader(&block, heapId, size, flags, false)) {
    MemoryPool::FreeRouted(allocation.pointer, size, allocation.route, nullptr);
    return result;
  }
  ForgetFreed(block.user);
#if STORMBREAKER_PINNED_RUNTIME || STORMBREAKER_BENCHMARK_PINNED_HOTPATH
  if ((flags & StormApi::kFlagZeroMemory) != 0) {
    memset(block.user, 0, size);
  } else if (IsFillPatternEnabled()) {
    memset(block.user, 0xEE, size);
  }
#else
  __try {
    if ((flags & StormApi::kFlagZeroMemory) != 0) {
      memset(block.user, 0, size);
    } else if (IsFillPatternEnabled()) {
      memset(block.user, 0xEE, size);
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    MemoryPool::FreeRouted(block.raw, size, block.route, nullptr);
    return result;
  }
#endif
  result.pointer = block.user;
  result.block = block;
  return result;
}

bool ValidateCanary(const ManagedBlock& block) noexcept {
  if (!block.canary) {
    return true;
  }
  __try {
    return *reinterpret_cast<const uint16_t*>(
               static_cast<const uint8_t*>(block.user) +
               block.requestedSize) == kTailCanary;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

void PoisonAndFill(const ManagedBlock& block) noexcept {
  __try {
    if (IsFillPatternEnabled() && block.requestedSize != 0) {
      memset(block.user, 0xDD, block.requestedSize);
    }
    memset(block.raw, 0xD3, block.headerSize);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}

bool ValidateAndPoisonManagedFree(void* raw, size_t usableSize,
                                  void* context) noexcept {
  auto* validation =
      static_cast<ConditionalManagedFreeContext*>(context);
  ManagedBlock block{};
  if (!validation ||
      !DecodeRawAllocation(raw, usableSize, validation->route, &block) ||
      block.user != validation->expectedUser) {
    return false;
  }
  if (!ValidateCanary(block)) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
  PoisonAndFill(block);
  validation->block = block;
  return true;
}

bool FreeManagedRaw(const ManagedBlock& block) noexcept {
  if (!ValidateCanary(block)) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
  RememberFreed(block.user);
  PoisonAndFill(block);
  return MemoryPool::FreeRouted(block.raw, block.requestedSize, block.route,
                                nullptr);
}

void AccountAllocation(StormHeapRegistry::Registry::OperationGuard& guard,
                       const ManagedBlock& block) noexcept {
#if defined(STORMBREAKER_TESTING)
  if (!g_testingRegistryAccountingEnabled.load(std::memory_order_relaxed)) {
    g_liveBlocks.fetch_add(1, std::memory_order_relaxed);
    return;
  }
#endif
  const bool trackMain = MainRegistryAccountingEnabled();
  if (guard.GetKind() == StormHeapRegistry::HeapKind::Explicit ||
      trackMain) {
    guard.RecordAllocation(block.requestedSize, block.payloadUsableSize);
  }
  g_liveBlocks.fetch_add(1, std::memory_order_relaxed);
}

void AccountFree(StormHeapRegistry::Registry::OperationGuard& guard,
                 const ManagedBlock& block) noexcept {
#if defined(STORMBREAKER_TESTING)
  if (!g_testingRegistryAccountingEnabled.load(std::memory_order_relaxed)) {
    SaturatingSubtract(g_liveBlocks, 1);
    return;
  }
#endif
  const bool trackMain = MainRegistryAccountingEnabled();
  if (guard.GetKind() == StormHeapRegistry::HeapKind::Explicit ||
      trackMain) {
    guard.RecordFree(block.requestedSize, block.payloadUsableSize);
  }
  SaturatingSubtract(g_liveBlocks, 1);
}

void AccountReallocation(StormHeapRegistry::Registry::OperationGuard& guard,
                         const ManagedBlock& oldBlock,
                         const ManagedBlock& newBlock) noexcept {
#if defined(STORMBREAKER_TESTING)
  if (!g_testingRegistryAccountingEnabled.load(std::memory_order_relaxed)) {
    return;
  }
#endif
  const bool trackMain = MainRegistryAccountingEnabled();
  if (guard.GetKind() == StormHeapRegistry::HeapKind::Explicit ||
      trackMain) {
    guard.RecordReallocation(
        oldBlock.requestedSize, oldBlock.payloadUsableSize,
        newBlock.requestedSize, newBlock.payloadUsableSize);
  }
}

StormHeapRegistry::AccessResult AcquireHeap(
    uint32_t heapId, bool createMain, const char* name, uint32_t line,
    StormHeapRegistry::Registry::OperationGuard* guard,
    StormHeapRegistry::SlotHint* registrySlotHint = nullptr) noexcept {
#if defined(STORMBREAKER_TESTING)
  const bool pinGeneration =
      !StormHeapRegistry::IsMainHeapId(heapId) ||
      g_testingMainHeapPinEnabled.load(std::memory_order_relaxed);
#else
  constexpr bool pinGeneration = true;
#endif
  for (uint32_t wait = 0;; ++wait) {
    StormHeapRegistry::AccessResult result =
        createMain
            ? g_registry.AcquireOrCreateMain(heapId, name, line, guard,
                                             nullptr, registrySlotHint,
                                             pinGeneration)
            : g_registry.Acquire(heapId, guard, pinGeneration);
    if (result != StormHeapRegistry::AccessResult::Destroying) {
      return result;
    }
    if ((wait & 63u) == 63u) {
      Sleep(0);
    } else {
      YieldProcessor();
    }
  }
}

FastFreeResult TryFastManagedFree(void* pointer, uint32_t expectedHeapId,
                                  bool enforceHeapId) noexcept {
  FastFreeResult result{};
#if defined(STORMBREAKER_TESTING)
  if (!g_testingFastFreeEnabled.load(std::memory_order_relaxed)) {
    return result;
  }
#endif
  ManagedBlock candidate{};
  if (!TryDecodePointerHeader(pointer, &candidate)) {
    return result;
  }
  if (enforceHeapId && candidate.heapId != expectedHeapId) {
    result.disposition = FastFreeDisposition::Rejected;
    return result;
  }

  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access =
      AcquireHeap(candidate.heapId, false, nullptr, 0, &guard);
  if (access != StormHeapRegistry::AccessResult::Managed) {
    if (MemoryPool::OwnsAddress(candidate.raw, nullptr)) {
      result.disposition = FastFreeDisposition::Rejected;
    }
    return result;
  }

  ConditionalManagedFreeContext validation{};
  validation.expectedUser = pointer;
  validation.route = candidate.route;
  if (!MemoryPool::FreeRoutedConditional(
          candidate.raw, candidate.requestedSize, candidate.route,
          &ValidateAndPoisonManagedFree, &validation, nullptr)) {
    result.disposition = FastFreeDisposition::Rejected;
    return result;
  }
  RememberFreed(pointer);
  AccountFree(guard, validation.block);
  result.disposition = FastFreeDisposition::Freed;
  result.block = validation.block;
  return result;
}

bool SafeCopy(void* destination, const void* source, size_t size) noexcept {
  if (size == 0) {
    return true;
  }
  __try {
    memcpy(destination, source, size);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

void FillReallocGrowth(void* pointer, uint32_t oldSize, uint32_t newSize,
                       uint32_t flags) noexcept {
  if (!pointer || newSize <= oldSize) {
    return;
  }
  __try {
    uint8_t* tail = static_cast<uint8_t*>(pointer) + oldSize;
    const size_t growth = newSize - oldSize;
    if ((flags & StormApi::kFlagZeroMemory) != 0) {
      memset(tail, 0, growth);
    } else if (IsFillPatternEnabled()) {
      memset(tail, 0xEE, growth);
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
}

// SEH wrappers contain no C++ objects with destructors.
void* CallNativeAlloc(int ecx, int edx, uint32_t size,
                      const char* sourceFile, int32_t sourceLine,
                      uint32_t flags) noexcept {
  __try {
    return g_api.alloc
               ? g_api.alloc(ecx, edx, size, sourceFile, sourceLine, flags)
               : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
}

int CallNativeFree(void* pointer, const char* sourceFile, int32_t sourceLine,
                   uint32_t flags) noexcept {
  __try {
    return g_api.free
               ? g_api.free(pointer, sourceFile, sourceLine, flags)
               : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

int CallNativeGetSize(const void* pointer, const char* sourceFile,
                      int32_t sourceLine) noexcept {
  __try {
    return g_api.getSize ? g_api.getSize(pointer, sourceFile, sourceLine) : -1;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return -1;
  }
}

void* CallNativeReAlloc(int ecx, int edx, void* pointer, uint32_t newSize,
                        const char* sourceFile, int32_t sourceLine,
                        uint32_t flags) noexcept {
  __try {
    return g_api.reAlloc ? g_api.reAlloc(ecx, edx, pointer, newSize,
                                         sourceFile, sourceLine, flags)
                         : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
}

uint32_t CallNativeGetHeapByCaller(const char* sourceFile,
                                   int32_t sourceLine) noexcept {
  __try {
    return g_api.getHeapByCaller
               ? g_api.getHeapByCaller(sourceFile, sourceLine)
               : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

uint32_t ComputeDirectCallerHeap(const char* sourceFile, int32_t sourceLine,
                                 bool* succeeded) noexcept {
  // Storm ordinal 483 calls Storm_502(name, case-sensitive, line), masks the
  // result to 31 bits, and maps zero to one. These constants are the verified
  // 1.27a table at Storm RVA 0x43F18.
#if defined(STORMBREAKER_TESTING)
  const bool useByteTable =
      g_testingDirectCallerByteTableEnabled.load(std::memory_order_relaxed);
#endif
  if (succeeded) {
    *succeeded = false;
  }
  uint32_t result = 0;
  __try {
    if (!sourceFile) {
      result = static_cast<uint32_t>(sourceLine) & 0x7FFFFFFFu;
    } else {
      uint32_t primary = sourceLine != 0
                             ? static_cast<uint32_t>(sourceLine)
                             : 0x7FED7FEDu;
      uint32_t secondary = 0xEEEEEEEEu;
      const auto* cursor =
          reinterpret_cast<const unsigned char*>(sourceFile);
      for (uint32_t value = *cursor; value != 0; value = *++cursor) {
#if defined(STORMBREAKER_TESTING)
        const uint32_t byteDelta =
            useByteTable
                ? kStormCallerHashByteTable[value]
                : kStormCallerHashNibbleTable[value >> 4u] -
                      kStormCallerHashNibbleTable[value & 0x0Fu];
#else
        const uint32_t byteDelta = kStormCallerHashByteTable[value];
#endif
        primary = byteDelta ^ (secondary + primary);
        secondary += value + 32u * secondary + primary + 3u;
      }
      result = primary & 0x7FFFFFFFu;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
  if (succeeded) {
    *succeeded = true;
  }
  return result != 0 ? result : 1u;
}

uint32_t ComputeOrCallNativeCallerHeap(const char* sourceFile,
                                       int32_t sourceLine) noexcept {
  if (g_directCallerHashEnabled.load(std::memory_order_relaxed)) {
    bool succeeded = false;
    const uint32_t heapId =
        ComputeDirectCallerHeap(sourceFile, sourceLine, &succeeded);
    if (succeeded) {
      return heapId;
    }
  }
  return CallNativeGetHeapByCaller(sourceFile, sourceLine);
}

bool ValidateDirectCallerHash(
    const StormApi::ResolvedApi& api) noexcept {
  if (!api.getHeapByCaller) {
    return false;
  }
  static constexpr char kProbe[] = "StormBreakerCallerHashProbe";
  static constexpr char kMapProbe[] = "war3map.j";
  static constexpr char kHighByteProbe[] = {
      static_cast<char>(0x80), static_cast<char>(0xFE), 0};
  struct Probe {
    const char* name;
    int32_t line;
  };
  static constexpr Probe kProbes[] = {
      {nullptr, 0}, {nullptr, -1}, {"", 0},       {kProbe, 0},
      {kProbe, 1}, {kProbe, 42},  {kMapProbe, 123}, {kHighByteProbe, -7},
  };
  for (const Probe& probe : kProbes) {
    bool computed = false;
    const uint32_t expected =
        ComputeDirectCallerHeap(probe.name, probe.line, &computed);
    uint32_t native = 0;
    __try {
      native = api.getHeapByCaller(probe.name, probe.line);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return false;
    }
    if (!computed || native != expected) {
      Logger::GetInstance().LogWarning(
          "direct caller hash validation mismatch: line=%d direct=%08X "
          "native=%08X",
          probe.line, expected, native);
      return false;
    }
  }
  return true;
}

void NoteCallerCacheCounter(std::atomic<uint64_t>& counter,
                            uint32_t& pending) noexcept {
  ++pending;
  if (pending == kCallerCacheCounterBatch) {
    counter.fetch_add(kCallerCacheCounterBatch, std::memory_order_relaxed);
    pending = 0;
  }
}

ModuleImageRange GetModuleImageRange(HMODULE module) noexcept {
  ModuleImageRange range{};
  if (!module) {
    return range;
  }
  __try {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
      return range;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt->OptionalHeader.SizeOfImage == 0) {
      return range;
    }
    const uintptr_t begin = reinterpret_cast<uintptr_t>(module);
    const uintptr_t end = begin + nt->OptionalHeader.SizeOfImage;
    if (end > begin) {
      range.begin = begin;
      range.end = end;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    range = {};
  }
  return range;
}

void RefreshCallerModuleRanges(HMODULE stormModule,
                               HMODULE gameModule,
                               HMODULE hostModule) noexcept {
  g_callerModuleRanges[0] = GetModuleImageRange(stormModule);
  g_callerModuleRanges[1] = GetModuleImageRange(gameModule);
  g_callerModuleRanges[2] = GetModuleImageRange(hostModule);
}

size_t CallerHeapCacheWays() noexcept {
#if defined(STORMBREAKER_TESTING)
  return g_testingCallerCacheWays.load(std::memory_order_relaxed);
#else
  return kCallerHeapCacheWays;
#endif
}

size_t CallerThreadCacheCapacity() noexcept {
#if defined(STORMBREAKER_TESTING)
  return g_testingCallerThreadCacheCapacity.load(std::memory_order_relaxed);
#else
  return kCallerThreadCacheCapacity;
#endif
}

size_t HeapIdSlotHintCapacity() noexcept {
#if defined(STORMBREAKER_TESTING)
  return g_testingHeapIdSlotHintCapacity.load(std::memory_order_relaxed);
#else
  return kHeapIdSlotHintCapacity;
#endif
}

bool TryResolveHeapIdSlotHint(
    uint32_t heapId, StormHeapRegistry::SlotHint* outHint) noexcept {
  const size_t capacity = HeapIdSlotHintCapacity();
  if (!outHint || capacity == 0 || !tls_heapIdSlotHints.entries ||
      tls_heapIdSlotHints.capacity != capacity) {
    return false;
  }
  const HeapIdSlotHintEntry& entry =
      tls_heapIdSlotHints.entries[Mix32(heapId) & (capacity - 1u)];
  if (entry.heapId != heapId ||
      entry.hint.slot == StormHeapRegistry::kInvalidSlotHint ||
      entry.hint.registryEpoch == 0) {
    return false;
  }
  *outHint = entry.hint;
  return true;
}

void PublishHeapIdSlotHint(
    uint32_t heapId, const StormHeapRegistry::SlotHint& hint) noexcept {
  const size_t capacity = HeapIdSlotHintCapacity();
  if (heapId == 0 || hint.slot == StormHeapRegistry::kInvalidSlotHint ||
      hint.registryEpoch == 0 || capacity == 0 ||
      !tls_heapIdSlotHints.Ensure(capacity)) {
    return;
  }
  HeapIdSlotHintEntry& entry =
      tls_heapIdSlotHints.entries[Mix32(heapId) & (capacity - 1u)];
  entry.hint = hint;
  entry.heapId = heapId;
}

void InvalidateHeapIdSlotHint(uint32_t heapId) noexcept {
  const size_t capacity = HeapIdSlotHintCapacity();
  if (capacity == 0 || !tls_heapIdSlotHints.entries ||
      tls_heapIdSlotHints.capacity != capacity) {
    return;
  }
  HeapIdSlotHintEntry& entry =
      tls_heapIdSlotHints.entries[Mix32(heapId) & (capacity - 1u)];
  if (entry.heapId == heapId) {
    entry = {};
  }
}

uint32_t CallerHeapCacheHash(const char* sourceFile,
                             int32_t sourceLine) noexcept {
  const uint32_t pointer =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(sourceFile));
  const uint32_t line = static_cast<uint32_t>(sourceLine);
  return Mix32(pointer ^ (line * 0x9E3779B9u));
}

size_t CallerHeapCacheSetIndex(uint32_t hash, size_t ways) noexcept {
  const size_t setCount = kCallerHeapCacheCapacity / ways;
  return static_cast<size_t>(hash) & (setCount - 1u);
}

bool TryResolveThreadCaller(uint32_t hash, const char* sourceFile,
                            int32_t sourceLine, uint32_t* heapId,
                            CallerHeapCacheEntry** sharedEntry) noexcept {
  const size_t capacity = CallerThreadCacheCapacity();
  if (capacity == 0 || !tls_callerThreadCache.entries ||
      tls_callerThreadCache.capacity != capacity) {
    return false;
  }
  const CallerThreadCacheEntry& entry =
      tls_callerThreadCache.entries[hash & (capacity - 1u)];
  if (entry.heapId == 0 || entry.sourceFile != sourceFile ||
      entry.sourceLine != sourceLine) {
    return false;
  }
  *heapId = entry.heapId;
  if (sharedEntry) {
    *sharedEntry = entry.sharedEntry;
  }
  return true;
}

void PublishThreadCaller(uint32_t hash, const char* sourceFile,
                         int32_t sourceLine, uint32_t heapId,
                         CallerHeapCacheEntry* sharedEntry) noexcept {
  const size_t capacity = CallerThreadCacheCapacity();
  if (capacity == 0 || heapId == 0) {
    return;
  }
  if (!tls_callerThreadCache.Ensure(capacity)) {
    return;
  }
  CallerThreadCacheEntry& entry =
      tls_callerThreadCache.entries[hash & (capacity - 1u)];
  entry.sourceFile = sourceFile;
  entry.sourceLine = sourceLine;
  entry.heapId = heapId;
  entry.sharedEntry = sharedEntry;
}

bool IsCoreCallerName(const char* sourceFile) noexcept {
  if (!sourceFile) {
    return true;
  }
  const uintptr_t address = reinterpret_cast<uintptr_t>(sourceFile);
  bool inCoreImage = false;
  for (const ModuleImageRange& range : g_callerModuleRanges) {
    if (address >= range.begin && address < range.end) {
      inCoreImage = true;
      break;
    }
  }
  if (!inCoreImage) {
    return false;
  }
  return true;
}

bool IsImmutableCallerName(const char* sourceFile) noexcept {
  if (!IsCoreCallerName(sourceFile)) {
    return false;
  }
  if (!sourceFile) {
    return true;
  }
  MEMORY_BASIC_INFORMATION memory{};
  if (VirtualQuery(sourceFile, &memory, sizeof(memory)) != sizeof(memory) ||
      memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE ||
      (memory.Protect & PAGE_GUARD) != 0) {
    return false;
  }
  const DWORD protection = memory.Protect & 0xFFu;
  if (protection != PAGE_READONLY && protection != PAGE_EXECUTE_READ) {
    return false;
  }
  return true;
}

void ResetCallerHeapCache() noexcept {
  for (CallerHeapCacheEntry& entry : g_callerHeapCache) {
    entry.state.store(0, std::memory_order_relaxed);
    entry.sourceFile = nullptr;
    entry.sourceLine = 0;
    entry.heapId = 0;
    entry.registrySlot.store(StormHeapRegistry::kInvalidSlotHint,
                             std::memory_order_relaxed);
    entry.registryEpoch.store(0, std::memory_order_relaxed);
  }
  tls_callerHeapCachePendingHits = 0;
  tls_callerHeapCachePendingMisses = 0;
  tls_callerHeapCachePendingBypasses = 0;
  tls_callerHeapCachePendingSaturated = 0;
  tls_heapIdSlotHintPendingHits = 0;
  tls_heapIdSlotHintPendingMisses = 0;
  tls_callerThreadCache.Clear();
  tls_heapIdSlotHints.Clear();
}

uint32_t ResolveCallerHeap(
    const char* sourceFile, int32_t sourceLine,
    CallerHeapCacheEntry** outCacheEntry = nullptr) noexcept {
  if (outCacheEntry) {
    *outCacheEntry = nullptr;
  }
  const uint32_t hash = CallerHeapCacheHash(sourceFile, sourceLine);
  uint32_t threadHeapId = 0;
  if (TryResolveThreadCaller(hash, sourceFile, sourceLine, &threadHeapId,
                             outCacheEntry)) {
    NoteCallerCacheCounter(g_callerHeapCacheHits,
                           tls_callerHeapCachePendingHits);
    return threadHeapId;
  }
  if (!IsCoreCallerName(sourceFile)) {
    NoteCallerCacheCounter(g_callerHeapCacheMisses,
                           tls_callerHeapCachePendingMisses);
    NoteCallerCacheCounter(g_callerHeapCacheBypasses,
                           tls_callerHeapCachePendingBypasses);
    return ComputeOrCallNativeCallerHeap(sourceFile, sourceLine);
  }

  const size_t ways = CallerHeapCacheWays();
  const size_t set = CallerHeapCacheSetIndex(hash, ways);
  const size_t first = set * ways;
  for (size_t probe = 0; probe < ways; ++probe) {
    CallerHeapCacheEntry& entry = g_callerHeapCache[first + probe];
    const uint32_t state = entry.state.load(std::memory_order_acquire);
    if (state == 0) {
      break;
    }
    if (state == 2 && entry.sourceFile == sourceFile &&
        entry.sourceLine == sourceLine) {
      NoteCallerCacheCounter(g_callerHeapCacheHits,
                             tls_callerHeapCachePendingHits);
      if (outCacheEntry) {
        *outCacheEntry = &entry;
      }
      PublishThreadCaller(hash, sourceFile, sourceLine, entry.heapId, &entry);
      return entry.heapId;
    }
  }

  NoteCallerCacheCounter(g_callerHeapCacheMisses,
                         tls_callerHeapCachePendingMisses);
  const uint32_t heapId =
      ComputeOrCallNativeCallerHeap(sourceFile, sourceLine);
  if (heapId == 0 || !IsImmutableCallerName(sourceFile)) {
    NoteCallerCacheCounter(g_callerHeapCacheBypasses,
                           tls_callerHeapCachePendingBypasses);
    return heapId;
  }

  {
    AcquireSRWLockExclusive(&g_callerHeapCacheWriteLock);
    CallerHeapCacheEntry* insertion = nullptr;
    for (size_t probe = 0; probe < ways; ++probe) {
      CallerHeapCacheEntry& entry = g_callerHeapCache[first + probe];
      const uint32_t state = entry.state.load(std::memory_order_acquire);
      if (state == 2 && entry.sourceFile == sourceFile &&
          entry.sourceLine == sourceLine) {
        insertion = &entry;
        break;
      }
      if (state == 0) {
        insertion = &entry;
        entry.state.store(1, std::memory_order_relaxed);
        entry.sourceFile = sourceFile;
        entry.sourceLine = sourceLine;
        entry.heapId = heapId;
        entry.registrySlot.store(StormHeapRegistry::kInvalidSlotHint,
                                 std::memory_order_relaxed);
        entry.registryEpoch.store(0, std::memory_order_relaxed);
        entry.state.store(2, std::memory_order_release);
        g_callerHeapCacheEntries.fetch_add(1, std::memory_order_relaxed);
        break;
      }
    }
    if (insertion && insertion->state.load(std::memory_order_relaxed) == 2) {
      // Another thread may have published this immutable key while the
      // native trampoline was running. Prefer the first published value.
      const uint32_t publishedHeapId = insertion->heapId;
      if (outCacheEntry) {
        *outCacheEntry = insertion;
      }
      PublishThreadCaller(hash, sourceFile, sourceLine, publishedHeapId,
                          insertion);
      ReleaseSRWLockExclusive(&g_callerHeapCacheWriteLock);
      return publishedHeapId;
    }
    ReleaseSRWLockExclusive(&g_callerHeapCacheWriteLock);
    if (!insertion) {
      NoteCallerCacheCounter(g_callerHeapCacheSaturated,
                             tls_callerHeapCachePendingSaturated);
    }
  }
  PublishThreadCaller(hash, sourceFile, sourceLine, heapId, nullptr);
  return heapId;
}

StormHeapRegistry::AccessResult AcquireCallerHeap(
    uint32_t heapId, const char* name, uint32_t line,
    CallerHeapCacheEntry* cacheEntry,
    StormHeapRegistry::Registry::OperationGuard* guard) noexcept {
  StormHeapRegistry::SlotHint hint{};
  bool useSharedHint = cacheEntry != nullptr;
#if defined(STORMBREAKER_TESTING)
  useSharedHint = useSharedHint &&
                  g_testingCallerSlotHintEnabled.load(
                      std::memory_order_relaxed);
#endif
  if (useSharedHint) {
    const uint32_t epoch =
        cacheEntry->registryEpoch.load(std::memory_order_acquire);
    if (epoch != 0) {
      hint.slot = cacheEntry->registrySlot.load(std::memory_order_relaxed);
      hint.registryEpoch = epoch;
    }
  }

  const bool useHeapIdHint = cacheEntry == nullptr &&
                             HeapIdSlotHintCapacity() != 0;
  if (useHeapIdHint) {
    if (TryResolveHeapIdSlotHint(heapId, &hint)) {
      NoteCallerCacheCounter(g_heapIdSlotHintHits,
                             tls_heapIdSlotHintPendingHits);
    } else {
      NoteCallerCacheCounter(g_heapIdSlotHintMisses,
                             tls_heapIdSlotHintPendingMisses);
    }
  }

  const auto result = AcquireHeap(heapId, true, name, line, guard, &hint);
  const bool acquired = result == StormHeapRegistry::AccessResult::Managed ||
                        result == StormHeapRegistry::AccessResult::Native;
  if (useSharedHint && hint.slot != StormHeapRegistry::kInvalidSlotHint &&
      hint.registryEpoch != 0 &&
      acquired) {
    cacheEntry->registrySlot.store(hint.slot, std::memory_order_relaxed);
    cacheEntry->registryEpoch.store(hint.registryEpoch,
                                    std::memory_order_release);
  }
  if (useHeapIdHint) {
    if (acquired && hint.slot != StormHeapRegistry::kInvalidSlotHint &&
        hint.registryEpoch != 0) {
      PublishHeapIdSlotHint(heapId, hint);
    } else {
      InvalidateHeapIdSlotHint(heapId);
    }
  }
  return result;
}

uint32_t CallNativeGetHeapByPtr(const void* pointer) noexcept {
  __try {
    return g_api.getHeapByPtr ? g_api.getHeapByPtr(pointer) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

void* CallNativeHeapAlloc(uint32_t heapId, uint32_t flags,
                          uint32_t size) noexcept {
  __try {
    return g_api.heapAlloc ? g_api.heapAlloc(heapId, flags, size) : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
}

int CallNativeHeapFree(uint32_t heapId, uint32_t flags,
                       void* pointer) noexcept {
  __try {
    return g_api.heapFree ? g_api.heapFree(heapId, flags, pointer) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

int CallNativeHeapSize(uint32_t heapId, uint32_t flags,
                       const void* pointer) noexcept {
  __try {
    return g_api.heapSize ? g_api.heapSize(heapId, flags, pointer) : -1;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return -1;
  }
}

void* CallNativeHeapReAlloc(uint32_t heapId, uint32_t flags, void* pointer,
                            uint32_t newSize) noexcept {
  __try {
    return g_api.heapReAlloc
               ? g_api.heapReAlloc(heapId, flags, pointer, newSize)
               : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
}

struct NativeLargeInfo {
  bool valid = false;
  uint32_t requestedSize = 0;
  uint32_t correction = 0;
};

NativeLargeInfo QueryNativeLarge(const void* pointer) noexcept {
  NativeLargeInfo info{};
  if (!pointer || (reinterpret_cast<uintptr_t>(pointer) & 7u) != 0) {
    return info;
  }
  __try {
    const uint8_t* user = static_cast<const uint8_t*>(pointer);
    if ((*(user - 5) & 0x08u) == 0) {
      return info;
    }
    const uint16_t* arenaHeader =
        *reinterpret_cast<uint16_t* const*>(user - 12);
    if (!arenaHeader ||
        (*(reinterpret_cast<const uint8_t*>(arenaHeader) + 3) & 0x04u) == 0) {
      return info;
    }
    const uint32_t requested = *reinterpret_cast<const uint32_t*>(user - 16);
    const uint32_t nativeAccounted = *arenaHeader;
    if (requested < StormApi::kNativeLargeThreshold ||
        requested <= nativeAccounted) {
      return info;
    }
    info.valid = true;
    info.requestedSize = requested;
    info.correction = requested - nativeAccounted;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return {};
  }
  return info;
}

void SubtractNativeCounter(uint32_t amount) noexcept;

void ApplyNativeCounterCorrection(const NativeLargeInfo& info) noexcept {
  if (!info.valid || info.correction == 0) {
    return;
  }
  SubtractNativeCounter(info.correction);
}

void SubtractNativeCounter(uint32_t amount) noexcept {
  if (amount == 0 || !g_api.nativeAllocatedBytes) {
    return;
  }
  auto* counter = reinterpret_cast<volatile LONG*>(
      const_cast<uint32_t*>(g_api.nativeAllocatedBytes));
  __try {
    LONG observed = *counter;
    for (;;) {
      const uint32_t current = static_cast<uint32_t>(observed);
      const uint32_t desired =
          current > amount ? current - amount : 0;
      const LONG previous = InterlockedCompareExchange(
          counter, static_cast<LONG>(desired), observed);
      if (previous == observed) {
        return;
      }
      observed = previous;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
}

uint32_t SumNativeHeapRequested(uint32_t heapId,
                                bool* hasAllocated = nullptr) noexcept {
  if (hasAllocated) {
    *hasAllocated = false;
  }
  uint32_t total = 0;
  const void* cursor = nullptr;
  for (uint32_t iteration = 0; iteration < 1u << 20; ++iteration) {
    void* next = nullptr;
    StormApi::BlockInfo481 info{};
    info.structSize = sizeof(info);
    int found = 0;
    __try {
      found = g_api.findNextBlock
                  ? g_api.findNextBlock(heapId, cursor, &next, &info)
                  : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return total;
    }
    if (!found || !next || next == cursor) {
      break;
    }
    if (info.allocated && info.valid) {
      if (hasAllocated) {
        *hasAllocated = true;
      }
      total += info.requestedBytes;
    }
    cursor = next;
  }
  return total;
}

ReallocResult ReallocateManaged(
    const ManagedBlock& oldBlock,
    StormHeapRegistry::Registry::OperationGuard& guard, uint32_t newSize,
    uint32_t flags, bool heapApi, int ecx, int edx,
    const char* sourceFile, int32_t sourceLine) noexcept {
  ReallocResult result{};
  const bool sameHeaderKind = IsSmallRequest(newSize) == oldBlock.isSmall;
  const MemoryPool::BackendRoute newRoute = MemoryPool::SelectRoute(newSize);
  // Storm's external-large path always moves. Only native small blocks use
  // the grow/shrink-in-place path, so preserve that observable behavior.
  const bool canTryInPlace = oldBlock.isSmall && sameHeaderKind &&
                             newRoute == oldBlock.route &&
                             !IsReallocShuffleEnabled()
#if defined(STORMBREAKER_TESTING)
                             && g_testingInPlaceReallocateEnabled.load(
                                    std::memory_order_relaxed)
#endif
      ;

  if (canTryInPlace) {
#if defined(STORMBREAKER_TESTING)
    g_testingInPlaceReallocateAttempts.fetch_add(
        1, std::memory_order_relaxed);
#endif
    if (newSize == oldBlock.requestedSize) {
#if defined(STORMBREAKER_TESTING)
      g_testingInPlaceReallocateSuccesses.fetch_add(
          1, std::memory_order_relaxed);
#endif
      result.pointer = oldBlock.user;
      result.newBlock = oldBlock;
      result.succeeded = true;
      result.inPlace = true;
      result.newManaged = true;
      AccountReallocation(guard, oldBlock, oldBlock);
      return result;
    }

    const size_t newPhysicalSize = oldBlock.headerSize + newSize +
                                   (oldBlock.canary ? 2u : 0u);
    size_t newPhysicalUsable = 0;
    const auto status = MemoryPool::ReallocateInPlaceRouted(
        oldBlock.raw, oldBlock.requestedSize, newPhysicalSize, newSize,
        oldBlock.route, &newPhysicalUsable);
    if (status == MemoryPool::InPlaceReallocateStatus::Succeeded) {
#if defined(STORMBREAKER_TESTING)
      g_testingInPlaceReallocateSuccesses.fetch_add(
          1, std::memory_order_relaxed);
#endif
      ManagedBlock updated = oldBlock;
      updated.physicalUsableSize = newPhysicalUsable;
      FillReallocGrowth(updated.user, oldBlock.requestedSize, newSize, flags);
      if (!WriteManagedHeader(&updated, oldBlock.heapId, newSize, flags,
                              true)) {
        g_failures.fetch_add(1, std::memory_order_relaxed);
        return result;
      }
      AccountReallocation(guard, oldBlock, updated);
      result.pointer = updated.user;
      result.newBlock = updated;
      result.succeeded = true;
      result.inPlace = true;
      result.newManaged = true;
      return result;
    }
#if defined(STORMBREAKER_TESTING)
    g_testingInPlaceReallocateMisses.fetch_add(
        1, std::memory_order_relaxed);
#endif
  }

  if ((flags & StormApi::kFlagNoMove) != 0) {
    return result;
  }

  const bool targetManaged = ShouldManage(newSize) &&
                             !IsProtectMemoryEnabled();
  if (targetManaged) {
    // Native Storm allocates moved realloc targets with allocation flags zero;
    // only the grown tail observes realloc's zero/fill flags.
    ManagedAllocation replacement =
        AllocateManagedRaw(oldBlock.heapId, newSize, 0);
    if (replacement.pointer) {
      if (!SafeCopy(replacement.pointer, oldBlock.user,
                    (std::min)(oldBlock.requestedSize, newSize))) {
        FreeManagedRaw(replacement.block);
        return result;
      }
      FillReallocGrowth(replacement.pointer, oldBlock.requestedSize, newSize,
                        flags);
      if (!FreeManagedRaw(oldBlock)) {
        FreeManagedRaw(replacement.block);
        return result;
      }
      AccountReallocation(guard, oldBlock, replacement.block);
      result.pointer = replacement.pointer;
      result.newBlock = replacement.block;
      result.succeeded = true;
      result.oldFreed = true;
      result.newAllocated = true;
      result.newManaged = true;
      return result;
    }
  }

  void* nativeReplacement =
      heapApi ? CallNativeHeapAlloc(oldBlock.heapId, 0, newSize)
              : CallNativeAlloc(ecx, edx, newSize, sourceFile, sourceLine, 0);
  if (!nativeReplacement) {
    return result;
  }
  if (!SafeCopy(nativeReplacement, oldBlock.user,
                (std::min)(oldBlock.requestedSize, newSize))) {
    if (heapApi) {
      CallNativeHeapFree(oldBlock.heapId, 0, nativeReplacement);
    } else {
      CallNativeFree(nativeReplacement, sourceFile, sourceLine, 0);
    }
    return result;
  }
  FillReallocGrowth(nativeReplacement, oldBlock.requestedSize, newSize, flags);
  if (!FreeManagedRaw(oldBlock)) {
    if (heapApi) {
      CallNativeHeapFree(oldBlock.heapId, 0, nativeReplacement);
    } else {
      CallNativeFree(nativeReplacement, sourceFile, sourceLine, 0);
    }
    return result;
  }
  AccountFree(guard, oldBlock);
  result.pointer = nativeReplacement;
  result.succeeded = true;
  result.oldFreed = true;
  result.newAllocated = true;
  result.newManaged = false;
  return result;
}

bool TryMigrateNativeToManaged(
    void* oldPointer, uint32_t oldSize, uint32_t newSize, uint32_t flags,
    uint32_t heapId, bool heapApi,
    const char* sourceFile, int32_t sourceLine,
    StormHeapRegistry::Registry::OperationGuard& guard,
    ReallocResult* output) noexcept {
  if (!output || (flags & StormApi::kFlagNoMove) != 0 ||
      IsProtectMemoryEnabled() || !ShouldManage(newSize)) {
    return false;
  }
  ManagedAllocation replacement = AllocateManagedRaw(heapId, newSize, 0);
  if (!replacement.pointer) {
    return false;
  }
  if (!SafeCopy(replacement.pointer, oldPointer,
                (std::min)(oldSize, newSize))) {
    FreeManagedRaw(replacement.block);
    return false;
  }
  FillReallocGrowth(replacement.pointer, oldSize, newSize, flags);

  const NativeLargeInfo largeInfo = QueryNativeLarge(oldPointer);
  const int freed = heapApi
                        ? CallNativeHeapFree(heapId, 0, oldPointer)
                        : CallNativeFree(oldPointer, sourceFile, sourceLine, 0);
  if (!freed) {
    FreeManagedRaw(replacement.block);
    return false;
  }
  ApplyNativeCounterCorrection(largeInfo);
  AccountAllocation(guard, replacement.block);
  output->pointer = replacement.pointer;
  output->newBlock = replacement.block;
  output->succeeded = true;
  output->oldFreed = true;
  output->newAllocated = true;
  output->newManaged = true;
  return true;
}

struct ManagedSnapshotCollectContext {
  uint32_t heapId;
  void** pointers;
  uint32_t capacity;
  uint32_t count;
  bool overflow;
};

bool CollectManagedSnapshotVisitor(void* raw, size_t usable,
                                   MemoryPool::BackendRoute route,
                                   void* context) noexcept {
  auto* collect = static_cast<ManagedSnapshotCollectContext*>(context);
  ManagedBlock block{};
  if (!DecodeRawAllocation(raw, usable, route, &block) ||
      block.heapId != collect->heapId) {
    return true;
  }
  if (collect->count == collect->capacity) {
    collect->overflow = true;
    return false;
  }
  collect->pointers[collect->count++] = block.user;
  return true;
}

void ReleaseManagedBlockEnumeration() noexcept {
  if (tls_blockEnumeration.pointers) {
    VirtualFree(tls_blockEnumeration.pointers, 0, MEM_RELEASE);
  }
  tls_blockEnumeration = {};
}

bool BuildManagedBlockEnumeration(uint32_t heapId) noexcept {
  ReleaseManagedBlockEnumeration();
  const uint32_t capacity = (std::max)(
      1u, g_liveBlocks.load(std::memory_order_acquire));
  if (capacity > (std::numeric_limits<size_t>::max)() / sizeof(void*)) {
    return false;
  }
  void** pointers = static_cast<void**>(VirtualAlloc(
      nullptr, static_cast<size_t>(capacity) * sizeof(void*),
      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!pointers) {
    return false;
  }

  ManagedSnapshotCollectContext collect{};
  collect.heapId = heapId;
  collect.pointers = pointers;
  collect.capacity = capacity;
  const bool visited = MemoryPool::VisitAllocations(
      MemoryPool::BackendRoute::Automatic,
      &CollectManagedSnapshotVisitor, &collect);
  if (!visited || collect.overflow) {
    VirtualFree(pointers, 0, MEM_RELEASE);
    return false;
  }

  std::sort(pointers, pointers + collect.count,
            [](const void* left, const void* right) {
              return reinterpret_cast<uintptr_t>(left) <
                     reinterpret_cast<uintptr_t>(right);
            });
  tls_blockEnumeration.pointers = pointers;
  tls_blockEnumeration.capacity = capacity;
  tls_blockEnumeration.count = collect.count;
  tls_blockEnumeration.heapId = heapId;
  tls_blockEnumeration.valid = true;
  g_blockEnumerationSnapshotBuilds.fetch_add(1, std::memory_order_relaxed);
  return true;
}

bool CachedEnumerationContains(uint32_t heapId,
                               const void* pointer) noexcept {
  if (!pointer || !tls_blockEnumeration.valid ||
      tls_blockEnumeration.heapId != heapId) {
    return false;
  }
  void** const begin = tls_blockEnumeration.pointers;
  void** const end = begin + tls_blockEnumeration.count;
  return std::binary_search(
      begin, end, const_cast<void*>(pointer),
      [](const void* left, const void* right) {
        return reinterpret_cast<uintptr_t>(left) <
               reinterpret_cast<uintptr_t>(right);
      });
}

bool FindCachedManagedNext(uint32_t heapId, const void* previous,
                           ManagedBlock* output) noexcept {
  if (!output) {
    return false;
  }
  if ((!tls_blockEnumeration.valid ||
       tls_blockEnumeration.heapId != heapId) &&
      !BuildManagedBlockEnumeration(heapId)) {
    return false;
  }

  void** const begin = tls_blockEnumeration.pointers;
  void** const end = begin + tls_blockEnumeration.count;
  void** candidate = previous
      ? std::upper_bound(
            begin, end, const_cast<void*>(previous),
            [](const void* cursor, const void* entry) {
              return reinterpret_cast<uintptr_t>(cursor) <
                     reinterpret_cast<uintptr_t>(entry);
            })
      : begin;
  while (candidate != end) {
    ManagedBlock block{};
    if (QueryPointerImpl(*candidate, &block) ==
            StormTakeover::BlockQueryResult::Managed &&
        block.heapId == heapId) {
      *output = block;
      return true;
    }
    ++candidate;
  }

  const uint32_t exhaustedHeapId = tls_blockEnumeration.heapId;
  ReleaseManagedBlockEnumeration();
  tls_blockEnumeration.heapId = exhaustedHeapId;
  tls_blockEnumeration.exhaustedCursor = previous;
  return false;
}

struct DestroyCollectContext {
  uint32_t heapId;
  DestroySnapshotEntry* entries;
  uint32_t capacity;
  uint32_t count;
  uint32_t persistentCount;
  bool taggedSnapshot;
  bool invalid;
  bool overflow;
};

bool CollectDestroyVisitor(void* raw, size_t usable,
                           MemoryPool::BackendRoute route,
                           void* context) noexcept {
  auto* collect = static_cast<DestroyCollectContext*>(context);
  ManagedBlock block{};
  if (!DecodeRawAllocation(raw, usable, route, &block) ||
      block.heapId != collect->heapId) {
    return true;
  }
  if (block.persistent) {
    ++collect->persistentCount;
    return true;
  }
  if (collect->count == collect->capacity) {
    collect->overflow = true;
    return false;
  }
  DestroySnapshotEntry& entry = collect->entries[collect->count];
  if (collect->taggedSnapshot) {
    const uintptr_t rawAddress = reinterpret_cast<uintptr_t>(raw);
    if ((rawAddress & kDestroySnapshotTagMask) != 0u ||
        (route != MemoryPool::BackendRoute::Tlsf &&
         route != MemoryPool::BackendRoute::Mimalloc) ||
        usable > UINT32_MAX) {
      collect->invalid = true;
      return false;
    }
    uintptr_t tags =
        route == MemoryPool::BackendRoute::Mimalloc
            ? kDestroySnapshotMimallocTag
            : 0u;
    tags |= block.canary ? kDestroySnapshotCanaryTag : 0u;
    tags |= block.isSmall ? 0u : kDestroySnapshotLargeTag;
    entry.tagged.taggedRaw = rawAddress | tags;
    entry.tagged.usableSize = static_cast<uint32_t>(usable);
    entry.tagged.requestedSize = block.requestedSize;
  } else {
    entry.legacy.raw = raw;
    entry.legacy.usableSize = usable;
    entry.legacy.route = route;
  }
  ++collect->count;
  return true;
}

MemoryPool::BackendRoute DestroySnapshotRoute(
    const DestroySnapshotEntry& entry, bool taggedSnapshot) noexcept {
  if (!taggedSnapshot) {
    return entry.legacy.route;
  }
  return (entry.tagged.taggedRaw & kDestroySnapshotMimallocTag) != 0u
             ? MemoryPool::BackendRoute::Mimalloc
             : MemoryPool::BackendRoute::Tlsf;
}

bool DecodeDestroySnapshotEntry(const DestroySnapshotEntry& entry,
                                bool taggedSnapshot, uint32_t heapId,
                                ManagedBlock* output) noexcept {
  if (!output) {
    return false;
  }
  if (!taggedSnapshot) {
    ManagedBlock block{};
    if (!DecodeRawAllocation(entry.legacy.raw, entry.legacy.usableSize,
                             entry.legacy.route, &block) ||
        block.heapId != heapId || block.persistent) {
      return false;
    }
    *output = block;
    return true;
  }

  const uintptr_t taggedRaw = entry.tagged.taggedRaw;
  ManagedBlock block{};
  block.raw = reinterpret_cast<void*>(taggedRaw & ~kDestroySnapshotTagMask);
  block.heapId = heapId;
  block.requestedSize = entry.tagged.requestedSize;
  block.physicalUsableSize = entry.tagged.usableSize;
  block.route = DestroySnapshotRoute(entry, true);
  block.canary = (taggedRaw & kDestroySnapshotCanaryTag) != 0u;
  block.isSmall = (taggedRaw & kDestroySnapshotLargeTag) == 0u;
  block.headerSize = block.isSmall ? sizeof(SmallManagedHeader)
                                   : sizeof(LargeManagedHeader);
  block.user = static_cast<uint8_t*>(block.raw) + block.headerSize;
  const size_t nonPayload = block.headerSize + (block.canary ? 2u : 0u);
  block.payloadUsableSize =
      block.physicalUsableSize > nonPayload
          ? block.physicalUsableSize - nonPayload
          : block.requestedSize;
  *output = block;
  return block.raw != nullptr;
}

void PrepareDestroyBatchBlock(const ManagedBlock& block) noexcept {
  if (!ValidateCanary(block)) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
  RememberFreed(block.user);
  PoisonAndFill(block);
}

bool AccountDestroyedBlock(const StormHeapRegistry::DestroyToken& token,
                           const ManagedBlock& block,
                           bool trackRegistryStatistics) noexcept {
  if (trackRegistryStatistics &&
      !g_registry.RecordDestroyFree(token, block.requestedSize,
                                    block.payloadUsableSize)) {
    return false;
  }
  SaturatingSubtract(g_liveBlocks, 1);
  StormBreaker::LeakProfiler::RecordFree(
      block.user, block.requestedSize,
      StormBreaker::LeakProfiler::AllocationDomain::Managed,
      MakeMetadata(block.heapId, 0, StormApi::kOrdinalHeapDestroy,
                   ProfilerRoute(block.route)));
  return true;
}

uint64_t HistogramPercentile(const MemoryPool::LatencyHistogramStats& stats,
                             uint64_t numerator,
                             uint64_t denominator) noexcept {
  if (stats.sampleCount == 0 || denominator == 0) {
    return 0;
  }
  const uint64_t target =
      (stats.sampleCount * numerator + denominator - 1) / denominator;
  uint64_t cumulative = 0;
  for (size_t index = 0;
       index < MemoryPool::kLatencyHistogramBucketCount + 1; ++index) {
    cumulative += stats.bucketCounts[index];
    if (cumulative >= target) {
      return index < MemoryPool::kLatencyHistogramBucketCount
                 ? stats.upperBoundsNanoseconds[index]
                 : stats.maxNanoseconds;
    }
  }
  return stats.maxNanoseconds;
}

bool AttachTarget(PVOID* target, PVOID hook, const char* name) noexcept {
  const LONG result = DetourAttach(target, hook);
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError("DetourAttach(%s) failed: %ld", name,
                                   result);
    return false;
  }
  return true;
}

bool DetachTarget(PVOID* target, PVOID hook, const char* name) noexcept {
  const LONG result = DetourDetach(target, hook);
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError("DetourDetach(%s) failed: %ld", name,
                                   result);
    return false;
  }
  return true;
}

void CloseThreadHandles(std::vector<HANDLE>* handles) noexcept {
  if (!handles) {
    return;
  }
  for (HANDLE handle : *handles) {
    if (handle) {
      CloseHandle(handle);
    }
  }
  handles->clear();
}

bool UpdateOtherProcessThreads(std::vector<HANDLE>* handles) noexcept {
  if (!handles) {
    return false;
  }
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    Logger::GetInstance().LogError(
        "CreateToolhelp32Snapshot(threads) failed: %lu", GetLastError());
    return false;
  }

  const DWORD processId = GetCurrentProcessId();
  const DWORD currentThreadId = GetCurrentThreadId();
  THREADENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  bool success = true;
  if (Thread32First(snapshot, &entry)) {
    do {
      if (entry.th32OwnerProcessID != processId ||
          entry.th32ThreadID == currentThreadId) {
        continue;
      }
      HANDLE thread = OpenThread(
          THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
              THREAD_QUERY_INFORMATION,
          FALSE, entry.th32ThreadID);
      if (!thread) {
        const DWORD error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER) {
          continue;
        }
        Logger::GetInstance().LogError(
            "OpenThread(%lu) for Detours failed: %lu",
            entry.th32ThreadID, error);
        success = false;
        break;
      }
      try {
        handles->push_back(thread);
      } catch (...) {
        CloseHandle(thread);
        success = false;
        break;
      }
      const LONG result = DetourUpdateThread(thread);
      if (result != NO_ERROR) {
        Logger::GetInstance().LogError(
            "DetourUpdateThread(%lu) failed: %ld",
            entry.th32ThreadID, result);
        success = false;
        break;
      }
    } while (Thread32Next(snapshot, &entry));
  } else if (GetLastError() != ERROR_NO_MORE_FILES) {
    Logger::GetInstance().LogError(
        "Thread32First failed: %lu", GetLastError());
    success = false;
  }
  CloseHandle(snapshot);
  return success;
}

} // namespace

namespace StormTakeover {

const char* ModeName(TakeoverMode mode) noexcept {
  switch (mode) {
  case TakeoverMode::Large:
    return "large";
  case TakeoverMode::Size32K:
    return "32k";
  case TakeoverMode::Size8K:
    return "8k";
  case TakeoverMode::Size2K:
    return "2k";
  case TakeoverMode::Size256:
    return "256";
  case TakeoverMode::Full:
    return "full";
  }
  return "unknown";
}

const char* RouteName(
    StormBreaker::LeakProfiler::BackendRoute route) noexcept {
  using Route = StormBreaker::LeakProfiler::BackendRoute;
  switch (route) {
  case Route::NativeStorm:
    return "native-storm";
  case Route::Tlsf:
    return "tlsf";
  case Route::Mimalloc:
    return "mimalloc";
  case Route::TlsfSharded:
    return "tlsf-sharded";
  default:
    return "unknown";
  }
}

const char* DegradedReasonName(
    StormBreaker::LeakProfiler::DegradedReason reason) noexcept {
  using Reason = StormBreaker::LeakProfiler::DegradedReason;
  switch (reason) {
  case Reason::IntentionalNative:
    return "intentional-native";
  case Reason::HookBypass:
    return "hook-bypass";
  case Reason::UnsafePeriod:
    return "unsafe-period";
  case Reason::BelowTakeoverThreshold:
    return "below-takeover-threshold";
  case Reason::UnknownHeap:
    return "unknown-heap";
  case Reason::RegistryCapacity:
    return "registry-capacity";
  case Reason::BackendUnavailable:
    return "backend-unavailable";
  case Reason::BackendOutOfMemory:
    return "backend-out-of-memory";
  case Reason::RequestedBudgetExceeded:
    return "requested-budget-exceeded";
  case Reason::UnsupportedFlags:
    return "unsupported-flags";
  case Reason::ProtectMemory:
    return "protect-memory";
  case Reason::PointerRejected:
    return "pointer-rejected";
  case Reason::NativeException:
    return "native-exception";
  case Reason::InitializationFailure:
    return "initialization-failure";
  case Reason::ExplicitNativeHeap:
    return "explicit-native-heap";
  default:
    return "none";
  }
}

bool Initialize() noexcept {
  if (g_initialized.load(std::memory_order_acquire)) {
    return true;
  }
  if (!MemoryPool::IsInitialized()) {
    Logger::GetInstance().LogError(
        "StormTakeover requires an initialized MemoryPool");
    return false;
  }
  TakeoverMode mode = TakeoverMode::Large;
  uint32_t threshold = StormApi::kNativeLargeThreshold;
  if (!ParseTakeoverMode(&mode, &threshold)) {
    Logger::GetInstance().LogError(
        "invalid STORMBREAKER_TAKEOVER_MODE; expected "
        "large|32k|8k|2k|256|full");
    return false;
  }
  if (!g_registry.Initialize()) {
    Logger::GetInstance().LogError("Storm heap registry initialization failed");
    return false;
  }
  const bool needsFullExportSurface = mode != TakeoverMode::Large;
  if (needsFullExportSurface) {
    g_heapSnapshots =
        static_cast<StormHeapRegistry::HeapSnapshot*>(VirtualAlloc(
            nullptr,
            sizeof(StormHeapRegistry::HeapSnapshot) *
                StormHeapRegistry::kHeapRegistryCapacity,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    g_nativeHeapSnapshots = static_cast<NativeHeapSnapshot*>(VirtualAlloc(
        nullptr,
        sizeof(NativeHeapSnapshot) * StormHeapRegistry::kHeapRegistryCapacity,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    g_nativeHeapIndex = static_cast<NativeHeapIndex*>(VirtualAlloc(
        nullptr,
        sizeof(NativeHeapIndex) * StormHeapRegistry::kHeapRegistryCapacity,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  }
  if (needsFullExportSurface &&
      (!g_heapSnapshots || !g_nativeHeapSnapshots || !g_nativeHeapIndex)) {
    if (g_heapSnapshots) {
      VirtualFree(g_heapSnapshots, 0, MEM_RELEASE);
      g_heapSnapshots = nullptr;
    }
    if (g_nativeHeapSnapshots) {
      VirtualFree(g_nativeHeapSnapshots, 0, MEM_RELEASE);
      g_nativeHeapSnapshots = nullptr;
    }
    if (g_nativeHeapIndex) {
      VirtualFree(g_nativeHeapIndex, 0, MEM_RELEASE);
      g_nativeHeapIndex = nullptr;
    }
    g_registry.Shutdown();
    return false;
  }

  g_processSecret.store(GenerateSecret(), std::memory_order_release);
  g_mode.store(mode, std::memory_order_release);
  g_threshold.store(threshold, std::memory_order_release);
  g_optionFlags.store(0, std::memory_order_relaxed);
  g_apiCalls.store(0, std::memory_order_relaxed);
  g_managedCalls.store(0, std::memory_order_relaxed);
  g_nativeCalls.store(0, std::memory_order_relaxed);
  g_fallbackCalls.store(0, std::memory_order_relaxed);
  g_degradedCalls.store(0, std::memory_order_relaxed);
  g_rejectedPointers.store(0, std::memory_order_relaxed);
  g_failures.store(0, std::memory_order_relaxed);
  g_liveBlocks.store(0, std::memory_order_relaxed);
  g_blockEnumerationCalls.store(0, std::memory_order_relaxed);
  g_blockEnumerationSnapshotBuilds.store(0, std::memory_order_relaxed);
  g_heapEnumerationCalls.store(0, std::memory_order_relaxed);
  g_heapEnumerationRebuilds.store(0, std::memory_order_relaxed);
  g_heapDestroySnapshots.store(0, std::memory_order_relaxed);
  g_heapDestroySnapshotBlocks.store(0, std::memory_order_relaxed);
  g_heapDestroyBatchCalls.store(0, std::memory_order_relaxed);
  g_heapDestroyBatchBlocks.store(0, std::memory_order_relaxed);
  g_heapDestroyBatchFallbacks.store(0, std::memory_order_relaxed);
  g_callerHeapCacheHits.store(0, std::memory_order_relaxed);
  g_callerHeapCacheMisses.store(0, std::memory_order_relaxed);
  g_callerHeapCacheBypasses.store(0, std::memory_order_relaxed);
  g_callerHeapCacheSaturated.store(0, std::memory_order_relaxed);
  g_heapIdSlotHintHits.store(0, std::memory_order_relaxed);
  g_heapIdSlotHintMisses.store(0, std::memory_order_relaxed);
  g_callerHeapCacheEntries.store(0, std::memory_order_relaxed);
  g_lastRequestedSize.store(0, std::memory_order_relaxed);
  g_directCallerHashEnabled.store(false, std::memory_order_relaxed);
#if defined(STORMBREAKER_TESTING)
  g_testingInPlaceReallocateAttempts.store(0, std::memory_order_relaxed);
  g_testingInPlaceReallocateSuccesses.store(0, std::memory_order_relaxed);
  g_testingInPlaceReallocateMisses.store(0, std::memory_order_relaxed);
#endif
  ResetCallerHeapCache();
  ReleaseManagedBlockEnumeration();
  g_cachedManagedHeapCount = 0;
  g_cachedNativeHeapCount = 0;
  g_cachedBackendReservedBytes = 0;
  g_cachedBackendCommittedBytes = 0;
  g_heapEnumerationCacheValid = false;
  g_hookClosing.store(false, std::memory_order_relaxed);
  g_allExportsInstalled.store(false, std::memory_order_relaxed);
  g_activeHookCalls.store(0, std::memory_order_relaxed);
  for (auto& slot : g_recentlyFreed) {
    slot.store(0, std::memory_order_relaxed);
  }
  g_initialized.store(true, std::memory_order_release);
  Logger::GetInstance().LogInfo(
      "Storm takeover initialized: mode=%s threshold=%u backend=%s",
      ModeName(mode), threshold, MemoryPool::GetBackendName());
  return true;
}

bool Shutdown() noexcept {
  if (!g_initialized.load(std::memory_order_acquire)) {
    return true;
  }
  if (g_installed.load(std::memory_order_acquire) || !CanCleanShutdown()) {
    return false;
  }
  if (!g_registry.Shutdown()) {
    return false;
  }
  if (g_heapSnapshots) {
    VirtualFree(g_heapSnapshots, 0, MEM_RELEASE);
    g_heapSnapshots = nullptr;
  }
  if (g_nativeHeapSnapshots) {
    VirtualFree(g_nativeHeapSnapshots, 0, MEM_RELEASE);
    g_nativeHeapSnapshots = nullptr;
  }
  if (g_nativeHeapIndex) {
    VirtualFree(g_nativeHeapIndex, 0, MEM_RELEASE);
    g_nativeHeapIndex = nullptr;
  }
  g_cachedManagedHeapCount = 0;
  g_cachedNativeHeapCount = 0;
  g_cachedBackendReservedBytes = 0;
  g_cachedBackendCommittedBytes = 0;
  g_heapEnumerationCacheValid = false;
  RefreshCallerModuleRanges(nullptr, nullptr, nullptr);
  g_directCallerHashEnabled.store(false, std::memory_order_relaxed);
  ReleaseManagedBlockEnumeration();
  g_api = {};
  g_initialized.store(false, std::memory_order_release);
  return true;
}

bool Install(HMODULE stormModule) noexcept {
  if (g_installed.load(std::memory_order_acquire)) {
    return true;
  }
  if (!g_initialized.load(std::memory_order_acquire)) {
    return false;
  }
  wchar_t failure[256]{};
  HMODULE gameModule = GetModuleHandleA("Game.dll");
  const bool isWorldEdit = gameModule == nullptr;
  if (gameModule) {
    if (!StormVersionProfile::VerifyGame127a(
            gameModule, failure, ARRAYSIZE(failure))) {
      Logger::GetInstance().LogError(
          "Game 1.27a verification failed: %ls", failure);
      return false;
    }
  } else {
    HMODULE hostModule = GetModuleHandleA(nullptr);
    if (!StormVersionProfile::VerifyWorldEdit127a(
            hostModule, failure, ARRAYSIZE(failure))) {
      Logger::GetInstance().LogError(
          "neither verified Game.dll nor verified WorldEdit.exe is active: %ls",
          failure);
      return false;
    }
  }
  StormApi::ResolvedApi resolved{};
  if (!StormVersionProfile::ResolveVerified127a(
          stormModule, &resolved, failure, ARRAYSIZE(failure))) {
    Logger::GetInstance().LogError(
        "Storm 1.27a verification failed: %ls", failure);
    return false;
  }
  g_api = resolved;
  const bool directCallerHash = ValidateDirectCallerHash(resolved);
  RefreshCallerModuleRanges(stormModule, gameModule, GetModuleHandleA(nullptr));
  RefreshOptionsFromStorm();
  g_hookClosing.store(false, std::memory_order_release);

  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    return false;
  }
  std::vector<HANDLE> updatedThreads;
  if (!UpdateOtherProcessThreads(&updatedThreads)) {
    DetourTransactionAbort();
    CloseThreadHandles(&updatedThreads);
    return false;
  }

#define SB_ATTACH(member, hook, label)                                         \
  AttachTarget(reinterpret_cast<PVOID*>(&g_api.member),                        \
               reinterpret_cast<PVOID>(hook), label)
  const bool installAllExports = GetMode() != TakeoverMode::Large;
  bool attached =
      SB_ATTACH(alloc, HookedFull_SMemAlloc, "401 SMemAlloc") &&
      SB_ATTACH(free, HookedFull_SMemFree, "403 SMemFree") &&
      SB_ATTACH(getSize, HookedFull_SMemGetSize, "404 SMemGetSize") &&
      SB_ATTACH(reAlloc, HookedFull_SMemReAlloc, "405 SMemReAlloc");
  if (attached && installAllExports) {
    attached =
        SB_ATTACH(getAllocated, HookedFull_SMemGetAllocated,
                  "406 SMemGetAllocated") &&
        SB_ATTACH(findNextBlock, HookedFull_SMemFindNextBlock,
                  "481 SMemFindNextBlock") &&
        SB_ATTACH(findNextHeap, HookedFull_SMemFindNextHeap,
                  "482 SMemFindNextHeap") &&
        SB_ATTACH(getHeapByCaller, HookedFull_SMemGetHeapByCaller,
                  "483 SMemGetHeapByCaller") &&
        SB_ATTACH(getHeapByPtr, HookedFull_SMemGetHeapByPtr,
                  "484 SMemGetHeapByPtr") &&
        SB_ATTACH(heapAlloc, HookedFull_SMemHeapAlloc, "485 SMemHeapAlloc") &&
        SB_ATTACH(heapCreate, HookedFull_SMemHeapCreate,
                  "486 SMemHeapCreate") &&
        SB_ATTACH(heapDestroy, HookedFull_SMemHeapDestroy,
                  "487 SMemHeapDestroy") &&
        SB_ATTACH(heapFree, HookedFull_SMemHeapFree, "488 SMemHeapFree") &&
        SB_ATTACH(heapReAlloc, HookedFull_SMemHeapReAlloc,
                  "489 SMemHeapReAlloc") &&
        SB_ATTACH(heapSize, HookedFull_SMemHeapSize, "490 SMemHeapSize") &&
        SB_ATTACH(setOption, HookedFull_SMemSetOption, "496 SMemSetOption");
  }
#undef SB_ATTACH

  if (!attached) {
    DetourTransactionAbort();
    CloseThreadHandles(&updatedThreads);
    g_api = resolved;
    return false;
  }
  result = DetourTransactionCommit();
  CloseThreadHandles(&updatedThreads);
  if (result != NO_ERROR) {
    g_api = resolved;
    return false;
  }
  g_directCallerHashEnabled.store(directCallerHash, std::memory_order_release);
  g_installed.store(true, std::memory_order_release);
  g_allExportsInstalled.store(installAllExports, std::memory_order_release);
  Logger::GetInstance().LogInfo(
      "Storm memory hooks installed; StormSHA256=%s hostSHA256=%s "
      "mode=%s backend=%s scope=%s callerHash=%s",
      StormVersionProfile::ExpectedStormSha256(),
      isWorldEdit ? StormVersionProfile::ExpectedWorldEditSha256()
                  : StormVersionProfile::ExpectedGameSha256(),
      ModeName(GetMode()),
      MemoryPool::GetBackendName(), installAllExports ? "all" : "core",
      directCallerHash ? "direct-verified" : "native-trampoline");
  return true;
}

bool Uninstall() noexcept {
  if (!g_installed.load(std::memory_order_acquire)) {
    return true;
  }
#if STORMBREAKER_PINNED_RUNTIME
  Logger::GetInstance().LogWarning(
      "Pinned runtime refuses memory Hook detachment; hooks remain installed");
  return false;
#endif
  bool expectedClosing = false;
  if (!g_hookClosing.compare_exchange_strong(
          expectedClosing, true, std::memory_order_acq_rel)) {
    return false;
  }
  const ULONGLONG drainDeadline = GetTickCount64() + 20000u;
  for (uint32_t wait = 0;
       g_activeHookCalls.load(std::memory_order_acquire) != 0; ++wait) {
    if (GetTickCount64() >= drainDeadline) {
      Logger::GetInstance().LogError(
          "timed out waiting for in-flight Storm hooks to drain");
      g_hookClosing.store(false, std::memory_order_release);
      return false;
    }
    if ((wait & 63u) == 63u) {
      Sleep(wait >= 256u ? 1u : 0u);
    } else {
      YieldProcessor();
    }
  }
  if (!CanCleanShutdown()) {
    g_hookClosing.store(false, std::memory_order_release);
    return false;
  }
  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    g_hookClosing.store(false, std::memory_order_release);
    return false;
  }
  std::vector<HANDLE> updatedThreads;
  if (!UpdateOtherProcessThreads(&updatedThreads)) {
    DetourTransactionAbort();
    CloseThreadHandles(&updatedThreads);
    g_hookClosing.store(false, std::memory_order_release);
    return false;
  }
#define SB_DETACH(member, hook, label)                                         \
  DetachTarget(reinterpret_cast<PVOID*>(&g_api.member),                        \
               reinterpret_cast<PVOID>(hook), label)
  const bool detachAllExports =
      g_allExportsInstalled.load(std::memory_order_acquire);
  bool detached =
      SB_DETACH(alloc, HookedFull_SMemAlloc, "401 SMemAlloc") &&
      SB_DETACH(free, HookedFull_SMemFree, "403 SMemFree") &&
      SB_DETACH(getSize, HookedFull_SMemGetSize, "404 SMemGetSize") &&
      SB_DETACH(reAlloc, HookedFull_SMemReAlloc, "405 SMemReAlloc");
  if (detached && detachAllExports) {
    detached =
        SB_DETACH(getAllocated, HookedFull_SMemGetAllocated,
                  "406 SMemGetAllocated") &&
        SB_DETACH(findNextBlock, HookedFull_SMemFindNextBlock,
                  "481 SMemFindNextBlock") &&
        SB_DETACH(findNextHeap, HookedFull_SMemFindNextHeap,
                  "482 SMemFindNextHeap") &&
        SB_DETACH(getHeapByCaller, HookedFull_SMemGetHeapByCaller,
                  "483 SMemGetHeapByCaller") &&
        SB_DETACH(getHeapByPtr, HookedFull_SMemGetHeapByPtr,
                  "484 SMemGetHeapByPtr") &&
        SB_DETACH(heapAlloc, HookedFull_SMemHeapAlloc, "485 SMemHeapAlloc") &&
        SB_DETACH(heapCreate, HookedFull_SMemHeapCreate,
                  "486 SMemHeapCreate") &&
        SB_DETACH(heapDestroy, HookedFull_SMemHeapDestroy,
                  "487 SMemHeapDestroy") &&
        SB_DETACH(heapFree, HookedFull_SMemHeapFree, "488 SMemHeapFree") &&
        SB_DETACH(heapReAlloc, HookedFull_SMemHeapReAlloc,
                  "489 SMemHeapReAlloc") &&
        SB_DETACH(heapSize, HookedFull_SMemHeapSize, "490 SMemHeapSize") &&
        SB_DETACH(setOption, HookedFull_SMemSetOption, "496 SMemSetOption");
  }
#undef SB_DETACH
  if (!detached) {
    DetourTransactionAbort();
    CloseThreadHandles(&updatedThreads);
    g_hookClosing.store(false, std::memory_order_release);
    return false;
  }
  result = DetourTransactionCommit();
  CloseThreadHandles(&updatedThreads);
  if (result != NO_ERROR) {
    g_hookClosing.store(false, std::memory_order_release);
    return false;
  }
  g_installed.store(false, std::memory_order_release);
  g_allExportsInstalled.store(false, std::memory_order_release);
  return true;
}

bool IsInstalled() noexcept {
  return g_installed.load(std::memory_order_acquire);
}

bool IsInitialized() noexcept {
  return g_initialized.load(std::memory_order_acquire);
}

bool CanCleanShutdown() noexcept {
  return g_liveBlocks.load(std::memory_order_acquire) == 0 &&
         MemoryPool::GetRequestedLiveBytes() == 0;
}

RuntimeStats GetRuntimeStats() noexcept {
  RuntimeStats stats{};
  stats.apiCalls = g_apiCalls.load(std::memory_order_relaxed);
  stats.managedCalls = g_managedCalls.load(std::memory_order_relaxed);
  stats.nativeCalls = g_nativeCalls.load(std::memory_order_relaxed);
  stats.fallbackCalls = g_fallbackCalls.load(std::memory_order_relaxed);
  stats.degradedCalls = g_degradedCalls.load(std::memory_order_relaxed);
  stats.rejectedPointers = g_rejectedPointers.load(std::memory_order_relaxed);
  stats.failures = g_failures.load(std::memory_order_relaxed);
  stats.liveBlocks = g_liveBlocks.load(std::memory_order_relaxed);
  stats.liveRequestedBytes = MemoryPool::GetRequestedLiveBytes();
  stats.blockEnumerationCalls =
      g_blockEnumerationCalls.load(std::memory_order_relaxed);
  stats.blockEnumerationSnapshotBuilds =
      g_blockEnumerationSnapshotBuilds.load(std::memory_order_relaxed);
  stats.heapEnumerationCalls =
      g_heapEnumerationCalls.load(std::memory_order_relaxed);
  stats.heapEnumerationRebuilds =
      g_heapEnumerationRebuilds.load(std::memory_order_relaxed);
  stats.heapDestroySnapshots =
      g_heapDestroySnapshots.load(std::memory_order_relaxed);
  stats.heapDestroySnapshotBlocks =
      g_heapDestroySnapshotBlocks.load(std::memory_order_relaxed);
  stats.heapDestroyBatchCalls =
      g_heapDestroyBatchCalls.load(std::memory_order_relaxed);
  stats.heapDestroyBatchBlocks =
      g_heapDestroyBatchBlocks.load(std::memory_order_relaxed);
  stats.heapDestroyBatchFallbacks =
      g_heapDestroyBatchFallbacks.load(std::memory_order_relaxed);
  stats.callerHeapCacheHits =
      g_callerHeapCacheHits.load(std::memory_order_relaxed);
  stats.callerHeapCacheMisses =
      g_callerHeapCacheMisses.load(std::memory_order_relaxed);
  stats.callerHeapCacheBypasses =
      g_callerHeapCacheBypasses.load(std::memory_order_relaxed);
  stats.callerHeapCacheSaturated =
      g_callerHeapCacheSaturated.load(std::memory_order_relaxed);
  stats.heapIdSlotHintHits =
      g_heapIdSlotHintHits.load(std::memory_order_relaxed);
  stats.heapIdSlotHintMisses =
      g_heapIdSlotHintMisses.load(std::memory_order_relaxed);
  stats.callerHeapCacheEntries =
      g_callerHeapCacheEntries.load(std::memory_order_relaxed);
  stats.lastHeapId = g_lastHeapId.load(std::memory_order_relaxed);
  stats.lastStormFlags = g_lastStormFlags.load(std::memory_order_relaxed);
  stats.lastRequestedSize =
      g_lastRequestedSize.load(std::memory_order_relaxed);
  stats.lastOrdinal = g_lastOrdinal.load(std::memory_order_relaxed);
  stats.lastRoute =
      static_cast<StormBreaker::LeakProfiler::BackendRoute>(
          g_lastRoute.load(std::memory_order_relaxed));
  stats.lastDegradedReason =
      static_cast<StormBreaker::LeakProfiler::DegradedReason>(
          g_lastReason.load(std::memory_order_relaxed));
  stats.directCallerHash =
      g_directCallerHashEnabled.load(std::memory_order_relaxed);
  stats.threshold = GetThreshold();
  stats.optionFlags = g_optionFlags.load(std::memory_order_relaxed);
  stats.mode = GetMode();
  stats.initialized = IsInitialized();
  stats.installed = IsInstalled();
  return stats;
}

StormHeapRegistry::RegistryStats GetRegistryStats() noexcept {
  return g_registry.GetStats();
}

StormBreaker::LeakProfiler::TakeoverSnapshot GetTelemetrySnapshot() noexcept {
  StormBreaker::LeakProfiler::TakeoverSnapshot snapshot{};
  const auto registry = g_registry.GetStats();
  snapshot.managedApiCalls = g_managedCalls.load(std::memory_order_relaxed);
  snapshot.nativeApiCalls = g_nativeCalls.load(std::memory_order_relaxed);
  snapshot.managedFallbackCalls =
      g_fallbackCalls.load(std::memory_order_relaxed);
  snapshot.degradedCalls = g_degradedCalls.load(std::memory_order_relaxed);
  snapshot.registryInsertFailures = registry.capacityFailures;
  snapshot.registryCapacity = registry.capacity;
  snapshot.registryActive = registry.activeHeaps;
  snapshot.registryDestroying = registry.destroyingHeaps;
  snapshot.registryTombstones = registry.tombstoneHeaps;
  snapshot.registryNativeDelegated = registry.nativeHeaps;
  snapshot.stormOptionFlags = g_optionFlags.load(std::memory_order_relaxed);
  snapshot.lastHeapId = g_lastHeapId.load(std::memory_order_relaxed);
  snapshot.lastStormFlags = g_lastStormFlags.load(std::memory_order_relaxed);
  snapshot.lastExportedOrdinal =
      g_lastOrdinal.load(std::memory_order_relaxed);
  snapshot.lastRoute =
      static_cast<StormBreaker::LeakProfiler::BackendRoute>(
          g_lastRoute.load(std::memory_order_relaxed));
  snapshot.lastDegradedReason =
      static_cast<StormBreaker::LeakProfiler::DegradedReason>(
          g_lastReason.load(std::memory_order_relaxed));

  const auto pool = MemoryPool::GetExtendedStats();
  const size_t routeIndex = static_cast<size_t>(snapshot.lastRoute);
  if (routeIndex < StormBreaker::LeakProfiler::kBackendRouteCount) {
    auto& latency = snapshot.routeLatency[routeIndex];
    latency.sampleCount = pool.operationLatency.sampleCount;
    latency.totalNanoseconds = pool.operationLatency.totalNanoseconds;
    latency.maxNanoseconds = pool.operationLatency.maxNanoseconds;
    latency.p50Nanoseconds =
        HistogramPercentile(pool.operationLatency, 50, 100);
    latency.p95Nanoseconds =
        HistogramPercentile(pool.operationLatency, 95, 100);
    latency.p99Nanoseconds =
        HistogramPercentile(pool.operationLatency, 99, 100);
  }
  return snapshot;
}

TakeoverMode GetMode() noexcept {
  return g_mode.load(std::memory_order_acquire);
}

uint32_t GetThreshold() noexcept {
  return g_threshold.load(std::memory_order_acquire);
}

BlockQueryResult QueryPointer(const void* pointer, uint32_t* requestedSize,
                              uint32_t* heapId) noexcept {
  ManagedBlock block{};
  const BlockQueryResult result = QueryPointerImpl(pointer, &block);
  if (requestedSize) {
    *requestedSize = result == BlockQueryResult::Managed
                         ? block.requestedSize
                         : 0;
  }
  if (heapId) {
    *heapId = result == BlockQueryResult::Managed ? block.heapId : 0;
  }
  return result;
}

#if defined(STORMBREAKER_TESTING)
namespace Testing {

bool RegisterManagedHeap(uint32_t heapId, bool explicitHeap,
                         const char* name, uint32_t sourceLine) noexcept {
  const auto result = g_registry.RegisterManaged(
      heapId,
      explicitHeap ? StormHeapRegistry::HeapKind::Explicit
                   : StormHeapRegistry::HeapKind::Main,
      name, sourceLine);
  return result == StormHeapRegistry::CreateResult::CreatedManaged ||
         result == StormHeapRegistry::CreateResult::AlreadyManaged;
}

bool GetLayout(const void* pointer, uint32_t* headerSize, uint32_t* route,
               bool* persistent) noexcept {
  ManagedBlock block{};
  if (QueryPointerImpl(pointer, &block) != BlockQueryResult::Managed) {
    return false;
  }
  if (headerSize) {
    *headerSize = static_cast<uint32_t>(block.headerSize);
  }
  if (route) {
    *route = static_cast<uint32_t>(block.route);
  }
  if (persistent) {
    *persistent = block.persistent;
  }
  return true;
}

void SetOptionFlags(uint32_t optionFlags) noexcept {
  g_optionFlags.store(optionFlags, std::memory_order_release);
}

void SetNativeApi(const StormApi::ResolvedApi* api) noexcept {
  g_api = api ? *api : StormApi::ResolvedApi{};
  RefreshCallerModuleRanges(g_api.module, GetModuleHandleA("Game.dll"),
                            GetModuleHandleA(nullptr));
}

void SetFastFreeEnabled(bool enabled) noexcept {
  g_testingFastFreeEnabled.store(enabled, std::memory_order_release);
}

void SetRegistryAccountingEnabled(bool enabled) noexcept {
  g_testingRegistryAccountingEnabled.store(enabled, std::memory_order_release);
}

void SetMainRegistryAccountingEnabled(bool enabled) noexcept {
  g_testingMainRegistryAccountingEnabled.store(enabled,
                                                std::memory_order_release);
}

void SetCallerSlotHintEnabled(bool enabled) noexcept {
  g_testingCallerSlotHintEnabled.store(enabled, std::memory_order_release);
}

void SetDirectCallerHashEnabled(bool enabled) noexcept {
  g_directCallerHashEnabled.store(enabled, std::memory_order_release);
}

void SetDirectCallerByteTableEnabled(bool enabled) noexcept {
  g_testingDirectCallerByteTableEnabled.store(enabled,
                                               std::memory_order_release);
}

void SetRecentFreedFibonacciHashEnabled(bool enabled) noexcept {
  g_testingRecentFreedFibonacciHashEnabled.store(enabled,
                                                  std::memory_order_release);
}

void SetCallerCacheWays(uint32_t ways) noexcept {
  if (ways == 4u || ways == 8u) {
    g_testingCallerCacheWays.store(ways, std::memory_order_release);
  }
}

void SetCallerThreadCacheCapacity(uint32_t capacity) noexcept {
  if (capacity == 0u || capacity == 64u || capacity == 256u ||
      capacity == 1024u) {
    g_testingCallerThreadCacheCapacity.store(capacity,
                                              std::memory_order_release);
    tls_callerThreadCache.Release();
  }
}

void SetHeapIdSlotHintCapacity(uint32_t capacity) noexcept {
  if (capacity == 0u || capacity == 64u || capacity == 256u ||
      capacity == 1024u) {
    g_testingHeapIdSlotHintCapacity.store(capacity,
                                          std::memory_order_release);
    tls_heapIdSlotHints.Release();
  }
}

void SetMainHeapPinEnabled(bool enabled) noexcept {
  g_testingMainHeapPinEnabled.store(enabled, std::memory_order_release);
}

void SetInPlaceReallocateEnabled(bool enabled) noexcept {
  g_testingInPlaceReallocateEnabled.store(enabled, std::memory_order_release);
}

void SetHeapDestroyBatchSize(uint32_t batchSize) noexcept {
  if (batchSize == 0u || batchSize == 256u || batchSize == 1024u ||
      batchSize == 4096u || batchSize == 16384u || batchSize == 65536u) {
    g_testingHeapDestroyBatchSize.store(batchSize, std::memory_order_release);
  }
}

void SetHeapDestroyTaggedSnapshotEnabled(bool enabled) noexcept {
  g_testingHeapDestroyTaggedSnapshotEnabled.store(enabled,
                                                  std::memory_order_release);
}

InPlaceReallocateStats GetInPlaceReallocateStats() noexcept {
  InPlaceReallocateStats stats{};
  stats.attempts =
      g_testingInPlaceReallocateAttempts.load(std::memory_order_relaxed);
  stats.successes =
      g_testingInPlaceReallocateSuccesses.load(std::memory_order_relaxed);
  stats.misses =
      g_testingInPlaceReallocateMisses.load(std::memory_order_relaxed);
  return stats;
}

uint32_t ResolveCallerHeap(const char* sourceFile,
                           int32_t sourceLine) noexcept {
  return ::ResolveCallerHeap(sourceFile, sourceLine);
}

uint32_t ComputeDirectCallerHeap(const char* sourceFile,
                                 int32_t sourceLine) noexcept {
  bool succeeded = false;
  const uint32_t result =
      ::ComputeDirectCallerHeap(sourceFile, sourceLine, &succeeded);
  return succeeded ? result : 0;
}

uint32_t GetRecentFreedSlot(const void* pointer) noexcept {
  return static_cast<uint32_t>(FreedSlot(pointer));
}

} // namespace Testing
#endif

} // namespace StormTakeover

namespace {

uint32_t CallNativeGetAllocated(uint32_t* outA, uint32_t* outB,
                                uint32_t* outC) noexcept {
  __try {
    return g_api.getAllocated ? g_api.getAllocated(outA, outB, outC) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

void WriteAllocatedOutputs(uint32_t value, uint32_t* outA, uint32_t* outB,
                           uint32_t* outC) noexcept {
  __try {
    if (outA) {
      *outA = value;
    }
    if (outB) {
      *outB = value;
    }
    if (outC) {
      *outC = value;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
  }
}

int CallNativeFindNextBlock(uint32_t heapId, const void* previousBlock,
                            void** nextBlock,
                            StormApi::BlockInfo481* info) noexcept {
  __try {
    return g_api.findNextBlock
               ? g_api.findNextBlock(heapId, previousBlock, nextBlock, info)
               : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

int CallNativeFindNextHeap(uint32_t currentHeapId, uint32_t* nextHeapId,
                           StormApi::HeapInfo482* info) noexcept {
  __try {
    return g_api.findNextHeap
               ? g_api.findNextHeap(currentHeapId, nextHeapId, info)
               : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

bool CollectNativeHeapSnapshots(uint32_t* count) noexcept {
  if (!count || !g_nativeHeapSnapshots) {
    return false;
  }
  *count = 0;
  uint32_t cursor = 0;
  for (;;) {
    if (*count == StormHeapRegistry::kHeapRegistryCapacity) {
      g_failures.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    uint32_t next = 0;
    StormApi::HeapInfo482 info{};
    info.structSize = sizeof(info);
    if (!CallNativeFindNextHeap(cursor, &next, &info)) {
      return true;
    }
    if (next == 0 || next == cursor) {
      g_failures.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    g_nativeHeapSnapshots[*count].heapId = next;
    g_nativeHeapSnapshots[*count].info = info;
    ++*count;
    cursor = next;
  }
}

struct HeapEnumerationAggregation {
  StormHeapRegistry::HeapSnapshot* snapshots = nullptr;
  uint32_t count = 0;
};

bool AggregateManagedHeapVisitor(void* raw, size_t usable,
                                 MemoryPool::BackendRoute route,
                                 void* context) noexcept {
  auto* aggregation = static_cast<HeapEnumerationAggregation*>(context);
  ManagedBlock block{};
  if (!aggregation ||
      !DecodeRawAllocation(raw, usable, route, &block)) {
    // The shared MemoryPool may also contain a block owned by the legacy
    // large-only hook. It has a different header and is not an ordinal 482
    // managed-heap allocation.
    return true;
  }
  auto* const begin = aggregation->snapshots;
  auto* const end = begin + aggregation->count;
  auto* found = std::lower_bound(
      begin, end, block.heapId,
      [](const StormHeapRegistry::HeapSnapshot& snapshot, uint32_t heapId) {
        return snapshot.heapId < heapId;
      });
  if (found == end || found->heapId != block.heapId) {
    return true;
  }
  ++found->allocationCount;
  found->liveRequestedBytes += block.requestedSize;
  found->liveUsableBytes += block.payloadUsableSize;
  return true;
}

bool RebuildHeapEnumerationCache() noexcept {
  g_heapEnumerationCacheValid = false;
  g_cachedManagedHeapCount = 0;
  g_cachedNativeHeapCount = 0;
  g_cachedBackendReservedBytes = 0;
  g_cachedBackendCommittedBytes = 0;

  uint32_t nativeCount = 0;
  if (!CollectNativeHeapSnapshots(&nativeCount)) {
    return false;
  }
  const auto copied = g_registry.CopySnapshots(
      g_heapSnapshots, StormHeapRegistry::kHeapRegistryCapacity,
      StormHeapRegistry::HeapStateMask(
          StormHeapRegistry::HeapState::Active));
  if (copied.invalidArgument || copied.truncated) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  std::sort(g_heapSnapshots, g_heapSnapshots + copied.written,
            [](const StormHeapRegistry::HeapSnapshot& left,
               const StormHeapRegistry::HeapSnapshot& right) {
              return left.heapId < right.heapId;
            });
  // Current live values are reconstructed only when ordinal 482 asks for
  // them. This removes several locked atomic updates from every ordinary
  // main-heap allocation while keeping the exported view exact.
  for (uint32_t index = 0; index < copied.written; ++index) {
    auto& snapshot = g_heapSnapshots[index];
    snapshot.liveRequestedBytes = 0;
    snapshot.liveUsableBytes = 0;
    snapshot.allocationCount = 0;
    snapshot.freeCount = 0;
    snapshot.reallocationCount = 0;
  }
  HeapEnumerationAggregation aggregation{g_heapSnapshots, copied.written};
  if (!MemoryPool::VisitAllocations(MemoryPool::BackendRoute::Automatic,
                                    &AggregateManagedHeapVisitor,
                                    &aggregation)) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
  for (uint32_t index = 0; index < copied.written; ++index) {
    auto& snapshot = g_heapSnapshots[index];
    snapshot.peakRequestedBytes =
        (std::max)(snapshot.peakRequestedBytes,
                   snapshot.liveRequestedBytes);
    snapshot.peakUsableBytes =
        (std::max)(snapshot.peakUsableBytes, snapshot.liveUsableBytes);
  }
  for (uint32_t index = 0; index < nativeCount; ++index) {
    g_nativeHeapIndex[index].heapId = g_nativeHeapSnapshots[index].heapId;
    g_nativeHeapIndex[index].snapshotIndex = index;
  }
  std::sort(g_nativeHeapIndex, g_nativeHeapIndex + nativeCount,
            [](const NativeHeapIndex& left, const NativeHeapIndex& right) {
              return left.heapId < right.heapId;
            });

  const auto pool = MemoryPool::GetExtendedStats();
  g_cachedManagedHeapCount = copied.written;
  g_cachedNativeHeapCount = nativeCount;
  g_cachedBackendReservedBytes = pool.reservedBytes;
  g_cachedBackendCommittedBytes = pool.committedBytes;
  g_heapEnumerationCacheValid = true;
  g_heapEnumerationRebuilds.fetch_add(1, std::memory_order_relaxed);
  return true;
}

const NativeHeapSnapshot* FindNativeSnapshot(uint32_t heapId,
                                              uint32_t nativeCount,
                                              uint32_t* orderIndex) noexcept {
  const NativeHeapIndex* const begin = g_nativeHeapIndex;
  const NativeHeapIndex* const end = begin + nativeCount;
  const NativeHeapIndex* found = std::lower_bound(
      begin, end, heapId,
      [](const NativeHeapIndex& entry, uint32_t id) {
        return entry.heapId < id;
      });
  if (found == end || found->heapId != heapId) {
    return nullptr;
  }
  if (orderIndex) {
    *orderIndex = found->snapshotIndex;
  }
  return &g_nativeHeapSnapshots[found->snapshotIndex];
}

const StormHeapRegistry::HeapSnapshot* FindManagedSnapshot(
    uint32_t heapId, uint32_t managedCount) noexcept {
  const StormHeapRegistry::HeapSnapshot* const begin = g_heapSnapshots;
  const StormHeapRegistry::HeapSnapshot* const end =
      begin + managedCount;
  const StormHeapRegistry::HeapSnapshot* found = std::lower_bound(
      begin, end, heapId,
      [](const StormHeapRegistry::HeapSnapshot& entry, uint32_t id) {
        return entry.heapId < id;
      });
  return found != end && found->heapId == heapId ? found : nullptr;
}

bool IsNativeSnapshotId(uint32_t heapId, uint32_t nativeCount) noexcept {
  return FindNativeSnapshot(heapId, nativeCount, nullptr) != nullptr;
}

const StormHeapRegistry::HeapSnapshot* FindNextManagedOnlySnapshot(
    uint32_t afterHeapId, uint32_t managedCount,
    uint32_t nativeCount) noexcept {
  const StormHeapRegistry::HeapSnapshot* const begin = g_heapSnapshots;
  const StormHeapRegistry::HeapSnapshot* const end =
      begin + managedCount;
  const StormHeapRegistry::HeapSnapshot* candidate = std::upper_bound(
      begin, end, afterHeapId,
      [](uint32_t id, const StormHeapRegistry::HeapSnapshot& entry) {
        return id < entry.heapId;
      });
  while (candidate != end &&
         IsNativeSnapshotId(candidate->heapId, nativeCount)) {
    ++candidate;
  }
  return candidate != end ? candidate : nullptr;
}

uint32_t CallNativeHeapCreate(void* baseAddress, uint32_t initialSize,
                              uint32_t flags, const char* sourceFile,
                              int32_t sourceLine) noexcept {
  __try {
    return g_api.heapCreate
               ? g_api.heapCreate(baseAddress, initialSize, flags, sourceFile,
                                  sourceLine)
               : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

int CallNativeHeapDestroy(uint32_t heapId) noexcept {
  __try {
    return g_api.heapDestroy ? g_api.heapDestroy(heapId) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

int CallNativeSetOption(uint32_t valueBits, uint32_t maskBits) noexcept {
  __try {
    return g_api.setOption ? g_api.setOption(valueBits, maskBits) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_failures.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
}

void RecordStormApiEvent(uint16_t ordinal, uint32_t heapId, uint32_t flags,
                         uint64_t primary, uint64_t secondary,
                         bool managed) noexcept {
  StormBreaker::LeakProfiler::StormApiEvent event{};
  event.domain = managed
                     ? StormBreaker::LeakProfiler::AllocationDomain::Managed
                     : StormBreaker::LeakProfiler::AllocationDomain::Native;
  event.metadata = MakeMetadata(
      heapId, flags, ordinal,
      managed ? static_cast<StormBreaker::LeakProfiler::BackendRoute>(
                    g_lastRoute.load(std::memory_order_relaxed))
              : StormBreaker::LeakProfiler::BackendRoute::NativeStorm);
  event.primaryValue = primary;
  event.secondaryValue = secondary;
  StormBreaker::LeakProfiler::RecordStormApi(event);
}

void RecordReallocEvent(
    void* oldPointer, void* newPointer, uint32_t oldSize, uint32_t newSize,
    bool oldManaged, bool newManaged, bool oldFreed, bool newAllocated,
    bool inPlace, const StormBreaker::LeakProfiler::EventMetadata& oldMetadata,
    const StormBreaker::LeakProfiler::EventMetadata& newMetadata) noexcept {
  StormBreaker::LeakProfiler::ReallocOutcome event{};
  event.oldPointer = oldPointer;
  event.newPointer = newPointer;
  event.oldSize = oldSize;
  event.newSize = newSize;
  event.oldFreed = oldFreed;
  event.newAllocated = newAllocated;
  event.inPlace = inPlace;
  event.domain = oldManaged
                     ? StormBreaker::LeakProfiler::AllocationDomain::Managed
                     : StormBreaker::LeakProfiler::AllocationDomain::Native;
  event.newDomain = newManaged
                        ? StormBreaker::LeakProfiler::AllocationDomain::Managed
                        : StormBreaker::LeakProfiler::AllocationDomain::Native;
  event.metadata = oldMetadata;
  event.newMetadata = newMetadata;
  StormBreaker::LeakProfiler::RecordReallocOutcome(event);
}

bool IsManagedAccess(StormHeapRegistry::AccessResult result) noexcept {
  return result == StormHeapRegistry::AccessResult::Managed;
}

} // namespace

extern "C" void* __fastcall HookedFull_SMemAlloc(
    int ecx, int edx, uint32_t size, const char* sourceFile,
    int32_t sourceLine, uint32_t flags) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeAlloc(ecx, edx, size, sourceFile, sourceLine, flags);
  }
  if (!ShouldManage(size) && !DetailedAccountingEnabled()) {
    return CallNativeAlloc(ecx, edx, size, sourceFile, sourceLine, flags);
  }

  CallerHeapCacheEntry* callerCacheEntry = nullptr;
  const uint32_t heapId =
      ResolveCallerHeap(sourceFile, sourceLine, &callerCacheEntry);
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = heapId != 0
                          ? AcquireCallerHeap(heapId, sourceFile, sourceLine,
                                              callerCacheEntry, &guard)
                          : StormHeapRegistry::AccessResult::InvalidArgument;
  if (!IsProtectMemoryEnabled() && ShouldManage(size) &&
      IsManagedAccess(access)) {
    ManagedAllocation allocation = AllocateManagedRaw(heapId, size, flags);
    if (allocation.pointer) {
      AccountAllocation(guard, allocation.block);
      const auto route = ProfilerRoute(allocation.block.route);
      NoteCall(StormApi::kOrdinalAlloc, heapId, flags, route,
               StormBreaker::LeakProfiler::DegradedReason::None, true, false,
               false);
      StormBreaker::LeakProfiler::RecordAlloc(
          allocation.pointer, size,
          StormBreaker::LeakProfiler::AllocationDomain::Managed,
          MakeMetadata(heapId, flags, StormApi::kOrdinalAlloc, route));
      return allocation.pointer;
    }
  }

  const bool attemptedManaged = !IsProtectMemoryEnabled() &&
                                ShouldManage(size) &&
                                IsManagedAccess(access);
  const bool protectFallback = IsProtectMemoryEnabled() && ShouldManage(size);
  void* native = CallNativeAlloc(ecx, edx, size, sourceFile, sourceLine, flags);
  const auto reason = protectFallback
                          ? StormBreaker::LeakProfiler::DegradedReason::ProtectMemory
                      : attemptedManaged
                          ? StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory
                          : StormBreaker::LeakProfiler::DegradedReason::BelowTakeoverThreshold;
  NoteCall(StormApi::kOrdinalAlloc, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm, reason,
           false, attemptedManaged || protectFallback,
           attemptedManaged || protectFallback, size);
  if (native) {
    StormBreaker::LeakProfiler::RecordAlloc(
        native, size, StormBreaker::LeakProfiler::AllocationDomain::Native,
        MakeMetadata(heapId, flags, StormApi::kOrdinalAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
                     reason, attemptedManaged || protectFallback,
                     attemptedManaged || protectFallback));
  }
  return native;
}

extern "C" int __stdcall HookedFull_SMemFree(
    void* pointer, const char* sourceFile, int32_t sourceLine,
    uint32_t flags) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeFree(pointer, sourceFile, sourceLine, flags);
  }
  const FastFreeResult fastFree =
      TryFastManagedFree(pointer, 0, false);
  if (fastFree.disposition == FastFreeDisposition::Freed) {
    const auto route = ProfilerRoute(fastFree.block.route);
    NoteCall(StormApi::kOrdinalFree, fastFree.block.heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    StormBreaker::LeakProfiler::RecordFree(
        pointer, fastFree.block.requestedSize,
        StormBreaker::LeakProfiler::AllocationDomain::Managed,
        MakeMetadata(fastFree.block.heapId, flags, StormApi::kOrdinalFree,
                     route));
    return 1;
  }
  if (fastFree.disposition == FastFreeDisposition::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    NoteCall(StormApi::kOrdinalFree, 0, flags,
             StormBreaker::LeakProfiler::BackendRoute::Unknown,
             StormBreaker::LeakProfiler::DegradedReason::PointerRejected,
             true, false, true);
    return 0;
  }
  ManagedBlock block{};
  const auto query = QueryPointerImpl(pointer, &block);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    NoteCall(StormApi::kOrdinalFree, 0, flags,
             StormBreaker::LeakProfiler::BackendRoute::Unknown,
             StormBreaker::LeakProfiler::DegradedReason::PointerRejected,
             true, false, true);
    return 0;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    StormHeapRegistry::Registry::OperationGuard guard;
    if (!IsManagedAccess(
            AcquireHeap(block.heapId, false, nullptr, 0, &guard))) {
      g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
      return 0;
    }
    if (!FreeManagedRaw(block)) {
      g_failures.fetch_add(1, std::memory_order_relaxed);
      return 0;
    }
    AccountFree(guard, block);
    const auto route = ProfilerRoute(block.route);
    NoteCall(StormApi::kOrdinalFree, block.heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    StormBreaker::LeakProfiler::RecordFree(
        pointer, block.requestedSize,
        StormBreaker::LeakProfiler::AllocationDomain::Managed,
        MakeMetadata(block.heapId, flags, StormApi::kOrdinalFree, route));
    return 1;
  }

  const int nativeSize = StormBreaker::LeakProfiler::IsEnabled()
                             ? CallNativeGetSize(pointer, sourceFile, sourceLine)
                             : -1;
  const NativeLargeInfo largeInfo = QueryNativeLarge(pointer);
  const int result = CallNativeFree(pointer, sourceFile, sourceLine, flags);
  if (result) {
    ApplyNativeCounterCorrection(largeInfo);
    if (pointer && nativeSize >= 0) {
      StormBreaker::LeakProfiler::RecordFree(
          pointer, static_cast<uint32_t>(nativeSize),
          StormBreaker::LeakProfiler::AllocationDomain::Native,
          MakeMetadata(0, flags, StormApi::kOrdinalFree,
                       StormBreaker::LeakProfiler::BackendRoute::NativeStorm));
    }
  }
  NoteCall(StormApi::kOrdinalFree, 0, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  return result;
}

extern "C" int __stdcall HookedFull_SMemGetSize(
    const void* pointer, const char* sourceFile, int32_t sourceLine) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeGetSize(pointer, sourceFile, sourceLine);
  }
  ManagedBlock block{};
  const auto query = QueryPointerImpl(pointer, &block);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return -1;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    StormHeapRegistry::Registry::OperationGuard guard;
    if (!IsManagedAccess(
            AcquireHeap(block.heapId, false, nullptr, 0, &guard))) {
      return -1;
    }
    NoteCall(StormApi::kOrdinalGetSize, block.heapId, 0,
             ProfilerRoute(block.route),
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    return static_cast<int>(block.requestedSize);
  }
  NoteCall(StormApi::kOrdinalGetSize, 0, 0,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  return CallNativeGetSize(pointer, sourceFile, sourceLine);
}

extern "C" void* __fastcall HookedFull_SMemReAlloc(
    int ecx, int edx, void* pointer, uint32_t newSize,
    const char* sourceFile, int32_t sourceLine, uint32_t flags) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeReAlloc(ecx, edx, pointer, newSize, sourceFile,
                             sourceLine, flags);
  }

  if (!pointer && !ShouldManage(newSize) && !DetailedAccountingEnabled()) {
    return CallNativeAlloc(ecx, edx, newSize, sourceFile, sourceLine, flags);
  }

  if (!pointer) {
    CallerHeapCacheEntry* callerCacheEntry = nullptr;
    const uint32_t heapId =
        ResolveCallerHeap(sourceFile, sourceLine, &callerCacheEntry);
    StormHeapRegistry::Registry::OperationGuard guard;
    const auto access = heapId
                            ? AcquireCallerHeap(heapId, sourceFile,
                                                sourceLine, callerCacheEntry,
                                                &guard)
                            : StormHeapRegistry::AccessResult::InvalidArgument;
    const bool protectFallback = IsProtectMemoryEnabled() &&
                                 ShouldManage(newSize);
    const bool attemptedManaged = !IsProtectMemoryEnabled() &&
                                  ShouldManage(newSize) &&
                                  IsManagedAccess(access);
    if (attemptedManaged) {
      ManagedAllocation allocation = AllocateManagedRaw(heapId, newSize, flags);
      if (allocation.pointer) {
        AccountAllocation(guard, allocation.block);
        const auto route = ProfilerRoute(allocation.block.route);
        NoteCall(StormApi::kOrdinalReAlloc, heapId, flags, route,
                 StormBreaker::LeakProfiler::DegradedReason::None, true, false,
                 false);
        RecordReallocEvent(nullptr, allocation.pointer, 0, newSize, false, true,
                           false, true, false,
                           MakeMetadata(0, flags, StormApi::kOrdinalReAlloc,
                                        StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
                           MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc,
                                        route));
        return allocation.pointer;
      }
    }
    void* native = CallNativeAlloc(ecx, edx, newSize, sourceFile, sourceLine,
                                   flags);
    const auto reason = protectFallback
                            ? StormBreaker::LeakProfiler::DegradedReason::ProtectMemory
                        : attemptedManaged
                            ? StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory
                            : StormBreaker::LeakProfiler::DegradedReason::BelowTakeoverThreshold;
    NoteCall(StormApi::kOrdinalReAlloc, heapId, flags,
             StormBreaker::LeakProfiler::BackendRoute::NativeStorm, reason,
             false, attemptedManaged || protectFallback,
             attemptedManaged || protectFallback, newSize);
    RecordReallocEvent(nullptr, native, 0, newSize, false, false, false,
                       native != nullptr, false,
                       MakeMetadata(0, flags, StormApi::kOrdinalReAlloc,
                                    StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
                       MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc,
                                    StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
                                    reason, attemptedManaged || protectFallback,
                                    attemptedManaged || protectFallback));
    return native;
  }

  ManagedBlock oldBlock{};
  const auto query = QueryPointerImpl(pointer, &oldBlock);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    StormHeapRegistry::Registry::OperationGuard guard;
    if (!IsManagedAccess(
            AcquireHeap(oldBlock.heapId, false, nullptr, 0, &guard))) {
      return nullptr;
    }
    ReallocResult outcome = ReallocateManaged(
        oldBlock, guard, newSize, flags, false, ecx, edx, sourceFile,
        sourceLine);
    const auto oldRoute = ProfilerRoute(oldBlock.route);
    const auto newRoute = outcome.newManaged
                              ? ProfilerRoute(outcome.newBlock.route)
                              : StormBreaker::LeakProfiler::BackendRoute::NativeStorm;
    NoteCall(StormApi::kOrdinalReAlloc, oldBlock.heapId, flags,
             outcome.succeeded ? newRoute : oldRoute,
             outcome.succeeded
                 ? StormBreaker::LeakProfiler::DegradedReason::None
                 : StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory,
             outcome.newManaged || !outcome.succeeded,
             outcome.succeeded && !outcome.newManaged,
             outcome.succeeded && !outcome.newManaged, newSize);
    RecordReallocEvent(
        pointer, outcome.pointer, oldBlock.requestedSize, newSize, true,
        outcome.newManaged, outcome.oldFreed, outcome.newAllocated,
        outcome.inPlace,
        MakeMetadata(oldBlock.heapId, flags, StormApi::kOrdinalReAlloc,
                     oldRoute),
        MakeMetadata(oldBlock.heapId, flags, StormApi::kOrdinalReAlloc,
                     newRoute));
    return outcome.pointer;
  }

  if (StormTakeover::GetMode() == StormTakeover::TakeoverMode::Large &&
      !DetailedAccountingEnabled()) {
    const NativeLargeInfo largeInfo = QueryNativeLarge(pointer);
    void* native = CallNativeReAlloc(ecx, edx, pointer, newSize, sourceFile,
                                     sourceLine, flags);
    if (native && native != pointer) {
      ApplyNativeCounterCorrection(largeInfo);
    }
    return native;
  }

  const int oldSize = CallNativeGetSize(pointer, sourceFile, sourceLine);
  const uint32_t heapId = CallNativeGetHeapByPtr(pointer);
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = heapId
                          ? AcquireHeap(heapId, true, sourceFile, sourceLine,
                                        &guard)
                          : StormHeapRegistry::AccessResult::InvalidArgument;
  ReallocResult migrated{};
  const bool preserveNativeSmallZero =
      newSize == 0 && oldSize >= 0 &&
      static_cast<uint32_t>(oldSize) < StormApi::kNativeLargeThreshold &&
      !IsReallocShuffleEnabled();
  if (StormTakeover::GetMode() != StormTakeover::TakeoverMode::Large &&
      !preserveNativeSmallZero && oldSize >= 0 && IsManagedAccess(access) &&
      TryMigrateNativeToManaged(pointer, static_cast<uint32_t>(oldSize),
                                newSize, flags, heapId, false,
                                sourceFile, sourceLine, guard, &migrated)) {
    const auto route = ProfilerRoute(migrated.newBlock.route);
    NoteCall(StormApi::kOrdinalReAlloc, heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    RecordReallocEvent(
        pointer, migrated.pointer, static_cast<uint32_t>(oldSize), newSize,
        false, true, true, true, false,
        MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
        MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc, route));
    return migrated.pointer;
  }

  const NativeLargeInfo largeInfo = QueryNativeLarge(pointer);
  void* native = CallNativeReAlloc(ecx, edx, pointer, newSize, sourceFile,
                                   sourceLine, flags);
  if (native && native != pointer) {
    ApplyNativeCounterCorrection(largeInfo);
  }
  NoteCall(StormApi::kOrdinalReAlloc, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  RecordReallocEvent(
      pointer, native, oldSize >= 0 ? static_cast<uint32_t>(oldSize) : 0,
      newSize, false, false, native && native != pointer, native != nullptr,
      native == pointer,
      MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc,
                   StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
      MakeMetadata(heapId, flags, StormApi::kOrdinalReAlloc,
                   StormBreaker::LeakProfiler::BackendRoute::NativeStorm));
  return native;
}

extern "C" uint32_t __stdcall HookedFull_SMemGetAllocated(
    uint32_t* outA, uint32_t* outB, uint32_t* outC) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeGetAllocated(outA, outB, outC);
  }
  const uint32_t native = CallNativeGetAllocated(nullptr, nullptr, nullptr);
  const uint64_t managedRequested = MemoryPool::GetRequestedLiveBytes();
  const uint32_t combined =
      native + static_cast<uint32_t>(managedRequested);
  WriteAllocatedOutputs(combined, outA, outB, outC);
  NoteCall(StormApi::kOrdinalGetAllocated, 0, 0,
           StormBreaker::LeakProfiler::BackendRoute::Unknown,
           StormBreaker::LeakProfiler::DegradedReason::None, true, false,
           false);
  RecordStormApiEvent(StormApi::kOrdinalGetAllocated, 0, 0, combined, native,
                      true);
  return combined;
}

extern "C" int __stdcall HookedFull_SMemFindNextBlock(
    uint32_t heapId, const void* previousBlock, void** nextBlock,
    StormApi::BlockInfo481* info) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeFindNextBlock(heapId, previousBlock, nextBlock, info);
  }
  if (heapId == 0 || !nextBlock || !info ||
      info->structSize != sizeof(*info)) {
    return 0;
  }
  g_blockEnumerationCalls.fetch_add(1, std::memory_order_relaxed);
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireHeap(heapId, false, nullptr, 0, &guard);
  if (access == StormHeapRegistry::AccessResult::Tombstone) {
    *nextBlock = nullptr;
    return 0;
  }

  if (!previousBlock) {
    // A null cursor always starts a new chain. Native Storm blocks retain
    // their original order and are followed by one managed snapshot.
    ReleaseManagedBlockEnumeration();
  }
  if (previousBlock && tls_blockEnumeration.heapId == heapId &&
      tls_blockEnumeration.exhaustedCursor == previousBlock) {
    *nextBlock = nullptr;
    return 0;
  }

  bool previousIsManaged =
      CachedEnumerationContains(heapId, previousBlock);
  bool previousIsForeignManaged = false;
  if (previousBlock && !previousIsManaged) {
    ManagedBlock decodedPrevious{};
    if (TryDecodePointerHeader(previousBlock, &decodedPrevious)) {
      previousIsManaged = decodedPrevious.heapId == heapId;
      previousIsForeignManaged = !previousIsManaged;
    }
  }
  if (previousIsForeignManaged) {
    *nextBlock = nullptr;
    return 0;
  }

  if (!previousIsManaged) {
    const int native = CallNativeFindNextBlock(
        heapId, previousBlock, nextBlock, info);
    if (native && *nextBlock) {
      NoteCall(StormApi::kOrdinalFindNextBlock, heapId, 0,
               StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
               StormBreaker::LeakProfiler::DegradedReason::None, false,
               false, false);
      RecordStormApiEvent(StormApi::kOrdinalFindNextBlock, heapId, 0,
                          reinterpret_cast<uintptr_t>(*nextBlock),
                          info->requestedBytes, false);
      return 1;
    }
  }

  ManagedBlock managed{};
  const void* managedCursor = previousIsManaged ? previousBlock : nullptr;
  if (!FindCachedManagedNext(heapId, managedCursor, &managed)) {
    *nextBlock = nullptr;
    NoteCall(StormApi::kOrdinalFindNextBlock, heapId, 0,
             StormBreaker::LeakProfiler::BackendRoute::Unknown,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    return 0;
  }
  const uint32_t structureSize = info->structSize;
  memset(info, 0, sizeof(*info));
  info->structSize = structureSize;
  info->block = managed.user;
  info->allocated = TRUE;
  info->valid = ValidateCanary(managed) ? TRUE : FALSE;
  info->requestedBytes = managed.requestedSize;
  info->overheadBytes = static_cast<uint32_t>(
      managed.physicalUsableSize > managed.requestedSize
          ? managed.physicalUsableSize - managed.requestedSize
          : 0);
  *nextBlock = managed.user;
  NoteCall(StormApi::kOrdinalFindNextBlock, heapId, 0,
           ProfilerRoute(managed.route),
           StormBreaker::LeakProfiler::DegradedReason::None, true, false,
           false);
  RecordStormApiEvent(StormApi::kOrdinalFindNextBlock, heapId, 0,
                      reinterpret_cast<uintptr_t>(*nextBlock),
                      info->requestedBytes, true);
  return 1;
}

extern "C" int __stdcall HookedFull_SMemFindNextHeap(
    uint32_t currentHeapId, uint32_t* nextHeapId,
    StormApi::HeapInfo482* info) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeFindNextHeap(currentHeapId, nextHeapId, info);
  }
  if (!nextHeapId || !info || info->structSize != sizeof(*info)) {
    return 0;
  }

  g_heapEnumerationCalls.fetch_add(1, std::memory_order_relaxed);
  AcquireSRWLockExclusive(&g_snapshotLock);
  if ((currentHeapId == 0 || !g_heapEnumerationCacheValid) &&
      !RebuildHeapEnumerationCache()) {
    ReleaseSRWLockExclusive(&g_snapshotLock);
    *nextHeapId = 0;
    return 0;
  }
  const uint32_t nativeCount = g_cachedNativeHeapCount;
  const uint32_t managedCount = g_cachedManagedHeapCount;

  enum class Selection : uint8_t { None, Native, Managed, Aggregate };
  Selection selection = Selection::None;
  uint32_t nativeIndex = 0;
  const StormHeapRegistry::HeapSnapshot* managed = nullptr;

  if (currentHeapId == 0) {
    if (nativeCount != 0) {
      selection = Selection::Native;
    } else if ((managed = FindNextManagedOnlySnapshot(
                    0, managedCount, nativeCount)) != nullptr) {
      selection = Selection::Managed;
    } else {
      selection = Selection::Aggregate;
    }
  } else {
    uint32_t currentNativeIndex = 0;
    const bool currentWasNative =
        FindNativeSnapshot(currentHeapId, nativeCount,
                           &currentNativeIndex) != nullptr;
    if (currentWasNative) {
      if (currentNativeIndex + 1 < nativeCount) {
        nativeIndex = currentNativeIndex + 1;
        selection = Selection::Native;
      } else if ((managed = FindNextManagedOnlySnapshot(
                      0, managedCount, nativeCount)) != nullptr) {
        selection = Selection::Managed;
      } else {
        selection = Selection::Aggregate;
      }
    }
    if (!currentWasNative && currentHeapId != kAggregateHeapId) {
      const auto* currentManaged =
          FindManagedSnapshot(currentHeapId, managedCount);
      if (currentManaged &&
          !IsNativeSnapshotId(currentHeapId, nativeCount)) {
        managed = FindNextManagedOnlySnapshot(
            currentHeapId, managedCount, nativeCount);
        selection = managed ? Selection::Managed : Selection::Aggregate;
      }
    }
  }

  if (selection == Selection::None) {
    if (currentHeapId == kAggregateHeapId) {
      g_heapEnumerationCacheValid = false;
    }
    ReleaseSRWLockExclusive(&g_snapshotLock);
    *nextHeapId = 0;
    return 0;
  }

  const uint32_t structureSize = info->structSize;
  bool returnedManaged = false;
  uint32_t selectedId = 0;
  if (selection == Selection::Native) {
    const NativeHeapSnapshot& selected = g_nativeHeapSnapshots[nativeIndex];
    selectedId = selected.heapId;
    *info = selected.info;
    const auto* matchingManaged =
        FindManagedSnapshot(selectedId, managedCount);
    if (matchingManaged) {
      info->liveAllocationCount += static_cast<uint32_t>(
          matchingManaged->allocationCount -
          (std::min)(matchingManaged->allocationCount,
                     matchingManaged->freeCount));
      info->requestedBytes +=
          static_cast<uint32_t>(matchingManaged->liveRequestedBytes);
      returnedManaged = true;
    }
  } else {
    memset(info, 0, sizeof(*info));
    info->structSize = structureSize;
    selectedId = selection == Selection::Aggregate
                     ? kAggregateHeapId
                     : managed->heapId;
    info->heapId = selectedId;
    info->maxAllocationSize = 0x7FFFFFFFu;
    if (selection == Selection::Aggregate) {
      _snprintf_s(info->sourceName, sizeof(info->sourceName), _TRUNCATE,
                  "StormBreaker managed backend (%s)",
                  MemoryPool::GetBackendName());
      info->committedBytes =
          static_cast<uint32_t>(g_cachedBackendCommittedBytes);
      info->reservedBytes =
          static_cast<uint32_t>(g_cachedBackendReservedBytes);
      returnedManaged = true;
    } else {
      memcpy(info->sourceName, managed->name,
             (std::min)(sizeof(managed->name), sizeof(info->sourceName) - 1));
      info->sourceLine = static_cast<int32_t>(managed->sourceLine);
      info->liveAllocationCount = static_cast<uint32_t>(
          managed->allocationCount -
          (std::min)(managed->allocationCount, managed->freeCount));
      info->requestedBytes =
          static_cast<uint32_t>(managed->liveRequestedBytes);
      returnedManaged = true;
    }
  }
  ReleaseSRWLockExclusive(&g_snapshotLock);
  *nextHeapId = selectedId;
  NoteCall(StormApi::kOrdinalFindNextHeap, selectedId, 0,
           returnedManaged
               ? StormBreaker::LeakProfiler::BackendRoute::Unknown
               : StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, returnedManaged,
           false, false);
  RecordStormApiEvent(StormApi::kOrdinalFindNextHeap, selectedId, 0,
                      info->requestedBytes, info->committedBytes,
                      returnedManaged);
  return 1;
}

extern "C" uint32_t __stdcall HookedFull_SMemGetHeapByCaller(
    const char* sourceFile, int32_t sourceLine) {
  ScopedHookDepth depth;
  CallerHeapCacheEntry* callerCacheEntry = nullptr;
  const uint32_t heapId =
      ResolveCallerHeap(sourceFile, sourceLine, &callerCacheEntry);
  if (!depth.IsOutermost() || heapId == 0) {
    return heapId;
  }
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireCallerHeap(
      heapId, sourceFile, sourceLine, callerCacheEntry, &guard);
  const bool managed = IsManagedAccess(access);
  NoteCall(StormApi::kOrdinalGetHeapByCaller, heapId, 0,
           StormBreaker::LeakProfiler::BackendRoute::Unknown,
           managed ? StormBreaker::LeakProfiler::DegradedReason::None
                   : StormBreaker::LeakProfiler::DegradedReason::RegistryCapacity,
           managed, false, !managed);
  RecordStormApiEvent(StormApi::kOrdinalGetHeapByCaller, heapId, 0, heapId, 0,
                      managed);
  return heapId;
}

extern "C" uint32_t __stdcall HookedFull_SMemGetHeapByPtr(
    const void* pointer) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeGetHeapByPtr(pointer);
  }
  ManagedBlock block{};
  const auto query = QueryPointerImpl(pointer, &block);
  if (query == StormTakeover::BlockQueryResult::Managed) {
    NoteCall(StormApi::kOrdinalGetHeapByPtr, block.heapId, 0,
             ProfilerRoute(block.route),
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    return block.heapId;
  }
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  const uint32_t heapId = CallNativeGetHeapByPtr(pointer);
  NoteCall(StormApi::kOrdinalGetHeapByPtr, heapId, 0,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  return heapId;
}

extern "C" void* __stdcall HookedFull_SMemHeapAlloc(
    uint32_t heapId, uint32_t flags, uint32_t size) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeHeapAlloc(heapId, flags, size);
  }
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireHeap(heapId, false, nullptr, 0, &guard);
  if (access == StormHeapRegistry::AccessResult::Tombstone) {
    return nullptr;
  }
  const bool protectFallback = IsProtectMemoryEnabled() &&
                               ShouldManage(size) &&
                               IsManagedAccess(access);
  const bool attemptedManaged = !IsProtectMemoryEnabled() &&
                                ShouldManage(size) &&
                                IsManagedAccess(access);
  if (attemptedManaged) {
    ManagedAllocation allocation = AllocateManagedRaw(heapId, size, flags);
    if (allocation.pointer) {
      AccountAllocation(guard, allocation.block);
      const auto route = ProfilerRoute(allocation.block.route);
      NoteCall(StormApi::kOrdinalHeapAlloc, heapId, flags, route,
               StormBreaker::LeakProfiler::DegradedReason::None, true, false,
               false);
      StormBreaker::LeakProfiler::RecordAlloc(
          allocation.pointer, size,
          StormBreaker::LeakProfiler::AllocationDomain::Managed,
          MakeMetadata(heapId, flags, StormApi::kOrdinalHeapAlloc, route));
      return allocation.pointer;
    }
  }
  void* native = CallNativeHeapAlloc(heapId, flags, size);
  const auto reason = protectFallback
                          ? StormBreaker::LeakProfiler::DegradedReason::ProtectMemory
                      : attemptedManaged
                          ? StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory
                          : StormBreaker::LeakProfiler::DegradedReason::BelowTakeoverThreshold;
  NoteCall(StormApi::kOrdinalHeapAlloc, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm, reason,
           false, attemptedManaged || protectFallback,
           attemptedManaged || protectFallback, size);
  if (native) {
    StormBreaker::LeakProfiler::RecordAlloc(
        native, size, StormBreaker::LeakProfiler::AllocationDomain::Native,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
                     reason, attemptedManaged || protectFallback,
                     attemptedManaged || protectFallback));
  }
  return native;
}

extern "C" uint32_t __stdcall HookedFull_SMemHeapCreate(
    void* baseAddress, uint32_t initialSize, uint32_t flags,
    const char* sourceFile, int32_t sourceLine) {
  ScopedHookDepth depth;
  const uint32_t heapId = CallNativeHeapCreate(
      baseAddress, initialSize, flags, sourceFile, sourceLine);
  if (!depth.IsOutermost() || heapId == 0 || baseAddress != nullptr) {
    return heapId;
  }

  bool managed = false;
  if (StormTakeover::GetMode() == StormTakeover::TakeoverMode::Full &&
      !IsProtectMemoryEnabled()) {
    void* sentinel =
        CallNativeHeapAlloc(heapId, StormApi::kFlagPersistent, 0);
    if (sentinel) {
      const auto registered = g_registry.RegisterManaged(
          heapId, StormHeapRegistry::HeapKind::Explicit, sourceFile,
          static_cast<uint32_t>(sourceLine));
      managed =
          registered == StormHeapRegistry::CreateResult::CreatedManaged ||
          registered == StormHeapRegistry::CreateResult::AlreadyManaged;
      if (!managed || !g_registry.SetNativeSentinel(heapId, sentinel)) {
        CallNativeHeapFree(heapId, 0, sentinel);
        managed = false;
      }
    }
  }
  if (!managed) {
    g_registry.RegisterNative(heapId, StormHeapRegistry::HeapKind::Explicit,
                              sourceFile,
                              static_cast<uint32_t>(sourceLine));
  }
  NoteCall(StormApi::kOrdinalHeapCreate, heapId, flags,
           managed ? StormBreaker::LeakProfiler::BackendRoute::Unknown
                   : StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           managed ? StormBreaker::LeakProfiler::DegradedReason::None
                   : StormBreaker::LeakProfiler::DegradedReason::ExplicitNativeHeap,
           managed, false, !managed &&
                               StormTakeover::GetMode() ==
                                   StormTakeover::TakeoverMode::Full);
  RecordStormApiEvent(StormApi::kOrdinalHeapCreate, heapId, flags, initialSize,
                      heapId, managed);
  return heapId;
}

extern "C" int __stdcall HookedFull_SMemHeapDestroy(uint32_t heapId) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeHeapDestroy(heapId);
  }
  StormHeapRegistry::DestroyToken token{};
  const auto begun = g_registry.BeginDestroy(heapId, &token);
  if (begun != StormHeapRegistry::DestroyResult::BegunManaged) {
    if (begun != StormHeapRegistry::DestroyResult::BegunNative &&
        begun != StormHeapRegistry::DestroyResult::NotFound) {
      NoteCall(StormApi::kOrdinalHeapDestroy, heapId, 0,
               StormBreaker::LeakProfiler::BackendRoute::Unknown,
               StormBreaker::LeakProfiler::DegradedReason::PointerRejected,
               false, false, true);
      return 0;
    }
    const uint32_t nativeBefore = SumNativeHeapRequested(heapId);
    const int native = CallNativeHeapDestroy(heapId);
    bool nativeSurvivors = false;
    const uint32_t nativeAfter =
        SumNativeHeapRequested(heapId, &nativeSurvivors);
    if (nativeBefore >= nativeAfter) {
      SubtractNativeCounter(nativeBefore - nativeAfter);
    }
    if (begun == StormHeapRegistry::DestroyResult::BegunNative) {
      if (native && !nativeSurvivors) {
        g_registry.FinishDestroy(
            &token, StormHeapRegistry::FinishMode::DiscardLiveStatistics);
      } else {
        g_registry.CancelDestroy(&token);
      }
    }
    NoteCall(StormApi::kOrdinalHeapDestroy, heapId, 0,
             StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
             StormBreaker::LeakProfiler::DegradedReason::None, false, false,
             false);
    return native;
  }

  AcquireSRWLockExclusive(&g_destroyLock);
  if (tls_blockEnumeration.heapId == heapId) {
    ReleaseManagedBlockEnumeration();
  }
  bool trackRegistryStatistics =
      !StormHeapRegistry::IsMainHeapId(heapId) ||
      MainRegistryAccountingEnabled();
#if defined(STORMBREAKER_TESTING)
  trackRegistryStatistics =
      trackRegistryStatistics &&
      g_testingRegistryAccountingEnabled.load(std::memory_order_relaxed);
#endif
  uint32_t persistentCount = 0;
  bool failed = false;
  const uint32_t snapshotCapacity = (std::max)(
      1u, g_liveBlocks.load(std::memory_order_acquire));
  DestroySnapshotEntry* destroySnapshot = nullptr;
  if (snapshotCapacity <=
      (std::numeric_limits<size_t>::max)() /
          sizeof(DestroySnapshotEntry)) {
    destroySnapshot = static_cast<DestroySnapshotEntry*>(VirtualAlloc(
        nullptr, static_cast<size_t>(snapshotCapacity) *
                     sizeof(DestroySnapshotEntry),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  }
  if (!destroySnapshot) {
    failed = true;
  }

  bool taggedDestroySnapshot = false;
#if defined(STORMBREAKER_TESTING)
  taggedDestroySnapshot = g_testingHeapDestroyTaggedSnapshotEnabled.load(
      std::memory_order_relaxed);
#endif
  DestroyCollectContext collect{};
  if (!failed) {
    collect.heapId = heapId;
    collect.entries = destroySnapshot;
    collect.capacity = snapshotCapacity;
    collect.taggedSnapshot = taggedDestroySnapshot;
    const bool visited = MemoryPool::VisitAllocations(
        MemoryPool::BackendRoute::Automatic,
        &CollectDestroyVisitor, &collect);
    persistentCount = collect.persistentCount;
    failed = !visited || collect.invalid || collect.overflow;
    if (!failed) {
      g_heapDestroySnapshots.fetch_add(1, std::memory_order_relaxed);
      g_heapDestroySnapshotBlocks.fetch_add(collect.count,
                                            std::memory_order_relaxed);
    }
  }

  uint32_t destroyBatchSize = 0u;
#if defined(STORMBREAKER_TESTING)
  destroyBatchSize =
      g_testingHeapDestroyBatchSize.load(std::memory_order_relaxed);
#endif
  MemoryPool::BatchFreeEntry* destroyBatch = nullptr;
  LegacyDestroyBatchMetadata* legacyBatchMetadata = nullptr;
  void* destroyBatchAllocation = nullptr;
  uint32_t destroyBatchCapacity = 0;
  if (!failed && collect.count != 0 && destroyBatchSize != 0) {
    destroyBatchCapacity = (std::min)(collect.count, destroyBatchSize);
    const size_t batchEntryBytes =
        static_cast<size_t>(destroyBatchCapacity) *
        sizeof(MemoryPool::BatchFreeEntry);
    const size_t batchMetadataBytes =
        taggedDestroySnapshot
            ? 0u
            : static_cast<size_t>(destroyBatchCapacity) *
                  sizeof(LegacyDestroyBatchMetadata);
    destroyBatchAllocation = VirtualAlloc(
        nullptr, batchEntryBytes + batchMetadataBytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (destroyBatchAllocation) {
      destroyBatch =
          static_cast<MemoryPool::BatchFreeEntry*>(destroyBatchAllocation);
      if (!taggedDestroySnapshot) {
        legacyBatchMetadata =
            reinterpret_cast<LegacyDestroyBatchMetadata*>(
                static_cast<uint8_t*>(destroyBatchAllocation) +
                batchEntryBytes);
      }
    } else {
      destroyBatchCapacity = 0;
      g_heapDestroyBatchFallbacks.fetch_add(1, std::memory_order_relaxed);
    }
  }

  if (destroyBatch) {
    uint32_t index = 0;
    while (index < collect.count && !failed) {
      const MemoryPool::BackendRoute route = DestroySnapshotRoute(
          destroySnapshot[index], taggedDestroySnapshot);
      uint32_t routeEnd = index + 1u;
      while (routeEnd < collect.count &&
             DestroySnapshotRoute(destroySnapshot[routeEnd],
                                  taggedDestroySnapshot) == route) {
        ++routeEnd;
      }
      while (index < routeEnd && !failed) {
        const uint32_t chunkCount =
            (std::min)(destroyBatchCapacity, routeEnd - index);
        if (!taggedDestroySnapshot) {
          for (uint32_t offset = 0; offset < chunkCount; ++offset) {
            ManagedBlock block{};
            if (!DecodeDestroySnapshotEntry(
                    destroySnapshot[index + offset], false, heapId,
                    &block)) {
              failed = true;
              break;
            }
          }
        }
        for (uint32_t offset = 0; offset < chunkCount && !failed; ++offset) {
          ManagedBlock block{};
          if (!DecodeDestroySnapshotEntry(destroySnapshot[index + offset],
                                          taggedDestroySnapshot, heapId,
                                          &block)) {
            failed = true;
            break;
          }
          if (!taggedDestroySnapshot) {
            LegacyDestroyBatchMetadata& metadata =
                legacyBatchMetadata[offset];
            metadata.user = block.user;
            metadata.requestedSize = block.requestedSize;
            metadata.payloadUsableSize =
                static_cast<uint32_t>(block.payloadUsableSize);
          }
          PrepareDestroyBatchBlock(block);
          destroyBatch[offset].pointer = block.raw;
          destroyBatch[offset].requestedCharge = block.requestedSize;
        }
        if (failed) {
          break;
        }

        const MemoryPool::BatchFreeResult released =
            MemoryPool::FreeRoutedBatch(destroyBatch, chunkCount, route);
        g_heapDestroyBatchCalls.fetch_add(1, std::memory_order_relaxed);
        g_heapDestroyBatchBlocks.fetch_add(released.freedCount,
                                           std::memory_order_relaxed);
        bool accountingSucceeded = true;
        for (uint32_t offset = 0; offset < released.freedCount; ++offset) {
          ManagedBlock block{};
          if (taggedDestroySnapshot) {
            if (!DecodeDestroySnapshotEntry(
                    destroySnapshot[index + offset], true, heapId, &block)) {
              accountingSucceeded = false;
              continue;
            }
          } else {
            const LegacyDestroyBatchMetadata& metadata =
                legacyBatchMetadata[offset];
            block.user = metadata.user;
            block.heapId = heapId;
            block.requestedSize = metadata.requestedSize;
            block.payloadUsableSize = metadata.payloadUsableSize;
            block.route = route;
          }
          if (!AccountDestroyedBlock(token, block,
                                     trackRegistryStatistics)) {
            accountingSucceeded = false;
          }
        }
        if (released.freedCount != chunkCount || !accountingSucceeded) {
          failed = true;
          break;
        }
        index += chunkCount;
      }
    }
  } else {
    for (uint32_t index = 0; index < collect.count && !failed; ++index) {
      ManagedBlock block{};
      if (!DecodeDestroySnapshotEntry(destroySnapshot[index],
                                      taggedDestroySnapshot, heapId, &block) ||
          !FreeManagedRaw(block) ||
          !AccountDestroyedBlock(token, block, trackRegistryStatistics)) {
        failed = true;
        break;
      }
    }
  }
  if (destroyBatchAllocation) {
    VirtualFree(destroyBatchAllocation, 0, MEM_RELEASE);
  }
  if (destroySnapshot) {
    VirtualFree(destroySnapshot, 0, MEM_RELEASE);
  }

  if (!failed && persistentCount == 0) {
    void* sentinel = g_registry.TakeNativeSentinel(heapId);
    if (sentinel && !CallNativeHeapFree(heapId, 0, sentinel)) {
      if (!g_registry.RestoreNativeSentinel(token, sentinel)) {
        g_registry.MarkDegraded();
      }
      failed = true;
    }
  }
  int nativeResult = 0;
  bool nativeSurvivors = false;
  if (!failed) {
    const uint32_t nativeBefore = SumNativeHeapRequested(heapId);
    nativeResult = CallNativeHeapDestroy(heapId);
    const uint32_t nativeAfter =
        SumNativeHeapRequested(heapId, &nativeSurvivors);
    if (nativeBefore >= nativeAfter) {
      SubtractNativeCounter(nativeBefore - nativeAfter);
    }
  }
  StormHeapRegistry::DestroyResult finished =
      StormHeapRegistry::DestroyResult::Cancelled;
  if (failed || !nativeResult || persistentCount != 0 || nativeSurvivors) {
    finished = g_registry.CancelDestroy(&token);
  } else {
    finished = g_registry.FinishDestroy(&token);
  }
  ReleaseSRWLockExclusive(&g_destroyLock);
  const bool success =
      !failed && nativeResult &&
      (finished == StormHeapRegistry::DestroyResult::Finished ||
       finished == StormHeapRegistry::DestroyResult::Cancelled);
  if (success) {
    // Explicit heaps are a reliable lifetime boundary. Empty TLSF growth
    // pools can now be identified in O(1), so return their VA immediately.
    MemoryPool::TrimRoute(MemoryPool::BackendRoute::Tlsf);
  }
  NoteCall(StormApi::kOrdinalHeapDestroy, heapId, 0,
           StormBreaker::LeakProfiler::BackendRoute::Unknown,
           success ? StormBreaker::LeakProfiler::DegradedReason::None
                   : StormBreaker::LeakProfiler::DegradedReason::PointerRejected,
           true, false, !success);
  RecordStormApiEvent(StormApi::kOrdinalHeapDestroy, heapId, 0,
                      persistentCount, nativeResult, true);
  return success ? 1 : 0;
}

extern "C" int __stdcall HookedFull_SMemHeapFree(
    uint32_t heapId, uint32_t flags, void* pointer) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeHeapFree(heapId, flags, pointer);
  }
  const FastFreeResult fastFree =
      TryFastManagedFree(pointer, heapId, true);
  if (fastFree.disposition == FastFreeDisposition::Freed) {
    const auto route = ProfilerRoute(fastFree.block.route);
    NoteCall(StormApi::kOrdinalHeapFree, heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    StormBreaker::LeakProfiler::RecordFree(
        pointer, fastFree.block.requestedSize,
        StormBreaker::LeakProfiler::AllocationDomain::Managed,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapFree, route));
    return 1;
  }
  if (fastFree.disposition == FastFreeDisposition::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    NoteCall(StormApi::kOrdinalHeapFree, heapId, flags,
             StormBreaker::LeakProfiler::BackendRoute::Unknown,
             StormBreaker::LeakProfiler::DegradedReason::PointerRejected,
             true, false, true);
    return 0;
  }
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireHeap(heapId, false, nullptr, 0, &guard);
  if (access == StormHeapRegistry::AccessResult::Tombstone) {
    return 0;
  }
  ManagedBlock block{};
  const auto query = QueryPointerImpl(pointer, &block);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    if (block.heapId != heapId) {
      return 0;
    }
    if (!IsManagedAccess(access) || !FreeManagedRaw(block)) {
      return 0;
    }
    AccountFree(guard, block);
    const auto route = ProfilerRoute(block.route);
    NoteCall(StormApi::kOrdinalHeapFree, heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    StormBreaker::LeakProfiler::RecordFree(
        pointer, block.requestedSize,
        StormBreaker::LeakProfiler::AllocationDomain::Managed,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapFree, route));
    return 1;
  }
  const int nativeSize = StormBreaker::LeakProfiler::IsEnabled()
                             ? CallNativeHeapSize(heapId, flags, pointer)
                             : -1;
  const NativeLargeInfo largeInfo = QueryNativeLarge(pointer);
  const int result = CallNativeHeapFree(heapId, flags, pointer);
  if (result) {
    ApplyNativeCounterCorrection(largeInfo);
    if (nativeSize >= 0) {
      StormBreaker::LeakProfiler::RecordFree(
          pointer, static_cast<uint32_t>(nativeSize),
          StormBreaker::LeakProfiler::AllocationDomain::Native,
          MakeMetadata(heapId, flags, StormApi::kOrdinalHeapFree,
                       StormBreaker::LeakProfiler::BackendRoute::NativeStorm));
    }
  }
  NoteCall(StormApi::kOrdinalHeapFree, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  return result;
}

extern "C" void* __stdcall HookedFull_SMemHeapReAlloc(
    uint32_t heapId, uint32_t flags, void* pointer, uint32_t newSize) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeHeapReAlloc(heapId, flags, pointer, newSize);
  }

  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireHeap(heapId, false, nullptr, 0, &guard);
  if (access == StormHeapRegistry::AccessResult::Tombstone) {
    return nullptr;
  }
  if (!pointer) {
    const bool protectFallback = IsProtectMemoryEnabled() &&
                                 ShouldManage(newSize) &&
                                 IsManagedAccess(access);
    const bool attemptedManaged = !IsProtectMemoryEnabled() &&
                                  ShouldManage(newSize) &&
                                  IsManagedAccess(access);
    if (attemptedManaged) {
      ManagedAllocation allocation = AllocateManagedRaw(heapId, newSize, flags);
      if (allocation.pointer) {
        AccountAllocation(guard, allocation.block);
        const auto route = ProfilerRoute(allocation.block.route);
        NoteCall(StormApi::kOrdinalHeapReAlloc, heapId, flags, route,
                 StormBreaker::LeakProfiler::DegradedReason::None, true, false,
                 false);
        RecordReallocEvent(
            nullptr, allocation.pointer, 0, newSize, false, true, false, true,
            false,
            MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                         StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
            MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc, route));
        return allocation.pointer;
      }
    }
    void* native = CallNativeHeapAlloc(heapId, flags, newSize);
    const auto reason = protectFallback
                            ? StormBreaker::LeakProfiler::DegradedReason::ProtectMemory
                        : attemptedManaged
                            ? StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory
                            : StormBreaker::LeakProfiler::DegradedReason::BelowTakeoverThreshold;
    NoteCall(StormApi::kOrdinalHeapReAlloc, heapId, flags,
             StormBreaker::LeakProfiler::BackendRoute::NativeStorm, reason,
             false, attemptedManaged || protectFallback,
             attemptedManaged || protectFallback, newSize);
    RecordReallocEvent(
        nullptr, native, 0, newSize, false, false, false, native != nullptr,
        false,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
                     reason, attemptedManaged || protectFallback,
                     attemptedManaged || protectFallback));
    return native;
  }

  ManagedBlock oldBlock{};
  const auto query = QueryPointerImpl(pointer, &oldBlock);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    if (oldBlock.heapId != heapId || !IsManagedAccess(access)) {
      return nullptr;
    }
    ReallocResult outcome = ReallocateManaged(
        oldBlock, guard, newSize, flags, true, 0, 0, nullptr, 0);
    const auto oldRoute = ProfilerRoute(oldBlock.route);
    const auto newRoute = outcome.newManaged
                              ? ProfilerRoute(outcome.newBlock.route)
                              : StormBreaker::LeakProfiler::BackendRoute::NativeStorm;
    NoteCall(StormApi::kOrdinalHeapReAlloc, heapId, flags,
             outcome.succeeded ? newRoute : oldRoute,
             outcome.succeeded
                 ? StormBreaker::LeakProfiler::DegradedReason::None
                 : StormBreaker::LeakProfiler::DegradedReason::BackendOutOfMemory,
             true, false, !outcome.succeeded, newSize);
    RecordReallocEvent(
        pointer, outcome.pointer, oldBlock.requestedSize, newSize, true,
        outcome.newManaged, outcome.oldFreed, outcome.newAllocated,
        outcome.inPlace,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc, oldRoute),
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc, newRoute));
    return outcome.pointer;
  }

  const int oldSize = CallNativeHeapSize(heapId, flags, pointer);
  ReallocResult migrated{};
  const bool preserveNativeSmallZero =
      newSize == 0 && oldSize >= 0 &&
      static_cast<uint32_t>(oldSize) < StormApi::kNativeLargeThreshold &&
      !IsReallocShuffleEnabled();
  if (!preserveNativeSmallZero && oldSize >= 0 && IsManagedAccess(access) &&
      TryMigrateNativeToManaged(pointer, static_cast<uint32_t>(oldSize),
                                newSize, flags, heapId, true, nullptr, 0,
                                guard, &migrated)) {
    const auto route = ProfilerRoute(migrated.newBlock.route);
    NoteCall(StormApi::kOrdinalHeapReAlloc, heapId, flags, route,
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    RecordReallocEvent(
        pointer, migrated.pointer, static_cast<uint32_t>(oldSize), newSize,
        false, true, true, true, false,
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                     StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
        MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc, route));
    return migrated.pointer;
  }
  const NativeLargeInfo largeInfo = QueryNativeLarge(pointer);
  void* native = CallNativeHeapReAlloc(heapId, flags, pointer, newSize);
  if (native && native != pointer) {
    ApplyNativeCounterCorrection(largeInfo);
  }
  NoteCall(StormApi::kOrdinalHeapReAlloc, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  RecordReallocEvent(
      pointer, native, oldSize >= 0 ? static_cast<uint32_t>(oldSize) : 0,
      newSize, false, false, native && native != pointer, native != nullptr,
      native == pointer,
      MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                   StormBreaker::LeakProfiler::BackendRoute::NativeStorm),
      MakeMetadata(heapId, flags, StormApi::kOrdinalHeapReAlloc,
                   StormBreaker::LeakProfiler::BackendRoute::NativeStorm));
  return native;
}

extern "C" int __stdcall HookedFull_SMemHeapSize(
    uint32_t heapId, uint32_t flags, const void* pointer) {
  ScopedHookDepth depth;
  if (!depth.IsOutermost()) {
    return CallNativeHeapSize(heapId, flags, pointer);
  }
  StormHeapRegistry::Registry::OperationGuard guard;
  const auto access = AcquireHeap(heapId, false, nullptr, 0, &guard);
  if (access == StormHeapRegistry::AccessResult::Tombstone) {
    return -1;
  }
  ManagedBlock block{};
  const auto query = QueryPointerImpl(pointer, &block);
  if (query == StormTakeover::BlockQueryResult::Rejected) {
    g_rejectedPointers.fetch_add(1, std::memory_order_relaxed);
    return -1;
  }
  if (query == StormTakeover::BlockQueryResult::Managed) {
    if (block.heapId != heapId) {
      return -1;
    }
    if (!IsManagedAccess(access)) {
      return -1;
    }
    NoteCall(StormApi::kOrdinalHeapSize, heapId, flags,
             ProfilerRoute(block.route),
             StormBreaker::LeakProfiler::DegradedReason::None, true, false,
             false);
    return static_cast<int>(block.requestedSize);
  }
  NoteCall(StormApi::kOrdinalHeapSize, heapId, flags,
           StormBreaker::LeakProfiler::BackendRoute::NativeStorm,
           StormBreaker::LeakProfiler::DegradedReason::None, false, false,
           false);
  return CallNativeHeapSize(heapId, flags, pointer);
}

extern "C" int __stdcall HookedFull_SMemSetOption(
    uint32_t valueBits, uint32_t maskBits) {
  ScopedHookDepth depth;
  const int result = CallNativeSetOption(valueBits, maskBits);
  if (!depth.IsOutermost()) {
    return result;
  }
  uint32_t current = g_optionFlags.load(std::memory_order_relaxed);
  for (;;) {
    const uint32_t desired = (current & ~maskBits) | (valueBits & maskBits);
    if (g_optionFlags.compare_exchange_weak(current, desired,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
      break;
    }
  }
  NoteCall(StormApi::kOrdinalSetOption, 0, maskBits,
           StormBreaker::LeakProfiler::BackendRoute::Unknown,
           StormBreaker::LeakProfiler::DegradedReason::None, true, false,
           false);
  RecordStormApiEvent(StormApi::kOrdinalSetOption, 0, maskBits, valueBits,
                      g_optionFlags.load(std::memory_order_relaxed), true);
  return result;
}
