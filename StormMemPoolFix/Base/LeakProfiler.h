#pragma once

#include <cstddef>
#include <cstdint>

namespace StormBreaker {
namespace LeakProfiler {

constexpr std::size_t kRingCapacity = 65536;
constexpr std::size_t kMaxStackDepth = 16;
constexpr std::uint64_t kNativeSmallBlockLimit = 64u * 1024u;
constexpr std::uint32_t kNativeSmallSampleRate = 256;
constexpr std::uint16_t kBinaryStreamVersion = 2;

enum class Mode : std::uint8_t {
  Off = 0,
  Sampled = 1,
  Full = 2,
};

enum class AllocationDomain : std::uint8_t {
  Native = 1,
  Managed = 2,
};

// Values are stable because they are persisted in SBLP v2 and metrics JSONL.
enum class BackendRoute : std::uint8_t {
  Unknown = 0,
  NativeStorm = 1,
  Tlsf = 2,
  Mimalloc = 3,
  TlsfSharded = 4,
  Count = 5,
};

constexpr std::size_t kBackendRouteCount =
    static_cast<std::size_t>(BackendRoute::Count);

enum class DegradedReason : std::uint8_t {
  None = 0,
  IntentionalNative = 1,
  HookBypass = 2,
  UnsafePeriod = 3,
  BelowTakeoverThreshold = 4,
  UnknownHeap = 5,
  RegistryCapacity = 6,
  BackendUnavailable = 7,
  BackendOutOfMemory = 8,
  RequestedBudgetExceeded = 9,
  UnsupportedFlags = 10,
  ProtectMemory = 11,
  PointerRejected = 12,
  NativeException = 13,
  InitializationFailure = 14,
  ExplicitNativeHeap = 15,
};

// Fallback and degraded are independent bits. A compatibility fallback is
// normally both, while an observed degraded state may not allocate anything.
enum class EventDisposition : std::uint8_t {
  Normal = 0,
  Fallback = 1,
  Degraded = 2,
  FallbackDegraded = 3,
};

constexpr bool IsFallback(EventDisposition disposition) noexcept {
  return (static_cast<std::uint8_t>(disposition) & 1u) != 0;
}

constexpr bool IsDegraded(EventDisposition disposition) noexcept {
  return (static_cast<std::uint8_t>(disposition) & 2u) != 0;
}

// Fixed-size metadata is copied into the preallocated event ring. It owns no
// memory and is safe to construct on an allocation hook's producer path.
struct EventMetadata {
  std::uint32_t heapId = 0;
  std::uint32_t stormFlags = 0;
  std::uint16_t exportedOrdinal = 0;
  BackendRoute route = BackendRoute::Unknown;
  DegradedReason reason = DegradedReason::None;
  EventDisposition disposition = EventDisposition::Normal;
};

static_assert(sizeof(EventMetadata) == 16,
              "event metadata must remain a compact value type");

enum class EventType : std::uint16_t {
  Alloc = 1,
  Free = 2,
  ReallocOutcome = 3,
  EpochMarker = 4,
  Checkpoint = 5,
  ModuleSnapshot = 6,
  StormApi = 7,
};

struct ReallocOutcome {
  void *oldPointer = nullptr;
  void *newPointer = nullptr;
  std::uint64_t oldSize = 0;
  std::uint64_t newSize = 0;
  bool oldFreed = false;
  bool newAllocated = false;
  bool inPlace = false;
  // domain describes the old pointer; newDomain allows managed/native
  // migrations to remain a single realloc outcome record.
  AllocationDomain domain = AllocationDomain::Native;
  AllocationDomain newDomain = AllocationDomain::Native;
  EventMetadata metadata{};
  EventMetadata newMetadata{};
};

struct StormApiEvent {
  AllocationDomain domain = AllocationDomain::Native;
  EventMetadata metadata{};
  std::uint64_t primaryValue = 0;
  std::uint64_t secondaryValue = 0;
  bool captureStack = false;
};

struct RouteLatencySnapshot {
  std::uint64_t sampleCount = 0;
  std::uint64_t totalNanoseconds = 0;
  std::uint64_t maxNanoseconds = 0;
  std::uint64_t p50Nanoseconds = 0;
  std::uint64_t p95Nanoseconds = 0;
  std::uint64_t p99Nanoseconds = 0;
};

// Published by the once-per-second snapshot provider, never by the event
// producer itself. The same value is embedded in SBLP checkpoints and JSONL.
struct TakeoverSnapshot {
  std::uint64_t managedApiCalls = 0;
  std::uint64_t nativeApiCalls = 0;
  std::uint64_t managedFallbackCalls = 0;
  std::uint64_t nativeFallbackCalls = 0;
  std::uint64_t degradedCalls = 0;
  std::uint64_t registryInsertFailures = 0;
  std::uint32_t registryCapacity = 0;
  std::uint32_t registryActive = 0;
  std::uint32_t registryDestroying = 0;
  std::uint32_t registryTombstones = 0;
  std::uint32_t registryNativeDelegated = 0;
  std::uint32_t stormOptionFlags = 0;
  std::uint32_t lastHeapId = 0;
  std::uint32_t lastStormFlags = 0;
  std::uint16_t lastExportedOrdinal = 0;
  BackendRoute lastRoute = BackendRoute::Unknown;
  DegradedReason lastDegradedReason = DegradedReason::None;
  RouteLatencySnapshot routeLatency[kBackendRouteCount]{};
};

struct HealthSnapshot {
  Mode mode = Mode::Off;
  std::uint32_t queueCapacity = static_cast<std::uint32_t>(kRingCapacity);
  std::uint32_t queueDepth = 0;
  std::uint64_t eventsEnqueued = 0;
  std::uint64_t eventsWritten = 0;
  std::uint64_t dropped = 0;
  std::uint64_t recursionSkips = 0;
  std::uint64_t writeErrors = 0;
  std::uint64_t managedEvents = 0;
  std::uint64_t nativeEvents = 0;
  std::uint64_t fallbackEvents = 0;
  std::uint64_t degradedEvents = 0;
  bool incomplete = false;
  bool writerRunning = false;
  TakeoverSnapshot takeover{};
};

// Invalid or missing values are deliberately treated as off.
Mode ParseMode(const char *value) noexcept;
Mode ReadModeFromEnvironment() noexcept;
const char *ModeName(Mode mode) noexcept;

// If artifactDirectory is null or empty, the standard artifact environment
// variables are consulted before falling back to .\StormBreaker.
bool Start(Mode mode, const wchar_t *artifactDirectory = nullptr) noexcept;
bool StartFromEnvironment(const wchar_t *artifactDirectory = nullptr) noexcept;
void RequestStop() noexcept;
void Stop(std::uint32_t timeoutMilliseconds = 5000) noexcept;

Mode GetMode() noexcept;
bool IsEnabled() noexcept;
bool ShouldRecord(AllocationDomain domain, const void *pointer,
                  std::uint64_t size) noexcept;

void RecordAlloc(void *pointer, std::uint64_t size,
                 AllocationDomain domain) noexcept;
void RecordAlloc(void *pointer, std::uint64_t size, AllocationDomain domain,
                 const EventMetadata &metadata) noexcept;
void RecordFree(void *pointer, std::uint64_t size,
                AllocationDomain domain) noexcept;
void RecordFree(void *pointer, std::uint64_t size, AllocationDomain domain,
                const EventMetadata &metadata) noexcept;
void RecordReallocOutcome(const ReallocOutcome &outcome) noexcept;
void RecordStormApi(const StormApiEvent &event) noexcept;
void MarkEpoch(std::uint64_t epoch, std::uint32_t reason = 0) noexcept;

void UpdateTakeoverSnapshot(const TakeoverSnapshot &snapshot) noexcept;
TakeoverSnapshot GetTakeoverSnapshot() noexcept;

HealthSnapshot GetHealthSnapshot() noexcept;
const wchar_t *GetOutputPath() noexcept;

#if defined(STORMBREAKER_TESTING)
namespace Testing {
bool ExerciseRingSaturation(HealthSnapshot *snapshot) noexcept;
}
#endif

} // namespace LeakProfiler
} // namespace StormBreaker
