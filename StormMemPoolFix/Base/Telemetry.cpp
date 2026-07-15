#include "pch.h"

#include "Telemetry.h"

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cwchar>

namespace StormBreaker {
namespace Telemetry {
namespace {

constexpr wchar_t kDefaultArtifactDirectory[] = L".\\StormBreaker";
constexpr DWORD kPublishIntervalMilliseconds = 1000;
constexpr std::size_t kTakeoverScalarFieldCount = 17;
constexpr std::size_t kRouteLatencyFieldCount = 6;
constexpr std::size_t kTakeoverFieldCount =
    kTakeoverScalarFieldCount +
    LeakProfiler::kBackendRouteCount * kRouteLatencyFieldCount;

template <std::size_t FieldCount> class AtomicSnapshotStore {
public:
  void Publish(const std::uint64_t (&values)[FieldCount]) noexcept {
    std::uint64_t version = version_.load(std::memory_order_acquire);
    for (;;) {
      if ((version & 1u) != 0) {
        version = version_.load(std::memory_order_acquire);
        continue;
      }
      if (version_.compare_exchange_weak(
              version, version + 1, std::memory_order_acq_rel,
              std::memory_order_acquire)) {
        break;
      }
    }
    for (std::size_t index = 0; index < FieldCount; ++index) {
      fields_[index].store(values[index], std::memory_order_relaxed);
    }
    version_.store(version + 2, std::memory_order_release);
  }

  void Read(std::uint64_t (&values)[FieldCount]) const noexcept {
    for (;;) {
      const std::uint64_t before = version_.load(std::memory_order_acquire);
      if ((before & 1u) != 0) {
        continue;
      }
      for (std::size_t index = 0; index < FieldCount; ++index) {
        values[index] = fields_[index].load(std::memory_order_relaxed);
      }
      const std::uint64_t after = version_.load(std::memory_order_acquire);
      if (before == after) {
        return;
      }
    }
  }

private:
  mutable std::atomic<std::uint64_t> version_{0};
  std::atomic<std::uint64_t> fields_[FieldCount]{};
};

AtomicSnapshotStore<2> g_runtime;
AtomicSnapshotStore<8> g_hook;
AtomicSnapshotStore<8> g_backend;
AtomicSnapshotStore<18> g_pool;
AtomicSnapshotStore<12> g_latency;
AtomicSnapshotStore<14> g_profiler;
AtomicSnapshotStore<kTakeoverFieldCount> g_takeover;

std::atomic<bool> g_running{false};
std::atomic<std::uint64_t> g_writeErrors{0};
std::atomic<SnapshotProvider> g_snapshotProvider{nullptr};
SRWLOCK g_lifecycleLock = SRWLOCK_INIT;
HANDLE g_file = INVALID_HANDLE_VALUE;
HANDLE g_stopEvent = nullptr;
HANDLE g_writerThread = nullptr;
wchar_t g_outputPath[32768]{};

void EncodeTakeoverSnapshot(
    const TakeoverSnapshot &snapshot,
    std::uint64_t (&values)[kTakeoverFieldCount]) noexcept {
  std::size_t offset = 0;
  values[offset++] = snapshot.managedApiCalls;
  values[offset++] = snapshot.nativeApiCalls;
  values[offset++] = snapshot.managedFallbackCalls;
  values[offset++] = snapshot.nativeFallbackCalls;
  values[offset++] = snapshot.degradedCalls;
  values[offset++] = snapshot.registryInsertFailures;
  values[offset++] = snapshot.registryCapacity;
  values[offset++] = snapshot.registryActive;
  values[offset++] = snapshot.registryDestroying;
  values[offset++] = snapshot.registryTombstones;
  values[offset++] = snapshot.registryNativeDelegated;
  values[offset++] = snapshot.stormOptionFlags;
  values[offset++] = snapshot.lastHeapId;
  values[offset++] = snapshot.lastStormFlags;
  values[offset++] = snapshot.lastExportedOrdinal;
  values[offset++] = static_cast<std::uint8_t>(snapshot.lastRoute);
  values[offset++] =
      static_cast<std::uint8_t>(snapshot.lastDegradedReason);
  for (std::size_t route = 0;
       route < LeakProfiler::kBackendRouteCount; ++route) {
    const RouteLatencySnapshot &latency = snapshot.routeLatency[route];
    values[offset++] = latency.sampleCount;
    values[offset++] = latency.totalNanoseconds;
    values[offset++] = latency.maxNanoseconds;
    values[offset++] = latency.p50Nanoseconds;
    values[offset++] = latency.p95Nanoseconds;
    values[offset++] = latency.p99Nanoseconds;
  }
}

TakeoverSnapshot DecodeTakeoverSnapshot(
    const std::uint64_t (&values)[kTakeoverFieldCount]) noexcept {
  TakeoverSnapshot snapshot{};
  std::size_t offset = 0;
  snapshot.managedApiCalls = values[offset++];
  snapshot.nativeApiCalls = values[offset++];
  snapshot.managedFallbackCalls = values[offset++];
  snapshot.nativeFallbackCalls = values[offset++];
  snapshot.degradedCalls = values[offset++];
  snapshot.registryInsertFailures = values[offset++];
  snapshot.registryCapacity = static_cast<std::uint32_t>(values[offset++]);
  snapshot.registryActive = static_cast<std::uint32_t>(values[offset++]);
  snapshot.registryDestroying =
      static_cast<std::uint32_t>(values[offset++]);
  snapshot.registryTombstones =
      static_cast<std::uint32_t>(values[offset++]);
  snapshot.registryNativeDelegated =
      static_cast<std::uint32_t>(values[offset++]);
  snapshot.stormOptionFlags =
      static_cast<std::uint32_t>(values[offset++]);
  snapshot.lastHeapId = static_cast<std::uint32_t>(values[offset++]);
  snapshot.lastStormFlags = static_cast<std::uint32_t>(values[offset++]);
  snapshot.lastExportedOrdinal =
      static_cast<std::uint16_t>(values[offset++]);
  snapshot.lastRoute = static_cast<BackendRoute>(values[offset++]);
  snapshot.lastDegradedReason =
      static_cast<DegradedReason>(values[offset++]);
  for (std::size_t route = 0;
       route < LeakProfiler::kBackendRouteCount; ++route) {
    RouteLatencySnapshot &latency = snapshot.routeLatency[route];
    latency.sampleCount = values[offset++];
    latency.totalNanoseconds = values[offset++];
    latency.maxNanoseconds = values[offset++];
    latency.p50Nanoseconds = values[offset++];
    latency.p95Nanoseconds = values[offset++];
    latency.p99Nanoseconds = values[offset++];
  }
  return snapshot;
}

bool CopyWide(const wchar_t *source, wchar_t *destination,
              std::size_t capacity) noexcept {
  if (!source || !destination || capacity == 0) {
    return false;
  }
  const std::size_t length = std::wcslen(source);
  if (length >= capacity) {
    return false;
  }
  std::wmemcpy(destination, source, length + 1);
  return true;
}

bool ReadEnvironmentDirectory(const wchar_t *name, wchar_t *destination,
                              std::size_t capacity) noexcept {
  const DWORD length = GetEnvironmentVariableW(
      name, destination, static_cast<DWORD>(capacity));
  return length > 0 && length < capacity;
}

bool ResolveArtifactDirectory(const wchar_t *overrideDirectory,
                              wchar_t *destination,
                              std::size_t capacity) noexcept {
  if (overrideDirectory && *overrideDirectory) {
    return CopyWide(overrideDirectory, destination, capacity);
  }
  if (ReadEnvironmentDirectory(L"STORMBREAKER_ARTIFACT_DIR", destination,
                               capacity)) {
    return true;
  }
  if (ReadEnvironmentDirectory(L"DXVK_WAR3_AUTOTEST_ARTIFACT_DIR",
                               destination, capacity)) {
    return true;
  }
  return CopyWide(kDefaultArtifactDirectory, destination, capacity);
}

bool EnsureDirectoryTree(const wchar_t *directory) noexcept {
  wchar_t path[32768]{};
  if (!CopyWide(directory, path, _countof(path))) {
    return false;
  }
  for (wchar_t *cursor = path; *cursor; ++cursor) {
    if (*cursor != L'\\' && *cursor != L'/') {
      continue;
    }
    if (cursor == path || (cursor == path + 2 && path[1] == L':')) {
      continue;
    }
    const wchar_t separator = *cursor;
    *cursor = L'\0';
    if (!CreateDirectoryW(path, nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
      *cursor = separator;
      return false;
    }
    *cursor = separator;
  }
  return CreateDirectoryW(path, nullptr) != FALSE ||
         GetLastError() == ERROR_ALREADY_EXISTS;
}

bool BuildOutputPath(const wchar_t *artifactDirectory) noexcept {
  wchar_t directory[32768]{};
  if (!ResolveArtifactDirectory(artifactDirectory, directory,
                                _countof(directory)) ||
      !EnsureDirectoryTree(directory)) {
    return false;
  }
  const std::size_t length = std::wcslen(directory);
  const bool hasSeparator =
      length > 0 && (directory[length - 1] == L'\\' ||
                     directory[length - 1] == L'/');
  const int written = std::swprintf(
      g_outputPath, _countof(g_outputPath),
      hasSeparator ? L"%lsmetrics_%lu.jsonl" : L"%ls\\metrics_%lu.jsonl",
      directory, static_cast<unsigned long>(GetCurrentProcessId()));
  return written > 0 && static_cast<std::size_t>(written) <
                            _countof(g_outputPath);
}

std::uint64_t UnixTimeMilliseconds() noexcept {
  FILETIME fileTime{};
  GetSystemTimeAsFileTime(&fileTime);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = fileTime.dwLowDateTime;
  ticks.HighPart = fileTime.dwHighDateTime;
  constexpr std::uint64_t kWindowsToUnix100ns = 116444736000000000ULL;
  return (ticks.QuadPart - kWindowsToUnix100ns) / 10000ULL;
}

bool WriteAll(const void *data, std::size_t length) noexcept {
  const auto *bytes = static_cast<const std::uint8_t *>(data);
  while (length != 0) {
    const DWORD chunk = static_cast<DWORD>(
        length > MAXDWORD ? MAXDWORD : length);
    DWORD written = 0;
    if (!WriteFile(g_file, bytes, chunk, &written, nullptr) || written == 0) {
      return false;
    }
    bytes += written;
    length -= written;
  }
  return true;
}

const char *ProfilerModeName(std::uint64_t mode) noexcept {
  if (mode == 1) {
    return "sampled";
  }
  if (mode == 2) {
    return "full";
  }
  return "off";
}

const char *BackendName(std::uint64_t backend) noexcept {
  switch (static_cast<MemoryBackend>(backend)) {
  case MemoryBackend::Tlsf:
    return "tlsf";
  case MemoryBackend::Mimalloc:
    return "mimalloc";
  case MemoryBackend::TlsfSharded:
    return "tlsf-sharded";
  case MemoryBackend::Hybrid:
    return "hybrid";
  default:
    return "off";
  }
}

const char *RouteName(BackendRoute route) noexcept {
  switch (route) {
  case BackendRoute::NativeStorm:
    return "native-storm";
  case BackendRoute::Tlsf:
    return "tlsf";
  case BackendRoute::Mimalloc:
    return "mimalloc";
  case BackendRoute::TlsfSharded:
    return "tlsf-sharded";
  default:
    return "unknown";
  }
}

const char *DegradedReasonName(DegradedReason reason) noexcept {
  switch (reason) {
  case DegradedReason::IntentionalNative:
    return "intentional-native";
  case DegradedReason::HookBypass:
    return "hook-bypass";
  case DegradedReason::UnsafePeriod:
    return "unsafe-period";
  case DegradedReason::BelowTakeoverThreshold:
    return "below-takeover-threshold";
  case DegradedReason::UnknownHeap:
    return "unknown-heap";
  case DegradedReason::RegistryCapacity:
    return "registry-capacity";
  case DegradedReason::BackendUnavailable:
    return "backend-unavailable";
  case DegradedReason::BackendOutOfMemory:
    return "backend-out-of-memory";
  case DegradedReason::RequestedBudgetExceeded:
    return "requested-budget-exceeded";
  case DegradedReason::UnsupportedFlags:
    return "unsupported-flags";
  case DegradedReason::ProtectMemory:
    return "protect-memory";
  case DegradedReason::PointerRejected:
    return "pointer-rejected";
  case DegradedReason::NativeException:
    return "native-exception";
  case DegradedReason::InitializationFailure:
    return "initialization-failure";
  case DegradedReason::ExplicitNativeHeap:
    return "explicit-native-heap";
  default:
    return "none";
  }
}

template <std::size_t Capacity> class FixedLineBuilder {
public:
  bool Append(const char *format, ...) noexcept {
    if (!valid_ || length_ >= Capacity) {
      valid_ = false;
      return false;
    }
    va_list arguments;
    va_start(arguments, format);
    const int written = std::vsnprintf(data_ + length_, Capacity - length_,
                                       format, arguments);
    va_end(arguments);
    if (written < 0 ||
        static_cast<std::size_t>(written) >= Capacity - length_) {
      valid_ = false;
      return false;
    }
    length_ += static_cast<std::size_t>(written);
    return true;
  }

  bool IsValid() const noexcept { return valid_; }
  const char *Data() const noexcept { return data_; }
  std::size_t Length() const noexcept { return length_; }

private:
  char data_[Capacity]{};
  std::size_t length_ = 0;
  bool valid_ = true;
};

bool WriteMetricsLine(std::uint64_t sequence) noexcept {
  std::uint64_t runtime[2]{};
  std::uint64_t hook[8]{};
  std::uint64_t backend[8]{};
  std::uint64_t pool[18]{};
  std::uint64_t latency[12]{};
  std::uint64_t profiler[14]{};
  std::uint64_t takeoverValues[kTakeoverFieldCount]{};
  g_runtime.Read(runtime);
  g_hook.Read(hook);
  g_backend.Read(backend);
  g_pool.Read(pool);
  g_latency.Read(latency);
  g_profiler.Read(profiler);
  g_takeover.Read(takeoverValues);
  const TakeoverSnapshot takeover =
      DecodeTakeoverSnapshot(takeoverValues);
  const std::uint64_t freeBytes =
      pool[2] > pool[0] ? pool[2] - pool[0] : 0;
  const char *backendName = BackendName(runtime[1]);

  FixedLineBuilder<16384> line;
  line.Append(
      "{\"schema\":\"stormbreaker.metrics.v2\",\"timestampUnixMs\":%llu,"
      "\"pid\":%lu,\"sequence\":%llu,\"hooksInstalled\":%s,"
      "\"memoryBackend\":\"%s\",",
      static_cast<unsigned long long>(UnixTimeMilliseconds()),
      static_cast<unsigned long>(GetCurrentProcessId()),
      static_cast<unsigned long long>(sequence),
      runtime[0] ? "true" : "false", backendName);
  line.Append(
      "\"hook\":{\"allocCalls\":%llu,\"freeCalls\":%llu,"
      "\"reallocCalls\":%llu,\"getSizeCalls\":%llu,"
      "\"cleanupCalls\":%llu,\"resetCalls\":%llu,"
      "\"bypassCalls\":%llu,\"failures\":%llu},",
      static_cast<unsigned long long>(hook[0]),
      static_cast<unsigned long long>(hook[1]),
      static_cast<unsigned long long>(hook[2]),
      static_cast<unsigned long long>(hook[3]),
      static_cast<unsigned long long>(hook[4]),
      static_cast<unsigned long long>(hook[5]),
      static_cast<unsigned long long>(hook[6]),
      static_cast<unsigned long long>(hook[7]));
  line.Append(
      "\"backend\":{\"name\":\"%s\",\"managedAllocations\":%llu,"
      "\"managedFrees\":%llu,\"nativeAllocations\":%llu,"
      "\"nativeFrees\":%llu,\"managedBytes\":%llu,"
      "\"nativeBytes\":%llu,\"fallbackAllocations\":%llu,"
      "\"failures\":%llu},",
      backendName, static_cast<unsigned long long>(backend[0]),
      static_cast<unsigned long long>(backend[1]),
      static_cast<unsigned long long>(backend[2]),
      static_cast<unsigned long long>(backend[3]),
      static_cast<unsigned long long>(backend[4]),
      static_cast<unsigned long long>(backend[5]),
      static_cast<unsigned long long>(backend[6]),
      static_cast<unsigned long long>(backend[7]));
  line.Append(
      "\"pool\":{\"totalBytes\":%llu,\"usedBytes\":%llu,"
      "\"freeBytes\":%llu,\"peakUsedBytes\":%llu,"
      "\"requestedLiveBytes\":%llu,\"usableLiveBytes\":%llu,"
      "\"reservedBytes\":%llu,\"committedBytes\":%llu,"
      "\"peakRequestedLiveBytes\":%llu,\"peakUsableLiveBytes\":%llu,"
      "\"peakReservedBytes\":%llu,\"peakCommittedBytes\":%llu,"
      "\"requestedLiveBudgetBytes\":%llu,\"allocationCount\":%llu,"
      "\"freeCount\":%llu,\"reallocCount\":%llu,"
      "\"failureCount\":%llu,\"extendCount\":%llu,"
      "\"trimCount\":%llu,\"lockWaitCount\":%llu,"
      "\"lockWaitNanoseconds\":%llu,\"maxLockWaitNanoseconds\":%llu},",
      static_cast<unsigned long long>(pool[2]),
      static_cast<unsigned long long>(pool[0]),
      static_cast<unsigned long long>(freeBytes),
      static_cast<unsigned long long>(pool[4]),
      static_cast<unsigned long long>(pool[0]),
      static_cast<unsigned long long>(pool[1]),
      static_cast<unsigned long long>(pool[2]),
      static_cast<unsigned long long>(pool[3]),
      static_cast<unsigned long long>(pool[4]),
      static_cast<unsigned long long>(pool[5]),
      static_cast<unsigned long long>(pool[6]),
      static_cast<unsigned long long>(pool[7]),
      static_cast<unsigned long long>(pool[8]),
      static_cast<unsigned long long>(pool[9]),
      static_cast<unsigned long long>(pool[10]),
      static_cast<unsigned long long>(pool[11]),
      static_cast<unsigned long long>(pool[12]),
      static_cast<unsigned long long>(pool[13]),
      static_cast<unsigned long long>(pool[14]),
      static_cast<unsigned long long>(pool[15]),
      static_cast<unsigned long long>(pool[16]),
      static_cast<unsigned long long>(pool[17]));
  line.Append(
      "\"latency\":{\"sampleCount\":%llu,\"totalNanoseconds\":%llu,"
      "\"maxNanoseconds\":%llu,\"p50Nanoseconds\":%llu,"
      "\"p95Nanoseconds\":%llu,\"p99Nanoseconds\":%llu,"
      "\"allocateP99Nanoseconds\":%llu,\"freeP99Nanoseconds\":%llu,"
      "\"reallocateP99Nanoseconds\":%llu,\"copyP99Nanoseconds\":%llu,"
      "\"growthP99Nanoseconds\":%llu,\"lockWaitP99Nanoseconds\":%llu},",
      static_cast<unsigned long long>(latency[0]),
      static_cast<unsigned long long>(latency[1]),
      static_cast<unsigned long long>(latency[2]),
      static_cast<unsigned long long>(latency[3]),
      static_cast<unsigned long long>(latency[4]),
      static_cast<unsigned long long>(latency[5]),
      static_cast<unsigned long long>(latency[6]),
      static_cast<unsigned long long>(latency[7]),
      static_cast<unsigned long long>(latency[8]),
      static_cast<unsigned long long>(latency[9]),
      static_cast<unsigned long long>(latency[10]),
      static_cast<unsigned long long>(latency[11]));
  line.Append(
      "\"profiler\":{\"mode\":\"%s\",\"eventsEnqueued\":%llu,"
      "\"eventsWritten\":%llu,\"dropped\":%llu,"
      "\"recursionSkips\":%llu,\"writeErrors\":%llu,"
      "\"managedEvents\":%llu,\"nativeEvents\":%llu,"
      "\"fallbackEvents\":%llu,\"degradedEvents\":%llu,"
      "\"queueCapacity\":%llu,\"queueDepth\":%llu,"
      "\"incomplete\":%s,\"writerRunning\":%s},",
      ProfilerModeName(profiler[11]),
      static_cast<unsigned long long>(profiler[0]),
      static_cast<unsigned long long>(profiler[1]),
      static_cast<unsigned long long>(profiler[2]),
      static_cast<unsigned long long>(profiler[3]),
      static_cast<unsigned long long>(profiler[4]),
      static_cast<unsigned long long>(profiler[5]),
      static_cast<unsigned long long>(profiler[6]),
      static_cast<unsigned long long>(profiler[7]),
      static_cast<unsigned long long>(profiler[8]),
      static_cast<unsigned long long>(profiler[9]),
      static_cast<unsigned long long>(profiler[10]),
      profiler[12] ? "true" : "false",
      profiler[13] ? "true" : "false");
  line.Append(
      "\"takeover\":{\"managedApiCalls\":%llu,\"nativeApiCalls\":%llu,"
      "\"managedFallbackCalls\":%llu,\"nativeFallbackCalls\":%llu,"
      "\"degradedCalls\":%llu,\"stormOptionFlags\":%u,"
      "\"last\":{\"heapId\":%u,\"stormFlags\":%u,"
      "\"exportedOrdinal\":%u,\"route\":\"%s\","
      "\"degradedReason\":\"%s\",\"degradedReasonCode\":%u},"
      "\"registry\":{\"capacity\":%u,\"active\":%u,"
      "\"destroying\":%u,\"tombstones\":%u,"
      "\"nativeDelegated\":%u,\"insertFailures\":%llu}},",
      static_cast<unsigned long long>(takeover.managedApiCalls),
      static_cast<unsigned long long>(takeover.nativeApiCalls),
      static_cast<unsigned long long>(takeover.managedFallbackCalls),
      static_cast<unsigned long long>(takeover.nativeFallbackCalls),
      static_cast<unsigned long long>(takeover.degradedCalls),
      static_cast<unsigned>(takeover.stormOptionFlags),
      static_cast<unsigned>(takeover.lastHeapId),
      static_cast<unsigned>(takeover.lastStormFlags),
      static_cast<unsigned>(takeover.lastExportedOrdinal),
      RouteName(takeover.lastRoute),
      DegradedReasonName(takeover.lastDegradedReason),
      static_cast<unsigned>(takeover.lastDegradedReason),
      static_cast<unsigned>(takeover.registryCapacity),
      static_cast<unsigned>(takeover.registryActive),
      static_cast<unsigned>(takeover.registryDestroying),
      static_cast<unsigned>(takeover.registryTombstones),
      static_cast<unsigned>(takeover.registryNativeDelegated),
      static_cast<unsigned long long>(takeover.registryInsertFailures));
  line.Append("\"routeLatency\":{");
  for (std::size_t route = 0;
       route < LeakProfiler::kBackendRouteCount; ++route) {
    const BackendRoute routeValue = static_cast<BackendRoute>(route);
    const RouteLatencySnapshot &routeLatency =
        takeover.routeLatency[route];
    line.Append(
        "%s\"%s\":{\"sampleCount\":%llu,\"totalNanoseconds\":%llu,"
        "\"maxNanoseconds\":%llu,\"p50Nanoseconds\":%llu,"
        "\"p95Nanoseconds\":%llu,\"p99Nanoseconds\":%llu}",
        route == 0 ? "" : ",", RouteName(routeValue),
        static_cast<unsigned long long>(routeLatency.sampleCount),
        static_cast<unsigned long long>(routeLatency.totalNanoseconds),
        static_cast<unsigned long long>(routeLatency.maxNanoseconds),
        static_cast<unsigned long long>(routeLatency.p50Nanoseconds),
        static_cast<unsigned long long>(routeLatency.p95Nanoseconds),
        static_cast<unsigned long long>(routeLatency.p99Nanoseconds));
  }
  line.Append(
      "},\"telemetryWriteErrors\":%llu}\n",
      static_cast<unsigned long long>(
          g_writeErrors.load(std::memory_order_acquire)));
  return line.IsValid() && WriteAll(line.Data(), line.Length());
}

DWORD WINAPI WriterThreadMain(void *) noexcept {
  std::uint64_t sequence = 1;
  for (;;) {
    if (SnapshotProvider provider =
            g_snapshotProvider.load(std::memory_order_acquire)) {
      provider();
    }
    const LeakProfiler::HealthSnapshot health =
        LeakProfiler::GetHealthSnapshot();
    ProfilerHealthSnapshot profiler{};
    profiler.eventsEnqueued = health.eventsEnqueued;
    profiler.eventsWritten = health.eventsWritten;
    profiler.dropped = health.dropped;
    profiler.recursionSkips = health.recursionSkips;
    profiler.writeErrors = health.writeErrors;
    profiler.managedEvents = health.managedEvents;
    profiler.nativeEvents = health.nativeEvents;
    profiler.fallbackEvents = health.fallbackEvents;
    profiler.degradedEvents = health.degradedEvents;
    profiler.queueCapacity = health.queueCapacity;
    profiler.queueDepth = health.queueDepth;
    profiler.mode = static_cast<std::uint8_t>(health.mode);
    profiler.incomplete = health.incomplete;
    profiler.writerRunning = health.writerRunning;
    UpdateProfilerHealth(profiler);
    if (!WriteMetricsLine(sequence++)) {
      g_writeErrors.fetch_add(1, std::memory_order_relaxed);
    }
    if (!FlushFileBuffers(g_file)) {
      g_writeErrors.fetch_add(1, std::memory_order_relaxed);
    }
    if (WaitForSingleObject(g_stopEvent, kPublishIntervalMilliseconds) ==
        WAIT_OBJECT_0) {
      break;
    }
  }
  return 0;
}

} // namespace

void UpdateRuntime(const RuntimeSnapshot &snapshot) noexcept {
  const std::uint64_t values[2] = {
      snapshot.hooksInstalled ? 1u : 0u,
      static_cast<std::uint8_t>(snapshot.memoryBackend)};
  g_runtime.Publish(values);
}

void UpdateHook(const HookSnapshot &snapshot) noexcept {
  const std::uint64_t values[8] = {
      snapshot.allocCalls,   snapshot.freeCalls,   snapshot.reallocCalls,
      snapshot.getSizeCalls, snapshot.cleanupCalls, snapshot.resetCalls,
      snapshot.bypassCalls,  snapshot.failures};
  g_hook.Publish(values);
}

void UpdateBackend(const BackendSnapshot &snapshot) noexcept {
  const std::uint64_t values[8] = {
      snapshot.managedAllocations, snapshot.managedFrees,
      snapshot.nativeAllocations,  snapshot.nativeFrees,
      snapshot.managedBytes,       snapshot.nativeBytes,
      snapshot.fallbackAllocations, snapshot.failures};
  g_backend.Publish(values);
}

void UpdatePool(const PoolSnapshot &snapshot) noexcept {
  const std::uint64_t values[18] = {
      snapshot.requestedLiveBytes,
      snapshot.usableLiveBytes,
      snapshot.reservedBytes,
      snapshot.committedBytes,
      snapshot.peakRequestedLiveBytes,
      snapshot.peakUsableLiveBytes,
      snapshot.peakReservedBytes,
      snapshot.peakCommittedBytes,
      snapshot.requestedLiveBudgetBytes,
      snapshot.allocationCount,
      snapshot.freeCount,
      snapshot.reallocCount,
      snapshot.failureCount,
      snapshot.extendCount,
      snapshot.trimCount,
      snapshot.lockWaitCount,
      snapshot.lockWaitNanoseconds,
      snapshot.maxLockWaitNanoseconds};
  g_pool.Publish(values);
}

void UpdateLatency(const LatencySnapshot &snapshot) noexcept {
  const std::uint64_t values[12] = {
      snapshot.sampleCount, snapshot.totalNanoseconds,
      snapshot.maxNanoseconds, snapshot.p50Nanoseconds,
      snapshot.p95Nanoseconds, snapshot.p99Nanoseconds,
      snapshot.allocateP99Nanoseconds, snapshot.freeP99Nanoseconds,
      snapshot.reallocateP99Nanoseconds, snapshot.copyP99Nanoseconds,
      snapshot.growthP99Nanoseconds, snapshot.lockWaitP99Nanoseconds};
  g_latency.Publish(values);
}

void UpdateProfilerHealth(const ProfilerHealthSnapshot &snapshot) noexcept {
  const std::uint64_t values[14] = {
      snapshot.eventsEnqueued,
      snapshot.eventsWritten,
      snapshot.dropped,
      snapshot.recursionSkips,
      snapshot.writeErrors,
      snapshot.managedEvents,
      snapshot.nativeEvents,
      snapshot.fallbackEvents,
      snapshot.degradedEvents,
      snapshot.queueCapacity,
      snapshot.queueDepth,
      snapshot.mode,
      snapshot.incomplete ? 1u : 0u,
      snapshot.writerRunning ? 1u : 0u};
  g_profiler.Publish(values);
}

void UpdateTakeover(const TakeoverSnapshot &snapshot) noexcept {
  std::uint64_t values[kTakeoverFieldCount]{};
  EncodeTakeoverSnapshot(snapshot, values);
  g_takeover.Publish(values);
  LeakProfiler::UpdateTakeoverSnapshot(snapshot);
}

void SetSnapshotProvider(SnapshotProvider provider) noexcept {
  g_snapshotProvider.store(provider, std::memory_order_release);
}

bool Start(const wchar_t *artifactDirectory) noexcept {
  AcquireSRWLockExclusive(&g_lifecycleLock);
  if (g_running.load(std::memory_order_acquire)) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return true;
  }

  g_outputPath[0] = L'\0';
  if (!BuildOutputPath(artifactDirectory)) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }

  g_file = CreateFileW(g_outputPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                       nullptr);
  if (g_file == INVALID_HANDLE_VALUE) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }
  g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent) {
    CloseHandle(g_file);
    g_file = INVALID_HANDLE_VALUE;
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }
  g_writeErrors.store(0, std::memory_order_relaxed);
  g_writerThread =
      CreateThread(nullptr, 0, WriterThreadMain, nullptr, 0, nullptr);
  if (!g_writerThread) {
    CloseHandle(g_stopEvent);
    CloseHandle(g_file);
    g_stopEvent = nullptr;
    g_file = INVALID_HANDLE_VALUE;
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }

  g_running.store(true, std::memory_order_release);
  ReleaseSRWLockExclusive(&g_lifecycleLock);
  return true;
}

void RequestStop() noexcept {
  HANDLE stopEvent = g_stopEvent;
  if (stopEvent) {
    SetEvent(stopEvent);
  }
}

bool Stop(std::uint32_t timeoutMilliseconds) noexcept {
  RequestStop();

  AcquireSRWLockExclusive(&g_lifecycleLock);
  if (!g_running.load(std::memory_order_acquire)) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return true;
  }
  HANDLE writerThread = g_writerThread;
  ReleaseSRWLockExclusive(&g_lifecycleLock);

  if (WaitForSingleObject(writerThread, timeoutMilliseconds) != WAIT_OBJECT_0) {
    return false;
  }

  AcquireSRWLockExclusive(&g_lifecycleLock);
  CloseHandle(g_writerThread);
  CloseHandle(g_stopEvent);
  CloseHandle(g_file);
  g_writerThread = nullptr;
  g_stopEvent = nullptr;
  g_file = INVALID_HANDLE_VALUE;
  g_running.store(false, std::memory_order_release);
  ReleaseSRWLockExclusive(&g_lifecycleLock);
  return true;
}

bool IsRunning() noexcept { return g_running.load(std::memory_order_acquire); }

const wchar_t *GetOutputPath() noexcept { return g_outputPath; }

} // namespace Telemetry
} // namespace StormBreaker
