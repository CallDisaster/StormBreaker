#pragma once

#include "LeakProfiler.h"

#include <cstdint>

namespace StormBreaker {
namespace Telemetry {

enum class MemoryBackend : std::uint8_t {
  Off = 0,
  Tlsf = 1,
  Mimalloc = 2,
  TlsfSharded = 3,
  Hybrid = 4,
};

using BackendRoute = LeakProfiler::BackendRoute;
using DegradedReason = LeakProfiler::DegradedReason;
using RouteLatencySnapshot = LeakProfiler::RouteLatencySnapshot;
using TakeoverSnapshot = LeakProfiler::TakeoverSnapshot;

struct RuntimeSnapshot {
  bool hooksInstalled = false;
  MemoryBackend memoryBackend = MemoryBackend::Off;
};

struct HookSnapshot {
  std::uint64_t allocCalls = 0;
  std::uint64_t freeCalls = 0;
  std::uint64_t reallocCalls = 0;
  std::uint64_t getSizeCalls = 0;
  std::uint64_t cleanupCalls = 0;
  std::uint64_t resetCalls = 0;
  std::uint64_t bypassCalls = 0;
  std::uint64_t failures = 0;
};

struct BackendSnapshot {
  std::uint64_t managedAllocations = 0;
  std::uint64_t managedFrees = 0;
  std::uint64_t nativeAllocations = 0;
  std::uint64_t nativeFrees = 0;
  std::uint64_t managedBytes = 0;
  std::uint64_t nativeBytes = 0;
  std::uint64_t fallbackAllocations = 0;
  std::uint64_t failures = 0;
};

struct PoolSnapshot {
  std::uint64_t requestedLiveBytes = 0;
  std::uint64_t usableLiveBytes = 0;
  std::uint64_t reservedBytes = 0;
  std::uint64_t committedBytes = 0;
  std::uint64_t peakRequestedLiveBytes = 0;
  std::uint64_t peakUsableLiveBytes = 0;
  std::uint64_t peakReservedBytes = 0;
  std::uint64_t peakCommittedBytes = 0;
  std::uint64_t requestedLiveBudgetBytes = 0;
  std::uint64_t allocationCount = 0;
  std::uint64_t freeCount = 0;
  std::uint64_t reallocCount = 0;
  std::uint64_t failureCount = 0;
  std::uint64_t extendCount = 0;
  std::uint64_t trimCount = 0;
  std::uint64_t lockWaitCount = 0;
  std::uint64_t lockWaitNanoseconds = 0;
  std::uint64_t maxLockWaitNanoseconds = 0;
};

struct LatencySnapshot {
  std::uint64_t sampleCount = 0;
  std::uint64_t totalNanoseconds = 0;
  std::uint64_t maxNanoseconds = 0;
  std::uint64_t p50Nanoseconds = 0;
  std::uint64_t p95Nanoseconds = 0;
  std::uint64_t p99Nanoseconds = 0;
  std::uint64_t allocateP99Nanoseconds = 0;
  std::uint64_t freeP99Nanoseconds = 0;
  std::uint64_t reallocateP99Nanoseconds = 0;
  std::uint64_t copyP99Nanoseconds = 0;
  std::uint64_t growthP99Nanoseconds = 0;
  std::uint64_t lockWaitP99Nanoseconds = 0;
};

struct ProfilerHealthSnapshot {
  std::uint64_t eventsEnqueued = 0;
  std::uint64_t eventsWritten = 0;
  std::uint64_t dropped = 0;
  std::uint64_t recursionSkips = 0;
  std::uint64_t writeErrors = 0;
  std::uint64_t managedEvents = 0;
  std::uint64_t nativeEvents = 0;
  std::uint64_t fallbackEvents = 0;
  std::uint64_t degradedEvents = 0;
  std::uint32_t queueCapacity = 0;
  std::uint32_t queueDepth = 0;
  std::uint8_t mode = 0;
  bool incomplete = false;
  bool writerRunning = false;
};

// Each category is atomically published as one coherent snapshot. These APIs
// intentionally take plain value objects and do not depend on MemoryPool.
void UpdateRuntime(const RuntimeSnapshot &snapshot) noexcept;
void UpdateHook(const HookSnapshot &snapshot) noexcept;
void UpdateBackend(const BackendSnapshot &snapshot) noexcept;
void UpdatePool(const PoolSnapshot &snapshot) noexcept;
void UpdateLatency(const LatencySnapshot &snapshot) noexcept;
void UpdateProfilerHealth(const ProfilerHealthSnapshot &snapshot) noexcept;
void UpdateTakeover(const TakeoverSnapshot &snapshot) noexcept;

using SnapshotProvider = void (*)() noexcept;
void SetSnapshotProvider(SnapshotProvider provider) noexcept;

bool Start(const wchar_t *artifactDirectory = nullptr) noexcept;
void RequestStop() noexcept;
bool Stop(std::uint32_t timeoutMilliseconds = 5000) noexcept;
bool IsRunning() noexcept;
const wchar_t *GetOutputPath() noexcept;

} // namespace Telemetry
} // namespace StormBreaker
