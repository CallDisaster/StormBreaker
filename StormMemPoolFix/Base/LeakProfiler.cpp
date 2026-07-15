#include "pch.h"

#include "LeakProfiler.h"

#include <TlHelp32.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <new>

namespace StormBreaker {
namespace LeakProfiler {
namespace {

constexpr std::uint16_t kRecordHeaderSize = 24;
constexpr std::uint16_t kFileVersion = kBinaryStreamVersion;
constexpr std::size_t kFileHeaderSize = 32;
constexpr std::size_t kMaxRecordSize = 2048;
constexpr wchar_t kDefaultArtifactDirectory[] = L".\\StormBreaker";
constexpr DWORD kConsumerPollMilliseconds = 10;
constexpr ULONGLONG kCheckpointMilliseconds = 1000;

constexpr std::uint16_t kFlagNativeSampled = 0x0001;
constexpr std::uint16_t kReallocOldFreed = 0x0001;
constexpr std::uint16_t kReallocNewAllocated = 0x0002;
constexpr std::uint16_t kReallocInPlace = 0x0004;
constexpr std::uint16_t kReallocOldTracked = 0x0008;
constexpr std::uint16_t kReallocNewTracked = 0x0010;
constexpr std::uint16_t kReallocOldSampled = 0x0020;
constexpr std::uint16_t kReallocNewSampled = 0x0040;
constexpr std::uint16_t kReallocNewDomainManaged = 0x0080;
constexpr std::uint16_t kCheckpointPayloadVersion = 2;

constexpr std::size_t kTakeoverScalarFieldCount = 17;
constexpr std::size_t kRouteLatencyFieldCount = 6;
constexpr std::size_t kTakeoverFieldCount =
    kTakeoverScalarFieldCount +
    kBackendRouteCount * kRouteLatencyFieldCount;

struct ProfileEvent {
  EventType type = EventType::Alloc;
  AllocationDomain domain = AllocationDomain::Native;
  AllocationDomain secondDomain = AllocationDomain::Native;
  std::uint8_t stackDepth = 0;
  std::uint16_t flags = 0;
  std::uint32_t threadId = 0;
  std::uint64_t timestampQpc = 0;
  std::uint64_t pointer = 0;
  std::uint64_t secondPointer = 0;
  std::uint64_t size = 0;
  std::uint64_t secondSize = 0;
  std::uint64_t epoch = 0;
  std::uint32_t reason = 0;
  EventMetadata metadata{};
  EventMetadata secondMetadata{};
  std::uint64_t stack[kMaxStackDepth]{};
};

struct alignas(64) RingSlot {
  RingSlot() noexcept : sequence(0), event{} {}

  std::atomic<std::uint64_t> sequence;
  ProfileEvent event;
};

class BoundedMpscRing {
public:
  explicit BoundedMpscRing(RingSlot *slots) noexcept
      : slots_(slots), enqueuePosition_(0), dequeuePosition_(0) {}

  void Reset() noexcept {
    enqueuePosition_.store(0, std::memory_order_relaxed);
    dequeuePosition_.store(0, std::memory_order_relaxed);
    for (std::uint64_t index = 0; index < kRingCapacity; ++index) {
      slots_[index].sequence.store(index, std::memory_order_relaxed);
    }
  }

  bool TryPush(const ProfileEvent &event) noexcept {
    std::uint64_t position =
        enqueuePosition_.load(std::memory_order_relaxed);
    for (;;) {
      RingSlot &slot = slots_[position & (kRingCapacity - 1)];
      const std::uint64_t sequence =
          slot.sequence.load(std::memory_order_acquire);
      const std::int64_t difference =
          static_cast<std::int64_t>(sequence - position);

      if (difference == 0) {
        if (enqueuePosition_.compare_exchange_weak(
                position, position + 1, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
          slot.event = event;
          slot.sequence.store(position + 1, std::memory_order_release);
          return true;
        }
      } else if (difference < 0) {
        return false;
      } else {
        position = enqueuePosition_.load(std::memory_order_relaxed);
      }
    }
  }

  bool TryPop(ProfileEvent &event) noexcept {
    const std::uint64_t position =
        dequeuePosition_.load(std::memory_order_relaxed);
    RingSlot &slot = slots_[position & (kRingCapacity - 1)];
    const std::uint64_t sequence =
        slot.sequence.load(std::memory_order_acquire);
    const std::int64_t difference =
        static_cast<std::int64_t>(sequence - (position + 1));
    if (difference != 0) {
      return false;
    }

    event = slot.event;
    dequeuePosition_.store(position + 1, std::memory_order_relaxed);
    slot.sequence.store(position + kRingCapacity,
                        std::memory_order_release);
    return true;
  }

  std::uint32_t Depth() const noexcept {
    const std::uint64_t enqueue =
        enqueuePosition_.load(std::memory_order_acquire);
    const std::uint64_t dequeue =
        dequeuePosition_.load(std::memory_order_acquire);
    if (enqueue < dequeue) {
      return 0;
    }
    const std::uint64_t depth = enqueue - dequeue;
    return static_cast<std::uint32_t>(
        depth > kRingCapacity ? kRingCapacity : depth);
  }

  void DestroySlots() noexcept {
    for (std::size_t index = 0; index < kRingCapacity; ++index) {
      slots_[index].~RingSlot();
    }
  }

private:
  static_assert((kRingCapacity & (kRingCapacity - 1)) == 0,
                "ring capacity must be a power of two");
  RingSlot *slots_ = nullptr;
  alignas(64) std::atomic<std::uint64_t> enqueuePosition_;
  alignas(64) std::atomic<std::uint64_t> dequeuePosition_;
};

struct TrackingDecision {
  bool tracked;
  bool sampled;
};

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

// The ring is preallocated before profiling starts, but profiler=off must not
// inflate the DLL image or process commit by the full diagnostic buffer.
BoundedMpscRing *g_ring = nullptr;
std::atomic<Mode> g_mode{Mode::Off};
std::atomic<bool> g_accepting{false};
std::atomic<bool> g_started{false};
std::atomic<bool> g_writerRunning{false};
std::atomic<bool> g_incomplete{false};
std::atomic<std::uint32_t> g_activeProducers{0};
std::atomic<std::uint64_t> g_eventsEnqueued{0};
std::atomic<std::uint64_t> g_eventsWritten{0};
std::atomic<std::uint64_t> g_dropped{0};
std::atomic<std::uint64_t> g_recursionSkips{0};
std::atomic<std::uint64_t> g_writeErrors{0};
std::atomic<std::uint64_t> g_recordSequence{0};
std::atomic<std::uint64_t> g_managedEvents{0};
std::atomic<std::uint64_t> g_nativeEvents{0};
std::atomic<std::uint64_t> g_fallbackEvents{0};
std::atomic<std::uint64_t> g_degradedEvents{0};
AtomicSnapshotStore<kTakeoverFieldCount> g_takeover;
thread_local std::uint32_t g_recursionDepth = 0;

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
  for (std::size_t route = 0; route < kBackendRouteCount; ++route) {
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
  for (std::size_t route = 0; route < kBackendRouteCount; ++route) {
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

bool EnsureRing() noexcept {
  if (g_ring) {
    return true;
  }
  constexpr std::size_t kSlotAlignment = alignof(RingSlot);
  const std::size_t slotsOffset =
      (sizeof(BoundedMpscRing) + kSlotAlignment - 1) &
      ~(kSlotAlignment - 1);
  const std::size_t allocationBytes =
      slotsOffset + sizeof(RingSlot) * kRingCapacity;
  void *memory = VirtualAlloc(nullptr, allocationBytes,
                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!memory) {
    return false;
  }
  auto *slots = reinterpret_cast<RingSlot *>(
      static_cast<std::uint8_t *>(memory) + slotsOffset);
  for (std::size_t index = 0; index < kRingCapacity; ++index) {
    new (&slots[index]) RingSlot();
  }
  g_ring = new (memory) BoundedMpscRing(slots);
  return true;
}

void ReleaseRing() noexcept {
  BoundedMpscRing *ring = g_ring;
  if (!ring) {
    return;
  }
  g_ring = nullptr;
  ring->DestroySlots();
  ring->~BoundedMpscRing();
  VirtualFree(ring, 0, MEM_RELEASE);
}

class ScopedRecursionGuard {
public:
  ScopedRecursionGuard() noexcept { ++g_recursionDepth; }
  ~ScopedRecursionGuard() noexcept { --g_recursionDepth; }
  ScopedRecursionGuard(const ScopedRecursionGuard &) = delete;
  ScopedRecursionGuard &operator=(const ScopedRecursionGuard &) = delete;
};

class ScopedProducer {
public:
  ScopedProducer() noexcept {
    g_activeProducers.fetch_add(1, std::memory_order_acq_rel);
    active_ = g_accepting.load(std::memory_order_acquire);
  }
  ~ScopedProducer() noexcept {
    g_activeProducers.fetch_sub(1, std::memory_order_release);
  }
  bool IsActive() const noexcept { return active_; }

  ScopedProducer(const ScopedProducer &) = delete;
  ScopedProducer &operator=(const ScopedProducer &) = delete;

private:
  bool active_ = false;
};

bool EqualsIgnoreCase(const char *left, const char *right) noexcept {
  if (!left || !right) {
    return false;
  }
  while (*left && *right) {
    char a = *left++;
    char b = *right++;
    if (a >= 'A' && a <= 'Z') {
      a = static_cast<char>(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
      b = static_cast<char>(b - 'A' + 'a');
    }
    if (a != b) {
      return false;
    }
  }
  return *left == '\0' && *right == '\0';
}

std::uint64_t PointerHash(const void *pointer) noexcept {
  std::uint64_t value =
      static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(pointer));
  value ^= value >> 33;
  value *= 0xff51afd7ed558ccdULL;
  value ^= value >> 33;
  value *= 0xc4ceb9fe1a85ec53ULL;
  value ^= value >> 33;
  return value;
}

TrackingDecision DecideTracking(Mode mode, AllocationDomain domain,
                                const void *pointer,
                                std::uint64_t size) noexcept {
  if (mode == Mode::Off || pointer == nullptr) {
    return {false, false};
  }
  if (mode == Mode::Full || domain == AllocationDomain::Managed) {
    return {true, false};
  }
  if (size > kNativeSmallBlockLimit) {
    return {true, false};
  }
  const bool selected =
      (PointerHash(pointer) & (kNativeSmallSampleRate - 1u)) == 0;
  return {selected, selected};
}

std::uint64_t QueryQpc() noexcept {
  LARGE_INTEGER value{};
  QueryPerformanceCounter(&value);
  return static_cast<std::uint64_t>(value.QuadPart);
}

std::uint8_t CaptureFrames(std::uint64_t *frames) noexcept {
  void *captured[kMaxStackDepth]{};
  const USHORT count = CaptureStackBackTrace(
      3, static_cast<DWORD>(kMaxStackDepth), captured, nullptr);
  for (USHORT index = 0; index < count; ++index) {
    frames[index] = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(captured[index]));
  }
  return static_cast<std::uint8_t>(count);
}

ProfileEvent MakeEvent(EventType type, AllocationDomain domain,
                       const EventMetadata &metadata,
                       bool withStack) noexcept {
  ProfileEvent event{};
  event.type = type;
  event.domain = domain;
  event.metadata = metadata;
  event.threadId = GetCurrentThreadId();
  event.timestampQpc = QueryQpc();
  if (withStack) {
    event.stackDepth = CaptureFrames(event.stack);
  }
  return event;
}

void QueueEvent(const ProfileEvent &event) noexcept {
  BoundedMpscRing *ring = g_ring;
  if (ring && ring->TryPush(event)) {
    g_eventsEnqueued.fetch_add(1, std::memory_order_relaxed);
    const bool operationEvent =
        event.type == EventType::Alloc || event.type == EventType::Free ||
        event.type == EventType::ReallocOutcome ||
        event.type == EventType::StormApi;
    if (!operationEvent) {
      return;
    }
    const bool reallocEvent = event.type == EventType::ReallocOutcome;
    if (event.domain == AllocationDomain::Managed ||
        (reallocEvent &&
         event.secondDomain == AllocationDomain::Managed)) {
      g_managedEvents.fetch_add(1, std::memory_order_relaxed);
    }
    if (event.domain == AllocationDomain::Native ||
        (reallocEvent && event.secondDomain == AllocationDomain::Native)) {
      g_nativeEvents.fetch_add(1, std::memory_order_relaxed);
    }
    if (IsFallback(event.metadata.disposition) ||
        (reallocEvent &&
         IsFallback(event.secondMetadata.disposition))) {
      g_fallbackEvents.fetch_add(1, std::memory_order_relaxed);
    }
    if (IsDegraded(event.metadata.disposition) ||
        event.metadata.reason != DegradedReason::None ||
        (reallocEvent &&
         (IsDegraded(event.secondMetadata.disposition) ||
          event.secondMetadata.reason != DegradedReason::None))) {
      g_degradedEvents.fetch_add(1, std::memory_order_relaxed);
    }
    return;
  }
  g_dropped.fetch_add(1, std::memory_order_relaxed);
  g_incomplete.store(true, std::memory_order_release);
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
      hasSeparator ? L"%lsleak_profile_%lu.sblp"
                   : L"%ls\\leak_profile_%lu.sblp",
      directory, static_cast<unsigned long>(GetCurrentProcessId()));
  return written > 0 && static_cast<std::size_t>(written) <
                            _countof(g_outputPath);
}

void PutU8(std::uint8_t *buffer, std::size_t &offset,
           std::uint8_t value) noexcept {
  buffer[offset++] = value;
}

void PutU16(std::uint8_t *buffer, std::size_t &offset,
            std::uint16_t value) noexcept {
  buffer[offset++] = static_cast<std::uint8_t>(value);
  buffer[offset++] = static_cast<std::uint8_t>(value >> 8);
}

void PutU32(std::uint8_t *buffer, std::size_t &offset,
            std::uint32_t value) noexcept {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    buffer[offset++] = static_cast<std::uint8_t>(value >> shift);
  }
}

void PutU64(std::uint8_t *buffer, std::size_t &offset,
            std::uint64_t value) noexcept {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    buffer[offset++] = static_cast<std::uint8_t>(value >> shift);
  }
}

void PutEventMetadata(std::uint8_t *buffer, std::size_t &offset,
                      const EventMetadata &metadata) noexcept {
  PutU32(buffer, offset, metadata.heapId);
  PutU32(buffer, offset, metadata.stormFlags);
  PutU16(buffer, offset, metadata.exportedOrdinal);
  PutU8(buffer, offset, static_cast<std::uint8_t>(metadata.route));
  PutU8(buffer, offset, static_cast<std::uint8_t>(metadata.reason));
  PutU8(buffer, offset,
        static_cast<std::uint8_t>(metadata.disposition));
  PutU8(buffer, offset, 0);
  PutU16(buffer, offset, 0);
}

std::uint32_t Crc32(const std::uint8_t *data, std::size_t length) noexcept {
  std::uint32_t crc = 0xffffffffu;
  for (std::size_t index = 0; index < length; ++index) {
    crc ^= data[index];
    for (unsigned bit = 0; bit < 8; ++bit) {
      const std::uint32_t mask =
          static_cast<std::uint32_t>(-
              static_cast<std::int32_t>(crc & 1u));
      crc = (crc >> 1) ^ (0xedb88320u & mask);
    }
  }
  return ~crc;
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

bool WriteFileHeader(Mode mode) noexcept {
  std::uint8_t header[kFileHeaderSize]{};
  std::size_t offset = 0;
  header[offset++] = 'S';
  header[offset++] = 'B';
  header[offset++] = 'L';
  header[offset++] = 'P';
  PutU16(header, offset, kFileVersion);
  PutU16(header, offset, static_cast<std::uint16_t>(kFileHeaderSize));
  PutU8(header, offset, 1); // little endian
  PutU8(header, offset, static_cast<std::uint8_t>(sizeof(void *)));
  PutU8(header, offset, static_cast<std::uint8_t>(mode));
  PutU8(header, offset, 0);
  PutU32(header, offset, GetCurrentProcessId());

  FILETIME fileTime{};
  GetSystemTimeAsFileTime(&fileTime);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = fileTime.dwLowDateTime;
  ticks.HighPart = fileTime.dwHighDateTime;
  constexpr std::uint64_t kWindowsToUnix100ns = 116444736000000000ULL;
  const std::uint64_t unixNanoseconds =
      (ticks.QuadPart - kWindowsToUnix100ns) * 100ULL;
  PutU64(header, offset, unixNanoseconds);

  LARGE_INTEGER frequency{};
  QueryPerformanceFrequency(&frequency);
  PutU64(header, offset, static_cast<std::uint64_t>(frequency.QuadPart));
  return offset == kFileHeaderSize && WriteAll(header, sizeof(header));
}

bool WriteRecord(EventType type, const std::uint8_t *payload,
                 std::size_t payloadLength) noexcept {
  if (payloadLength + kRecordHeaderSize + sizeof(std::uint32_t) >
      kMaxRecordSize) {
    return false;
  }

  std::uint8_t record[kMaxRecordSize]{};
  std::size_t offset = 0;
  record[offset++] = 'S';
  record[offset++] = 'B';
  record[offset++] = 'L';
  record[offset++] = 'R';
  const std::uint32_t totalLength = static_cast<std::uint32_t>(
      kRecordHeaderSize + payloadLength + sizeof(std::uint32_t));
  PutU32(record, offset, totalLength);
  PutU16(record, offset, static_cast<std::uint16_t>(type));
  PutU16(record, offset, kRecordHeaderSize);
  PutU64(record, offset,
         g_recordSequence.fetch_add(1, std::memory_order_relaxed) + 1);
  PutU32(record, offset, static_cast<std::uint32_t>(payloadLength));
  std::memcpy(record + offset, payload, payloadLength);
  offset += payloadLength;
  const std::uint32_t crc = Crc32(record, offset);
  PutU32(record, offset, crc);
  return offset == totalLength && WriteAll(record, offset);
}

bool WriteModuleSnapshot() noexcept {
  HANDLE snapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  MODULEENTRY32W module{};
  module.dwSize = sizeof(module);
  bool ok = Module32FirstW(snapshot, &module) != FALSE;
  while (ok) {
    char path[1100]{};
    const int encoded = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, module.szExePath, -1, path,
        static_cast<int>(sizeof(path)), nullptr, nullptr);
    if (encoded <= 1) {
      CloseHandle(snapshot);
      return false;
    }

    const std::size_t pathLength = static_cast<std::size_t>(encoded - 1);
    std::uint8_t payload[sizeof(std::uint64_t) * 2 + sizeof(std::uint16_t) +
                         sizeof(path)]{};
    std::size_t offset = 0;
    PutU64(payload, offset, static_cast<std::uint64_t>(
                                reinterpret_cast<std::uintptr_t>(
                                    module.modBaseAddr)));
    PutU64(payload, offset, static_cast<std::uint64_t>(module.modBaseSize));
    PutU16(payload, offset, static_cast<std::uint16_t>(pathLength));
    std::memcpy(payload + offset, path, pathLength);
    offset += pathLength;
    if (!WriteRecord(EventType::ModuleSnapshot, payload, offset)) {
      CloseHandle(snapshot);
      return false;
    }
    ok = Module32NextW(snapshot, &module) != FALSE;
  }

  const DWORD error = GetLastError();
  CloseHandle(snapshot);
  return error == ERROR_NO_MORE_FILES;
}

bool WriteProfileEvent(const ProfileEvent &event) noexcept {
  std::uint8_t payload[256]{};
  std::size_t offset = 0;

  if (event.type == EventType::EpochMarker) {
    PutU64(payload, offset, event.timestampQpc);
    PutU64(payload, offset, event.epoch);
    PutU32(payload, offset, event.reason);
    PutU32(payload, offset, event.threadId);
    return WriteRecord(event.type, payload, offset);
  }

  PutU64(payload, offset, event.timestampQpc);
  PutU32(payload, offset, event.threadId);
  PutU8(payload, offset, static_cast<std::uint8_t>(event.domain));
  PutU8(payload, offset, event.stackDepth);
  PutU16(payload, offset, event.flags);
  PutEventMetadata(payload, offset, event.metadata);
  if (event.type == EventType::ReallocOutcome) {
    PutU64(payload, offset, event.pointer);
    PutU64(payload, offset, event.secondPointer);
    PutU64(payload, offset, event.size);
    PutU64(payload, offset, event.secondSize);
    PutU8(payload, offset, static_cast<std::uint8_t>(event.secondDomain));
    PutU8(payload, offset, 0);
    PutU16(payload, offset, 0);
    PutEventMetadata(payload, offset, event.secondMetadata);
  } else if (event.type == EventType::StormApi) {
    PutU64(payload, offset, event.pointer);
    PutU64(payload, offset, event.secondPointer);
  } else {
    PutU64(payload, offset, event.pointer);
    PutU64(payload, offset, event.size);
  }
  for (std::uint8_t index = 0; index < event.stackDepth; ++index) {
    PutU64(payload, offset, event.stack[index]);
  }
  return WriteRecord(event.type, payload, offset);
}

bool WriteCheckpoint() noexcept {
  std::uint8_t payload[512]{};
  std::size_t offset = 0;
  PutU64(payload, offset, QueryQpc());
  PutU64(payload, offset,
         g_eventsEnqueued.load(std::memory_order_acquire));
  PutU64(payload, offset,
         g_eventsWritten.load(std::memory_order_acquire));
  PutU64(payload, offset, g_dropped.load(std::memory_order_acquire));
  PutU32(payload, offset, g_ring ? g_ring->Depth() : 0);
  PutU8(payload, offset,
        g_incomplete.load(std::memory_order_acquire) ? 1u : 0u);
  PutU8(payload, offset,
        g_writeErrors.load(std::memory_order_acquire) != 0 ? 1u : 0u);
  PutU16(payload, offset, kCheckpointPayloadVersion);
  PutU64(payload, offset,
         g_managedEvents.load(std::memory_order_acquire));
  PutU64(payload, offset,
         g_nativeEvents.load(std::memory_order_acquire));
  PutU64(payload, offset,
         g_fallbackEvents.load(std::memory_order_acquire));
  PutU64(payload, offset,
         g_degradedEvents.load(std::memory_order_acquire));

  std::uint64_t values[kTakeoverFieldCount]{};
  g_takeover.Read(values);
  const TakeoverSnapshot takeover = DecodeTakeoverSnapshot(values);
  PutU64(payload, offset, takeover.managedApiCalls);
  PutU64(payload, offset, takeover.nativeApiCalls);
  PutU64(payload, offset, takeover.managedFallbackCalls);
  PutU64(payload, offset, takeover.nativeFallbackCalls);
  PutU64(payload, offset, takeover.degradedCalls);
  PutU64(payload, offset, takeover.registryInsertFailures);
  PutU32(payload, offset, takeover.registryCapacity);
  PutU32(payload, offset, takeover.registryActive);
  PutU32(payload, offset, takeover.registryDestroying);
  PutU32(payload, offset, takeover.registryTombstones);
  PutU32(payload, offset, takeover.registryNativeDelegated);
  PutU32(payload, offset, takeover.stormOptionFlags);
  PutU32(payload, offset, takeover.lastHeapId);
  PutU32(payload, offset, takeover.lastStormFlags);
  PutU16(payload, offset, takeover.lastExportedOrdinal);
  PutU8(payload, offset, static_cast<std::uint8_t>(takeover.lastRoute));
  PutU8(payload, offset,
        static_cast<std::uint8_t>(takeover.lastDegradedReason));
  PutU8(payload, offset, static_cast<std::uint8_t>(kBackendRouteCount));
  PutU8(payload, offset, 0);
  PutU16(payload, offset, 0);
  for (std::size_t route = 0; route < kBackendRouteCount; ++route) {
    const RouteLatencySnapshot &latency = takeover.routeLatency[route];
    PutU64(payload, offset, latency.sampleCount);
    PutU64(payload, offset, latency.totalNanoseconds);
    PutU64(payload, offset, latency.maxNanoseconds);
    PutU64(payload, offset, latency.p50Nanoseconds);
    PutU64(payload, offset, latency.p95Nanoseconds);
    PutU64(payload, offset, latency.p99Nanoseconds);
  }
  return WriteRecord(EventType::Checkpoint, payload, offset);
}

void NoteWriteError() noexcept {
  g_writeErrors.fetch_add(1, std::memory_order_relaxed);
  g_incomplete.store(true, std::memory_order_release);
}

DWORD WINAPI WriterThreadMain(void *) noexcept {
  g_writerRunning.store(true, std::memory_order_release);
  ULONGLONG nextCheckpoint = GetTickCount64() + kCheckpointMilliseconds;

  for (;;) {
    std::uint32_t drained = 0;
    ProfileEvent event{};
    while (drained < 4096 && g_ring && g_ring->TryPop(event)) {
      if (WriteProfileEvent(event)) {
        g_eventsWritten.fetch_add(1, std::memory_order_relaxed);
      } else {
        NoteWriteError();
      }
      ++drained;
    }

    const ULONGLONG now = GetTickCount64();
    if (now >= nextCheckpoint) {
      if (!WriteCheckpoint()) {
        NoteWriteError();
      }
      if (!FlushFileBuffers(g_file)) {
        NoteWriteError();
      }
      nextCheckpoint = now + kCheckpointMilliseconds;
    }

    const bool stopping =
        WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
    if (stopping &&
        g_activeProducers.load(std::memory_order_acquire) == 0 &&
        (!g_ring || g_ring->Depth() == 0)) {
      if (!WriteCheckpoint()) {
        NoteWriteError();
      }
      if (!FlushFileBuffers(g_file)) {
        NoteWriteError();
      }
      break;
    }

    if (drained == 0) {
      WaitForSingleObject(g_stopEvent, kConsumerPollMilliseconds);
    }
  }

  g_writerRunning.store(false, std::memory_order_release);
  return 0;
}

} // namespace

Mode ParseMode(const char *value) noexcept {
  if (EqualsIgnoreCase(value, "sampled")) {
    return Mode::Sampled;
  }
  if (EqualsIgnoreCase(value, "full")) {
    return Mode::Full;
  }
  return Mode::Off;
}

Mode ReadModeFromEnvironment() noexcept {
  char value[32]{};
  const DWORD length = GetEnvironmentVariableA(
      "STORMBREAKER_PROFILER", value, static_cast<DWORD>(sizeof(value)));
  if (length == 0 || length >= sizeof(value)) {
    return Mode::Off;
  }
  return ParseMode(value);
}

const char *ModeName(Mode mode) noexcept {
  switch (mode) {
  case Mode::Sampled:
    return "sampled";
  case Mode::Full:
    return "full";
  default:
    return "off";
  }
}

bool Start(Mode mode, const wchar_t *artifactDirectory) noexcept {
  if (mode == Mode::Off) {
    g_mode.store(Mode::Off, std::memory_order_release);
    return true;
  }

  AcquireSRWLockExclusive(&g_lifecycleLock);
  if (g_started.load(std::memory_order_acquire)) {
    const bool sameMode = g_mode.load(std::memory_order_acquire) == mode;
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return sameMode;
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

  if (!EnsureRing()) {
    CloseHandle(g_stopEvent);
    CloseHandle(g_file);
    g_stopEvent = nullptr;
    g_file = INVALID_HANDLE_VALUE;
    g_outputPath[0] = L'\0';
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }
  g_ring->Reset();
  g_eventsEnqueued.store(0, std::memory_order_relaxed);
  g_eventsWritten.store(0, std::memory_order_relaxed);
  g_dropped.store(0, std::memory_order_relaxed);
  g_recursionSkips.store(0, std::memory_order_relaxed);
  g_writeErrors.store(0, std::memory_order_relaxed);
  g_recordSequence.store(0, std::memory_order_relaxed);
  g_managedEvents.store(0, std::memory_order_relaxed);
  g_nativeEvents.store(0, std::memory_order_relaxed);
  g_fallbackEvents.store(0, std::memory_order_relaxed);
  g_degradedEvents.store(0, std::memory_order_relaxed);
  g_activeProducers.store(0, std::memory_order_relaxed);
  g_incomplete.store(false, std::memory_order_relaxed);

  if (!WriteFileHeader(mode) || !WriteModuleSnapshot() ||
      !FlushFileBuffers(g_file)) {
    CloseHandle(g_stopEvent);
    CloseHandle(g_file);
    g_stopEvent = nullptr;
    g_file = INVALID_HANDLE_VALUE;
    g_outputPath[0] = L'\0';
    ReleaseRing();
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }

  g_mode.store(mode, std::memory_order_release);
  g_writerThread =
      CreateThread(nullptr, 0, WriterThreadMain, nullptr, 0, nullptr);
  if (!g_writerThread) {
    g_mode.store(Mode::Off, std::memory_order_release);
    CloseHandle(g_stopEvent);
    CloseHandle(g_file);
    g_stopEvent = nullptr;
    g_file = INVALID_HANDLE_VALUE;
    g_outputPath[0] = L'\0';
    ReleaseRing();
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }

  g_started.store(true, std::memory_order_release);
  g_accepting.store(true, std::memory_order_release);
  ReleaseSRWLockExclusive(&g_lifecycleLock);
  return true;
}

bool StartFromEnvironment(const wchar_t *artifactDirectory) noexcept {
  return Start(ReadModeFromEnvironment(), artifactDirectory);
}

void RequestStop() noexcept {
  g_accepting.store(false, std::memory_order_release);
  g_mode.store(Mode::Off, std::memory_order_release);
  HANDLE stopEvent = g_stopEvent;
  if (stopEvent) {
    SetEvent(stopEvent);
  }
}

void Stop(std::uint32_t timeoutMilliseconds) noexcept {
  RequestStop();

  AcquireSRWLockExclusive(&g_lifecycleLock);
  if (!g_started.load(std::memory_order_acquire)) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return;
  }
  HANDLE writerThread = g_writerThread;
  ReleaseSRWLockExclusive(&g_lifecycleLock);

  const DWORD waitResult = WaitForSingleObject(writerThread, timeoutMilliseconds);
  if (waitResult != WAIT_OBJECT_0) {
    return;
  }

  AcquireSRWLockExclusive(&g_lifecycleLock);
  CloseHandle(g_writerThread);
  CloseHandle(g_stopEvent);
  CloseHandle(g_file);
  g_writerThread = nullptr;
  g_stopEvent = nullptr;
  g_file = INVALID_HANDLE_VALUE;
  g_started.store(false, std::memory_order_release);
  ReleaseRing();
  ReleaseSRWLockExclusive(&g_lifecycleLock);
}

Mode GetMode() noexcept { return g_mode.load(std::memory_order_acquire); }

bool IsEnabled() noexcept { return GetMode() != Mode::Off; }

bool ShouldRecord(AllocationDomain domain, const void *pointer,
                  std::uint64_t size) noexcept {
  return DecideTracking(GetMode(), domain, pointer, size).tracked;
}

void RecordAlloc(void *pointer, std::uint64_t size,
                 AllocationDomain domain) noexcept {
  // Preserve the old ABI and keep profiler=off to one mode load and branch.
  if (GetMode() == Mode::Off) {
    return;
  }
  const EventMetadata metadata{};
  RecordAlloc(pointer, size, domain, metadata);
}

void RecordAlloc(void *pointer, std::uint64_t size, AllocationDomain domain,
                 const EventMetadata &metadata) noexcept {
  const Mode mode = GetMode();
  const TrackingDecision decision =
      DecideTracking(mode, domain, pointer, size);
  if (!decision.tracked || !g_accepting.load(std::memory_order_acquire)) {
    return;
  }
  if (g_recursionDepth != 0) {
    g_recursionSkips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  ScopedProducer producer;
  if (!producer.IsActive()) {
    return;
  }
  ScopedRecursionGuard recursionGuard;
  ProfileEvent event = MakeEvent(EventType::Alloc, domain, metadata, true);
  event.pointer = static_cast<std::uint64_t>(
      reinterpret_cast<std::uintptr_t>(pointer));
  event.size = size;
  if (decision.sampled) {
    event.flags |= kFlagNativeSampled;
  }
  QueueEvent(event);
}

void RecordFree(void *pointer, std::uint64_t size,
                AllocationDomain domain) noexcept {
  // Preserve the old ABI and keep profiler=off to one mode load and branch.
  if (GetMode() == Mode::Off) {
    return;
  }
  const EventMetadata metadata{};
  RecordFree(pointer, size, domain, metadata);
}

void RecordFree(void *pointer, std::uint64_t size, AllocationDomain domain,
                const EventMetadata &metadata) noexcept {
  const Mode mode = GetMode();
  const TrackingDecision decision =
      DecideTracking(mode, domain, pointer, size);
  if (!decision.tracked || !g_accepting.load(std::memory_order_acquire)) {
    return;
  }
  if (g_recursionDepth != 0) {
    g_recursionSkips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  ScopedProducer producer;
  if (!producer.IsActive()) {
    return;
  }
  ScopedRecursionGuard recursionGuard;
  ProfileEvent event = MakeEvent(EventType::Free, domain, metadata, true);
  event.pointer = static_cast<std::uint64_t>(
      reinterpret_cast<std::uintptr_t>(pointer));
  event.size = size;
  if (decision.sampled) {
    event.flags |= kFlagNativeSampled;
  }
  QueueEvent(event);
}

void RecordReallocOutcome(const ReallocOutcome &outcome) noexcept {
  const Mode mode = GetMode();
  const TrackingDecision oldDecision = DecideTracking(
      mode, outcome.domain, outcome.oldPointer, outcome.oldSize);
  const TrackingDecision newDecision = DecideTracking(
      mode, outcome.newDomain, outcome.newPointer, outcome.newSize);
  if ((!oldDecision.tracked && !newDecision.tracked) ||
      !g_accepting.load(std::memory_order_acquire)) {
    return;
  }
  if (g_recursionDepth != 0) {
    g_recursionSkips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  ScopedProducer producer;
  if (!producer.IsActive()) {
    return;
  }
  ScopedRecursionGuard recursionGuard;
  ProfileEvent event = MakeEvent(EventType::ReallocOutcome, outcome.domain,
                                 outcome.metadata, true);
  event.secondDomain = outcome.newDomain;
  event.secondMetadata = outcome.newMetadata;
  event.pointer = static_cast<std::uint64_t>(
      reinterpret_cast<std::uintptr_t>(outcome.oldPointer));
  event.secondPointer = static_cast<std::uint64_t>(
      reinterpret_cast<std::uintptr_t>(outcome.newPointer));
  event.size = outcome.oldSize;
  event.secondSize = outcome.newSize;
  event.flags = static_cast<std::uint16_t>(
      (outcome.oldFreed ? kReallocOldFreed : 0) |
      (outcome.newAllocated ? kReallocNewAllocated : 0) |
      (outcome.inPlace ? kReallocInPlace : 0) |
      (oldDecision.tracked ? kReallocOldTracked : 0) |
      (newDecision.tracked ? kReallocNewTracked : 0) |
      (oldDecision.sampled ? kReallocOldSampled : 0) |
      (newDecision.sampled ? kReallocNewSampled : 0) |
      (outcome.newDomain == AllocationDomain::Managed
           ? kReallocNewDomainManaged
           : 0));
  QueueEvent(event);
}

void RecordStormApi(const StormApiEvent &apiEvent) noexcept {
  const Mode mode = GetMode();
  if (mode == Mode::Off ||
      !g_accepting.load(std::memory_order_acquire)) {
    return;
  }

  bool sampled = false;
  bool tracked = mode == Mode::Full ||
                 apiEvent.domain == AllocationDomain::Managed;
  if (!tracked && apiEvent.primaryValue != 0) {
    const auto *pointer = reinterpret_cast<const void *>(
        static_cast<std::uintptr_t>(apiEvent.primaryValue));
    sampled =
        (PointerHash(pointer) & (kNativeSmallSampleRate - 1u)) == 0;
    tracked = sampled;
  }
  if (!tracked) {
    return;
  }
  if (g_recursionDepth != 0) {
    g_recursionSkips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  ScopedProducer producer;
  if (!producer.IsActive()) {
    return;
  }
  ScopedRecursionGuard recursionGuard;
  ProfileEvent event = MakeEvent(EventType::StormApi, apiEvent.domain,
                                 apiEvent.metadata,
                                 apiEvent.captureStack);
  event.pointer = apiEvent.primaryValue;
  event.secondPointer = apiEvent.secondaryValue;
  if (sampled) {
    event.flags |= kFlagNativeSampled;
  }
  QueueEvent(event);
}

void MarkEpoch(std::uint64_t epoch, std::uint32_t reason) noexcept {
  if (!IsEnabled() || !g_accepting.load(std::memory_order_acquire)) {
    return;
  }
  if (g_recursionDepth != 0) {
    g_recursionSkips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  ScopedProducer producer;
  if (!producer.IsActive()) {
    return;
  }
  ScopedRecursionGuard recursionGuard;
  const EventMetadata metadata{};
  ProfileEvent event = MakeEvent(EventType::EpochMarker,
                                 AllocationDomain::Native, metadata, false);
  event.epoch = epoch;
  event.reason = reason;
  QueueEvent(event);
}

void UpdateTakeoverSnapshot(const TakeoverSnapshot &snapshot) noexcept {
  std::uint64_t values[kTakeoverFieldCount]{};
  EncodeTakeoverSnapshot(snapshot, values);
  g_takeover.Publish(values);
}

TakeoverSnapshot GetTakeoverSnapshot() noexcept {
  std::uint64_t values[kTakeoverFieldCount]{};
  g_takeover.Read(values);
  return DecodeTakeoverSnapshot(values);
}

HealthSnapshot GetHealthSnapshot() noexcept {
  HealthSnapshot snapshot{};
  snapshot.mode = GetMode();
  snapshot.queueDepth = g_ring ? g_ring->Depth() : 0;
  snapshot.eventsEnqueued =
      g_eventsEnqueued.load(std::memory_order_acquire);
  snapshot.eventsWritten =
      g_eventsWritten.load(std::memory_order_acquire);
  snapshot.dropped = g_dropped.load(std::memory_order_acquire);
  snapshot.recursionSkips =
      g_recursionSkips.load(std::memory_order_acquire);
  snapshot.writeErrors = g_writeErrors.load(std::memory_order_acquire);
  snapshot.managedEvents =
      g_managedEvents.load(std::memory_order_acquire);
  snapshot.nativeEvents =
      g_nativeEvents.load(std::memory_order_acquire);
  snapshot.fallbackEvents =
      g_fallbackEvents.load(std::memory_order_acquire);
  snapshot.degradedEvents =
      g_degradedEvents.load(std::memory_order_acquire);
  snapshot.incomplete = g_incomplete.load(std::memory_order_acquire);
  snapshot.writerRunning =
      g_writerRunning.load(std::memory_order_acquire);
  snapshot.takeover = GetTakeoverSnapshot();
  return snapshot;
}

const wchar_t *GetOutputPath() noexcept { return g_outputPath; }

#if defined(STORMBREAKER_TESTING)
namespace Testing {

bool ExerciseRingSaturation(HealthSnapshot *snapshot) noexcept {
  AcquireSRWLockExclusive(&g_lifecycleLock);
  if (g_started.load(std::memory_order_acquire) || !EnsureRing()) {
    ReleaseSRWLockExclusive(&g_lifecycleLock);
    return false;
  }

  g_ring->Reset();
  g_eventsEnqueued.store(0, std::memory_order_relaxed);
  g_eventsWritten.store(0, std::memory_order_relaxed);
  g_dropped.store(0, std::memory_order_relaxed);
  g_managedEvents.store(0, std::memory_order_relaxed);
  g_nativeEvents.store(0, std::memory_order_relaxed);
  g_fallbackEvents.store(0, std::memory_order_relaxed);
  g_degradedEvents.store(0, std::memory_order_relaxed);
  g_incomplete.store(false, std::memory_order_relaxed);
  g_mode.store(Mode::Full, std::memory_order_release);
  g_accepting.store(true, std::memory_order_release);

  ProfileEvent event{};
  event.type = EventType::Alloc;
  event.domain = AllocationDomain::Managed;
  event.pointer = 0x1000;
  event.size = 64;
  for (std::size_t index = 0; index < kRingCapacity + 1; ++index) {
    event.pointer += 16;
    QueueEvent(event);
  }

  if (snapshot) {
    *snapshot = GetHealthSnapshot();
  }
  const bool saturated =
      g_dropped.load(std::memory_order_acquire) == 1 &&
      g_incomplete.load(std::memory_order_acquire) &&
      g_ring->Depth() == kRingCapacity;

  g_accepting.store(false, std::memory_order_release);
  g_mode.store(Mode::Off, std::memory_order_release);
  ReleaseRing();
  ReleaseSRWLockExclusive(&g_lifecycleLock);
  return saturated;
}

} // namespace Testing
#endif

} // namespace LeakProfiler
} // namespace StormBreaker
