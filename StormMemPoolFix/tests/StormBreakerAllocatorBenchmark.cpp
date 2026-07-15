#include "pch.h"

#include "Base/LeakProfiler.h"
#include "Base/MemorySafety.h"
#include "Storm/MemoryPool.h"
#include "Storm/StormApi.h"
#include "Storm/StormHook.h"
#include "Storm/StormTakeover.h"
#include "SegregatedArenaBenchmarkAllocator.h"
#include "rpmalloc.h"

#include <Psapi.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

constexpr const char* kStaticCallerName = "benchmark-static-caller";
constexpr uint64_t kNanosecondsPerMillisecond = 1000000ull;
constexpr uint32_t kBenchmarkHeapId = 0x8000BEEFu;

struct Options {
  std::string engine = "takeover";
  std::string backend = "hybrid";
  std::string scenario = "map-load";
  std::string profile = "quick";
  std::string callerMode = "static";
  std::string apiMode = "caller";
  std::string takeoverMode = "full";
  bool fastFree = true;
  bool registryAccounting = true;
  bool registryMembershipFilter = true;
  bool registryPredictedSlot = false;
  bool registryHazardPinning = false;
  bool mainRegistryAccounting = false;
  bool callerSlotHint = true;
  bool directCallerHash = false;
  bool directCallerByteTable = true;
  std::string recentFreeHash = "fibonacci";
  bool inPlaceReallocate = true;
  bool tlsfRangeIndex = true;
  bool detailedCounterBatching = false;
  bool poolDetailedStats = true;
  bool tlsfMainPoolDecommit = false;
  bool tlsfTopDown = false;
  bool tlsfConstantTimeEmptyCheck = true;
  uint32_t tlsfWarmEmptyPools = 0;
  bool trimAfterDrain = false;
  uint32_t callerCacheWays = 8;
  uint32_t callerThreadCacheCapacity = 256;
  uint32_t heapIdSlotHintCapacity = 0;
  bool mainHeapPin = true;
  uint32_t heapDestroyBatchSize = 0;
  bool heapDestroyTaggedSnapshot = false;
  bool spanCache = true;
  bool segregatedRemoteFree = false;
  bool segregatedLazySpan = false;
  uint32_t segregatedRemoteBatch = 0;
  uint32_t segregatedSpanKiB = 64;
  uint32_t segregatedTlsfInitialMiB = 4;
  uint32_t poolInitialMiB = 64;
  uint32_t mimallocArenaReserveMiB = 0;
  uint32_t mimallocPageFullRetain = 2;
  uint32_t mimallocPageMaxCandidates = 4;
  bool rpmallocGlobalCache = true;
  uint32_t rpmallocGlobalCacheMultiplier = 8;
  uint32_t rpmallocThreadSpanCacheLimit = 400;
  uint32_t rpmallocSpanMapCount = 32;
  uint64_t seed = 0x5B10BEEFull;
};

class Pcg32 final {
public:
  explicit Pcg32(uint64_t seed) noexcept {
    state_ = 0;
    increment_ = (seed << 1u) | 1u;
    Next();
    state_ += seed ^ 0x9E3779B97F4A7C15ull;
    Next();
  }

  uint32_t Next() noexcept {
    const uint64_t old = state_;
    state_ = old * 6364136223846793005ull + increment_;
    const uint32_t shifted = static_cast<uint32_t>(((old >> 18u) ^ old) >> 27u);
    const uint32_t rotation = static_cast<uint32_t>(old >> 59u);
    return (shifted >> rotation) | (shifted << ((0u - rotation) & 31u));
  }

  uint32_t Bounded(uint32_t bound) noexcept {
    if (bound <= 1) {
      return 0;
    }
    const uint32_t threshold = static_cast<uint32_t>(0u - bound) % bound;
    for (;;) {
      const uint32_t value = Next();
      if (value >= threshold) {
        return value % bound;
      }
    }
  }

private:
  uint64_t state_ = 0;
  uint64_t increment_ = 1;
};

uint32_t Mix32(uint32_t value) noexcept {
  value ^= value >> 16;
  value *= 0x7FEB352Du;
  value ^= value >> 15;
  value *= 0x846CA68Bu;
  value ^= value >> 16;
  return value;
}

uint64_t MixChecksum(uint64_t checksum, uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ull;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  value ^= value >> 31;
  return checksum ^ (value + (checksum << 6) + (checksum >> 2));
}

bool SetMimallocOption(const char* name, uint32_t selected) noexcept {
  char value[16]{};
  if (!name || sprintf_s(value, "%u", selected) <= 0) {
    return false;
  }
  return SetEnvironmentVariableA(name, value) != FALSE;
}

bool ConfigureMimallocOptions(const Options& options) noexcept {
  return SetMimallocOption(
             "STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB",
             options.mimallocArenaReserveMiB) &&
         SetMimallocOption(
             "STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN",
             options.mimallocPageFullRetain) &&
         SetMimallocOption(
             "STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES",
             options.mimallocPageMaxCandidates);
}

struct ProcessMemory {
  uint64_t workingSet = 0;
  uint64_t peakWorkingSet = 0;
  uint64_t privateBytes = 0;
  uint64_t commitBytes = 0;
  uint64_t occupiedVirtualBytes = 0;
  uint64_t largestFreeRegionBytes = 0;
  uint64_t freeRegionCount = 0;
};

ProcessMemory CaptureProcessMemory() noexcept {
  ProcessMemory result{};
  PROCESS_MEMORY_COUNTERS_EX counters{};
  counters.cb = sizeof(counters);
  if (GetProcessMemoryInfo(
          GetCurrentProcess(),
          reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
          sizeof(counters))) {
    result.workingSet = counters.WorkingSetSize;
    result.peakWorkingSet = counters.PeakWorkingSetSize;
    result.privateBytes = counters.PrivateUsage;
    result.commitBytes = counters.PagefileUsage;
  }

  SYSTEM_INFO systemInfo{};
  GetSystemInfo(&systemInfo);
  uintptr_t address =
      reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
  const uintptr_t maximum =
      reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);
  while (address < maximum) {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<const void*>(address), &memory,
                     sizeof(memory)) != sizeof(memory) ||
        memory.RegionSize == 0) {
      break;
    }
    if (memory.State == MEM_FREE) {
      result.largestFreeRegionBytes =
          (std::max)(result.largestFreeRegionBytes,
                     static_cast<uint64_t>(memory.RegionSize));
      ++result.freeRegionCount;
    } else {
      result.occupiedVirtualBytes += memory.RegionSize;
    }
    const uintptr_t next = address + memory.RegionSize;
    if (next <= address) {
      break;
    }
    address = next;
  }
  return result;
}

struct LatencySummary {
  uint64_t samples = 0;
  uint64_t p50Nanoseconds = 0;
  uint64_t p95Nanoseconds = 0;
  uint64_t p99Nanoseconds = 0;
  uint64_t maximumNanoseconds = 0;
  uint64_t overOneMillisecond = 0;
  uint64_t overTenMilliseconds = 0;
};

class LatencySamples final {
public:
  explicit LatencySamples(uint32_t interval) noexcept
      : interval_(interval == 0 ? 1 : interval) {}

  void Reserve(uint64_t operations) {
    values_.reserve(static_cast<size_t>(operations / interval_ + 16));
  }

  bool ShouldSample(uint64_t operation) const noexcept {
    return operation % interval_ == 0;
  }

  template <typename Function>
  auto Measure(uint64_t operation, Function&& function) {
    if (!ShouldSample(operation)) {
      return function();
    }
    const auto start = Clock::now();
    auto result = function();
    const uint64_t nanoseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - start).count());
    values_.push_back(nanoseconds);
    return result;
  }

  void Merge(const LatencySamples& other) {
    if (this == &other) {
      return;
    }
    values_.insert(values_.end(), other.values_.begin(), other.values_.end());
  }

  LatencySummary Summarize() {
    LatencySummary result{};
    if (values_.empty()) {
      return result;
    }
    std::sort(values_.begin(), values_.end());
    const auto percentile = [&](uint32_t numerator) {
      const size_t index = static_cast<size_t>(
          ((static_cast<uint64_t>(values_.size()) * numerator + 99u) / 100u) -
          1u);
      return values_[(std::min)(index, values_.size() - 1u)];
    };
    result.samples = values_.size();
    result.p50Nanoseconds = percentile(50);
    result.p95Nanoseconds = percentile(95);
    result.p99Nanoseconds = percentile(99);
    result.maximumNanoseconds = values_.back();
    for (uint64_t value : values_) {
      result.overOneMillisecond += value >= kNanosecondsPerMillisecond ? 1 : 0;
      result.overTenMilliseconds +=
          value >= 10u * kNanosecondsPerMillisecond ? 1 : 0;
    }
    return result;
  }

private:
  uint32_t interval_ = 1;
  std::vector<uint64_t> values_;
};

struct LiveBlock {
  void* pointer = nullptr;
  uint32_t size = 0;
  uint32_t caller = 0;
  uint8_t pattern = 0;
};

struct RunResult {
  bool valid = true;
  uint64_t traceOperations = 0;
  uint64_t totalOperations = 0;
  uint64_t failures = 0;
  uint64_t wallNanoseconds = 0;
  uint64_t trimNanoseconds = 0;
  uint64_t checksum = 0xCBF29CE484222325ull;
  uint64_t peakLiveBlocks = 0;
  uint64_t peakLiveRequestedBytes = 0;
  ProcessMemory before{};
  ProcessMemory peak{};
  ProcessMemory after{};
  LatencySummary latency{};
  MemoryPool::ExtendedPoolStats pool{};
  StormTakeover::RuntimeStats takeover{};
  StormTakeover::Testing::InPlaceReallocateStats inPlaceReallocate{};
  StormHeapRegistry::RegistryStats registry{};
};

void TouchBlock(const LiveBlock& block) noexcept {
  if (!block.pointer || block.size == 0) {
    return;
  }
  auto* bytes = static_cast<uint8_t*>(block.pointer);
  bytes[0] = block.pattern;
  bytes[block.size - 1u] = static_cast<uint8_t>(block.pattern ^ 0xA5u);
}

bool ValidateBlock(const LiveBlock& block) noexcept {
  if (!block.pointer || block.size == 0) {
    return block.pointer != nullptr;
  }
  const auto* bytes = static_cast<const uint8_t*>(block.pointer);
  return bytes[0] == block.pattern &&
         bytes[block.size - 1u] == static_cast<uint8_t>(block.pattern ^ 0xA5u);
}

uint32_t MapLoadSize(Pcg32& random) noexcept {
  const uint32_t bucket = random.Bounded(10000);
  if (bucket < 6000) {
    return 8u + random.Bounded(57u);
  }
  if (bucket < 8500) {
    return 65u + random.Bounded(192u);
  }
  if (bucket < 9700) {
    return 257u + random.Bounded(768u);
  }
  if (bucket < 9980) {
    return 1025u + random.Bounded(7168u);
  }
  if (bucket < 9999) {
    return 8193u + random.Bounded(57344u);
  }
  return 65536u + random.Bounded(983041u);
}

uint32_t HotCallerId(uint64_t operation, uint64_t seed) noexcept {
  constexpr uint32_t kHotCallerCount = 32u;
  constexpr uint32_t kCallerCount = 4096u;
  const uint32_t foldedOperation = static_cast<uint32_t>(operation) ^
                                   static_cast<uint32_t>(operation >> 32u);
  const uint32_t hash = Mix32(foldedOperation ^ static_cast<uint32_t>(seed) ^
                              static_cast<uint32_t>(seed >> 32u));
  if (hash % 10u != 0u) {
    return 1u + Mix32(hash ^ 0x484F5453u) % kHotCallerCount;
  }
  return kHotCallerCount + 1u +
         Mix32(hash ^ 0x5441494Cu) % (kCallerCount - kHotCallerCount);
}

uint32_t EditorSize(Pcg32& random) noexcept {
  const uint32_t selector = random.Bounded(100);
  if (selector < 65) {
    return 64u * 1024u + random.Bounded(192u * 1024u);
  }
  if (selector < 95) {
    return 256u * 1024u + random.Bounded(768u * 1024u);
  }
  return 1024u * 1024u + random.Bounded(3u * 1024u * 1024u);
}

struct alignas(8) MockNativeHeader {
  uint32_t requestedSize;
  uint32_t cookie;
  uint32_t stormFlags;
  uint32_t reserved;
};

static_assert(sizeof(MockNativeHeader) == 16);
constexpr uint32_t kMockNativeCookie = 0x53424E41u;

MockNativeHeader* MockNativeHeaderFromUser(const void* pointer) noexcept {
  return pointer ? const_cast<MockNativeHeader*>(
                       static_cast<const MockNativeHeader*>(pointer) - 1)
                 : nullptr;
}

void* __fastcall MockAlloc(int, int, uint32_t size, const char*, int32_t,
                            uint32_t flags) {
  const size_t physicalSize = size == 0 ? 1u : size;
  auto* header = static_cast<MockNativeHeader*>(HeapAlloc(
      GetProcessHeap(),
      (flags & StormApi::kFlagZeroMemory) != 0 ? HEAP_ZERO_MEMORY : 0,
      sizeof(MockNativeHeader) + physicalSize));
  if (!header) {
    return nullptr;
  }
  header->requestedSize = size;
  header->cookie = kMockNativeCookie;
  // QueryNativeLarge checks user[-5] bit 3. Keep it clear for the native
  // small-block path represented by this mock.
  header->stormFlags = 0;
  header->reserved = 0;
  return header + 1;
}

int __stdcall MockFree(void* pointer, const char*, int32_t, uint32_t) {
  if (!pointer) {
    return 1;
  }
  MockNativeHeader* header = MockNativeHeaderFromUser(pointer);
  return header->cookie == kMockNativeCookie &&
                 HeapFree(GetProcessHeap(), 0, header)
             ? 1
             : 0;
}

int __stdcall MockGetSize(const void* pointer, const char*, int32_t) {
  const MockNativeHeader* header = MockNativeHeaderFromUser(pointer);
  if (!header || header->cookie != kMockNativeCookie ||
      header->requestedSize > INT_MAX) {
    return -1;
  }
  return static_cast<int>(header->requestedSize);
}

void* __fastcall MockReAlloc(int, int, void* pointer, uint32_t newSize,
                             const char*, int32_t, uint32_t flags) {
  if (!pointer) {
    return MockAlloc(0, 0, newSize, nullptr, 0, flags);
  }
  if (newSize == 0) {
    MockFree(pointer, nullptr, 0, flags);
    return nullptr;
  }
  MockNativeHeader* oldHeader = MockNativeHeaderFromUser(pointer);
  if (!oldHeader || oldHeader->cookie != kMockNativeCookie) {
    return nullptr;
  }
  auto* newHeader = static_cast<MockNativeHeader*>(HeapReAlloc(
      GetProcessHeap(),
      (flags & StormApi::kFlagZeroMemory) != 0 ? HEAP_ZERO_MEMORY : 0,
      oldHeader, sizeof(MockNativeHeader) + newSize));
  if (!newHeader) {
    return nullptr;
  }
  newHeader->requestedSize = newSize;
  newHeader->cookie = kMockNativeCookie;
  newHeader->stormFlags = 0;
  newHeader->reserved = 0;
  return newHeader + 1;
}

uint32_t __stdcall MockGetHeapByCaller(const char* sourceFile,
                                       int32_t sourceLine) {
  return StormTakeover::Testing::ComputeDirectCallerHeap(sourceFile,
                                                          sourceLine);
}

uint32_t __stdcall MockGetHeapByPtr(const void*) { return 1u; }

int __stdcall MockHeapDestroy(uint32_t) { return 1; }

StormApi::ResolvedApi MakeMockApi() noexcept {
  StormApi::ResolvedApi api{};
  api.alloc = &MockAlloc;
  api.free = &MockFree;
  api.getSize = &MockGetSize;
  api.reAlloc = &MockReAlloc;
  api.getHeapByCaller = &MockGetHeapByCaller;
  api.getHeapByPtr = &MockGetHeapByPtr;
  api.heapDestroy = &MockHeapDestroy;
  return api;
}

class NativeStormEngine final {
public:
  bool Initialize(const Options&) noexcept { return true; }
  bool Shutdown(RunResult&) noexcept { return true; }

  void* Allocate(uint32_t size, const char* caller, int32_t line,
                 uint32_t flags) const noexcept {
    return MockAlloc(0, 0, size, caller, line, flags);
  }

  bool Free(void* pointer, const char* caller, int32_t line,
            uint32_t flags) const noexcept {
    return MockFree(pointer, caller, line, flags) != 0;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) const noexcept {
    return MockReAlloc(0, 0, pointer, newSize, caller, line, flags);
  }
};

class LegacyLargeEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    if (!SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND",
                                 options.backend.c_str()) ||
        !SetEnvironmentVariableA("STORMBREAKER_PROFILER", "off") ||
        !ConfigureMimallocOptions(options)) {
      return false;
    }
    MemoryPool::SetLatencyTrackingEnabled(false);
    MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(
        options.tlsfRangeIndex);
    MemoryPool::Config poolConfig = MemoryPool::GetConfig();
    poolConfig.initialSize =
        static_cast<size_t>(options.poolInitialMiB) * 1024u * 1024u;
    poolConfig.enableStats = options.poolDetailedStats;
    if (!MemoryPool::SetConfig(poolConfig)) {
      return false;
    }

    MemorySafetyConfig safety = MemorySafety::GetDefaultConfig();
    safety.enableTracking = false;
    safety.enableValidation = false;
    safety.enableDeferredFree = false;
    safety.enableLeakDetection = false;
    safety.enableCorruptionDetection = false;
    if (!MemorySafety::GetInstance().Initialize(safety)) {
      return false;
    }
    StormHook::SetRuntimeStatsEnabled(false);
    StormHook::Testing::SetMinimalLargeHookPathEnabled(true);
    if (!StormHook::Initialize()) {
      StormHook::Testing::SetMinimalLargeHookPathEnabled(false);
      MemorySafety::GetInstance().Shutdown();
      return false;
    }

    g_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(&MockAlloc);
    g_origStormFree = reinterpret_cast<Storm_MemFree_t>(&MockFree);
    g_origStormGetSize = reinterpret_cast<Storm_MemGetSize_t>(&MockGetSize);
    g_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(&MockReAlloc);
    initialized_ = true;
    return true;
  }

  bool Shutdown(RunResult& result) noexcept {
    if (!initialized_) {
      return false;
    }
    result.pool = MemoryPool::GetExtendedStats();
    const bool drained = StormHook::GetManagedBlockCount() == 0 &&
                         result.pool.requestedLiveBytes == 0 &&
                         result.pool.usableLiveBytes == 0;
    g_origStormAlloc = nullptr;
    g_origStormFree = nullptr;
    g_origStormGetSize = nullptr;
    g_origStormReAlloc = nullptr;
    StormHook::Testing::SetMinimalLargeHookPathEnabled(false);
    StormHook::Shutdown();
    MemorySafety::GetInstance().Shutdown();
    MemoryPool::Shutdown();
    initialized_ = false;
    return drained && !MemoryPool::IsInitialized();
  }

  void* Allocate(uint32_t size, const char* caller, int32_t line,
                 uint32_t flags) const noexcept {
    return Hooked_Storm_MemAlloc(0, 0, size, caller, line, flags);
  }

  bool Free(void* pointer, const char* caller, int32_t line,
            uint32_t flags) const noexcept {
    return Hooked_Storm_MemFree(pointer, caller, line, flags) != 0;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) const noexcept {
    return Hooked_Storm_MemReAlloc(
        0, 0, pointer, newSize, caller, line, flags);
  }

private:
  bool initialized_ = false;
};

class WinHeapEngine final {
public:
  bool Initialize(const Options&) noexcept { return true; }
  bool Shutdown(RunResult&) noexcept { return true; }

  void* Allocate(uint32_t size, const char* caller, int32_t line,
                 uint32_t flags) const noexcept {
    return MockAlloc(0, 0, size, caller, line, flags);
  }

  bool Free(void* pointer, const char* caller, int32_t line,
            uint32_t flags) const noexcept {
    return MockFree(pointer, caller, line, flags) != 0;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) const noexcept {
    return MockReAlloc(0, 0, pointer, newSize, caller, line, flags);
  }
};

class PrivateHeapEngine final {
public:
  bool Initialize(const Options&) noexcept {
    heap_ = HeapCreate(0, 0, 0);
    if (!heap_) {
      return false;
    }
    ULONG compatibility = 2;
    if (!HeapSetInformation(heap_, HeapCompatibilityInformation,
                            &compatibility, sizeof(compatibility))) {
      HeapDestroy(heap_);
      heap_ = nullptr;
      return false;
    }
    liveBlocks_.store(0, std::memory_order_relaxed);
    return true;
  }

  bool Shutdown(RunResult&) noexcept {
    const bool drained =
        liveBlocks_.load(std::memory_order_relaxed) == 0;
    const bool destroyed = heap_ && HeapDestroy(heap_) != FALSE;
    heap_ = nullptr;
    return drained && destroyed;
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) noexcept {
    if (!heap_) {
      return nullptr;
    }
    void* pointer = HeapAlloc(
        heap_, (flags & StormApi::kFlagZeroMemory) != 0
                   ? HEAP_ZERO_MEMORY
                   : 0,
        size == 0 ? 1u : size);
    if (pointer) {
      liveBlocks_.fetch_add(1, std::memory_order_relaxed);
    }
    return pointer;
  }

  bool Free(void* pointer, const char*, int32_t,
            uint32_t) noexcept {
    if (!pointer) {
      return true;
    }
    if (!heap_ || !HeapFree(heap_, 0, pointer)) {
      return false;
    }
    liveBlocks_.fetch_sub(1, std::memory_order_relaxed);
    return true;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) noexcept {
    if (!pointer) {
      return Allocate(newSize, caller, line, flags);
    }
    if (newSize == 0) {
      Free(pointer, caller, line, flags);
      return nullptr;
    }
    return heap_
               ? HeapReAlloc(
                     heap_, (flags & StormApi::kFlagZeroMemory) != 0
                                ? HEAP_ZERO_MEMORY
                                : 0,
                     pointer, newSize)
               : nullptr;
  }

private:
  HANDLE heap_ = nullptr;
  std::atomic<uint64_t> liveBlocks_{0};
};

class RpmallocEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    rpmalloc_config_t config{};
    config.span_size = 64u * 1024u;
    config.span_map_count = options.rpmallocSpanMapCount;
    config.enable_huge_pages = 0;
    if (rpmalloc_set_global_cache_multiplier(
            options.rpmallocGlobalCache
                ? options.rpmallocGlobalCacheMultiplier
                : 0u) != 0 ||
        rpmalloc_set_thread_span_cache_limit(
            options.rpmallocThreadSpanCacheLimit) != 0) {
      return false;
    }
    if (rpmalloc_initialize_config(&config) != 0) {
      return false;
    }
    heap_ = rpmalloc_heap_acquire();
    if (!heap_) {
      rpmalloc_finalize();
      return false;
    }
    liveBlocks_.store(0, std::memory_order_relaxed);
    initialized_ = true;
    return true;
  }

  bool Shutdown(RunResult&) noexcept {
    if (!initialized_) {
      return false;
    }
    const bool drained =
        liveBlocks_.load(std::memory_order_relaxed) == 0;
    {
      std::lock_guard<std::mutex> lock(lock_);
      rpmalloc_heap_free_all(heap_);
      rpmalloc_heap_release(heap_);
      heap_ = nullptr;
    }
    rpmalloc_finalize();
    initialized_ = false;
    return drained;
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) noexcept {
    if (!initialized_ || !heap_) {
      return nullptr;
    }
    const size_t physicalSize = size == 0 ? 1u : size;
    std::lock_guard<std::mutex> lock(lock_);
    void* pointer = (flags & StormApi::kFlagZeroMemory) != 0
                        ? rpmalloc_heap_calloc(heap_, 1, physicalSize)
                        : rpmalloc_heap_alloc(heap_, physicalSize);
    if (pointer) {
      liveBlocks_.fetch_add(1, std::memory_order_relaxed);
    }
    return pointer;
  }

  bool Free(void* pointer, const char*, int32_t,
            uint32_t) noexcept {
    if (!pointer) {
      return true;
    }
    std::lock_guard<std::mutex> lock(lock_);
    rpmalloc_heap_free(heap_, pointer);
    liveBlocks_.fetch_sub(1, std::memory_order_relaxed);
    return true;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) noexcept {
    if (!pointer) {
      return Allocate(newSize, caller, line, flags);
    }
    if (newSize == 0) {
      Free(pointer, caller, line, flags);
      return nullptr;
    }
    std::lock_guard<std::mutex> lock(lock_);
    const size_t oldUsable = rpmalloc_usable_size(pointer);
    void* replacement = rpmalloc_heap_realloc(heap_, pointer, newSize, 0);
    if (replacement && (flags & StormApi::kFlagZeroMemory) != 0 &&
        newSize > oldUsable) {
      std::memset(static_cast<uint8_t*>(replacement) + oldUsable, 0,
                  newSize - oldUsable);
    }
    return replacement;
  }

private:
  bool initialized_ = false;
  rpmalloc_heap_t* heap_ = nullptr;
  std::mutex lock_;
  std::atomic<uint64_t> liveBlocks_{0};
};

class RpmallocThreadedEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    rpmalloc_config_t config{};
    config.span_size = 64u * 1024u;
    config.span_map_count = options.rpmallocSpanMapCount;
    config.enable_huge_pages = 0;
    if (rpmalloc_set_global_cache_multiplier(
            options.rpmallocGlobalCache
                ? options.rpmallocGlobalCacheMultiplier
                : 0u) != 0 ||
        rpmalloc_set_thread_span_cache_limit(
            options.rpmallocThreadSpanCacheLimit) != 0) {
      return false;
    }
    if (rpmalloc_initialize_config(&config) != 0) {
      return false;
    }
    liveBlocks_.store(0, std::memory_order_relaxed);
    initialized_.store(true, std::memory_order_release);
    return true;
  }

  bool Shutdown(RunResult&) noexcept {
    if (!initialized_.exchange(false, std::memory_order_acq_rel)) {
      return false;
    }
    const bool drained =
        liveBlocks_.load(std::memory_order_relaxed) == 0;
    rpmalloc_finalize();
    return drained;
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) noexcept {
    if (!EnsureThreadHeap()) {
      return nullptr;
    }
    const size_t physicalSize = size == 0 ? 1u : size;
    void* pointer = (flags & StormApi::kFlagZeroMemory) != 0
                        ? rpcalloc(1, physicalSize)
                        : rpmalloc(physicalSize);
    if (pointer) {
      liveBlocks_.fetch_add(1, std::memory_order_relaxed);
    }
    return pointer;
  }

  bool Free(void* pointer, const char*, int32_t, uint32_t) noexcept {
    if (!pointer) {
      return true;
    }
    if (!initialized_.load(std::memory_order_acquire)) {
      return false;
    }
    rpfree(pointer);
    liveBlocks_.fetch_sub(1, std::memory_order_relaxed);
    return true;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) noexcept {
    if (!pointer) {
      return Allocate(newSize, caller, line, flags);
    }
    if (newSize == 0) {
      Free(pointer, caller, line, flags);
      return nullptr;
    }
    if (!EnsureThreadHeap()) {
      return nullptr;
    }
    const size_t oldUsable = rpmalloc_usable_size(pointer);
    void* replacement = rprealloc(pointer, newSize);
    if (replacement && (flags & StormApi::kFlagZeroMemory) != 0 &&
        newSize > oldUsable) {
      std::memset(static_cast<uint8_t*>(replacement) + oldUsable, 0,
                  newSize - oldUsable);
    }
    return replacement;
  }

private:
  bool EnsureThreadHeap() const noexcept {
    if (!initialized_.load(std::memory_order_acquire)) {
      return false;
    }
    if (!rpmalloc_is_thread_initialized()) {
      rpmalloc_thread_initialize();
    }
    return rpmalloc_is_thread_initialized() != 0;
  }

  std::atomic<bool> initialized_{false};
  std::atomic<uint64_t> liveBlocks_{0};
};

class SegregatedArenaEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    return allocator_.Initialize(options.spanCache,
                                 options.segregatedSpanKiB,
                                 options.segregatedRemoteFree,
                                 options.segregatedLazySpan,
                                 options.segregatedRemoteBatch);
  }

  bool Shutdown(RunResult&) noexcept {
    return allocator_.Shutdown();
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) noexcept {
    return allocator_.Allocate(
        size, (flags & StormApi::kFlagZeroMemory) != 0);
  }

  bool Free(void* pointer, const char*, int32_t,
            uint32_t) noexcept {
    return allocator_.Free(pointer);
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char*,
                   int32_t, uint32_t flags) noexcept {
    return allocator_.Reallocate(
        pointer, newSize, (flags & StormApi::kFlagZeroMemory) != 0);
  }

private:
  StormBreaker::Benchmark::SegregatedArenaAllocator allocator_{};
};

struct alignas(16) PoolBenchmarkHeader {
  uint32_t requestedSize = 0;
  uint32_t route = 0;
  uint32_t cookie = 0;
  uint32_t reserved = 0;
};

static_assert(sizeof(PoolBenchmarkHeader) == 16);

uint32_t PoolHeaderCookie(const PoolBenchmarkHeader* header,
                          uint32_t requestedSize,
                          MemoryPool::BackendRoute route) noexcept {
  return Mix32(static_cast<uint32_t>(
                   reinterpret_cast<uintptr_t>(header)) ^
               requestedSize ^
               (static_cast<uint32_t>(route) * 0x9E3779B9u) ^
               0x504F4F4Cu);
}

bool DecodePoolHeader(void* pointer, PoolBenchmarkHeader** output,
                      MemoryPool::BackendRoute* route) noexcept {
  if (!pointer || !output || !route) {
    return false;
  }
  auto* header = static_cast<PoolBenchmarkHeader*>(pointer) - 1;
  const auto decodedRoute =
      static_cast<MemoryPool::BackendRoute>(header->route);
  if ((decodedRoute != MemoryPool::BackendRoute::Tlsf &&
       decodedRoute != MemoryPool::BackendRoute::Mimalloc) ||
      header->cookie !=
          PoolHeaderCookie(header, header->requestedSize, decodedRoute)) {
    return false;
  }
  *output = header;
  *route = decodedRoute;
  return true;
}

class PoolEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    if (!SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND",
                                 options.backend.c_str()) ||
        !SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE",
                                 options.takeoverMode.c_str()) ||
        !ConfigureMimallocOptions(options)) {
      return false;
    }
    MemoryPool::SetLatencyTrackingEnabled(false);
    MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(
        options.tlsfRangeIndex);
    MemoryPool::Config poolConfig = MemoryPool::GetConfig();
    poolConfig.initialSize =
        static_cast<size_t>(options.poolInitialMiB) * 1024u * 1024u;
    poolConfig.enableStats = options.poolDetailedStats;
    if (!MemoryPool::SetConfig(poolConfig)) {
      return false;
    }
    initialized_ = MemoryPool::Initialize();
    inPlaceReallocate_ = options.inPlaceReallocate;
    return initialized_;
  }

  bool Shutdown(RunResult& result) noexcept {
    if (!initialized_) {
      return false;
    }
    result.pool = MemoryPool::GetExtendedStats();
    const bool drained = result.pool.requestedLiveBytes == 0 &&
                         result.pool.usableLiveBytes == 0;
    MemoryPool::Shutdown();
    initialized_ = false;
    return drained && !MemoryPool::IsInitialized();
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) const noexcept {
    if (size > UINT32_MAX - sizeof(PoolBenchmarkHeader)) {
      return nullptr;
    }
    const auto allocation = MemoryPool::AllocateRouted(
        sizeof(PoolBenchmarkHeader) + size, size, 16,
        MemoryPool::BackendRoute::Automatic);
    if (!allocation.pointer) {
      return nullptr;
    }
    auto* header = static_cast<PoolBenchmarkHeader*>(allocation.pointer);
    header->requestedSize = size;
    header->route = static_cast<uint32_t>(allocation.route);
    header->cookie = PoolHeaderCookie(header, size, allocation.route);
    header->reserved = 0;
    void* user = header + 1;
    if ((flags & StormApi::kFlagZeroMemory) != 0 && size != 0) {
      std::memset(user, 0, size);
    }
    return user;
  }

  bool Free(void* pointer, const char*, int32_t,
            uint32_t) const noexcept {
    if (!pointer) {
      return true;
    }
    PoolBenchmarkHeader* header = nullptr;
    MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
    if (!DecodePoolHeader(pointer, &header, &route)) {
      return false;
    }
    return MemoryPool::FreeRouted(
        header, header->requestedSize, route, nullptr);
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) const noexcept {
    if (!pointer) {
      return Allocate(newSize, caller, line, flags);
    }
    if (newSize == 0) {
      Free(pointer, caller, line, flags);
      return nullptr;
    }
    PoolBenchmarkHeader* header = nullptr;
    MemoryPool::BackendRoute oldRoute =
        MemoryPool::BackendRoute::Automatic;
    if (!DecodePoolHeader(pointer, &header, &oldRoute)) {
      return nullptr;
    }
    const uint32_t oldSize = header->requestedSize;
    const MemoryPool::BackendRoute newRoute =
        MemoryPool::SelectRoute(newSize);
    if (inPlaceReallocate_ && newRoute == oldRoute) {
      size_t usableSize = 0;
      const auto status = MemoryPool::ReallocateInPlaceRouted(
          header, oldSize, sizeof(PoolBenchmarkHeader) + newSize, newSize,
          oldRoute, &usableSize);
      if (status == MemoryPool::InPlaceReallocateStatus::Succeeded) {
        header->requestedSize = newSize;
        header->route = static_cast<uint32_t>(oldRoute);
        header->cookie = PoolHeaderCookie(header, newSize, oldRoute);
        void* user = header + 1;
        if ((flags & StormApi::kFlagZeroMemory) != 0 && newSize > oldSize) {
          std::memset(static_cast<uint8_t*>(user) + oldSize, 0,
                      newSize - oldSize);
        }
        return user;
      }
    }

    void* replacement = Allocate(newSize, caller, line, flags);
    if (!replacement) {
      return nullptr;
    }
    std::memcpy(replacement, pointer, (std::min)(oldSize, newSize));
    if (!Free(pointer, caller, line, flags)) {
      Free(replacement, caller, line, flags);
      return nullptr;
    }
    return replacement;
  }

private:
  bool initialized_ = false;
  bool inPlaceReallocate_ = true;
};

class SegregatedHybridEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    if (!SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf") ||
        !SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE", "full")) {
      return false;
    }
    MemoryPool::SetLatencyTrackingEnabled(false);
    MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(
        options.tlsfRangeIndex);
    MemoryPool::Config poolConfig = MemoryPool::GetConfig();
    poolConfig.initialSize =
        static_cast<size_t>(options.segregatedTlsfInitialMiB) * 1024u * 1024u;
    poolConfig.enableStats = options.poolDetailedStats;
    if (!MemoryPool::SetConfig(poolConfig)) {
      return false;
    }
    if (!MemoryPool::Initialize()) {
      return false;
    }
    if (!small_.Initialize(options.spanCache,
                           options.segregatedSpanKiB,
                           options.segregatedRemoteFree,
                           options.segregatedLazySpan,
                           options.segregatedRemoteBatch)) {
      MemoryPool::Shutdown();
      return false;
    }
    initialized_ = true;
    return true;
  }

  bool Shutdown(RunResult& result) noexcept {
    if (!initialized_) {
      return false;
    }
    result.pool = MemoryPool::GetExtendedStats();
    const bool poolDrained = result.pool.requestedLiveBytes == 0 &&
                             result.pool.usableLiveBytes == 0;
    const bool smallDrained = small_.Shutdown();
    MemoryPool::Shutdown();
    initialized_ = false;
    return poolDrained && smallDrained && !MemoryPool::IsInitialized();
  }

  void* Allocate(uint32_t size, const char*, int32_t,
                 uint32_t flags) noexcept {
    if (size > UINT32_MAX - sizeof(PoolBenchmarkHeader)) {
      return nullptr;
    }
    const size_t physicalSize = sizeof(PoolBenchmarkHeader) + size;
    const MemoryPool::BackendRoute route = RouteFor(size);
    void* raw = nullptr;
    if (route == MemoryPool::BackendRoute::Mimalloc) {
      raw = small_.Allocate(static_cast<uint32_t>(physicalSize), false);
    } else {
      raw = MemoryPool::AllocateRouted(
                physicalSize, size, 16, MemoryPool::BackendRoute::Tlsf)
                .pointer;
    }
    if (!raw) {
      return nullptr;
    }
    auto* header = static_cast<PoolBenchmarkHeader*>(raw);
    WriteHeader(header, size, route);
    void* user = header + 1;
    if ((flags & StormApi::kFlagZeroMemory) != 0 && size != 0) {
      std::memset(user, 0, size);
    }
    return user;
  }

  bool Free(void* pointer, const char*, int32_t, uint32_t) noexcept {
    if (!pointer) {
      return true;
    }
    PoolBenchmarkHeader* header = nullptr;
    MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
    if (!DecodePoolHeader(pointer, &header, &route)) {
      return false;
    }
    return route == MemoryPool::BackendRoute::Mimalloc
               ? small_.Free(header)
               : MemoryPool::FreeRouted(header, header->requestedSize,
                                        MemoryPool::BackendRoute::Tlsf,
                                        nullptr);
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) noexcept {
    if (!pointer) {
      return Allocate(newSize, caller, line, flags);
    }
    if (newSize == 0) {
      Free(pointer, caller, line, flags);
      return nullptr;
    }
    PoolBenchmarkHeader* header = nullptr;
    MemoryPool::BackendRoute oldRoute = MemoryPool::BackendRoute::Automatic;
    if (!DecodePoolHeader(pointer, &header, &oldRoute)) {
      return nullptr;
    }
    const uint32_t oldSize = header->requestedSize;
    const MemoryPool::BackendRoute newRoute = RouteFor(newSize);
    if (newRoute == oldRoute) {
      PoolBenchmarkHeader* updated = nullptr;
      if (oldRoute == MemoryPool::BackendRoute::Mimalloc) {
        updated = static_cast<PoolBenchmarkHeader*>(small_.Reallocate(
            header,
            static_cast<uint32_t>(sizeof(PoolBenchmarkHeader) + newSize),
            false));
      } else {
        size_t usableSize = 0;
        const auto status = MemoryPool::ReallocateInPlaceRouted(
            header, oldSize, sizeof(PoolBenchmarkHeader) + newSize, newSize,
            MemoryPool::BackendRoute::Tlsf, &usableSize);
        if (status == MemoryPool::InPlaceReallocateStatus::Succeeded) {
          updated = header;
        }
      }
      if (updated) {
        WriteHeader(updated, newSize, newRoute);
        void* user = updated + 1;
        if ((flags & StormApi::kFlagZeroMemory) != 0 && newSize > oldSize) {
          std::memset(static_cast<uint8_t*>(user) + oldSize, 0,
                      newSize - oldSize);
        }
        return user;
      }
    }

    void* replacement = Allocate(newSize, caller, line, 0);
    if (!replacement) {
      return nullptr;
    }
    std::memcpy(replacement, pointer, (std::min)(oldSize, newSize));
    if ((flags & StormApi::kFlagZeroMemory) != 0 && newSize > oldSize) {
      std::memset(static_cast<uint8_t*>(replacement) + oldSize, 0,
                  newSize - oldSize);
    }
    if (!Free(pointer, caller, line, flags)) {
      Free(replacement, caller, line, 0);
      return nullptr;
    }
    return replacement;
  }

private:
  static constexpr uint32_t kSmallMaximum =
      32768u - sizeof(PoolBenchmarkHeader);

  static MemoryPool::BackendRoute RouteFor(uint32_t size) noexcept {
    return size <= kSmallMaximum
               ? MemoryPool::BackendRoute::Mimalloc
               : MemoryPool::BackendRoute::Tlsf;
  }

  static void WriteHeader(PoolBenchmarkHeader* header, uint32_t size,
                          MemoryPool::BackendRoute route) noexcept {
    header->requestedSize = size;
    header->route = static_cast<uint32_t>(route);
    header->cookie = PoolHeaderCookie(header, size, route);
    header->reserved = 0;
  }

  bool initialized_ = false;
  StormBreaker::Benchmark::SegregatedArenaAllocator small_{};
};

class TakeoverEngine final {
public:
  bool Initialize(const Options& options) noexcept {
    if (!SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND",
                                 options.backend.c_str()) ||
        !SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE",
                                 options.takeoverMode.c_str()) ||
        !SetEnvironmentVariableA("STORMBREAKER_PROFILER", "off") ||
        !SetEnvironmentVariableA("STORMBREAKER_TELEMETRY", "0") ||
        !ConfigureMimallocOptions(options)) {
      return false;
    }
    MemoryPool::SetLatencyTrackingEnabled(false);
    MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(
        options.tlsfRangeIndex);
    MemoryPool::Config poolConfig = MemoryPool::GetConfig();
    poolConfig.initialSize =
        static_cast<size_t>(options.poolInitialMiB) * 1024u * 1024u;
    poolConfig.enableStats = options.poolDetailedStats;
    if (!MemoryPool::SetConfig(poolConfig)) {
      return false;
    }
    if (!MemoryPool::Initialize()) {
      return false;
    }
    if (!StormTakeover::Initialize()) {
      MemoryPool::Shutdown();
      return false;
    }
    api_ = MakeMockApi();
    StormTakeover::Testing::SetNativeApi(&api_);
    StormTakeover::Testing::SetFastFreeEnabled(options.fastFree);
    StormTakeover::Testing::SetRegistryAccountingEnabled(
        options.registryAccounting);
    StormTakeover::Testing::SetMainRegistryAccountingEnabled(
        options.mainRegistryAccounting);
    StormTakeover::Testing::SetCallerSlotHintEnabled(options.callerSlotHint);
    StormTakeover::Testing::SetDirectCallerHashEnabled(
        options.directCallerHash);
    StormTakeover::Testing::SetDirectCallerByteTableEnabled(
        options.directCallerByteTable);
    StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(
        options.recentFreeHash == "fibonacci");
    StormTakeover::Testing::SetCallerCacheWays(options.callerCacheWays);
    StormTakeover::Testing::SetCallerThreadCacheCapacity(
        options.callerThreadCacheCapacity);
    StormTakeover::Testing::SetHeapIdSlotHintCapacity(
        options.heapIdSlotHintCapacity);
    StormTakeover::Testing::SetMainHeapPinEnabled(options.mainHeapPin);
    StormTakeover::Testing::SetInPlaceReallocateEnabled(
        options.inPlaceReallocate);
    StormTakeover::Testing::SetHeapDestroyBatchSize(
        options.heapDestroyBatchSize);
    StormTakeover::Testing::SetHeapDestroyTaggedSnapshotEnabled(
        options.heapDestroyTaggedSnapshot);
    heapApi_ = options.apiMode == "heap";
    if (heapApi_ && !StormTakeover::Testing::RegisterManagedHeap(
                        kBenchmarkHeapId, true, "benchmark-fixed-heap", 1)) {
      StormTakeover::Testing::SetNativeApi(nullptr);
      StormTakeover::Shutdown();
      MemoryPool::Shutdown();
      return false;
    }
    initialized_ = true;
    return true;
  }

  bool Shutdown(RunResult& result) noexcept {
    if (!initialized_) {
      return false;
    }
    result.pool = MemoryPool::GetExtendedStats();
    result.takeover = StormTakeover::GetRuntimeStats();
    result.inPlaceReallocate =
        StormTakeover::Testing::GetInPlaceReallocateStats();
    result.registry = StormTakeover::GetRegistryStats();
    const bool drained = result.pool.requestedLiveBytes == 0 &&
                         result.pool.usableLiveBytes == 0 &&
                         result.takeover.liveBlocks == 0;
    StormTakeover::Testing::SetNativeApi(nullptr);
    StormTakeover::Testing::SetFastFreeEnabled(true);
    StormTakeover::Testing::SetRegistryAccountingEnabled(true);
    StormTakeover::Testing::SetMainRegistryAccountingEnabled(false);
    StormTakeover::Testing::SetCallerSlotHintEnabled(true);
    StormTakeover::Testing::SetDirectCallerByteTableEnabled(true);
    StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(true);
    StormTakeover::Testing::SetCallerCacheWays(8);
    StormTakeover::Testing::SetCallerThreadCacheCapacity(256);
    StormTakeover::Testing::SetHeapIdSlotHintCapacity(0);
    StormTakeover::Testing::SetMainHeapPinEnabled(true);
    StormTakeover::Testing::SetInPlaceReallocateEnabled(true);
    StormTakeover::Testing::SetHeapDestroyBatchSize(0);
    StormTakeover::Testing::SetHeapDestroyTaggedSnapshotEnabled(false);
    const bool takeoverStopped = StormTakeover::Shutdown();
    MemoryPool::Shutdown();
    initialized_ = false;
    return drained && takeoverStopped && !MemoryPool::IsInitialized();
  }

  void* Allocate(uint32_t size, const char* caller, int32_t line,
                 uint32_t flags) const noexcept {
    if (heapApi_) {
      return HookedFull_SMemHeapAlloc(kBenchmarkHeapId, flags, size);
    }
    return HookedFull_SMemAlloc(0, 0, size, caller, line, flags);
  }

  bool Free(void* pointer, const char* caller, int32_t line,
            uint32_t flags) const noexcept {
    if (heapApi_) {
      return HookedFull_SMemHeapFree(kBenchmarkHeapId, flags, pointer) != 0;
    }
    return HookedFull_SMemFree(pointer, caller, line, flags) != 0;
  }

  void* Reallocate(void* pointer, uint32_t newSize, const char* caller,
                   int32_t line, uint32_t flags) const noexcept {
    if (heapApi_) {
      return HookedFull_SMemHeapReAlloc(
          kBenchmarkHeapId, flags, pointer, newSize);
    }
    return HookedFull_SMemReAlloc(0, 0, pointer, newSize, caller, line, flags);
  }

private:
  bool initialized_ = false;
  bool heapApi_ = false;
  StormApi::ResolvedApi api_{};
};

void UpdatePeak(RunResult& result, uint64_t blocks,
                uint64_t requestedBytes) noexcept {
  result.peakLiveBlocks = (std::max)(result.peakLiveBlocks, blocks);
  result.peakLiveRequestedBytes =
      (std::max)(result.peakLiveRequestedBytes, requestedBytes);
}

template <typename Engine>
bool Drain(Engine& engine, std::vector<LiveBlock>& live, const char* caller,
           LatencySamples& latency, RunResult& result) {
  const auto start = Clock::now();
  while (!live.empty()) {
    const LiveBlock block = live.back();
    live.pop_back();
    const uint64_t operation = result.totalOperations++;
    const bool freed = latency.Measure(operation, [&] {
      return engine.Free(block.pointer, caller,
                         static_cast<int32_t>(block.caller), 0);
    });
    result.checksum = MixChecksum(
        result.checksum,
        (static_cast<uint64_t>(block.size) << 32u) | block.caller | 0xF0000000u);
    if (!freed) {
      ++result.failures;
      result.valid = false;
    }
  }
  result.wallNanoseconds += static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  return result.valid;
}

void TrimAfterDrainIfRequested(const Options& options, RunResult& result) {
  if (options.trimAfterDrain) {
    const auto start = Clock::now();
    MemoryPool::OnMemoryPressure();
    result.trimNanoseconds += static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - start).count());
  }
}

template <typename Engine>
RunResult RunMapLoad(Engine& engine, const Options& options,
                     const char* caller,
                     bool hotCallerLocality = false) {
  const bool standard = options.profile == "standard";
  const uint64_t operationLimit = standard ? 6600000ull : 660000ull;
  const uint32_t liveTarget = standard ? 1300000u : 130000u;
  constexpr uint32_t callerCount = 4096u;
  RunResult result{};
  std::vector<LiveBlock> live;
  live.reserve(liveTarget + 1u);
  LatencySamples latency(1024u);
  latency.Reserve(operationLimit + liveTarget);
  Pcg32 random(options.seed);
  uint64_t liveRequested = 0;
  result.before = CaptureProcessMemory();

  const auto start = Clock::now();
  for (uint64_t operation = 0; operation < operationLimit; ++operation) {
    const uint32_t decision = random.Bounded(100u);
    const bool allocate = live.empty() ||
                          (live.size() < liveTarget && decision < 70u);
    if (allocate) {
      const uint32_t size = MapLoadSize(random);
      // Consume the same RNG value in both scenarios so caller-locality is an
      // exact allocation trace with only the call-site distribution changed.
      const uint32_t uniformCallerId = random.Bounded(callerCount) + 1u;
      const uint32_t callerId = hotCallerLocality
                                    ? HotCallerId(operation, options.seed)
                                    : uniformCallerId;
      const uint32_t flags = random.Bounded(16u) == 0
                                 ? StormApi::kFlagZeroMemory
                                 : 0u;
      void* pointer = latency.Measure(operation, [&] {
        return engine.Allocate(size, caller, static_cast<int32_t>(callerId),
                               flags);
      });
      if (!pointer) {
        ++result.failures;
        result.valid = false;
        continue;
      }
      LiveBlock block{pointer, size, callerId,
                      static_cast<uint8_t>(Mix32(static_cast<uint32_t>(operation)))};
      TouchBlock(block);
      live.push_back(block);
      liveRequested += size;
      UpdatePeak(result, live.size(), liveRequested);
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(size) << 32u) | callerId | 0xA0000000u);
    } else if (decision < 92u) {
      const uint32_t index = random.Bounded(static_cast<uint32_t>(live.size()));
      const LiveBlock block = live[index];
      live[index] = live.back();
      live.pop_back();
      if (!ValidateBlock(block) ||
          !latency.Measure(operation, [&] {
            return engine.Free(block.pointer, caller,
                               static_cast<int32_t>(block.caller), 0);
          })) {
        ++result.failures;
        result.valid = false;
      }
      liveRequested -= block.size;
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(block.size) << 32u) | block.caller |
              0xB0000000u);
    } else {
      const uint32_t index = random.Bounded(static_cast<uint32_t>(live.size()));
      LiveBlock& block = live[index];
      if (!ValidateBlock(block)) {
        ++result.failures;
        result.valid = false;
      }
      const uint32_t newSize = MapLoadSize(random);
      void* replacement = latency.Measure(operation, [&] {
        return engine.Reallocate(block.pointer, newSize, caller,
                                 static_cast<int32_t>(block.caller), 0);
      });
      if (!replacement) {
        ++result.failures;
        result.valid = false;
        continue;
      }
      liveRequested -= block.size;
      liveRequested += newSize;
      block.pointer = replacement;
      block.size = newSize;
      TouchBlock(block);
      UpdatePeak(result, live.size(), liveRequested);
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(newSize) << 32u) | block.caller |
              0xC0000000u);
    }
    ++result.totalOperations;
  }
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  result.traceOperations = operationLimit;
  result.peak = CaptureProcessMemory();
  Drain(engine, live, caller, latency, result);
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  result.latency = latency.Summarize();
  return result;
}

template <typename Engine>
RunResult RunSmallChurn(Engine& engine, const Options& options,
                        const char* caller) {
  const bool standard = options.profile == "standard";
  const uint64_t operationLimit = standard ? 5000000ull : 500000ull;
  const uint32_t liveTarget = standard ? 131072u : 32768u;
  constexpr uint32_t callerCount = 2048u;
  RunResult result{};
  std::vector<LiveBlock> live;
  live.reserve(liveTarget + 1u);
  LatencySamples latency(512u);
  latency.Reserve(operationLimit + liveTarget);
  Pcg32 random(options.seed);
  uint64_t liveRequested = 0;
  result.before = CaptureProcessMemory();
  const auto start = Clock::now();
  for (uint64_t operation = 0; operation < operationLimit; ++operation) {
    const bool allocate = live.empty() ||
                          (live.size() < liveTarget && random.Bounded(100) < 55);
    if (allocate) {
      const uint32_t size = 8u + random.Bounded(505u);
      const uint32_t callerId = random.Bounded(callerCount) + 1u;
      void* pointer = latency.Measure(operation, [&] {
        return engine.Allocate(size, caller, static_cast<int32_t>(callerId), 0);
      });
      if (!pointer) {
        ++result.failures;
        result.valid = false;
      } else {
        LiveBlock block{pointer, size, callerId,
                        static_cast<uint8_t>(callerId ^ size)};
        TouchBlock(block);
        live.push_back(block);
        liveRequested += size;
        UpdatePeak(result, live.size(), liveRequested);
        result.checksum = MixChecksum(
            result.checksum,
            (static_cast<uint64_t>(size) << 32u) | callerId | 0x11000000u);
      }
    } else {
      const uint32_t index = random.Bounded(static_cast<uint32_t>(live.size()));
      const LiveBlock block = live[index];
      live[index] = live.back();
      live.pop_back();
      if (!ValidateBlock(block) ||
          !latency.Measure(operation, [&] {
            return engine.Free(block.pointer, caller,
                               static_cast<int32_t>(block.caller), 0);
          })) {
        ++result.failures;
        result.valid = false;
      }
      liveRequested -= block.size;
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(block.size) << 32u) | block.caller |
              0x22000000u);
    }
    ++result.totalOperations;
  }
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  result.traceOperations = operationLimit;
  result.peak = CaptureProcessMemory();
  Drain(engine, live, caller, latency, result);
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  result.latency = latency.Summarize();
  return result;
}

template <typename Engine>
RunResult RunRealloc(Engine& engine, const Options& options,
                     const char* caller) {
  const bool standard = options.profile == "standard";
  const uint32_t liveTarget = standard ? 131072u : 32768u;
  const uint64_t reallocations = standard ? 4000000ull : 400000ull;
  RunResult result{};
  std::vector<LiveBlock> live;
  live.reserve(liveTarget);
  LatencySamples latency(512u);
  latency.Reserve(reallocations + liveTarget * 2ull);
  Pcg32 random(options.seed);
  uint64_t liveRequested = 0;
  result.before = CaptureProcessMemory();
  auto phaseStart = Clock::now();
  for (uint32_t index = 0; index < liveTarget; ++index) {
    const uint32_t size = 16u + random.Bounded(1009u);
    const uint32_t callerId = random.Bounded(4096u) + 1u;
    void* pointer = latency.Measure(result.totalOperations, [&] {
      return engine.Allocate(size, caller, static_cast<int32_t>(callerId), 0);
    });
    ++result.totalOperations;
    if (!pointer) {
      ++result.failures;
      result.valid = false;
      continue;
    }
    LiveBlock block{pointer, size, callerId,
                    static_cast<uint8_t>(index ^ callerId)};
    TouchBlock(block);
    live.push_back(block);
    liveRequested += size;
  }
  result.wallNanoseconds += static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - phaseStart).count());
  UpdatePeak(result, live.size(), liveRequested);
  result.peak = CaptureProcessMemory();

  phaseStart = Clock::now();
  for (uint64_t index = 0; index < reallocations && !live.empty(); ++index) {
    LiveBlock& block = live[random.Bounded(static_cast<uint32_t>(live.size()))];
    if (!ValidateBlock(block)) {
      ++result.failures;
      result.valid = false;
    }
    uint32_t newSize = 8u + random.Bounded(4089u);
    if (random.Bounded(1000u) == 0) {
      newSize = StormApi::kNativeLargeThreshold + random.Bounded(256u * 1024u);
    }
    const uint64_t operation = result.totalOperations++;
    void* replacement = latency.Measure(operation, [&] {
      return engine.Reallocate(block.pointer, newSize, caller,
                               static_cast<int32_t>(block.caller), 0);
    });
    if (!replacement) {
      ++result.failures;
      result.valid = false;
      continue;
    }
    liveRequested -= block.size;
    liveRequested += newSize;
    block.pointer = replacement;
    block.size = newSize;
    TouchBlock(block);
    UpdatePeak(result, live.size(), liveRequested);
    result.checksum = MixChecksum(
        result.checksum,
        (static_cast<uint64_t>(newSize) << 32u) | block.caller | 0x33000000u);
  }
  result.wallNanoseconds += static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - phaseStart).count());
  result.traceOperations = liveTarget + reallocations;
  Drain(engine, live, caller, latency, result);
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  result.latency = latency.Summarize();
  return result;
}

template <typename Engine>
RunResult RunEditorBurst(Engine& engine, const Options& options,
                         const char* caller) {
  const bool standard = options.profile == "standard";
  const uint32_t cycles = standard ? 32u : 8u;
  const uint32_t blocksPerCycle = 96u;
  RunResult result{};
  std::vector<LiveBlock> live;
  live.reserve(blocksPerCycle);
  LatencySamples latency(1u);
  latency.Reserve(static_cast<uint64_t>(cycles) * blocksPerCycle * 2u);
  Pcg32 random(options.seed);
  result.before = CaptureProcessMemory();

  for (uint32_t cycle = 0; cycle < cycles; ++cycle) {
    uint64_t liveRequested = 0;
    auto phaseStart = Clock::now();
    for (uint32_t index = 0; index < blocksPerCycle; ++index) {
      const uint32_t size = EditorSize(random);
      const uint32_t callerId = random.Bounded(256u) + 1u;
      const uint64_t operation = result.totalOperations++;
      void* pointer = latency.Measure(operation, [&] {
        return engine.Allocate(size, caller, static_cast<int32_t>(callerId), 0);
      });
      if (!pointer) {
        ++result.failures;
        result.valid = false;
        continue;
      }
      LiveBlock block{pointer, size, callerId,
                      static_cast<uint8_t>(cycle ^ index)};
      TouchBlock(block);
      live.push_back(block);
      liveRequested += size;
      UpdatePeak(result, live.size(), liveRequested);
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(size) << 32u) | callerId | 0x44000000u);
    }
    result.wallNanoseconds += static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - phaseStart).count());
    const ProcessMemory atBurst = CaptureProcessMemory();
    if (atBurst.privateBytes > result.peak.privateBytes) {
      result.peak = atBurst;
    }
    for (size_t index = live.size(); index > 1; --index) {
      const size_t other = random.Bounded(static_cast<uint32_t>(index));
      std::swap(live[index - 1u], live[other]);
    }
    Drain(engine, live, caller, latency, result);
  }
  result.traceOperations = result.totalOperations;
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  result.latency = latency.Summarize();
  return result;
}

template <typename Engine>
RunResult RunCrossThread(Engine& engine, const Options& options,
                         const char* caller) {
  constexpr uint32_t threadCount = 4u;
  const bool standard = options.profile == "standard";
  const uint32_t blocksPerThread = standard ? 250000u : 25000u;
  RunResult result{};
  std::vector<LiveBlock> blocks[threadCount];
  LatencySamples threadLatency[threadCount] = {
      LatencySamples(256u), LatencySamples(256u),
      LatencySamples(256u), LatencySamples(256u)};
  uint64_t threadChecksums[threadCount]{};
  uint64_t threadRequested[threadCount]{};
  std::atomic<bool> valid{true};
  for (uint32_t thread = 0; thread < threadCount; ++thread) {
    blocks[thread].reserve(blocksPerThread);
    threadLatency[thread].Reserve(blocksPerThread * 2ull);
  }
  result.before = CaptureProcessMemory();
  auto phaseStart = Clock::now();
  std::vector<std::thread> workers;
  workers.reserve(threadCount);
  for (uint32_t thread = 0; thread < threadCount; ++thread) {
    workers.emplace_back([&, thread] {
      Pcg32 random(options.seed + thread * 0x9E3779B9u);
      for (uint32_t index = 0; index < blocksPerThread; ++index) {
        const uint32_t size = 8u + random.Bounded(2041u);
        const uint32_t callerId = random.Bounded(4096u) + 1u;
        void* pointer = threadLatency[thread].Measure(index, [&] {
          return engine.Allocate(size, caller, static_cast<int32_t>(callerId),
                                 0);
        });
        if (!pointer) {
          valid.store(false, std::memory_order_relaxed);
          continue;
        }
        LiveBlock block{pointer, size, callerId,
                        static_cast<uint8_t>(thread ^ index)};
        TouchBlock(block);
        blocks[thread].push_back(block);
        threadRequested[thread] += size;
        threadChecksums[thread] = MixChecksum(
            threadChecksums[thread],
            (static_cast<uint64_t>(size) << 32u) | callerId | 0x55000000u);
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  workers.clear();
  result.wallNanoseconds += static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - phaseStart).count());
  uint64_t totalRequested = 0;
  uint64_t totalBlocks = 0;
  for (uint32_t thread = 0; thread < threadCount; ++thread) {
    totalRequested += threadRequested[thread];
    totalBlocks += blocks[thread].size();
  }
  UpdatePeak(result, totalBlocks, totalRequested);
  result.peak = CaptureProcessMemory();

  phaseStart = Clock::now();
  for (uint32_t thread = 0; thread < threadCount; ++thread) {
    workers.emplace_back([&, thread] {
      const uint32_t source = (thread + 1u) % threadCount;
      uint64_t operation = blocksPerThread;
      for (const LiveBlock& block : blocks[source]) {
        if (!ValidateBlock(block) ||
            !threadLatency[thread].Measure(operation++, [&] {
              return engine.Free(block.pointer, caller,
                                 static_cast<int32_t>(block.caller), 0);
            })) {
          valid.store(false, std::memory_order_relaxed);
        }
        threadChecksums[thread] = MixChecksum(
            threadChecksums[thread],
            (static_cast<uint64_t>(block.size) << 32u) | block.caller |
                0x66000000u);
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  result.wallNanoseconds += static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - phaseStart).count());
  for (uint32_t thread = 0; thread < threadCount; ++thread) {
    result.totalOperations += blocks[thread].size() * 2ull;
    blocks[thread].clear();
    result.checksum ^= threadChecksums[thread];
    if (thread != 0) {
      threadLatency[0].Merge(threadLatency[thread]);
    }
  }
  result.traceOperations = result.totalOperations;
  result.valid = valid.load(std::memory_order_relaxed);
  result.failures = result.valid ? 0 : 1;
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  result.latency = threadLatency[0].Summarize();
  return result;
}

template <typename Engine>
RunResult RunTrimCycle(Engine& engine, const Options& options,
                       const char* caller) {
  const bool standard = options.profile == "standard";
  const uint32_t cycleCount = standard ? 20u : 8u;
  const uint32_t blockCount = standard ? 65536u : 16384u;
  RunResult result{};
  result.before = CaptureProcessMemory();
  result.peak = result.before;
  Pcg32 random(options.seed);
  LatencySamples latency(512);
  latency.Reserve(static_cast<uint64_t>(cycleCount) * blockCount * 2u);
  std::vector<LiveBlock> live;
  live.reserve(blockCount);

  const auto mergeProcessPeak = [&](const ProcessMemory& sample) {
    result.peak.workingSet =
        (std::max)(result.peak.workingSet, sample.workingSet);
    result.peak.peakWorkingSet =
        (std::max)(result.peak.peakWorkingSet, sample.peakWorkingSet);
    result.peak.privateBytes =
        (std::max)(result.peak.privateBytes, sample.privateBytes);
    result.peak.commitBytes =
        (std::max)(result.peak.commitBytes, sample.commitBytes);
    result.peak.occupiedVirtualBytes =
        (std::max)(result.peak.occupiedVirtualBytes,
                   sample.occupiedVirtualBytes);
    if (result.peak.largestFreeRegionBytes == 0 ||
        (sample.largestFreeRegionBytes != 0 &&
         sample.largestFreeRegionBytes <
             result.peak.largestFreeRegionBytes)) {
      result.peak.largestFreeRegionBytes = sample.largestFreeRegionBytes;
    }
    result.peak.freeRegionCount =
        (std::max)(result.peak.freeRegionCount, sample.freeRegionCount);
  };

  for (uint32_t cycle = 0; cycle < cycleCount; ++cycle) {
    const auto cycleStart = Clock::now();
    uint64_t requested = 0;
    for (uint32_t index = 0; index < blockCount; ++index) {
      const uint32_t size = 8u + random.Bounded(505u);
      // Real allocation sites are reused across epochs. Keeping this bounded
      // prevents the caller-heap registry from becoming the benchmark itself.
      const uint32_t line = (index & 2047u) + 1u;
      const uint64_t operation = result.totalOperations++;
      void* pointer = latency.Measure(operation, [&] {
        return engine.Allocate(size, caller, static_cast<int32_t>(line), 0);
      });
      if (!pointer) {
        result.valid = false;
        ++result.failures;
        continue;
      }
      static_cast<uint8_t*>(pointer)[0] =
          static_cast<uint8_t>((cycle + index) & 0xFFu);
      live.push_back({pointer, size, line, 0});
      requested += size;
      result.checksum = MixChecksum(
          result.checksum,
          (static_cast<uint64_t>(size) << 32u) | line | 0xCC000000u);
    }
    UpdatePeak(result, live.size(), requested);
    mergeProcessPeak(CaptureProcessMemory());

    for (const LiveBlock& block : live) {
      const uint64_t operation = result.totalOperations++;
      const bool freed = latency.Measure(operation, [&] {
        return engine.Free(block.pointer, caller,
                           static_cast<int32_t>(block.caller), 0);
      });
      if (!freed) {
        result.valid = false;
        ++result.failures;
      }
    }
    live.clear();

    const auto trimStart = Clock::now();
    MemoryPool::OnMemoryPressure();
    result.trimNanoseconds += static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - trimStart).count());
    result.wallNanoseconds += static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - cycleStart).count());
    if (!MemoryPool::Internal::ValidatePool()) {
      result.valid = false;
      ++result.failures;
      break;
    }
  }

  result.traceOperations = result.totalOperations;
  result.after = CaptureProcessMemory();
  result.latency = latency.Summarize();
  if (MemoryPool::GetRequestedLiveBytes() != 0 ||
      MemoryPool::GetUsableLiveBytes() != 0) {
    result.valid = false;
    ++result.failures;
  }
  return result;
}

template <typename Engine>
RunResult RunFragmentedTrim(Engine& engine, const Options& options,
                            const char* caller) {
  const uint32_t blockCount =
      options.profile == "standard" ? 524288u : 131072u;
  RunResult result{};
  result.before = CaptureProcessMemory();
  std::vector<LiveBlock> blocks;
  blocks.reserve(blockCount);
  Pcg32 random(options.seed);
  uint64_t liveRequested = 0;

  for (uint32_t index = 0; index < blockCount; ++index) {
    const uint32_t size = 64u + random.Bounded(129u);
    const uint32_t line = (index & 2047u) + 1u;
    void* pointer = engine.Allocate(
        size, caller, static_cast<int32_t>(line), 0);
    ++result.totalOperations;
    if (!pointer) {
      result.valid = false;
      ++result.failures;
      continue;
    }
    LiveBlock block{pointer, size, line,
                    static_cast<uint8_t>(index ^ size)};
    TouchBlock(block);
    blocks.push_back(block);
    liveRequested += size;
    result.checksum = MixChecksum(
        result.checksum,
        (static_cast<uint64_t>(size) << 32u) | line | 0xF1000000u);
  }
  UpdatePeak(result, blocks.size(), liveRequested);
  result.peak = CaptureProcessMemory();

  size_t survivorCount = 0;
  for (size_t index = 0; index < blocks.size(); ++index) {
    const LiveBlock block = blocks[index];
    if ((index & 31u) == 0) {
      blocks[survivorCount++] = block;
      continue;
    }
    ++result.totalOperations;
    if (!ValidateBlock(block) ||
        !engine.Free(block.pointer, caller,
                     static_cast<int32_t>(block.caller), 0)) {
      result.valid = false;
      ++result.failures;
    } else {
      liveRequested -= block.size;
    }
  }
  blocks.resize(survivorCount);

  const auto trimStart = Clock::now();
  MemoryPool::OnMemoryPressure();
  result.trimNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - trimStart).count());
  result.wallNanoseconds = result.trimNanoseconds;
  result.after = CaptureProcessMemory();
  result.latency.samples = 1;
  result.latency.p50Nanoseconds = result.trimNanoseconds;
  result.latency.p95Nanoseconds = result.trimNanoseconds;
  result.latency.p99Nanoseconds = result.trimNanoseconds;
  result.latency.maximumNanoseconds = result.trimNanoseconds;
  result.latency.overOneMillisecond =
      result.trimNanoseconds >= kNanosecondsPerMillisecond ? 1u : 0u;
  result.latency.overTenMilliseconds =
      result.trimNanoseconds >= 10u * kNanosecondsPerMillisecond ? 1u : 0u;

  for (const LiveBlock& block : blocks) {
    ++result.totalOperations;
    if (!ValidateBlock(block) ||
        !engine.Free(block.pointer, caller,
                     static_cast<int32_t>(block.caller), 0)) {
      result.valid = false;
      ++result.failures;
    } else {
      liveRequested -= block.size;
    }
  }
  blocks.clear();
  MemoryPool::OnMemoryPressure();
  result.traceOperations = result.totalOperations;
  if (liveRequested != 0 || MemoryPool::GetRequestedLiveBytes() != 0 ||
      MemoryPool::GetUsableLiveBytes() != 0 ||
      !MemoryPool::Internal::ValidatePool()) {
    result.valid = false;
    ++result.failures;
  }
  return result;
}

template <typename Engine>
RunResult RunRegistrySaturation(Engine& engine, const Options& options,
                                const char*) {
  (void)engine;
  const uint32_t overflowAttempts =
      options.profile == "standard" ? 4096u : 1024u;
  RunResult result{};

  for (uint32_t index = 0;
       index < StormHeapRegistry::kHeapRegistryCapacity; ++index) {
    if (!StormTakeover::Testing::RegisterManagedHeap(
            index + 1u, false, "registry-saturation", index + 1u)) {
      result.valid = false;
      ++result.failures;
      return result;
    }
  }

  result.before = CaptureProcessMemory();
  result.peak = result.before;
  LatencySamples latency(1u);
  latency.Reserve(overflowAttempts);
  const auto start = Clock::now();
  for (uint32_t index = 0; index < overflowAttempts; ++index) {
    const uint32_t heapId = 0x10000000u + index;
    const bool unexpectedlyRegistered = latency.Measure(index, [&] {
      return StormTakeover::Testing::RegisterManagedHeap(
          heapId, false, "registry-overflow", index);
    });
    if (unexpectedlyRegistered) {
      result.valid = false;
      ++result.failures;
    }
    result.checksum = MixChecksum(result.checksum, heapId);
  }
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  result.traceOperations = overflowAttempts;
  result.totalOperations = overflowAttempts;
  result.latency = latency.Summarize();
  result.after = CaptureProcessMemory();
  result.peak.workingSet =
      (std::max)(result.peak.workingSet, result.after.workingSet);
  result.peak.peakWorkingSet =
      (std::max)(result.peak.peakWorkingSet, result.after.peakWorkingSet);
  result.peak.privateBytes =
      (std::max)(result.peak.privateBytes, result.after.privateBytes);
  result.peak.commitBytes =
      (std::max)(result.peak.commitBytes, result.after.commitBytes);
  result.peak.occupiedVirtualBytes =
      (std::max)(result.peak.occupiedVirtualBytes,
                 result.after.occupiedVirtualBytes);
  if (result.peak.largestFreeRegionBytes == 0 ||
      (result.after.largestFreeRegionBytes != 0 &&
       result.after.largestFreeRegionBytes <
           result.peak.largestFreeRegionBytes)) {
    result.peak.largestFreeRegionBytes =
        result.after.largestFreeRegionBytes;
  }
  result.peak.freeRegionCount =
      (std::max)(result.peak.freeRegionCount, result.after.freeRegionCount);

  if (!StormTakeover::Testing::RegisterManagedHeap(
          1u, false, "registry-saturation", 1u)) {
    result.valid = false;
    ++result.failures;
  }
  return result;
}

template <typename Engine>
RunResult RunHeapEnumeration(Engine& engine, const Options& options,
                             const char*) {
  (void)engine;
  const bool standard = options.profile == "standard";
  const uint32_t blockCount = standard ? 250000u : 25000u;
  RunResult result{};
  std::vector<LiveBlock> blocks;
  blocks.reserve(blockCount);
  Pcg32 random(options.seed);
  LatencySamples latency(1u);
  latency.Reserve(blockCount + 1u);
  if (!StormTakeover::Testing::RegisterManagedHeap(
          kBenchmarkHeapId, true, "benchmark-enumeration", 481)) {
    result.valid = false;
    result.failures = 1;
    return result;
  }

  result.before = CaptureProcessMemory();
  uint64_t requested = 0;
  for (uint32_t index = 0; index < blockCount; ++index) {
    const uint32_t size = 8u + random.Bounded(2041u);
    void* pointer = HookedFull_SMemHeapAlloc(kBenchmarkHeapId, 0, size);
    if (!pointer) {
      result.valid = false;
      ++result.failures;
      continue;
    }
    LiveBlock block{pointer, size, index + 1u,
                    static_cast<uint8_t>(index ^ size)};
    TouchBlock(block);
    blocks.push_back(block);
    requested += size;
  }
  UpdatePeak(result, blocks.size(), requested);
  result.peak = CaptureProcessMemory();

  const auto start = Clock::now();
  const void* cursor = nullptr;
  uintptr_t previousAddress = 0;
  uint64_t enumeratedRequested = 0;
  uint32_t enumerated = 0;
  for (;;) {
    StormApi::BlockInfo481 info{};
    info.structSize = sizeof(info);
    void* next = nullptr;
    const uint64_t operation = result.totalOperations++;
    const int found = latency.Measure(operation, [&] {
      return HookedFull_SMemFindNextBlock(
          kBenchmarkHeapId, cursor, &next, &info);
    });
    if (!found) {
      break;
    }
    const uintptr_t address = reinterpret_cast<uintptr_t>(next);
    if (!next || next == cursor || address <= previousAddress ||
        info.block != next || !info.allocated || !info.valid) {
      result.valid = false;
      ++result.failures;
      break;
    }
    previousAddress = address;
    cursor = next;
    enumeratedRequested += info.requestedBytes;
    ++enumerated;
    result.checksum += MixChecksum(
        0x481481481ull,
        (static_cast<uint64_t>(info.requestedBytes) << 32u) |
            0x81000000u);
    if (enumerated > blockCount) {
      result.valid = false;
      ++result.failures;
      break;
    }
  }
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  result.traceOperations = result.totalOperations;
  if (enumerated != blocks.size() || enumeratedRequested != requested) {
    result.valid = false;
    ++result.failures;
  }
  result.latency = latency.Summarize();

  for (const LiveBlock& block : blocks) {
    if (!HookedFull_SMemHeapFree(kBenchmarkHeapId, 0, block.pointer)) {
      result.valid = false;
      ++result.failures;
    }
  }
  if (!HookedFull_SMemHeapDestroy(kBenchmarkHeapId)) {
    result.valid = false;
    ++result.failures;
  }
  const auto enumerationStats = StormTakeover::GetRuntimeStats();
  if (enumerationStats.blockEnumerationCalls != blocks.size() + 1u ||
      enumerationStats.blockEnumerationSnapshotBuilds != 1u ||
      enumerationStats.heapDestroySnapshots != 1u ||
      enumerationStats.heapDestroySnapshotBlocks != 0u) {
    result.valid = false;
    ++result.failures;
  }
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  return result;
}

template <typename Engine>
RunResult RunHeapDestroy(Engine& engine, const Options& options,
                         const char*) {
  (void)engine;
  const bool standard = options.profile == "standard";
  const uint32_t blockCount = standard ? 500000u : 50000u;
  RunResult result{};
  Pcg32 random(options.seed);
  if (!StormTakeover::Testing::RegisterManagedHeap(
          kBenchmarkHeapId, true, "benchmark-destroy", 487)) {
    result.valid = false;
    result.failures = 1;
    return result;
  }

  result.before = CaptureProcessMemory();
  uint64_t requested = 0;
  uint32_t allocated = 0;
  for (uint32_t index = 0; index < blockCount; ++index) {
    const uint32_t size = 8u + random.Bounded(505u);
    if (!HookedFull_SMemHeapAlloc(kBenchmarkHeapId, 0, size)) {
      result.valid = false;
      ++result.failures;
      continue;
    }
    requested += size;
    ++allocated;
    result.checksum = MixChecksum(
        result.checksum,
        (static_cast<uint64_t>(size) << 32u) | index | 0x87000000u);
  }
  UpdatePeak(result, allocated, requested);
  result.peak = CaptureProcessMemory();

  const auto start = Clock::now();
  const int destroyed = HookedFull_SMemHeapDestroy(kBenchmarkHeapId);
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          Clock::now() - start).count());
  result.traceOperations = allocated;
  result.totalOperations = allocated;
  if (!destroyed || allocated != blockCount ||
      MemoryPool::GetRequestedLiveBytes() != 0) {
    result.valid = false;
    ++result.failures;
  }
  const auto destroyStats = StormTakeover::GetRuntimeStats();
  const uint64_t expectedBatchCalls =
      options.heapDestroyBatchSize == 0
          ? 0
          : (static_cast<uint64_t>(allocated) +
             options.heapDestroyBatchSize - 1u) /
                options.heapDestroyBatchSize;
  if (destroyStats.heapDestroySnapshots != 1u ||
      destroyStats.heapDestroySnapshotBlocks != allocated ||
      destroyStats.heapDestroyBatchCalls != expectedBatchCalls ||
      destroyStats.heapDestroyBatchBlocks !=
          (options.heapDestroyBatchSize == 0 ? 0u : allocated) ||
      destroyStats.heapDestroyBatchFallbacks != 0u ||
      destroyStats.blockEnumerationSnapshotBuilds != 0u) {
    result.valid = false;
    ++result.failures;
  }
  TrimAfterDrainIfRequested(options, result);
  result.after = CaptureProcessMemory();
  return result;
}

template <typename Engine>
RunResult RunCallerHash(Engine&, const Options& options) {
  static constexpr const char* kCallerNames[] = {
      "war3map.j",
      "Scripts\\Blizzard.j",
      "E:\\Work\\Warcraft III\\Maps\\Development\\war3map.generated.j",
      "E:\\Mycode\\Source\\Repos\\War3MapReforge\\Core\\Base\\Graphics\\"
      "dxvk\\subprojects\\StormBreaker\\StormMemPoolFix\\Storm\\"
      "StormTakeover.cpp",
  };
  const uint64_t operationLimit =
      options.profile == "standard" ? 20000000ull : 2000000ull;
  RunResult result{};
  LatencySamples latency(1024u);
  latency.Reserve(operationLimit);
  result.before = CaptureProcessMemory();

  uint32_t rolling = static_cast<uint32_t>(options.seed);
  const auto start = Clock::now();
  for (uint64_t operation = 0; operation < operationLimit; ++operation) {
    const char* sourceFile = kCallerNames[operation & 3u];
    const int32_t sourceLine = static_cast<int32_t>(
        static_cast<uint32_t>(operation) * 0x9E3779B9u ^
        static_cast<uint32_t>(options.seed));
    const uint32_t heapId = latency.Measure(operation, [&] {
      return StormTakeover::Testing::ComputeDirectCallerHeap(sourceFile,
                                                              sourceLine);
    });
    rolling = (rolling << 5u) | (rolling >> 27u);
    rolling ^= heapId;
  }
  result.wallNanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start)
          .count());
  result.traceOperations = operationLimit;
  result.totalOperations = operationLimit;
  result.checksum = MixChecksum(result.checksum, rolling);
  result.latency = latency.Summarize();
  result.after = CaptureProcessMemory();
  return result;
}

template <typename Engine>
RunResult RunScenario(Engine& engine, const Options& options,
                       const char* caller) {
  if (options.scenario == "map-load") {
    return RunMapLoad(engine, options, caller);
  }
  if (options.scenario == "caller-locality") {
    return RunMapLoad(engine, options, caller, true);
  }
  if (options.scenario == "small-churn") {
    return RunSmallChurn(engine, options, caller);
  }
  if (options.scenario == "realloc") {
    return RunRealloc(engine, options, caller);
  }
  if (options.scenario == "editor-burst") {
    return RunEditorBurst(engine, options, caller);
  }
  if (options.scenario == "cross-thread") {
    return RunCrossThread(engine, options, caller);
  }
  if (options.scenario == "trim-cycle") {
    return RunTrimCycle(engine, options, caller);
  }
  if (options.scenario == "trim-fragmented") {
    return RunFragmentedTrim(engine, options, caller);
  }
  if (options.scenario == "registry-saturation") {
    return RunRegistrySaturation(engine, options, caller);
  }
  if (options.scenario == "heap-enumeration") {
    return RunHeapEnumeration(engine, options, caller);
  }
  if (options.scenario == "heap-destroy") {
    return RunHeapDestroy(engine, options, caller);
  }
  if (options.scenario == "caller-hash") {
    return RunCallerHash(engine, options);
  }
  RunResult invalid{};
  invalid.valid = false;
  invalid.failures = 1;
  return invalid;
}

template <typename Engine>
RunResult Execute(Engine& engine, const Options& options, const char* caller) {
  RunResult result{};
  if (!engine.Initialize(options)) {
    result.valid = false;
    result.failures = 1;
    return result;
  }
  result = RunScenario(engine, options, caller);
  if (!engine.Shutdown(result)) {
    result.valid = false;
    ++result.failures;
  }
  return result;
}

bool ParseUnsigned64(const char* text, uint64_t* value) noexcept {
  if (!text || !*text || !value) {
    return false;
  }
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(text, &end, 0);
  if (!end || *end != '\0') {
    return false;
  }
  *value = parsed;
  return true;
}

bool ParseOptions(int argc, char** argv, Options* options) {
  if (!options) {
    return false;
  }
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (index + 1 >= argc) {
      return false;
    }
    const char* value = argv[++index];
    if (argument == "--engine") {
      options->engine = value;
    } else if (argument == "--backend") {
      options->backend = value;
    } else if (argument == "--scenario") {
      options->scenario = value;
    } else if (argument == "--profile") {
      options->profile = value;
    } else if (argument == "--caller-mode") {
      options->callerMode = value;
    } else if (argument == "--api-mode") {
      options->apiMode = value;
    } else if (argument == "--takeover-mode") {
      options->takeoverMode = value;
    } else if (argument == "--fast-free") {
      if (std::strcmp(value, "on") == 0) {
        options->fastFree = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->fastFree = false;
      } else {
        return false;
      }
    } else if (argument == "--registry-accounting") {
      if (std::strcmp(value, "on") == 0) {
        options->registryAccounting = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->registryAccounting = false;
      } else {
        return false;
      }
    } else if (argument == "--registry-membership-filter") {
      if (std::strcmp(value, "on") == 0) {
        options->registryMembershipFilter = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->registryMembershipFilter = false;
      } else {
        return false;
      }
    } else if (argument == "--registry-predicted-slot") {
      if (std::strcmp(value, "on") == 0) {
        options->registryPredictedSlot = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->registryPredictedSlot = false;
      } else {
        return false;
      }
    } else if (argument == "--registry-hazard-pinning") {
      if (std::strcmp(value, "on") == 0) {
        options->registryHazardPinning = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->registryHazardPinning = false;
      } else {
        return false;
      }
    } else if (argument == "--main-registry-accounting") {
      if (std::strcmp(value, "on") == 0) {
        options->mainRegistryAccounting = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->mainRegistryAccounting = false;
      } else {
        return false;
      }
    } else if (argument == "--caller-slot-hint") {
      if (std::strcmp(value, "on") == 0) {
        options->callerSlotHint = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->callerSlotHint = false;
      } else {
        return false;
      }
    } else if (argument == "--direct-caller-hash") {
      if (std::strcmp(value, "on") == 0) {
        options->directCallerHash = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->directCallerHash = false;
      } else {
        return false;
      }
    } else if (argument == "--direct-hash-byte-table") {
      if (std::strcmp(value, "on") == 0) {
        options->directCallerByteTable = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->directCallerByteTable = false;
      } else {
        return false;
      }
    } else if (argument == "--recent-free-hash") {
      if (std::strcmp(value, "mix32") != 0 &&
          std::strcmp(value, "fibonacci") != 0) {
        return false;
      }
      options->recentFreeHash = value;
    } else if (argument == "--inplace-realloc") {
      if (std::strcmp(value, "on") == 0) {
        options->inPlaceReallocate = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->inPlaceReallocate = false;
      } else {
        return false;
      }
    } else if (argument == "--tlsf-range-index") {
      if (std::strcmp(value, "on") == 0) {
        options->tlsfRangeIndex = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->tlsfRangeIndex = false;
      } else {
        return false;
      }
    } else if (argument == "--detailed-counter-batching") {
      if (std::strcmp(value, "on") == 0) {
        options->detailedCounterBatching = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->detailedCounterBatching = false;
      } else {
        return false;
      }
    } else if (argument == "--pool-detailed-stats") {
      if (std::strcmp(value, "on") == 0) {
        options->poolDetailedStats = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->poolDetailedStats = false;
      } else {
        return false;
      }
    } else if (argument == "--tlsf-main-pool-decommit") {
      if (std::strcmp(value, "on") == 0) {
        options->tlsfMainPoolDecommit = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->tlsfMainPoolDecommit = false;
      } else {
        return false;
      }
    } else if (argument == "--tlsf-top-down") {
      if (std::strcmp(value, "on") == 0) {
        options->tlsfTopDown = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->tlsfTopDown = false;
      } else {
        return false;
      }
    } else if (argument == "--tlsf-constant-time-empty-check") {
      if (std::strcmp(value, "on") == 0) {
        options->tlsfConstantTimeEmptyCheck = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->tlsfConstantTimeEmptyCheck = false;
      } else {
        return false;
      }
    } else if (argument == "--tlsf-warm-empty-pools") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) || parsed > 8u) {
        return false;
      }
      options->tlsfWarmEmptyPools = static_cast<uint32_t>(parsed);
    } else if (argument == "--trim-after-drain") {
      if (std::strcmp(value, "on") == 0) {
        options->trimAfterDrain = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->trimAfterDrain = false;
      } else {
        return false;
      }
    } else if (argument == "--caller-cache-ways") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 4u && parsed != 8u)) {
        return false;
      }
      options->callerCacheWays = static_cast<uint32_t>(parsed);
    } else if (argument == "--caller-thread-cache") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 64u && parsed != 256u &&
           parsed != 1024u)) {
        return false;
      }
      options->callerThreadCacheCapacity = static_cast<uint32_t>(parsed);
    } else if (argument == "--heap-id-slot-hint") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 64u && parsed != 256u &&
           parsed != 1024u)) {
        return false;
      }
      options->heapIdSlotHintCapacity = static_cast<uint32_t>(parsed);
    } else if (argument == "--main-heap-pin") {
      if (std::strcmp(value, "on") == 0) {
        options->mainHeapPin = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->mainHeapPin = false;
      } else {
        return false;
      }
    } else if (argument == "--heap-destroy-batch-size") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 256u && parsed != 1024u &&
           parsed != 4096u && parsed != 16384u && parsed != 65536u)) {
        return false;
      }
      options->heapDestroyBatchSize = static_cast<uint32_t>(parsed);
    } else if (argument == "--heap-destroy-tagged-snapshot") {
      if (std::strcmp(value, "on") == 0) {
        options->heapDestroyTaggedSnapshot = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->heapDestroyTaggedSnapshot = false;
      } else {
        return false;
      }
    } else if (argument == "--span-cache") {
      if (std::strcmp(value, "on") == 0) {
        options->spanCache = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->spanCache = false;
      } else {
        return false;
      }
    } else if (argument == "--segregated-remote-free") {
      if (std::strcmp(value, "on") == 0) {
        options->segregatedRemoteFree = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->segregatedRemoteFree = false;
      } else {
        return false;
      }
    } else if (argument == "--segregated-lazy-span") {
      if (std::strcmp(value, "on") == 0) {
        options->segregatedLazySpan = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->segregatedLazySpan = false;
      } else {
        return false;
      }
    } else if (argument == "--segregated-remote-batch") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 1u && parsed != 4u &&
           parsed != 8u && parsed != 16u && parsed != 32u &&
           parsed != 64u)) {
        return false;
      }
      options->segregatedRemoteBatch = static_cast<uint32_t>(parsed);
    } else if (argument == "--segregated-span-kib") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 16u && parsed != 32u && parsed != 64u)) {
        return false;
      }
      options->segregatedSpanKiB = static_cast<uint32_t>(parsed);
    } else if (argument == "--segregated-tlsf-initial-mib") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 4u && parsed != 16u && parsed != 64u)) {
        return false;
      }
      options->segregatedTlsfInitialMiB = static_cast<uint32_t>(parsed);
    } else if (argument == "--pool-initial-mib") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 4u && parsed != 16u && parsed != 32u &&
           parsed != 64u)) {
        return false;
      }
      options->poolInitialMiB = static_cast<uint32_t>(parsed);
    } else if (argument == "--mimalloc-arena-reserve-mib") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 8u && parsed != 16u &&
           parsed != 32u && parsed != 64u && parsed != 128u)) {
        return false;
      }
      options->mimallocArenaReserveMiB = static_cast<uint32_t>(parsed);
    } else if (argument == "--mimalloc-page-full-retain") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) || parsed > 8u) {
        return false;
      }
      options->mimallocPageFullRetain = static_cast<uint32_t>(parsed);
    } else if (argument == "--mimalloc-page-max-candidates") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          parsed < 1u || parsed > 16u) {
        return false;
      }
      options->mimallocPageMaxCandidates = static_cast<uint32_t>(parsed);
    } else if (argument == "--rpmalloc-global-cache") {
      if (std::strcmp(value, "on") == 0) {
        options->rpmallocGlobalCache = true;
      } else if (std::strcmp(value, "off") == 0) {
        options->rpmallocGlobalCache = false;
      } else {
        return false;
      }
    } else if (argument == "--rpmalloc-span-map-count") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 1u && parsed != 4u && parsed != 8u &&
           parsed != 16u && parsed != 32u && parsed != 64u)) {
        return false;
      }
      options->rpmallocSpanMapCount = static_cast<uint32_t>(parsed);
    } else if (argument == "--rpmalloc-global-cache-multiplier") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 1u && parsed != 2u &&
           parsed != 4u && parsed != 8u)) {
        return false;
      }
      options->rpmallocGlobalCacheMultiplier =
          static_cast<uint32_t>(parsed);
    } else if (argument == "--rpmalloc-thread-span-cache-limit") {
      uint64_t parsed = 0;
      if (!ParseUnsigned64(value, &parsed) ||
          (parsed != 0u && parsed != 32u && parsed != 64u &&
           parsed != 128u && parsed != 256u && parsed != 400u)) {
        return false;
      }
      options->rpmallocThreadSpanCacheLimit =
          static_cast<uint32_t>(parsed);
    } else if (argument == "--seed") {
      if (!ParseUnsigned64(value, &options->seed)) {
        return false;
      }
    } else {
      return false;
    }
  }
  const bool engineValid =
      options->engine == "native-storm" ||
      options->engine == "legacy-large" ||
      options->engine == "winheap" ||
      options->engine == "private-heap" ||
      options->engine == "rpmalloc" ||
      options->engine == "rpmalloc-threaded" ||
      options->engine == "segregated-arena" ||
      options->engine == "segregated-hybrid" ||
      options->engine == "pool" ||
      options->engine == "takeover";
  const bool backendValid = options->backend == "tlsf" ||
                            options->backend == "mimalloc" ||
                            options->backend == "hybrid" ||
                            options->backend == "tlsf-sharded";
  const bool profileValid =
      options->profile == "quick" || options->profile == "standard";
  const bool callerValid = options->callerMode == "static" ||
                           options->callerMode == "dynamic";
  const bool apiModeValid = options->apiMode == "caller" ||
                            options->apiMode == "heap";
  const bool takeoverModeValid = options->takeoverMode == "large" ||
                                 options->takeoverMode == "full";
  const bool scenarioValid = options->scenario == "map-load" ||
                             options->scenario == "caller-locality" ||
                             options->scenario == "small-churn" ||
                             options->scenario == "realloc" ||
                             options->scenario == "editor-burst" ||
                             options->scenario == "cross-thread" ||
                             options->scenario == "trim-cycle" ||
                             options->scenario == "trim-fragmented" ||
                              options->scenario == "registry-saturation" ||
                              options->scenario == "heap-enumeration" ||
                              options->scenario == "heap-destroy" ||
                              options->scenario == "caller-hash";
  const bool takeoverOnlyScenario =
      options->scenario == "heap-enumeration" ||
      options->scenario == "heap-destroy" ||
      options->scenario == "caller-hash" ||
      options->scenario == "trim-cycle" ||
      options->scenario == "trim-fragmented" ||
      options->scenario == "registry-saturation";
  const bool tlsfOnlyScenario = options->scenario == "trim-fragmented";
  return engineValid && (!takeoverOnlyScenario ||
                         options->engine == "takeover") &&
         (!tlsfOnlyScenario || options->backend == "tlsf") &&
         backendValid && profileValid && callerValid &&
         apiModeValid && takeoverModeValid && scenarioValid;
}

void PrintMemory(const char* name, const ProcessMemory& memory) {
  std::printf(
      "\"%s\":{\"working_set\":%llu,\"peak_working_set\":%llu,"
      "\"private\":%llu,\"commit\":%llu,\"virtual\":%llu,"
      "\"largest_free_region\":%llu,\"free_regions\":%llu}",
      name, static_cast<unsigned long long>(memory.workingSet),
      static_cast<unsigned long long>(memory.peakWorkingSet),
      static_cast<unsigned long long>(memory.privateBytes),
      static_cast<unsigned long long>(memory.commitBytes),
      static_cast<unsigned long long>(memory.occupiedVirtualBytes),
      static_cast<unsigned long long>(memory.largestFreeRegionBytes),
      static_cast<unsigned long long>(memory.freeRegionCount));
}

void PrintResult(const Options& options, const RunResult& result) {
  const double operationsPerSecond =
      result.wallNanoseconds == 0
          ? 0.0
          : static_cast<double>(result.totalOperations) * 1000000000.0 /
                static_cast<double>(result.wallNanoseconds);
  std::printf("\n{");
  std::printf(
      "\"schema\":1,\"valid\":%s,\"engine\":\"%s\","
      "\"backend\":\"%s\",\"scenario\":\"%s\"," 
      "\"profile\":\"%s\",\"caller_mode\":\"%s\"," 
      "\"api_mode\":\"%s\",\"takeover_mode\":\"%s\","
      "\"fast_free\":%s,"
      "\"registry_accounting\":%s,\"registry_membership_filter\":%s,"
      "\"registry_predicted_slot\":%s,"
      "\"registry_hazard_pinning\":%s,"
      "\"main_registry_accounting\":%s,"
      "\"caller_slot_hint\":%s,\"direct_caller_hash\":%s,"
      "\"direct_hash_byte_table\":%s,"
      "\"recent_free_hash\":\"%s\","
      "\"inplace_realloc\":%s,"
      "\"tlsf_range_index\":%s,\"detailed_counter_batching\":%s,"
      "\"pool_detailed_stats\":%s,"
      "\"tlsf_main_pool_decommit\":%s,\"tlsf_top_down\":%s,"
      "\"tlsf_constant_time_empty_check\":%s,"
      "\"tlsf_warm_empty_pools\":%u,"
      "\"trim_after_drain\":%s,"
      "\"caller_cache_ways\":%u,\"caller_thread_cache\":%u,"
      "\"heap_id_slot_hint\":%u,"
      "\"main_heap_pin\":%s,\"heap_destroy_batch_size\":%u,"
      "\"heap_destroy_tagged_snapshot\":%s,"
      "\"span_cache\":%s,"
      "\"segregated_remote_free\":%s,"
      "\"segregated_lazy_span\":%s,"
      "\"segregated_remote_batch\":%u,"
      "\"segregated_span_kib\":%u,"
      "\"segregated_tlsf_initial_mib\":%u,\"pool_initial_mib\":%u,"
      "\"mimalloc_arena_reserve_mib\":%u,"
      "\"mimalloc_page_full_retain\":%u,"
      "\"mimalloc_page_max_candidates\":%u,"
      "\"rpmalloc_global_cache\":%s,"
      "\"rpmalloc_global_cache_multiplier\":%u,"
      "\"rpmalloc_thread_span_cache_limit\":%u,"
      "\"rpmalloc_span_map_count\":%u,"
      "\"seed\":%llu,",
      result.valid ? "true" : "false", options.engine.c_str(),
      options.engine == "native-storm" ||
              options.engine == "winheap" ||
              options.engine == "private-heap" ||
              options.engine == "rpmalloc" ||
              options.engine == "rpmalloc-threaded" ||
              options.engine == "segregated-arena" ||
              options.engine == "segregated-hybrid"
          ? options.engine.c_str()
          : options.backend.c_str(),
      options.scenario.c_str(), options.profile.c_str(),
      options.callerMode.c_str(),
      options.apiMode.c_str(),
      options.takeoverMode.c_str(),
      options.fastFree ? "true" : "false",
      options.registryAccounting ? "true" : "false",
      options.registryMembershipFilter ? "true" : "false",
      options.registryPredictedSlot ? "true" : "false",
      options.registryHazardPinning ? "true" : "false",
      options.mainRegistryAccounting ? "true" : "false",
      options.callerSlotHint ? "true" : "false",
      options.directCallerHash ? "true" : "false",
      options.directCallerByteTable ? "true" : "false",
      options.recentFreeHash.c_str(),
      options.inPlaceReallocate ? "true" : "false",
      options.tlsfRangeIndex ? "true" : "false",
      options.detailedCounterBatching ? "true" : "false",
      options.poolDetailedStats ? "true" : "false",
      options.tlsfMainPoolDecommit ? "true" : "false",
      options.tlsfTopDown ? "true" : "false",
      options.tlsfConstantTimeEmptyCheck ? "true" : "false",
      options.tlsfWarmEmptyPools,
      options.trimAfterDrain ? "true" : "false",
      options.callerCacheWays,
      options.callerThreadCacheCapacity,
      options.heapIdSlotHintCapacity,
      options.mainHeapPin ? "true" : "false",
      options.heapDestroyBatchSize,
      options.heapDestroyTaggedSnapshot ? "true" : "false",
      options.spanCache ? "true" : "false",
      options.segregatedRemoteFree ? "true" : "false",
      options.segregatedLazySpan ? "true" : "false",
      options.segregatedRemoteBatch,
      options.segregatedSpanKiB,
      options.segregatedTlsfInitialMiB,
      options.poolInitialMiB,
      options.mimallocArenaReserveMiB,
      options.mimallocPageFullRetain,
      options.mimallocPageMaxCandidates,
      options.rpmallocGlobalCache ? "true" : "false",
      options.rpmallocGlobalCacheMultiplier,
      options.rpmallocThreadSpanCacheLimit,
      options.rpmallocSpanMapCount,
      static_cast<unsigned long long>(options.seed));
  std::printf(
      "\"trace_operations\":%llu,\"total_operations\":%llu,"
      "\"failures\":%llu,\"wall_ns\":%llu,\"trim_ns\":%llu,"
      "\"ops_per_sec\":%.3f,"
      "\"checksum\":%llu,\"peak_live_blocks\":%llu,"
      "\"peak_live_requested\":%llu,",
      static_cast<unsigned long long>(result.traceOperations),
      static_cast<unsigned long long>(result.totalOperations),
      static_cast<unsigned long long>(result.failures),
      static_cast<unsigned long long>(result.wallNanoseconds),
      static_cast<unsigned long long>(result.trimNanoseconds),
      operationsPerSecond,
      static_cast<unsigned long long>(result.checksum),
      static_cast<unsigned long long>(result.peakLiveBlocks),
      static_cast<unsigned long long>(result.peakLiveRequestedBytes));
  std::printf(
      "\"latency\":{\"samples\":%llu,\"p50_ns\":%llu,"
      "\"p95_ns\":%llu,\"p99_ns\":%llu,\"max_ns\":%llu,"
      "\"over_1ms\":%llu,\"over_10ms\":%llu},",
      static_cast<unsigned long long>(result.latency.samples),
      static_cast<unsigned long long>(result.latency.p50Nanoseconds),
      static_cast<unsigned long long>(result.latency.p95Nanoseconds),
      static_cast<unsigned long long>(result.latency.p99Nanoseconds),
      static_cast<unsigned long long>(result.latency.maximumNanoseconds),
      static_cast<unsigned long long>(result.latency.overOneMillisecond),
      static_cast<unsigned long long>(result.latency.overTenMilliseconds));
  std::printf("\"memory\":{");
  PrintMemory("before", result.before);
  std::printf(",");
  PrintMemory("peak", result.peak);
  std::printf(",");
  PrintMemory("after", result.after);
  std::printf("},");
  std::printf(
      "\"pool\":{\"requested_live\":%llu,\"usable_live\":%llu,"
      "\"reserved\":%llu,\"committed\":%llu,\"failures\":%llu,"
      "\"extend_count\":%llu,\"trim_count\":%llu,"
      "\"lock_wait_count\":%llu,\"lock_wait_ns\":%llu,"
      "\"max_lock_wait_ns\":%llu,\"growth_samples\":%llu,"
      "\"growth_max_ns\":%llu},",
      static_cast<unsigned long long>(result.pool.requestedLiveBytes),
      static_cast<unsigned long long>(result.pool.usableLiveBytes),
      static_cast<unsigned long long>(result.pool.reservedBytes),
      static_cast<unsigned long long>(result.pool.committedBytes),
      static_cast<unsigned long long>(result.pool.failureCount),
      static_cast<unsigned long long>(result.pool.extendCount),
      static_cast<unsigned long long>(result.pool.trimCount),
      static_cast<unsigned long long>(result.pool.lockWaitCount),
      static_cast<unsigned long long>(result.pool.lockWaitNanoseconds),
      static_cast<unsigned long long>(result.pool.maxLockWaitNanoseconds),
      static_cast<unsigned long long>(result.pool.growthLatency.sampleCount),
      static_cast<unsigned long long>(result.pool.growthLatency.maxNanoseconds));
  std::printf(
      "\"takeover\":{\"live_blocks\":%llu,\"rejected\":%llu,"
      "\"degraded\":%llu,\"caller_hits\":%llu,\"caller_misses\":%llu,"
      "\"caller_bypasses\":%llu,\"caller_saturated\":%llu,"
      "\"heap_id_hint_hits\":%llu,\"heap_id_hint_misses\":%llu,"
      "\"caller_entries\":%u,\"block_enumeration_calls\":%llu,"
      "\"block_enumeration_snapshot_builds\":%llu,"
      "\"heap_enumeration_calls\":%llu,\"heap_enumeration_rebuilds\":%llu,"
      "\"heap_destroy_snapshots\":%llu,\"heap_destroy_snapshot_blocks\":%llu,"
      "\"heap_destroy_batch_calls\":%llu,"
      "\"heap_destroy_batch_blocks\":%llu,"
      "\"heap_destroy_batch_fallbacks\":%llu,"
      "\"inplace_attempts\":%llu,"
      "\"inplace_successes\":%llu,\"inplace_misses\":%llu},",
      static_cast<unsigned long long>(result.takeover.liveBlocks),
      static_cast<unsigned long long>(result.takeover.rejectedPointers),
      static_cast<unsigned long long>(result.takeover.degradedCalls),
      static_cast<unsigned long long>(result.takeover.callerHeapCacheHits),
      static_cast<unsigned long long>(result.takeover.callerHeapCacheMisses),
      static_cast<unsigned long long>(result.takeover.callerHeapCacheBypasses),
      static_cast<unsigned long long>(result.takeover.callerHeapCacheSaturated),
      static_cast<unsigned long long>(result.takeover.heapIdSlotHintHits),
      static_cast<unsigned long long>(result.takeover.heapIdSlotHintMisses),
      result.takeover.callerHeapCacheEntries,
      static_cast<unsigned long long>(result.takeover.blockEnumerationCalls),
      static_cast<unsigned long long>(
          result.takeover.blockEnumerationSnapshotBuilds),
      static_cast<unsigned long long>(result.takeover.heapEnumerationCalls),
      static_cast<unsigned long long>(result.takeover.heapEnumerationRebuilds),
      static_cast<unsigned long long>(result.takeover.heapDestroySnapshots),
      static_cast<unsigned long long>(
          result.takeover.heapDestroySnapshotBlocks),
      static_cast<unsigned long long>(result.takeover.heapDestroyBatchCalls),
      static_cast<unsigned long long>(result.takeover.heapDestroyBatchBlocks),
      static_cast<unsigned long long>(
          result.takeover.heapDestroyBatchFallbacks),
      static_cast<unsigned long long>(result.inPlaceReallocate.attempts),
      static_cast<unsigned long long>(result.inPlaceReallocate.successes),
      static_cast<unsigned long long>(result.inPlaceReallocate.misses));
  std::printf(
      "\"registry\":{\"occupied\":%u,\"active\":%u,"
      "\"collisions\":%llu,\"degraded\":%llu}}\n",
      result.registry.occupiedSlots, result.registry.activeHeaps,
      static_cast<unsigned long long>(result.registry.insertionCollisionProbes),
      static_cast<unsigned long long>(result.registry.degradedEvents));
}

} // namespace

int main(int argc, char** argv) {
  Options options{};
  if (!ParseOptions(argc, argv, &options)) {
    std::fprintf(
        stderr,
        "usage: StormBreakerAllocatorBenchmark --engine "
        "native-storm|legacy-large|winheap|private-heap|rpmalloc|"
        "rpmalloc-threaded|"
        "segregated-arena|"
        "segregated-hybrid|"
        "pool|takeover "
        "--backend tlsf|mimalloc|hybrid|tlsf-sharded --takeover-mode "
        "large|full --scenario "
        "map-load|caller-locality|"
        "small-churn|realloc|editor-burst|cross-thread|trim-cycle|"
        "trim-fragmented|"
        "registry-saturation|"
        "heap-enumeration|"
        "heap-destroy|caller-hash "
        "--profile quick|standard "
        "--caller-mode static|dynamic --api-mode caller|heap "
        "--fast-free on|off --registry-accounting on|off "
        "--registry-membership-filter on|off "
        "--registry-predicted-slot on|off "
        "--registry-hazard-pinning on|off "
        "--main-registry-accounting on|off --caller-slot-hint on|off "
        "--direct-hash-byte-table on|off "
        "--recent-free-hash mix32|fibonacci "
        "--inplace-realloc on|off --tlsf-range-index on|off "
        "--detailed-counter-batching on|off "
        "--pool-detailed-stats on|off "
        "--tlsf-main-pool-decommit on|off --tlsf-top-down on|off "
        "--tlsf-constant-time-empty-check on|off "
        "--tlsf-warm-empty-pools 0..8 "
        "--trim-after-drain on|off "
        "--direct-caller-hash on|off "
        "--caller-cache-ways 4|8 --caller-thread-cache 0|64|256|1024 "
        "--heap-id-slot-hint 0|64|256|1024 "
        "--main-heap-pin on|off "
        "--heap-destroy-batch-size 0|256|1024|4096|16384|65536 "
        "--heap-destroy-tagged-snapshot on|off "
        "--span-cache on|off "
        "--segregated-remote-free on|off "
        "--segregated-lazy-span on|off "
        "--segregated-remote-batch 0|1|4|8|16|32|64 "
        "--segregated-span-kib 16|32|64 "
        "--segregated-tlsf-initial-mib 4|16|64 "
        "--pool-initial-mib 4|16|32|64 "
        "--mimalloc-arena-reserve-mib 0|8|16|32|64|128 "
        "--mimalloc-page-full-retain 0..8 "
        "--mimalloc-page-max-candidates 1..16 "
        "--rpmalloc-global-cache on|off "
        "--rpmalloc-global-cache-multiplier 0|1|2|4|8 "
        "--rpmalloc-thread-span-cache-limit 0|32|64|128|256|400 "
        "--rpmalloc-span-map-count 1|4|8|16|32|64 "
        "--seed N\n");
    return 2;
  }

  MemoryPool::Internal::SetDetailedCounterBatchingEnabledForTesting(
      options.detailedCounterBatching);
  MemoryPool::Internal::SetTlsfMainPoolDecommitEnabledForTesting(
      options.tlsfMainPoolDecommit);
  MemoryPool::Internal::SetTlsfTopDownEnabledForTesting(
      options.tlsfTopDown);
  MemoryPool::Internal::SetTlsfConstantTimeEmptyCheckEnabledForTesting(
      options.tlsfConstantTimeEmptyCheck);
  MemoryPool::Internal::SetTlsfWarmEmptyPoolLimitForTesting(
      options.tlsfWarmEmptyPools);
  StormHeapRegistry::Testing::SetMembershipFilterEnabled(
      options.registryMembershipFilter);
  StormHeapRegistry::Testing::SetPredictedMainSlotEnabled(
      options.registryPredictedSlot);
  StormHeapRegistry::Testing::SetHazardPinningEnabled(
      options.registryHazardPinning);
  std::string dynamicCaller = "benchmark-dynamic-caller";
  const char* caller = options.callerMode == "dynamic"
                           ? dynamicCaller.c_str()
                           : kStaticCallerName;
  RunResult result{};
  if (options.engine == "native-storm") {
    NativeStormEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "legacy-large") {
    LegacyLargeEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "winheap") {
    WinHeapEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "private-heap") {
    PrivateHeapEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "rpmalloc") {
    RpmallocEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "rpmalloc-threaded") {
    RpmallocThreadedEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "segregated-arena") {
    SegregatedArenaEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "segregated-hybrid") {
    SegregatedHybridEngine engine;
    result = Execute(engine, options, caller);
  } else if (options.engine == "pool") {
    PoolEngine engine;
    result = Execute(engine, options, caller);
  } else {
    TakeoverEngine engine;
    result = Execute(engine, options, caller);
  }
  PrintResult(options, result);
  return result.valid ? 0 : 1;
}
