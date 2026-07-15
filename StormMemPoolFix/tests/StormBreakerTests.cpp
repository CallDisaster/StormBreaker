#include "pch.h"

#include "Base/LeakProfiler.h"
#include "Base/Logger.h"
#include "Base/MemorySafety.h"
#include "Storm/MemoryPool.h"
#include "Storm/StormHook.h"
#include "Storm/StormHeapRegistry.h"
#include "Storm/StormTakeover.h"
#include "Storm/StormVersionProfile.h"
#include "Storm/tlsf.h"
#include "mimalloc.h"

#include <array>
#include <atomic>
#include <climits>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

std::atomic<unsigned> g_cleanupCalls{0};
std::atomic<unsigned> g_resetCalls{0};
std::atomic<unsigned> g_findNextHeapCalls{0};
std::atomic<unsigned> g_getHeapByCallerCalls{0};
std::atomic<int> g_heapDestroyResult{1};
std::atomic<uintptr_t> g_nativeBlockSurvivor{0};

struct ConditionalFreeProbe {
  void *expectedPointer = nullptr;
  size_t minimumUsableSize = 0;
  uint32_t calls = 0;
  bool allow = false;
};

struct AllocationVisitProbe {
  size_t count = 0;
  size_t usableBytes = 0;
  bool routesValid = true;
};

bool CountVisitedAllocation(void *, size_t usableSize,
                            MemoryPool::BackendRoute route, void *context) {
  auto *probe = static_cast<AllocationVisitProbe *>(context);
  if (!probe) {
    return false;
  }
  ++probe->count;
  probe->usableBytes += usableSize;
  probe->routesValid = probe->routesValid &&
                      route == MemoryPool::BackendRoute::Tlsf;
  return true;
}

bool ValidateConditionalFree(void *pointer, size_t usableSize,
                             void *context) {
  auto *probe = static_cast<ConditionalFreeProbe *>(context);
  if (!probe) {
    return false;
  }
  ++probe->calls;
  return probe->allow && pointer == probe->expectedPointer &&
         usableSize >= probe->minimumUsableSize;
}

bool Check(bool condition, const char *expression, int line) {
  if (!condition) {
    std::fprintf(stderr, "FAILED line %d: %s\n", line, expression);
  }
  return condition;
}

#define CHECK(expression)                                                       \
  do {                                                                          \
    if (!Check(!!(expression), #expression, __LINE__)) {                         \
      return false;                                                             \
    }                                                                           \
  } while (false)

bool CreateSizedFile(const char *path, DWORD size) {
  HANDLE file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  LARGE_INTEGER position{};
  position.QuadPart = size;
  const bool ok = SetFilePointerEx(file, position, nullptr, FILE_BEGIN) &&
                  SetEndOfFile(file);
  CloseHandle(file);
  return ok;
}

uint64_t FileSizeOrZero(const char *path) {
  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  if (!GetFileAttributesExA(path, GetFileExInfoStandard, &attributes)) {
    return 0;
  }
  return (static_cast<uint64_t>(attributes.nFileSizeHigh) << 32) |
         attributes.nFileSizeLow;
}

bool TestLoggerRotationWithFullBackupSet() {
  char tempPath[MAX_PATH]{};
  char tempFile[MAX_PATH]{};
  if (!GetTempPathA(ARRAYSIZE(tempPath), tempPath) ||
      !GetTempFileNameA(tempPath, "sbr", 0, tempFile)) {
    return false;
  }
  DeleteFileA(tempFile);
  if (!CreateDirectoryA(tempFile, nullptr)) {
    return false;
  }

  char base[MAX_PATH]{};
  _snprintf_s(base, ARRAYSIZE(base), _TRUNCATE, "%s\\rotation.log",
              tempFile);
  bool prepared = CreateSizedFile(base, 8192);
  for (unsigned index = 1; index <= 5 && prepared; ++index) {
    char backup[MAX_PATH]{};
    _snprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, "%s.%u", base,
                index);
    prepared = CreateSizedFile(backup, index);
  }

  LoggerConfig config = Logger::GetReleaseConfig();
  config.enableConsole = false;
  config.enableDebugOutput = false;
  config.enableFile = true;
  config.logDirectory = tempFile;
  config.logFileName = "rotation.log";
  config.maxFileSize = 4096;
  config.maxBackupFiles = 5;
  const bool initialized = prepared && Logger::GetInstance().Initialize(config);
  if (initialized) {
    Logger::GetInstance().LogInfo("rotation regression trigger");
    Logger::GetInstance().FlushLogs();
  }

  char firstBackup[MAX_PATH]{};
  _snprintf_s(firstBackup, ARRAYSIZE(firstBackup), _TRUNCATE, "%s.1", base);
  const uint64_t activeSize = FileSizeOrZero(base);
  const uint64_t firstBackupSize = FileSizeOrZero(firstBackup);
  if (initialized) {
    Logger::GetInstance().Shutdown();
  }

  DeleteFileA(base);
  for (unsigned index = 1; index <= 5; ++index) {
    char backup[MAX_PATH]{};
    _snprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE, "%s.%u", base,
                index);
    DeleteFileA(backup);
  }
  RemoveDirectoryA(tempFile);
  return initialized && activeSize > 0 && activeSize < 4096 &&
         firstBackupSize == 8192;
}

void *__fastcall MockAlloc(int, int, size_t size, const char *, DWORD, DWORD) {
  return size == 0 ? nullptr : HeapAlloc(GetProcessHeap(), 0, size);
}

int __stdcall MockFree(void *ptr, const char *, int, DWORD) {
  return !ptr || HeapFree(GetProcessHeap(), 0, ptr) ? 1 : 0;
}

void *__fastcall MockRealloc(int, int, void *ptr, size_t size, const char *,
                             DWORD, DWORD) {
  if (!ptr) {
    return MockAlloc(0, 0, size, nullptr, 0, 0);
  }
  if (size == 0) {
    MockFree(ptr, nullptr, 0, 0);
    return nullptr;
  }
  return HeapReAlloc(GetProcessHeap(), 0, ptr, size);
}

int __stdcall MockGetSize(void *ptr, const char *, int) {
  if (!ptr) {
    return -1;
  }
  const SIZE_T size = HeapSize(GetProcessHeap(), 0, ptr);
  return size == static_cast<SIZE_T>(-1) || size > INT_MAX
             ? -1
             : static_cast<int>(size);
}

uint32_t __stdcall MockGetAllocated(uint32_t *outA, uint32_t *outB,
                                    uint32_t *outC) {
  constexpr uint32_t value = 1234;
  if (outA) {
    *outA = value;
  }
  if (outB) {
    *outB = value;
  }
  if (outC) {
    *outC = value;
  }
  return value;
}

uint32_t __stdcall MockGetHeapByCaller(const char *, int32_t) {
  g_getHeapByCallerCalls.fetch_add(1, std::memory_order_relaxed);
  return 0x12345678u;
}

uint32_t __stdcall MockGetHeapByPtr(const void *) { return 0x12345678u; }

int __stdcall MockFindNextHeap(uint32_t currentHeapId, uint32_t *nextHeapId,
                               StormApi::HeapInfo482 *info) {
  g_findNextHeapCalls.fetch_add(1, std::memory_order_relaxed);
  if (!nextHeapId || !info || info->structSize != sizeof(*info)) {
    return 0;
  }
  uint32_t next = 0;
  if (currentHeapId == 0) {
    next = 0x200u;
  } else if (currentHeapId == 0x200u) {
    next = 0x10u;
  } else {
    return 0;
  }
  const uint32_t structSize = info->structSize;
  std::memset(info, 0, sizeof(*info));
  info->structSize = structSize;
  info->heapId = next;
  info->requestedBytes = next;
  *nextHeapId = next;
  return 1;
}

int __stdcall MockFindNextBlock(uint32_t, const void *previousBlock,
                                void **nextBlock,
                                StormApi::BlockInfo481 *info) {
  const uintptr_t survivor =
      g_nativeBlockSurvivor.load(std::memory_order_relaxed);
  if (!nextBlock || !info || info->structSize != sizeof(*info) ||
      survivor == 0 || previousBlock != nullptr) {
    if (nextBlock) {
      *nextBlock = nullptr;
    }
    return 0;
  }
  const uint32_t structSize = info->structSize;
  std::memset(info, 0, sizeof(*info));
  info->structSize = structSize;
  info->block = reinterpret_cast<void *>(survivor);
  info->allocated = TRUE;
  info->valid = TRUE;
  info->requestedBytes = 0;
  *nextBlock = info->block;
  return 1;
}

void *__fastcall MockFullAlloc(int ecx, int edx, uint32_t size,
                               const char *sourceFile, int32_t sourceLine,
                               uint32_t flags) {
  return MockAlloc(ecx, edx, size, sourceFile,
                   static_cast<DWORD>(sourceLine), flags);
}

int __stdcall MockFullFree(void *pointer, const char *sourceFile,
                           int32_t sourceLine, uint32_t flags) {
  return MockFree(pointer, sourceFile, sourceLine, flags);
}

int __stdcall MockFullGetSize(const void *pointer, const char *sourceFile,
                              int32_t sourceLine) {
  return MockGetSize(const_cast<void *>(pointer), sourceFile, sourceLine);
}

void *__fastcall MockFullRealloc(int ecx, int edx, void *pointer,
                                 uint32_t size, const char *sourceFile,
                                 int32_t sourceLine, uint32_t flags) {
  if (pointer && size == 0) {
    return pointer;
  }
  return MockRealloc(ecx, edx, pointer, size, sourceFile,
                     static_cast<DWORD>(sourceLine), flags);
}

void *__stdcall MockHeapAlloc(uint32_t, uint32_t flags, uint32_t size) {
  return HeapAlloc(GetProcessHeap(),
                   (flags & StormApi::kFlagZeroMemory) != 0
                       ? HEAP_ZERO_MEMORY
                       : 0,
                   size == 0 ? 1 : size);
}

int __stdcall MockHeapFree(uint32_t, uint32_t, void *pointer) {
  return !pointer || HeapFree(GetProcessHeap(), 0, pointer) ? 1 : 0;
}

void *__stdcall MockHeapReAlloc(uint32_t heapId, uint32_t flags,
                                void *pointer, uint32_t size) {
  if (!pointer) {
    return MockHeapAlloc(heapId, flags, size);
  }
  return HeapReAlloc(GetProcessHeap(),
                     (flags & StormApi::kFlagZeroMemory) != 0
                         ? HEAP_ZERO_MEMORY
                         : 0,
                     pointer, size == 0 ? 1 : size);
}

int __stdcall MockHeapSize(uint32_t, uint32_t, const void *pointer) {
  const SIZE_T size = pointer
                          ? HeapSize(GetProcessHeap(), 0,
                                     const_cast<void *>(pointer))
                          : static_cast<SIZE_T>(-1);
  return size == static_cast<SIZE_T>(-1) || size > INT_MAX
             ? -1
             : static_cast<int>(size);
}

int __stdcall MockHeapDestroy(uint32_t) {
  return g_heapDestroyResult.load(std::memory_order_relaxed);
}

uint32_t __stdcall MockHeapCreate(void *, uint32_t, uint32_t,
                                  const char *, int32_t) {
  static std::atomic<uint32_t> nextId{0x80001000u};
  return nextId.fetch_add(1, std::memory_order_relaxed);
}

StormApi::ResolvedApi MockFullApi() {
  StormApi::ResolvedApi api{};
  api.alloc = &MockFullAlloc;
  api.free = &MockFullFree;
  api.getSize = &MockFullGetSize;
  api.reAlloc = &MockFullRealloc;
  api.getAllocated = &MockGetAllocated;
  api.findNextBlock = &MockFindNextBlock;
  api.findNextHeap = &MockFindNextHeap;
  api.getHeapByCaller = &MockGetHeapByCaller;
  api.getHeapByPtr = &MockGetHeapByPtr;
  api.heapAlloc = &MockHeapAlloc;
  api.heapCreate = &MockHeapCreate;
  api.heapDestroy = &MockHeapDestroy;
  api.heapFree = &MockHeapFree;
  api.heapReAlloc = &MockHeapReAlloc;
  api.heapSize = &MockHeapSize;
  return api;
}

void __stdcall MockCleanup() { g_cleanupCalls.fetch_add(1); }

int __stdcall MockReset() {
  g_resetCalls.fetch_add(1);
  return 77;
}

MemorySafetyConfig DisabledSafetyConfig() {
  MemorySafetyConfig config = MemorySafety::GetDefaultConfig();
  config.enableTracking = false;
  config.enableValidation = false;
  config.enableDeferredFree = false;
  config.enableLeakDetection = false;
  config.enableCorruptionDetection = false;
  return config;
}

bool ConfigureSmallPool() {
  MemoryPool::Config config{};
  config.initialSize = 4u * 1024u * 1024u;
  config.maxSize = 32u * 1024u * 1024u;
  config.extendGranularity = 4u * 1024u * 1024u;
  config.alignment = 16;
  config.enableDebug = false;
  config.enableStats = true;
  return MemoryPool::SetConfig(config);
}

bool TestRegistrySlotHintIdentityAndEpoch() {
  StormHeapRegistry::Testing::SetPredictedMainSlotEnabled(true);
  StormHeapRegistry::Registry registry;
  CHECK(registry.Initialize());

  StormHeapRegistry::SlotHint firstHint{};
  StormHeapRegistry::Registry::OperationGuard firstGuard;
  CHECK(registry.AcquireOrCreateMain(
            0x10101u, "first", 1, &firstGuard, nullptr, &firstHint) ==
        StormHeapRegistry::AccessResult::Managed);
  CHECK(firstHint.slot < StormHeapRegistry::kHeapRegistryCapacity);
  CHECK(firstHint.registryEpoch != 0);
  firstGuard.Reset();

  StormHeapRegistry::SlotHint conflictingHint = firstHint;
  StormHeapRegistry::Registry::OperationGuard secondGuard;
  CHECK(registry.AcquireOrCreateMain(
            0x20202u, "second", 2, &secondGuard, nullptr,
            &conflictingHint) == StormHeapRegistry::AccessResult::Managed);
  CHECK(secondGuard.GetHeapId() == 0x20202u);
  secondGuard.Reset();

  const uint32_t oldEpoch = firstHint.registryEpoch;
  CHECK(registry.Shutdown());
  CHECK(registry.Initialize());
  StormHeapRegistry::Registry::OperationGuard reinitializedGuard;
  CHECK(registry.AcquireOrCreateMain(
            0x10101u, "first", 1, &reinitializedGuard, nullptr,
            &firstHint) == StormHeapRegistry::AccessResult::Managed);
  CHECK(firstHint.registryEpoch != oldEpoch);
  reinitializedGuard.Reset();
  StormHeapRegistry::Testing::SetPredictedMainSlotEnabled(false);
  StormHeapRegistry::Registry::OperationGuard fallbackGuard;
  CHECK(registry.AcquireOrCreateMain(
            0x30303u, "fallback", 3, &fallbackGuard) ==
        StormHeapRegistry::AccessResult::Managed);
  fallbackGuard.Reset();
  StormHeapRegistry::Testing::SetPredictedMainSlotEnabled(false);
  CHECK(registry.Shutdown());
  return true;
}

bool TestRegistryHazardPinning() {
  StormHeapRegistry::Testing::SetHazardPinningEnabled(true);
  StormHeapRegistry::Registry registry;
  CHECK(registry.Initialize());

  constexpr uint32_t kHeapId = 0x40404u;
  StormHeapRegistry::Registry::OperationGuard firstGuard;
  StormHeapRegistry::Registry::OperationGuard secondGuard;
  CHECK(registry.AcquireOrCreateMain(
            kHeapId, "hazard", 4, &firstGuard) ==
        StormHeapRegistry::AccessResult::Managed);
  CHECK(registry.Acquire(kHeapId, &secondGuard) ==
        StormHeapRegistry::AccessResult::Managed);

  StormHeapRegistry::DestroyToken token{};
  std::atomic<bool> started{false};
  std::atomic<uint32_t> destroyResult{0xFFFFFFFFu};
  std::thread destroyThread([&] {
    started.store(true, std::memory_order_release);
    destroyResult.store(
        static_cast<uint32_t>(registry.BeginDestroy(kHeapId, &token)),
        std::memory_order_release);
  });
  while (!started.load(std::memory_order_acquire)) {
    SwitchToThread();
  }
  Sleep(5);
  const bool waitedForBoth =
      destroyResult.load(std::memory_order_acquire) == 0xFFFFFFFFu;
  firstGuard.Reset();
  Sleep(2);
  const bool waitedForSecond =
      destroyResult.load(std::memory_order_acquire) == 0xFFFFFFFFu;
  secondGuard.Reset();
  destroyThread.join();

  const bool begun = static_cast<StormHeapRegistry::DestroyResult>(
                         destroyResult.load(std::memory_order_acquire)) ==
                     StormHeapRegistry::DestroyResult::BegunManaged;
  const bool cancelled =
      begun && registry.CancelDestroy(&token) ==
                   StormHeapRegistry::DestroyResult::Cancelled;
  const bool shutdown = registry.Shutdown();
  StormHeapRegistry::Testing::SetHazardPinningEnabled(false);
  CHECK(waitedForBoth && waitedForSecond && begun && cancelled && shutdown);
  return true;
}

bool TestRegistryFullTableMembershipFilter() {
  StormHeapRegistry::Testing::SetMembershipFilterEnabled(true);
  StormHeapRegistry::Registry registry;
  CHECK(registry.Initialize());

  for (uint32_t index = 0;
       index < StormHeapRegistry::kHeapRegistryCapacity; ++index) {
    CHECK(registry.RegisterManaged(
              index + 1u, StormHeapRegistry::HeapKind::Main,
              "membership-filter", index + 1u) ==
          StormHeapRegistry::CreateResult::CreatedManaged);
  }

  const auto filteredBefore = registry.GetStats();
  constexpr uint32_t kOverflowAttempts = 1024u;
  for (uint32_t index = 0; index < kOverflowAttempts; ++index) {
    CHECK(registry.RegisterManaged(
              0x10000000u + index, StormHeapRegistry::HeapKind::Main,
              "membership-overflow", index) ==
          StormHeapRegistry::CreateResult::CapacityExhausted);
  }
  const auto filteredAfter = registry.GetStats();
  CHECK(filteredAfter.capacityFailures ==
        filteredBefore.capacityFailures + kOverflowAttempts);
  CHECK(filteredAfter.insertionCollisionProbes -
            filteredBefore.insertionCollisionProbes <=
        static_cast<uint64_t>(StormHeapRegistry::kHeapRegistryCapacity) *
            16u);

  StormHeapRegistry::Registry::OperationGuard existing;
  CHECK(registry.Acquire(1u, &existing) ==
        StormHeapRegistry::AccessResult::Managed);
  existing.Reset();

  StormHeapRegistry::Testing::SetMembershipFilterEnabled(false);
  const auto unfilteredBefore = registry.GetStats();
  CHECK(registry.RegisterManaged(
            0x20000000u, StormHeapRegistry::HeapKind::Main,
            "membership-unfiltered", 0) ==
        StormHeapRegistry::CreateResult::CapacityExhausted);
  const auto unfilteredAfter = registry.GetStats();
  CHECK(unfilteredAfter.insertionCollisionProbes -
            unfilteredBefore.insertionCollisionProbes ==
        StormHeapRegistry::kHeapRegistryCapacity);
  StormHeapRegistry::Testing::SetMembershipFilterEnabled(true);

  CHECK(registry.Shutdown());
  return true;
}

bool TestHookContract() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf"));
  CHECK(ConfigureSmallPool());
  MemoryPool::SetLatencyTrackingEnabled(true);
  StormHook::SetRuntimeStatsEnabled(true);
  CHECK(MemorySafety::GetInstance().Initialize(DisabledSafetyConfig()));
  CHECK(StormHook::Initialize());

  g_origStormAlloc = &MockAlloc;
  g_origStormFree = &MockFree;
  g_origStormReAlloc = &MockRealloc;
  g_origStormGetSize = &MockGetSize;
  g_origCleanupAll = &MockCleanup;
  g_origResetMemoryManager = &MockReset;

  const size_t threshold = StormHook::GetLargeBlockThreshold();
  CHECK(threshold == 0xFE7C);
  CHECK(StormHook::AllocateMemory(threshold - 1, "below", 1) == nullptr);

  void *managed = StormHook::AllocateMemory(threshold, "boundary", 2);
  CHECK(managed != nullptr);
  CHECK((reinterpret_cast<uintptr_t>(managed) & 0x0F) == 0);
  auto *header = reinterpret_cast<StormAllocHeader *>(managed) - 1;
  MemoryPool::AllocationOwnership managedOwnership{};
  CHECK(MemoryPool::QueryAllocation(header, &managedOwnership));
  CHECK(sizeof(StormAllocHeader) == 16);
  CHECK(header->magic == STORMBREAKER_MAGIC);
  CHECK(header->requestedSize == threshold);
  CHECK(header->sizeCookie ==
        (static_cast<uint32_t>(threshold) ^ kStormBreakerCookie));
  CHECK(header->headerSize == sizeof(StormAllocHeader));
  CHECK(header->rejectTag == kStormBreakerRejectTag);
  CHECK(Hooked_Storm_MemGetSize(managed, "boundary", 0) ==
        static_cast<int>(threshold));
  CHECK(StormHook::FreeMemory(managed));

  void *zeroRealloc = StormHook::AllocateMemory(threshold + 32, "zero", 3);
  CHECK(zeroRealloc != nullptr);
  const StormHook::ManagedReallocResult zeroResult =
      StormHook::TryReallocMemory(zeroRealloc, 0, "zero", 4);
  CHECK(zeroResult.disposition ==
        StormHook::ManagedReallocDisposition::Freed);
  CHECK(zeroResult.pointer == nullptr);

  void *doubleFree = StormHook::AllocateMemory(threshold + 64, "double", 5);
  CHECK(doubleFree != nullptr);
  CHECK(StormHook::FreeMemory(doubleFree));
  CHECK(StormHook_Internal::IsRejectedManagedPointer(doubleFree));
  CHECK(StormHook::FreeMemory(doubleFree));

  void *corrupt = StormHook::AllocateMemory(threshold + 96, "corrupt", 6);
  CHECK(corrupt != nullptr);
  auto *corruptHeader = reinterpret_cast<StormAllocHeader *>(corrupt) - 1;
  const uint32_t originalCookie = corruptHeader->sizeCookie;
  corruptHeader->sizeCookie ^= 1;
  CHECK(StormHook_Internal::IsRejectedManagedPointer(corrupt));
  CHECK(StormHook::FreeMemory(corrupt));
  corruptHeader->sizeCookie = originalCookie;
  CHECK(StormHook::FreeMemory(corrupt));

  void *crossThread =
      StormHook::AllocateMemory(threshold + 128, "thread", 7);
  CHECK(crossThread != nullptr);
  std::atomic<bool> crossThreadFreed{false};
  std::thread freeThread([&] {
    crossThreadFreed.store(StormHook::FreeMemory(crossThread));
  });
  freeThread.join();
  CHECK(crossThreadFreed.load());

  void *migrating =
      StormHook::AllocateMemory(threshold + 256, "migration", 8);
  CHECK(migrating != nullptr);
  std::memset(migrating, 0x5A, threshold + 256);
  const size_t nativeSize = threshold - 16;
  void *native = Hooked_Storm_MemReAlloc(
      0, 0, migrating, nativeSize, "migration", 9, 0);
  CHECK(native != nullptr);
  CHECK(!MemoryPool::IsFromPool(native));
  CHECK(static_cast<unsigned char *>(native)[0] == 0x5A);
  CHECK(static_cast<unsigned char *>(native)[nativeSize - 1] == 0x5A);
  CHECK(Hooked_Storm_MemFree(native, "migration", 0, 0) == 1);

  void *nativeOld = MockAlloc(0, 0, 128, nullptr, 0, 0);
  CHECK(nativeOld != nullptr);
  void *nativeLarge = Hooked_Storm_MemReAlloc(
      0, 0, nativeOld, threshold + 512, "native", 10, 0);
  CHECK(nativeLarge != nullptr);
  CHECK(!MemoryPool::IsFromPool(nativeLarge));
  CHECK(Hooked_Storm_MemFree(nativeLarge, "native", 0, 0) == 1);

  // This production-sized request falls just below 16 MiB. TLSF rounds its
  // lookup to the next second-level class, so a naive 16 MiB growth pool is
  // present but can never satisfy it.
  constexpr size_t kTlsfClassBoundaryRequest = 16658448u;
  CHECK(tlsf_allocation_pool_size(kTlsfClassBoundaryRequest, 16) >
        16u * 1024u * 1024u);
  CHECK(tlsf_allocation_pool_size(SIZE_MAX, 16) == 0);
  CHECK(tlsf_allocation_pool_size(4096, 3) == 0);
  void *classBoundary =
      MemoryPool::AllocateAlignedKnownSize(kTlsfClassBoundaryRequest, 16);
  CHECK(classBoundary != nullptr);
  MemoryPool::FreeKnownSizeUntracked(classBoundary,
                                     kTlsfClassBoundaryRequest);
  CHECK(MemoryPool::GetExtendedStats().requestedLiveBytes == 0);
  CHECK(MemoryPool::GetExtendedStats().reservedBytes <=
        24u * 1024u * 1024u);

  CHECK(MemoryPool::AllocateAlignedKnownSize(33u * 1024u * 1024u, 16) ==
        nullptr);

  g_cleanupCalls.store(0);
  g_resetCalls.store(0);
  Hooked_StormHeap_CleanupAll();
  CHECK(g_cleanupCalls.load() == 1);
  CHECK(Hooked_ResetMemoryManager() == 77);
  CHECK(g_resetCalls.load() == 1);

  std::vector<void *> blocks;
  for (size_t index = 0; index < 128; ++index) {
    void *block = StormHook::AllocateMemory(
        threshold + (index % 8) * 4096, "stress", 11);
    CHECK(block != nullptr);
    blocks.push_back(block);
  }
  std::atomic<bool> stressOk{true};
  std::vector<std::thread> workers;
  for (size_t worker = 0; worker < 4; ++worker) {
    workers.emplace_back([&, worker] {
      for (size_t index = worker; index < blocks.size(); index += 4) {
        if (!StormHook::FreeMemory(blocks[index])) {
          stressOk.store(false);
        }
      }
    });
  }
  for (std::thread &worker : workers) {
    worker.join();
  }
  CHECK(stressOk.load());
  CHECK(StormHook::GetManagedBlockCount() == 0);
  CHECK(StormHook::GetTotalManagedSize() == 0);
  const MemoryPool::ExtendedPoolStats tlsfStats =
      MemoryPool::GetExtendedStats();
  CHECK(tlsfStats.requestedLiveBytes == 0);
  CHECK(tlsfStats.copyLatency.sampleCount >= 1);
  CHECK(tlsfStats.growthLatency.sampleCount >= 1);
  CHECK(MemoryPool::Internal::ValidatePool());

  StormHook::Shutdown();
  MemorySafety::GetInstance().Shutdown();
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  return true;
}

bool TestMimallocBackend() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "mimalloc"));
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MIMALLOC_PURGE_DELAY_MS",
                                nullptr));
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB", nullptr));
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN", nullptr));
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES", nullptr));
  MemoryPool::SetLatencyTrackingEnabled(true);
  CHECK(MemoryPool::Initialize());
  CHECK(mi_option_get(mi_option_purge_delay) == -1);
  CHECK(mi_option_get(mi_option_arena_reserve) == 128L * 1024L);
  CHECK(mi_option_get(mi_option_page_full_retain) == 2);
  CHECK(mi_option_get(mi_option_page_max_candidates) == 4);

  std::vector<std::pair<void *, size_t>> blocks;
  for (size_t index = 0; index < 512; ++index) {
    const size_t size = 1024 + (index % 31) * 257;
    void *ptr = MemoryPool::AllocateAlignedKnownSize(size, 16);
    CHECK(ptr != nullptr);
    blocks.emplace_back(ptr, size);
  }

  std::vector<std::thread> workers;
  for (size_t worker = 0; worker < 4; ++worker) {
    workers.emplace_back([&, worker] {
      for (size_t index = worker; index < blocks.size(); index += 4) {
        MemoryPool::FreeKnownSizeUntracked(blocks[index].first,
                                           blocks[index].second);
      }
    });
  }
  for (std::thread &worker : workers) {
    worker.join();
  }

  MemoryPool::OnMemoryPressure();
  CHECK(mi_option_get(mi_option_purge_delay) == -1);
  CHECK(MemoryPool::GetExtendedStats().requestedLiveBytes == 0);
  CHECK(MemoryPool::Internal::ValidatePool());
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());

  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB", "7"));
  CHECK(!MemoryPool::Initialize());
  CHECK(!MemoryPool::IsInitialized());
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB", nullptr));

  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN", "9"));
  CHECK(!MemoryPool::Initialize());
  CHECK(!MemoryPool::IsInitialized());
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN", nullptr));

  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES", "0"));
  CHECK(!MemoryPool::Initialize());
  CHECK(!MemoryPool::IsInitialized());
  CHECK(SetEnvironmentVariableA(
      "STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES", nullptr));
  return true;
}

bool TestConditionalRoutedFree() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "hybrid"));
  CHECK(ConfigureSmallPool());
  MemoryPool::SetLatencyTrackingEnabled(false);
  CHECK(MemoryPool::Initialize());

  constexpr size_t physicalSize = 160;
  constexpr size_t requestedCharge = 128;
  const MemoryPool::BackendRoute routes[] = {
      MemoryPool::BackendRoute::Tlsf,
      MemoryPool::BackendRoute::Mimalloc,
  };
  for (const auto route : routes) {
    const auto allocation = MemoryPool::AllocateRouted(
        physicalSize, requestedCharge, 16, route);
    CHECK(allocation.pointer != nullptr);
    CHECK(allocation.route == route);
    CHECK(MemoryPool::GetRequestedLiveBytes() == requestedCharge);

    ConditionalFreeProbe probe{};
    probe.expectedPointer = allocation.pointer;
    probe.minimumUsableSize = physicalSize;
    CHECK(!MemoryPool::FreeRoutedConditional(
        static_cast<unsigned char *>(allocation.pointer) + 16,
        requestedCharge, route, &ValidateConditionalFree, &probe));
    CHECK(probe.calls == 0);
    CHECK(MemoryPool::GetRequestedLiveBytes() == requestedCharge);

    CHECK(!MemoryPool::FreeRoutedConditional(
        allocation.pointer, requestedCharge, route,
        &ValidateConditionalFree, &probe));
    CHECK(probe.calls == 1);
    CHECK(MemoryPool::GetRequestedLiveBytes() == requestedCharge);
    MemoryPool::AllocationOwnership ownership{};
    CHECK(MemoryPool::QueryAllocation(allocation.pointer, &ownership));

    probe.allow = true;
    CHECK(MemoryPool::FreeRoutedConditional(
        allocation.pointer, requestedCharge, route,
        &ValidateConditionalFree, &probe));
    CHECK(probe.calls == 2);
    CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
    CHECK(!MemoryPool::FreeRoutedConditional(
        allocation.pointer, requestedCharge, route,
        &ValidateConditionalFree, &probe));
    CHECK(probe.calls == 2);
  }

  CHECK(MemoryPool::GetUsableLiveBytes() == 0);
  CHECK(MemoryPool::Internal::ValidatePool());
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  return true;
}

bool TestRoutedBatchFree() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "hybrid"));
  CHECK(ConfigureSmallPool());
  MemoryPool::SetLatencyTrackingEnabled(false);
  CHECK(MemoryPool::Initialize());

  constexpr size_t kEntryCount = 48;
  constexpr size_t kInvalidIndex = 19;
  const MemoryPool::BackendRoute routes[] = {
      MemoryPool::BackendRoute::Tlsf,
      MemoryPool::BackendRoute::Mimalloc,
  };
  for (const auto route : routes) {
    std::array<MemoryPool::BatchFreeEntry, kEntryCount> entries{};
    size_t totalRequested = 0;
    size_t prefixRequested = 0;
    for (size_t index = 0; index < entries.size(); ++index) {
      const size_t requested = 33u + index * 17u;
      const size_t physical = requested + 32u;
      const auto allocation = MemoryPool::AllocateRouted(
          physical, requested, 16, route);
      CHECK(allocation.pointer != nullptr);
      CHECK(allocation.route == route);
      entries[index] = {allocation.pointer, requested};
      totalRequested += requested;
      if (index < kInvalidIndex) {
        prefixRequested += requested;
      }
    }
    CHECK(MemoryPool::GetRequestedLiveBytes() == totalRequested);

    const auto automatic = MemoryPool::FreeRoutedBatch(
        entries.data(), entries.size(),
        MemoryPool::BackendRoute::Automatic);
    CHECK(automatic.freedCount == 0 && automatic.usableBytes == 0);
    CHECK(MemoryPool::GetRequestedLiveBytes() == totalRequested);

    void* const original = entries[kInvalidIndex].pointer;
    entries[kInvalidIndex].pointer =
        static_cast<unsigned char*>(original) + 1;
    const auto prefix = MemoryPool::FreeRoutedBatch(
        entries.data(), entries.size(), route);
    CHECK(prefix.freedCount == kInvalidIndex);
    CHECK(prefix.usableBytes != 0);
    CHECK(MemoryPool::GetRequestedLiveBytes() ==
          totalRequested - prefixRequested);

    entries[kInvalidIndex].pointer = original;
    const auto remainder = MemoryPool::FreeRoutedBatch(
        entries.data() + kInvalidIndex,
        entries.size() - kInvalidIndex, route);
    CHECK(remainder.freedCount == entries.size() - kInvalidIndex);
    CHECK(remainder.usableBytes != 0);
    CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
    CHECK(MemoryPool::GetUsableLiveBytes() == 0);
  }

  CHECK(MemoryPool::Internal::ValidatePool());
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  return true;
}

bool TestDetailedCounterBatching() {
  constexpr size_t kBlockCount = 600;
  for (const bool enabled : {false, true}) {
    CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf"));
    CHECK(ConfigureSmallPool());
    MemoryPool::Internal::SetDetailedCounterBatchingEnabledForTesting(
        enabled);
    CHECK(MemoryPool::Initialize());

    std::vector<void*> blocks;
    blocks.reserve(kBlockCount);
    for (size_t index = 0; index < kBlockCount; ++index) {
      void* block = MemoryPool::Allocate(96u + index % 17u);
      CHECK(block != nullptr);
      block = MemoryPool::Reallocate(block, 160u + index % 31u);
      CHECK(block != nullptr);
      blocks.push_back(block);
    }
    const auto allocated = MemoryPool::GetExtendedStats();
    CHECK(allocated.allocCount == kBlockCount);
    CHECK(allocated.reallocCount == kBlockCount);
    CHECK(allocated.freeCount == 0);

    std::thread freeingThread([&] {
      for (void* block : blocks) {
        MemoryPool::Free(block);
      }
    });
    freeingThread.join();

    const auto freed = MemoryPool::GetExtendedStats();
    CHECK(freed.allocCount == kBlockCount);
    CHECK(freed.reallocCount == kBlockCount);
    CHECK(freed.freeCount == kBlockCount);
    CHECK(freed.requestedLiveBytes == 0);
    CHECK(freed.usableLiveBytes == 0);
    CHECK(MemoryPool::Internal::ValidatePool());
    MemoryPool::Shutdown();
    CHECK(!MemoryPool::IsInitialized());
  }
  MemoryPool::Internal::SetDetailedCounterBatchingEnabledForTesting(false);
  return true;
}

bool TestTlsfPoolRangeIndex() {
  constexpr size_t kAllocationSize = 3u * 1024u * 1024u;
  for (const bool indexed : {false, true}) {
    CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf"));
    CHECK(ConfigureSmallPool());
    MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(indexed);
    CHECK(MemoryPool::Initialize());

    std::vector<MemoryPool::RoutedAllocation> allocations;
    allocations.reserve(6);
    for (size_t index = 0; index < 6; ++index) {
      const auto allocation = MemoryPool::AllocateRouted(
          kAllocationSize, kAllocationSize, 16,
          MemoryPool::BackendRoute::Tlsf);
      CHECK(allocation.pointer != nullptr);
      CHECK(allocation.route == MemoryPool::BackendRoute::Tlsf);
      allocations.push_back(allocation);
    }
    CHECK(MemoryPool::Internal::GetPoolCount() >= 6);

    for (const auto& allocation : allocations) {
      MemoryPool::AllocationOwnership ownership{};
      CHECK(MemoryPool::QueryAllocation(
          allocation.pointer, MemoryPool::BackendRoute::Tlsf, &ownership));
      CHECK(ownership.route == MemoryPool::BackendRoute::Tlsf);
      CHECK(ownership.usableSize >= kAllocationSize);
      auto* interior = static_cast<unsigned char*>(allocation.pointer) + 1;
      CHECK(!MemoryPool::QueryAllocation(
          interior, MemoryPool::BackendRoute::Tlsf, &ownership));
      MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
      CHECK(MemoryPool::OwnsAddress(interior, &route));
      CHECK(route == MemoryPool::BackendRoute::Tlsf);
    }

    for (const auto& allocation : allocations) {
      CHECK(MemoryPool::FreeRouted(
          allocation.pointer, kAllocationSize,
          MemoryPool::BackendRoute::Tlsf));
    }
    CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
    CHECK(MemoryPool::Internal::ValidatePool());
    MemoryPool::OnMemoryPressure();
    CHECK(MemoryPool::Internal::GetPoolCount() == 1);
    MemoryPool::Shutdown();
    CHECK(!MemoryPool::IsInitialized());
  }
  MemoryPool::Internal::SetTlsfRangeIndexEnabledForTesting(true);
  return true;
}

bool TestTlsfMainPoolDecommit() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf"));
  CHECK(ConfigureSmallPool());
  MemoryPool::Internal::SetTlsfMainPoolDecommitEnabledForTesting(true);
  CHECK(MemoryPool::Initialize());

  std::vector<std::pair<void*, size_t>> blocks;
  blocks.reserve(512);
  for (size_t index = 0; index < 512; ++index) {
    const size_t requested = 128u + index % 97u;
    void* block = MemoryPool::AllocateRouted(
        requested, 16, MemoryPool::BackendRoute::Tlsf).pointer;
    CHECK(block != nullptr);
    blocks.emplace_back(block, requested);
  }
  const auto livePool = MemoryPool::GetExtendedStats();
  MemoryPool::OnMemoryPressure();
  CHECK(MemoryPool::GetExtendedStats().committedBytes ==
        livePool.committedBytes);
  for (const auto& block : blocks) {
    CHECK(MemoryPool::FreeRouted(
        block.first, block.second, MemoryPool::BackendRoute::Tlsf));
  }
  CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
  CHECK(MemoryPool::GetUsableLiveBytes() == 0);

  const auto beforeTrim = MemoryPool::GetExtendedStats();
  CHECK(beforeTrim.committedBytes == beforeTrim.reservedBytes);
  MemoryPool::OnMemoryPressure();
  const auto afterTrim = MemoryPool::GetExtendedStats();
  CHECK(afterTrim.reservedBytes == beforeTrim.reservedBytes);
  CHECK(afterTrim.committedBytes < beforeTrim.committedBytes);
  CHECK(afterTrim.committedBytes <= 64u * 1024u);
  CHECK(MemoryPool::Internal::ValidatePool());

  const auto recommitted = MemoryPool::AllocateRouted(
      4096, 16, MemoryPool::BackendRoute::Tlsf);
  CHECK(recommitted.pointer != nullptr);
  CHECK(MemoryPool::GetExtendedStats().committedBytes ==
        beforeTrim.committedBytes);
  CHECK(MemoryPool::FreeRouted(
      recommitted.pointer, 4096, MemoryPool::BackendRoute::Tlsf));
  MemoryPool::OnMemoryPressure();
  CHECK(MemoryPool::GetExtendedStats().committedBytes ==
        afterTrim.committedBytes);
  CHECK(MemoryPool::Internal::ValidatePool());

  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  MemoryPool::Internal::SetTlsfMainPoolDecommitEnabledForTesting(false);
  return true;
}

bool TestTlsfShardedBackend() {
  MemoryPool::Internal::SetTlsfWarmEmptyPoolLimitForTesting(1);
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND",
                                "tlsf-sharded"));

  MemoryPool::Config invalidConfig{};
  invalidConfig.initialSize = 128u * 1024u;
  invalidConfig.maxSize = 1024u * 1024u;
  invalidConfig.extendGranularity = 128u * 1024u;
  invalidConfig.alignment = 16;
  invalidConfig.enableStats = true;
  CHECK(MemoryPool::SetConfig(invalidConfig));
  CHECK(!MemoryPool::Initialize());
  CHECK(!MemoryPool::IsInitialized());

  CHECK(ConfigureSmallPool());
  MemoryPool::DisableThreadSafety();
  CHECK(!MemoryPool::IsThreadSafeEnabled());
  MemoryPool::EnableThreadSafety();
  CHECK(MemoryPool::IsThreadSafeEnabled());
  MemoryPool::SetLatencyTrackingEnabled(true);
  CHECK(MemoryPool::Initialize());
  CHECK(MemoryPool::GetBackendKind() ==
        MemoryPool::BackendKind::TlsfSharded);
  CHECK(std::strcmp(MemoryPool::GetBackendName(), "tlsf-sharded") == 0);
  CHECK(MemoryPool::Internal::GetPoolCount() == 4);
  CHECK(MemoryPool::GetExtendedStats().reservedBytes ==
        4u * 1024u * 1024u);
  CHECK(MemoryPool::Internal::ValidatePool());

  // Prove the aggregate max is shared rather than split into four hard caps.
  // Twelve MiB is greater than this configuration's old max/4 limit (8 MiB).
  constexpr size_t kBorrowedCapacitySize = 12u * 1024u * 1024u;
  MemoryPool::Internal::SetTlsfShardAffinityForTesting(1);
  void *borrowedCapacity = MemoryPool::Allocate(kBorrowedCapacitySize);
  CHECK(borrowedCapacity != nullptr);
  MemoryPool::AllocationOwnership ownership{};
  CHECK(MemoryPool::QueryAllocation(borrowedCapacity, &ownership));
  CHECK(ownership.usableSize >= kBorrowedCapacitySize);
  MemoryPool::Free(borrowedCapacity);

  constexpr size_t kOwnerAllocationSize = 2560u * 1024u;
  MemoryPool::Internal::SetTlsfShardAffinityForTesting(0);
  void *first = MemoryPool::Allocate(kOwnerAllocationSize);
  void *second = MemoryPool::Allocate(kOwnerAllocationSize);
  CHECK(first != nullptr && second != nullptr);
  std::memset(first, 0x5a, 4096);

  // Consume the remaining aggregate reservation while retaining the freed
  // 13 MiB pool on shard one. The owner cannot grow, so realloc must move to
  // that existing cross-shard capacity.
  MemoryPool::Internal::SetTlsfShardAffinityForTesting(2);
  constexpr size_t kAggregateFillerSize = 8u * 1024u * 1024u;
  void *aggregateFiller = MemoryPool::Allocate(kAggregateFillerSize);
  CHECK(aggregateFiller != nullptr);
  const uint64_t reservedWithFiller =
      MemoryPool::GetExtendedStats().reservedBytes;
  CHECK(reservedWithFiller > 4u * 1024u * 1024u);
  CHECK(reservedWithFiller <= 32u * 1024u * 1024u);

  MemoryPool::Internal::SetTlsfShardAffinityForTesting(1);
  constexpr size_t kMovedAllocationSize = 5u * 1024u * 1024u;
  void *moved = MemoryPool::Reallocate(first, kMovedAllocationSize);
  CHECK(moved != nullptr);
  for (size_t index = 0; index < 4096; ++index) {
    CHECK(static_cast<unsigned char *>(moved)[index] == 0x5a);
  }
  if (moved != first) {
    CHECK(!MemoryPool::QueryAllocation(first, &ownership));
  }
  CHECK(MemoryPool::QueryAllocation(moved, &ownership));
  CHECK(ownership.route == MemoryPool::BackendRoute::Tlsf);
  CHECK(ownership.usableSize >= kMovedAllocationSize);

  CHECK(MemoryPool::Reallocate(second, 20u * 1024u * 1024u) == nullptr);
  CHECK(MemoryPool::QueryAllocation(second, &ownership));
  CHECK(ownership.usableSize >= kOwnerAllocationSize);

  MemoryPool::Internal::SetTlsfShardAffinityForTesting(2);
  constexpr size_t kInPlaceOriginalSize = 4096;
  constexpr size_t kInPlaceShrunkSize = 2048;
  const auto inPlace = MemoryPool::AllocateRouted(
      kInPlaceOriginalSize, kInPlaceOriginalSize, 16,
      MemoryPool::BackendRoute::Tlsf);
  CHECK(inPlace.pointer != nullptr);
  size_t inPlaceUsable = 0;
  CHECK(MemoryPool::ReallocateInPlaceRouted(
            inPlace.pointer, kInPlaceOriginalSize, kInPlaceShrunkSize,
            kInPlaceShrunkSize, MemoryPool::BackendRoute::Tlsf,
            &inPlaceUsable) ==
        MemoryPool::InPlaceReallocateStatus::Succeeded);
  CHECK(inPlaceUsable >= kInPlaceShrunkSize);

  struct RoutedBlock {
    void *pointer;
    size_t requested;
  };
  std::vector<RoutedBlock> routedBlocks;
  routedBlocks.reserve(512);
  for (size_t index = 0; index < 512; ++index) {
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(
        index % 4);
    const size_t requested = 64u + (index % 29u) * 37u;
    const auto allocation = MemoryPool::AllocateRouted(
        requested, requested, 16, MemoryPool::BackendRoute::Tlsf);
    CHECK(allocation.pointer != nullptr);
    CHECK(allocation.route == MemoryPool::BackendRoute::Tlsf);
    routedBlocks.push_back({allocation.pointer, requested});
  }

  for (size_t index = 0; index < routedBlocks.size(); index += 17) {
    CHECK(MemoryPool::QueryAllocation(
        routedBlocks[index].pointer, MemoryPool::BackendRoute::Tlsf,
        &ownership));
    auto *interior = static_cast<unsigned char *>(
        routedBlocks[index].pointer) + 1;
    CHECK(!MemoryPool::QueryAllocation(
        interior, MemoryPool::BackendRoute::Tlsf, &ownership));
    MemoryPool::BackendRoute route = MemoryPool::BackendRoute::Automatic;
    CHECK(MemoryPool::OwnsAddress(interior, &route));
    CHECK(route == MemoryPool::BackendRoute::Tlsf);
  }

  AllocationVisitProbe visit{};
  CHECK(MemoryPool::VisitAllocations(
      MemoryPool::BackendRoute::Tlsf, &CountVisitedAllocation, &visit));
  CHECK(visit.routesValid);
  CHECK(visit.count == routedBlocks.size() + 4);
  CHECK(visit.usableBytes >=
        kMovedAllocationSize + kOwnerAllocationSize);

  std::atomic<bool> churnStart{false};
  std::atomic<bool> churnOk{true};
  std::vector<std::thread> churnWorkers;
  for (size_t worker = 0; worker < 4; ++worker) {
    churnWorkers.emplace_back([&, worker] {
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(worker);
      while (!churnStart.load(std::memory_order_acquire)) {
        YieldProcessor();
      }
      for (size_t iteration = 0; iteration < 500; ++iteration) {
        const size_t requested = 96u + (iteration % 23u) * 19u;
        const auto allocation = MemoryPool::AllocateRouted(
            requested, requested, 16, MemoryPool::BackendRoute::Tlsf);
        if (!allocation.pointer ||
            !MemoryPool::FreeRouted(
                allocation.pointer, requested,
                MemoryPool::BackendRoute::Tlsf)) {
          churnOk.store(false, std::memory_order_relaxed);
          break;
        }
      }
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
    });
  }
  churnStart.store(true, std::memory_order_release);
  for (size_t snapshot = 0; snapshot < 64; ++snapshot) {
    AllocationVisitProbe concurrentVisit{};
    CHECK(MemoryPool::VisitAllocations(
        MemoryPool::BackendRoute::Tlsf, &CountVisitedAllocation,
        &concurrentVisit));
    CHECK(concurrentVisit.routesValid);
  }
  for (std::thread &worker : churnWorkers) {
    worker.join();
  }
  CHECK(churnOk.load(std::memory_order_relaxed));
  CHECK(MemoryPool::Internal::ValidatePool());

  std::atomic<bool> crossThreadFreeOk{true};
  std::vector<std::thread> workers;
  for (size_t worker = 0; worker < 8; ++worker) {
    workers.emplace_back([&, worker] {
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(
          (worker + 1) % 4);
      for (size_t index = worker; index < routedBlocks.size(); index += 8) {
        if (!MemoryPool::FreeRouted(
                routedBlocks[index].pointer,
                routedBlocks[index].requested,
                MemoryPool::BackendRoute::Tlsf)) {
          crossThreadFreeOk.store(false, std::memory_order_relaxed);
        }
      }
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
    });
  }
  workers.emplace_back([&] {
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(3);
    MemoryPool::Free(moved);
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
  });
  workers.emplace_back([&] {
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(1);
    MemoryPool::Free(aggregateFiller);
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
  });
  workers.emplace_back([&] {
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(0);
    if (!MemoryPool::FreeRouted(
            inPlace.pointer, kInPlaceShrunkSize,
            MemoryPool::BackendRoute::Tlsf)) {
      crossThreadFreeOk.store(false, std::memory_order_relaxed);
    }
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
  });
  workers.emplace_back([&] {
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(2);
    MemoryPool::Free(second);
    MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
  });
  for (std::thread &worker : workers) {
    worker.join();
  }
  CHECK(crossThreadFreeOk.load(std::memory_order_relaxed));
  CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
  CHECK(MemoryPool::GetUsableLiveBytes() == 0);
  CHECK(MemoryPool::Internal::ValidatePool());

  const auto grownStats = MemoryPool::GetExtendedStats();
  CHECK(grownStats.reservedBytes > 4u * 1024u * 1024u);
  CHECK(grownStats.reservedBytes <= 32u * 1024u * 1024u);
  CHECK(grownStats.growthLatency.sampleCount >= 1);
  MemoryPool::OnMemoryPressure();
  CHECK(MemoryPool::Internal::GetPoolCount() == 4);
  CHECK(MemoryPool::GetExtendedStats().reservedBytes ==
        4u * 1024u * 1024u);
  CHECK(MemoryPool::GetExtendedStats().trimCount >= 1);

  CHECK(MemoryPool::ExtendPool(256u * 1024u));
  CHECK(MemoryPool::Internal::GetPoolCount() >= 8);
  const size_t poolsBeforeFailedExtend =
      MemoryPool::Internal::GetPoolCount();
  const uint64_t reservedBeforeFailedExtend =
      MemoryPool::GetExtendedStats().reservedBytes;
  MemoryPool::Internal::SetTlsfShardExtendFailureForTesting(2);
  CHECK(!MemoryPool::ExtendPool(256u * 1024u));
  MemoryPool::Internal::SetTlsfShardExtendFailureForTesting(SIZE_MAX);
  CHECK(MemoryPool::Internal::GetPoolCount() == poolsBeforeFailedExtend);
  CHECK(MemoryPool::GetExtendedStats().reservedBytes ==
        reservedBeforeFailedExtend);
  MemoryPool::CompactPool();
  MemoryPool::Internal::DumpPoolInfo();
  MemoryPool::OnMemoryPressure();
  CHECK(MemoryPool::Internal::GetPoolCount() == 4);
  CHECK(MemoryPool::Internal::ValidatePool());

  std::atomic<bool> largeRaceStart{false};
  std::atomic<bool> largeRaceRelease{false};
  std::atomic<size_t> largeRaceAttempts{0};
  void *largeRaceBlocks[4]{};
  std::vector<std::thread> largeRaceWorkers;
  for (size_t worker = 0; worker < 4; ++worker) {
    largeRaceWorkers.emplace_back([&, worker] {
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(worker);
      while (!largeRaceStart.load(std::memory_order_acquire)) {
        YieldProcessor();
      }
      constexpr size_t requested = 12u * 1024u * 1024u;
      largeRaceBlocks[worker] = MemoryPool::AllocateRouted(
          requested, requested, 16,
          MemoryPool::BackendRoute::Tlsf).pointer;
      largeRaceAttempts.fetch_add(1, std::memory_order_acq_rel);
      while (!largeRaceRelease.load(std::memory_order_acquire)) {
        YieldProcessor();
      }
      if (largeRaceBlocks[worker]) {
        MemoryPool::FreeRouted(
            largeRaceBlocks[worker], requested,
            MemoryPool::BackendRoute::Tlsf);
      }
      MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
    });
  }
  largeRaceStart.store(true, std::memory_order_release);
  while (largeRaceAttempts.load(std::memory_order_acquire) != 4) {
    YieldProcessor();
  }
  size_t largeRaceSuccesses = 0;
  for (void *pointer : largeRaceBlocks) {
    largeRaceSuccesses += pointer != nullptr ? 1u : 0u;
  }
  const auto largeRaceStats = MemoryPool::GetExtendedStats();
  const bool largeRacePoolValid = MemoryPool::Internal::ValidatePool();
  largeRaceRelease.store(true, std::memory_order_release);
  for (std::thread &worker : largeRaceWorkers) {
    worker.join();
  }
  CHECK(largeRaceSuccesses >= 1 && largeRaceSuccesses <= 2);
  CHECK(largeRaceStats.reservedBytes <= 32u * 1024u * 1024u);
  CHECK(largeRaceStats.peakReservedBytes <= 32u * 1024u * 1024u);
  CHECK(largeRacePoolValid);
  CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
  CHECK(MemoryPool::GetUsableLiveBytes() == 0);
  MemoryPool::OnMemoryPressure();
  CHECK(MemoryPool::Internal::GetPoolCount() == 4);
  CHECK(MemoryPool::Internal::ValidatePool());

  MemoryPool::Internal::SetTlsfShardAffinityForTesting(SIZE_MAX);
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  MemoryPool::Internal::SetTlsfWarmEmptyPoolLimitForTesting(0);
  return true;
}

bool TestFullTakeoverContract() {
  StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(true);
  constexpr uint32_t heapId = 0x80000042u;
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "hybrid"));
  CHECK(SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE", "full"));
  CHECK(ConfigureSmallPool());
  MemoryPool::SetLatencyTrackingEnabled(true);
  CHECK(MemoryPool::Initialize());
  CHECK(StormTakeover::Initialize());
  StormApi::ResolvedApi destroyApi{};
  destroyApi.findNextBlock = &MockFindNextBlock;
  destroyApi.heapDestroy = &MockHeapDestroy;
  StormTakeover::Testing::SetNativeApi(&destroyApi);
  CHECK(StormTakeover::GetMode() == StormTakeover::TakeoverMode::Full);
  CHECK(StormTakeover::Testing::RegisterManagedHeap(
      heapId, true, "full-takeover-test", 100));

  void *smallBlock = HookedFull_SMemHeapAlloc(heapId, 0, 64);
  CHECK(smallBlock != nullptr);
  CHECK((reinterpret_cast<uintptr_t>(smallBlock) & 7u) == 0);
  uint32_t headerSize = 0;
  uint32_t route = 0;
  bool persistent = false;
  CHECK(StormTakeover::Testing::GetLayout(smallBlock, &headerSize, &route,
                                          &persistent));
  CHECK(headerSize == 8);
  CHECK(route ==
        static_cast<uint32_t>(MemoryPool::BackendRoute::Mimalloc));
  CHECK(!persistent);
  CHECK(HookedFull_SMemGetHeapByPtr(smallBlock) == heapId);
  CHECK(HookedFull_SMemHeapSize(heapId, 0, smallBlock) == 64);

  void *zero = HookedFull_SMemHeapReAlloc(heapId, 0, smallBlock, 0);
  CHECK(zero != nullptr);
  CHECK(HookedFull_SMemHeapSize(heapId, 0, zero) == 0);
  const uint32_t expectedAllocated =
      static_cast<uint32_t>(MemoryPool::GetRequestedLiveBytes());
  uint32_t allocatedA = 0;
  uint32_t allocatedB = 0;
  uint32_t allocatedC = 0;
  CHECK(HookedFull_SMemGetAllocated(&allocatedA, &allocatedB, &allocatedC) ==
        expectedAllocated);
  CHECK(allocatedA == expectedAllocated && allocatedB == expectedAllocated &&
        allocatedC == expectedAllocated);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, zero) == 1);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, zero) == 0);
  CHECK(StormTakeover::QueryPointer(zero, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Rejected);

  void *large =
      HookedFull_SMemHeapAlloc(heapId, 0, StormApi::kNativeLargeThreshold);
  CHECK(large != nullptr);
  CHECK((reinterpret_cast<uintptr_t>(large) & 15u) == 0);
  CHECK(StormTakeover::Testing::GetLayout(large, &headerSize, &route,
                                          &persistent));
  CHECK(headerSize == 16);
  CHECK(route == static_cast<uint32_t>(MemoryPool::BackendRoute::Tlsf));
  std::memset(large, 0x3C, StormApi::kNativeLargeThreshold);
  void *grownLarge = HookedFull_SMemHeapReAlloc(
      heapId, 0, large, StormApi::kNativeLargeThreshold + 4096u);
  CHECK(grownLarge != nullptr && grownLarge != large);
  CHECK(static_cast<unsigned char *>(grownLarge)[0] == 0x3C);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, grownLarge) == 1);

  void *corrupt = HookedFull_SMemHeapAlloc(heapId, 0, 32);
  CHECK(corrupt != nullptr);
  auto *checksum = static_cast<unsigned char *>(corrupt) - 1;
  const unsigned char savedChecksum = *checksum;
  *checksum ^= 1u;
  CHECK(HookedFull_SMemHeapFree(heapId, 0, corrupt) == 0);
  CHECK(StormTakeover::QueryPointer(corrupt, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Rejected);
  *checksum = savedChecksum;
  CHECK(HookedFull_SMemHeapFree(heapId, 0, corrupt) == 1);

  void *crossThread = HookedFull_SMemHeapAlloc(heapId, 0, 96);
  CHECK(crossThread != nullptr);
  std::atomic<int> crossThreadResult{0};
  std::thread takeoverFreeThread([&] {
    crossThreadResult.store(
        HookedFull_SMemHeapFree(heapId, 0, crossThread));
  });
  takeoverFreeThread.join();
  CHECK(crossThreadResult.load() == 1);

  void *enumeratedA = HookedFull_SMemHeapAlloc(heapId, 0, 128);
  void *enumeratedB = HookedFull_SMemHeapAlloc(heapId, 0, 192);
  CHECK(enumeratedA != nullptr && enumeratedB != nullptr);
  StormApi::BlockInfo481 blockInfo{};
  blockInfo.structSize = sizeof(blockInfo);
  void *nextBlock = nullptr;
  const void *blockCursor = nullptr;
  uint32_t enumeratedCount = 0;
  uint32_t enumeratedBytes = 0;
  bool sawEnumeratedA = false;
  bool sawEnumeratedB = false;
  for (;;) {
    blockInfo = {};
    blockInfo.structSize = sizeof(blockInfo);
    nextBlock = nullptr;
    if (!HookedFull_SMemFindNextBlock(heapId, blockCursor, &nextBlock,
                                      &blockInfo)) {
      break;
    }
    CHECK(nextBlock != nullptr && nextBlock != blockCursor);
    CHECK(blockInfo.block == nextBlock);
    CHECK(blockInfo.allocated == TRUE);
    CHECK(blockInfo.valid == TRUE);
    sawEnumeratedA = sawEnumeratedA || nextBlock == enumeratedA;
    sawEnumeratedB = sawEnumeratedB || nextBlock == enumeratedB;
    enumeratedBytes += blockInfo.requestedBytes;
    ++enumeratedCount;
    CHECK(enumeratedCount <= 2);
    blockCursor = nextBlock;
  }
  CHECK(enumeratedCount == 2);
  CHECK(enumeratedBytes == 320);
  CHECK(sawEnumeratedA && sawEnumeratedB);

  g_nativeBlockSurvivor.store(0x12345000u, std::memory_order_relaxed);
  blockInfo = {};
  blockInfo.structSize = sizeof(blockInfo);
  nextBlock = nullptr;
  CHECK(HookedFull_SMemFindNextBlock(heapId, nullptr, &nextBlock,
                                     &blockInfo) == 1);
  CHECK(nextBlock == reinterpret_cast<void *>(0x12345000u));
  blockCursor = nextBlock;
  blockInfo = {};
  blockInfo.structSize = sizeof(blockInfo);
  nextBlock = nullptr;
  CHECK(HookedFull_SMemFindNextBlock(heapId, blockCursor, &nextBlock,
                                     &blockInfo) == 1);
  CHECK(nextBlock == enumeratedA || nextBlock == enumeratedB);
  g_nativeBlockSurvivor.store(0, std::memory_order_relaxed);

  StormApi::HeapInfo482 heapInfo{};
  heapInfo.structSize = sizeof(heapInfo);
  uint32_t nextHeapId = 0;
  CHECK(HookedFull_SMemFindNextHeap(0, &nextHeapId, &heapInfo) == 1);
  CHECK(nextHeapId == heapId);
  CHECK(heapInfo.heapId == heapId);
  CHECK(heapInfo.liveAllocationCount == 2);
  CHECK(heapInfo.requestedBytes == 320);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, enumeratedA) == 1);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, enumeratedB) == 1);

  void *ordinary = HookedFull_SMemHeapAlloc(heapId, 0, 256);
  void *kept = HookedFull_SMemHeapAlloc(
      heapId, StormApi::kFlagPersistent, 128);
  CHECK(ordinary != nullptr && kept != nullptr);
  const auto trimBeforeDestroy = MemoryPool::GetExtendedStats();
  CHECK(HookedFull_SMemHeapDestroy(heapId) == 1);
  const auto trimAfterDestroy = MemoryPool::GetExtendedStats();
  CHECK(trimAfterDestroy.trimCount == trimBeforeDestroy.trimCount + 1u);
  CHECK(StormTakeover::QueryPointer(ordinary, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Rejected);
  CHECK(StormTakeover::QueryPointer(kept, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Managed);
  CHECK(HookedFull_SMemHeapSize(heapId, 0, kept) == 128);
  CHECK(HookedFull_SMemHeapFree(heapId, 0, kept) == 1);
  CHECK(HookedFull_SMemHeapDestroy(heapId) == 1);

  const auto stats = StormTakeover::GetRuntimeStats();
  CHECK(stats.liveBlocks == 0);
  CHECK(stats.liveRequestedBytes == 0);
  CHECK(MemoryPool::GetExtendedStats().requestedLiveBytes == 0);
  CHECK(MemoryPool::GetExtendedStats().usableLiveBytes == 0);
  CHECK(MemoryPool::Internal::ValidatePool());
  StormTakeover::Testing::SetNativeApi(nullptr);
  CHECK(StormTakeover::Shutdown());
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(true);
  return true;
}

bool TestFullTakeoverMixedDomainsAndFlags() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "hybrid"));
  CHECK(SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE", "full"));
  CHECK(ConfigureSmallPool());
  CHECK(MemoryPool::Initialize());
  CHECK(StormTakeover::Initialize());
  const StormApi::ResolvedApi mockApi = MockFullApi();
  StormTakeover::Testing::SetNativeApi(&mockApi);
  g_findNextHeapCalls.store(0, std::memory_order_relaxed);
  g_getHeapByCallerCalls.store(0, std::memory_order_relaxed);
  g_heapDestroyResult.store(1, std::memory_order_relaxed);
  g_nativeBlockSurvivor.store(0, std::memory_order_relaxed);

  constexpr const char *callerCacheName = "caller-cache-hot-path";
  void *cachedCallerBlock = HookedFull_SMemAlloc(
      0, 0, 72, callerCacheName, 31337, 0);
  CHECK(cachedCallerBlock != nullptr);
  CHECK(HookedFull_SMemFree(cachedCallerBlock, callerCacheName, 31337, 0) ==
        1);
  CHECK(HookedFull_SMemHeapDestroy(0x12345678u) == 1);
  cachedCallerBlock = HookedFull_SMemAlloc(
      0, 0, 72, callerCacheName, 31337, 0);
  CHECK(cachedCallerBlock != nullptr);
  CHECK(HookedFull_SMemFree(cachedCallerBlock, callerCacheName, 31337, 0) ==
        1);
  std::atomic<bool> crossThreadCallerCacheHit{false};
  std::thread callerCacheThread([&] {
    void* block = HookedFull_SMemAlloc(
        0, 0, 72, callerCacheName, 31337, 0);
    crossThreadCallerCacheHit.store(
        block != nullptr &&
            HookedFull_SMemFree(block, callerCacheName, 31337, 0) == 1,
        std::memory_order_relaxed);
  });
  callerCacheThread.join();
  CHECK(crossThreadCallerCacheHit.load(std::memory_order_relaxed));
  CHECK(g_getHeapByCallerCalls.load(std::memory_order_relaxed) == 1);

  void *zeroed = HookedFull_SMemAlloc(
      0, 0, 48, "zeroed", 1, StormApi::kFlagZeroMemory);
  CHECK(zeroed != nullptr);
  for (size_t index = 0; index < 48; ++index) {
    CHECK(static_cast<unsigned char *>(zeroed)[index] == 0);
  }
  CHECK(HookedFull_SMemFree(zeroed, "zeroed", 1, 0) == 1);

  StormTakeover::Testing::SetOptionFlags(1u | 8u);
  void *debugBlock = HookedFull_SMemAlloc(0, 0, 32, "debug", 2, 0);
  CHECK(debugBlock != nullptr);
  for (size_t index = 0; index < 32; ++index) {
    CHECK(static_cast<unsigned char *>(debugBlock)[index] == 0xEE);
  }
  CHECK(HookedFull_SMemFree(debugBlock, "debug", 2, 0) == 1);
  StormTakeover::Testing::SetOptionFlags(0);

  void *noMove = HookedFull_SMemAlloc(0, 0, 64, "nomove", 3, 0);
  CHECK(noMove != nullptr);
  std::memset(noMove, 0x4A, 64);
  CHECK(HookedFull_SMemReAlloc(
            0, 0, noMove, StormApi::kNativeLargeThreshold, "nomove", 3,
            StormApi::kFlagNoMove) == nullptr);
  CHECK(HookedFull_SMemGetSize(noMove, "nomove", 3) == 64);
  CHECK(static_cast<unsigned char *>(noMove)[0] == 0x4A);
  CHECK(HookedFull_SMemFree(noMove, "nomove", 3, 0) == 1);

  void *crossRoute = HookedFull_SMemAlloc(0, 0, 96, "route", 4, 0);
  CHECK(crossRoute != nullptr);
  std::memset(crossRoute, 0x5B, 96);
  void *largeRoute = HookedFull_SMemReAlloc(
      0, 0, crossRoute, StormApi::kNativeLargeThreshold, "route", 4, 0);
  CHECK(largeRoute != nullptr);
  uint32_t headerSize = 0;
  uint32_t route = 0;
  bool persistent = false;
  CHECK(StormTakeover::Testing::GetLayout(
      largeRoute, &headerSize, &route, &persistent));
  CHECK(headerSize == 16);
  CHECK(route == static_cast<uint32_t>(MemoryPool::BackendRoute::Tlsf));
  CHECK(static_cast<unsigned char *>(largeRoute)[95] == 0x5B);
  void *smallRoute = HookedFull_SMemReAlloc(
      0, 0, largeRoute, 128, "route", 4, 0);
  CHECK(smallRoute != nullptr);
  CHECK(StormTakeover::Testing::GetLayout(
      smallRoute, &headerSize, &route, &persistent));
  CHECK(headerSize == 8);
  CHECK(route == static_cast<uint32_t>(MemoryPool::BackendRoute::Mimalloc));
  CHECK(static_cast<unsigned char *>(smallRoute)[95] == 0x5B);
  CHECK(HookedFull_SMemFree(smallRoute, "route", 4, 0) == 1);

  void *nativeZero = MockFullAlloc(0, 0, 64, "native-zero", 5, 0);
  CHECK(nativeZero != nullptr);
  CHECK(HookedFull_SMemReAlloc(
            0, 0, nativeZero, 0, "native-zero", 5, 0) == nativeZero);
  CHECK(StormTakeover::QueryPointer(nativeZero, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(HookedFull_SMemFree(nativeZero, "native-zero", 5, 0) == 1);

  void *nativeOld = MockAlloc(0, 0, 64, nullptr, 0, 0);
  CHECK(nativeOld != nullptr);
  std::memset(nativeOld, 0x6C, 64);
  void *migrated = HookedFull_SMemReAlloc(
      0, 0, nativeOld, 256, "native-to-managed", 5, 0);
  CHECK(migrated != nullptr);
  CHECK(StormTakeover::QueryPointer(migrated, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Managed);
  CHECK(static_cast<unsigned char *>(migrated)[0] == 0x6C);
  CHECK(HookedFull_SMemFree(migrated, "native-to-managed", 5, 0) == 1);

  void *managedOld = HookedFull_SMemAlloc(
      0, 0, 128, "managed-to-native", 6, 0);
  CHECK(managedOld != nullptr);
  std::memset(managedOld, 0x7D, 128);
  constexpr uint32_t nativeFallbackSize = 33u * 1024u * 1024u;
  void *nativeFallback = HookedFull_SMemReAlloc(
      0, 0, managedOld, nativeFallbackSize, "managed-to-native", 6, 0);
  CHECK(nativeFallback != nullptr);
  CHECK(StormTakeover::QueryPointer(nativeFallback, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(static_cast<unsigned char *>(nativeFallback)[127] == 0x7D);
  CHECK(HookedFull_SMemFree(nativeFallback, "managed-to-native", 6, 0) == 1);

  StormTakeover::Testing::SetOptionFlags(4u);
  void *protectedNative =
      HookedFull_SMemAlloc(0, 0, 80, "protect", 7, 0);
  CHECK(protectedNative != nullptr);
  CHECK(StormTakeover::QueryPointer(protectedNative, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(HookedFull_SMemFree(protectedNative, "protect", 7, 0) == 1);
  StormTakeover::Testing::SetOptionFlags(0);

  const uint32_t explicitHeap = HookedFull_SMemHeapCreate(
      nullptr, 4096, 0, "explicit", 8);
  CHECK(explicitHeap != 0);
  void *explicitManaged =
      HookedFull_SMemHeapAlloc(explicitHeap, 0, 64);
  CHECK(explicitManaged != nullptr);
  CHECK(StormTakeover::QueryPointer(explicitManaged, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Managed);
  CHECK(HookedFull_SMemHeapFree(explicitHeap, 0, explicitManaged) == 1);
  StormTakeover::Testing::SetOptionFlags(4u);
  void *explicitProtected =
      HookedFull_SMemHeapAlloc(explicitHeap, 0, 64);
  CHECK(explicitProtected != nullptr);
  CHECK(StormTakeover::QueryPointer(explicitProtected, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(HookedFull_SMemHeapFree(explicitHeap, 0, explicitProtected) == 1);
  StormTakeover::Testing::SetOptionFlags(0);
  CHECK(HookedFull_SMemHeapDestroy(explicitHeap) == 1);

  StormTakeover::Testing::SetHeapDestroyBatchSize(0);
  StormTakeover::Testing::SetHeapDestroyTaggedSnapshotEnabled(true);
  const uint32_t taggedSnapshotHeap = HookedFull_SMemHeapCreate(
      nullptr, 4096, 0, "tagged-snapshot", 9);
  CHECK(taggedSnapshotHeap != 0);
  StormTakeover::Testing::SetOptionFlags(1u);
  void* taggedSmall =
      HookedFull_SMemHeapAlloc(taggedSnapshotHeap, 0, 64);
  void* taggedLarge = HookedFull_SMemHeapAlloc(
      taggedSnapshotHeap, 0, StormApi::kNativeLargeThreshold);
  CHECK(taggedSmall != nullptr && taggedLarge != nullptr);
  CHECK(StormTakeover::Testing::GetLayout(
      taggedSmall, &headerSize, &route, &persistent));
  CHECK(headerSize == 8u);
  CHECK(route ==
        static_cast<uint32_t>(MemoryPool::BackendRoute::Mimalloc));
  CHECK(StormTakeover::Testing::GetLayout(
      taggedLarge, &headerSize, &route, &persistent));
  CHECK(headerSize == 16u);
  CHECK(route == static_cast<uint32_t>(MemoryPool::BackendRoute::Tlsf));
  StormTakeover::Testing::SetOptionFlags(0);
  const auto taggedStatsBefore = StormTakeover::GetRuntimeStats();
  CHECK(HookedFull_SMemHeapDestroy(taggedSnapshotHeap) == 1);
  const auto taggedStatsAfter = StormTakeover::GetRuntimeStats();
  CHECK(taggedStatsAfter.heapDestroySnapshotBlocks ==
        taggedStatsBefore.heapDestroySnapshotBlocks + 2u);
  CHECK(taggedStatsAfter.heapDestroyBatchCalls ==
        taggedStatsBefore.heapDestroyBatchCalls);
  CHECK(StormTakeover::QueryPointer(taggedSmall, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Rejected);
  CHECK(StormTakeover::QueryPointer(taggedLarge, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Rejected);

  StormTakeover::Testing::SetOptionFlags(4u);
  const uint32_t nativeSurvivorHeap = HookedFull_SMemHeapCreate(
      nullptr, 4096, 0, "native-survivor", 9);
  StormTakeover::Testing::SetOptionFlags(0);
  CHECK(nativeSurvivorHeap != 0);
  g_nativeBlockSurvivor.store(0x12345000u, std::memory_order_relaxed);
  CHECK(HookedFull_SMemHeapDestroy(nativeSurvivorHeap) == 1);
  void* nativeAfterCancelledDestroy =
      HookedFull_SMemHeapAlloc(nativeSurvivorHeap, 0, 32);
  CHECK(nativeAfterCancelledDestroy != nullptr);
  CHECK(HookedFull_SMemHeapFree(
            nativeSurvivorHeap, 0, nativeAfterCancelledDestroy) == 1);
  g_nativeBlockSurvivor.store(0, std::memory_order_relaxed);
  CHECK(HookedFull_SMemHeapDestroy(nativeSurvivorHeap) == 1);
  CHECK(HookedFull_SMemHeapAlloc(nativeSurvivorHeap, 0, 32) == nullptr);

  StormTakeover::Testing::SetOptionFlags(4u);
  const uint32_t nativeFailedDestroyHeap = HookedFull_SMemHeapCreate(
      nullptr, 4096, 0, "native-failed-destroy", 10);
  StormTakeover::Testing::SetOptionFlags(0);
  CHECK(nativeFailedDestroyHeap != 0);
  g_heapDestroyResult.store(0, std::memory_order_relaxed);
  CHECK(HookedFull_SMemHeapDestroy(nativeFailedDestroyHeap) == 0);
  void* nativeAfterFailedDestroy =
      HookedFull_SMemHeapAlloc(nativeFailedDestroyHeap, 0, 32);
  CHECK(nativeAfterFailedDestroy != nullptr);
  CHECK(HookedFull_SMemHeapFree(
            nativeFailedDestroyHeap, 0, nativeAfterFailedDestroy) == 1);
  g_heapDestroyResult.store(1, std::memory_order_relaxed);
  CHECK(HookedFull_SMemHeapDestroy(nativeFailedDestroyHeap) == 1);

  StormApi::HeapInfo482 cursorInfo{};
  cursorInfo.structSize = sizeof(cursorInfo);
  uint32_t cursor = 0;
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 1);
  CHECK(cursor == 0x200u);
  cursorInfo.structSize = sizeof(cursorInfo);
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 1);
  CHECK(cursor == 0x10u);
  cursorInfo.structSize = sizeof(cursorInfo);
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 1);
  CHECK(cursor == 0x12345678u);
  cursorInfo.structSize = sizeof(cursorInfo);
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 1);
  CHECK(cursor == 0xFFFFFFFEu);
  cursorInfo.structSize = sizeof(cursorInfo);
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 0);
  CHECK(cursor == 0);
  CHECK(g_findNextHeapCalls.load(std::memory_order_relaxed) == 3);
  auto enumerationStats = StormTakeover::GetRuntimeStats();
  CHECK(enumerationStats.heapEnumerationCalls == 5);
  CHECK(enumerationStats.heapEnumerationRebuilds == 1);

  cursor = 0;
  cursorInfo.structSize = sizeof(cursorInfo);
  CHECK(HookedFull_SMemFindNextHeap(cursor, &cursor, &cursorInfo) == 1);
  CHECK(cursor == 0x200u);
  CHECK(g_findNextHeapCalls.load(std::memory_order_relaxed) == 6);
  enumerationStats = StormTakeover::GetRuntimeStats();
  CHECK(enumerationStats.heapEnumerationCalls == 6);
  CHECK(enumerationStats.heapEnumerationRebuilds == 2);

  uint32_t allocatedA = 0;
  uint32_t allocatedB = 0;
  uint32_t allocatedC = 0;
  const uint32_t expected =
      1234u + static_cast<uint32_t>(MemoryPool::GetRequestedLiveBytes());
  CHECK(HookedFull_SMemGetAllocated(
            &allocatedA, &allocatedB, &allocatedC) == expected);
  CHECK(allocatedA == expected && allocatedB == expected &&
        allocatedC == expected);

  const auto stats = StormTakeover::GetRuntimeStats();
  CHECK(stats.fallbackCalls >= 2);
  CHECK(stats.liveBlocks == 0);
  CHECK(MemoryPool::GetRequestedLiveBytes() == 0);
  CHECK(MemoryPool::GetUsableLiveBytes() == 0);

  // More unique immutable callers than the fixed cache can retain must take
  // the bounded saturation path instead of turning misses into a full-table
  // scan. Use enough overflow to flush the batched diagnostic counter.
  const auto cacheStatsBefore = StormTakeover::GetRuntimeStats();
  for (int32_t line = 100000; line < 132768; ++line) {
    CHECK(StormTakeover::Testing::ResolveCallerHeap(callerCacheName, line) ==
          0x12345678u);
  }
  const auto cacheStatsAfter = StormTakeover::GetRuntimeStats();
  CHECK(cacheStatsAfter.callerHeapCacheSaturated >=
        cacheStatsBefore.callerHeapCacheSaturated + 4096u);

  char mutableCallerName[] = "caller-cache-dynamic-name";
  const auto bypassStatsBefore = StormTakeover::GetRuntimeStats();
  for (int32_t line = 200000; line < 204096; ++line) {
    CHECK(StormTakeover::Testing::ResolveCallerHeap(mutableCallerName, line) ==
          0x12345678u);
  }
  const auto bypassStatsAfter = StormTakeover::GetRuntimeStats();
  CHECK(bypassStatsAfter.callerHeapCacheBypasses >=
        bypassStatsBefore.callerHeapCacheBypasses + 4096u);

  // Dynamic caller strings cannot safely be retained by pointer. Cache the
  // already-computed heap ID's validated registry slot instead.
  StormTakeover::Testing::SetHeapIdSlotHintCapacity(64);
  const auto heapIdHintStatsBefore = StormTakeover::GetRuntimeStats();
  for (int32_t iteration = 0; iteration < 4097; ++iteration) {
    void* block = HookedFull_SMemAlloc(
        0, 0, 24, mutableCallerName, 200001, 0);
    CHECK(block != nullptr);
    CHECK(HookedFull_SMemFree(block, mutableCallerName, 200001, 0) == 1);
  }
  const auto heapIdHintStatsAfter = StormTakeover::GetRuntimeStats();
  CHECK(heapIdHintStatsAfter.heapIdSlotHintHits >=
        heapIdHintStatsBefore.heapIdSlotHintHits + 4096u);
  StormTakeover::Testing::SetHeapIdSlotHintCapacity(0);

  StormTakeover::Testing::SetNativeApi(nullptr);
  CHECK(StormTakeover::Shutdown());
  MemoryPool::Shutdown();
  return true;
}

bool TestLargeCompatibilityMode() {
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "hybrid"));
  CHECK(SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE", "large"));
  CHECK(ConfigureSmallPool());
  MemoryPool::SetLatencyTrackingEnabled(false);
  CHECK(MemoryPool::Initialize());
  CHECK(MemoryPool::GetBackendKind() == MemoryPool::BackendKind::Hybrid);
  CHECK(MemoryPool::GetExtendedStats().reservedBytes == 4u * 1024u * 1024u);
  CHECK(StormTakeover::Initialize());
  const StormApi::ResolvedApi mockApi = MockFullApi();
  StormTakeover::Testing::SetNativeApi(&mockApi);
  g_getHeapByCallerCalls.store(0, std::memory_order_relaxed);

  void *smallPointer =
      HookedFull_SMemAlloc(0, 0, 128, "large-fast-path", 1, 0);
  CHECK(smallPointer != nullptr);
  CHECK(StormTakeover::QueryPointer(smallPointer, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(HookedFull_SMemFree(smallPointer, "large-fast-path", 1, 0) == 1);

  void* smallReallocNull = HookedFull_SMemReAlloc(
      0, 0, nullptr, 128, "large-realloc-null-fast-path", 2, 0);
  CHECK(smallReallocNull != nullptr);
  CHECK(StormTakeover::QueryPointer(smallReallocNull, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Native);
  CHECK(g_getHeapByCallerCalls.load(std::memory_order_relaxed) == 0);
  CHECK(HookedFull_SMemFree(
            smallReallocNull, "large-realloc-null-fast-path", 2, 0) == 1);

  void *large = HookedFull_SMemAlloc(
      0, 0, StormApi::kNativeLargeThreshold, "large-managed", 2, 0);
  CHECK(large != nullptr);
  CHECK(StormTakeover::QueryPointer(large, nullptr, nullptr) ==
        StormTakeover::BlockQueryResult::Managed);
  std::memset(large, 0x71, StormApi::kNativeLargeThreshold);
  void *moved = HookedFull_SMemReAlloc(
      0, 0, large, StormApi::kNativeLargeThreshold + 4096u,
      "large-managed", 2, 0);
  CHECK(moved != nullptr && moved != large);
  CHECK(static_cast<unsigned char *>(moved)[0] == 0x71);
  CHECK(HookedFull_SMemFree(moved, "large-managed", 2, 0) == 1);

  CHECK(StormTakeover::GetRuntimeStats().liveBlocks == 0);
  CHECK(StormTakeover::Shutdown());
  MemoryPool::Shutdown();
  CHECK(!MemoryPool::IsInitialized());
  return true;
}

bool TestDirectCallerHeapHash() {
  using StormTakeover::Testing::ComputeDirectCallerHeap;
  const auto verify = [&]() {
    CHECK(ComputeDirectCallerHeap(nullptr, 0) == 0x00000001u);
    CHECK(ComputeDirectCallerHeap(nullptr, -1) == 0x7FFFFFFFu);
    CHECK(ComputeDirectCallerHeap("", 0) == 0x7FED7FEDu);
    CHECK(ComputeDirectCallerHeap("StormBreakerCallerHashProbe", 0) ==
          0x353A95DFu);
    CHECK(ComputeDirectCallerHeap("StormBreakerCallerHashProbe", 1) ==
          0x7ACFF88Bu);
    CHECK(ComputeDirectCallerHeap("StormBreakerCallerHashProbe", 42) ==
          0x330F60D8u);
    CHECK(ComputeDirectCallerHeap("war3map.j", 123) == 0x3E8DA0AEu);
    const char highBytes[] = {
        static_cast<char>(0x80), static_cast<char>(0xFE), 0};
    CHECK(ComputeDirectCallerHeap(highBytes, -7) == 0x5F6C4509u);
    return true;
  };
  StormTakeover::Testing::SetDirectCallerByteTableEnabled(false);
  CHECK(verify());
  StormTakeover::Testing::SetDirectCallerByteTableEnabled(true);
  CHECK(verify());
  return true;
}

bool TestRecentFreedHashDistribution() {
  const auto countUnique = [](bool fibonacci, uint32_t addressStep) {
    StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(fibonacci);
    std::vector<uint8_t> seen(65536u, 0);
    uint32_t unique = 0;
    for (uint32_t index = 0; index < 65536u; ++index) {
      const uintptr_t address =
          0x10000000u + static_cast<uintptr_t>(index) * addressStep;
      const uint32_t slot = StormTakeover::Testing::GetRecentFreedSlot(
          reinterpret_cast<const void*>(address));
      if (slot >= seen.size()) {
        return 0u;
      }
      if (seen[slot] == 0) {
        seen[slot] = 1;
        ++unique;
      }
    }
    return unique;
  };

  const uint32_t mixedUnique = countUnique(false, 8u);
  const uint32_t fibonacciUnique = countUnique(true, 8u);
  const uint32_t stridedMixedUnique = countUnique(false, 31u * 8u);
  const uint32_t stridedFibonacciUnique = countUnique(true, 31u * 8u);
  StormTakeover::Testing::SetRecentFreedFibonacciHashEnabled(true);
  CHECK(mixedUnique >= 40000u);
  CHECK(fibonacciUnique >= mixedUnique + 10000u);
  CHECK(stridedFibonacciUnique >= stridedMixedUnique + 10000u);
  return true;
}

bool TestHeapEnumerationSnapshotCache() {
  constexpr uint32_t kManagedHeapCount = 2048;
  constexpr uint32_t kFirstManagedHeapId = 0x10000000u;
  CHECK(SetEnvironmentVariableA("STORMBREAKER_MEMORY_BACKEND", "tlsf"));
  CHECK(SetEnvironmentVariableA("STORMBREAKER_TAKEOVER_MODE", "full"));
  CHECK(ConfigureSmallPool());
  CHECK(MemoryPool::Initialize());
  CHECK(StormTakeover::Initialize());
  const StormApi::ResolvedApi mockApi = MockFullApi();
  StormTakeover::Testing::SetNativeApi(&mockApi);
  g_findNextHeapCalls.store(0, std::memory_order_relaxed);

  for (uint32_t index = 0; index < kManagedHeapCount; ++index) {
    CHECK(StormTakeover::Testing::RegisterManagedHeap(
        kFirstManagedHeapId + index, false, "enumeration-cache", 42));
  }
  void* liveA = HookedFull_SMemHeapAlloc(kFirstManagedHeapId, 0, 128);
  void* liveB = HookedFull_SMemHeapAlloc(kFirstManagedHeapId, 0, 192);
  CHECK(liveA != nullptr && liveB != nullptr);
  const auto expectedPoolStats = MemoryPool::GetExtendedStats();

  uint32_t cursor = 0;
  uint32_t returned = 0;
  for (;;) {
    StormApi::HeapInfo482 info{};
    info.structSize = sizeof(info);
    uint32_t next = 0;
    if (!HookedFull_SMemFindNextHeap(cursor, &next, &info)) {
      CHECK(next == 0);
      break;
    }
    if (returned == 0) {
      CHECK(next == 0x200u);
    } else if (returned == 1) {
      CHECK(next == 0x10u);
    } else if (returned < kManagedHeapCount + 2u) {
      CHECK(next == kFirstManagedHeapId + returned - 2u);
      if (returned == 2u) {
        CHECK(info.liveAllocationCount == 2u);
        CHECK(info.requestedBytes == 320u);
      }
    } else {
      CHECK(returned == kManagedHeapCount + 2u);
      CHECK(next == 0xFFFFFFFEu);
      CHECK(info.committedBytes ==
            static_cast<uint32_t>(expectedPoolStats.committedBytes));
      CHECK(info.reservedBytes ==
            static_cast<uint32_t>(expectedPoolStats.reservedBytes));
    }
    cursor = next;
    ++returned;
    CHECK(returned <= kManagedHeapCount + 3u);
  }

  CHECK(returned == kManagedHeapCount + 3u);
  CHECK(g_findNextHeapCalls.load(std::memory_order_relaxed) == 3);
  const auto stats = StormTakeover::GetRuntimeStats();
  CHECK(stats.heapEnumerationCalls == kManagedHeapCount + 4u);
  CHECK(stats.heapEnumerationRebuilds == 1);

  CHECK(HookedFull_SMemHeapFree(kFirstManagedHeapId, 0, liveA) == 1);
  CHECK(HookedFull_SMemHeapFree(kFirstManagedHeapId, 0, liveB) == 1);

  StormTakeover::Testing::SetNativeApi(nullptr);
  CHECK(StormTakeover::Shutdown());
  MemoryPool::Shutdown();
  return true;
}

bool TestProfilerRing() {
  using namespace StormBreaker::LeakProfiler;
  CHECK(ParseMode("off") == Mode::Off);
  CHECK(ParseMode("sampled") == Mode::Sampled);
  CHECK(ParseMode("FULL") == Mode::Full);
  CHECK(ParseMode("invalid") == Mode::Off);
  HealthSnapshot snapshot{};
  CHECK(Testing::ExerciseRingSaturation(&snapshot));
  CHECK(snapshot.queueDepth == kRingCapacity);
  CHECK(snapshot.dropped == 1);
  CHECK(snapshot.incomplete);
  return true;
}

bool TestVersionProfilesWhenAvailable() {
  wchar_t root[MAX_PATH]{};
  const DWORD length = GetEnvironmentVariableW(
      L"STORMBREAKER_TEST_WAR3_ROOT", root, ARRAYSIZE(root));
  if (length == 0) {
    return true;
  }
  CHECK(length < ARRAYSIZE(root));

  wchar_t stormPath[MAX_PATH]{};
  wchar_t gamePath[MAX_PATH]{};
  wchar_t editorPath[MAX_PATH]{};
  CHECK(_snwprintf_s(stormPath, ARRAYSIZE(stormPath), _TRUNCATE,
                     L"%ls\\Storm.dll", root) > 0);
  CHECK(_snwprintf_s(gamePath, ARRAYSIZE(gamePath), _TRUNCATE,
                     L"%ls\\Game.dll", root) > 0);
  CHECK(_snwprintf_s(editorPath, ARRAYSIZE(editorPath), _TRUNCATE,
                     L"%ls\\WorldEdit.exe", root) > 0);

  HMODULE storm = LoadLibraryExW(
      stormPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
  HMODULE game = LoadLibraryExW(
      gamePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
  HMODULE editor = LoadLibraryExW(
      editorPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
  CHECK(storm != nullptr && game != nullptr && editor != nullptr);

  wchar_t failure[256]{};
  StormApi::ResolvedApi api{};
  const bool stormVerified = StormVersionProfile::ResolveVerified127a(
      storm, &api, failure, ARRAYSIZE(failure));
  if (!stormVerified) {
    std::fwprintf(stderr, L"Storm profile failure: %ls\n", failure);
  }
  CHECK(stormVerified);
  CHECK(api.alloc != nullptr && api.heapReAlloc != nullptr &&
        api.setOption != nullptr);
  CHECK(StormVersionProfile::ResolveVerified127a(
      storm, &api, nullptr, 0));
  CHECK(StormVersionProfile::VerifyGame127a(
      game, failure, ARRAYSIZE(failure)));
  CHECK(StormVersionProfile::VerifyGame127a(game, nullptr, 0));
  CHECK(StormVersionProfile::VerifyWorldEdit127a(
      editor, failure, ARRAYSIZE(failure)));
  CHECK(StormVersionProfile::VerifyWorldEdit127a(editor, nullptr, 0));
  CHECK(!StormVersionProfile::VerifyGame127a(
      storm, failure, ARRAYSIZE(failure)));
  CHECK(!StormVersionProfile::VerifyGame127a(storm, nullptr, 0));

  FreeLibrary(editor);
  FreeLibrary(game);
  FreeLibrary(storm);
  return true;
}

} // namespace

int main() {
  if (!TestLoggerRotationWithFullBackupSet()) {
    std::fprintf(stderr, "Logger rotation regression test failed\n");
    return 1;
  }
  LoggerConfig loggerConfig = Logger::GetReleaseConfig();
  loggerConfig.enableConsole = false;
  loggerConfig.enableDebugOutput = false;
  loggerConfig.enableFile = false;
  if (!Logger::GetInstance().Initialize(loggerConfig)) {
    std::fprintf(stderr, "Logger initialization failed\n");
    return 1;
  }

  const bool ok = TestRegistrySlotHintIdentityAndEpoch() &&
                   TestRegistryHazardPinning() &&
                   TestRegistryFullTableMembershipFilter() &&
                  TestHookContract() && TestMimallocBackend() &&
         TestConditionalRoutedFree() && TestRoutedBatchFree() &&
         TestDetailedCounterBatching() &&
         TestTlsfPoolRangeIndex() && TestTlsfMainPoolDecommit() &&
         TestTlsfShardedBackend() &&
                  TestFullTakeoverContract() &&
                  TestFullTakeoverMixedDomainsAndFlags() &&
                   TestLargeCompatibilityMode() &&
                   TestDirectCallerHeapHash() &&
                   TestRecentFreedHashDistribution() &&
                   TestHeapEnumerationSnapshotCache() &&
                  TestProfilerRing() && TestVersionProfilesWhenAvailable();
  Logger::GetInstance().Shutdown();
  return ok ? 0 : 1;
}
