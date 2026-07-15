#pragma once

#include "Base/LeakProfiler.h"
#include "StormApi.h"
#include "StormHeapRegistry.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace StormTakeover {

enum class TakeoverMode : uint32_t {
  Large = 0,
  Size32K = 1,
  Size8K = 2,
  Size2K = 3,
  Size256 = 4,
  Full = 5,
};

enum class BlockQueryResult : uint8_t {
  Native,
  Managed,
  Rejected,
};

struct RuntimeStats {
  uint64_t apiCalls = 0;
  uint64_t managedCalls = 0;
  uint64_t nativeCalls = 0;
  uint64_t fallbackCalls = 0;
  uint64_t degradedCalls = 0;
  uint64_t rejectedPointers = 0;
  uint64_t failures = 0;
  uint64_t liveBlocks = 0;
  uint64_t liveRequestedBytes = 0;
  uint64_t blockEnumerationCalls = 0;
  uint64_t blockEnumerationSnapshotBuilds = 0;
  uint64_t heapEnumerationCalls = 0;
  uint64_t heapEnumerationRebuilds = 0;
  uint64_t heapDestroySnapshots = 0;
  uint64_t heapDestroySnapshotBlocks = 0;
  uint64_t heapDestroyBatchCalls = 0;
  uint64_t heapDestroyBatchBlocks = 0;
  uint64_t heapDestroyBatchFallbacks = 0;
  uint64_t callerHeapCacheHits = 0;
  uint64_t callerHeapCacheMisses = 0;
  uint64_t callerHeapCacheBypasses = 0;
  uint64_t callerHeapCacheSaturated = 0;
  uint64_t heapIdSlotHintHits = 0;
  uint64_t heapIdSlotHintMisses = 0;
  uint32_t callerHeapCacheEntries = 0;
  uint32_t lastHeapId = 0;
  uint32_t lastStormFlags = 0;
  uint32_t lastRequestedSize = 0;
  uint16_t lastOrdinal = 0;
  StormBreaker::LeakProfiler::BackendRoute lastRoute =
      StormBreaker::LeakProfiler::BackendRoute::Unknown;
  StormBreaker::LeakProfiler::DegradedReason lastDegradedReason =
      StormBreaker::LeakProfiler::DegradedReason::None;
  bool directCallerHash = false;
  uint32_t threshold = 0;
  uint32_t optionFlags = 0;
  TakeoverMode mode = TakeoverMode::Large;
  bool initialized = false;
  bool installed = false;
};

bool Initialize() noexcept;
bool Shutdown() noexcept;
bool Install(HMODULE stormModule) noexcept;
bool Uninstall() noexcept;
bool IsInstalled() noexcept;
bool IsInitialized() noexcept;
bool CanCleanShutdown() noexcept;

RuntimeStats GetRuntimeStats() noexcept;
StormHeapRegistry::RegistryStats GetRegistryStats() noexcept;
StormBreaker::LeakProfiler::TakeoverSnapshot GetTelemetrySnapshot() noexcept;
TakeoverMode GetMode() noexcept;
uint32_t GetThreshold() noexcept;
const char* ModeName(TakeoverMode mode) noexcept;
const char* RouteName(
    StormBreaker::LeakProfiler::BackendRoute route) noexcept;
const char* DegradedReasonName(
    StormBreaker::LeakProfiler::DegradedReason reason) noexcept;

// Test-facing ownership helpers. They do not invoke a native Storm API.
BlockQueryResult QueryPointer(const void* pointer, uint32_t* requestedSize,
                              uint32_t* heapId) noexcept;

#if defined(STORMBREAKER_TESTING)
namespace Testing {
struct InPlaceReallocateStats {
  uint64_t attempts = 0;
  uint64_t successes = 0;
  uint64_t misses = 0;
};

bool RegisterManagedHeap(uint32_t heapId, bool explicitHeap,
                         const char* name, uint32_t sourceLine) noexcept;
bool GetLayout(const void* pointer, uint32_t* headerSize,
               uint32_t* route, bool* persistent) noexcept;
void SetOptionFlags(uint32_t optionFlags) noexcept;
void SetNativeApi(const StormApi::ResolvedApi* api) noexcept;
void SetFastFreeEnabled(bool enabled) noexcept;
void SetRegistryAccountingEnabled(bool enabled) noexcept;
void SetMainRegistryAccountingEnabled(bool enabled) noexcept;
void SetCallerSlotHintEnabled(bool enabled) noexcept;
void SetDirectCallerHashEnabled(bool enabled) noexcept;
void SetDirectCallerByteTableEnabled(bool enabled) noexcept;
void SetRecentFreedFibonacciHashEnabled(bool enabled) noexcept;
void SetCallerCacheWays(uint32_t ways) noexcept;
void SetCallerThreadCacheCapacity(uint32_t capacity) noexcept;
void SetHeapIdSlotHintCapacity(uint32_t capacity) noexcept;
void SetMainHeapPinEnabled(bool enabled) noexcept;
void SetInPlaceReallocateEnabled(bool enabled) noexcept;
void SetHeapDestroyBatchSize(uint32_t batchSize) noexcept;
void SetHeapDestroyTaggedSnapshotEnabled(bool enabled) noexcept;
InPlaceReallocateStats GetInPlaceReallocateStats() noexcept;
uint32_t ResolveCallerHeap(const char* sourceFile,
                           int32_t sourceLine) noexcept;
uint32_t ComputeDirectCallerHeap(const char* sourceFile,
                                 int32_t sourceLine) noexcept;
uint32_t GetRecentFreedSlot(const void* pointer) noexcept;
} // namespace Testing
#endif

} // namespace StormTakeover

extern "C" {
void* __fastcall HookedFull_SMemAlloc(int ecx, int edx, uint32_t size,
                                      const char* sourceFile,
                                      int32_t sourceLine, uint32_t flags);
int __stdcall HookedFull_SMemFree(void* pointer, const char* sourceFile,
                                  int32_t sourceLine, uint32_t flags);
int __stdcall HookedFull_SMemGetSize(const void* pointer,
                                     const char* sourceFile,
                                     int32_t sourceLine);
void* __fastcall HookedFull_SMemReAlloc(int ecx, int edx, void* pointer,
                                        uint32_t newSize,
                                        const char* sourceFile,
                                        int32_t sourceLine, uint32_t flags);
uint32_t __stdcall HookedFull_SMemGetAllocated(uint32_t* outA,
                                               uint32_t* outB,
                                               uint32_t* outC);
int __stdcall HookedFull_SMemFindNextBlock(uint32_t heapId,
                                           const void* previousBlock,
                                           void** nextBlock,
                                           StormApi::BlockInfo481* info);
int __stdcall HookedFull_SMemFindNextHeap(uint32_t currentHeapId,
                                          uint32_t* nextHeapId,
                                          StormApi::HeapInfo482* info);
uint32_t __stdcall HookedFull_SMemGetHeapByCaller(const char* sourceFile,
                                                  int32_t sourceLine);
uint32_t __stdcall HookedFull_SMemGetHeapByPtr(const void* pointer);
void* __stdcall HookedFull_SMemHeapAlloc(uint32_t heapId, uint32_t flags,
                                         uint32_t size);
uint32_t __stdcall HookedFull_SMemHeapCreate(void* baseAddress,
                                             uint32_t initialSize,
                                             uint32_t flags,
                                             const char* sourceFile,
                                             int32_t sourceLine);
int __stdcall HookedFull_SMemHeapDestroy(uint32_t heapId);
int __stdcall HookedFull_SMemHeapFree(uint32_t heapId, uint32_t flags,
                                      void* pointer);
void* __stdcall HookedFull_SMemHeapReAlloc(uint32_t heapId, uint32_t flags,
                                           void* pointer, uint32_t newSize);
int __stdcall HookedFull_SMemHeapSize(uint32_t heapId, uint32_t flags,
                                      const void* pointer);
int __stdcall HookedFull_SMemSetOption(uint32_t valueBits,
                                       uint32_t maskBits);
}
