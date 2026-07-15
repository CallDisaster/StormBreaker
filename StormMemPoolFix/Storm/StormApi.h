#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>

#if !defined(_WIN32) || defined(_WIN64)
#error StormBreaker supports only the Warcraft III Win32/x86 ABI.
#endif

namespace StormApi {

constexpr uint16_t kOrdinalAlloc = 401;
constexpr uint16_t kOrdinalFree = 403;
constexpr uint16_t kOrdinalGetSize = 404;
constexpr uint16_t kOrdinalReAlloc = 405;
constexpr uint16_t kOrdinalGetAllocated = 406;
constexpr uint16_t kOrdinalFindNextBlock = 481;
constexpr uint16_t kOrdinalFindNextHeap = 482;
constexpr uint16_t kOrdinalGetHeapByCaller = 483;
constexpr uint16_t kOrdinalGetHeapByPtr = 484;
constexpr uint16_t kOrdinalHeapAlloc = 485;
constexpr uint16_t kOrdinalHeapCreate = 486;
constexpr uint16_t kOrdinalHeapDestroy = 487;
constexpr uint16_t kOrdinalHeapFree = 488;
constexpr uint16_t kOrdinalHeapReAlloc = 489;
constexpr uint16_t kOrdinalHeapSize = 490;
constexpr uint16_t kOrdinalSetOption = 496;

constexpr uint32_t kFlagZeroMemory = 0x00000008u;
constexpr uint32_t kFlagNoMove = 0x00000010u;
constexpr uint32_t kFlagSuppressLeakWarning = 0x04000000u;
constexpr uint32_t kFlagPersistent = 0x08000000u;
constexpr uint32_t kNativeLargeThreshold = 0xFE7Cu;

#pragma pack(push, 4)
struct BlockInfo481 {
  uint32_t structSize;
  void* block;
  BOOL allocated;
  BOOL valid;
  uint32_t requestedBytes;
  uint32_t overheadBytes;
  uint32_t reserved;
};

struct HeapInfo482 {
  uint32_t structSize;
  uint32_t heapId;
  char sourceName[260];
  int32_t sourceLine;
  uint32_t reserved272;
  uint32_t committedBytes;
  uint32_t reservedBytes;
  uint32_t maxAllocationSize;
  uint32_t liveAllocationCount;
  uint32_t requestedBytes;
};
#pragma pack(pop)

static_assert(sizeof(void*) == 4 && sizeof(size_t) == 4,
              "Storm memory ABI requires Win32 pointers");
static_assert(sizeof(BlockInfo481) == 28,
              "ordinal 481 block record ABI changed");
static_assert(sizeof(HeapInfo482) == 296,
              "ordinal 482 heap record ABI changed");
static_assert(offsetof(HeapInfo482, committedBytes) == 276,
              "ordinal 482 committed field moved");
static_assert(offsetof(HeapInfo482, requestedBytes) == 292,
              "ordinal 482 requested field moved");

using AllocFn = void*(__fastcall*)(int, int, uint32_t, const char*, int32_t,
                                   uint32_t);
using FreeFn = int(__stdcall*)(void*, const char*, int32_t, uint32_t);
using GetSizeFn = int(__stdcall*)(const void*, const char*, int32_t);
using ReAllocFn = void*(__fastcall*)(int, int, void*, uint32_t, const char*,
                                     int32_t, uint32_t);
using GetAllocatedFn = uint32_t(__stdcall*)(uint32_t*, uint32_t*, uint32_t*);
using FindNextBlockFn = int(__stdcall*)(uint32_t, const void*, void**,
                                        BlockInfo481*);
using FindNextHeapFn = int(__stdcall*)(uint32_t, uint32_t*, HeapInfo482*);
using GetHeapByCallerFn = uint32_t(__stdcall*)(const char*, int32_t);
using GetHeapByPtrFn = uint32_t(__stdcall*)(const void*);
using HeapAllocFn = void*(__stdcall*)(uint32_t, uint32_t, uint32_t);
using HeapCreateFn = uint32_t(__stdcall*)(void*, uint32_t, uint32_t,
                                          const char*, int32_t);
using HeapDestroyFn = int(__stdcall*)(uint32_t);
using HeapFreeFn = int(__stdcall*)(uint32_t, uint32_t, void*);
using HeapReAllocFn = void*(__stdcall*)(uint32_t, uint32_t, void*, uint32_t);
using HeapSizeFn = int(__stdcall*)(uint32_t, uint32_t, const void*);
using SetOptionFn = int(__stdcall*)(uint32_t, uint32_t);
using CleanupAllFn = void(__stdcall*)();

struct ResolvedApi {
  HMODULE module = nullptr;
  uintptr_t base = 0;
  AllocFn alloc = nullptr;
  FreeFn free = nullptr;
  GetSizeFn getSize = nullptr;
  ReAllocFn reAlloc = nullptr;
  GetAllocatedFn getAllocated = nullptr;
  FindNextBlockFn findNextBlock = nullptr;
  FindNextHeapFn findNextHeap = nullptr;
  GetHeapByCallerFn getHeapByCaller = nullptr;
  GetHeapByPtrFn getHeapByPtr = nullptr;
  HeapAllocFn heapAlloc = nullptr;
  HeapCreateFn heapCreate = nullptr;
  HeapDestroyFn heapDestroy = nullptr;
  HeapFreeFn heapFree = nullptr;
  HeapReAllocFn heapReAlloc = nullptr;
  HeapSizeFn heapSize = nullptr;
  SetOptionFn setOption = nullptr;
  CleanupAllFn cleanupAll = nullptr;

  volatile uint8_t* memorySystemInitialized = nullptr;
  volatile uint32_t* debugMemoryEnabled = nullptr;
  volatile uint32_t* errorHandlingEnabled = nullptr;
  volatile uint32_t* protectMemoryEnabled = nullptr;
  volatile uint32_t* fillPatternEnabled = nullptr;
  volatile uint32_t* reallocShuffleEnabled = nullptr;
  volatile uint32_t* nativeAllocatedBytes = nullptr;
};

} // namespace StormApi
