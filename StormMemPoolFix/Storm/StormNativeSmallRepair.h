#pragma once

#include "StormApi.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace StormNativeSmallRepair {

enum class Mode : uint8_t {
  Off,
  Search,
  Coalesce,
};

#pragma pack(push, 4)
struct NativeFreeBlock {
  uint16_t totalBytes;
  uint8_t alignmentPadding;
  uint8_t flags;
  NativeFreeBlock* next;
};

struct NativeArena {
  NativeArena* next;
  uint32_t heapId;
  uint32_t bucketIndex;
  uint32_t blockSignature;
  uint32_t currentArena;
  uint32_t liveAllocationCount;
  uint32_t requestedLiveBytes;
  uint8_t* dataStart;
  uint8_t* bumpEnd;
  uint32_t adjacentFreeHint;
  uint32_t commitGranularity;
  uint32_t committedBytes;
  uint32_t reservedBytes;
  uint32_t externalRequestedBytes;
  uint32_t allocationCalls;
  uint32_t freeCalls;
  uint32_t reserved64;
  NativeFreeBlock* freeBins[9];
  int32_t sourceLine;
  char sourceName[1];
};
#pragma pack(pop)

static_assert(sizeof(NativeFreeBlock) == 8,
              "Storm small free block ABI changed");
static_assert(offsetof(NativeArena, dataStart) == 28,
              "Storm arena dataStart offset changed");
static_assert(offsetof(NativeArena, freeBins) == 68,
              "Storm arena free-bin offset changed");
static_assert(offsetof(NativeArena, sourceName) == 108,
              "Storm arena source-name offset changed");

enum class RepairResult : uint8_t {
  FitAlreadyAvailable,
  PromotedHigherBin,
  NoFit,
  InvalidArena,
};

struct RuntimeStats {
  uint32_t calls;
  uint32_t promotions;
  uint32_t rebuilds;
  uint32_t invalidArenaSkips;
  uint32_t bypasses;
};

// Pure free-list operation used by the hook and deterministic tests.
RepairResult RepairFreeLists(NativeArena* arena,
                             uint32_t requiredTotalBytes) noexcept;

bool Configure(const StormApi::ResolvedApi& api) noexcept;
LONG Attach() noexcept;
LONG Detach() noexcept;
void Reset() noexcept;

Mode GetMode() noexcept;
const char* GetModeName() noexcept;
RuntimeStats GetRuntimeStats() noexcept;

} // namespace StormNativeSmallRepair
