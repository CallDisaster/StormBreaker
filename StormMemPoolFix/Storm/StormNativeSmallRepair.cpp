#include "pch.h"
#include "StormNativeSmallRepair.h"

#include <detours.h>

#include <cstring>

namespace StormNativeSmallRepair {
namespace {

constexpr uint32_t kAllocPageRva = 0x2A510u;
constexpr uint32_t kRebuildFreeListRva = 0x2A920u;
constexpr uint8_t kFreeFlag = 0x02u;
constexpr uint32_t kSmallRequestLimit = 0xFE7Bu;
constexpr uint32_t kMaximumArenaReserve = 0x10000000u;

using AllocPageFn = void*(__fastcall*)(NativeArena*, uint32_t, uint32_t);
using RebuildFreeListFn = void(__fastcall*)(NativeArena*);

Mode g_mode = Mode::Off;
AllocPageFn g_originalAllocPage = nullptr;
RebuildFreeListFn g_rebuildFreeList = nullptr;
volatile uint32_t* g_debugMemoryEnabled = nullptr;
volatile uint32_t* g_protectMemoryEnabled = nullptr;
volatile LONG g_calls = 0;
volatile LONG g_promotions = 0;
volatile LONG g_rebuilds = 0;
volatile LONG g_invalidArenaSkips = 0;
volatile LONG g_bypasses = 0;

struct Candidate {
  NativeFreeBlock* block = nullptr;
  NativeFreeBlock** link = nullptr;
  bool valid = true;
};

bool ReadMode(Mode* mode) noexcept {
  char value[32]{};
  const DWORD length = GetEnvironmentVariableA(
      "STORMBREAKER_NATIVE_SMALL_REPAIR", value,
      static_cast<DWORD>(sizeof(value)));
  if (length == 0 || _stricmp(value, "off") == 0) {
    *mode = Mode::Off;
    return true;
  }
  if (length >= sizeof(value)) {
    return false;
  }
  if (_stricmp(value, "search") == 0) {
    *mode = Mode::Search;
    return true;
  }
  if (_stricmp(value, "coalesce") == 0) {
    *mode = Mode::Coalesce;
    return true;
  }
  return false;
}

bool IsArenaLayoutPlausible(const NativeArena* arena) noexcept {
  if (!arena || !arena->dataStart || !arena->bumpEnd ||
      arena->reservedBytes < 0x1000u ||
      arena->reservedBytes > kMaximumArenaReserve ||
      arena->committedBytes > arena->reservedBytes) {
    return false;
  }

  const uint64_t base = reinterpret_cast<uintptr_t>(arena);
  const uint64_t data = reinterpret_cast<uintptr_t>(arena->dataStart);
  const uint64_t bump = reinterpret_cast<uintptr_t>(arena->bumpEnd);
  const uint64_t end = base + arena->reservedBytes;
  return data >= base + 108u && data <= bump && bump <= end &&
         (data & 7u) == 0 && (bump & 7u) == 0;
}

bool IsFreeBlockPlausible(const NativeArena* arena,
                          const NativeFreeBlock* block) noexcept {
  if (!block) {
    return false;
  }
  const uintptr_t address = reinterpret_cast<uintptr_t>(block);
  const uintptr_t data = reinterpret_cast<uintptr_t>(arena->dataStart);
  const uintptr_t bump = reinterpret_cast<uintptr_t>(arena->bumpEnd);
  const uint32_t total = block->totalBytes;
  return address >= data && address + sizeof(NativeFreeBlock) <= bump &&
         (address & 7u) == 0 && total >= sizeof(NativeFreeBlock) &&
         (total & 7u) == 0 && address + total <= bump &&
         (block->flags & kFreeFlag) != 0;
}

Candidate FindCandidate(NativeArena* arena, uint32_t bin,
                        uint32_t required) noexcept {
  Candidate result{};
  NativeFreeBlock** link = &arena->freeBins[bin];
  uint32_t bestRemainder = 0x7FFFFFFFu;
  uint32_t tolerance = 16u;
  const uintptr_t data = reinterpret_cast<uintptr_t>(arena->dataStart);
  const uintptr_t bump = reinterpret_cast<uintptr_t>(arena->bumpEnd);
  const size_t maximumNodes = (bump - data) / 8u + 1u;

  for (size_t visited = 0; *link; ++visited) {
    if (visited >= maximumNodes ||
        !IsFreeBlockPlausible(arena, *link)) {
      result.valid = false;
      result.block = nullptr;
      result.link = nullptr;
      return result;
    }
    NativeFreeBlock* block = *link;
    const uint32_t rawBlockBin = block->totalBytes >> 5;
    const uint32_t blockBin = rawBlockBin < 8u ? rawBlockBin : 8u;
    if (blockBin != bin) {
      result.valid = false;
      result.block = nullptr;
      result.link = nullptr;
      return result;
    }
    if (block->totalBytes >= required) {
      const uint32_t remainder = block->totalBytes - required;
      if (remainder < bestRemainder) {
        result.block = block;
        result.link = link;
        bestRemainder = remainder;
        if (remainder < tolerance) {
          break;
        }
        tolerance += 4u;
      }
    }
    link = &block->next;
  }
  return result;
}

uint32_t RequiredTotalBytes(uint32_t requested, bool debug) noexcept {
  const uint32_t unaligned = requested + 8u + (debug ? 2u : 0u);
  return (unaligned + 7u) & ~7u;
}

void* __fastcall HookedAllocPage(NativeArena* arena, uint32_t requested,
                                 uint32_t headerFlags) noexcept {
  InterlockedIncrement(&g_calls);
  if (!g_originalAllocPage) {
    return nullptr;
  }

  if (!arena || requested > kSmallRequestLimit ||
      !g_protectMemoryEnabled || *g_protectMemoryEnabled != 0) {
    InterlockedIncrement(&g_bypasses);
    return g_originalAllocPage(arena, requested, headerFlags);
  }

  const bool debug = g_debugMemoryEnabled && *g_debugMemoryEnabled != 0;
  const uint32_t required = RequiredTotalBytes(requested, debug);
  if (!IsArenaLayoutPlausible(arena)) {
    InterlockedIncrement(&g_invalidArenaSkips);
    return g_originalAllocPage(arena, requested, headerFlags);
  }

  const uint32_t rawTarget = required >> 5;
  const uint32_t target = rawTarget < 8u ? rawTarget : 8u;
  NativeFreeBlock* const head = arena->freeBins[target];
  if (!head) {
    // Native Storm already checks higher bins and performs its normal
    // hint>=4 rebuild when the exact target bin is empty.
    InterlockedIncrement(&g_bypasses);
    return g_originalAllocPage(arena, requested, headerFlags);
  }
  if (!IsFreeBlockPlausible(arena, head)) {
    InterlockedIncrement(&g_invalidArenaSkips);
    return g_originalAllocPage(arena, requested, headerFlags);
  }
  const uint32_t rawHeadBin = head->totalBytes >> 5;
  const uint32_t headBin = rawHeadBin < 8u ? rawHeadBin : 8u;
  if (headBin != target) {
    InterlockedIncrement(&g_invalidArenaSkips);
    return g_originalAllocPage(arena, requested, headerFlags);
  }
  if (head->totalBytes >= required ||
      (target == 8u && g_mode == Mode::Search)) {
    InterlockedIncrement(&g_bypasses);
    return g_originalAllocPage(arena, requested, headerFlags);
  }

  RepairResult result = RepairFreeLists(arena, required);
  if (result == RepairResult::PromotedHigherBin) {
    InterlockedIncrement(&g_promotions);
  } else if (result == RepairResult::InvalidArena) {
    InterlockedIncrement(&g_invalidArenaSkips);
  } else if (result == RepairResult::NoFit &&
             g_mode == Mode::Coalesce && arena->adjacentFreeHint >= 4u &&
             g_rebuildFreeList) {
    g_rebuildFreeList(arena);
    InterlockedIncrement(&g_rebuilds);
    result = RepairFreeLists(arena, required);
    if (result == RepairResult::PromotedHigherBin) {
      InterlockedIncrement(&g_promotions);
    } else if (result == RepairResult::InvalidArena) {
      InterlockedIncrement(&g_invalidArenaSkips);
    }
  }
  return g_originalAllocPage(arena, requested, headerFlags);
}

} // namespace

RepairResult RepairFreeLists(NativeArena* arena,
                             uint32_t requiredTotalBytes) noexcept {
  if (!IsArenaLayoutPlausible(arena) || requiredTotalBytes < 8u ||
      requiredTotalBytes > 0xFFFFu || (requiredTotalBytes & 7u) != 0) {
    return RepairResult::InvalidArena;
  }

  const uint32_t rawTarget = requiredTotalBytes >> 5;
  const uint32_t target = rawTarget < 8u ? rawTarget : 8u;
  Candidate targetCandidate = FindCandidate(arena, target,
                                            requiredTotalBytes);
  if (!targetCandidate.valid) {
    return RepairResult::InvalidArena;
  }
  if (targetCandidate.block) {
    return RepairResult::FitAlreadyAvailable;
  }

  // If the target bin is empty, Storm already advances to the next non-empty
  // bin. The defect occurs only when a non-empty target bin has no fitting
  // block and masks a fitting higher bin.
  if (!arena->freeBins[target]) {
    for (uint32_t bin = target + 1u; bin < 9u; ++bin) {
      if (!arena->freeBins[bin]) {
        continue;
      }
      Candidate higher = FindCandidate(arena, bin, requiredTotalBytes);
      if (!higher.valid) {
        return RepairResult::InvalidArena;
      }
      return higher.block ? RepairResult::FitAlreadyAvailable
                          : RepairResult::NoFit;
    }
    return RepairResult::NoFit;
  }

  for (uint32_t bin = target + 1u; bin < 9u; ++bin) {
    if (!arena->freeBins[bin]) {
      continue;
    }
    Candidate higher = FindCandidate(arena, bin, requiredTotalBytes);
    if (!higher.valid) {
      return RepairResult::InvalidArena;
    }
    if (!higher.block) {
      continue;
    }
    *higher.link = higher.block->next;
    higher.block->next = arena->freeBins[target];
    arena->freeBins[target] = higher.block;
    return RepairResult::PromotedHigherBin;
  }
  return RepairResult::NoFit;
}

bool Configure(const StormApi::ResolvedApi& api) noexcept {
  g_mode = Mode::Off;
  g_originalAllocPage = nullptr;
  g_rebuildFreeList = nullptr;
  g_debugMemoryEnabled = nullptr;
  g_protectMemoryEnabled = nullptr;
  InterlockedExchange(&g_calls, 0);
  InterlockedExchange(&g_promotions, 0);
  InterlockedExchange(&g_rebuilds, 0);
  InterlockedExchange(&g_invalidArenaSkips, 0);
  InterlockedExchange(&g_bypasses, 0);

  Mode requestedMode = Mode::Off;
  if (!ReadMode(&requestedMode)) {
    return false;
  }
  g_mode = requestedMode;
  g_debugMemoryEnabled = api.debugMemoryEnabled;
  g_protectMemoryEnabled = api.protectMemoryEnabled;
  if (g_mode == Mode::Off) {
    return true;
  }
  if (!api.module || !api.base || !g_debugMemoryEnabled ||
      !g_protectMemoryEnabled) {
    return false;
  }

  auto* allocPage = reinterpret_cast<uint8_t*>(api.base + kAllocPageRva);
  auto* rebuild = reinterpret_cast<uint8_t*>(api.base + kRebuildFreeListRva);
  constexpr uint8_t kAllocPageProlog[] = {
      0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x83, 0x3D};
  constexpr uint8_t kRebuildProlog[] = {
      0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x2C, 0xA1};
  if (std::memcmp(allocPage, kAllocPageProlog,
                  sizeof(kAllocPageProlog)) != 0 ||
      std::memcmp(rebuild, kRebuildProlog, sizeof(kRebuildProlog)) != 0) {
    g_mode = Mode::Off;
    return false;
  }
  g_originalAllocPage = reinterpret_cast<AllocPageFn>(allocPage);
  g_rebuildFreeList = reinterpret_cast<RebuildFreeListFn>(rebuild);
  return true;
}

LONG Attach() noexcept {
  if (g_mode == Mode::Off) {
    return NO_ERROR;
  }
  if (!g_originalAllocPage) {
    return ERROR_INVALID_FUNCTION;
  }
  return DetourAttach(&reinterpret_cast<PVOID&>(g_originalAllocPage),
                      reinterpret_cast<PVOID>(HookedAllocPage));
}

LONG Detach() noexcept {
  if (g_mode == Mode::Off) {
    return NO_ERROR;
  }
  if (!g_originalAllocPage) {
    return ERROR_INVALID_FUNCTION;
  }
  return DetourDetach(&reinterpret_cast<PVOID&>(g_originalAllocPage),
                      reinterpret_cast<PVOID>(HookedAllocPage));
}

void Reset() noexcept {
  g_mode = Mode::Off;
  g_originalAllocPage = nullptr;
  g_rebuildFreeList = nullptr;
  g_debugMemoryEnabled = nullptr;
  g_protectMemoryEnabled = nullptr;
}

Mode GetMode() noexcept { return g_mode; }

const char* GetModeName() noexcept {
  switch (g_mode) {
  case Mode::Search:
    return "search";
  case Mode::Coalesce:
    return "coalesce";
  default:
    return "off";
  }
}

RuntimeStats GetRuntimeStats() noexcept {
  return {static_cast<uint32_t>(InterlockedCompareExchange(&g_calls, 0, 0)),
          static_cast<uint32_t>(InterlockedCompareExchange(&g_promotions, 0, 0)),
          static_cast<uint32_t>(InterlockedCompareExchange(&g_rebuilds, 0, 0)),
          static_cast<uint32_t>(InterlockedCompareExchange(&g_invalidArenaSkips, 0, 0)),
          static_cast<uint32_t>(InterlockedCompareExchange(&g_bypasses, 0, 0))};
}

} // namespace StormNativeSmallRepair
