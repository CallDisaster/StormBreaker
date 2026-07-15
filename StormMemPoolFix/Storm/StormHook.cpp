// ======================== StormHook.cpp 完整修复版本 ========================
#include "pch.h"
#include "StormHook.h"
#include "Base/LeakProfiler.h"
#include "Base/Logger.h"
#include "Base/MemorySafety.h"
#include "MemoryPool.h"
#include "StormOffsets.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <detours.h>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

// ======================== 全局变量定义 ========================
Storm_MemAlloc_t g_origStormAlloc = nullptr;
Storm_MemFree_t g_origStormFree = nullptr;
Storm_MemReAlloc_t g_origStormReAlloc = nullptr;
Storm_MemGetSize_t g_origStormGetSize = nullptr;
StormHeap_CleanupAll_t g_origCleanupAll = nullptr;
ResetMemoryManager_t g_origResetMemoryManager = nullptr;

// ======================== 内部状态管理 ========================
namespace {
// (已移除 unordered_map 管理表，改为 16 字节 O(1) Header 验证)

// 全局状态标志
std::atomic<bool> g_initialized(false);
std::atomic<uint32_t> g_unsafeDepth(0);
std::atomic<uint32_t> g_cleanupDepth(0);
std::atomic<uint32_t> g_resetDepth(0);

// 统计信息
std::atomic<size_t> g_totalAllocatedBlocks(0);
std::atomic<size_t> g_totalAllocatedBytes(0);
std::atomic<size_t> g_totalFreedBlocks(0);
std::atomic<size_t> g_totalFreedBytes(0);
std::atomic<size_t> g_liveManagedBlocks(0);
std::atomic<size_t> g_liveManagedBytes(0);
std::atomic<bool> g_runtimeStatsEnabled(false);

constexpr size_t kStormNativeLargeBlockThreshold = 0xFE7C;

// 大块分配阈值：Storm.dll 在 size > 0xFE7B 时进入 VirtualAlloc 大块路径。
std::atomic<size_t> g_largeBlockThreshold{kStormNativeLargeBlockThreshold};
std::atomic<size_t> g_managedAllocationFailures{0};

std::atomic<uint64_t> g_hookAllocCalls{0};
std::atomic<uint64_t> g_hookFreeCalls{0};
std::atomic<uint64_t> g_hookReallocCalls{0};
std::atomic<uint64_t> g_hookGetSizeCalls{0};
std::atomic<uint64_t> g_hookCleanupCalls{0};
std::atomic<uint64_t> g_hookResetCalls{0};
std::atomic<uint64_t> g_hookBypassCalls{0};
std::atomic<uint64_t> g_hookFailures{0};
std::atomic<uint64_t> g_nativeAllocations{0};
std::atomic<uint64_t> g_nativeFrees{0};
std::atomic<uint64_t> g_nativeAllocatedBytes{0};
std::atomic<uint64_t> g_fallbackAllocations{0};
std::atomic<uint64_t> g_profilerEpoch{0};

constexpr size_t kFreedPointerTableSize = 4096;
constexpr uint32_t kFreedHeaderCookie = 0x46524545u; // 'FREE'
constexpr uint16_t kFreedHeaderTag = 0x4652u;        // 'FR'
static_assert((kFreedPointerTableSize & (kFreedPointerTableSize - 1)) == 0,
              "freed pointer table must be a power of two");
std::atomic<uintptr_t> g_recentlyFreedPointers[kFreedPointerTableSize]{};
std::atomic<uint64_t> g_rejectedManagedPointers{0};

template <typename T>
void AddRuntimeStat(std::atomic<T> &counter, T value = static_cast<T>(1)) {
  if (g_runtimeStatsEnabled.load(std::memory_order_relaxed)) {
    counter.fetch_add(value, std::memory_order_relaxed);
  }
}

void SaturatingSubtract(std::atomic<size_t> &counter, size_t value) {
  size_t current = counter.load(std::memory_order_relaxed);
  while (current != 0) {
    const size_t desired = current > value ? current - value : 0;
    if (counter.compare_exchange_weak(current, desired,
                                      std::memory_order_relaxed)) {
      return;
    }
  }
}

// 线程局部状态（避免递归）
thread_local bool tls_inHook = false;
thread_local uint32_t tls_cleanupDepth = 0;
thread_local uint32_t tls_resetDepth = 0;
thread_local void *tls_rejectedManagedProbe = nullptr;

// 关闭状态
std::atomic<bool> g_shutdownMode{false};
std::atomic<DWORD> g_shutdownThreadId{0};

class ScopedHookFlag {
public:
  ScopedHookFlag() : m_previous(tls_inHook) { tls_inHook = true; }
  ~ScopedHookFlag() { tls_inHook = m_previous; }

  ScopedHookFlag(const ScopedHookFlag &) = delete;
  ScopedHookFlag &operator=(const ScopedHookFlag &) = delete;

private:
  bool m_previous;
};

class ScopedThreadDepth {
public:
  explicit ScopedThreadDepth(uint32_t &depth)
      : m_depth(depth), m_outermost(depth++ == 0) {}
  ~ScopedThreadDepth() { --m_depth; }

  bool IsOutermost() const { return m_outermost; }

  ScopedThreadDepth(const ScopedThreadDepth &) = delete;
  ScopedThreadDepth &operator=(const ScopedThreadDepth &) = delete;

private:
  uint32_t &m_depth;
  bool m_outermost;
};

class ScopedCleanupState {
public:
  explicit ScopedCleanupState(bool active) : m_active(active) {
    if (!m_active) {
      return;
    }
    g_cleanupDepth.fetch_add(1, std::memory_order_acq_rel);
    StormHook_Internal::EnterUnsafePeriod();
  }

  ~ScopedCleanupState() {
    if (!m_active) {
      return;
    }
    StormHook::ProcessDeferredFree();
    StormHook_Internal::ExitUnsafePeriod();
    g_cleanupDepth.fetch_sub(1, std::memory_order_acq_rel);
  }

  ScopedCleanupState(const ScopedCleanupState &) = delete;
  ScopedCleanupState &operator=(const ScopedCleanupState &) = delete;

private:
  bool m_active;
};

class ScopedResetState {
public:
  explicit ScopedResetState(bool active) : m_active(active) {
    if (m_active) {
      StormHook::PrepareForReset();
    }
  }

  ~ScopedResetState() {
    if (m_active) {
      StormHook::PostReset();
    }
  }

  ScopedResetState(const ScopedResetState &) = delete;
  ScopedResetState &operator=(const ScopedResetState &) = delete;

private:
  bool m_active;
};

size_t QueryNativeSizeForProfiler(void *ptr, const char *name,
                                  int argList) {
  if (!ptr || !g_origStormGetSize) {
    return 0;
  }

  __try {
    const int size = g_origStormGetSize(ptr, name, argList);
    return size > 0 ? static_cast<size_t>(size) : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}

void RecordReallocProfile(
    bool enabled, void *oldPointer, void *newPointer, size_t oldSize,
    size_t newSize,
    bool oldFreed, bool newAllocated, bool inPlace,
    StormBreaker::LeakProfiler::AllocationDomain oldDomain,
    StormBreaker::LeakProfiler::AllocationDomain newDomain) {
  if (!enabled) {
    return;
  }
  StormBreaker::LeakProfiler::ReallocOutcome outcome{};
  outcome.oldPointer = oldPointer;
  outcome.newPointer = newPointer;
  outcome.oldSize = oldSize;
  outcome.newSize = newSize;
  outcome.oldFreed = oldFreed;
  outcome.newAllocated = newAllocated;
  outcome.inPlace = inPlace;
  outcome.domain = oldDomain;
  outcome.newDomain = newDomain;
  StormBreaker::LeakProfiler::RecordReallocOutcome(outcome);
}
} // namespace

// ======================== SEH包装的辅助函数 ========================
namespace SEH_Helpers {
thread_local DWORD g_lastExceptionCode = 0;

// SEH包装的内存复制（避免C++对象）
BOOL SafeMemCopy_SEH(void *dst, const void *src, size_t size) {
  if (!dst || !src || size == 0)
    return FALSE;

  __try {
    memcpy(dst, src, size);
    return TRUE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_lastExceptionCode = GetExceptionCode();
    return FALSE;
  }
}

// SEH包装的原始Storm调用
void *CallOrigStormAlloc_SEH(int ecx, int edx, size_t size, const char *name,
                             DWORD srcLine, DWORD flags) {
  __try {
    return g_origStormAlloc
               ? g_origStormAlloc(ecx, edx, size, name, srcLine, flags)
               : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_lastExceptionCode = GetExceptionCode();
    return nullptr;
  }
}

int CallOrigStormFree_SEH(void *ptr, const char *name, int argList,
                          DWORD flags) {
  __try {
    return g_origStormFree ? g_origStormFree(ptr, name, argList, flags) : 1;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_lastExceptionCode = GetExceptionCode();
    return 1;
  }
}

void *CallOrigStormReAlloc_SEH(int ecx, int edx, void *oldPtr, size_t newSize,
                               const char *name, DWORD srcLine, DWORD flags) {
  __try {
    return g_origStormReAlloc ? g_origStormReAlloc(ecx, edx, oldPtr, newSize,
                                                   name, srcLine, flags)
                              : nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    g_lastExceptionCode = GetExceptionCode();
    return nullptr;
  }
}

DWORD CallOrigCleanup_SEH() {
  __try {
    if (g_origCleanupAll) {
      g_origCleanupAll();
    }
    return 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return GetExceptionCode();
  }
}

int CallOrigReset_SEH(DWORD *exceptionCode) {
  if (exceptionCode) {
    *exceptionCode = 0;
  }
  __try {
    return g_origResetMemoryManager ? g_origResetMemoryManager() : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    if (exceptionCode) {
      *exceptionCode = GetExceptionCode();
    }
    return 0;
  }
}

// 获取最后异常代码的函数，用于外部日志记录
DWORD GetLastExceptionCode() { return g_lastExceptionCode; }

// 清除异常代码
void ClearLastExceptionCode() { g_lastExceptionCode = 0; }
} // namespace SEH_Helpers

namespace {
BOOL CopyManagedMemory(void *destination, const void *source, size_t size) {
  if (!MemoryPool::IsLatencyTrackingEnabled()) {
    return SEH_Helpers::SafeMemCopy_SEH(destination, source, size);
  }

  const auto start = std::chrono::steady_clock::now();
  const BOOL result =
      SEH_Helpers::SafeMemCopy_SEH(destination, source, size);
  const uint64_t nanoseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - start)
          .count());
  MemoryPool::RecordCopyLatency(nanoseconds);
  return result;
}
} // namespace

// ======================== 内部实现函数 ========================
namespace StormHook_Internal {
static inline bool ShouldBypassHooks() {
  if (!g_shutdownMode.load(std::memory_order_acquire)) {
    return false;
  }
  DWORD owner = g_shutdownThreadId.load(std::memory_order_acquire);
  return owner == 0 || owner != GetCurrentThreadId();
}

// === 新增：基于 16 字节 Header 的防伪操作 ===

size_t FreedPointerSlot(void *userPtr) {
  const uintptr_t value = reinterpret_cast<uintptr_t>(userPtr) >> 4;
  return static_cast<size_t>((value * 2654435761u) &
                             (kFreedPointerTableSize - 1));
}

void ForgetFreedPointer(void *userPtr) {
  const uintptr_t value = reinterpret_cast<uintptr_t>(userPtr);
  auto &slot = g_recentlyFreedPointers[FreedPointerSlot(userPtr)];
  uintptr_t observed = slot.load(std::memory_order_relaxed);
  if (observed == value) {
    slot.compare_exchange_strong(observed, 0, std::memory_order_relaxed);
  }
}

void RememberFreedPointer(void *userPtr) {
  const uintptr_t value = reinterpret_cast<uintptr_t>(userPtr);
  g_recentlyFreedPointers[FreedPointerSlot(userPtr)].store(
      value, std::memory_order_release);
}

bool IsRecentlyFreedPointer(void *userPtr) {
  const uintptr_t value = reinterpret_cast<uintptr_t>(userPtr);
  const uintptr_t observed =
      g_recentlyFreedPointers[FreedPointerSlot(userPtr)].load(
          std::memory_order_acquire);
  if (observed != value || value < sizeof(StormAllocHeader)) {
    return false;
  }

  void *rawPtr = reinterpret_cast<void *>(value - sizeof(StormAllocHeader));
  return MemoryPool::IsFromPool(rawPtr);
}

bool HeaderHasManagedMarker(const StormAllocHeader &header) {
  const bool liveMarker =
      header.magic == STORMBREAKER_MAGIC ||
      (header.headerSize == sizeof(StormAllocHeader) &&
       header.rejectTag == kStormBreakerRejectTag);
  const bool freedMarker =
      header.sizeCookie == kFreedHeaderCookie &&
      header.headerSize == sizeof(StormAllocHeader) &&
      header.rejectTag == kFreedHeaderTag;
  return liveMarker || freedMarker;
}

bool HasManagedHeaderMarker(void *userPtr) {
  if (!userPtr || reinterpret_cast<uintptr_t>(userPtr) <
                      sizeof(StormAllocHeader)) {
    return false;
  }
  __try {
    const auto *header = reinterpret_cast<const StormAllocHeader *>(
        static_cast<const uint8_t *>(userPtr) - sizeof(StormAllocHeader));
    return HeaderHasManagedMarker(*header);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

bool IsRejectedManagedPointer(void *userPtr) {
  return tls_rejectedManagedProbe == userPtr ||
         IsRecentlyFreedPointer(userPtr) || HasManagedHeaderMarker(userPtr);
}

bool IsRejectedAfterManagedProbe(void *userPtr) {
  return tls_rejectedManagedProbe == userPtr ||
         IsRecentlyFreedPointer(userPtr);
}

void NoteRejectedManagedPointer(void *userPtr, const char *operation) {
  AddRuntimeStat(g_hookFailures);
  const uint64_t count =
      g_rejectedManagedPointers.fetch_add(1, std::memory_order_relaxed) + 1;
  if (count <= 4 || (count & (count - 1)) == 0) {
    Logger::GetInstance().LogWarning(
        "StormHook: 拒绝将已释放或损坏的托管指针交给 Storm: op=%s, ptr=%p, count=%llu",
        operation ? operation : "unknown", userPtr,
        static_cast<unsigned long long>(count));
  }
}

void SetupStormTlsfHeader(void *userPtr, size_t size) {
  if (!userPtr)
    return;
  uint8_t *ptr = static_cast<uint8_t *>(userPtr);
  StormAllocHeader *header =
      reinterpret_cast<StormAllocHeader *>(ptr - sizeof(StormAllocHeader));

  ForgetFreedPointer(userPtr);

  header->magic = STORMBREAKER_MAGIC;
  header->requestedSize = static_cast<uint32_t>(size);
  header->sizeCookie = static_cast<uint32_t>(size) ^ kStormBreakerCookie;
  header->headerSize = sizeof(StormAllocHeader);
  header->rejectTag = kStormBreakerRejectTag;

  g_liveManagedBlocks.fetch_add(1, std::memory_order_relaxed);
  g_liveManagedBytes.fetch_add(size, std::memory_order_relaxed);
  AddRuntimeStat(g_totalAllocatedBlocks);
  AddRuntimeStat(g_totalAllocatedBytes, size);
}

bool QueryManagedBlock(void *userPtr, StormAllocHeader **outOriginalHeader,
                       size_t *outOriginalSize) {
  tls_rejectedManagedProbe = nullptr;
  if (!userPtr)
    return false;

  uint8_t *ptr = static_cast<uint8_t *>(userPtr);
  uintptr_t ptrValue = reinterpret_cast<uintptr_t>(ptr);
  if (ptrValue < sizeof(StormAllocHeader) || (ptrValue & 0x0F) != 0) {
    return false;
  }

  __try {
    StormAllocHeader *header =
        reinterpret_cast<StormAllocHeader *>(ptr - sizeof(StormAllocHeader));

    // 1. O(1) 验证自身私有 Magic
    if (header->magic != STORMBREAKER_MAGIC) {
      if (HeaderHasManagedMarker(*header)) {
        tls_rejectedManagedProbe = userPtr;
      }
      return false;
    }

    // 2. 验证防伪标签与 Header Size
    if (header->rejectTag != kStormBreakerRejectTag ||
        header->headerSize != sizeof(StormAllocHeader)) {
      tls_rejectedManagedProbe = userPtr;
      return false;
    }

    // 3. 验证长度 Cookie
    if ((header->requestedSize ^ kStormBreakerCookie) != header->sizeCookie) {
      tls_rejectedManagedProbe = userPtr;
      return false;
    }

    if (outOriginalHeader)
      *outOriginalHeader = header;
    if (outOriginalSize)
      *outOriginalSize = header->requestedSize;

    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

void PoisonManagedHeader(StormAllocHeader *hdr) {
  if (!hdr)
    return;

  if (hdr->magic == STORMBREAKER_MAGIC) {
    SaturatingSubtract(g_liveManagedBlocks, 1);
    SaturatingSubtract(g_liveManagedBytes, hdr->requestedSize);
    AddRuntimeStat(g_totalFreedBlocks);
    AddRuntimeStat(g_totalFreedBytes,
                   static_cast<size_t>(hdr->requestedSize));
  }

  hdr->magic = 0xDEADDEAD;
  hdr->requestedSize = 0;
  hdr->sizeCookie = kFreedHeaderCookie;
  hdr->headerSize = sizeof(StormAllocHeader);
  hdr->rejectTag = kFreedHeaderTag;
}

void LogManagedAllocationFailure(size_t totalNeeded) {
  const size_t count =
      g_managedAllocationFailures.fetch_add(1, std::memory_order_relaxed) + 1;
  if (count <= 4 || (count & (count - 1)) == 0) {
    Logger::GetInstance().LogWarning(
        "StormHook: 托管分配失败 size=%zu，回退 Storm (累计=%zu)",
        totalNeeded, count);
  }
}

void *AllocateManagedBlock(size_t size, const char *name, DWORD srcLine) {
  const size_t headerSize = sizeof(StormAllocHeader);
  if (size > SIZE_MAX - headerSize) {
    return nullptr;
  }

  const size_t totalNeeded = size + headerSize;
  void *poolBlock = MemoryPool::AllocateAlignedKnownSize(totalNeeded, 16);
  if (!poolBlock) {
    LogManagedAllocationFailure(totalNeeded);
    return nullptr;
  }

  uint8_t *userPtr = static_cast<uint8_t *>(poolBlock) + headerSize;
  SetupStormTlsfHeader(userPtr, size);

  if (!StormHook::IsInUnsafePeriod()) {
    MemorySafety::GetInstance().RegisterMemoryBlock(poolBlock, userPtr, size,
                                                    name, srcLine);
  }

  if (size >= 1024 * 1024) {
    Logger::GetInstance().LogDebug("分配大块: user=%p, size=%zu MB", userPtr,
                                   size / (1024 * 1024));
  }

  return userPtr;
}

bool FreeManagedBlock(void *ptr, StormAllocHeader *hdr, size_t origSize) {
  if (!ptr || !hdr) {
    return false;
  }

  RememberFreedPointer(ptr);
  PoisonManagedHeader(hdr);
  MemorySafety::GetInstance().TryUnregisterBlock(ptr);

  void *actualPtr = static_cast<void *>(static_cast<uint8_t *>(ptr) -
                                        sizeof(StormAllocHeader));
  MemoryPool::FreeKnownSizeUntracked(
      actualPtr, origSize + sizeof(StormAllocHeader));

  if (origSize >= 1024 * 1024) {
    Logger::GetInstance().LogDebug("释放大块: ptr=%p, size=%zu MB", ptr,
                                   origSize / (1024 * 1024));
  }

  return true;
}

struct NativeLargeBlockInfo {
  bool valid = false;
  size_t actualSize = 0;
  size_t stormAccountedSize = 0;
  size_t counterCorrection = 0;
};

NativeLargeBlockInfo QueryNativeLargeBlockForCounterFix(void *userPtr) {
  NativeLargeBlockInfo info{};
  if (!userPtr) {
    return info;
  }

  uintptr_t ptrValue = reinterpret_cast<uintptr_t>(userPtr);
  if (ptrValue < 16 || (ptrValue & 0x07) != 0) {
    return info;
  }

  __try {
    uint8_t *ptr = static_cast<uint8_t *>(userPtr);
    const uint8_t userFlags = *(ptr - 5);
    if ((userFlags & 0x08) == 0) {
      return info;
    }

    auto *stormHeader = *reinterpret_cast<uint16_t **>(ptr - 12);
    if (!stormHeader) {
      return info;
    }

    const uint8_t stormHeaderFlags =
        *(reinterpret_cast<uint8_t *>(stormHeader) + 3);
    if ((stormHeaderFlags & 0x04) == 0) {
      return info;
    }

    const size_t actualSize = *reinterpret_cast<uint32_t *>(ptr - 16);
    const size_t accountedSize = *stormHeader;
    if (actualSize < kStormNativeLargeBlockThreshold ||
        actualSize <= accountedSize) {
      return info;
    }

    info.valid = true;
    info.actualSize = actualSize;
    info.stormAccountedSize = accountedSize;
    info.counterCorrection = actualSize - accountedSize;
    return info;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return NativeLargeBlockInfo{};
  }
}

void ApplyNativeLargeFreeCounterCorrection(const NativeLargeBlockInfo &info) {
  if (!info.valid || info.counterCorrection == 0 || gStormDllBase == 0) {
    return;
  }

  __try {
    auto *counter = reinterpret_cast<volatile LONG *>(
        gStormDllBase + OFFSET_g_TotalAllocatedMemory);
    LONG observed = *counter;
    for (;;) {
      const uint32_t current = static_cast<uint32_t>(observed);
      const uint32_t correction =
          static_cast<uint32_t>(std::min<size_t>(info.counterCorrection,
                                                UINT32_MAX));
      const uint32_t desired = current > correction ? current - correction : 0;
      const LONG previous = InterlockedCompareExchange(
          counter, static_cast<LONG>(desired), observed);
      if (previous == observed) {
        break;
      }
      observed = previous;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Logger::GetInstance().LogWarning(
        "Storm native 大块计数修正失败: size=%zu, correction=%zu, code=0x%08X",
        info.actualSize, info.counterCorrection, GetExceptionCode());
  }
}

void EnterUnsafePeriod() {
  if (g_unsafeDepth.fetch_add(1, std::memory_order_acq_rel) == 0) {
    Logger::GetInstance().LogDebug("进入不安全期");
  }
}

void ExitUnsafePeriod() {
  uint32_t current = g_unsafeDepth.load(std::memory_order_acquire);
  while (current != 0) {
    if (g_unsafeDepth.compare_exchange_weak(
            current, current - 1, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      if (current == 1) {
        Logger::GetInstance().LogDebug("退出不安全期");
      }
      return;
    }
  }
  Logger::GetInstance().LogWarning("忽略未配对的不安全期退出");
}
} // namespace StormHook_Internal

// ======================== 公共接口实现 ========================
namespace StormHook {

bool Initialize() {
  if (g_initialized.exchange(true, std::memory_order_acq_rel)) {
    return true; // 已初始化
  }

  Logger::GetInstance().LogInfo("初始化StormHook系统...");

  // 初始化内存池
  if (!MemoryPool::Initialize()) {
    Logger::GetInstance().LogError("内存池初始化失败");
    g_initialized.store(false, std::memory_order_release);
    return false;
  }

  // 初始化内存安全系统
  if (!MemorySafety::GetInstance().Initialize()) {
    Logger::GetInstance().LogError("内存安全系统初始化失败");
    g_initialized.store(false, std::memory_order_release);
    return false;
  }

  Logger::GetInstance().LogInfo("大块拦截阈值: %zu KiB",
                                GetLargeBlockThreshold() / 1024);

  Logger::GetInstance().LogInfo("StormHook系统初始化完成");
  g_shutdownMode.store(false, std::memory_order_release);
  g_shutdownThreadId.store(0, std::memory_order_release);
  g_totalAllocatedBlocks.store(0, std::memory_order_relaxed);
  g_totalAllocatedBytes.store(0, std::memory_order_relaxed);
  g_totalFreedBlocks.store(0, std::memory_order_relaxed);
  g_totalFreedBytes.store(0, std::memory_order_relaxed);
  g_liveManagedBlocks.store(0, std::memory_order_relaxed);
  g_liveManagedBytes.store(0, std::memory_order_relaxed);
  g_managedAllocationFailures.store(0, std::memory_order_relaxed);
  g_hookAllocCalls.store(0, std::memory_order_relaxed);
  g_hookFreeCalls.store(0, std::memory_order_relaxed);
  g_hookReallocCalls.store(0, std::memory_order_relaxed);
  g_hookGetSizeCalls.store(0, std::memory_order_relaxed);
  g_hookCleanupCalls.store(0, std::memory_order_relaxed);
  g_hookResetCalls.store(0, std::memory_order_relaxed);
  g_hookBypassCalls.store(0, std::memory_order_relaxed);
  g_hookFailures.store(0, std::memory_order_relaxed);
  g_nativeAllocations.store(0, std::memory_order_relaxed);
  g_nativeFrees.store(0, std::memory_order_relaxed);
  g_nativeAllocatedBytes.store(0, std::memory_order_relaxed);
  g_fallbackAllocations.store(0, std::memory_order_relaxed);
  g_profilerEpoch.store(0, std::memory_order_relaxed);
  g_rejectedManagedPointers.store(0, std::memory_order_relaxed);
  for (auto &slot : g_recentlyFreedPointers) {
    slot.store(0, std::memory_order_relaxed);
  }
  return true;
}

void Shutdown() {
  if (!g_initialized.exchange(false, std::memory_order_acq_rel)) {
    return; // 未初始化
  }

  if (g_shutdownMode.load(std::memory_order_acquire)) {
    return;
  }

  Logger::GetInstance().LogInfo("关闭StormHook系统...");
  g_shutdownThreadId.store(GetCurrentThreadId(), std::memory_order_release);
  g_shutdownMode.store(true, std::memory_order_release);

  // 清理所有管理的块
  FlushManagedBlocks();

  Logger::GetInstance().LogInfo("StormHook系统已关闭");
}

bool IsOurBlock(void *userPtr) {
  if (!userPtr || !g_initialized.load(std::memory_order_acquire)) {
    return false;
  }
  return StormHook_Internal::QueryManagedBlock(userPtr, nullptr, nullptr);
}

bool IsInUnsafePeriod() {
  return g_unsafeDepth.load(std::memory_order_acquire) != 0 ||
         g_cleanupDepth.load(std::memory_order_acquire) != 0 ||
         g_resetDepth.load(std::memory_order_acquire) != 0;
}

void SetLargeBlockThreshold(size_t bytes) {
  if (bytes < kStormNativeLargeBlockThreshold)
    bytes = kStormNativeLargeBlockThreshold;
  g_largeBlockThreshold.store(bytes, std::memory_order_release);
  Logger::GetInstance().LogInfo("大块拦截阈值已设置为: %zu KiB", bytes / 1024);
}

size_t GetLargeBlockThreshold() {
  return g_largeBlockThreshold.load(std::memory_order_acquire);
}

void *AllocateMemory(size_t size, const char *name, DWORD srcLine) {
  if (!g_initialized.load(std::memory_order_acquire) || tls_inHook) {
    return nullptr;
  }

  if (size < g_largeBlockThreshold.load(std::memory_order_acquire)) {
    return nullptr;
  }

  // 在不安全期间直接回退到原生分配
  if (IsInUnsafePeriod()) {
    return nullptr;
  }

  ScopedHookFlag guard;
  return StormHook_Internal::AllocateManagedBlock(size, name, srcLine);
}

bool FreeMemory(void *ptr) {
  if (!ptr || !g_initialized.load(std::memory_order_acquire) || tls_inHook) {
    return false; // 不受管
  }

  ScopedHookFlag guard;

  StormAllocHeader *hdr = nullptr;
  size_t origSize = 0;

  if (!StormHook_Internal::QueryManagedBlock(ptr, &hdr, &origSize)) {
    if (StormHook_Internal::IsRejectedAfterManagedProbe(ptr)) {
      StormHook_Internal::NoteRejectedManagedPointer(ptr, "free");
      return true;
    }
    return false; // 不是我们管理的块
  }

  return StormHook_Internal::FreeManagedBlock(ptr, hdr, origSize);
}

ManagedReallocResult TryReallocMemory(void *oldPtr, size_t newSize,
                                      const char *name, DWORD srcLine) {
  ManagedReallocResult result{};
  if (!g_initialized.load(std::memory_order_acquire) || tls_inHook) {
    return result;
  }

  if (!oldPtr) {
    void *allocated = AllocateMemory(newSize, name, srcLine);
    if (allocated) {
      result.disposition = ManagedReallocDisposition::Succeeded;
      result.pointer = allocated;
    } else if (newSize >= GetLargeBlockThreshold() && !IsInUnsafePeriod()) {
      result.disposition = ManagedReallocDisposition::Failed;
    }
    return result;
  }

  ScopedHookFlag guard;

  StormAllocHeader *hdr = nullptr;
  size_t oldSize = 0;
  if (!StormHook_Internal::QueryManagedBlock(oldPtr, &hdr, &oldSize)) {
    if (StormHook_Internal::IsRejectedAfterManagedProbe(oldPtr)) {
      StormHook_Internal::NoteRejectedManagedPointer(oldPtr, "realloc");
      result.disposition = ManagedReallocDisposition::Failed;
    }
    return result;
  }

  if (newSize == 0) {
    if (StormHook_Internal::FreeManagedBlock(oldPtr, hdr, oldSize)) {
      result.disposition = ManagedReallocDisposition::Freed;
    } else {
      result.disposition = ManagedReallocDisposition::Failed;
    }
    return result;
  }

  // === 单向降级策略 ===
  // 如果新请求的大小远小于大块阈值，我们将其释放给原生 Storm，不强制留存在 TLSF
  // 池中。
  // 注意：单向降级机制不自动劫持新的原生小块重分配，这阻止了可能的小块对象提升导致的崩溃。
  if (newSize < GetLargeBlockThreshold()) {
    // 让外部拦截器去调原生 Alloc -> Memcpy -> 我们负责 Free(oldPtr)
    result.disposition = ManagedReallocDisposition::Failed;
    return result;
  }

  void *newPtr = StormHook_Internal::AllocateManagedBlock(newSize, name, srcLine);
  if (!newPtr) {
    result.disposition = ManagedReallocDisposition::Failed;
    return result;
  }

  size_t copySize = (oldSize < newSize) ? oldSize : newSize;
  if (!CopyManagedMemory(newPtr, oldPtr, copySize)) {
    Logger::GetInstance().LogError("重分配数据复制失败");
    StormAllocHeader *newHdr = nullptr;
    size_t allocatedSize = 0;
    if (StormHook_Internal::QueryManagedBlock(newPtr, &newHdr, &allocatedSize)) {
      StormHook_Internal::FreeManagedBlock(newPtr, newHdr, allocatedSize);
    }
    result.disposition = ManagedReallocDisposition::Failed;
    return result;
  }

  StormHook_Internal::FreeManagedBlock(oldPtr, hdr, oldSize);
  result.disposition = ManagedReallocDisposition::Succeeded;
  result.pointer = newPtr;
  return result;
}

void FlushManagedBlocks() {
  Logger::GetInstance().LogInfo(
      "无锁架构不再记录所有地址，内存清理交由底层的 TLSF 容器销毁统一完成。");
}

void ProcessDeferredFree() {
  MemorySafety::GetInstance().ProcessDeferredFreeQueue();
}

size_t GetManagedBlockCount() {
  return g_liveManagedBlocks.load(std::memory_order_relaxed);
}

size_t GetTotalManagedSize() {
  return g_liveManagedBytes.load(std::memory_order_relaxed);
}

void SetRuntimeStatsEnabled(bool enabled) {
  g_runtimeStatsEnabled.store(enabled, std::memory_order_release);
}

bool IsRuntimeStatsEnabled() {
  return g_runtimeStatsEnabled.load(std::memory_order_acquire);
}

void PrepareForReset() {
  Logger::GetInstance().LogDebug("准备Reset，进入不安全期...");
  g_resetDepth.fetch_add(1, std::memory_order_acq_rel);

  // 我们自己的不安全期
  StormHook_Internal::EnterUnsafePeriod();
  // 让 MemorySafety 也进入不安全期
  MemorySafety::GetInstance().EnterUnsafePeriod();

  // 为避免 Reset 过程后半段才去 free，尽量在 Reset 前清空延迟队列
  MemorySafety::GetInstance().FlushDeferredFreeQueue();

  // 清理 TLSF 空闲页
  MemoryPool::TrimFreePages();
}

void PostReset() {
  Logger::GetInstance().LogDebug("Reset完成，开始收尾...");

  // 我们使用 16 字节 O(1) 防伪头，不再填写真实的 StormHeap*，因此 Reset
  // 不会导致指针悬空需要修复 这里仅需退出安全保护范围即可

  MemorySafety::GetInstance().ExitUnsafePeriod();
  MemorySafety::GetInstance().ProcessDeferredFreeQueue();

  StormHook_Internal::ExitUnsafePeriod();
  uint32_t current = g_resetDepth.load(std::memory_order_acquire);
  while (current != 0 &&
         !g_resetDepth.compare_exchange_weak(
             current, current - 1, std::memory_order_acq_rel,
             std::memory_order_acquire)) {
  }

  Logger::GetInstance().LogInfo("ResetMemoryManager完成");
}

RuntimeStats GetRuntimeStats() {
  RuntimeStats stats{};
  stats.allocCalls = g_hookAllocCalls.load(std::memory_order_relaxed);
  stats.freeCalls = g_hookFreeCalls.load(std::memory_order_relaxed);
  stats.reallocCalls = g_hookReallocCalls.load(std::memory_order_relaxed);
  stats.getSizeCalls = g_hookGetSizeCalls.load(std::memory_order_relaxed);
  stats.cleanupCalls = g_hookCleanupCalls.load(std::memory_order_relaxed);
  stats.resetCalls = g_hookResetCalls.load(std::memory_order_relaxed);
  stats.bypassCalls = g_hookBypassCalls.load(std::memory_order_relaxed);
  stats.failures = g_hookFailures.load(std::memory_order_relaxed);
  stats.managedAllocations =
      g_totalAllocatedBlocks.load(std::memory_order_relaxed);
  stats.managedFrees = g_totalFreedBlocks.load(std::memory_order_relaxed);
  stats.nativeAllocations =
      g_nativeAllocations.load(std::memory_order_relaxed);
  stats.nativeFrees = g_nativeFrees.load(std::memory_order_relaxed);
  stats.nativeAllocatedBytes =
      g_nativeAllocatedBytes.load(std::memory_order_relaxed);
  stats.fallbackAllocations =
      g_fallbackAllocations.load(std::memory_order_relaxed);
  stats.managedAllocationFailures =
      g_managedAllocationFailures.load(std::memory_order_relaxed);
  return stats;
}

// 新增：验证指针是否正确对齐
bool IsPointerAligned(void *ptr, size_t alignment) {
  if (!ptr)
    return false;
  return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

bool ValidateBlockAlignment(void *userPtr) {
  if (!userPtr) {
    return false;
  }

  if (!IsOurBlock(userPtr)) {
    return false;
  }

  return IsPointerAligned(userPtr, 16);
}
} // namespace StormHook

// ======================== Hook函数实现 ========================

void *__fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
                                       const char *name, DWORD srcLine,
                                       DWORD flags) {
  AddRuntimeStat(g_hookAllocCalls);
  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    void *result = SEH_Helpers::CallOrigStormAlloc_SEH(
        ecx, edx, size, name, srcLine, flags);
    if (result) {
      AddRuntimeStat(g_nativeAllocations);
      AddRuntimeStat(g_nativeAllocatedBytes, static_cast<uint64_t>(size));
      StormBreaker::LeakProfiler::RecordAlloc(
          result, size,
          StormBreaker::LeakProfiler::AllocationDomain::Native);
    }
    return result;
  }
  // 尝试用我们的系统分配
  void *ptr = StormHook::AllocateMemory(size, name, srcLine);
  if (ptr) {
    StormBreaker::LeakProfiler::RecordAlloc(
        ptr, size, StormBreaker::LeakProfiler::AllocationDomain::Managed);
    return ptr;
  }

  if (size >= StormHook::GetLargeBlockThreshold() &&
      !StormHook::IsInUnsafePeriod()) {
    AddRuntimeStat(g_fallbackAllocations);
  }

  // 回退到原始Storm分配
  SEH_Helpers::ClearLastExceptionCode();
  void *result =
      SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, size, name, srcLine, flags);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode != 0) {
    AddRuntimeStat(g_hookFailures);
    Logger::GetInstance().LogError(
        "Storm原始分配函数异常: size=%zu, code=0x%08X", size, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }
  if (result) {
    AddRuntimeStat(g_nativeAllocations);
    AddRuntimeStat(g_nativeAllocatedBytes, static_cast<uint64_t>(size));
    StormBreaker::LeakProfiler::RecordAlloc(
        result, size, StormBreaker::LeakProfiler::AllocationDomain::Native);
  } else if (exceptCode == 0) {
    AddRuntimeStat(g_hookFailures);
  }

  return result;
}

int __stdcall Hooked_Storm_MemFree(void *ptr, const char *name, int argList,
                                   DWORD flags) {
  AddRuntimeStat(g_hookFreeCalls);
  const bool profilerEnabled = StormBreaker::LeakProfiler::IsEnabled();
  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    const size_t nativeSize = profilerEnabled
                                  ? QueryNativeSizeForProfiler(ptr, name, argList)
                                  : 0;
    SEH_Helpers::ClearLastExceptionCode();
    const int result =
        SEH_Helpers::CallOrigStormFree_SEH(ptr, name, argList, flags);
    if (SEH_Helpers::GetLastExceptionCode() == 0 && result != 0 && ptr) {
      AddRuntimeStat(g_nativeFrees);
      if (profilerEnabled) {
        StormBreaker::LeakProfiler::RecordFree(
            ptr, nativeSize,
            StormBreaker::LeakProfiler::AllocationDomain::Native);
      }
    }
    return result;
  }
  if (!ptr) {
    return 1; // NULL指针认为成功
  }

  size_t managedSize = 0;
  if (profilerEnabled) {
    StormHook_Internal::QueryManagedBlock(ptr, nullptr, &managedSize);
  }

  // 尝试用我们的系统释放
  if (StormHook::FreeMemory(ptr)) {
    if (profilerEnabled) {
      StormBreaker::LeakProfiler::RecordFree(
          ptr, managedSize,
          StormBreaker::LeakProfiler::AllocationDomain::Managed);
    }
    return 1; // 成功
  }

  const size_t nativeSize = profilerEnabled
                                ? QueryNativeSizeForProfiler(ptr, name, argList)
                                : 0;
  const auto nativeLargeInfo =
      StormHook_Internal::QueryNativeLargeBlockForCounterFix(ptr);

  // 回退到原始Storm释放
  SEH_Helpers::ClearLastExceptionCode();
  int result = SEH_Helpers::CallOrigStormFree_SEH(ptr, name, argList, flags);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode == 0 && result != 0) {
    StormHook_Internal::ApplyNativeLargeFreeCounterCorrection(nativeLargeInfo);
    AddRuntimeStat(g_nativeFrees);
    if (profilerEnabled) {
      StormBreaker::LeakProfiler::RecordFree(
          ptr, nativeSize,
          StormBreaker::LeakProfiler::AllocationDomain::Native);
    }
  }
  if (exceptCode != 0) {
    AddRuntimeStat(g_hookFailures);
    Logger::GetInstance().LogError("Storm原始释放函数异常: ptr=%p, code=0x%08X",
                                   ptr, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }

  return result;
}

int __stdcall Hooked_Storm_MemGetSize(void *ptr, const char *name,
                                      int argList) {
  AddRuntimeStat(g_hookGetSizeCalls);
  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    return g_origStormGetSize ? g_origStormGetSize(ptr, name, argList) : -1;
  }
  constexpr size_t kStormSizeLimit = 0x7FFFFFFF;

  size_t blockSize = 0;
  if (ptr && StormHook_Internal::QueryManagedBlock(ptr, nullptr, &blockSize)) {
    if (blockSize > kStormSizeLimit) {
      blockSize = kStormSizeLimit;
    }
    return static_cast<int>(blockSize);
  }
  if (ptr && StormHook_Internal::IsRejectedAfterManagedProbe(ptr)) {
    StormHook_Internal::NoteRejectedManagedPointer(ptr, "get-size");
    return -1;
  }

  if (!g_origStormGetSize) {
    return -1;
  }

  return g_origStormGetSize(ptr, name, argList);
}

void *__fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void *oldPtr,
                                         size_t newSize, const char *name,
                                         DWORD srcLine, DWORD flags) {
  using StormBreaker::LeakProfiler::AllocationDomain;
  AddRuntimeStat(g_hookReallocCalls);

  const bool profilerEnabled = StormBreaker::LeakProfiler::IsEnabled();
  size_t observedOldSize = 0;
  const bool observedOldManaged =
      profilerEnabled && oldPtr && StormHook_Internal::QueryManagedBlock(
                                       oldPtr, nullptr, &observedOldSize);
  if (profilerEnabled && oldPtr && !observedOldManaged) {
    observedOldSize = QueryNativeSizeForProfiler(oldPtr, name, 0);
  }

  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    SEH_Helpers::ClearLastExceptionCode();
    void *result = SEH_Helpers::CallOrigStormReAlloc_SEH(
        ecx, edx, oldPtr, newSize, name, srcLine, flags);
    const bool succeeded = SEH_Helpers::GetLastExceptionCode() == 0;
    const bool oldFreed =
        succeeded && oldPtr && (result != nullptr || newSize == 0);
    const bool newAllocated = succeeded && result != nullptr;
    RecordReallocProfile(profilerEnabled, oldPtr, result, observedOldSize,
                         newSize, oldFreed,
                         newAllocated, result && result == oldPtr,
                         AllocationDomain::Native,
                         AllocationDomain::Native);
    return result;
  }

  const auto managedResult =
      StormHook::TryReallocMemory(oldPtr, newSize, name, srcLine);
  if (managedResult.disposition ==
      StormHook::ManagedReallocDisposition::Succeeded) {
    RecordReallocProfile(
        profilerEnabled, oldPtr, managedResult.pointer, observedOldSize, newSize,
        oldPtr != nullptr && observedOldManaged,
        managedResult.pointer != nullptr,
        managedResult.pointer != nullptr && managedResult.pointer == oldPtr,
        observedOldManaged ? AllocationDomain::Managed
                           : AllocationDomain::Native,
        AllocationDomain::Managed);
    return managedResult.pointer;
  }
  if (managedResult.disposition ==
      StormHook::ManagedReallocDisposition::Freed) {
    RecordReallocProfile(profilerEnabled, oldPtr, nullptr, observedOldSize, 0,
                         true, false,
                         false, AllocationDomain::Managed,
                         AllocationDomain::Managed);
    return nullptr;
  }

  StormAllocHeader *managedHdr = nullptr;
  size_t managedOldSize = 0;
  const bool managedFailure =
      managedResult.disposition ==
      StormHook::ManagedReallocDisposition::Failed;
  if (managedFailure && oldPtr && newSize > 0) {
    if (!StormHook_Internal::QueryManagedBlock(oldPtr, &managedHdr,
                                               &managedOldSize)) {
      AddRuntimeStat(g_hookFailures);
      Logger::GetInstance().LogError(
          "托管重分配失败后无法重新验证旧块，拒绝交给原生 Storm: ptr=%p",
          oldPtr);
      return nullptr;
    }

    // 使用Storm分配新内存
    SEH_Helpers::ClearLastExceptionCode();
    void *newPtr = SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, newSize, name,
                                                       srcLine, flags);

    if (newPtr) {
      // 复制数据
      size_t copySize =
          (managedOldSize < newSize) ? managedOldSize : newSize;

      if (CopyManagedMemory(newPtr, oldPtr, copySize)) {
        // 释放旧块
        StormHook_Internal::FreeManagedBlock(oldPtr, managedHdr,
                                             managedOldSize);
        AddRuntimeStat(g_nativeAllocations);
        AddRuntimeStat(g_nativeAllocatedBytes,
                       static_cast<uint64_t>(newSize));
        AddRuntimeStat(g_fallbackAllocations);
        RecordReallocProfile(profilerEnabled, oldPtr, newPtr, managedOldSize,
                             newSize, true,
                             true, false, AllocationDomain::Managed,
                             AllocationDomain::Native);
        return newPtr;
      } else {
        // 复制失败，释放新分配的内存
        SEH_Helpers::CallOrigStormFree_SEH(newPtr, name, 0, 0);
      }
    }

    AddRuntimeStat(g_hookFailures);
    RecordReallocProfile(profilerEnabled, oldPtr, nullptr, managedOldSize,
                         newSize, false,
                         false, false, AllocationDomain::Managed,
                         AllocationDomain::Native);
    return nullptr;
  }

  // 回退到原始Storm重分配
  const auto nativeLargeInfo =
      StormHook_Internal::QueryNativeLargeBlockForCounterFix(oldPtr);
  SEH_Helpers::ClearLastExceptionCode();
  void *result = SEH_Helpers::CallOrigStormReAlloc_SEH(
      ecx, edx, oldPtr, newSize, name, srcLine, flags);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode == 0 && (flags & 0x10) == 0) {
    StormHook_Internal::ApplyNativeLargeFreeCounterCorrection(nativeLargeInfo);
  }
  if (exceptCode != 0) {
    AddRuntimeStat(g_hookFailures);
    Logger::GetInstance().LogError(
        "Storm原始重分配函数异常: ptr=%p, size=%zu, code=0x%08X", oldPtr,
        newSize, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }

  const bool succeeded = exceptCode == 0;
  const bool oldFreed =
      succeeded && oldPtr && (result != nullptr || newSize == 0);
  const bool newAllocated = succeeded && result != nullptr;
  if (newAllocated) {
    AddRuntimeStat(g_nativeAllocations);
    AddRuntimeStat(g_nativeAllocatedBytes, static_cast<uint64_t>(newSize));
  }
  if (oldFreed) {
    AddRuntimeStat(g_nativeFrees);
  }
  if (!newAllocated && newSize != 0 && exceptCode == 0) {
    AddRuntimeStat(g_hookFailures);
  }
  if (managedFailure) {
    AddRuntimeStat(g_fallbackAllocations);
  }
  RecordReallocProfile(profilerEnabled, oldPtr, result, observedOldSize,
                       newSize, oldFreed,
                       newAllocated, result && result == oldPtr,
                       AllocationDomain::Native, AllocationDomain::Native);

  return result;
}

void __stdcall Hooked_StormHeap_CleanupAll() {
  AddRuntimeStat(g_hookCleanupCalls);
  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    if (g_origCleanupAll) {
      g_origCleanupAll();
    }
    return;
  }
  ScopedThreadDepth threadDepth(tls_cleanupDepth);
  const bool outermost = threadDepth.IsOutermost();

  // 使用静态变量控制日志频率，避免刷屏
  static std::atomic<DWORD> lastLogTime{0};
  static std::atomic<size_t> callCount{0};

  DWORD currentTime = GetTickCount();
  size_t currentCount = callCount.fetch_add(1, std::memory_order_relaxed);

  // 只有在超过1秒间隔或者是错误时才记录日志
  bool shouldLog =
      (currentTime - lastLogTime.load(std::memory_order_relaxed) > 1000) ||
      (currentCount % 100 == 0);

  if (outermost && shouldLog) {
    lastLogTime.store(currentTime, std::memory_order_relaxed);
    Logger::GetInstance().LogDebug("CleanupAll调用 (第%zu次)", currentCount);
  }

  {
    ScopedCleanupState cleanupState(outermost);

    // 安全执行原始CleanupAll
    const DWORD cleanupException = SEH_Helpers::CallOrigCleanup_SEH();
    if (cleanupException != 0) {
      AddRuntimeStat(g_hookFailures);
      Logger::GetInstance().LogError(
          "CleanupAll执行异常: 0x%08X (调用次数: %zu)", cleanupException,
          currentCount);
    }
  }

  if (outermost) {
    StormBreaker::LeakProfiler::MarkEpoch(
        g_profilerEpoch.load(std::memory_order_relaxed), 2);
  }
}

int __stdcall Hooked_ResetMemoryManager() {
  AddRuntimeStat(g_hookResetCalls);
  if (StormHook_Internal::ShouldBypassHooks()) {
    AddRuntimeStat(g_hookBypassCalls);
    return g_origResetMemoryManager ? g_origResetMemoryManager() : 0;
  }
  ScopedThreadDepth threadDepth(tls_resetDepth);
  const bool outermost = threadDepth.IsOutermost();
  DWORD resetException = 0;
  int result = 0;
  {
    if (outermost) {
      Logger::GetInstance().LogInfo("开始ResetMemoryManager...");
    }
    ScopedResetState resetState(outermost);
    result = SEH_Helpers::CallOrigReset_SEH(&resetException);
    if (resetException != 0) {
      AddRuntimeStat(g_hookFailures);
      Logger::GetInstance().LogError("ResetMemoryManager执行异常: 0x%08X",
                                     resetException);
    }
  }

  if (outermost) {
    const uint64_t epoch =
        g_profilerEpoch.fetch_add(1, std::memory_order_relaxed) + 1;
    StormBreaker::LeakProfiler::MarkEpoch(epoch, 1);
  }
  return result;
}
