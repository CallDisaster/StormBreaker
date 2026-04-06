// ======================== StormHook.cpp 完整修复版本 ========================
#include "StormHook.h"
#include "Base/Logger.h"
#include "Base/MemorySafety.h"
#include "MemoryPool.h"
#include "pch.h"
#include <algorithm>
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
std::atomic<bool> g_inUnsafePeriod(false);
std::atomic<bool> g_inCleanupAll(false);
std::atomic<bool> g_inReset(false);

// 统计信息
std::atomic<size_t> g_totalAllocatedBlocks(0);
std::atomic<size_t> g_totalAllocatedBytes(0);
std::atomic<size_t> g_totalFreedBlocks(0);
std::atomic<size_t> g_totalFreedBytes(0);

// 大块分配阈值（64KB）
std::atomic<size_t> g_largeBlockThreshold{
    64 * 1024}; // 默认 64 KiB，覆盖Storm大块阈值

// 线程局部状态（避免递归）
thread_local bool tls_inHook = false;

// 真实StormHeap探测
std::atomic<void *> g_defaultStormHeap{nullptr};

// 关闭状态
std::atomic<bool> g_shutdownMode{false};
std::atomic<DWORD> g_shutdownThreadId{0};
} // namespace

// ======================== SEH包装的辅助函数 ========================
namespace SEH_Helpers {
DWORD g_lastExceptionCode = 0;

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

// 获取最后异常代码的函数，用于外部日志记录
DWORD GetLastExceptionCode() { return g_lastExceptionCode; }

// 清除异常代码
void ClearLastExceptionCode() { g_lastExceptionCode = 0; }
} // namespace SEH_Helpers

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

void SetupStormTlsfHeader(void *userPtr, size_t size) {
  if (!userPtr)
    return;
  uint8_t *ptr = static_cast<uint8_t *>(userPtr);
  StormAllocHeader *header =
      reinterpret_cast<StormAllocHeader *>(ptr - sizeof(StormAllocHeader));

  header->magic = STORMBREAKER_MAGIC;
  header->requestedSize = static_cast<uint32_t>(size);
  header->sizeCookie = static_cast<uint32_t>(size) ^ kStormBreakerCookie;
  header->headerSize = sizeof(StormAllocHeader);
  header->rejectTag = kStormBreakerRejectTag;

  g_totalAllocatedBlocks.fetch_add(1, std::memory_order_relaxed);
  g_totalAllocatedBytes.fetch_add(size, std::memory_order_relaxed);
}

bool QueryManagedBlock(void *userPtr, StormAllocHeader **outOriginalHeader,
                       size_t *outOriginalSize) {
  if (!userPtr)
    return false;

  uint8_t *ptr = static_cast<uint8_t *>(userPtr);
  StormAllocHeader *header =
      reinterpret_cast<StormAllocHeader *>(ptr - sizeof(StormAllocHeader));

  // 1. O(1) 验证自身私有 Magic
  if (header->magic != STORMBREAKER_MAGIC) {
    return false;
  }

  // 2. 验证防伪标签与 Header Size
  if (header->rejectTag != kStormBreakerRejectTag ||
      header->headerSize != sizeof(StormAllocHeader)) {
    return false;
  }

  // 3. 验证长度 Cookie
  if ((header->requestedSize ^ kStormBreakerCookie) != header->sizeCookie) {
    return false;
  }

  if (outOriginalHeader)
    *outOriginalHeader = header;
  if (outOriginalSize)
    *outOriginalSize = header->requestedSize;

  return true;
}

void PoisonManagedHeader(StormAllocHeader *hdr) {
  if (!hdr)
    return;

  if (hdr->magic == STORMBREAKER_MAGIC) {
    g_totalFreedBlocks.fetch_add(1, std::memory_order_relaxed);
    g_totalFreedBytes.fetch_add(hdr->requestedSize, std::memory_order_relaxed);
  }

  hdr->magic = 0xDEADDEAD;
  hdr->requestedSize = 0;
  hdr->sizeCookie = 0;
  hdr->rejectTag = 0;
}

void EnterUnsafePeriod() {
  g_inUnsafePeriod.store(true, std::memory_order_release);
  Logger::GetInstance().LogDebug("进入不安全期");
}

void ExitUnsafePeriod() {
  g_inUnsafePeriod.store(false, std::memory_order_release);
  Logger::GetInstance().LogDebug("退出不安全期");
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

  // === 新增：主动探测默认StormHeap* ===
  StormHook_Internal::ProbeDefaultStormHeapPointer();

  Logger::GetInstance().LogInfo("大块拦截阈值: %zu KiB",
                                GetLargeBlockThreshold() / 1024);

  Logger::GetInstance().LogInfo("StormHook系统初始化完成");
  g_shutdownMode.store(false, std::memory_order_release);
  g_shutdownThreadId.store(0, std::memory_order_release);
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

  // 关闭内存安全系统
  MemorySafety::GetInstance().Shutdown();

  // 关闭内存池
  MemoryPool::Shutdown();

  Logger::GetInstance().LogInfo("StormHook系统已关闭");
}

bool IsOurBlock(void *userPtr) {
  if (!userPtr || !g_initialized.load(std::memory_order_acquire)) {
    return false;
  }
  return StormHook_Internal::QueryManagedBlock(userPtr, nullptr, nullptr);
}

bool IsInUnsafePeriod() {
  return g_inUnsafePeriod.load(std::memory_order_acquire) ||
         g_inCleanupAll.load(std::memory_order_acquire) ||
         g_inReset.load(std::memory_order_acquire);
}

void SetLargeBlockThreshold(size_t bytes) {
  if (bytes < 64 * 1024)
    bytes = 64 * 1024; // 最低不小于 64 KiB
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

  tls_inHook = true;

  const size_t headerSize = sizeof(StormAllocHeader);
  const size_t alignment = 16;
  const size_t totalNeeded = size + headerSize;

  // 从 TLSF 分配 16 字节对齐的内存
  void *poolBlock = MemoryPool::AllocateAligned(totalNeeded, 16);
  if (!poolBlock) {
    Logger::GetInstance().LogError("TLSF分配失败: size=%zu", totalNeeded);
    tls_inHook = false;
    return nullptr;
  }

  uint8_t *userPtr = static_cast<uint8_t *>(poolBlock) + headerSize;
  StormHook_Internal::SetupStormTlsfHeader(userPtr, size);

  if (!IsInUnsafePeriod()) {
    MemorySafety::GetInstance().RegisterMemoryBlock(poolBlock, userPtr, size,
                                                    name, srcLine);
  }

  if (size >= 1024 * 1024) {
    Logger::GetInstance().LogInfo("分配大块: user=%p, size=%zu MB", userPtr,
                                  size / (1024 * 1024));
  }

  tls_inHook = false;
  return userPtr;
}

bool FreeMemory(void *ptr) {
  if (!ptr || !g_initialized.load(std::memory_order_acquire) || tls_inHook) {
    return false; // 不受管
  }

  tls_inHook = true;

  StormAllocHeader *hdr = nullptr;
  size_t origSize = 0;

  if (!StormHook_Internal::QueryManagedBlock(ptr, &hdr, &origSize)) {
    tls_inHook = false;
    return false; // 不是我们管理的块
  }

  // 下毒破坏标志，防止 Double Free 也防止地址复用时幽灵状态
  StormHook_Internal::PoisonManagedHeader(hdr);

  // 一定要解除安全池监控
  MemorySafety::GetInstance().TryUnregisterBlock(ptr);

  // 由于 AllocateAligned 的申请原理，分配出的原指针刚好在 16 字节前
  void *actualPtr = static_cast<void *>(static_cast<uint8_t *>(ptr) -
                                        sizeof(StormAllocHeader));
  MemoryPool::Free(actualPtr);

  if (origSize >= 1024 * 1024) {
    Logger::GetInstance().LogInfo("释放大块: ptr=%p, size=%zu MB", ptr,
                                  origSize / (1024 * 1024));
  }

  tls_inHook = false;
  return true;
}

void *ReallocMemory(void *oldPtr, size_t newSize, const char *name,
                    DWORD srcLine) {
  if (!g_initialized.load(std::memory_order_acquire) || tls_inHook) {
    return nullptr;
  }

  if (!oldPtr) {
    return AllocateMemory(newSize, name, srcLine);
  }

  if (newSize == 0) {
    FreeMemory(oldPtr);
    return nullptr;
  }

  tls_inHook = true;

  StormAllocHeader *hdr = nullptr;
  size_t oldSize = 0;
  if (!StormHook_Internal::QueryManagedBlock(oldPtr, &hdr, &oldSize)) {
    tls_inHook = false;
    return nullptr; // 让原生 Storm 去重分配
  }

  // === 单向降级策略 ===
  // 如果新请求的大小远小于大块阈值，我们将其释放给原生 Storm，不强制留存在 TLSF
  // 池中。
  // 注意：单向降级机制不自动劫持新的原生小块重分配，这阻止了可能的小块对象提升导致的崩溃。
  if (newSize < GetLargeBlockThreshold()) {
    tls_inHook = false;
    // 让外部拦截器去调原生 Alloc -> Memcpy -> 我们负责 Free(oldPtr)
    return nullptr;
  }

  void *newPtr = AllocateMemory(newSize, name, srcLine);
  if (!newPtr) {
    Logger::GetInstance().LogError("重分配新块失败: size=%zu", newSize);
    tls_inHook = false;
    return nullptr;
  }

  size_t copySize = (oldSize < newSize) ? oldSize : newSize;
  if (!SEH_Helpers::SafeMemCopy_SEH(newPtr, oldPtr, copySize)) {
    Logger::GetInstance().LogError("重分配数据复制失败");
    FreeMemory(newPtr);
    tls_inHook = false;
    return nullptr;
  }

  FreeMemory(oldPtr);
  tls_inHook = false;
  return newPtr;
}

void FlushManagedBlocks() {
  Logger::GetInstance().LogInfo(
      "无锁架构不再记录所有地址，内存清理交由底层的 TLSF 容器销毁统一完成。");
}

void ProcessDeferredFree() {
  MemorySafety::GetInstance().ProcessDeferredFreeQueue();
}

size_t GetManagedBlockCount() {
  return g_totalAllocatedBlocks.load(std::memory_order_relaxed) -
         g_totalFreedBlocks.load(std::memory_order_relaxed);
}

size_t GetTotalManagedSize() {
  return g_totalAllocatedBytes.load(std::memory_order_relaxed) -
         g_totalFreedBytes.load(std::memory_order_relaxed);
}

void PrepareForReset() {
  Logger::GetInstance().LogDebug("准备Reset，进入不安全期...");
  g_inReset.store(true, std::memory_order_release);

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
  g_inReset.store(false, std::memory_order_release);

  Logger::GetInstance().LogInfo("ResetMemoryManager完成");
}

// 新增：验证指针是否正确对齐
bool IsPointerAligned(void *ptr, size_t alignment) {
  if (!ptr)
    return false;
  return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

// (ValidateBlockAlignment 方法已因为无锁头而淘汰)
} // namespace StormHook

// ======================== Hook函数实现 ========================

void *__fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
                                       const char *name, DWORD srcLine,
                                       DWORD flags) {
  if (StormHook_Internal::ShouldBypassHooks()) {
    return SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, size, name, srcLine,
                                               flags);
  }
  // 尝试用我们的系统分配
  void *ptr = StormHook::AllocateMemory(size, name, srcLine);
  if (ptr) {
    return ptr;
  }

  // 回退到原始Storm分配
  void *result =
      SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, size, name, srcLine, flags);

  // === 新增：顺手被动抓一次StormHeap ===
  StormHook_Internal::TryCaptureDefaultHeapFromAllocResult(result);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode != 0) {
    Logger::GetInstance().LogError(
        "Storm原始分配函数异常: size=%zu, code=0x%08X", size, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }

  return result;
}

int __stdcall Hooked_Storm_MemFree(void *ptr, const char *name, int argList,
                                   DWORD flags) {
  if (StormHook_Internal::ShouldBypassHooks()) {
    return SEH_Helpers::CallOrigStormFree_SEH(ptr, name, argList, flags);
  }
  if (!ptr) {
    return 1; // NULL指针认为成功
  }

  // 尝试用我们的系统释放
  if (StormHook::FreeMemory(ptr)) {
    return 1; // 成功
  }

  // 回退到原始Storm释放
  int result = SEH_Helpers::CallOrigStormFree_SEH(ptr, name, argList, flags);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode != 0) {
    Logger::GetInstance().LogError("Storm原始释放函数异常: ptr=%p, code=0x%08X",
                                   ptr, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }

  return result;
}

int __stdcall Hooked_Storm_MemGetSize(void *ptr, const char *name,
                                      int argList) {
  if (StormHook_Internal::ShouldBypassHooks()) {
    return g_origStormGetSize ? g_origStormGetSize(ptr, name, argList) : -1;
  }
  constexpr size_t kStormSizeLimit = 0x7FFFFFFF;

  if (ptr && StormHook::IsOurBlock(ptr)) {
    size_t blockSize = 0;
    if (StormHook_Internal::QueryManagedBlock(ptr, nullptr, &blockSize)) {
      if (blockSize > kStormSizeLimit) {
        blockSize = kStormSizeLimit;
      }
      return static_cast<int>(blockSize);
    }
  }

  if (!g_origStormGetSize) {
    return -1;
  }

  return g_origStormGetSize(ptr, name, argList);
}

void *__fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void *oldPtr,
                                         size_t newSize, const char *name,
                                         DWORD srcLine, DWORD flags) {
  if (StormHook_Internal::ShouldBypassHooks()) {
    return SEH_Helpers::CallOrigStormReAlloc_SEH(ecx, edx, oldPtr, newSize,
                                                 name, srcLine, flags);
  }
  // 尝试用我们的系统重分配
  void *ptr = StormHook::ReallocMemory(oldPtr, newSize, name, srcLine);
  if (ptr) {
    return ptr;
  }

  // 如果oldPtr是我们管理的但新大小不需要大块处理，需要手动迁移
  if (oldPtr && StormHook::IsOurBlock(oldPtr) && newSize > 0) {
    // 使用Storm分配新内存
    void *newPtr = SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, newSize, name,
                                                       srcLine, flags);

    if (newPtr) {
      // 复制数据
      size_t oldSize = 0;
      StormHook_Internal::QueryManagedBlock(oldPtr, nullptr, &oldSize);
      size_t copySize = (oldSize < newSize) ? oldSize : newSize;

      if (SEH_Helpers::SafeMemCopy_SEH(newPtr, oldPtr, copySize)) {
        // 释放旧块
        StormHook::FreeMemory(oldPtr);
        return newPtr;
      } else {
        // 复制失败，释放新分配的内存
        SEH_Helpers::CallOrigStormFree_SEH(newPtr, name, 0, 0);
      }
    }

    return nullptr;
  }

  // 回退到原始Storm重分配
  void *result = SEH_Helpers::CallOrigStormReAlloc_SEH(
      ecx, edx, oldPtr, newSize, name, srcLine, flags);

  // 检查是否有异常发生
  DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
  if (exceptCode != 0) {
    Logger::GetInstance().LogError(
        "Storm原始重分配函数异常: ptr=%p, size=%zu, code=0x%08X", oldPtr,
        newSize, exceptCode);
    SEH_Helpers::ClearLastExceptionCode();
  }

  return result;
}

void __stdcall Hooked_StormHeap_CleanupAll() {
  if (StormHook_Internal::ShouldBypassHooks()) {
    if (g_origCleanupAll) {
      g_origCleanupAll();
    }
    return;
  }
  // 防止递归调用
  if (g_inCleanupAll.exchange(true, std::memory_order_acq_rel)) {
    return;
  }

  // 使用静态变量控制日志频率，避免刷屏
  static std::atomic<DWORD> lastLogTime{0};
  static std::atomic<size_t> callCount{0};

  DWORD currentTime = GetTickCount();
  size_t currentCount = callCount.fetch_add(1, std::memory_order_relaxed);

  // 只有在超过1秒间隔或者是错误时才记录日志
  bool shouldLog =
      (currentTime - lastLogTime.load(std::memory_order_relaxed) > 1000) ||
      (currentCount % 100 == 0);

  if (shouldLog) {
    lastLogTime.store(currentTime, std::memory_order_relaxed);
    Logger::GetInstance().LogDebug("CleanupAll调用 (第%zu次)", currentCount);
  }

  StormHook_Internal::EnterUnsafePeriod();

  // 安全执行原始CleanupAll
  __try {
    if (g_origCleanupAll) {
      g_origCleanupAll();
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Logger::GetInstance().LogError("CleanupAll执行异常: 0x%08X (调用次数: %zu)",
                                   GetExceptionCode(), currentCount);
  }

  // 处理延迟释放
  StormHook::ProcessDeferredFree();

  StormHook_Internal::ExitUnsafePeriod();
  g_inCleanupAll.store(false, std::memory_order_release);
}

int __stdcall Hooked_ResetMemoryManager() {
  if (StormHook_Internal::ShouldBypassHooks()) {
    return g_origResetMemoryManager ? g_origResetMemoryManager() : 0;
  }
  Logger::GetInstance().LogInfo("开始ResetMemoryManager...");

  // Reset前准备
  StormHook::PrepareForReset();

  int result = 0;

  // 安全执行原始Reset
  __try {
    if (g_origResetMemoryManager) {
      result = g_origResetMemoryManager();
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Logger::GetInstance().LogError("ResetMemoryManager执行异常: 0x%08X",
                                   GetExceptionCode());
  }

  // Reset后清理
  StormHook::PostReset();

  Logger::GetInstance().LogInfo("ResetMemoryManager完成");
  return result;
}
