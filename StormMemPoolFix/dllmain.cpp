// StormBreaker
// Author: Disaster (CallDisaster)
// GitHub: https://github.com/CallDisaster/StormBreaker
// License: MIT License
// Date: 2025-03-02
// Description: 延缓 Warcraft III 旧版本 Storm.dll 的虚拟内存增长过快的问题

#include "pch.h"
#include "Base/LeakProfiler.h"
#include "Base/Telemetry.h"
#include "Storm/MemoryPool.h"
#include <Base/Logger.h>
#include <Base/MemorySafety.h>
#include <Game/PathCapUnlock.h>
#include <Storm/StormHook.h>
#include <Storm/StormNativeSmallRepair.h>
#include <Storm/StormOffsets.h>
#include <Storm/StormTakeover.h>
#include <Storm/StormVersionProfile.h>
#include <cstdlib>
#include <cstdio>
#include <detours.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <mimalloc.h>
#include <windows.h>

#ifndef STORMBREAKER_LARGE_ONLY
#define STORMBREAKER_LARGE_ONLY 0
#endif


namespace {
bool ReadEnvFlag(const char *name) {
  char buffer[8] = {};
  DWORD size = GetEnvironmentVariableA(name, buffer, sizeof(buffer));
  if (size == 0 || size >= sizeof(buffer)) {
    return false;
  }

  return _stricmp(buffer, "1") == 0 || _stricmp(buffer, "true") == 0 ||
         _stricmp(buffer, "yes") == 0 || _stricmp(buffer, "on") == 0;
}

bool ShouldEnableVerboseLogs() { return ReadEnvFlag("STORMBREAKER_VERBOSE_LOG"); }

bool ShouldEnableMemorySafety() {
  return ReadEnvFlag("STORMBREAKER_MEMORY_SAFETY");
}

bool ShouldEnableTelemetry() {
  return ReadEnvFlag("STORMBREAKER_TELEMETRY");
}

bool ShouldEnableMemoryMonitor() {
  return ReadEnvFlag("STORMBREAKER_MEMORY_MONITOR");
}

bool ShouldEnableControlPanel() {
  return !ReadEnvFlag("STORMBREAKER_DISABLE_CONTROL_PANEL");
}

bool ShouldCreateDebugConsole() {
  if (ReadEnvFlag("STORMBREAKER_DISABLE_DEBUG_CONSOLE")) {
    return false;
  }
  return true;
}

static HMODULE g_pinnedModule = nullptr;
static char g_artifactLogDirectory[32768] = {};

bool PinModuleUntilProcessExit() {
  if (g_pinnedModule) {
    return true;
  }

  HMODULE pinned = nullptr;
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_PIN,
                         reinterpret_cast<LPCSTR>(&PinModuleUntilProcessExit),
                         &pinned)) {
    g_pinnedModule = pinned;
    OutputDebugStringA(
        "StormBreaker: module pinned until process exit to survive ASI "
        "loader unload\n");
    return true;
  } else {
    OutputDebugStringA("StormBreaker: failed to pin module\n");
    return false;
  }
}
} // namespace

void CreateConsole() {
  // 检查是否已经有控制台
  if (GetConsoleWindow() != nullptr) {
    return; // 已经有控制台了
  }

  if (!AllocConsole()) {
    OutputDebugStringA("StormBreaker: 无法分配控制台\n");
    return;
  }

  FILE *fp;
  freopen_s(&fp, "CONOUT$", "w", stdout); // 绑定标准输出到控制台
  freopen_s(&fp, "CONOUT$", "w", stderr); // 绑定标准错误到控制台
  freopen_s(&fp, "CONIN$", "r", stdin);   // 绑定标准输入到控制台

  // 设置UTF-8编码
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);

  // 设置控制台标题
  SetConsoleTitleA("StormBreaker Debug Console");

  // 设置控制台窗口大小
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hConsole != INVALID_HANDLE_VALUE) {
    COORD bufferSize = {120, 300}; // 宽度120字符，缓冲区300行
    SetConsoleScreenBufferSize(hConsole, bufferSize);

    SMALL_RECT windowSize = {0, 0, 119, 29}; // 窗口显示30行
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
  }

  printf("StormBreaker debug console enabled.\n");
  printf("Log file: .\\StormBreaker\\StormMemory.log\n\n");
  printf("Set STORMBREAKER_DISABLE_DEBUG_CONSOLE=1 to disable this console.\n\n");
  printf("Set STORMBREAKER_VERBOSE_LOG=1 for per-allocation debug logs.\n");
  printf("Set STORMBREAKER_MEMORY_SAFETY=1 for full block tracking.\n\n");
  printf("Control panel status is flushed immediately every 60 seconds.\n\n");
}

namespace {
static HANDLE g_initThread = nullptr;
static std::atomic<bool> g_systemInitialized{false};
static std::atomic<bool> g_hooksInstalled{false};
static std::atomic<bool> g_telemetryStarted{false};
static HANDLE g_controlPanelStopEvent = nullptr;
static HANDLE g_controlPanelThread = nullptr;

StormBreaker::Telemetry::MemoryBackend GetTelemetryBackend() {
  if (!MemoryPool::IsInitialized()) {
    return StormBreaker::Telemetry::MemoryBackend::Off;
  }
  switch (MemoryPool::GetBackendKind()) {
  case MemoryPool::BackendKind::Tlsf:
    return StormBreaker::Telemetry::MemoryBackend::Tlsf;
  case MemoryPool::BackendKind::Mimalloc:
    return StormBreaker::Telemetry::MemoryBackend::Mimalloc;
  case MemoryPool::BackendKind::TlsfSharded:
    return StormBreaker::Telemetry::MemoryBackend::TlsfSharded;
  case MemoryPool::BackendKind::Hybrid:
    return StormBreaker::Telemetry::MemoryBackend::Hybrid;
  default:
    return StormBreaker::Telemetry::MemoryBackend::Off;
  }
}

uint64_t HistogramPercentile(const MemoryPool::LatencyHistogramStats &stats,
                             uint64_t percentile) {
  if (stats.sampleCount == 0) {
    return 0;
  }
  const uint64_t target =
      (stats.sampleCount / 100) * percentile +
      ((stats.sampleCount % 100) * percentile + 99) / 100;
  uint64_t cumulative = 0;
  for (size_t index = 0;
       index < MemoryPool::kLatencyHistogramBucketCount + 1; ++index) {
    cumulative += stats.bucketCounts[index];
    if (cumulative >= target) {
      return index < MemoryPool::kLatencyHistogramBucketCount
                 ? stats.upperBoundsNanoseconds[index]
                 : stats.maxNanoseconds;
    }
  }
  return stats.maxNanoseconds;
}

void PublishTelemetrySnapshot() noexcept {
  using namespace StormBreaker;

  if (!g_telemetryStarted.load(std::memory_order_acquire)) {
    return;
  }

  Telemetry::RuntimeSnapshot runtime{};
  runtime.hooksInstalled = g_hooksInstalled.load(std::memory_order_acquire);
  runtime.memoryBackend = GetTelemetryBackend();
  Telemetry::UpdateRuntime(runtime);

  const StormHook::RuntimeStats hookStats = StormHook::GetRuntimeStats();
  Telemetry::HookSnapshot hook{};
  hook.allocCalls = hookStats.allocCalls;
  hook.freeCalls = hookStats.freeCalls;
  hook.reallocCalls = hookStats.reallocCalls;
  hook.getSizeCalls = hookStats.getSizeCalls;
  hook.cleanupCalls = hookStats.cleanupCalls;
  hook.resetCalls = hookStats.resetCalls;
  hook.bypassCalls = hookStats.bypassCalls;
  hook.failures = hookStats.failures;
  Telemetry::UpdateHook(hook);

  Telemetry::BackendSnapshot backend{};
  backend.managedAllocations = hookStats.managedAllocations;
  backend.managedFrees = hookStats.managedFrees;
  backend.nativeAllocations = hookStats.nativeAllocations;
  backend.nativeFrees = hookStats.nativeFrees;
  backend.managedBytes = StormHook::GetTotalManagedSize();
  backend.nativeBytes = hookStats.nativeAllocatedBytes;
  backend.fallbackAllocations = hookStats.fallbackAllocations;
  backend.failures = hookStats.failures;
  Telemetry::UpdateBackend(backend);

  const MemoryPool::ExtendedPoolStats poolStats =
      MemoryPool::GetExtendedStats();
  Telemetry::PoolSnapshot pool{};
  pool.requestedLiveBytes = poolStats.requestedLiveBytes;
  pool.usableLiveBytes = poolStats.usableLiveBytes;
  pool.reservedBytes = poolStats.reservedBytes;
  pool.committedBytes = poolStats.committedBytes;
  pool.peakRequestedLiveBytes = poolStats.peakRequestedLiveBytes;
  pool.peakUsableLiveBytes = poolStats.peakUsableLiveBytes;
  pool.peakReservedBytes = poolStats.peakReservedBytes;
  pool.peakCommittedBytes = poolStats.peakCommittedBytes;
  pool.requestedLiveBudgetBytes = poolStats.requestedLiveBudgetBytes;
  pool.allocationCount = poolStats.allocCount;
  pool.freeCount = poolStats.freeCount;
  pool.reallocCount = poolStats.reallocCount;
  pool.failureCount = poolStats.failureCount;
  pool.extendCount = poolStats.extendCount;
  pool.trimCount = poolStats.trimCount;
  pool.lockWaitCount = poolStats.lockWaitCount;
  pool.lockWaitNanoseconds = poolStats.lockWaitNanoseconds;
  pool.maxLockWaitNanoseconds = poolStats.maxLockWaitNanoseconds;
  Telemetry::UpdatePool(pool);

  Telemetry::LatencySnapshot latency{};
  latency.sampleCount = poolStats.operationLatency.sampleCount;
  latency.totalNanoseconds = poolStats.operationLatency.totalNanoseconds;
  latency.maxNanoseconds = poolStats.operationLatency.maxNanoseconds;
  latency.p50Nanoseconds =
      HistogramPercentile(poolStats.operationLatency, 50);
  latency.p95Nanoseconds =
      HistogramPercentile(poolStats.operationLatency, 95);
  latency.p99Nanoseconds =
      HistogramPercentile(poolStats.operationLatency, 99);
  latency.allocateP99Nanoseconds =
      HistogramPercentile(poolStats.allocateLatency, 99);
  latency.freeP99Nanoseconds =
      HistogramPercentile(poolStats.freeLatency, 99);
  latency.reallocateP99Nanoseconds =
      HistogramPercentile(poolStats.reallocateLatency, 99);
  latency.copyP99Nanoseconds =
      HistogramPercentile(poolStats.copyLatency, 99);
  latency.growthP99Nanoseconds =
      HistogramPercentile(poolStats.growthLatency, 99);
  latency.lockWaitP99Nanoseconds =
      HistogramPercentile(poolStats.lockWaitLatency, 99);
  Telemetry::UpdateLatency(latency);

  const LeakProfiler::HealthSnapshot health =
      LeakProfiler::GetHealthSnapshot();
  Telemetry::ProfilerHealthSnapshot profiler{};
  profiler.eventsEnqueued = health.eventsEnqueued;
  profiler.eventsWritten = health.eventsWritten;
  profiler.dropped = health.dropped;
  profiler.recursionSkips = health.recursionSkips;
  profiler.writeErrors = health.writeErrors;
  profiler.managedEvents = health.managedEvents;
  profiler.nativeEvents = health.nativeEvents;
  profiler.fallbackEvents = health.fallbackEvents;
  profiler.degradedEvents = health.degradedEvents;
  profiler.queueCapacity = health.queueCapacity;
  profiler.queueDepth = health.queueDepth;
  profiler.mode = static_cast<uint8_t>(health.mode);
  profiler.incomplete = health.incomplete;
  profiler.writerRunning = health.writerRunning;
  Telemetry::UpdateProfilerHealth(profiler);

  LeakProfiler::TakeoverSnapshot takeover{};
#if !STORMBREAKER_LARGE_ONLY
  takeover = StormTakeover::GetTelemetrySnapshot();
#endif
  LeakProfiler::UpdateTakeoverSnapshot(takeover);
  Telemetry::UpdateTakeover(takeover);
}

DWORD ControlPanelIntervalMilliseconds() noexcept {
  constexpr DWORD kDefaultSeconds = 60;
  char value[16]{};
  const DWORD length = GetEnvironmentVariableA(
      "STORMBREAKER_STATUS_INTERVAL_SEC", value,
      static_cast<DWORD>(sizeof(value)));
  if (length == 0 || length >= sizeof(value)) {
    return kDefaultSeconds * 1000;
  }

  char *end = nullptr;
  const unsigned long parsed = std::strtoul(value, &end, 10);
  if (end == value || *end != '\0' || parsed < 5 || parsed > 3600) {
    return kDefaultSeconds * 1000;
  }
  return static_cast<DWORD>(parsed * 1000);
}

void EmitControlPanelStatus() noexcept {
  const bool ready = g_systemInitialized.load(std::memory_order_acquire);
  const bool hooks = g_hooksInstalled.load(std::memory_order_acquire);
  const MemoryPool::ExtendedPoolStats pool = MemoryPool::GetExtendedStats();
  const StormHook::RuntimeStats hook = StormHook::GetRuntimeStats();
#if STORMBREAKER_LARGE_ONLY
  const StormNativeSmallRepair::RuntimeStats nativeRepair =
      StormNativeSmallRepair::GetRuntimeStats();
  const char *backend = MemoryPool::GetBackendName();
  const char *buildIdentity = MemoryPool::GetBuildBackendIdentity();
  const unsigned long long liveBlocks =
      static_cast<unsigned long long>(StormHook::GetManagedBlockCount());
  const unsigned long long liveMiB = static_cast<unsigned long long>(
      StormHook::GetTotalManagedSize() / (1024u * 1024u));
  const unsigned long long requestedMiB = static_cast<unsigned long long>(
      pool.requestedLiveBytes / (1024u * 1024u));
  const unsigned long long reservedMiB = static_cast<unsigned long long>(
      pool.reservedBytes / (1024u * 1024u));
  const unsigned long long committedMiB = static_cast<unsigned long long>(
      pool.committedBytes / (1024u * 1024u));

  Logger::GetInstance().LogInfo(
      "[ControlPanel] ready=%s hooks=%s backend=%s build=%s "
      "mode=large-four-hook threshold=0x%zX liveBlocks=%llu live=%llu MiB "
      "requested=%llu MiB reserved=%llu MiB committed=%llu MiB "
      "managedAlloc=%llu managedFree=%llu fallback=%llu failures=%llu "
      "nativeSmallRepair=%s repairCalls=%u promotions=%u rebuilds=%u "
      "invalidSkips=%u bypasses=%u",
      ready ? "yes" : "no", hooks ? "yes" : "no", backend,
      buildIdentity, StormHook::GetLargeBlockThreshold(), liveBlocks, liveMiB,
      requestedMiB, reservedMiB, committedMiB,
      static_cast<unsigned long long>(hook.managedAllocations),
      static_cast<unsigned long long>(hook.managedFrees),
      static_cast<unsigned long long>(hook.fallbackAllocations),
      static_cast<unsigned long long>(hook.failures),
      StormNativeSmallRepair::GetModeName(), nativeRepair.calls,
      nativeRepair.promotions, nativeRepair.rebuilds,
      nativeRepair.invalidArenaSkips, nativeRepair.bypasses);
  Logger::GetInstance().FlushLogs();

  if (GetConsoleWindow() != nullptr) {
    char title[128]{};
    std::snprintf(title, sizeof(title),
                  "StormBreaker Large Block - %s - %s", backend,
                  hooks ? "HOOKED" : "NOT HOOKED");
    SetConsoleTitleA(title);
    std::printf(
        "\n[StormBreaker Large Block Control Panel] READY=%s HOOKS=%s "
        "BACKEND=%s\n"
        "  build identity=%s, takeover=large-four-hook, threshold=0x%zX\n"
        "  live blocks=%llu, live=%llu MiB, requested=%llu MiB\n"
        "  reserved=%llu MiB, committed=%llu MiB\n"
        "  managed alloc=%llu, managed free=%llu, fallback=%llu, "
        "failures=%llu\n"
        "  native small repair=%s, calls=%u, promotions=%u, rebuilds=%u, "
        "invalid skips=%u, bypasses=%u\n"
        "  next refresh in %lu seconds\n",
        ready ? "YES" : "NO", hooks ? "YES" : "NO", backend,
        buildIdentity, StormHook::GetLargeBlockThreshold(), liveBlocks,
        liveMiB, requestedMiB, reservedMiB, committedMiB,
        static_cast<unsigned long long>(hook.managedAllocations),
        static_cast<unsigned long long>(hook.managedFrees),
        static_cast<unsigned long long>(hook.fallbackAllocations),
        static_cast<unsigned long long>(hook.failures),
        StormNativeSmallRepair::GetModeName(), nativeRepair.calls,
        nativeRepair.promotions, nativeRepair.rebuilds,
        nativeRepair.invalidArenaSkips, nativeRepair.bypasses,
        ControlPanelIntervalMilliseconds() / 1000);
    std::fflush(stdout);
  }
  return;
#else
  const StormTakeover::RuntimeStats takeover =
      StormTakeover::GetRuntimeStats();
  const unsigned long long liveBlocks = static_cast<unsigned long long>(
      takeover.liveBlocks);
  const unsigned long long liveMiB = static_cast<unsigned long long>(
      takeover.liveRequestedBytes / (1024u * 1024u));
  const unsigned long long requestedMiB = static_cast<unsigned long long>(
      pool.requestedLiveBytes / (1024u * 1024u));
  const unsigned long long reservedMiB = static_cast<unsigned long long>(
      pool.reservedBytes / (1024u * 1024u));
  const unsigned long long committedMiB = static_cast<unsigned long long>(
      pool.committedBytes / (1024u * 1024u));
  const unsigned long long failures = static_cast<unsigned long long>(
      takeover.failures);
  const unsigned long long rejected = static_cast<unsigned long long>(
      takeover.rejectedPointers);
  const unsigned long long degraded = static_cast<unsigned long long>(
      takeover.degradedCalls);
  const unsigned long long fallback = static_cast<unsigned long long>(
      takeover.fallbackCalls);
  const unsigned long long blockEnumCalls = static_cast<unsigned long long>(
      takeover.blockEnumerationCalls);
  const unsigned long long blockEnumBuilds = static_cast<unsigned long long>(
      takeover.blockEnumerationSnapshotBuilds);
  const unsigned long long heapEnumCalls = static_cast<unsigned long long>(
      takeover.heapEnumerationCalls);
  const unsigned long long heapEnumRebuilds = static_cast<unsigned long long>(
      takeover.heapEnumerationRebuilds);
  const unsigned long long destroySnapshots = static_cast<unsigned long long>(
      takeover.heapDestroySnapshots);
  const unsigned long long destroyBlocks = static_cast<unsigned long long>(
      takeover.heapDestroySnapshotBlocks);
  const unsigned long long callerCacheHits = static_cast<unsigned long long>(
      takeover.callerHeapCacheHits);
  const unsigned long long callerCacheMisses = static_cast<unsigned long long>(
      takeover.callerHeapCacheMisses);
  const unsigned long long callerCacheBypasses =
      static_cast<unsigned long long>(takeover.callerHeapCacheBypasses);
  const unsigned long long callerCacheSaturated =
      static_cast<unsigned long long>(takeover.callerHeapCacheSaturated);
  const unsigned long long heapIdHintHits =
      static_cast<unsigned long long>(takeover.heapIdSlotHintHits);
  const unsigned long long heapIdHintMisses =
      static_cast<unsigned long long>(takeover.heapIdSlotHintMisses);
  const unsigned int callerCacheEntries = takeover.callerHeapCacheEntries;
  const char *backend = MemoryPool::GetBackendName();
  const char *buildIdentity = MemoryPool::GetBuildBackendIdentity();

  Logger::GetInstance().LogInfo(
      "[ControlPanel] ready=%s hooks=%s backend=%s build=%s mode=%s "
      "threshold=%u liveBlocks=%llu "
      "live=%llu MiB requested=%llu MiB reserved=%llu MiB committed=%llu MiB "
      "failures=%llu rejected=%llu fallback=%llu degraded=%llu "
      "last=%s/ord%u/heap%08X/flags%08X/size%u/route:%s "
      "callerHash=%s "
      "blockEnum=%llu/%llu heapEnum=%llu/%llu destroySnapshots=%llu/%llu "
      "callerCache=%llu/%llu/%llu/%llu entries=%u heapIdHint=%llu/%llu",
      ready ? "yes" : "no", hooks ? "yes" : "no", backend, buildIdentity,
      StormTakeover::ModeName(takeover.mode), takeover.threshold, liveBlocks,
      liveMiB, requestedMiB, reservedMiB, committedMiB, failures, rejected,
      fallback, degraded,
      StormTakeover::DegradedReasonName(takeover.lastDegradedReason),
      static_cast<unsigned>(takeover.lastOrdinal), takeover.lastHeapId,
      takeover.lastStormFlags, takeover.lastRequestedSize,
      StormTakeover::RouteName(takeover.lastRoute),
      takeover.directCallerHash ? "direct-verified" : "native-trampoline",
      blockEnumCalls, blockEnumBuilds, heapEnumCalls,
      heapEnumRebuilds, destroySnapshots, destroyBlocks, callerCacheHits,
      callerCacheMisses, callerCacheBypasses, callerCacheSaturated,
      callerCacheEntries, heapIdHintHits, heapIdHintMisses);
  Logger::GetInstance().FlushLogs();

  if (GetConsoleWindow() != nullptr) {
    char title[128]{};
    std::snprintf(title, sizeof(title),
                  "StormBreaker Control Panel - %s - %s", backend,
                  hooks ? "HOOKED" : "NOT HOOKED");
    SetConsoleTitleA(title);
    std::printf(
        "\n[StormBreaker Control Panel] READY=%s HOOKS=%s BACKEND=%s\n"
        "  build identity=%s, takeover=%s, threshold=%u\n"
        "  live blocks=%llu, live=%llu MiB, requested=%llu MiB\n"
        "  reserved=%llu MiB, committed=%llu MiB\n"
        "  failures=%llu, rejected=%llu, fallback=%llu, degraded=%llu\n"
        "  last reason=%s, ordinal=%u, heap=%08X, flags=%08X, size=%u, "
        "route=%s\n"
        "  caller hash=%s\n"
        "  block enumeration calls=%llu, snapshot builds=%llu\n"
        "  heap enumeration calls=%llu, snapshot rebuilds=%llu\n"
        "  heap destroy snapshots=%llu, blocks collected=%llu\n"
        "  caller heap cache hits=%llu, misses=%llu, bypasses=%llu, "
        "saturated=%llu, entries=%u\n"
        "  next refresh in %lu seconds\n",
        ready ? "YES" : "NO", hooks ? "YES" : "NO", backend, buildIdentity,
        StormTakeover::ModeName(takeover.mode), takeover.threshold, liveBlocks,
        liveMiB, requestedMiB, reservedMiB, committedMiB, failures, rejected,
        fallback, degraded,
        StormTakeover::DegradedReasonName(takeover.lastDegradedReason),
        static_cast<unsigned>(takeover.lastOrdinal), takeover.lastHeapId,
        takeover.lastStormFlags, takeover.lastRequestedSize,
        StormTakeover::RouteName(takeover.lastRoute),
        takeover.directCallerHash ? "direct-verified" : "native-trampoline",
        blockEnumCalls, blockEnumBuilds, heapEnumCalls,
        heapEnumRebuilds, destroySnapshots, destroyBlocks, callerCacheHits,
        callerCacheMisses, callerCacheBypasses, callerCacheSaturated,
        callerCacheEntries,
        ControlPanelIntervalMilliseconds() / 1000);
    std::fflush(stdout);
  }
#endif
}

DWORD WINAPI ControlPanelThreadMain(LPVOID) {
  EmitControlPanelStatus();
  const DWORD interval = ControlPanelIntervalMilliseconds();
  while (WaitForSingleObject(g_controlPanelStopEvent, interval) ==
         WAIT_TIMEOUT) {
    EmitControlPanelStatus();
  }
  return 0;
}

bool StartControlPanel() {
  if (!ShouldEnableControlPanel() || g_controlPanelThread != nullptr) {
    return true;
  }
  g_controlPanelStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!g_controlPanelStopEvent) {
    return false;
  }
  g_controlPanelThread =
      CreateThread(nullptr, 0, ControlPanelThreadMain, nullptr, 0, nullptr);
  if (!g_controlPanelThread) {
    CloseHandle(g_controlPanelStopEvent);
    g_controlPanelStopEvent = nullptr;
    return false;
  }
  return true;
}

bool StopControlPanel() {
  if (!g_controlPanelThread) {
    return true;
  }
  SetEvent(g_controlPanelStopEvent);
  if (WaitForSingleObject(g_controlPanelThread, 5000) != WAIT_OBJECT_0) {
    return false;
  }
  CloseHandle(g_controlPanelThread);
  CloseHandle(g_controlPanelStopEvent);
  g_controlPanelThread = nullptr;
  g_controlPanelStopEvent = nullptr;
  return true;
}
} // namespace

// 工作线程函数 - 在Loader Lock外执行所有重活
static DWORD WINAPI StormBreakerWorkerThread(LPVOID) {

  Logger::GetInstance().LogInfo("开始异步初始化StormBreaker系统...");

  // 第一步：初始化基础系统
  if (!InitializeStormBreaker()) {
    Logger::GetInstance().LogError("StormBreaker基础系统初始化失败");
    return 1;
  }

  // 第二步：安装Hook
  if (!InstallStormHooks()) {
    Logger::GetInstance().LogError("Storm Hook安装失败");
    ShutdownStormBreaker();
    return 2;
  }

  // if (!InstallPathCapUnlock(2.0f)) {
  //   Logger::GetInstance().LogWarning(
  //       "寻路容量写入未成功（可能是版本偏移变化），继续运行不影响其他功能");
  // }

  // 第三步：启动内存监控
  if (ShouldEnableMemoryMonitor() && !StartMemoryMonitoring()) {
    Logger::GetInstance().LogWarning("内存监控启动失败，但系统可继续运行");
  } else if (!ShouldEnableMemoryMonitor()) {
    Logger::GetInstance().LogInfo(
        "内存监控线程默认关闭，可用 STORMBREAKER_MEMORY_MONITOR=1 启用");
  }

  g_systemInitialized.store(true, std::memory_order_release);
  Logger::GetInstance().LogInfo("StormBreaker系统异步初始化完成");
  if (!StartControlPanel()) {
    Logger::GetInstance().LogWarning(
        "控制面板线程启动失败；文件日志仍可用于确认加载状态");
  }

  return 0;
}

// ======================== 基础系统初始化函数 ========================

bool InitializeStormBreaker() {
  // 检查 DXVK 版是否已经启动了 StormBreaker 机制
  HANDLE dxvkActiveEvent =
      OpenEventA(EVENT_ALL_ACCESS, FALSE, "DXVK_War3_StormBreaker_Active");
  if (dxvkActiveEvent != nullptr) {
    CloseHandle(dxvkActiveEvent);
    OutputDebugStringA(
        "StormBreaker: DXVK integrated StormBreaker is already active; "
        "standalone hook will stay disabled.\n");
    Logger::GetInstance().LogInfo(
        "检测到 DXVK 版 StormBreaker 正在运行，主动放弃挂钩。");
    // 挂起自身启动，通过返回 false 优雅退出初始化线程
    return false;
  }

  const bool verbose = ShouldEnableVerboseLogs();
  const bool enableMemorySafety = verbose || ShouldEnableMemorySafety();
  const bool enableTelemetry = ShouldEnableTelemetry();

  // 初始化日志系统（如果尚未初始化）
  if (!Logger::GetInstance().IsInitialized()) {
    const bool enableConsole = ShouldCreateDebugConsole();
    if (enableConsole) {
      CreateConsole();
    }

    LoggerConfig config =
        verbose ? Logger::GetDebugConfig() : Logger::GetReleaseConfig();
    config.enableConsole = enableConsole;
    config.flushImmediate = verbose;
    const DWORD artifactLength = GetEnvironmentVariableA(
        "STORMBREAKER_ARTIFACT_DIR", g_artifactLogDirectory,
        static_cast<DWORD>(sizeof(g_artifactLogDirectory)));
    if (artifactLength > 0 &&
        artifactLength < sizeof(g_artifactLogDirectory)) {
      config.logDirectory = g_artifactLogDirectory;
    }
    if (!Logger::GetInstance().Initialize(config)) {
      return false;
    }
  }

  Logger::GetInstance().LogInfo("初始化StormBreaker基础系统...");

  bool stormOk = InitializeStormOffsets();
  Logger::GetInstance().LogInfo("Storm偏移初始化: %s",
                                stormOk ? "成功" : "失败");
  if (!stormOk) {
    Logger::GetInstance().LogError(
        "当前 Storm.dll 不是已验证的 Warcraft III 1.27a，拒绝初始化内存接管");
    return false;
  }

  // 初始化内存池
  MemoryPool::SetLatencyTrackingEnabled(enableTelemetry);
  if (!MemoryPool::Initialize()) {
    Logger::GetInstance().LogError("内存池初始化失败");
    return false;
  }

  // 完整块跟踪会在每次分配/释放时维护哈希表，仅在显式诊断模式启用。
  MemorySafetyConfig safetyConfig = MemorySafety::GetDefaultConfig();
  if (!enableMemorySafety) {
    safetyConfig.enableTracking = false;
    safetyConfig.enableValidation = false;
    safetyConfig.enableDeferredFree = false;
    safetyConfig.enableLeakDetection = false;
    safetyConfig.enableCorruptionDetection = false;
  }

  if (!MemorySafety::GetInstance().Initialize(safetyConfig)) {
    Logger::GetInstance().LogError("内存安全系统初始化失败");
    MemoryPool::Shutdown();
    return false;
  }

  // 初始化StormHook系统
  StormHook::SetRuntimeStatsEnabled(enableTelemetry);
  if (!StormHook::Initialize()) {
    Logger::GetInstance().LogError("StormHook系统初始化失败");
    MemorySafety::GetInstance().Shutdown();
    MemoryPool::Shutdown();
    return false;
  }

#if !STORMBREAKER_LARGE_ONLY
  if (!StormTakeover::Initialize()) {
    Logger::GetInstance().LogError("Storm全导出接管层初始化失败");
    StormHook::Shutdown();
    MemorySafety::GetInstance().Shutdown();
    MemoryPool::Shutdown();
    return false;
  }
#else
  Logger::GetInstance().LogInfo(
      "大块专用构建：不初始化全导出 registry，不接管 Storm 小块 heap");
#endif

  if (!StormBreaker::LeakProfiler::StartFromEnvironment()) {
    Logger::GetInstance().LogError("LeakProfiler初始化失败");
#if !STORMBREAKER_LARGE_ONLY
    StormTakeover::Shutdown();
#endif
    StormHook::Shutdown();
    MemorySafety::GetInstance().Shutdown();
    MemoryPool::Shutdown();
    return false;
  }
  if (enableTelemetry) {
    StormBreaker::Telemetry::SetSnapshotProvider(&PublishTelemetrySnapshot);
    if (!StormBreaker::Telemetry::Start()) {
      Logger::GetInstance().LogError("遥测输出初始化失败");
      StormBreaker::Telemetry::SetSnapshotProvider(nullptr);
      StormBreaker::LeakProfiler::Stop();
#if !STORMBREAKER_LARGE_ONLY
      StormTakeover::Shutdown();
#endif
      StormHook::Shutdown();
      MemorySafety::GetInstance().Shutdown();
      MemoryPool::Shutdown();
      return false;
    }
    g_telemetryStarted.store(true, std::memory_order_release);
    PublishTelemetrySnapshot();
  } else {
    Logger::GetInstance().LogInfo(
        "metrics 与详细延迟统计默认关闭，可用 STORMBREAKER_TELEMETRY=1 启用");
  }
  Logger::GetInstance().LogInfo(
      "LeakProfiler模式: %s",
      StormBreaker::LeakProfiler::ModeName(
          StormBreaker::LeakProfiler::GetMode()));

  Logger::GetInstance().LogInfo("StormBreaker基础系统初始化完成");
  return true;
}

void ShutdownStormBreaker() {
  Logger::GetInstance().LogInfo("关闭StormBreaker系统...");

#if STORMBREAKER_LARGE_ONLY
  const size_t liveManagedBlocks = StormHook::GetManagedBlockCount();
#else
  const size_t liveManagedBlocks = static_cast<size_t>(
      StormTakeover::GetRuntimeStats().liveBlocks);
#endif
  const uint64_t livePoolBytes =
      MemoryPool::GetExtendedStats().requestedLiveBytes;
  if (g_hooksInstalled.load(std::memory_order_acquire) &&
      (liveManagedBlocks != 0 || livePoolBytes != 0)) {
    Logger::GetInstance().LogWarning(
        "拒绝关闭：仍有 %zu 个托管块、%llu 字节池内存，必须保持 Hook 与后端存活",
        liveManagedBlocks,
        static_cast<unsigned long long>(livePoolBytes));
    return;
  }

  // 卸载Hook
  if (g_hooksInstalled.load(std::memory_order_acquire)) {
    if (!UninstallStormHooks()) {
      Logger::GetInstance().LogError(
          "拒绝关闭：Detours 未完整卸载，保留 Hook 与内存池");
      return;
    }
  }

  if (!StopControlPanel()) {
    Logger::GetInstance().LogError(
        "拒绝继续关闭：控制面板线程仍可能读取 Hook 与内存池");
    return;
  }

  // 停止内存监控
  if (!StopMemoryMonitoring()) {
    Logger::GetInstance().LogError(
        "拒绝继续关闭：内存监控线程仍可能访问后端");
    return;
  }

  if (g_telemetryStarted.load(std::memory_order_acquire)) {
    PublishTelemetrySnapshot();
    if (!StormBreaker::Telemetry::Stop()) {
      Logger::GetInstance().LogError(
          "拒绝继续关闭：遥测线程仍可能访问后端");
      return;
    }
    g_telemetryStarted.store(false, std::memory_order_release);
    StormBreaker::Telemetry::SetSnapshotProvider(nullptr);
  }
  StormBreaker::LeakProfiler::Stop();

  // 关闭各个子系统
#if !STORMBREAKER_LARGE_ONLY
  if (!StormTakeover::Shutdown()) {
    Logger::GetInstance().LogError(
        "拒绝继续关闭：全导出接管层仍有存活块或Hook");
    return;
  }
#endif
  StormHook::Shutdown();
  MemorySafety::GetInstance().Shutdown();
  MemoryPool::Shutdown();

  g_systemInitialized.store(false, std::memory_order_release);

  Logger::GetInstance().LogInfo("StormBreaker系统已关闭");

  Logger::GetInstance().Shutdown();

  if (GetConsoleWindow() != nullptr) {
    FreeConsole();
  }
}

// ======================== Hook安装和卸载函数 ========================

bool InstallStormHooks() {
  Logger::GetInstance().LogInfo("安装Storm Hook...");

  if (g_hooksInstalled.load(std::memory_order_acquire)) {
    return true;
  }
#if STORMBREAKER_LARGE_ONLY
  HMODULE storm = GetModuleHandleA("Storm.dll");
  StormApi::ResolvedApi verified{};
  wchar_t failure[256]{};
  if (!storm || !StormVersionProfile::ResolveVerified127a(
                    storm, &verified, failure, ARRAYSIZE(failure))) {
    Logger::GetInstance().LogError(
        "大块Hook版本校验失败；保持原生Storm不变: %ls", failure);
    return false;
  }
  if (!StormNativeSmallRepair::Configure(verified)) {
    Logger::GetInstance().LogError(
        "STORMBREAKER_NATIVE_SMALL_REPAIR 配置无效或 Storm 内部函数校验失败");
    return false;
  }

  g_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(verified.alloc);
  g_origStormFree = reinterpret_cast<Storm_MemFree_t>(verified.free);
  g_origStormGetSize =
      reinterpret_cast<Storm_MemGetSize_t>(verified.getSize);
  g_origStormReAlloc =
      reinterpret_cast<Storm_MemReAlloc_t>(verified.reAlloc);
  g_origCleanupAll = nullptr;
  g_origResetMemoryManager = nullptr;

  const auto clearOriginals = []() noexcept {
    g_origStormAlloc = nullptr;
    g_origStormFree = nullptr;
    g_origStormGetSize = nullptr;
    g_origStormReAlloc = nullptr;
    StormNativeSmallRepair::Reset();
  };
  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook DetourTransactionBegin失败: %ld", result);
    clearOriginals();
    return false;
  }
  result = DetourUpdateThread(GetCurrentThread());
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook DetourUpdateThread失败: %ld", result);
    DetourTransactionAbort();
    clearOriginals();
    return false;
  }

  const auto attach = [](PVOID *target, PVOID hook,
                         const char *name) noexcept -> bool {
    const LONG attachResult = DetourAttach(target, hook);
    if (attachResult != NO_ERROR) {
      Logger::GetInstance().LogError(
          "DetourAttach(%s)失败: %ld", name, attachResult);
      return false;
    }
    return true;
  };
  bool attached =
      attach(&reinterpret_cast<PVOID &>(g_origStormAlloc),
             reinterpret_cast<PVOID>(Hooked_Storm_MemAlloc),
             "401 SMemAlloc") &&
      attach(&reinterpret_cast<PVOID &>(g_origStormFree),
             reinterpret_cast<PVOID>(Hooked_Storm_MemFree),
             "403 SMemFree") &&
      attach(&reinterpret_cast<PVOID &>(g_origStormGetSize),
             reinterpret_cast<PVOID>(Hooked_Storm_MemGetSize),
             "404 SMemGetSize") &&
      attach(&reinterpret_cast<PVOID &>(g_origStormReAlloc),
             reinterpret_cast<PVOID>(Hooked_Storm_MemReAlloc),
             "405 SMemReAlloc");
  if (attached) {
    const LONG repairResult = StormNativeSmallRepair::Attach();
    if (repairResult != NO_ERROR) {
      Logger::GetInstance().LogError(
          "DetourAttach(StormHeap_AllocPage native repair)失败: %ld",
          repairResult);
      attached = false;
    }
  }
  if (!attached) {
    DetourTransactionAbort();
    clearOriginals();
    return false;
  }
  result = DetourTransactionCommit();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook Detours事务提交失败: %ld", result);
    clearOriginals();
    return false;
  }

  g_hooksInstalled.store(true, std::memory_order_release);
  Logger::GetInstance().LogInfo(
      "Storm大块Hook安装成功: ordinals 401/403/404/405, threshold=0x%zX, "
      "native-small-repair=%s",
      StormHook::GetLargeBlockThreshold(),
      StormNativeSmallRepair::GetModeName());
  PublishTelemetrySnapshot();
  return true;
#else
  HMODULE verifiedStorm = GetModuleHandleA("Storm.dll");
  if (!verifiedStorm || !StormTakeover::Install(verifiedStorm)) {
    Logger::GetInstance().LogError(
        "全导出Storm Hook安装失败；保持原生Storm不变");
    return false;
  }
  g_hooksInstalled.store(true, std::memory_order_release);
  PublishTelemetrySnapshot();
  return true;
#endif

#if 0 // Retained only as a source-level reference for the legacy large hook.

  if (g_hooksInstalled.load(std::memory_order_acquire)) {
    Logger::GetInstance().LogInfo("Storm Hook已安装，跳过重复安装");
    return true;
  }

  HMODULE hStorm = GetModuleHandleA("Storm.dll");
  if (!hStorm) {
    Logger::GetInstance().LogError("未找到Storm.dll模块");
    return false;
  }

  // 尝试通过导出名获取函数地址
  auto pAlloc = GetProcAddress(hStorm, "SMemAlloc");
  auto pFree = GetProcAddress(hStorm, "SMemFree");
  auto pReAlloc = GetProcAddress(hStorm, "SMemReAlloc");
  auto pGetSize = GetProcAddress(hStorm, "SMemGetSize");
  auto pCleanup = GetProcAddress(hStorm, "SMemHeapCleanupAll");
  auto pReset = GetProcAddress(hStorm, "ResetMemoryManager");

  // 如果导出名不存在，尝试已知偏移（需要根据实际版本调整）
  if (!pAlloc || !pFree || !pReAlloc || !pGetSize || !pReset) {
    Logger::GetInstance().LogWarning(
        "部分导出名未找到，尝试使用已知偏移（风险较高）");
    uintptr_t base = reinterpret_cast<uintptr_t>(hStorm);

    // 这些偏移需要根据实际的Storm.dll版本进行调整
    if (!pAlloc)
      pAlloc = reinterpret_cast<FARPROC>(base + 0x2B830);
    if (!pFree)
      pFree = reinterpret_cast<FARPROC>(base + 0x2BE40);
    if (!pReAlloc)
      pReAlloc = reinterpret_cast<FARPROC>(base + 0x2C8B0);
    if (!pGetSize)
      pGetSize = reinterpret_cast<FARPROC>(base + 0x2C000);
    // ResetMemoryManager偏移尚未确认，默认不启用
    if (!pCleanup)
      pCleanup = reinterpret_cast<FARPROC>(base + 0x2AB50);
  }

  // 保存原始函数指针
  g_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(pAlloc);
  g_origStormFree = reinterpret_cast<Storm_MemFree_t>(pFree);
  g_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(pReAlloc);
  g_origStormGetSize = reinterpret_cast<Storm_MemGetSize_t>(pGetSize);
  g_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(pCleanup);
  g_origResetMemoryManager = reinterpret_cast<ResetMemoryManager_t>(pReset);

  if (!g_origStormAlloc || !g_origStormFree || !g_origStormReAlloc) {
    Logger::GetInstance().LogError(
        "缺少必须的 SMemAlloc/SMemFree/SMemReAlloc 地址，拒绝安装 Hook");
    return false;
  }

  // 使用Detours安装Hook
  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError("DetourTransactionBegin失败: %ld", result);
    return false;
  }

  result = DetourUpdateThread(GetCurrentThread());
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError("DetourUpdateThread失败: %ld", result);
    DetourTransactionAbort();
    return false;
  }

  auto attach = [&](PVOID *target, PVOID hook, const char *name) -> bool {
    const LONG attachResult = DetourAttach(target, hook);
    if (attachResult != NO_ERROR) {
      Logger::GetInstance().LogError("DetourAttach(%s)失败: %ld", name,
                                     attachResult);
      return false;
    }
    return true;
  };

  // Hook主要的内存函数
  if (!attach(&reinterpret_cast<PVOID &>(g_origStormAlloc),
              reinterpret_cast<PVOID>(Hooked_Storm_MemAlloc), "SMemAlloc") ||
      !attach(&reinterpret_cast<PVOID &>(g_origStormFree),
              reinterpret_cast<PVOID>(Hooked_Storm_MemFree), "SMemFree") ||
      !attach(&reinterpret_cast<PVOID &>(g_origStormReAlloc),
              reinterpret_cast<PVOID>(Hooked_Storm_MemReAlloc),
              "SMemReAlloc")) {
    DetourTransactionAbort();
    return false;
  }
  if (g_origStormGetSize) {
    if (!attach(&reinterpret_cast<PVOID &>(g_origStormGetSize),
                reinterpret_cast<PVOID>(Hooked_Storm_MemGetSize),
                "SMemGetSize")) {
      DetourTransactionAbort();
      return false;
    }
  } else {
    Logger::GetInstance().LogWarning(
        "未能定位 SMemGetSize，相关兼容功能将被禁用");
  }
  if (g_origResetMemoryManager) {
    if (!attach(&reinterpret_cast<PVOID &>(g_origResetMemoryManager),
                reinterpret_cast<PVOID>(Hooked_ResetMemoryManager),
                "ResetMemoryManager")) {
      DetourTransactionAbort();
      return false;
    }
  } else {
    Logger::GetInstance().LogWarning(
        "未能定位 ResetMemoryManager，Reset 协同功能暂不可用");
  }

  // Hook清理函数（如果找到的话）
  if (g_origCleanupAll) {
    if (!attach(&reinterpret_cast<PVOID &>(g_origCleanupAll),
                reinterpret_cast<PVOID>(Hooked_StormHeap_CleanupAll),
                "SMemHeapCleanupAll")) {
      DetourTransactionAbort();
      return false;
    }
  }

  result = DetourTransactionCommit();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError("Detours事务提交失败: %ld", result);
    return false;
  }

  Logger::GetInstance().LogInfo("Storm Hook安装成功");
  g_hooksInstalled.store(true, std::memory_order_release);
  PublishTelemetrySnapshot();
  return true;
#endif
}

bool UninstallStormHooks() {
  if (!g_hooksInstalled.load(std::memory_order_acquire)) {
    return true;
  }
#if STORMBREAKER_LARGE_ONLY
  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook卸载事务启动失败: %ld", result);
    return false;
  }
  result = DetourUpdateThread(GetCurrentThread());
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook卸载线程登记失败: %ld", result);
    DetourTransactionAbort();
    return false;
  }

  const auto detach = [](PVOID *target, PVOID hook,
                         const char *name) noexcept -> bool {
    const LONG detachResult = DetourDetach(target, hook);
    if (detachResult != NO_ERROR) {
      Logger::GetInstance().LogError(
          "DetourDetach(%s)失败: %ld", name, detachResult);
      return false;
    }
    return true;
  };
  bool detached =
      detach(&reinterpret_cast<PVOID &>(g_origStormAlloc),
             reinterpret_cast<PVOID>(Hooked_Storm_MemAlloc),
             "401 SMemAlloc") &&
      detach(&reinterpret_cast<PVOID &>(g_origStormFree),
             reinterpret_cast<PVOID>(Hooked_Storm_MemFree),
             "403 SMemFree") &&
      detach(&reinterpret_cast<PVOID &>(g_origStormGetSize),
             reinterpret_cast<PVOID>(Hooked_Storm_MemGetSize),
             "404 SMemGetSize") &&
      detach(&reinterpret_cast<PVOID &>(g_origStormReAlloc),
             reinterpret_cast<PVOID>(Hooked_Storm_MemReAlloc),
             "405 SMemReAlloc");
  if (detached) {
    const LONG repairResult = StormNativeSmallRepair::Detach();
    if (repairResult != NO_ERROR) {
      Logger::GetInstance().LogError(
          "DetourDetach(StormHeap_AllocPage native repair)失败: %ld",
          repairResult);
      detached = false;
    }
  }
  if (!detached) {
    DetourTransactionAbort();
    Logger::GetInstance().LogError(
        "大块Hook未完整卸载；保留trampoline、Hook和内存池");
    return false;
  }
  result = DetourTransactionCommit();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogError(
        "大块Hook卸载事务提交失败: %ld；保留后端");
    return false;
  }

  g_hooksInstalled.store(false, std::memory_order_release);
  g_origStormAlloc = nullptr;
  g_origStormFree = nullptr;
  g_origStormGetSize = nullptr;
  g_origStormReAlloc = nullptr;
  StormNativeSmallRepair::Reset();
  PublishTelemetrySnapshot();
  return true;
#else
  if (!StormTakeover::Uninstall()) {
    Logger::GetInstance().LogError(
        "全导出Detours未完整卸载；保留trampoline、Hook和内存池");
    return false;
  }
  g_hooksInstalled.store(false, std::memory_order_release);
  PublishTelemetrySnapshot();
  return true;
#endif

#if 0 // Retained only as a source-level reference for the legacy large hook.
  if (!g_hooksInstalled.load(std::memory_order_acquire)) {
    return true;
  }

  Logger::GetInstance().LogInfo("卸载Storm Hook...");

  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogWarning("DetourTransactionBegin(卸载)失败: %ld",
                                     result);
    return false;
  }

  result = DetourUpdateThread(GetCurrentThread());
  if (result != NO_ERROR) {
    Logger::GetInstance().LogWarning("DetourUpdateThread(卸载)失败: %ld",
                                     result);
    DetourTransactionAbort();
    return false;
  }

  auto detach = [&](PVOID *target, PVOID hook, const char *name) -> bool {
    const LONG detachResult = DetourDetach(target, hook);
    if (detachResult != NO_ERROR) {
      Logger::GetInstance().LogWarning("DetourDetach(%s)失败: %ld", name,
                                       detachResult);
      return false;
    }
    return true;
  };

  if (g_origStormAlloc) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origStormAlloc),
                reinterpret_cast<PVOID>(Hooked_Storm_MemAlloc), "SMemAlloc")) {
      DetourTransactionAbort();
      return false;
    }
  }
  if (g_origStormFree) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origStormFree),
                reinterpret_cast<PVOID>(Hooked_Storm_MemFree), "SMemFree")) {
      DetourTransactionAbort();
      return false;
    }
  }
  if (g_origStormReAlloc) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origStormReAlloc),
                reinterpret_cast<PVOID>(Hooked_Storm_MemReAlloc),
                "SMemReAlloc")) {
      DetourTransactionAbort();
      return false;
    }
  }
  if (g_origStormGetSize) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origStormGetSize),
                reinterpret_cast<PVOID>(Hooked_Storm_MemGetSize),
                "SMemGetSize")) {
      DetourTransactionAbort();
      return false;
    }
  }
  if (g_origResetMemoryManager) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origResetMemoryManager),
                reinterpret_cast<PVOID>(Hooked_ResetMemoryManager),
                "ResetMemoryManager")) {
      DetourTransactionAbort();
      return false;
    }
  }
  if (g_origCleanupAll) {
    if (!detach(&reinterpret_cast<PVOID &>(g_origCleanupAll),
                reinterpret_cast<PVOID>(Hooked_StormHeap_CleanupAll),
                "SMemHeapCleanupAll")) {
      DetourTransactionAbort();
      return false;
    }
  }

  result = DetourTransactionCommit();
  if (result != NO_ERROR) {
    Logger::GetInstance().LogWarning("Detours卸载失败: %ld", result);
    return false;
  }

  Logger::GetInstance().LogInfo("Storm Hook卸载成功");
  g_hooksInstalled.store(false, std::memory_order_release);
  PublishTelemetrySnapshot();

  // 清空函数指针
  g_origStormAlloc = nullptr;
  g_origStormFree = nullptr;
  g_origStormReAlloc = nullptr;
  g_origStormGetSize = nullptr;
  g_origCleanupAll = nullptr;
  g_origResetMemoryManager = nullptr;
  return true;
#endif
}

// ======================== 内存监控启动/停止 ========================

namespace {
// Avoid a MemoryMonitor destructor running from CRT process detach under the
// loader lock. It is deleted only by the explicit clean shutdown path.
static MemoryMonitor *g_memoryMonitor = nullptr;
static std::atomic<DWORD> g_lastStatsTime{0};
} // namespace

bool StartMemoryMonitoring() {
  Logger::GetInstance().LogInfo("启动内存监控...");

  try {
    if (!g_memoryMonitor) {
      g_memoryMonitor = new (std::nothrow) MemoryMonitor();
    }
    if (!g_memoryMonitor) {
      Logger::GetInstance().LogWarning("内存监控器分配失败");
      return false;
    }
    g_memoryMonitor->StartMonitoring(5000); // 5秒间隔
    Logger::GetInstance().LogInfo("内存监控启动成功");
    return true;
  } catch (const std::exception &e) {
    Logger::GetInstance().LogWarning("内存监控启动失败: %s", e.what());
    return false;
  } catch (...) {
    Logger::GetInstance().LogWarning("内存监控启动失败: 未知异常");
    return false;
  }
}

bool StopMemoryMonitoring() {
  Logger::GetInstance().LogInfo("停止内存监控...");

  try {
    if (g_memoryMonitor) {
      if (!g_memoryMonitor->StopMonitoring()) {
        return false;
      }
      delete g_memoryMonitor;
      g_memoryMonitor = nullptr;
    }
    Logger::GetInstance().LogInfo("内存监控已停止");
    return true;
  } catch (...) {
    Logger::GetInstance().LogWarning("停止内存监控时发生异常");
    return false;
  }
}

// ======================== 安全的DllMain实现 ========================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  switch (dwReason) {
  case DLL_PROCESS_ATTACH: {
    // 在Loader Lock下只做最基本的操作
    DisableThreadLibraryCalls(hModule);
    if (!PinModuleUntilProcessExit()) {
      return FALSE;
    }

    // 立即启动工作线程处理所有复杂初始化
    g_initThread = CreateThread(nullptr,                  // 默认安全属性
                                0,                        // 默认栈大小
                                StormBreakerWorkerThread, // 线程函数
                                nullptr,                  // 线程参数
                                0,                        // 默认创建标志
                                nullptr                   // 不需要线程ID
    );

    if (!g_initThread) {
      // 如果创建线程失败，记录到调试输出（不能用我们的Logger）
      OutputDebugStringA("StormBreaker: 无法创建初始化线程\n");
      return FALSE;
    }

    // 立即关闭线程句柄（线程继续运行）
    CloseHandle(g_initThread);
    g_initThread = nullptr;

    break;
  }

  case DLL_PROCESS_DETACH: {
    OutputDebugStringA(
        lpReserved != nullptr
            ? "StormBreaker: process exit; hooks and pools left for OS reclaim\n"
            : "StormBreaker: unexpected explicit detach; no teardown under loader lock\n");
    break;
  }

  default:
    break;
  }

  return TRUE;
}

// ======================== 公共状态查询接口 ========================

namespace StormBreaker {
// 检查系统是否已完全初始化
bool IsSystemReady() {
  return g_systemInitialized.load(std::memory_order_acquire);
}

// 检查Hook是否已安装
bool AreHooksInstalled() {
  return g_hooksInstalled.load(std::memory_order_acquire);
}

// 等待系统就绪（带超时）
bool WaitForSystemReady(DWORD timeoutMs = 10000) {
  DWORD startTime = GetTickCount();

  while (!g_systemInitialized.load(std::memory_order_acquire)) {
    if (GetTickCount() - startTime > timeoutMs) {
      return false; // 超时
    }
    Sleep(100);
  }

  return true;
}

// 强制同步初始化（仅用于测试或特殊情况）
bool ForceInitialize() {
  if (g_systemInitialized.load(std::memory_order_acquire)) {
    return true; // 已经初始化
  }

  if (!InitializeStormBreaker()) {
    return false;
  }

  if (!InstallStormHooks()) {
    ShutdownStormBreaker();
    return false;
  }

  g_hooksInstalled.store(true, std::memory_order_release);
  g_systemInitialized.store(true, std::memory_order_release);

  return true;
}
} // namespace StormBreaker
