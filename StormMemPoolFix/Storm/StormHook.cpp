#include "pch.h"
#include "StormHook.h"
#include "StormCompatible.h"
#include "StormDiagnostic.h"
#include <Windows.h>
#include <detours.h>
#include <chrono>
#include <thread>

// 全局变量定义
MemoryStats g_memStats;
Storm_MemAlloc_t s_origStormAlloc = nullptr;
Storm_MemFree_t s_origStormFree = nullptr;
Storm_MemReAlloc_t s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

std::atomic<bool> g_cleanAllInProgress{ false };
std::atomic<bool> g_shouldExit{ false };
std::atomic<size_t> g_peakVirtualMemoryUsage{ 0 };
HANDLE g_statsThreadHandle = NULL;
std::condition_variable g_shutdownCondition;
std::mutex g_shutdownMutex;

// Hook统计
static std::atomic<size_t> g_hookInterceptions{ 0 };
static std::atomic<size_t> g_hookFallbacks{ 0 };
static std::atomic<bool> g_systemReady{ false };

// 辅助函数实现
bool SafeValidatePointer(void* ptr, size_t expectedSize) {
    if (!ptr) return false;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        if (mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
            return false;
        }

        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        if (ptrAddr + expectedSize > regionEnd) {
            return false;
        }

        volatile char firstByte = *static_cast<char*>(ptr);
        if (expectedSize > 1) {
            volatile char lastByte = *static_cast<char*>(static_cast<char*>(ptr) + expectedSize - 1);
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

size_t GetProcessVirtualMemoryUsage() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc))) {
        return pmc.PrivateUsage;
    }

    return 0;
}

void UpdatePeakMemoryUsage() {
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t currentPeak = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    while (currentVMUsage > currentPeak) {
        if (g_peakVirtualMemoryUsage.compare_exchange_weak(currentPeak, currentVMUsage, std::memory_order_relaxed)) {
            if (currentVMUsage - currentPeak > 1024 * 1024) {
                LogMessage("[内存] 新程序虚拟内存峰值: %zu MB (+%zu KB)",
                    currentVMUsage / (1024 * 1024),
                    (currentVMUsage - currentPeak) / 1024);
            }
            break;
        }
        currentPeak = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);
    }
}

size_t GetStormVirtualMemoryUsage() {
    return Storm_g_TotalAllocatedMemory ? Storm_g_TotalAllocatedMemory : 0;
}

bool IsOurBlock(void* ptr) {
    if (!ptr) return false;

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    return allocator.IsOurPointer(ptr);
}

void GenerateMemoryReport(bool forceWrite) {
    static std::atomic<DWORD> lastReportTime{ 0 };
    DWORD currentTime = GetTickCount();
    DWORD lastTime = lastReportTime.load(std::memory_order_relaxed);

    if (!forceWrite && (currentTime - lastTime < 30000)) {
        return;
    }

    if (!forceWrite && !lastReportTime.compare_exchange_strong(lastTime, currentTime, std::memory_order_acquire)) {
        return;
    }

    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t peakVMUsage = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    if (currentVMUsage > peakVMUsage) {
        peakVMUsage = currentVMUsage;
        g_peakVirtualMemoryUsage.store(currentVMUsage, std::memory_order_relaxed);
    }

    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    size_t workingSetMB = 0;

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    size_t allocated, freed, allocCount, freeCount;
    allocator.GetStatistics(allocated, freed, allocCount, freeCount);

    size_t compatUsed = (allocated > freed) ? (allocated - freed) : 0;

    char reportBuffer[2048];
    sprintf_s(reportBuffer,
        "===== 内存使用报告 =====\n"
        "时间: %02d:%02d:%02d\n"
        "程序虚拟内存: %zu MB (峰值: %zu MB)\n"
        "Storm 虚拟内存: %zu MB\n"
        "兼容分配器: %zu MB (%zu 次分配)\n"
        "Hook拦截: %zu 次成功, %zu 次回退\n"
        "工作集大小: %zu MB\n"
        "========================\n",
        st.wHour, st.wMinute, st.wSecond,
        currentVMUsage / (1024 * 1024), peakVMUsage / (1024 * 1024),
        stormVMUsage / (1024 * 1024),
        compatUsed / (1024 * 1024), allocCount,
        g_hookInterceptions.load(), g_hookFallbacks.load(),
        workingSetMB
    );

    LogMessage("\n%s", reportBuffer);
}

void PrintMemoryStatus() {
    thread_local char buffer[512];

    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t peakVMUsage = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    if (currentVMUsage > peakVMUsage) {
        peakVMUsage = currentVMUsage;
        g_peakVirtualMemoryUsage.store(currentVMUsage, std::memory_order_relaxed);
    }

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    size_t allocated, freed, allocCount, freeCount;
    allocator.GetStatistics(allocated, freed, allocCount, freeCount);

    size_t compatUsed = (allocated > freed) ? (allocated - freed) : 0;

    SYSTEMTIME st;
    GetLocalTime(&st);

    sprintf_s(buffer, sizeof(buffer),
        "[%02d:%02d:%02d] [内存] 程序VM: %zu/%zu MB, Storm: %zu MB, 兼容: %zu MB (%zu次)",
        st.wHour, st.wMinute, st.wSecond,
        currentVMUsage / (1024 * 1024), peakVMUsage / (1024 * 1024),
        stormVMUsage / (1024 * 1024),
        compatUsed / (1024 * 1024), allocCount);

    printf("%s\n", buffer);
    LogMessage("%s", buffer);
}

// Hook函数实现
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag) {
    g_memoryTracker.RecordAlloc(size, name);

    if (!g_systemReady.load(std::memory_order_acquire)) {
        g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
        size_t result = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        if (result) {
            g_memStats.OnAlloc(size);
            UpdatePeakMemoryUsage();
        }
        return result;
    }

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    void* result = allocator.AllocateCompatible(size, name, src_line, flag);

    if (result) {
        g_hookInterceptions.fetch_add(1, std::memory_order_relaxed);
        g_memStats.OnAlloc(size);
        UpdatePeakMemoryUsage();

        // 记录诊断信息
        StormDiagnostic::DiagnosticTool::GetInstance().RecordBlockAllocation(
            result, static_cast<char*>(result) - sizeof(StormCompatible::StormBlockHeader),
            size, name, src_line, flag);

        return reinterpret_cast<size_t>(result);
    }

    g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
    LogMessage("[StormHook] 兼容分配器失败，回退到Storm: size=%zu, name=%s", size, name ? name : "null");

    size_t stormResult = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
    if (stormResult) {
        g_memStats.OnAlloc(size);
        UpdatePeakMemoryUsage();
    }

    return stormResult;
}

int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    if (!a1) return 1;

    void* ptr = reinterpret_cast<void*>(a1);

    if (!g_systemReady.load(std::memory_order_acquire)) {
        return s_origStormFree(a1, name, argList, a4);
    }

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    if (allocator.FreeCompatible(ptr)) {
        g_hookInterceptions.fetch_add(1, std::memory_order_relaxed);

        StormCompatible::StormBlockHeader* header = StormCompatible::StormBlockHeader::FromUserPtr(ptr);
        if (header && header->IsValid()) {
            size_t blockSize = header->Size;
            g_memStats.OnFree(blockSize);
            g_memoryTracker.RecordFree(blockSize, name);
        }

        // 记录诊断信息
        StormDiagnostic::DiagnosticTool::GetInstance().RecordBlockDeallocation(ptr);

        return 1;
    }

    g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);

    int result = s_origStormFree(a1, name, argList, a4);
    if (result) {
        g_memoryTracker.RecordFree(0, name);
    }

    return result;
}

void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag) {

    if (!oldPtr) {
        return reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        return nullptr;
    }

    if (!g_systemReady.load(std::memory_order_acquire)) {
        g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
        void* result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        if (result) {
            g_memStats.OnAlloc(newSize);
            UpdatePeakMemoryUsage();
        }
        return result;
    }

    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    void* result = allocator.ReallocateCompatible(oldPtr, newSize, name, src_line, flag);

    if (result) {
        g_hookInterceptions.fetch_add(1, std::memory_order_relaxed);
        g_memStats.OnAlloc(newSize);
        UpdatePeakMemoryUsage();
        return result;
    }

    g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
    LogMessage("[StormHook] 兼容重分配失败，回退到Storm: oldPtr=%p, newSize=%zu", oldPtr, newSize);

    void* stormResult = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
    if (stormResult) {
        g_memStats.OnAlloc(newSize);
        UpdatePeakMemoryUsage();
    }

    return stormResult;
}

void Hooked_StormHeap_CleanupAll() {
    static thread_local bool inCleanup = false;
    if (inCleanup) {
        LogMessage("[CleanAll] 递归调用被阻止");
        return;
    }

    static std::atomic<DWORD> lastCleanupTime{ 0 };
    DWORD currentTime = GetTickCount();
    DWORD lastTime = lastCleanupTime.load();

    if (currentTime - lastTime < 5000) {
        return;
    }

    if (!lastCleanupTime.compare_exchange_strong(lastTime, currentTime)) {
        return;
    }

    inCleanup = true;
    g_cleanAllInProgress.store(true, std::memory_order_release);
    LogMessage("[CleanAll] 开始执行清理");

    bool wasReady = g_systemReady.exchange(false, std::memory_order_acq_rel);

    __try {
        s_origCleanupAll();
        LogMessage("[CleanAll] Storm原始清理完成");

        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        size_t allocated, freed, allocCount, freeCount;
        allocator.GetStatistics(allocated, freed, allocCount, freeCount);

        LogMessage("[CleanAll] 兼容分配器统计: 已分配=%zu MB, 已释放=%zu MB",
            allocated / (1024 * 1024), freed / (1024 * 1024));

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[CleanAll] 清理过程中捕获到异常: 0x%08X", GetExceptionCode());
    }

    if (wasReady) {
        g_systemReady.store(true, std::memory_order_release);
    }

    g_cleanAllInProgress.store(false, std::memory_order_release);
    inCleanup = false;
    LogMessage("[CleanAll] 清理完成");
}

// 统计线程
DWORD WINAPI MemoryStatsThread(LPVOID) {
    LogMessage("[StatsThread] 内存监控线程已启动");

    std::unique_lock<std::mutex> lock(g_shutdownMutex, std::defer_lock);

    DWORD lastStatsTime = GetTickCount();
    DWORD lastReportTime = GetTickCount();

    while (!g_shouldExit.load(std::memory_order_acquire)) {
        lock.lock();
        bool shouldExit = g_shutdownCondition.wait_for(lock, std::chrono::seconds(10),
            [] { return g_shouldExit.load(std::memory_order_acquire); });
        lock.unlock();

        if (shouldExit) break;

        DWORD currentTime = GetTickCount();

        if (currentTime - lastReportTime > 30000) {
            GenerateMemoryReport(false);
            lastReportTime = currentTime;
        }

        if (currentTime - lastStatsTime > 60000) {
            PrintMemoryStatus();

            size_t intercepted = g_hookInterceptions.load();
            size_t fallback = g_hookFallbacks.load();
            size_t total = intercepted + fallback;

            if (total > 0) {
                double interceptRate = (intercepted * 100.0) / total;
                LogMessage("[统计] Hook拦截率: %.1f%% (%zu/%zu)", interceptRate, intercepted, total);
            }

            lastStatsTime = currentTime;
        }
    }

    LogMessage("[StatsThread] 内存监控线程安全退出");
    return 0;
}

// 初始化函数
bool InitializeStormMemoryHooks() {
    // 验证配置有效性
    if (!StormCompatConfig::ValidateConfiguration()) {
        LogMessage("[Init] 配置验证失败");
        return false;
    }

    if (!LogSystem::GetInstance().Initialize()) {
        printf("[错误] 无法初始化日志系统\n");
        return false;
    }



    LogMessage("[Init] === Storm内存池全面接管初始化 ===");
    LogMessage("[Init] 构建时间: %s %s", __DATE__, __TIME__);
    LogMessage("[Init] 编译器: %s",
#ifdef _MSC_VER
        "MSVC"
#elif defined(__GNUC__)
        "GCC"
#else
        "Unknown"
#endif
    );

    // 记录系统信息
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LogMessage("[Init] 系统信息: 处理器数=%u, 页大小=%u",
        sysInfo.dwNumberOfProcessors, sysInfo.dwPageSize);

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        LogMessage("[Init] 内存信息: 物理内存=%zu MB, 可用=%zu MB",
            memStatus.ullTotalPhys / (1024 * 1024),
            memStatus.ullAvailPhys / (1024 * 1024));
    }

    // 初始化Storm兼容分配器
    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    if (!allocator.Initialize()) {
        LogMessage("[Init] Storm兼容分配器初始化失败");
        return false;
    }

    // 初始化诊断系统
    StormDiagnostic::EnableDiagnostics(StormDiagnostic::DiagnosticLevel::Basic);

    // 查找Storm.dll基址
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        LogMessage("[Init] 未找到Storm.dll模块");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[Init] 找到Storm.dll，基址: 0x%08X", gStormDllBase);

    // 初始化原始函数指针
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);

    LogMessage("[Init] Storm函数地址: Alloc=%p, Free=%p, Realloc=%p, CleanupAll=%p",
        s_origStormAlloc, s_origStormFree, s_origStormReAlloc, s_origCleanupAll);

    if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
        LogMessage("[Init] 无法找到Storm内存函数");
        return false;
    }

    // 安装钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LogMessage("[Init] 安装钩子失败，错误: %ld", result);
        return false;
    }

    // 启动统计线程
    HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
    if (hThread) {
        g_statsThreadHandle = hThread;
    }

    // 启动定期HTML报告生成
    g_memoryTracker.StartPeriodicReporting(30000);

    // 标记系统就绪
    g_systemReady.store(true, std::memory_order_release);

    // 重置Storm的g_DebugHeapPtr
    Storm_g_DebugHeapPtr = 0;

    // 输出初始内存报告
    GenerateMemoryReport(true);

    LogMessage("[Init] Storm内存池全面接管初始化成功！");
    return true;
}

// 关闭函数
void ShutdownStormMemoryHooks() {
    LogMessage("[关闭] 开始关闭Storm内存池接管系统...");

    g_systemReady.store(false, std::memory_order_release);

    // 停止定期报告线程
    g_memoryTracker.StopPeriodicReporting();

    // 设置退出标志并通知等待的线程
    g_shouldExit.store(true, std::memory_order_release);
    g_shutdownCondition.notify_all();

    // 等待统计线程退出
    if (g_statsThreadHandle) {
        DWORD waitResult = WaitForSingleObject(g_statsThreadHandle, 1000);
        if (waitResult != WAIT_OBJECT_0) {
            LogMessage("[关闭] 统计线程未能在1秒内结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }
        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
    }

    // 生成最终报告
    LogMessage("[关闭] 生成最终内存报告...");
    g_memoryTracker.GenerateReport("FinalStormMemoryAllocation.log");
    g_memoryTracker.GenerateMemoryChartReport("FinalStormMemoryChart.html");
    StormDiagnostic::GenerateDiagnosticReport("FinalDiagnostic.html");

    // 输出统计信息
    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    size_t allocated, freed, allocCount, freeCount;
    allocator.GetStatistics(allocated, freed, allocCount, freeCount);

    LogMessage("[关闭] 兼容分配器最终统计:");
    LogMessage("  - 总分配: %zu 次, %zu MB", allocCount, allocated / (1024 * 1024));
    LogMessage("  - 总释放: %zu 次, %zu MB", freeCount, freed / (1024 * 1024));
    LogMessage("  - 当前使用: %zu MB", (allocated - freed) / (1024 * 1024));

    size_t totalIntercepted = g_hookInterceptions.load();
    size_t totalFallback = g_hookFallbacks.load();
    size_t total = totalIntercepted + totalFallback;

    if (total > 0) {
        double interceptRate = (totalIntercepted * 100.0) / total;
        LogMessage("[关闭] Hook拦截统计: %zu/%zu (%.1f%%) 被兼容分配器处理",
            totalIntercepted, total, interceptRate);
    }

    // 安全卸载钩子
    LogMessage("[关闭] 安全卸载钩子...");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (s_origCleanupAll) {
        DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);
    }

    Sleep(50);

    if (s_origStormReAlloc) {
        DetourDetach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    }

    if (s_origStormFree) {
        DetourDetach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    }

    if (s_origStormAlloc) {
        DetourDetach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    }

    LONG result = DetourTransactionCommit();
    LogMessage("[关闭] 钩子卸载%s", (result == NO_ERROR ? "成功" : "失败"));

    // 关闭诊断系统
    StormDiagnostic::DisableDiagnostics();

    // 关闭兼容分配器
    allocator.Shutdown();

    // 关闭日志系统
    LogMessage("[关闭] Storm内存池接管系统关闭完成");
    LogSystem::GetInstance().Shutdown();
}