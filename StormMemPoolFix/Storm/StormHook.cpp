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

// 线程局部存储，防止递归调用
thread_local bool g_inAllocHook = false;
thread_local bool g_inFreeHook = false;
thread_local bool g_inReallocHook = false;
thread_local DWORD g_hookDepth = 0;

// 最大Hook深度保护
static const DWORD MAX_HOOK_DEPTH = 3;

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
    static std::atomic<bool> reportInProgress{ false };
    if (reportInProgress.exchange(true)) {
        return; // 已经在生成报告，避免重复
    }

    static std::atomic<DWORD> lastReportTime{ 0 };
    DWORD currentTime = GetTickCount();
    DWORD lastTime = lastReportTime.load();

    if (!forceWrite && (currentTime - lastTime < 30000)) {
        reportInProgress.store(false);
        return;
    }

    if (!forceWrite && !lastReportTime.compare_exchange_strong(lastTime, currentTime)) {
        reportInProgress.store(false);
        return;
    }

    __try {
        // 快速收集统计数据
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

        // 使用静态缓冲区避免动态分配
        static char reportBuffer[2048];
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
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 静默处理异常，避免影响游戏
    }

    reportInProgress.store(false);
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
    // 递归检测
    if (g_inAllocHook || g_hookDepth >= MAX_HOOK_DEPTH) {
        // 递归调用，直接调用原始函数
        if (s_origStormAlloc) {
            return s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        }
        return 0;
    }

    // 参数验证
    if (size == 0 || size > 0x10000000) {
        return 0;
    }

    // 设置递归保护
    g_inAllocHook = true;
    g_hookDepth++;

    size_t result = 0;

    // 如果系统未就绪，直接调用原始函数
    if (!g_systemReady.load(std::memory_order_acquire)) {
        if (s_origStormAlloc) {
            result = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        }
    }
    else {
        // 尝试使用我们的分配器
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        void* ptr = allocator.AllocateCompatible(size, name, src_line, flag);

        if (ptr) {
            result = reinterpret_cast<size_t>(ptr);
            g_hookInterceptions.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            // 回退到原始函数
            if (s_origStormAlloc) {
                result = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
            }
            g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // 清除递归保护
    g_hookDepth--;
    g_inAllocHook = false;

    return result;
}

int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    // 递归检测
    if (g_inFreeHook || g_hookDepth >= MAX_HOOK_DEPTH) {
        // 递归调用，直接调用原始函数
        if (s_origStormFree) {
            return s_origStormFree(a1, name, argList, a4);
        }
        return 1;
    }

    if (!a1) return 1;

    // 设置递归保护
    g_inFreeHook = true;
    g_hookDepth++;

    int result = 1;
    void* ptr = reinterpret_cast<void*>(a1);

    // 如果系统未就绪，直接调用原始函数
    if (!g_systemReady.load(std::memory_order_acquire)) {
        if (s_origStormFree) {
            result = s_origStormFree(a1, name, argList, a4);
        }
    }
    else {
        // 尝试使用我们的分配器
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        if (allocator.IsOurPointer(ptr) && allocator.FreeCompatible(ptr)) {
            result = 1;
            g_hookInterceptions.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            // 回退到原始函数
            if (s_origStormFree) {
                result = s_origStormFree(a1, name, argList, a4);
            }
            g_hookFallbacks.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // 清除递归保护
    g_hookDepth--;
    g_inFreeHook = false;

    return result;
}

static size_t GetSafeBlockSize(void* ptr) {
    if (!ptr) return 0;

    __try {
        // 首先尝试Storm格式
        WORD* magicPtr = (WORD*)((char*)ptr - 2);
        if (*magicPtr == 0x6F6D) {
            // Storm格式，尝试获取大小
            BYTE* flagsPtr = (BYTE*)((char*)ptr - 5);
            if ((*flagsPtr & 0x2) == 0) { // 未释放
                // 这是有效的Storm块，但我们不能轻易获取大小
                // 返回0表示未知
                return 0;
            }
        }

        // 尝试我们的格式
        StormCompatible::StormBlockHeader* header =
            reinterpret_cast<StormCompatible::StormBlockHeader*>(
                static_cast<char*>(ptr) - sizeof(StormCompatible::StormBlockHeader));

        if (header->Magic == 0x6F6D && header->Size > 0 && header->Size < 0x40000000) {
            return header->Size;
        }

        return 0;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static void SafeMemoryCopy(void* dest, const void* src, size_t size) {
    if (!dest || !src || size == 0) return;

    __try {
        // 分批复制，减少一次性访问大量内存的风险
        const size_t chunkSize = 64;
        char* d = static_cast<char*>(dest);
        const char* s = static_cast<const char*>(src);

        while (size > 0) {
            size_t currentChunk = (size < chunkSize) ? size : chunkSize;

            __try {
                memcpy(d, s, currentChunk);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // 这个块复制失败，跳过
                break;
            }

            d += currentChunk;
            s += currentChunk;
            size -= currentChunk;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 完全失败，不复制任何数据
    }
}

void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag) {

    // 递归检测
    if (g_inReallocHook || g_hookDepth >= MAX_HOOK_DEPTH) {
        if (s_origStormReAlloc) {
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }
        return nullptr;
    }

    // 设置递归保护
    g_inReallocHook = true;
    g_hookDepth++;

    void* result = nullptr;

    // lambda形式的cleanup，保证函数任何地方return都会调用
    auto cleanup = [&]() {
        g_hookDepth--;
        g_inReallocHook = false;
        };

    // 基本边界情况处理
    if (!oldPtr) {
        result = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
        cleanup();
        return result;
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        cleanup();
        return nullptr;
    }

    // 如果系统未就绪，直接使用Storm
    if (!g_systemReady.load(std::memory_order_acquire)) {
        if (s_origStormReAlloc) {
            result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }
        cleanup();
        return result;
    }

    // 关键修复：检查指针来源并分别处理
    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();

    bool isOurPointer = allocator.IsOurPointer(oldPtr);

    if (isOurPointer) {
        // 我们分配的指针 - 不能直接传给Storm的Realloc
        // 必须采用：分配新的 -> 复制数据 -> 释放旧的

        // 获取旧块大小
        size_t oldSize = 0;
        StormCompatible::StormBlockHeader* header = StormCompatible::StormBlockHeader::FromUserPtr(oldPtr);
        if (header && header->IsValid()) {
            oldSize = header->Size;
        }

        // 分配新块
        void* newPtr = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
        if (!newPtr) {
            cleanup();
            return nullptr;
        }

        // 复制数据
        if (oldSize > 0) {
            size_t copySize = (oldSize < newSize) ? oldSize : newSize;
            // 安全的内存复制
            __try {
                memcpy(newPtr, oldPtr, copySize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // 复制失败，释放新分配的内存
                Hooked_Storm_MemFree(reinterpret_cast<int>(newPtr), const_cast<char*>(name), src_line, flag);
                cleanup();
                return nullptr;
            }
        }

        // 释放旧块
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);

        result = newPtr;
        cleanup();
        return result;
    }
    else {
        // Storm分配的指针 - 检查是否可以安全传给Storm
        bool canPassToStorm = false;

        __try {
            // 尝试验证这是一个有效的Storm指针
            // 检查魔数
            WORD* magicPtr = (WORD*)((char*)oldPtr - 2);
            if (*magicPtr == 0x6F6D) {
                // 检查标志位
                BYTE* flagsPtr = (BYTE*)((char*)oldPtr - 5);
                if ((*flagsPtr & 0x2) == 0) { // 未释放
                    canPassToStorm = true;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            canPassToStorm = false;
        }

        if (canPassToStorm && s_origStormReAlloc) {
            result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            cleanup();
            return result;
        }
        else {
            // 不能传给Storm，采用安全的方式：分配->复制->释放
            void* newPtr = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
            if (newPtr) {
                // 保守的复制策略 - 复制较小的固定大小
                size_t safeCopySize = (newSize < 256) ? newSize : 256;
                __try {
                    memcpy(newPtr, oldPtr, safeCopySize);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // 复制失败，只复制更小的部分
                    __try {
                        memcpy(newPtr, oldPtr, 64);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // 彻底失败，不复制数据
                    }
                }

                // 尝试释放旧指针
                if (s_origStormFree) {
                    __try {
                        s_origStormFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // 释放失败，记录但继续
                    }
                }
            }
            result = newPtr;
            cleanup();
            return result;
        }
    }
}

void Hooked_StormHeap_CleanupAll() {
    // 直接调用原始函数，不做额外处理
    if (s_origCleanupAll) {
        s_origCleanupAll();
    }
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

bool CheckHookHealth() {
    static DWORD lastCheck = 0;
    DWORD currentTime = GetTickCount();

    // 每30秒检查一次
    if (currentTime - lastCheck < 30000) {
        return true;
    }
    lastCheck = currentTime;

    __try {
        // 检查Hook是否还有效
        if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
            LogMessage("[HealthCheck] Hook函数指针丢失");
            return false;
        }

        // 检查系统状态
        if (!g_systemReady.load()) {
            LogMessage("[HealthCheck] 系统未就绪");
            return false;
        }

        // 检查分配器状态
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        size_t allocated, freed, allocCount, freeCount;
        allocator.GetStatistics(allocated, freed, allocCount, freeCount);

        // 检查统计数据是否合理
        if (allocCount < freeCount) {
            LogMessage("[HealthCheck] 警告：释放次数超过分配次数");
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[HealthCheck] 健康检查异常: 0x%08X", GetExceptionCode());
        return false;
    }
}

// 初始化函数
bool InitializeStormMemoryHooks() {
    // 检查当前栈大小
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(&mbi, &mbi, sizeof(mbi))) {
        size_t stackSize = mbi.RegionSize;
        if (stackSize < 1024 * 1024) { // 如果栈小于1MB
            LogMessage("[Init] 警告：栈大小只有 %zu KB，可能不足", stackSize / 1024);
        }
    }
    
    // 防止重复初始化
    static std::atomic<bool> initialized{false};
    if (initialized.exchange(true)) {
        LogMessage("[Init] 系统已经初始化，跳过重复初始化");
        return true;
    }
    
    LogMessage("[Init] === Storm内存池全面接管初始化开始 ===");
    
    // 基本检查
    if (!LogSystem::GetInstance().Initialize()) {
        printf("[错误] 无法初始化日志系统\n");
        return false;
    }
    
    // 查找Storm.dll
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        stormDll = GetModuleHandleA("storm.dll");
    }
    
    if (!stormDll) {
        LogMessage("[Init] 无法找到Storm.dll模块");
        return false;
    }
    
    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[Init] 找到Storm.dll，基址: 0x%08X", gStormDllBase);
    
    // 初始化原始函数指针（重要：确保这些指针有效）
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);
    
    LogMessage("[Init] Storm函数地址: Alloc=%p, Free=%p, Realloc=%p, CleanupAll=%p",
        s_origStormAlloc, s_origStormFree, s_origStormReAlloc, s_origCleanupAll);
    
    // 验证函数指针
    if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
        LogMessage("[Init] Storm函数指针无效");
        return false;
    }
    
    // 测试原始函数（小心测试）
    LogMessage("[Init] 测试Storm原始函数...");
    size_t testPtr = 0;
    bool testPassed = false;
    
    // 防止递归
    g_inAllocHook = true;
    g_inFreeHook = true;
    
    __try {
        testPtr = s_origStormAlloc(0, 0, 64, "test", 0, 0);
        if (testPtr) {
            s_origStormFree(testPtr, "test", 0, 0);
            testPassed = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[Init] Storm原始函数测试异常: 0x%08X", GetExceptionCode());
    }
    
    // 清除测试保护
    g_inAllocHook = false;
    g_inFreeHook = false;
    
    if (testPassed) {
        LogMessage("[Init] Storm原始函数测试通过");
    } else {
        LogMessage("[Init] 警告：Storm原始函数测试失败，但继续初始化");
    }
    
    // 初始化我们的分配器
    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();
    
    if (!allocator.Initialize()) {
        LogMessage("[Init] Storm兼容分配器初始化失败，但继续使用Storm原函数");
    }
    
    // 安装Hook（谨慎安装）
    LogMessage("[Init] 开始安装Hook...");
    
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    // 逐个安装，检查结果
    LONG result = DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    if (result != NO_ERROR) {
        LogMessage("[Init] Alloc Hook安装失败: %ld", result);
        DetourTransactionAbort();
        return false;
    }
    
    result = DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    if (result != NO_ERROR) {
        LogMessage("[Init] Free Hook安装失败: %ld", result);
        DetourTransactionAbort();
        return false;
    }
    
    result = DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    if (result != NO_ERROR) {
        LogMessage("[Init] Realloc Hook安装失败: %ld", result);
        DetourTransactionAbort();
        return false;
    }
    
    result = DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);
    if (result != NO_ERROR) {
        LogMessage("[Init] CleanupAll Hook安装失败: %ld", result);
        DetourTransactionAbort();
        return false;
    }
    
    result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LogMessage("[Init] Hook提交失败: %ld", result);
        return false;
    }
    
    LogMessage("[Init] Hook安装成功");
    
    // 标记系统就绪（在Hook安装成功后）
    g_systemReady.store(true, std::memory_order_release);
    
    LogMessage("[Init] === Storm内存池全面接管初始化完成 ===");
    return true;
}

static void GenerateFinalReports_SEH() {
    g_memoryTracker.GenerateReport("FinalStormMemoryAllocation.log");
    g_memoryTracker.GenerateMemoryChartReport("FinalStormMemoryChart.html");
    StormDiagnostic::GenerateDiagnosticReport("FinalDiagnostic.html");
}

static void OutputFinalStatistics_SEH() {
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
}

static void DetachAllHooks_SEH() {
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
}

static void ShutdownAllocator_SEH() {
    StormCompatible::StormCompatibleAllocator& allocator =
        StormCompatible::StormCompatibleAllocator::GetInstance();
    allocator.Shutdown();
}


void ShutdownStormMemoryHooks() {
    static std::atomic<bool> shuttingDown{ false };
    if (shuttingDown.exchange(true)) {
        return; // 防止重复关闭
    }

    LogMessage("[关闭] 开始关闭Storm内存池接管系统...");

    // 首先标记系统不可用
    g_systemReady.store(false, std::memory_order_release);

    // 等待一点时间让正在进行的操作完成
    Sleep(100);

    // 停止定期报告线程
    g_memoryTracker.StopPeriodicReporting();

    // 设置退出标志并通知等待的线程
    g_shouldExit.store(true, std::memory_order_release);
    g_shutdownCondition.notify_all();

    // 等待统计线程退出
    if (g_statsThreadHandle) {
        DWORD waitResult = WaitForSingleObject(g_statsThreadHandle, 2000);
        if (waitResult != WAIT_OBJECT_0) {
            LogMessage("[关闭] 统计线程未能在2秒内结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }
        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
    }

    // 生成最终报告
    __try {
        GenerateFinalReports_SEH();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[关闭] 生成最终报告时异常: 0x%08X", GetExceptionCode());
    }

    // 输出统计信息
    __try {
        OutputFinalStatistics_SEH();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[关闭] 输出统计信息时异常: 0x%08X", GetExceptionCode());
    }

    // 安全卸载钩子
    LogMessage("[关闭] 安全卸载钩子...");
    __try {
        DetachAllHooks_SEH();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[关闭] 卸载钩子时异常: 0x%08X", GetExceptionCode());
    }

    // 关闭诊断系统
    StormDiagnostic::DisableDiagnostics();

    // 关闭兼容分配器
    __try {
        ShutdownAllocator_SEH();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[关闭] 关闭兼容分配器时异常: 0x%08X", GetExceptionCode());
    }

    // 关闭日志系统
    LogMessage("[关闭] Storm内存池接管系统关闭完成");
    LogSystem::GetInstance().Shutdown();
}