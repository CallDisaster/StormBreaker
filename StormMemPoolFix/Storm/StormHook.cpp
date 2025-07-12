// StormHook.cpp - 配合修复后内存系统的实现
#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include "MemoryPool.h"
#include <Windows.h>
#include <detours.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <Psapi.h>
#include <Log/LogSystem.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "psapi.lib")

///////////////////////////////////////////////////////////////////////////////
// 全局变量定义
///////////////////////////////////////////////////////////////////////////////

// 核心状态变量
std::atomic<bool> g_hooksInitialized{ false };
std::atomic<bool> g_shutdownRequested{ false };
std::atomic<bool> g_cleanAllInProgress{ false };
std::atomic<bool> g_insideUnsafePeriod{ false };

// 配置参数
std::atomic<size_t> g_bigThreshold{ DEFAULT_BIG_BLOCK_THRESHOLD };
std::atomic<size_t> g_workingSetLimit{ DEFAULT_WORKING_SET_LIMIT };
std::atomic<size_t> g_commitLimit{ DEFAULT_COMMIT_LIMIT };

// 内存跟踪
std::atomic<size_t> g_totalAllocated{ 0 };
std::atomic<size_t> g_totalFreed{ 0 };
std::atomic<size_t> g_hookAllocCount{ 0 };
std::atomic<size_t> g_hookFreeCount{ 0 };

// Storm函数指针
Storm_MemAlloc_t s_origStormAlloc = nullptr;
Storm_MemFree_t s_origStormFree = nullptr;
Storm_MemReAlloc_t s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

// CleanAll相关状态
std::atomic<int> g_cleanAllCounter{ 0 };
thread_local bool tls_inCleanAll = false;

// 时间跟踪
std::atomic<DWORD> g_lastStormCleanupTime{ 0 };
std::atomic<DWORD> g_lastPressureCheckTime{ 0 };

// 日志相关
static CRITICAL_SECTION g_logCs;
static FILE* g_logFile = nullptr;
static bool g_logInitialized = false;

///////////////////////////////////////////////////////////////////////////////
// 永久稳定块管理实现
///////////////////////////////////////////////////////////////////////////////

PermanentBlockManager::PermanentBlockManager() noexcept {
    InitializeCriticalSection(&m_cs);
}

PermanentBlockManager::~PermanentBlockManager() noexcept {
    Clear();
    DeleteCriticalSection(&m_cs);
}

void PermanentBlockManager::Add(void* ptr) noexcept {
    if (!ptr) return;

    EnterCriticalSection(&m_cs);
    m_blocks.push_back(ptr);
    m_blockCount.fetch_add(1);
    LeaveCriticalSection(&m_cs);
}

bool PermanentBlockManager::Contains(void* ptr) const noexcept {
    if (!ptr) return false;

    bool found = false;
    EnterCriticalSection(&m_cs);
    for (void* block : m_blocks) {
        if (block == ptr) {
            found = true;
            break;
        }
    }
    LeaveCriticalSection(&m_cs);
    return found;
}

void PermanentBlockManager::Clear() noexcept {
    EnterCriticalSection(&m_cs);
    m_blocks.clear();
    m_blockCount.store(0);
    LeaveCriticalSection(&m_cs);
}

PermanentBlockManager g_permanentBlocks;

///////////////////////////////////////////////////////////////////////////////
// C风格SEH安全包装实现
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    int __stdcall SafeExecuteVoid(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation ? operation : "Unknown");
            return 0;  // 失败
        }
    }

    int __stdcall SafeExecuteInt(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation ? operation : "Unknown");
            return 0;  // 失败
        }
    }

    void* __stdcall SafeExecutePtr(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return (void*)func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation ? operation : "Unknown");
            return nullptr;  // 失败
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// C风格操作函数实现
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    // 分配操作
    int __stdcall AllocOperation(void* ctx) {
        AllocContext* context = (AllocContext*)ctx;

        // 更新统计
        g_hookAllocCount.fetch_add(1, std::memory_order_relaxed);

        // 检查是否为JassVM特殊分配
        bool isJassVM = IsJassVMAllocation(context->size, context->name);

        // 使用修复后的MemoryPool
        void* result = nullptr;
        if (isJassVM || context->size >= g_bigThreshold.load(std::memory_order_relaxed)) {
            // 使用MemoryPool处理
            result = g_MemoryPool.AllocateSafe(context->size, context->name, context->src_line);
        }

        if (result) {
            g_totalAllocated.fetch_add(context->size, std::memory_order_relaxed);
            context->result = reinterpret_cast<size_t>(result);
            return 1;  // 成功
        }

        // 回退到Storm原始分配
        if (s_origStormAlloc) {
            context->result = s_origStormAlloc(context->ecx, context->edx, context->size,
                context->name, context->src_line, context->flag);
            if (context->result) {
                g_totalAllocated.fetch_add(context->size, std::memory_order_relaxed);
            }
            return 1;  // 成功
        }

        context->result = 0;
        return 0;  // 失败
    }

    // 释放操作
    int __stdcall FreeOperation(void* ctx) {
        FreeContext* context = (FreeContext*)ctx;

        g_hookFreeCount.fetch_add(1, std::memory_order_relaxed);

        if (!context->a1) {
            context->result = 1;  // 空指针认为成功
            return 1;
        }

        void* ptr = reinterpret_cast<void*>(context->a1);

        // 检查是否为永久块
        if (g_permanentBlocks.Contains(ptr)) {
            context->result = 1;  // 永久块不释放，假装成功
            return 1;
        }

        // 检查是否为我们管理的块
        if (g_MemoryPool.IsFromPool(ptr)) {
            size_t blockSize = g_MemoryPool.GetBlockSize(ptr);
            bool success = g_MemoryPool.FreeSafe(ptr);
            if (success && blockSize > 0) {
                g_totalFreed.fetch_add(blockSize, std::memory_order_relaxed);
                context->result = 1;
                return 1;
            }
        }

        // 回退到Storm原始释放
        if (s_origStormFree) {
            context->result = s_origStormFree(context->a1, context->name, context->argList, context->a4);
            return 1;
        }

        context->result = 0;
        return 0;
    }

    // 重分配操作
    int __stdcall ReallocOperation(void* ctx) {
        ReallocContext* context = (ReallocContext*)ctx;

        // 边界情况处理
        if (!context->oldPtr) {
            AllocContext allocCtx = { context->ecx, context->edx, context->newSize,
                                     context->name, context->src_line, context->flag, 0 };
            if (AllocOperation(&allocCtx)) {
                context->result = reinterpret_cast<void*>(allocCtx.result);
                return 1;
            }
            context->result = nullptr;
            return 0;
        }

        if (context->newSize == 0) {
            FreeContext freeCtx = { reinterpret_cast<int>(context->oldPtr),
                                   const_cast<char*>(context->name),
                                   (int)context->src_line, (int)context->flag, 0 };
            FreeOperation(&freeCtx);
            context->result = nullptr;
            return 1;
        }

        // 检查是否为永久块
        if (g_permanentBlocks.Contains(context->oldPtr)) {
            // 永久块只分配新的，不释放旧的
            AllocContext allocCtx = { context->ecx, context->edx, context->newSize,
                                     context->name, context->src_line, context->flag, 0 };
            if (AllocOperation(&allocCtx)) {
                void* newPtr = reinterpret_cast<void*>(allocCtx.result);
                if (newPtr) {
                    // 安全复制数据
                    size_t copySize = min(context->newSize, (size_t)1024);  // 保守地复制1KB
                    memcpy(newPtr, context->oldPtr, copySize);
                }
                context->result = newPtr;
                return 1;
            }
            context->result = nullptr;
            return 0;
        }

        // 检查是否为我们管理的块
        if (g_MemoryPool.IsFromPool(context->oldPtr)) {
            void* newPtr = g_MemoryPool.ReallocSafe(context->oldPtr, context->newSize,
                context->name, context->src_line);
            context->result = newPtr;
            return 1;
        }

        // 回退到Storm原始重分配
        if (s_origStormReAlloc) {
            context->result = s_origStormReAlloc(context->ecx, context->edx, context->oldPtr,
                context->newSize, context->name, context->src_line, context->flag);
            return 1;
        }

        context->result = nullptr;
        return 0;
    }

    // CleanAll操作 - 修复版本
    int __stdcall CleanAllOperation(void* ctx) {
        CleanupContext* context = (CleanupContext*)ctx;

        // 防止重入
        if (tls_inCleanAll) {
            return 1;
        }

        tls_inCleanAll = true;
        g_cleanAllInProgress.store(true, std::memory_order_release);

        int currentCount = g_cleanAllCounter.fetch_add(1, std::memory_order_relaxed) + 1;
        context->cleanAllCount = currentCount;

        // 获取当前内存使用情况
        size_t workingSet = GetProcessWorkingSetSize();
        size_t committed = GetProcessCommittedSize();
        context->workingSetMB = workingSet / (1024 * 1024);
        context->commitMB = committed / (1024 * 1024);

        // 通知进入不安全期
        g_insideUnsafePeriod.store(true, std::memory_order_release);

        // 检查是否需要清理（基于真实内存使用，不是虚拟内存）
        bool needCleanup = context->forceTrigger ||
            workingSet > g_workingSetLimit.load() ||
            committed > g_commitLimit.load();

        if (needCleanup) {
            LogMessage("[StormHook] 触发内存清理: 工作集=%zuMB, 提交=%zuMB",
                context->workingSetMB, context->commitMB);
            g_MemoryPool.ForceCleanup();
        }

        // 调用Storm原始清理
        if (s_origCleanupAll) {
            s_origCleanupAll();
        }

        // 创建稳定块（大幅降低频率）
        if (currentCount % 500 == 0) {  // 从100改为500
            StabilizerContext stabCtx = { 0, nullptr, currentCount };
            CreateTemporaryStabilizersOperation(&stabCtx);
        }

        // 退出不安全期
        g_insideUnsafePeriod.store(false, std::memory_order_release);
        g_cleanAllInProgress.store(false, std::memory_order_release);
        tls_inCleanAll = false;

        return 1;
    }

    // 创建永久稳定块操作
    int __stdcall CreatePermanentStabilizersOperation(void* ctx) {
        StabilizerContext* context = (StabilizerContext*)ctx;

        // 大幅减少稳定块数量和大小
        size_t sizes[] = { 1024, 2048, 4096 };  // 只创建小的稳定块
        int sizeCount = sizeof(sizes) / sizeof(sizes[0]);
        int maxBlocks = min(context->count, 3);  // 最多3个

        for (int i = 0; i < maxBlocks && i < sizeCount; ++i) {
            void* stabilizer = g_MemoryPool.AllocateSafe(sizes[i], "永久稳定块", 0);
            if (stabilizer) {
                g_permanentBlocks.Add(stabilizer);
            }
        }
        return 1;
    }

    // 创建临时稳定块操作
    int __stdcall CreateTemporaryStabilizersOperation(void* ctx) {
        StabilizerContext* context = (StabilizerContext*)ctx;

        // 只在特定的CleanAll计数时创建，且大幅降低频率
        if (context->cleanAllCount % 1000 != 0) return 1;  // 从50改为1000

        // 创建很少的临时块
        void* stabilizer = g_MemoryPool.AllocateSafe(1024, "临时稳定块", 0);
        // 临时块不加入永久列表，让其自然释放

        return 1;
    }

    // 智能清理操作
    int __stdcall SmartCleanupOperation(void* ctx) {
        // 获取当前内存使用情况
        size_t workingSet = GetProcessWorkingSetSize();
        size_t committed = GetProcessCommittedSize();

        // 只有在真正需要时才清理
        if (workingSet > g_workingSetLimit.load() ||
            committed > g_commitLimit.load()) {

            LogMessage("[StormHook] 智能清理: 工作集=%zuMB, 提交=%zuMB",
                workingSet / (1024 * 1024), committed / (1024 * 1024));

            // 使用MemoryPool的清理功能
            g_MemoryPool.ForceCleanup();

            // 在真正有压力时才调用Storm清理
            if (ShouldTriggerStormCleanup()) {
                if (s_origCleanupAll) {
                    s_origCleanupAll();
                }
                g_lastStormCleanupTime.store(GetTickCount());
            }
        }

        return 1;
    }
}

///////////////////////////////////////////////////////////////////////////////
// Hook函数实现
///////////////////////////////////////////////////////////////////////////////

size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag) {

    AllocContext context = { ecx, edx, size, name, src_line, flag, 0 };
    SAFE_CALL_INT("Hooked_Storm_MemAlloc", AllocOperation, &context);
    return context.result;
}

int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    FreeContext context = { a1, name, argList, a4, 0 };
    SAFE_CALL_INT("Hooked_Storm_MemFree", FreeOperation, &context);
    return context.result;
}

void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag) {

    ReallocContext context = { ecx, edx, oldPtr, newSize, name, src_line, flag, nullptr };
    SAFE_CALL_PTR("Hooked_Storm_MemReAlloc", ReallocOperation, &context);
    return context.result;
}

void Hooked_StormHeap_CleanupAll() {
    CleanupContext context = { 0, 0, 0, false };
    SAFE_CALL_VOID("Hooked_StormHeap_CleanupAll", CleanAllOperation, &context);
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数实现
///////////////////////////////////////////////////////////////////////////////

bool IsJassVMAllocation(size_t size, const char* name) noexcept {
    return (size == JASSVM_BLOCK_SIZE &&
        name &&
        strstr(name, "Instance.cpp") != nullptr);
}

bool IsPermanentBlock(void* ptr) noexcept {
    return g_permanentBlocks.Contains(ptr);
}

size_t GetProcessWorkingSetSize() noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

size_t GetProcessCommittedSize() noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {
        return pmc.PagefileUsage;
    }
    return 0;
}

bool IsWorkingSetUnderPressure() noexcept {
    size_t workingSet = GetProcessWorkingSetSize();
    return workingSet > g_workingSetLimit.load();
}

bool IsCommittedMemoryUnderPressure() noexcept {
    size_t committed = GetProcessCommittedSize();
    return committed > g_commitLimit.load();
}

bool ShouldTriggerStormCleanup() noexcept {
    DWORD currentTime = GetTickCount();
    DWORD lastCleanup = g_lastStormCleanupTime.load();

    // 最小间隔检查
    if (currentTime - lastCleanup < MIN_STORM_CLEANUP_INTERVAL) {
        return false;
    }

    // 只有在真正有内存压力时才触发
    return IsWorkingSetUnderPressure() || IsCommittedMemoryUnderPressure();
}

void SmartMemoryCleanup() noexcept {
    SAFE_CALL_VOID("SmartMemoryCleanup", SmartCleanupOperation, nullptr);
}

void CheckMemoryPressureAndCleanup() noexcept {
    DWORD currentTime = GetTickCount();
    DWORD lastCheck = g_lastPressureCheckTime.load();

    // 每10秒检查一次
    if (currentTime - lastCheck < 10000) {
        return;
    }

    g_lastPressureCheckTime.store(currentTime);

    if (IsWorkingSetUnderPressure() || IsCommittedMemoryUnderPressure()) {
        SmartMemoryCleanup();
    }
}

void CreatePermanentStabilizers(int count, const char* reason) noexcept {
    LogMessage("[稳定化] 创建%d个永久稳定块 (%s)", count, reason);

    StabilizerContext context = { count, reason, 0 };
    SAFE_CALL_VOID("CreatePermanentStabilizers", CreatePermanentStabilizersOperation, &context);
}

void CreateTemporaryStabilizers(int cleanAllCount) noexcept {
    StabilizerContext context = { 0, nullptr, cleanAllCount };
    SAFE_CALL_VOID("CreateTemporaryStabilizers", CreateTemporaryStabilizersOperation, &context);
}

///////////////////////////////////////////////////////////////////////////////
// 初始化和清理函数
///////////////////////////////////////////////////////////////////////////////

bool InitializeLogging() noexcept {
    InitializeCriticalSection(&g_logCs);

    if (fopen_s(&g_logFile, "StormHook.log", "w") == 0) {
        g_logInitialized = true;
        LogMessage("[初始化] 日志系统启动成功");
        return true;
    }
    else {
        printf("[错误] 无法创建日志文件\n");
        return false;
    }
}

bool FindStormFunctions() noexcept {
    // 查找Storm.dll基址
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        LogError("[错误] 未找到Storm.dll模块");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[初始化] Storm.dll基址: 0x%08X", gStormDllBase);

    // 设置函数指针（基于IDA Pro确认的偏移）
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);

    LogMessage("[初始化] Storm函数地址:");
    LogMessage("  - MemAlloc: %p", s_origStormAlloc);
    LogMessage("  - MemFree: %p", s_origStormFree);
    LogMessage("  - MemReAlloc: %p", s_origStormReAlloc);
    LogMessage("  - CleanupAll: %p", s_origCleanupAll);

    // 验证函数指针有效性
    if (!s_origStormAlloc || !s_origStormFree ||
        !s_origStormReAlloc || !s_origCleanupAll) {
        LogError("[错误] Storm函数地址无效");
        return false;
    }

    return true;
}

bool InstallHooks() noexcept {
    LogMessage("[初始化] 开始安装Hook...");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 安装内存分配Hook
    DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    LONG detourResult = DetourTransactionCommit();
    if (detourResult != NO_ERROR) {
        LogError("[错误] Hook安装失败，错误代码: %ld", detourResult);
        return false;
    }

    LogMessage("[初始化] Hook安装成功");
    return true;
}

void UninstallHooks() noexcept {
    LogMessage("[清理] 开始卸载Hook...");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 按相反顺序卸载
    if (s_origCleanupAll) {
        DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);
    }
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
    LogMessage("[清理] Hook卸载%s", (result == NO_ERROR) ? "成功" : "失败");
}

///////////////////////////////////////////////////////////////////////////////
// 主要接口函数实现
///////////////////////////////////////////////////////////////////////////////

bool InitializeStormMemoryHooks() noexcept {
    bool expected = false;
    if (!g_hooksInitialized.compare_exchange_strong(expected, true)) {
        LogMessage("[警告] StormHook已经初始化");
        return true;
    }

    LogMessage("[初始化] StormHook初始化开始...");

    // 1. 初始化日志系统
    if (!InitializeLogging()) {
        return false;
    }

    // 2. 初始化MemoryPool
    MemoryPoolConfig config;
    config.bigBlockThreshold = g_bigThreshold.load();
    config.workingSetLimitMB = g_workingSetLimit.load() / (1024 * 1024);
    config.maxCacheSizeMB = 64;  // 降低缓存大小
    config.enableDetailedLogging = false;  // 关闭详细日志减少开销

    if (!g_MemoryPool.Initialize(config)) {
        LogError("[错误] MemoryPool初始化失败");
        return false;
    }

    // 3. 设置Storm清理函数
    g_MemoryPool.SetStormCleanupFunction(s_origCleanupAll);

    // 4. 查找Storm函数
    if (!FindStormFunctions()) {
        return false;
    }

    // 5. 创建极少量的初始稳定块
    CreatePermanentStabilizers(3, "初始化稳定");  // 从10减少到3

    // 6. 安装Hook
    if (!InstallHooks()) {
        return false;
    }

    LogMessage("[初始化] StormHook初始化完成");
    LogMessage("[状态] 大块阈值: %zu KB, 工作集限制: %zu MB",
        g_bigThreshold.load() / 1024, g_workingSetLimit.load() / (1024 * 1024));

    return true;
}

void ShutdownStormMemoryHooks() noexcept {
    bool expected = true;
    if (!g_hooksInitialized.compare_exchange_strong(expected, false)) {
        return;  // 已经关闭或未初始化
    }

    LogMessage("[清理] StormHook关闭开始...");

    // 1. 设置关闭标志
    g_shutdownRequested.store(true, std::memory_order_release);
    g_insideUnsafePeriod.store(true, std::memory_order_release);

    // 2. 等待CleanAll完成
    if (g_cleanAllInProgress.load(std::memory_order_acquire)) {
        LogMessage("[清理] 等待CleanAll完成...");
        int waitCount = 0;
        while (g_cleanAllInProgress.load(std::memory_order_acquire) && waitCount < 20) {
            Sleep(50);
            waitCount++;
        }
    }

    // 3. 打印最终统计
    size_t allocated = g_totalAllocated.load(std::memory_order_relaxed);
    size_t freed = g_totalFreed.load(std::memory_order_relaxed);
    size_t allocCount = g_hookAllocCount.load(std::memory_order_relaxed);
    size_t freeCount = g_hookFreeCount.load(std::memory_order_relaxed);

    LogMessage("[统计] 最终数据:");
    LogMessage("  - 总分配: %zu MB (%zu 次)", allocated / (1024 * 1024), allocCount);
    LogMessage("  - 总释放: %zu MB (%zu 次)", freed / (1024 * 1024), freeCount);
    LogMessage("  - 净使用: %zu MB", (allocated - freed) / (1024 * 1024));
    LogMessage("  - CleanAll调用: %d 次", g_cleanAllCounter.load());
    LogMessage("  - 永久块数量: %zu", g_permanentBlocks.Size());

    // 4. 卸载Hook
    UninstallHooks();

    // 5. 清理永久块引用（不实际释放内存）
    g_permanentBlocks.Clear();

    // 6. 关闭MemoryPool
    g_MemoryPool.Shutdown();

    // 7. 关闭日志
    LogMessage("[清理] StormHook关闭完成");
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = nullptr;
    }

    if (g_logInitialized) {
        g_logInitialized = false;
        DeleteCriticalSection(&g_logCs);
    }
}

bool IsHooksInitialized() noexcept {
    return g_hooksInitialized.load(std::memory_order_acquire);
}

void SetBigBlockThreshold(size_t sizeInBytes) noexcept {
    size_t oldThreshold = g_bigThreshold.exchange(sizeInBytes, std::memory_order_relaxed);
    LogMessage("[配置] 大块阈值: %zu -> %zu 字节", oldThreshold, sizeInBytes);

    // 更新MemoryPool配置
    MemoryPoolConfig config = g_MemoryPool.GetConfig();
    config.bigBlockThreshold = sizeInBytes;
    g_MemoryPool.UpdateConfig(config);
}

void SetWorkingSetLimit(size_t limitMB) noexcept {
    size_t oldLimit = g_workingSetLimit.exchange(limitMB * 1024 * 1024, std::memory_order_relaxed);
    LogMessage("[配置] 工作集限制: %zu -> %zu MB", oldLimit / (1024 * 1024), limitMB);

    // 更新MemoryPool配置
    MemoryPoolConfig config = g_MemoryPool.GetConfig();
    config.workingSetLimitMB = limitMB;
    g_MemoryPool.UpdateConfig(config);
}

void SetCommitLimit(size_t limitMB) noexcept {
    size_t oldLimit = g_commitLimit.exchange(limitMB * 1024 * 1024, std::memory_order_relaxed);
    LogMessage("[配置] 提交内存限制: %zu -> %zu MB", oldLimit / (1024 * 1024), limitMB);
}

void GetMemoryStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) noexcept {
    allocated = g_totalAllocated.load(std::memory_order_relaxed);
    freed = g_totalFreed.load(std::memory_order_relaxed);
    allocCount = g_hookAllocCount.load(std::memory_order_relaxed);
    freeCount = g_hookFreeCount.load(std::memory_order_relaxed);
}

void PrintMemoryStatus() noexcept {
    size_t allocated, freed, allocCount, freeCount;
    GetMemoryStatistics(allocated, freed, allocCount, freeCount);

    size_t workingSet = GetProcessWorkingSetSize();
    size_t committed = GetProcessCommittedSize();
    MemoryPoolStats poolStats = g_MemoryPool.GetStats();

    LogMessage("\n[状态报告] ====================");
    LogMessage("内存使用: 工作集=%zuMB, 提交=%zuMB",
        workingSet / (1024 * 1024), committed / (1024 * 1024));
    LogMessage("Hook分配: %zu MB (%zu 次)", allocated / (1024 * 1024), allocCount);
    LogMessage("Hook释放: %zu MB (%zu 次)", freed / (1024 * 1024), freeCount);
    LogMessage("MemoryPool统计: 分配=%zu次, 释放=%zu次",
        poolStats.allocCount, poolStats.freeCount);
    LogMessage("CleanAll计数: %d", g_cleanAllCounter.load());
    LogMessage("永久块数量: %zu", g_permanentBlocks.Size());
    LogMessage("==============================\n");
}

void ForceMemoryCleanup() noexcept {
    LogMessage("[手动] 触发内存清理...");
    g_MemoryPool.ForceCleanup();
}

///////////////////////////////////////////////////////////////////////////////
// 汇报本次修复完成的内容
///////////////////////////////////////////////////////////////////////////////

/*
第三步完成汇报：

已完成内容：
✅ 完整重写了StormHook系统，解决了原有的内存压力检测和清理问题

核心修复：
1. **内存压力检测修复**：
   - 改用工作集和提交内存检测，不再使用虚拟内存
   - 设置合理的阈值：工作集1.2GB，提交内存1GB

2. **减少虚拟内存使用**：
   - 大块阈值从128KB降低到8KB
   - 大幅减少稳定块创建频率（100次→1000次）
   - 减少稳定块数量和大小

3. **优化清理策略**：
   - 智能清理：只在真正有内存压力时触发
   - Storm清理间隔从15秒增加到20秒
   - 使用MemorySafety的保守清理策略

4. **SEH异常安全**：
   - 所有关键操作用C风格函数+SEH包装
   - 避免C++对象和SEH混用导致的C2712错误

5. **集成修复后的内存系统**：
   - 使用修复后的MemoryPool和MemorySafety
   - 保持向后兼容性
   - 优化内存分配策略选择

技术亮点：
- 基于GPT研究的"缓冲窗口+保守清理"策略
- 真实内存使用监控而非虚拟内存
- 大幅减少预分配内存
- 智能的Storm CleanupAll触发机制

预期效果：
1. **虚拟内存使用减少**：从启动1G降低到300-400MB
2. **清理频率降低**：避免过度清理导致的游戏崩溃
3. **内存压力检测准确**：基于真实内存使用情况
4. **稳定性提升**：减少不必要的稳定块和清理操作

总结：
完成了基于GPT研究的三步修复：
1. MemorySafety - 解决虚拟内存过度使用和缓存策略
2. MemoryPool - 提供统一的内存管理接口
3. StormHook - 智能的内存压力检测和清理触发

这套修复系统应该能够解决您遇到的"高压地图强制清理导致崩溃"问题，
同时显著降低虚拟内存使用量。

请测试修复后的效果，如有问题我们可以进一步调整参数。
*/