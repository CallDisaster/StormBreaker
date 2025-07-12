// StormHook.cpp - 修复后的Storm Hook实现
#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include "MemoryPool.h"
#include <Windows.h>
#include <detours.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
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

// 内存阈值配置
std::atomic<size_t> g_bigThreshold{ DEFAULT_BIG_BLOCK_THRESHOLD };

// 内存跟踪
std::atomic<size_t> g_totalAllocated{ 0 };
std::atomic<size_t> g_totalFreed{ 0 };
std::atomic<size_t> g_hookAllocCount{ 0 };
std::atomic<size_t> g_hookFreeCount{ 0 };

// Storm函数指针 - 基于IDA Pro确认的地址
Storm_MemAlloc_t s_origStormAlloc = nullptr;
Storm_MemFree_t s_origStormFree = nullptr;
Storm_MemReAlloc_t s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

// CleanAll相关状态
std::atomic<int> g_cleanAllCounter{ 0 };
thread_local bool tls_inCleanAll = false;

// 日志相关
static CRITICAL_SECTION g_logCs;
static FILE* g_logFile = nullptr;
static bool g_logInitialized = false;

///////////////////////////////////////////////////////////////////////////////
// C风格SEH安全包装实现
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    int __stdcall SafeExecuteVoid(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 纯C代码，不能调用LogError（因为它可能包含C++对象）
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
// 永久稳定块管理实现
///////////////////////////////////////////////////////////////////////////////

ThreadSafePermanentBlocks::ThreadSafePermanentBlocks() noexcept {
    InitializeCriticalSection(&m_cs);
}

ThreadSafePermanentBlocks::~ThreadSafePermanentBlocks() noexcept {
    Clear();
    DeleteCriticalSection(&m_cs);
}

void ThreadSafePermanentBlocks::Add(void* ptr) noexcept {
    if (!ptr) return;

    EnterCriticalSection(&m_cs);
    m_blocks.push_back(ptr);
    LeaveCriticalSection(&m_cs);
}

bool ThreadSafePermanentBlocks::Contains(void* ptr) const noexcept {
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

void ThreadSafePermanentBlocks::Clear() noexcept {
    EnterCriticalSection(&m_cs);
    m_blocks.clear();
    LeaveCriticalSection(&m_cs);
}

size_t ThreadSafePermanentBlocks::Size() const noexcept {
    size_t size = 0;
    EnterCriticalSection(&m_cs);
    size = m_blocks.size();
    LeaveCriticalSection(&m_cs);
    return size;
}

ThreadSafePermanentBlocks g_permanentBlocks;

///////////////////////////////////////////////////////////////////////////////
// C风格操作函数实现
///////////////////////////////////////////////////////////////////////////////

// 分配操作
int __stdcall AllocOperation(void* ctx) {
    AllocContext* context = (AllocContext*)ctx;

    // 更新统计（原子操作，无RAII）
    g_hookAllocCount.fetch_add(1, std::memory_order_relaxed);

    // 检查是否为JassVM特殊分配
    bool isJassVM = (context->size == JASSVM_BLOCK_SIZE &&
        context->name &&
        strstr(context->name, "Instance.cpp") != nullptr);

    if (isJassVM) {
        void* jvmPtr = JVM_MemPool::Allocate(context->size);
        if (jvmPtr) {
            g_totalAllocated.fetch_add(context->size, std::memory_order_relaxed);
            context->result = reinterpret_cast<size_t>(jvmPtr);
            return 1;  // 成功
        }
    }

    // 检查是否使用内存池
    bool useManagedPool = (context->size >= g_bigThreshold.load(std::memory_order_relaxed));

    if (useManagedPool && !g_shutdownRequested.load(std::memory_order_acquire)) {
        void* managedPtr = g_MemoryPool.AllocateSafe(context->size, context->name, context->src_line);
        if (managedPtr) {
            g_totalAllocated.fetch_add(context->size, std::memory_order_relaxed);
            context->result = reinterpret_cast<size_t>(managedPtr);
            return 1;  // 成功
        }
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

    // 检查是否为JVM内存池指针
    if (JVM_MemPool::IsFromPool(ptr)) {
        JVM_MemPool::Free(ptr);
        g_totalFreed.fetch_add(JASSVM_BLOCK_SIZE, std::memory_order_relaxed);
        context->result = 1;
        return 1;
    }

    // 检查是否为我们管理的大块
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

    // 检查是否为JVM内存池指针
    if (JVM_MemPool::IsFromPool(context->oldPtr)) {
        context->result = JVM_MemPool::Realloc(context->oldPtr, context->newSize);
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
                size_t copySize = min(context->newSize, (size_t)64);  // 保守地复制64字节
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
            context->newSize, context->name,
            context->src_line, context->flag);
        return 1;
    }

    context->result = nullptr;
    return 0;
}

// 创建永久稳定块操作
int __stdcall CreatePermanentStabilizersOperation(void* ctx) {
    StabilizerContext* context = (StabilizerContext*)ctx;

    // 创建不同大小的稳定块
    size_t sizes[] = { 64, 128, 256, 512, 1024, 2048, 4096 };
    int sizeCount = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < context->count && i < sizeCount; ++i) {
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

    // 只在特定的CleanAll计数时创建
    if (context->cleanAllCount % 50 != 0) return 1;

    // 创建几个临时块
    for (int i = 0; i < 3; ++i) {
        size_t size = 32 * (1 << i);  // 32, 64, 128
        void* stabilizer = g_MemoryPool.AllocateSafe(size, "临时稳定块", 0);
        // 临时块不加入永久列表
    }
    return 1;
}

// CleanAll操作
int __stdcall CleanAllOperation(void* ctx) {
    // 防止重入
    if (tls_inCleanAll) {
        return 1;
    }

    tls_inCleanAll = true;
    g_cleanAllInProgress.store(true, std::memory_order_release);

    int currentCount = g_cleanAllCounter.fetch_add(1, std::memory_order_relaxed) + 1;

    // 通知进入不安全期
    g_insideUnsafePeriod.store(true, std::memory_order_release);

    // 检查内存压力并触发清理
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {
        if (pmc.PrivateUsage > 1400LL * 1024 * 1024) {  // 1.4GB
            g_MemoryPool.ForceCleanup();
        }
    }

    // 调用Storm原始清理
    if (s_origCleanupAll) {
        s_origCleanupAll();
    }

    // 创建稳定块（降低频率）
    if (currentCount % 100 == 0) {
        StabilizerContext stabCtx = { 0, nullptr, currentCount };
        CreateTemporaryStabilizersOperation(&stabCtx);
    }

    // 退出不安全期
    g_insideUnsafePeriod.store(false, std::memory_order_release);
    g_cleanAllInProgress.store(false, std::memory_order_release);
    tls_inCleanAll = false;

    return 1;
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
    SAFE_CALL_VOID("Hooked_StormHeap_CleanupAll", CleanAllOperation, nullptr);
}

bool IsJassVMAllocation(size_t size, const char* name) noexcept {
    return (size == JASSVM_BLOCK_SIZE &&
        name &&
        strstr(name, "Instance.cpp") != nullptr);
}

bool IsPermanentBlock(void* ptr) noexcept {
    return g_permanentBlocks.Contains(ptr);
}

size_t GetProcessVirtualMemoryUsage() noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {
        return pmc.PrivateUsage;
    }
    return 0;
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

    // 将 fopen 改为 fopen_s
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
    config.enableDetailedLogging = true;

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

    // 5. 创建初始稳定块
    CreatePermanentStabilizers(10, "初始化稳定");

    // 6. 安装Hook
    if (!InstallHooks()) {
        return false;
    }

    LogMessage("[初始化] StormHook初始化完成");
    LogMessage("[状态] 大块阈值: %zu KB", g_bigThreshold.load() / 1024);

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

void GetMemoryStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) noexcept {
    allocated = g_totalAllocated.load(std::memory_order_relaxed);
    freed = g_totalFreed.load(std::memory_order_relaxed);
    allocCount = g_hookAllocCount.load(std::memory_order_relaxed);
    freeCount = g_hookFreeCount.load(std::memory_order_relaxed);
}

void PrintMemoryStatus() noexcept {
    size_t allocated, freed, allocCount, freeCount;
    GetMemoryStatistics(allocated, freed, allocCount, freeCount);

    size_t vmUsage = GetProcessVirtualMemoryUsage();
    MemoryPoolStats poolStats = g_MemoryPool.GetStats();

    LogMessage("\n[状态报告] ====================");
    LogMessage("虚拟内存使用: %zu MB", vmUsage / (1024 * 1024));
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