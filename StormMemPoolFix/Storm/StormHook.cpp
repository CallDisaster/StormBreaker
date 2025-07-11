#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include "MemoryPool.h"
#include "Base/MemorySafety.h"
#include <Windows.h>
#include <detours.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <condition_variable>
#include <Psapi.h>

///////////////////////////////////////////////////////////////////////////////
// 全局常量和配置
///////////////////////////////////////////////////////////////////////////////

// 大块阈值配置
constexpr size_t DEFAULT_BIG_BLOCK_THRESHOLD = 128 * 1024;  // 128KB
constexpr size_t JASSVM_BLOCK_SIZE = 0x28A8;                // JassVM特殊块大小

// Storm兼容魔数
constexpr WORD STORM_FRONT_MAGIC = 0x6F6D;
constexpr WORD STORM_TAIL_MAGIC = 0x12B1;
constexpr DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

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

// Storm函数指针
Storm_MemAlloc_t s_origStormAlloc = nullptr;
Storm_MemFree_t s_origStormFree = nullptr;
Storm_MemReAlloc_t s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

// CleanAll相关状态
std::atomic<int> g_cleanAllCounter{ 0 };
thread_local bool tls_inCleanAll = false;

// 永久稳定块管理
class ThreadSafePermanentBlocks {
private:
    mutable std::shared_mutex m_mutex;
    std::vector<void*> m_blocks;

public:
    void Add(void* ptr) {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_blocks.push_back(ptr);
    }

    bool Contains(void* ptr) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return std::find(m_blocks.begin(), m_blocks.end(), ptr) != m_blocks.end();
    }

    void Clear() {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_blocks.clear();
    }

    size_t Size() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_blocks.size();
    }
};

ThreadSafePermanentBlocks g_permanentBlocks;

// 日志相关
std::mutex g_logMutex;
FILE* g_logFile = nullptr;

///////////////////////////////////////////////////////////////////////////////
// SEH异常安全包装
///////////////////////////////////////////////////////////////////////////////

// SEH安全执行模板 - 这是最关键的兼容性保证
template<typename Func>
auto SafeExecute(Func&& func, const char* operation, auto defaultValue) noexcept -> decltype(func()) {
    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[SEH异常] 操作 %s 发生异常: 0x%08X", operation, GetExceptionCode());

        using ReturnType = decltype(func());
        if constexpr (std::is_same_v<ReturnType, decltype(defaultValue)>) {
            return defaultValue;
        }
        else {
            return static_cast<ReturnType>(defaultValue);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

// 线程安全的日志记录
void LogMessage(const char* format, ...) noexcept {
    if (!format) return;

    std::lock_guard<std::mutex> lock(g_logMutex);

    // 获取时间戳
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 格式化消息
    char buffer[2048];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);

    if (len > 0) {
        buffer[len] = '\0';

        // 控制台输出
        printf("[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buffer);

        // 文件输出
        if (g_logFile) {
            fprintf(g_logFile, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buffer);
            fflush(g_logFile);
        }
    }
}

// 检查是否为JassVM相关分配
bool IsJassVMAllocation(size_t size, const char* name) noexcept {
    return SafeExecute([=]() -> bool {
        return (size == JASSVM_BLOCK_SIZE &&
            name &&
            strstr(name, "Instance.cpp") != nullptr);
        }, "IsJassVMAllocation", false);
}

// 检查指针是否为我们的永久块
bool IsPermanentBlock(void* ptr) noexcept {
    return SafeExecute([=]() -> bool {
        return g_permanentBlocks.Contains(ptr);
        }, "IsPermanentBlock", false);
}

// 获取当前进程虚拟内存使用量
size_t GetProcessVirtualMemoryUsage() noexcept {
    return SafeExecute([]() -> size_t {
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);

        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
            sizeof(pmc))) {
            return pmc.PrivateUsage;
        }
        return 0;
        }, "GetProcessVirtualMemoryUsage", 0);
}

// 创建永久稳定块
void CreatePermanentStabilizers(int count, const char* reason) noexcept {
    SafeExecute([=]() -> void {
        LogMessage("[稳定化] 创建%d个永久稳定块 (%s)", count, reason);

        // 创建不同大小的稳定块
        std::vector<size_t> sizes = { 64, 128, 256, 512, 1024, 2048, 4096 };

        for (int i = 0; i < count && i < sizes.size(); ++i) {
            void* stabilizer = g_MemoryPool.AllocateSafe(sizes[i], "永久稳定块", 0);
            if (stabilizer) {
                g_permanentBlocks.Add(stabilizer);
                LogMessage("[稳定化] 创建永久块: %p (大小: %zu)", stabilizer, sizes[i]);
            }
        }
        }, "CreatePermanentStabilizers", );
}

// 创建临时稳定块
void CreateTemporaryStabilizers(int cleanAllCount) noexcept {
    SafeExecute([=]() -> void {
        // 只在特定的CleanAll计数时创建
        if (cleanAllCount % 50 != 0) return;

        LogMessage("[稳定化] 第%d次CleanAll，创建临时稳定块", cleanAllCount);

        // 创建几个临时块
        for (int i = 0; i < 3; ++i) {
            size_t size = 32 * (1 << i);  // 32, 64, 128
            void* stabilizer = g_MemoryPool.AllocateSafe(size, "临时稳定块", 0);
            if (stabilizer) {
                LogMessage("[稳定化] 创建临时块: %p (大小: %zu)", stabilizer, size);
            }
        }
        }, "CreateTemporaryStabilizers", );
}

///////////////////////////////////////////////////////////////////////////////
// Hook函数实现
///////////////////////////////////////////////////////////////////////////////

// Storm内存分配Hook
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag) {
    return SafeExecute([=]() -> size_t {
        g_hookAllocCount.fetch_add(1, std::memory_order_relaxed);

        // 检查是否为JassVM特殊分配
        if (IsJassVMAllocation(size, name)) {
            // 使用JVM内存池
            void* jvmPtr = JVM_MemPool::Allocate(size);
            if (jvmPtr) {
                g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
                LogMessage("[JassVM] 分配成功: %p, 大小: %zu", jvmPtr, size);
                return reinterpret_cast<size_t>(jvmPtr);
            }
            LogMessage("[JassVM] 分配失败，回退到Storm");
        }

        // 检查是否使用我们的内存池
        bool useManagedPool = (size >= g_bigThreshold.load(std::memory_order_relaxed));

        if (useManagedPool && !g_shutdownRequested.load(std::memory_order_acquire)) {
            // 使用MemoryPool分配
            void* managedPtr = g_MemoryPool.AllocateSafe(size, name, src_line);
            if (managedPtr) {
                g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
                return reinterpret_cast<size_t>(managedPtr);
            }
            LogMessage("[MemoryPool] 分配失败，回退到Storm: 大小=%zu", size);
        }

        // 回退到Storm原始分配
        size_t result = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        if (result) {
            g_totalAllocated.fetch_add(size, std::memory_order_relaxed);
        }
        return result;

        }, "Hooked_Storm_MemAlloc", 0);
}

// Storm内存释放Hook
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    return SafeExecute([=]() -> int {
        g_hookFreeCount.fetch_add(1, std::memory_order_relaxed);

        if (!a1) return 1;  // 空指针认为成功

        void* ptr = reinterpret_cast<void*>(a1);

        // 检查是否为永久块
        if (IsPermanentBlock(ptr)) {
            return 1;  // 永久块不释放，假装成功
        }

        // 检查是否为JVM内存池指针
        if (JVM_MemPool::IsFromPool(ptr)) {
            JVM_MemPool::Free(ptr);
            g_totalFreed.fetch_add(JASSVM_BLOCK_SIZE, std::memory_order_relaxed);
            return 1;
        }

        // 检查是否为我们管理的大块
        if (g_MemoryPool.IsFromPool(ptr)) {
            size_t blockSize = g_MemoryPool.GetBlockSize(ptr);
            bool success = g_MemoryPool.FreeSafe(ptr);
            if (success && blockSize > 0) {
                g_totalFreed.fetch_add(blockSize, std::memory_order_relaxed);
                return 1;
            }
            LogMessage("[MemoryPool] 释放失败，回退到Storm: %p", ptr);
        }

        // 回退到Storm原始释放
        return s_origStormFree(a1, name, argList, a4);

        }, "Hooked_Storm_MemFree", 0);
}

// Storm内存重分配Hook
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag) {
    return SafeExecute([=]() -> void* {
        // 边界情况处理
        if (!oldPtr) {
            size_t allocResult = Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag);
            return reinterpret_cast<void*>(allocResult);
        }

        if (newSize == 0) {
            Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
            return nullptr;
        }

        // 检查是否为JVM内存池指针
        if (JVM_MemPool::IsFromPool(oldPtr)) {
            return JVM_MemPool::Realloc(oldPtr, newSize);
        }

        // 检查是否为永久块
        if (IsPermanentBlock(oldPtr)) {
            // 永久块只分配新的，不释放旧的
            size_t allocResult = Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag);
            void* newPtr = reinterpret_cast<void*>(allocResult);

            if (newPtr) {
                // 尝试安全复制数据
                __try {
                    size_t copySize = min(newSize, (size_t)64);  // 保守地复制64字节
                    memcpy(newPtr, oldPtr, copySize);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    LogMessage("[重分配] 永久块数据复制失败: %p -> %p", oldPtr, newPtr);
                }
            }
            return newPtr;
        }

        // 检查是否为我们管理的块
        if (g_MemoryPool.IsFromPool(oldPtr)) {
            void* newPtr = g_MemoryPool.ReallocSafe(oldPtr, newSize, name, src_line);
            if (newPtr) {
                return newPtr;
            }
            LogMessage("[MemoryPool] 重分配失败，回退到Storm: %p, 新大小=%zu", oldPtr, newSize);
        }

        // 回退到Storm原始重分配
        return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);

        }, "Hooked_Storm_MemReAlloc", nullptr);
}

// StormHeap CleanupAll Hook - 关键的稳定性保证
void Hooked_StormHeap_CleanupAll() {
    SafeExecute([]() -> void {
        // 防止重入
        if (tls_inCleanAll) {
            return;
        }

        tls_inCleanAll = true;
        g_cleanAllInProgress.store(true, std::memory_order_release);

        int currentCount = g_cleanAllCounter.fetch_add(1, std::memory_order_relaxed) + 1;

        // 通知MemoryPool进入不安全期
        g_insideUnsafePeriod.store(true, std::memory_order_release);

        LogMessage("[CleanAll] 第%d次清理开始", currentCount);

        // 检查内存压力并触发清理
        size_t vmUsage = GetProcessVirtualMemoryUsage();
        if (vmUsage > 1400LL * 1024 * 1024) {  // 1.4GB
            LogMessage("[CleanAll] 内存压力检测: %zu MB，触发MemoryPool清理",
                vmUsage / (1024 * 1024));
            g_MemoryPool.ForceCleanup();
        }

        // 调用Storm原始清理
        __try {
            s_origCleanupAll();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[CleanAll] Storm原始清理异常: 0x%08X", GetExceptionCode());
        }

        // 创建稳定块（降低频率避免过度分配）
        if (currentCount % 100 == 0) {
            CreateTemporaryStabilizers(currentCount);
        }

        // 退出不安全期
        g_insideUnsafePeriod.store(false, std::memory_order_release);
        g_cleanAllInProgress.store(false, std::memory_order_release);
        tls_inCleanAll = false;

        LogMessage("[CleanAll] 第%d次清理完成", currentCount);

        }, "Hooked_StormHeap_CleanupAll", );
}

///////////////////////////////////////////////////////////////////////////////
// 初始化和清理
///////////////////////////////////////////////////////////////////////////////

// 初始化日志系统
bool InitializeLogging() noexcept {
    return SafeExecute([]() -> bool {
        g_logFile = fopen("StormHook.log", "w");
        if (g_logFile) {
            LogMessage("[初始化] 日志系统启动成功");
            return true;
        }
        else {
            printf("[错误] 无法创建日志文件\n");
            return false;
        }
        }, "InitializeLogging", false);
}

// 查找Storm函数地址
bool FindStormFunctions() noexcept {
    return SafeExecute([]() -> bool {
        // 查找Storm.dll基址
        HMODULE stormDll = GetModuleHandleA("Storm.dll");
        if (!stormDll) {
            LogMessage("[错误] 未找到Storm.dll模块");
            return false;
        }

        gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
        LogMessage("[初始化] Storm.dll基址: 0x%08X", gStormDllBase);

        // 设置函数指针（基于逆向文档的偏移）
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
            LogMessage("[错误] Storm函数地址无效");
            return false;
        }

        return true;
        }, "FindStormFunctions", false);
}

// 安装Hook
bool InstallHooks() noexcept {
    return SafeExecute([]() -> bool {
        LogMessage("[初始化] 开始安装Hook...");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // 安装内存分配Hook
        DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
        DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
        DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
        DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

        LONG result = DetourTransactionCommit();
        if (result != NO_ERROR) {
            LogMessage("[错误] Hook安装失败，错误代码: %ld", result);
            return false;
        }

        LogMessage("[初始化] Hook安装成功");
        return true;
        }, "InstallHooks", false);
}

// 主初始化函数
bool InitializeStormMemoryHooks() {
    return SafeExecute([]() -> bool {
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
            LogMessage("[错误] MemoryPool初始化失败");
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
        }, "InitializeStormMemoryHooks", false);
}

// 卸载Hook
void UninstallHooks() noexcept {
    SafeExecute([]() -> void {
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

        }, "UninstallHooks", );
}

// 主清理函数
void ShutdownStormMemoryHooks() {
    SafeExecute([]() -> void {
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

        }, "ShutdownStormMemoryHooks", );
}

///////////////////////////////////////////////////////////////////////////////
// 配置和状态查询接口
///////////////////////////////////////////////////////////////////////////////

// 设置大块阈值
void SetBigBlockThreshold(size_t sizeInBytes) {
    SafeExecute([=]() -> void {
        size_t oldThreshold = g_bigThreshold.exchange(sizeInBytes, std::memory_order_relaxed);
        LogMessage("[配置] 大块阈值: %zu -> %zu 字节", oldThreshold, sizeInBytes);

        // 更新MemoryPool配置
        MemoryPoolConfig config = g_MemoryPool.GetConfig();
        config.bigBlockThreshold = sizeInBytes;
        g_MemoryPool.UpdateConfig(config);

        }, "SetBigBlockThreshold", );
}

// 获取内存统计
void GetMemoryStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) {
    allocated = g_totalAllocated.load(std::memory_order_relaxed);
    freed = g_totalFreed.load(std::memory_order_relaxed);
    allocCount = g_hookAllocCount.load(std::memory_order_relaxed);
    freeCount = g_hookFreeCount.load(std::memory_order_relaxed);
}

// 打印当前状态
void PrintMemoryStatus() {
    SafeExecute([]() -> void {
        size_t allocated, freed, allocCount, freeCount;
        GetMemoryStatistics(allocated, freed, allocCount, freeCount);

        size_t vmUsage = GetProcessVirtualMemoryUsage();
        MemoryPoolStats poolStats = g_MemoryPool.GetStats();

        LogMessage("\n[状态报告] ====================");
        LogMessage("虚拟内存使用: %zu MB", vmUsage / (1024 * 1024));
        LogMessage("Hook分配: %zu MB (%zu 次)", allocated / (1024 * 1024), allocCount);
        LogMessage("Hook释放: %zu MB (%zu 次)", freed / (1024 * 1024), freeCount);
        LogMessage("MemoryPool统计: 分配=%zu次, 释放=%zu次",
            poolStats.allocCount.load(), poolStats.freeCount.load());
        LogMessage("CleanAll计数: %d", g_cleanAllCounter.load());
        LogMessage("永久块数量: %zu", g_permanentBlocks.Size());
        LogMessage("==============================\n");

        }, "PrintMemoryStatus", );
}

// 强制触发内存清理
void ForceMemoryCleanup() {
    SafeExecute([]() -> void {
        LogMessage("[手动] 触发内存清理...");
        g_MemoryPool.ForceCleanup();
        }, "ForceMemoryCleanup", );
}

// 检查Hook状态
bool IsHooksInitialized() {
    return g_hooksInitialized.load(std::memory_order_acquire);
}