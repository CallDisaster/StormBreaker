// StormBreaker
// Author: Disaster (CallDisaster)
// GitHub: https://github.com/CallDisaster/StormBreaker
// License: MIT License
// Date: 2025-03-02
// Description: 延缓 Warcraft III 旧版本 Storm.dll 的虚拟内存增长过快的问题

#include "pch.h"
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <io.h>
#include <fcntl.h>
#include <Base/Logger.h>
#include <Storm/StormHook.h>
#include <Storm/StormOffsets.h>
#include <mimalloc.h>
#include "Storm/MemoryPool.h"
#include <Base/MemorySafety.h>
#include <detours.h>
#include <Game/PathCapUnlock.h>

void CreateConsole()
{
    // 检查是否已经有控制台
    if (GetConsoleWindow() != nullptr) {
        return; // 已经有控制台了
    }

    if (!AllocConsole()) {
        OutputDebugStringA("StormBreaker: 无法分配控制台\n");
        return;
    }

    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);  // 绑定标准输出到控制台
    freopen_s(&fp, "CONOUT$", "w", stderr);  // 绑定标准错误到控制台
    freopen_s(&fp, "CONIN$", "r", stdin);    // 绑定标准输入到控制台
    
    // 设置UTF-8编码
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // 设置控制台标题
    SetConsoleTitleA("StormBreaker - Memory Pool Monitor");
    
    // 设置控制台窗口大小
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        COORD bufferSize = { 120, 300 };  // 宽度120字符，缓冲区300行
        SetConsoleScreenBufferSize(hConsole, bufferSize);
        
        SMALL_RECT windowSize = { 0, 0, 119, 29 };  // 窗口显示30行
        SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
    }
    
    // 输出欢迎信息
    printf("=== StormBreaker Memory Pool Monitor ===\n");
    printf("版本: v1.0 Build %s %s\n", __DATE__, __TIME__);
    printf("作者: CallDisaster\n");
    printf("控制台已启动，可以实时查看内存池状态\n");
    printf("日志文件保存在: .\\StormBreaker\\StormMemory.log\n");
    printf("=====================================\n\n");
}


namespace {
    static HANDLE g_initThread = nullptr;
    static std::atomic<bool> g_systemInitialized{ false };
    static std::atomic<bool> g_hooksInstalled{ false };
}

// 工作线程函数 - 在Loader Lock外执行所有重活
static DWORD WINAPI StormBreakerWorkerThread(LPVOID) {
    // 等一小段时间确保DLL加载完成
    Sleep(100);

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

    g_hooksInstalled.store(true, std::memory_order_release);

    if (!InstallPathCapUnlock(2.0f)) {
        Logger::GetInstance().LogWarning("寻路容量写入未成功（可能是版本偏移变化），继续运行不影响其他功能");
    }

    // 第三步：启动内存监控
    if (!StartMemoryMonitoring()) {
        Logger::GetInstance().LogWarning("内存监控启动失败，但系统可继续运行");
    }

    g_systemInitialized.store(true, std::memory_order_release);
    Logger::GetInstance().LogInfo("StormBreaker系统异步初始化完成");
    
    // 在控制台输出系统状态
    printf("\n=== 初始化完成 ===\n");
    printf("✓ 内存池已启动\n");
    printf("✓ Storm Hook已安装\n");
    printf("✓ 内存监控已启动\n");
    printf("✓ 日志级别: Info (减少输出)\n");
    printf("================\n\n");
    

    return 0;
}

// ======================== 基础系统初始化函数 ========================

bool InitializeStormBreaker() {
    // 创建控制台窗口用于实时查看日志
    CreateConsole();
    
    Logger::GetInstance().LogInfo("初始化StormBreaker基础系统...");

    // 初始化日志系统（如果尚未初始化）
    if (!Logger::GetInstance().IsInitialized()) {
        LoggerConfig config = Logger::GetDebugConfig();
        config.enableConsole = true;  // 启用控制台输出
        if (!Logger::GetInstance().Initialize(config)) {
            return false;
        }
    }

    bool stormOk = InitializeStormOffsets();
    Logger::GetInstance().LogInfo("Storm偏移初始化: %s", stormOk ? "成功" : "失败");

    // 初始化内存池
    if (!MemoryPool::Initialize()) {
        Logger::GetInstance().LogError("内存池初始化失败");
        return false;
    }

    // 初始化内存安全系统
    if (!MemorySafety::GetInstance().Initialize()) {
        Logger::GetInstance().LogError("内存安全系统初始化失败");
        return false;
    }

    // 初始化StormHook系统
    if (!StormHook::Initialize()) {
        Logger::GetInstance().LogError("StormHook系统初始化失败");
        return false;
    }

    Logger::GetInstance().LogInfo("StormBreaker基础系统初始化完成");
    return true;
}

void ShutdownStormBreaker() {
    Logger::GetInstance().LogInfo("关闭StormBreaker系统...");

    // 停止内存监控
    StopMemoryMonitoring();

    // 卸载Hook
    if (g_hooksInstalled.load(std::memory_order_acquire)) {
        UninstallStormHooks();
        g_hooksInstalled.store(false, std::memory_order_release);
    }

    // 关闭各个子系统
    StormHook::Shutdown();
    MemorySafety::GetInstance().Shutdown();
    MemoryPool::Shutdown();

    g_systemInitialized.store(false, std::memory_order_release);

    Logger::GetInstance().LogInfo("StormBreaker系统已关闭");
    
    // 输出关闭信息到控制台
    printf("\n=== StormBreaker 正在关闭 ===\n");
    printf("感谢使用 StormBreaker 内存优化器!\n");
    printf("按任意键关闭控制台...\n");
    
    Logger::GetInstance().Shutdown();
    
    // 等待用户按键后关闭控制台（可选）
    // getchar(); // 取消注释这行可以等待用户按键
    FreeConsole();
}

// ======================== Hook安装和卸载函数 ========================

bool InstallStormHooks() {
    Logger::GetInstance().LogInfo("安装Storm Hook...");

    HMODULE hStorm = GetModuleHandleA("Storm.dll");
    if (!hStorm) {
        Logger::GetInstance().LogError("未找到Storm.dll模块");
        return false;
    }

    // 尝试通过导出名获取函数地址
    auto pAlloc = GetProcAddress(hStorm, "SMemAlloc");
    auto pFree = GetProcAddress(hStorm, "SMemFree");
    auto pReAlloc = GetProcAddress(hStorm, "SMemReAlloc");
    auto pCleanup = GetProcAddress(hStorm, "SMemHeapCleanupAll");

    // 如果导出名不存在，尝试已知偏移（需要根据实际版本调整）
    if (!pAlloc || !pFree || !pReAlloc) {
        Logger::GetInstance().LogWarning("部分导出名未找到，尝试使用已知偏移（风险较高）");
        uintptr_t base = reinterpret_cast<uintptr_t>(hStorm);

        // 这些偏移需要根据实际的Storm.dll版本进行调整
        if (!pAlloc) pAlloc = reinterpret_cast<FARPROC>(base + 0x2B830);
        if (!pFree) pFree = reinterpret_cast<FARPROC>(base + 0x2BE40);
        if (!pReAlloc) pReAlloc = reinterpret_cast<FARPROC>(base + 0x2C8B0);
        if (!pCleanup) pCleanup = reinterpret_cast<FARPROC>(base + 0x2AB50);
    }

    // 保存原始函数指针
    g_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(pAlloc);
    g_origStormFree = reinterpret_cast<Storm_MemFree_t>(pFree);
    g_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(pReAlloc);
    g_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(pCleanup);

    // 使用Detours安装Hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Hook主要的内存函数
    DetourAttach(&reinterpret_cast<PVOID&>(g_origStormAlloc), Hooked_Storm_MemAlloc);
    DetourAttach(&reinterpret_cast<PVOID&>(g_origStormFree), Hooked_Storm_MemFree);
    DetourAttach(&reinterpret_cast<PVOID&>(g_origStormReAlloc), Hooked_Storm_MemReAlloc);

    // Hook清理函数（如果找到的话）
    if (g_origCleanupAll) {
        DetourAttach(&reinterpret_cast<PVOID&>(g_origCleanupAll), Hooked_StormHeap_CleanupAll);
    }

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        Logger::GetInstance().LogError("Detours事务提交失败: %ld", result);
        return false;
    }

    Logger::GetInstance().LogInfo("Storm Hook安装成功");
    return true;
}

void UninstallStormHooks() {
    if (!g_hooksInstalled.load(std::memory_order_acquire)) {
        return;
    }

    Logger::GetInstance().LogInfo("卸载Storm Hook...");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_origStormAlloc) {
        DetourDetach(&reinterpret_cast<PVOID&>(g_origStormAlloc), Hooked_Storm_MemAlloc);
    }
    if (g_origStormFree) {
        DetourDetach(&reinterpret_cast<PVOID&>(g_origStormFree), Hooked_Storm_MemFree);
    }
    if (g_origStormReAlloc) {
        DetourDetach(&reinterpret_cast<PVOID&>(g_origStormReAlloc), Hooked_Storm_MemReAlloc);
    }
    if (g_origCleanupAll) {
        DetourDetach(&reinterpret_cast<PVOID&>(g_origCleanupAll), Hooked_StormHeap_CleanupAll);
    }

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        Logger::GetInstance().LogWarning("Detours卸载失败: %ld", result);
    }
    else {
        Logger::GetInstance().LogInfo("Storm Hook卸载成功");
    }

    // 清空函数指针
    g_origStormAlloc = nullptr;
    g_origStormFree = nullptr;
    g_origStormReAlloc = nullptr;
    g_origCleanupAll = nullptr;
}

// ======================== 内存监控启动/停止 ========================

namespace {
    static MemoryMonitor g_memoryMonitor;
    static std::atomic<DWORD> g_lastStatsTime{0};
}

bool StartMemoryMonitoring() {
    Logger::GetInstance().LogInfo("启动内存监控...");

    try {
        g_memoryMonitor.StartMonitoring(5000); // 5秒间隔
        Logger::GetInstance().LogInfo("内存监控启动成功");
        return true;
    }
    catch (const std::exception& e) {
        Logger::GetInstance().LogError("内存监控启动失败: %s", e.what());
        return false;
    }
    catch (...) {
        Logger::GetInstance().LogError("内存监控启动失败: 未知异常");
        return false;
    }
}

void StopMemoryMonitoring() {
    Logger::GetInstance().LogInfo("停止内存监控...");

    try {
        g_memoryMonitor.StopMonitoring();
        Logger::GetInstance().LogInfo("内存监控已停止");
    }
    catch (...) {
        Logger::GetInstance().LogWarning("停止内存监控时发生异常");
    }
}

// ======================== 安全的DllMain实现 ========================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
    {
        // 在Loader Lock下只做最基本的操作
        DisableThreadLibraryCalls(hModule);

        // 立即启动工作线程处理所有复杂初始化
        g_initThread = CreateThread(
            nullptr,                    // 默认安全属性
            0,                         // 默认栈大小
            StormBreakerWorkerThread,  // 线程函数
            nullptr,                   // 线程参数
            0,                         // 默认创建标志
            nullptr                    // 不需要线程ID
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

    case DLL_PROCESS_DETACH:
    {
        // 等待初始化完成（如果还在进行中）
        if (!g_systemInitialized.load(std::memory_order_acquire)) {
            // 给一个合理的等待时间
            for (int i = 0; i < 50 && !g_systemInitialized.load(std::memory_order_acquire); ++i) {
                Sleep(100);
            }
        }

        // 执行清理
        ShutdownStormBreaker();
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
}