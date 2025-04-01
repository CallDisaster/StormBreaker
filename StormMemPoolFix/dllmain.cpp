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
#include <Graphic/Core.h>
#include <Graphic/GameOffsets.h>
#include <Graphic/Hooks.h>

#pragma comment(lib, "Version.lib")

void CreateConsole()
{
    AllocConsole();

    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);  // 绑定标准输出到控制台
    freopen_s(&fp, "CONOUT$", "w", stderr);  // 绑定标准错误到控制台
    freopen_s(&fp, "CONIN$", "r", stdin);    // 绑定标准输入到控制台
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

}

uint32_t GetGameBuildVersion()
{
    DWORD dwHandle;
    DWORD sz = GetFileVersionInfoSizeA("Game.dll", &dwHandle);
    if (sz == 0)
    {
        return 0;
    }

    char* buf = new char[sz];
    if (!GetFileVersionInfoA("Game.dll", dwHandle, sz, &buf[0]))
    {
        delete buf;
        return 0;
    }

    VS_FIXEDFILEINFO* pvi;
    sz = sizeof(VS_FIXEDFILEINFO);
    if (!VerQueryValueA(&buf[0], "\\", (LPVOID*)&pvi, (unsigned int*)&sz))
    {
        delete buf;
        return 0;
    }
    delete buf;

    return pvi->dwFileVersionLS & 0xFFFF;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    int featureActivationCount = 0;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateConsole();
        std::cout << "StormMemPoolFix v1.1.0 with mimalloc" << std::endl;
		std::cout << "Game Build Version: " << GetGameBuildVersion() << std::endl;
        Sleep(500);
        // 初始化内存钩子
        if (InitializeStormMemoryHooks()) {
            std::cout << "StormMemPoolHook 初始化成功！" << std::endl;
            // 打印初始内存报告到控制台
            PrintMemoryStatus();
            featureActivationCount++;
        }
        else {
            std::cout << "StormMemPoolHook 初始化失败！" << std::endl;
        }

        //// 初始化小块优化
        //if (HookAllStormHeapFunctions()) {
        //    std::cout << "StormHeapHook 初始化成功！" << std::endl;
        //    featureActivationCount++;
        //}
        //else {
        //    std::cout << "StormHeapHook 初始化失败！" << std::endl;
        //}
        featureActivationCount++;

        // 根据 featureActivationCount 输出最终状态
        if (featureActivationCount == 2) {
            std::cout << "所有系统启动成功！" << std::endl;
            std::cout << "Hello StormBreaker with mimalloc!" << std::endl;
        }
        else if (featureActivationCount == 1) {
            std::cout << "部分功能未启动成功！" << std::endl;
        }
        else {
            std::cout << "StormBreaker 注入失败！" << std::endl;
        }


        //if (!Core_Init(hModule)) {
        //    return FALSE;
        //}

        //LogInfo("ASI Plugin Attached.");

        //// 2. 初始化 Game Offsets (在获取 GameBase 之后)
        //try {
        //    // 调用 InitGameOffsets 来填充 GameOffsets.h 中声明的地址变量
        //    // 传入 1.27a (Build 52240) 的版本号
        //    InitGameOffsets(GAME_BUILD_127A); // 使用定义的常量
        //}
        //catch (...) {
        //    LogError("Exception during InitGameOffsets!");
        //    Core_Shutdown();
        //    return FALSE;
        //}
        //// 检查关键偏移量是否成功初始化
        //if (address_RenderUI == 0 || address_gxDevice == 0) {
        //    LogError("Required offsets (RenderUI or gxDevice) were not initialized!");
        //    Core_Shutdown();
        //    return FALSE;
        //}

        //// 计算 gxDevice 地址
        //if (address_gxDevice == 0) { std::cout << "无法获取设备指针" << std::endl; return false; }
        //g_absGxDeviceAddress = address_gxDevice;
        //LogInfo("Absolute address of gxDevice pointer variable: 0x%p", (void*)g_absGxDeviceAddress);
        //std::cout << "Absolute address of gxDevice pointer variable: 0x%p" << (void*)g_absGxDeviceAddress << std::endl;


        ////3. 初始化 Hook 库
        //if (!Hooks::Initialize()) {
        //    LogError("Failed to initialize hook library!");
        //    Core_Shutdown();
        //    return FALSE;
        //}
        //// 4. 安装初始 Hook (RenderUI)
        //if (!Hooks::InstallInitialHooks()) {
        //    LogError("Failed to install initial hooks!");
        //    //Hooks::Shutdown();
        //    //Core_Shutdown();
        //    return FALSE;
        //}

        //LogInfo("Initial hooks installed. Waiting for device pointer via RenderUI hook...");
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        // 关闭钩子
        ShutdownStormMemoryHooks();
        break;
    }
    return TRUE;
}