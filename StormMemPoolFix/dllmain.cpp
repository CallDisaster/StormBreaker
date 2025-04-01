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
#include <Base/MemPool/MemoryPoolManager.h>

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


// 在dllmain.cpp中添加
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    int featureActivationCount = 0;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateConsole();
        std::cout << "StormMemPoolFix v1.2.0 with Dual Memory Pool System" << std::endl;
        std::cout << "Game Build Version: " << GetGameBuildVersion() << std::endl;
        Sleep(500);

        // 读取配置文件，决定使用哪种内存池
        PoolType poolType = PoolType::MiMalloc; // 默认mimalloc

        // 检查命令行参数或配置文件
        char configPath[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, configPath, MAX_PATH);
        PathRemoveFileSpecA(configPath);
        strcat_s(configPath, "\\StormBreaker.ini");

        char poolTypeName[32] = { 0 };
        GetPrivateProfileStringA("Memory", "PoolType", "mimalloc", poolTypeName, sizeof(poolTypeName), configPath);

        if (_stricmp(poolTypeName, "tlsf") == 0) {
            poolType = PoolType::TLSF;
            std::cout << "使用TLSF内存池" << std::endl;
        }
        else {
            std::cout << "使用mimalloc内存池" << std::endl;
        }

        // 初始化内存钩子
        if (InitializeStormMemoryHooks(poolType)) {
            std::cout << "StormMemPoolHook 初始化成功！" << std::endl;
            // 打印初始内存报告到控制台
            PrintMemoryStatus();
            featureActivationCount++;
        }
        else {
            std::cout << "StormMemPoolHook 初始化失败！" << std::endl;
        }

        featureActivationCount++;

        // 根据 featureActivationCount 输出最终状态
        if (featureActivationCount == 2) {
            std::cout << "所有系统启动成功！" << std::endl;
            std::cout << "Hello StormBreaker with Dual Memory Pool System!" << std::endl;
        }
        else if (featureActivationCount == 1) {
            std::cout << "部分功能未启动成功！" << std::endl;
        }
        else {
            std::cout << "StormBreaker 注入失败！" << std::endl;
        }

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