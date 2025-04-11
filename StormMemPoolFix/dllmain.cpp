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
#include <Storm/StormHeap.h>

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


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    int featureActivationCount = 0;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateConsole();
        std::cout << "Version: 1.2.0 Power By TLSF" << std::endl; // 更新版本号

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

        // 初始化小块优化
        if (HookAllStormHeapFunctions()) {
            std::cout << "StormHeapHook 初始化成功！" << std::endl;
            featureActivationCount++;
        }
        else {
            std::cout << "StormHeapHook 初始化失败！" << std::endl;
        }

        // 根据 featureActivationCount 输出最终状态
        if (featureActivationCount == 2) {
            std::cout << "所有系统启动成功！" << std::endl;
            std::cout << "Hello StormBreaker!" << std::endl;
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
