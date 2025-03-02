// dllmain.cpp : 定义 DLL 应用程序的入口点。
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

    //// 让 wcout 可以正确输出 Unicode
    //_setmode(_fileno(stdout), _O_U16TEXT);
    //_setmode(_fileno(stdin), _O_U16TEXT);
    //_setmode(_fileno(stderr), _O_U16TEXT);
    std::cout << "Hello StormFix!" << std::endl;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateConsole();
        std::cout << "Version:0.05" << std::endl; // 更新版本号

        Sleep(500);

        // 初始化内存钩子
        if (InitializeStormMemoryHooks()) {
            std::cout << "StormMemPoolHook 初始化成功！" << std::endl;

            // 打印初始内存报告到控制台
            PrintMemoryStatus();
        }
        else {
            std::cout << "StormMemPoolHook 初始化失败！" << std::endl;
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
