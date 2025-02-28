// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <io.h>
#include <fcntl.h>
#include <Base/spdLogger.h>
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


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateConsole();
        std::cout << "Version:0.03" << std::endl;
        //if (SPDLogger::InitializeLogger()) {
        //    std::cout << "InitializeLogger success!" << std::endl;
        //}
        //else {
        //    std::cout << "InitializeLogger faild!" << std::endl;
        //}
// 例如：
    // 关闭 eager_commit
        mi_option_set_enabled(mi_option_eager_commit, false);

        // 关闭 arena_eager_commit (如果在大块场景里将 Arena 也会 eager commit)
        mi_option_set_enabled(mi_option_arena_eager_commit, false);

        // 禁用 large OS pages
        mi_option_set_enabled(mi_option_allow_large_os_pages, false);

        // 禁用 (or lower) reserve_huge_os_pages
        mi_option_set(mi_option_reserve_huge_os_pages, 0);

        mi_collect(true);  // 尝试释放未使用的内存
        // 使选项生效
        mi_process_init();
        Sleep(500);
        //if (HookAllStormHeapFunctions()) {
        //    std::cout << "StormFixHook success!" << std::endl;
        //}
        //else {
        //    std::cout << "StormFixHook failed!" << std::endl;
        //}
        if (InitializeStormMemoryHooks()) {
            std::cout << "StormMemPoolHook success!" << std::endl;
        }
        else {
            std::cout << "StormMemPoolHook failed!" << std::endl;
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        ShutdownStormMemoryHooks();
        break;
    }
    return TRUE;
}

