/************************************************************
 * StormOffsets.cpp
 *
 * 在此文件中定义并初始化全局变量 gStormDllBase，以及
 * 所有 Storm.dll 全局变量的偏移量(OFFSET_*)。
 *
 ************************************************************/
#include "pch.h"
#include "StormOffsets.h"

 // 这里可以在初始化时赋予正确的Storm.dll基址
uintptr_t gStormDllBase = 0;

/**
 * 全局变量偏移量
 */
uintptr_t OFFSET_dword_15056F74 = 0x56F74;  // Storm_ForceAllocSizeToFour
uintptr_t OFFSET_dword_1505536C = 0x5536C;  // Storm_ExtraAlignPadding
uintptr_t OFFSET_g_MemorySystemInitialized = 0x56F7C;
uintptr_t OFFSET_g_ErrorHandlingEnabled = 0x57388;
uintptr_t OFFSET_dword_15056F70 = 0x56F70;
uintptr_t OFFSET_dword_15055368 = 0x55368;
uintptr_t OFFSET_g_TotalAllocatedMemory = 0x5738C;
uintptr_t OFFSET_dword_15057728 = 0x57728;

uintptr_t OFFSET_g_DebugHeapPtr = 0x57380;
uintptr_t OFFSET_g_HeapActiveFlag = 0x55370;
uintptr_t OFFSET_g_HeapCriticalSections = 0x55770;
uintptr_t OFFSET_g_HeapTable = 0x56F80;

/**
 * 初始化Storm.dll基址
 * 应在程序启动时调用
 */
bool InitializeStormOffsets() {
    HMODULE hStorm = GetModuleHandleA("Storm.dll");
    if (!hStorm) {
        printf("[ERROR] 无法获取Storm.dll模块句柄\n");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(hStorm);
    printf("[INFO] Storm.dll基址已设置: 0x%p\n", hStorm);

    // 验证几个关键偏移
    __try {
        bool memSysInit = Storm_g_MemorySystemInitialized;
        size_t totalMem = Storm_g_TotalAllocatedMemory;
        printf("[INFO] Storm内存系统验证: 已初始化=%s, 总内存=%zu\n",
            memSysInit ? "是" : "否", totalMem);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[ERROR] Storm偏移验证失败，可能偏移不正确\n");
        gStormDllBase = 0;
        return false;
    }
}

/**
 * 获取Storm.dll基址
 */
uintptr_t GetStormDllBase() {
    return gStormDllBase;
}

/**
 * 检查Storm偏移是否已初始化
 */
bool IsStormOffsetsInitialized() {
    return gStormDllBase != 0;
}