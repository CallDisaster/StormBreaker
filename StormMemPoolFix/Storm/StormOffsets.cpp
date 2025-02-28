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

