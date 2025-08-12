/************************************************************
 * StormOffsets.h
 *
 * 声明所有在Storm.dll中出现的全局变量地址及宏封装。
 * 这些偏移量需要您自行根据实际的Storm版本填写。
 ************************************************************/
#pragma once
#include "pch.h"
#include <cstddef>

// Storm.dll基址
extern uintptr_t gStormDllBase;

// 偏移量（您已提供的）
extern uintptr_t OFFSET_g_MemorySystemInitialized;
extern uintptr_t OFFSET_g_ErrorHandlingEnabled;
extern uintptr_t OFFSET_dword_15056F74;
extern uintptr_t OFFSET_dword_1505536C;
extern uintptr_t OFFSET_dword_15056F70;
extern uintptr_t OFFSET_dword_15055368;
extern uintptr_t OFFSET_g_TotalAllocatedMemory;
extern uintptr_t OFFSET_dword_15057728;

extern uintptr_t OFFSET_g_DebugHeapPtr;
extern uintptr_t OFFSET_g_HeapActiveFlag;
extern uintptr_t OFFSET_g_HeapCriticalSections;

// 新增偏移量：Storm_g_HeapTable
extern uintptr_t OFFSET_g_HeapTable;

// 对应Storm.dll中的全局变量
#define Storm_g_MemorySystemInitialized  (*(bool*)      (gStormDllBase + OFFSET_g_MemorySystemInitialized))
#define Storm_g_ErrorHandlingEnabled     (*(bool*)      (gStormDllBase + OFFSET_g_ErrorHandlingEnabled))
#define Storm_ForceAllocSizeToFour        (*(uint32_t*)  (gStormDllBase + OFFSET_dword_15056F74))
#define Storm_ExtraAlignPadding           (*(uint32_t*)  (gStormDllBase + OFFSET_dword_1505536C))
#define Storm_dword_15056F70            (*(uint32_t*)  (gStormDllBase + OFFSET_dword_15056F70))
#define Storm_dword_15055368            (*(uint32_t*)  (gStormDllBase + OFFSET_dword_15055368))
#define Storm_g_TotalAllocatedMemory    (*(size_t*)    (gStormDllBase + OFFSET_g_TotalAllocatedMemory))
#define Storm_dword_15057728            (*(int*)       (gStormDllBase + OFFSET_dword_15057728))

#define Storm_g_DebugHeapPtr            (*(int*)       (gStormDllBase + OFFSET_g_DebugHeapPtr))
inline int& Storm_g_HeapActiveFlag(int index)
{
    return *(int*)((gStormDllBase + OFFSET_g_HeapActiveFlag) + index * sizeof(int));
}

// 访问CriticalSection数组
#include <windows.h>
inline LPCRITICAL_SECTION Storm_g_HeapCriticalSectionPtr(uint8_t index)
{
    constexpr size_t CRITICAL_SECTION_SIZE = 24; // CRITICAL_SECTION 大小
    constexpr int MAX_CRITICAL_SECTIONS = 256;  // 假设最多支持256个临界区

    if (index >= MAX_CRITICAL_SECTIONS)
    {
        printf("[ERROR] Invalid heap index after truncation: %u\n", index);
        return nullptr;
    }

    // 正确计算临界区地址
    uintptr_t baseAddress = gStormDllBase + OFFSET_g_HeapCriticalSections;
    uintptr_t sectionAddress = baseAddress + index * CRITICAL_SECTION_SIZE;

    return reinterpret_cast<LPCRITICAL_SECTION>(sectionAddress);
}

// 新增Storm_g_HeapTable宏定义
#define Storm_g_HeapTable (*(DWORD***)(gStormDllBase + OFFSET_g_HeapTable))

bool InitializeStormOffsets();
uintptr_t GetStormDllBase();
bool IsStormOffsetsInitialized();
