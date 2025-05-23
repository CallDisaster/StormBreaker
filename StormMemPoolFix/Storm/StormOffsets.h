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

// Storm兼容分配器配置
namespace StormCompatConfig {
    // 堆配置
    constexpr size_t DEFAULT_HEAP_SIZE = 16 * 1024 * 1024;  // 16MB per heap
    constexpr size_t MAX_HEAPS = 256;                       // 最大堆数量
    constexpr size_t HEAP_ALIGNMENT = 8;                   // 堆内存对齐

    // 空闲链表配置
    constexpr int FREE_LIST_LEVELS = 9;                    // 9个空闲链表级别
    constexpr size_t MIN_BLOCK_SIZE = 16;                  // 最小块大小
    constexpr size_t MAX_BLOCK_SIZE = 0xFFFF;              // 最大块大小（16位）

    // 性能配置
    constexpr DWORD STATS_UPDATE_INTERVAL = 30000;        // 统计更新间隔（毫秒）
    constexpr DWORD MEMORY_REPORT_INTERVAL = 60000;       // 内存报告间隔（毫秒）
    constexpr double MAX_FALLBACK_RATE = 0.20;            // 最大回退率（20%）

    // 调试配置
    constexpr bool ENABLE_BOUNDARY_CHECKS = true;         // 启用边界检查
    constexpr bool ENABLE_FILL_PATTERNS = false;          // 启用填充模式
    constexpr bool ENABLE_DETAILED_LOGGING = false;       // 启用详细日志

    // 魔数定义
    constexpr WORD STORM_MAGIC = 0x6F6D;                  // Storm标准魔数
    constexpr WORD BOUNDARY_MAGIC = 0x12B1;               // 边界检查魔数（4785）
    constexpr DWORD HEAP_SIGNATURE_BASE = 0x6F6D0000;     // 堆签名基础值

    bool ValidateConfiguration();
    void PrintConfiguration();
}
