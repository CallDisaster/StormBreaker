/************************************************************
 * StormOffsets.cpp
 *
 * 在此文件中定义并初始化全局变量 gStormDllBase，以及
 * 所有 Storm.dll 全局变量的偏移量(OFFSET_*)。
 *
 ************************************************************/
#include "pch.h"
#include "StormOffsets.h"
#include <cassert>


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

// 验证配置的有效性
namespace StormCompatConfig {
    bool ValidateConfiguration() {
        // 验证堆大小配置
        static_assert(DEFAULT_HEAP_SIZE >= 1024 * 1024, "堆大小不能小于1MB");
        static_assert(DEFAULT_HEAP_SIZE <= 256 * 1024 * 1024, "堆大小不能大于256MB");
        static_assert((DEFAULT_HEAP_SIZE & (DEFAULT_HEAP_SIZE - 1)) == 0, "堆大小必须是2的幂");

        // 验证对齐配置
        static_assert(HEAP_ALIGNMENT >= sizeof(void*), "堆对齐不能小于指针大小");
        static_assert((HEAP_ALIGNMENT & (HEAP_ALIGNMENT - 1)) == 0, "堆对齐必须是2的幂");

        // 验证块大小配置
        static_assert(MIN_BLOCK_SIZE >= sizeof(void*), "最小块大小不能小于指针大小");
        static_assert(MAX_BLOCK_SIZE <= 0xFFFF, "最大块大小不能超过16位");
        static_assert(MIN_BLOCK_SIZE < MAX_BLOCK_SIZE, "最小块大小必须小于最大块大小");

        // 验证魔数配置
        static_assert(STORM_MAGIC != 0, "Storm魔数不能为0");
        static_assert(BOUNDARY_MAGIC != 0, "边界魔数不能为0");
        static_assert(STORM_MAGIC != BOUNDARY_MAGIC, "两个魔数不能相同");

        return true;
    }

    void PrintConfiguration() {
        printf("[StormConfig] === 配置信息 ===\n");
        printf("[StormConfig] 默认堆大小: %zu MB\n", DEFAULT_HEAP_SIZE / (1024 * 1024));
        printf("[StormConfig] 最大堆数量: %zu\n", MAX_HEAPS);
        printf("[StormConfig] 堆对齐: %zu 字节\n", HEAP_ALIGNMENT);
        printf("[StormConfig] 空闲链表级别: %d\n", FREE_LIST_LEVELS);
        printf("[StormConfig] 块大小范围: %zu - %zu 字节\n", MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
        printf("[StormConfig] 统计更新间隔: %u 毫秒\n", STATS_UPDATE_INTERVAL);
        printf("[StormConfig] 内存报告间隔: %u 毫秒\n", MEMORY_REPORT_INTERVAL);
        printf("[StormConfig] 最大回退率: %.1f%%\n", MAX_FALLBACK_RATE * 100);
        printf("[StormConfig] 边界检查: %s\n", ENABLE_BOUNDARY_CHECKS ? "启用" : "禁用");
        printf("[StormConfig] 填充模式: %s\n", ENABLE_FILL_PATTERNS ? "启用" : "禁用");
        printf("[StormConfig] 详细日志: %s\n", ENABLE_DETAILED_LOGGING ? "启用" : "禁用");
        printf("[StormConfig] Storm魔数: 0x%04X\n", STORM_MAGIC);
        printf("[StormConfig] 边界魔数: 0x%04X\n", BOUNDARY_MAGIC);
    }
}