/************************************************************
 * StormHeap.h
 *
 * 声明“堆管理”相关的所有内部函数，在StormMemory.cpp中会调用。
 ************************************************************/
#pragma once
#include "pch.h"
#include <windows.h>
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif
// Storm兼容分配器的C接口（用于与现有代码兼容）
    typedef void* (*StormCompatAlloc_t)(size_t size, const char* name, DWORD srcLine, DWORD flags);
    typedef int (*StormCompatFree_t)(void* ptr);
    typedef void* (*StormCompatRealloc_t)(void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags);

    // 全局接口函数声明
    void* StormCompat_Allocate(size_t size, const char* name, DWORD srcLine, DWORD flags);
    int StormCompat_Free(void* ptr);
    void* StormCompat_Reallocate(void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags);
    bool StormCompat_IsOurPointer(void* ptr);
    void StormCompat_GetStatistics(size_t* allocated, size_t* freed, size_t* allocCount, size_t* freeCount);

    // 初始化和清理函数
    bool StormCompat_Initialize();
    void StormCompat_Shutdown();
    void StormCompat_PrintStats();

#ifdef __cplusplus
}
#endif

