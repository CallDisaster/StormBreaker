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
    // 定义函数指针类型
#pragma pack(push, 1)
    typedef DWORD* (__fastcall* StormHeap_Create_t)(char*, int, int, int, size_t, size_t, size_t);

#pragma pack(pop)
    typedef int(__fastcall* StormHeap_ComputeIndex_t)(const char*, int);
    typedef int(__fastcall* StormHeap_CommitPages_t)(DWORD*, int);
    typedef DWORD* (__fastcall* StormHeap_RebuildFreeList_t)(DWORD*);
    typedef char* (__fastcall* StormHeap_CombineFreeBlocks_t)(int, unsigned __int16*, int*, char*);
    typedef char(__fastcall* StormHeap_InternalFree_t)(DWORD*, unsigned __int16*);
    typedef void(__fastcall* sub_1502B4F0_t)(DWORD*, DWORD*, unsigned __int16*);
    typedef unsigned __int16* (__fastcall* StormHeap_AllocPage_t)(DWORD*, unsigned int, LPVOID);
    typedef size_t(__fastcall* StormHeap_Alloc_t)(int* pLocalIndex, DWORD* pHeap, DWORD flags, size_t size);
    typedef char* (__fastcall* StormHeap_ReallocImpl_t)(DWORD*, DWORD*, char*, unsigned __int16*, size_t, char);
    typedef int(__fastcall* sub_1502AE30_t)(DWORD*, unsigned __int16*, int, unsigned int);
    typedef int(__fastcall* sub_1502B680_t)(DWORD*, unsigned __int16*, int, unsigned int);
    typedef void(*StormHeap_CleanupAll_t)();
    // 声明函数指针变量
    extern StormHeap_Create_t pStormHeap_Create;
    extern StormHeap_ComputeIndex_t pStormHeap_ComputeIndex;
    extern StormHeap_CommitPages_t pStormHeap_CommitPages;
    extern StormHeap_RebuildFreeList_t pStormHeap_RebuildFreeList;
    extern StormHeap_CombineFreeBlocks_t pStormHeap_CombineFreeBlocks;
    extern StormHeap_InternalFree_t pStormHeap_InternalFree;
    extern sub_1502B4F0_t psub_1502B4F0;
    extern StormHeap_AllocPage_t pStormHeap_AllocPage;
    extern StormHeap_Alloc_t pStormHeap_Alloc;
    extern StormHeap_ReallocImpl_t pStormHeap_ReallocImpl;
    extern sub_1502AE30_t psub_1502AE30;
    extern sub_1502B680_t psub_1502B680;
    extern StormHeap_CleanupAll_t pStormHeap_CleanupAll;
    /**************************************
     * 逆向中提到的函数或结构
     **************************************/

     // StormHeap_AllocPage:
     //    在 StormHeapAlloc_2B3B0 里被调用, 申请或对齐物理页
    unsigned __int16* __fastcall StormHeap_AllocPage(DWORD* a1, unsigned int a2, LPVOID lpAddress);

    /**
     * StormHeap_RebuildFreeList:
     *   重建空闲链表, 逆向代码中提到
     */
    DWORD* __fastcall StormHeap_RebuildFreeList(DWORD* a1);

    /**
     * StormHeap_CombineFreeBlocks:
     *   合并空闲区块
     */
    char* __fastcall StormHeap_CombineFreeBlocks(int a1, unsigned __int16* a2, int* a3, char* a4);

    /**
     * StormHeap_CommitPages:
     *   虚拟提交更多内存页
     */
    int __fastcall StormHeap_CommitPages(DWORD* a1, int a2);

    /**
     * StormHeap_InternalFree:
     *   堆内部释放, 更新各种统计, 可能VirtualFree或合并到空闲链表
     */
    char __fastcall StormHeap_InternalFree(DWORD* a1, unsigned __int16* a2);

    /**
     * sub_1502B4F0:
     *   在Free里被调用，做一些释放前的操作(如填充0xDD, 统计减法)然后调StormHeap_InternalFree
     */
    void __fastcall sub_1502B4F0(DWORD* a1, DWORD* a2, unsigned __int16* a3);

    /**
     * StormHeap_Create:
     *   申请VirtualAlloc并初始化一个新的堆结构(逆向时见到)
     */
    DWORD* __fastcall StormHeap_Create(
        char* a1,
        int a2,
        int a3,
        size_t Size,
        int a5,
        size_t a6,
        size_t dwSize
    );

    /**
     * 其他类似函数(如StormHeap_ReallocImpl)若需要也可放此
     */

     /*************************************
      * ReAlloc 相关
      *************************************/
    char* __fastcall StormHeap_ReallocImpl(
        DWORD* heapPtr,
        DWORD* blockPtr,
        char* src,
        unsigned __int16* blockHeader,
        size_t newSize,
        char flags
    );

    /**
     * sub_1502AE30 / sub_1502B680:
     *   逆向分析里用于块扩缩容
     */
    int __fastcall sub_1502AE30(DWORD* a1, unsigned __int16* a2, int oldSize, unsigned int newSize);
    int __fastcall sub_1502B680(DWORD* a1, unsigned __int16* a2, int oldSize, unsigned int newSize);

#ifdef __cplusplus
}
#endif

