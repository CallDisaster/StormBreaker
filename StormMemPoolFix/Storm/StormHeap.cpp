///************************************************************
// * StormHeap.cpp
// *
// * 实现Storm Heap管理相关功能。
// * 全部引用StormOffsets.h提供的全局变量访问，保证与Storm.dll一致。
// ************************************************************/
#include "pch.h"
//#include "StormHeap.h"
//#include "StormOffsets.h"
//#include "StormMemoryInternal.h"
//#include <windows.h>
//#include <cstdio>
//#include <cstring>
//
//void* pStorm_502 = nullptr;
//void* pStorm_506 = nullptr;
//
//
// // 全局变量：页大小
//static DWORD g_VirtualMemoryPageSize = 0;
//
////------------------------------------------------------------------------------
// // StormHeap_Create
// // VirtualAlloc 一大块内存，并初始化堆结构
// //------------------------------------------------------------------------------
//DWORD* __fastcall StormHeap_Create(
//    char* a1,
//    int a2,
//    int a3,
//    size_t Size,
//    int a5,
//    size_t a6,
//    size_t dwSize
//)
//{
//    // 1. VirtualAlloc(..., MEM_RESERVE)
//    void* mem = VirtualAlloc(nullptr, dwSize, MEM_RESERVE, PAGE_READWRITE);
//    if (!mem)
//    {
//        Storm_dword_15055368 = 1;
//        Storm_AllocErrorHandler(8u, a1, a2, 0, 0, 1u);
//        ExitProcess(1u);
//    }
//
//    // 2. VirtualAlloc(..., MEM_COMMIT) 一部分
//    if (!VirtualAlloc(mem, a6, MEM_COMMIT, PAGE_READWRITE))
//    {
//        Storm_dword_15055368 = 1;
//        Storm_AllocErrorHandler(8u, a1, a2, 0, 0, 1u);
//        ExitProcess(1u);
//    }
//
//    // 3. 填写堆结构
//    DWORD* heapPtr = reinterpret_cast<DWORD*>(mem);
//    std::memset(heapPtr, 0, dwSize); // 初始化堆内存为0
//
//    heapPtr[0] = static_cast<DWORD>(dwSize);  // 堆总大小
//    heapPtr[1] = a3;                           // 堆索引
//    heapPtr[2] = a5;                           // 可能是某种标志或参数
//    heapPtr[10] = static_cast<DWORD>(g_VirtualMemoryPageSize); // 页大小
//    heapPtr[11] = 0;                            // 当前已提交大小
//    heapPtr[12] = static_cast<DWORD>(dwSize);   // 最大堆大小
//
//    heapPtr[7] = reinterpret_cast<DWORD>(mem) + sizeof(DWORD) * 13; // 堆起始指针 + 13 DWORD 头部
//    heapPtr[8] = reinterpret_cast<DWORD>(mem) + sizeof(DWORD) * 13; // 堆结束指针，初始与起始相同
//    heapPtr[9] = 0;                            // 空闲块计数
//
//    // 初始化空闲链表（索引 17-25）
//    for (int i = 17; i <= 25; i++)
//    {
//        heapPtr[i] = 0;
//    }
//
//    // 初始化活动块计数和总分配内存
//    heapPtr[5] = 0;  // active blocks
//    heapPtr[6] = 0;  // total allocated memory
//    heapPtr[15] = 0; // 计数器
//
//    return heapPtr;
//}
//
////------------------------------------------------------------------------------
// // StormHeap_CommitPages
// // 给堆追加 commit 页面
// //------------------------------------------------------------------------------
//int __fastcall StormHeap_CommitPages(DWORD* a1, int a2)
//{
//    // a1[10] => page size, a1[11] => current committed, a1[12] => max size
//    int pageSize = a1[10];
//    int currentCommitted = a1[11];
//    size_t needSize = a2 - currentCommitted;
//    int modSize = (a2 - currentCommitted) & (pageSize - 1);
//    if (modSize)
//        needSize += (pageSize - modSize);
//
//    unsigned int maxSize = a1[12];
//    if (currentCommitted + needSize > maxSize)
//        needSize = maxSize - currentCommitted;
//
//    LPVOID result = VirtualAlloc(reinterpret_cast<char*>(a1) + currentCommitted,
//        needSize,
//        MEM_COMMIT,
//        PAGE_READWRITE);
//    if (!result)
//        return 0;
//    a1[11] += needSize;
//    return 1;
//}
//
////------------------------------------------------------------------------------
// // StormHeap_RebuildFreeList
// // 扫描 [a1[7], a1[8]] 之间的块，并将空闲块挂回 a1[v13+17]
// //------------------------------------------------------------------------------
//DWORD* __fastcall StormHeap_RebuildFreeList(DWORD* a1)
//{
//    // 1. 清空所有空闲链表
//    for (int i = 17; i <= 25; i++)
//    {
//        a1[i] = 0;
//    }
//    a1[9] = 0;
//
//    // 2. 遍历堆中的所有块，重新构建空闲链表
//    unsigned __int16* current = reinterpret_cast<unsigned __int16*>(a1[7]);
//    unsigned __int16* end = reinterpret_cast<unsigned __int16*>(a1[8]);
//
//    while (current < end)
//    {
//        unsigned int blockSize = *current;
//        char flags = reinterpret_cast<char*>(current)[3];
//
//        if ((flags & 2) == 0) // 如果是空闲块
//        {
//            // 计算空闲链表索引
//            int index = (blockSize >> 5) < 9 ? (blockSize >> 5) : 8; // 索引 17-25 对应 0-8
//            DWORD* freeListHead = &a1[17 + index];
//            *reinterpret_cast<DWORD*>(current + 1) = *freeListHead;
//            *freeListHead = reinterpret_cast<DWORD>(current);
//
//            a1[9]++; // 空闲块计数
//        }
//
//        current = reinterpret_cast<unsigned __int16*>(reinterpret_cast<char*>(current) + blockSize);
//    }
//
//    return a1;
//}
//
////------------------------------------------------------------------------------
// // StormHeap_CombineFreeBlocks
// // 合并相邻空闲块
// //------------------------------------------------------------------------------
//char* __fastcall StormHeap_CombineFreeBlocks(int a1, unsigned __int16* a2, int* a3, char* a4)
//{
//    unsigned int blockSize = *a2;
//    char* nextPtr = reinterpret_cast<char*>(a2) + blockSize;
//    int needed = *a3;
//    unsigned int remainSize = blockSize - needed;
//
//    if (remainSize < 0x10)
//    {
//        // 合并
//        nextPtr[3] &= ~0x10u; // 清除合并标志
//        *a3 += remainSize;
//        *reinterpret_cast<int*>(a4) += remainSize;
//        return a4;
//    }
//    else
//    {
//        // 创建新的空闲块
//        char* newFree = reinterpret_cast<char*>(a2) + needed;
//        *reinterpret_cast<unsigned short*>(newFree) = remainSize;
//        reinterpret_cast<unsigned short*>(newFree)[1] = 512; // 假设标志为 0x200 (示例)
//        *reinterpret_cast<char*>(newFree + remainSize - 1) |= 0x10; // 设置合并标志
//
//        return newFree;
//    }
//}
//
////------------------------------------------------------------------------------
// // StormHeap_InternalFree
// // 堆内部释放
// //------------------------------------------------------------------------------
//char __fastcall StormHeap_InternalFree(DWORD* a1, unsigned __int16* a2)
//{
//    char flags = reinterpret_cast<char*>(a2)[3];
//    int freedSize = 0;
//
//    if (flags & 4)
//    {
//        // 大块释放
//        int v5 = reinterpret_cast<int*>(a2)[2];
//        if (v5)
//        {
//            int* blockPtr = reinterpret_cast<int*>(v5 - 16);
//            int realSize = *blockPtr;
//            void* base = reinterpret_cast<void*>((uintptr_t(blockPtr)) & ~(g_VirtualMemoryPageSize - 1));
//            a1[13] -= realSize;
//            VirtualFree(base, 0, MEM_RELEASE);
//            freedSize = realSize;
//        }
//    }
//    else
//    {
//        int offset = reinterpret_cast<unsigned char*>(a2)[2];
//        freedSize = *a2 - offset - 8;
//        if ((flags & 1) != 0)
//            freedSize = *a2 - offset - 10;
//    }
//
//    --a1[5];        // active blocks--
//    a1[6] -= freedSize;
//
//    // 标记块为已释放
//    reinterpret_cast<unsigned char*>(a2)[2] = 0;
//    reinterpret_cast<unsigned char*>(a2)[3] = (flags & 0x10) | 2;
//
//    // 更新堆的结束指针或插入到空闲链表
//    char* endPtr = reinterpret_cast<char*>(a2) + *a2;
//    if (reinterpret_cast<char*>(a1[8]) == endPtr)
//    {
//        reinterpret_cast<DWORD*>(a2)[1] = 0;
//        a1[8] = reinterpret_cast<DWORD>(a2);
//    }
//    else
//    {
//        endPtr[3] |= 0x10u; // 设置前一个块的合并标志
//        int index = (*a2 >> 5) < 9 ? (*a2 >> 5) : 8;
//        reinterpret_cast<DWORD*>(a2)[1] = a1[index + 17];
//        a1[index + 17] = reinterpret_cast<DWORD>(a2);
//
//        if ((reinterpret_cast<char*>(a2)[3] & 0x10) || (endPtr[3] & 2))
//            ++a1[9];
//    }
//
//    // 如果没有活动块，重置堆
//    if (a1[5] == 0)
//    {
//        a1[8] = a1[7];
//        for (int i = 17; i <= 25; i++)
//        {
//            a1[i] = 0;
//        }
//        a1[9] = 0;
//
//        bool isDebug = (a1[1] < 0x80000000);
//        if (isDebug)
//        {
//            int debugIndex = a1[2];
//            Storm_g_DebugHeapPtr = reinterpret_cast<int>(a1);
//            Storm_g_HeapActiveFlag(debugIndex) = 1;
//        }
//    }
//
//    return 2; // 返回固定值，可能表示成功
//}
//
////------------------------------------------------------------------------------
// // sub_1502B4F0
// // 在 Storm_MemFree 里被调用
// // 1) 计算要填充/释放大小
// // 2) 若启用填充 (dword_15056F70)，则 memset(..., 0xDD)
// // 3) g_TotalAllocatedMemory -= *a3
// // 4) a1[15]++ (计数?)
// // 5) 调用 StormHeap_InternalFree
// // 6) sub_15035850() => dword_15057728++
// //------------------------------------------------------------------------------
//void __fastcall sub_1502B4F0(DWORD* a1, DWORD* a2, unsigned __int16* a3)
//{
//    size_t blockSize;
//    if ((reinterpret_cast<unsigned char*>(a3)[3] & 4) != 0)
//    {
//        blockSize = *(a2 - 4);
//    }
//    else
//    {
//        int offset = reinterpret_cast<unsigned char*>(a3)[2] + 8;
//        if ((reinterpret_cast<unsigned char*>(a3)[3] & 1) != 0)
//            offset = reinterpret_cast<unsigned char*>(a3)[2] + 10;
//        blockSize = *a3 - offset;
//    }
//
//    // 如果启用 dword_15056F70 填充模式 并且 (flags & 4) == 0
//    if (Storm_dword_15056F70 && ((reinterpret_cast<unsigned char*>(a3)[3] & 4) == 0))
//    {
//        std::memset(a2, 0xDD, blockSize);
//    }
//
//    Storm_g_TotalAllocatedMemory -= *a3;
//    ++a1[15];  // 计数器
//
//    StormHeap_InternalFree(a1, a3);
//
//    // sub_15035850 => dword_15057728++
//    Storm_dword_15057728++;
//}
//
////------------------------------------------------------------------------------
// // StormHeap_AllocPage
// //------------------------------------------------------------------------------
//unsigned __int16* __fastcall StormHeap_AllocPage(DWORD* a1, unsigned int size, LPVOID lpAddress)
//{
//    //// 1. 判断是否为大块分配或特殊标志
//    //bool isLargeAlloc = (Storm_dword_15056F74 != 0 || size > 0xFE7B);
//    //bool specialFlag = (Storm_dword_1505536C != 0 && !isLargeAlloc);
//
//    // 2. 计算实际分配大小，考虑对齐和额外开销
//    unsigned int userSize = isLargeAlloc ? 4 : size;
//    unsigned int overhead = specialFlag ? 10 : 8;
//    unsigned int baseSize = userSize + overhead;
//    unsigned int alignFix = (-(int)baseSize) & 7; // 对齐到8字节边界
//    unsigned int finalSize = baseSize + alignFix;
//
//    // 3. 寻找空闲块
//    unsigned __int16* blockPtr = nullptr;
//
//    // 遍历空闲链表，寻找合适的块
//    for (int i = 17; i <= 25; i++)
//    {
//        DWORD* freeList = &a1[i];
//        DWORD currentFree = *freeList;
//        DWORD previousFree = 0;
//
//        while (currentFree != 0)
//        {
//            unsigned __int16* freeBlock = reinterpret_cast<unsigned __int16*>(currentFree);
//            unsigned int freeSize = *freeBlock;
//
//            if (freeSize >= finalSize)
//            {
//                // 找到合适的块，移除它
//                if (previousFree == 0)
//                {
//                    *freeList = *reinterpret_cast<DWORD*>(freeBlock + 1);
//                }
//                else
//                {
//                    *reinterpret_cast<DWORD*>(previousFree + 1) = *reinterpret_cast<DWORD*>(freeBlock + 1);
//                }
//
//                blockPtr = freeBlock;
//
//                // 如果剩余空间足够大，进行切割
//                if (freeSize > finalSize + 8)
//                {
//                    unsigned __int16* remainingBlock = reinterpret_cast<unsigned __int16*>(reinterpret_cast<char*>(blockPtr) + finalSize);
//                    *remainingBlock = freeSize - finalSize;
//                    reinterpret_cast<char*>(remainingBlock)[2] = 0;
//                    reinterpret_cast<char*>(remainingBlock)[3] = 0x2; // 标志位，表示空闲
//
//                    // 将剩余块插入到对应的空闲链表
//                    int index = (remainingBlock[0] >> 5) < 9 ? (remainingBlock[0] >> 5) : 8;
//                    DWORD* remainingFreeList = &a1[17 + index];
//                    *reinterpret_cast<DWORD*>(remainingBlock + 1) = *remainingFreeList;
//                    *remainingFreeList = reinterpret_cast<DWORD>(remainingBlock);
//
//                    a1[9]++; // 空闲块计数
//                }
//
//                break; // 分配成功
//            }
//
//            previousFree = currentFree;
//            currentFree = *reinterpret_cast<DWORD*>(freeBlock + 1);
//        }
//
//        if (blockPtr != nullptr)
//            break;
//    }
//
//    if (blockPtr == nullptr)
//    {
//        // 如果没有找到合适的空闲块，则分配新块
//        blockPtr = reinterpret_cast<unsigned __int16*>(
//            reinterpret_cast<char*>(a1) + Storm_g_TotalAllocatedMemory
//            );
//
//        // 检查是否需要提交更多内存
//        if (reinterpret_cast<char*>(blockPtr) + finalSize > reinterpret_cast<char*>(a1) + a1[11])
//        {
//            if (!StormHeap_CommitPages(a1, reinterpret_cast<char*>(blockPtr) + finalSize - reinterpret_cast<char*>(a1)))
//            {
//                Storm_SetLastError(0x8510007C);
//                if (Storm_g_ErrorHandlingEnabled)
//                {
//                    Storm_AllocErrorHandler(0x8510007C, "StormHeap_AllocPage", -1, 0, 1, 1u);
//                }
//                return nullptr;
//            }
//        }
//    }
//
//    // 4. 初始化块元数据
//    *blockPtr = finalSize; // 块大小
//    reinterpret_cast<char*>(blockPtr)[2] = alignFix; // 偏移
//    reinterpret_cast<char*>(blockPtr)[3] = (isLargeAlloc ? 0x4 : 0x1) | (specialFlag ? 0x2 : 0x0); // 标志位
//
//    // 设置尾部校验值
//    if (reinterpret_cast<char*>(blockPtr)[3] & 0x1)
//    {
//        unsigned short* tailPtr = reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(blockPtr) + finalSize - 2);
//        *tailPtr = 4785; // 0x1291
//    }
//
//    // 5. 更新堆状态
//    Storm_g_TotalAllocatedMemory += finalSize;
//    ++Storm_dword_15057728;
//
//    return blockPtr;
//}
//
////------------------------------------------------------------------------------
// // StormHeap_ReallocImpl
// // 逆向中提到: 用于在 ReAlloc 时尝试扩缩容同一块，否则分配新块 + memcpy + free 旧块
// //------------------------------------------------------------------------------
//char* __fastcall StormHeap_ReallocImpl(
//    DWORD* heapPtr,
//    DWORD* blockPtr,
//    char* src,
//    unsigned __int16* blockHeader,
//    size_t newSize,
//    char flags
//)
//{
//    // 1. 计算旧块大小
//    size_t oldSize = 0;
//    if ((reinterpret_cast<unsigned char*>(blockHeader)[3] & 4) != 0)
//    {
//        // 大块
//        oldSize = *(blockPtr - 4);
//    }
//    else
//    {
//        int offset = reinterpret_cast<unsigned char*>(blockHeader)[2] + 8;
//        if ((reinterpret_cast<unsigned char*>(blockHeader)[3] & 1) != 0)
//            offset = reinterpret_cast<unsigned char*>(blockHeader)[2] + 10;
//        oldSize = *blockHeader - offset;
//    }
//
//    // 2. 判断是否可以原地扩展或缩容
//    char* result = nullptr;
//    if (newSize > oldSize)
//    {
//        // 尝试原地扩容
//        if (sub_1502AE30(heapPtr, blockHeader, static_cast<int>(oldSize), static_cast<unsigned int>(newSize)))
//        {
//            // 如果成功，设置新增部分的内存
//            if (newSize > oldSize)
//            {
//                if (flags & 8)
//                {
//                    std::memset(src + oldSize, 0, newSize - oldSize);
//                }
//                else if (Storm_dword_15056F70)
//                {
//                    std::memset(src + oldSize, 0xEE, newSize - oldSize);
//                }
//            }
//            return src;
//        }
//    }
//    else if (newSize < oldSize)
//    {
//        // 尝试原地缩容
//        if (sub_1502B680(heapPtr, blockHeader, static_cast<int>(oldSize), static_cast<unsigned int>(newSize)))
//        {
//            // 如果成功，可能需要截断
//            return src;
//        }
//    }
//
//    // 3. 如果原地扩缩容失败，分配新块
//    if (flags & 0x10)
//        return nullptr;
//
//    unsigned __int16* newBlock = StormHeap_AllocPage(heapPtr, static_cast<unsigned int>(newSize), nullptr);
//    char* retPtr = reinterpret_cast<char*>(newBlock);
//    if (retPtr && src && newSize)
//    {
//        size_t copySize = (oldSize < newSize) ? oldSize : newSize;
//        std::memcpy(retPtr, src, copySize);
//    }
//
//    // 4. 释放旧块
//    sub_1502B4F0(heapPtr, reinterpret_cast<DWORD*>(src), blockHeader);
//
//    result = retPtr;
//
//    // 5. 若 newSize > oldSize => memset 新增部分
//    if (result && (newSize > oldSize))
//    {
//        if (flags & 8)
//        {
//            std::memset(result + oldSize, 0, newSize - oldSize);
//        }
//        else if (Storm_dword_15056F70)
//        {
//            std::memset(result + oldSize, 0xEE, newSize - oldSize);
//        }
//    }
//
//    return result;
//}
//
////------------------------------------------------------------------------------
// // sub_1502AE30
// // 处理在原地扩容
// //------------------------------------------------------------------------------
//int __fastcall sub_1502AE30(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4)
//{
//    // 1. 检查是否为大块或特殊标志
//    //BOOL bigAlloc = (Storm_dword_15056F74 != 0 || a4 > 0xFE7B);
//    //BOOL spFlag = (Storm_dword_1505536C != 0 && !bigAlloc);
//
//    // 2. 计算 finalSize
//    unsigned int sizeCandidate = (bigAlloc ? 4 : a4);
//    unsigned int overhead = (spFlag ? 10 : 8);
//    unsigned int basePlus = sizeCandidate + overhead;
//    unsigned int alignFix = (-(int)basePlus) & 7;
//    unsigned int finalSize = basePlus + alignFix;
//
//    // 3. 检查 finalSize 是否超过 0xFFFF 或是否为大块
//    if (finalSize > 0xFFFF || bigAlloc)
//        return 0;
//
//    unsigned int originalBlockSize = *a2;
//    if (finalSize > originalBlockSize)
//    {
//        // 尝试合并后续空闲块
//        unsigned int diff = finalSize - originalBlockSize;
//        unsigned int consumed = 0;
//        unsigned __int16* nextBlock = reinterpret_cast<unsigned __int16*>(reinterpret_cast<char*>(a2) + originalBlockSize);
//
//        // 遍历并合并空闲块
//        while (consumed < diff && nextBlock < reinterpret_cast<unsigned __int16*>(a1[8]))
//        {
//            char nextFlags = reinterpret_cast<char*>(nextBlock)[3];
//            if ((nextFlags & 2) != 0)
//                break; // 已分配块，无法合并
//
//            unsigned int nextBlkSize = *nextBlock;
//            consumed += nextBlkSize;
//            nextBlock = reinterpret_cast<unsigned __int16*>(reinterpret_cast<char*>(nextBlock) + nextBlkSize);
//        }
//
//        if (consumed < diff)
//            return 0; // 无法满足扩容需求
//
//        // 更新当前块大小
//        *a2 = originalBlockSize + consumed;
//
//        // 更新堆的总分配内存
//        a1[6] += (a4 - a3);
//
//        // 合并空闲块
//        StormHeap_CombineFreeBlocks(reinterpret_cast<int>(a1), a2, reinterpret_cast<int*>(&finalSize), reinterpret_cast<char*>(&alignFix));
//
//        // 重新构建空闲链表
//        StormHeap_RebuildFreeList(a1);
//
//        return 1; // 扩容成功
//    }
//    else
//    {
//        // finalSize <= originalBlockSize => 尝试缩容
//        if (sub_1502B680(a1, a2, a3, a4))
//        {
//            return 1; // 缩容成功
//        }
//        return 0; // 缩容失败
//    }
//}
//
////------------------------------------------------------------------------------
// // sub_1502B680
// // 处理在原地缩容
// //------------------------------------------------------------------------------
//int __fastcall sub_1502B680(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4)
//{
//    // 1. 判断是否为大块或特殊标志
//    BOOL bigAlloc = (Storm_dword_15056F74 != 0 || a4 > 0xFE7B);
//    BOOL spFlag = (Storm_dword_1505536C != 0 && !bigAlloc);
//
//    // 2. 计算 finalSize
//    unsigned int sizeCandidate = bigAlloc ? 4 : a4;
//    unsigned int overhead = spFlag ? 10 : 8;
//    unsigned int baseSize = sizeCandidate + overhead;
//    unsigned int alignFix = (-(int)baseSize) & 7;
//    unsigned int finalSize = baseSize + alignFix;
//
//    // 3. 计算剩余大小
//    unsigned int oldBlockSize = *a2;
//    unsigned int remainSize = oldBlockSize - finalSize;
//
//    if (remainSize < 0x10)
//    {
//        // 合并
//        reinterpret_cast<char*>(a2)[3] &= ~0x10u; // 清除合并标志
//        a1[6] += (a4 - a3);
//    }
//    else
//    {
//        // 创建新的空闲块
//        char* newFree = reinterpret_cast<char*>(a2) + finalSize;
//        *reinterpret_cast<unsigned short*>(newFree) = remainSize;
//        reinterpret_cast<unsigned short*>(newFree)[1] = 512; // 假设标志为 0x200 (示例)
//
//        // 计算空闲链表索引
//        int index = (remainSize >> 5) < 9 ? (remainSize >> 5) : 8;
//        DWORD* remainingFreeList = &a1[17 + index];
//        *reinterpret_cast<DWORD*>(newFree + 2) = *remainingFreeList;
//        *remainingFreeList = reinterpret_cast<DWORD>(newFree);
//
//        a1[9]++; // 空闲块计数
//
//        // 更新堆的总分配内存
//        a1[6] += (a4 - a3);
//    }
//
//    // 更新当前块大小和标志位
//    *a2 = finalSize;
//    reinterpret_cast<char*>(a2)[2] = alignFix;
//    reinterpret_cast<char*>(a2)[3] = (reinterpret_cast<char*>(a2)[3] & 0xFE) | (spFlag ? 0x2 : 0x0);
//
//    // 设置尾部校验值
//    if (reinterpret_cast<char*>(a2)[3] & 0x1)
//    {
//        unsigned short* tailPtr = reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(a2) + finalSize - 2);
//        *tailPtr = 4785; // 0x1291
//    }
//
//    return 1; // 缩容成功
//}
