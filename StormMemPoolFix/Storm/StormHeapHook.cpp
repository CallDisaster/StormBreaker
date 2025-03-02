#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <map>
#include <mutex>
#include <detours.h>
#include <cstring>
#include <iostream>
#include <intrin.h>
#include <unordered_set>
#include <unordered_map>
#include "StormOffsets.h"  
#include "StormHook.h"
#include "MemoryPool.h"

// 当块被 free 后, Storm 通常把头4字节改成 size(WORD) + AlignPadding(BYTE) + Flags(BYTE=2) + pNext
#pragma pack(push,1)
struct StormFreeBlock
{
    WORD  size;         // 包含头部在内的“整块大小”，= (sizeof(StormFreeBlock) + 用户区 + 可能余的边界)
    BYTE  AlignPadding; // 对齐
    BYTE  Flags;        // 0x2=free
    StormFreeBlock* pNext; // 后面链接
};
#pragma pack(pop)

// ============== 全局数据 ==============
static std::unordered_map<void*, size_t> g_DecommittedBlocks;
static std::mutex g_DecommitLock;

//size_t g_freedByAllocHook = 0;
//size_t g_freedByFreeHook = 0;
static size_t g_peakMemoryUsed = 0;

// StormOffsets 里定义的全局:
extern uintptr_t gStormDllBase;
inline size_t StormFix_GetCurrentUsage()
{
    if (Storm_g_TotalAllocatedMemory)
        return Storm_g_TotalAllocatedMemory;
    return 0;
}

// ============== StormFreeList / 触发合并等 ==============
#define FREE_LIST_SLOT_BASE 17
#define FREE_LIST_SLOT_COUNT 9

// ============== 原函数指针声明 ==============
typedef DWORD* (__fastcall* StormHeap_Create_t)(char*, int, int, size_t, int, SIZE_T, SIZE_T);
typedef unsigned __int16* (__fastcall* StormHeap_AllocPage_t)(char*, unsigned int, LPVOID);
typedef DWORD* (__fastcall* StormHeap_RebuildFreeList_t)(DWORD*);
typedef char* (__fastcall* StormHeap_CombineFreeBlocks_t)(int, unsigned __int16*, int*, char*);
typedef int(__fastcall* StormHeap_CommitPages_t)(DWORD*, int);
typedef char(__fastcall* StormHeap_InternalFree_t)(DWORD*, unsigned __int16*);
typedef int(__fastcall* StormHeap_ComputeIndex_t)(int*, int);
typedef void* (__fastcall* StormHeap_Alloc_t)(DWORD*, int, int, size_t);
typedef char* (__fastcall* StormHeap_ReallocImpl_t)(DWORD*, DWORD*, char*, unsigned __int16*, size_t, char);
typedef int(__fastcall* sub_1502AE30_t)(DWORD*, unsigned __int16*, int, unsigned int);
typedef int(__fastcall* sub_1502B680_t)(DWORD*, unsigned __int16*, int, unsigned int);
typedef void(__fastcall* sub_1502B4F0_t)(DWORD*, DWORD*, unsigned __int16*);
typedef void(__fastcall* sub_15035850_t)();

// 全局原函数指针
static StormHeap_Create_t           s_origStormHeap_Create = nullptr;
static StormHeap_AllocPage_t        s_origStormHeap_AllocPage = nullptr;
static StormHeap_RebuildFreeList_t  s_origStormHeap_RebuildFreeList = nullptr;
static StormHeap_CombineFreeBlocks_t s_origStormHeap_CombineFreeBlocks = nullptr;
static StormHeap_CommitPages_t      s_origStormHeap_CommitPages = nullptr;
static StormHeap_InternalFree_t     s_origStormHeap_InternalFree = nullptr;
static StormHeap_ComputeIndex_t     s_origStormHeap_ComputeIndex = nullptr;
static StormHeap_Alloc_t            s_origStormHeap_Alloc = nullptr;
static StormHeap_ReallocImpl_t      s_origStormHeap_ReallocImpl = nullptr;
static sub_1502AE30_t               s_origSub_1502AE30 = nullptr;
static sub_1502B680_t               s_origSub_1502B680 = nullptr;
static sub_1502B4F0_t               s_origSub_1502B4F0 = nullptr;
static sub_15035850_t               s_origSub_15035850 = nullptr;

// ============== 小工具: 判断空闲还是已分配, 获取块总大小 ==============
/**
 * 判断 `pBlock` 是否是“已 free”状态 (Flags=2)
 * 如果空闲:
 *    -> interpret as StormFreeBlock
 *    -> *size 即包含了头部 + 用户区 + alignment + boundary
 * 如果已分配:
 *    -> interpret as StormAllocHeader
 *    -> block大小 = hdr->Size + sizeof(StormAllocHeader) + hdr->AlignPadding (+ boundary?若Flag=1再+2)
 */
static bool StormBlockIsFree(const void* pBlock)
{
    const StormFreeBlock* fb = reinterpret_cast<const StormFreeBlock*>(pBlock);
    return (fb->Flags & 0x2) != 0; // 2 => free
}

static size_t StormBlockGetTotalSize(const void* pBlock)
{
    // 如果是 free
    const StormFreeBlock* fb = reinterpret_cast<const StormFreeBlock*>(pBlock);
    if ((fb->Flags & 0x2) != 0)
    {
        // => StormFreeBlock
        //  fb->size 包含了全部长度
        return fb->size;
    }
    else
    {
        // => StormAllocHeader
        const StormAllocHeader* ah = reinterpret_cast<const StormAllocHeader*>(pBlock);
        size_t total = ah->Size + sizeof(StormAllocHeader) + ah->AlignPadding;
        // 如果 (ah->Flags & 0x1) => boundaryMagic, 可能还会多 2字节
        // 不同版本Storm 里 boundaryMagic 不一定; 这里先演示不加
        // if (ah->Flags & 0x1) total += 2; 
        return total;
    }
}

// ============== 触发“紧凑合并”逻辑 (不变) ==============
static void CheckAndTriggerHeapCompact(char* heapBase)
{
    DWORD* heap = (DWORD*)heapBase;
    static int compactCounter = 0;
    // 大约超过 90% 时计数+1
    if ((heap[7] - heap[8]) > 0.9 * heap[7])
    {
        compactCounter++;
        if (compactCounter >= 3)
        {
            size_t usageBefore = StormFix_GetCurrentUsage();
            s_origStormHeap_RebuildFreeList(heap);
            size_t usageAfter = StormFix_GetCurrentUsage();
            if (usageBefore > usageAfter)
            {
                g_freedByAllocHook += (usageBefore - usageAfter);
            }
            compactCounter = 0;
        }
    }
    else
    {
        compactCounter = 0;
    }
}

// ============== Hook: StormHeap_AllocPage ==============
unsigned __int16* __fastcall StormHeap_AllocPageHook(char* heapBase, unsigned int requestedSize, LPVOID lpAddress)
{
    //printf("[AllocPage] Requesting size: %u\n", requestedSize);

    CheckAndTriggerHeapCompact(heapBase);

    // 调用原函数
    unsigned __int16* pResult = s_origStormHeap_AllocPage(heapBase, requestedSize, lpAddress);
    if (!pResult)
    {
        printf("[AllocPage] Allocation failed!\n");
        return nullptr;
    }

    // pResult => "用户可用地址" or "blockHeader + offset"?
    // 绝大多数Storm版本: pResult = blockHeader + (4 or 8?), 需自己测试
    // 目前你原代码是 "blockPtr = pResult - 4" => 可能是 StormFreeBlock? 
    // 更安全: 先 - (sizeof(StormAllocHeader)) 做检查:
    char* blockBase = (char*)pResult - sizeof(StormAllocHeader);
    // 但若 Storm 真的是 -(4) = Freed 结构, 那就得自己调试…

    // 这里维持你之前 approach: 
    char* guessBlock = (char*)pResult - 4;

    // 若它曾被我们 Decommit 过, 需要 Recommit
    {
        std::lock_guard<std::mutex> lock(g_DecommitLock);
        auto it = g_DecommittedBlocks.find((void*)guessBlock);
        if (it != g_DecommittedBlocks.end())
        {
            size_t blockSize = it->second;
            //printf("[AllocPage] Recommitting decommitted block at %p, size=%zu\n", guessBlock, blockSize);

            LPVOID re = VirtualAlloc(guessBlock, blockSize, MEM_COMMIT, PAGE_READWRITE);
            if (!re)
            {
                printf("[AllocPage] Recommit FAILED! ptr=%p, size=%zu, err=%d\n",
                    guessBlock, blockSize, GetLastError());
            }
            g_DecommittedBlocks.erase(it);
        }
    }

    //printf("[AllocPage] Allocated at %p\n", pResult);
    return pResult;
}

// ============== Hook: StormHeap_InternalFree ==============
char __fastcall StormHeap_InternalFreeHook(DWORD* heap, unsigned __int16* blockHeader)
{

    // 获取原始用户指针和大小
    void* userPtr = (void*)((char*)blockHeader + sizeof(StormAllocHeader));
    size_t size = 0;

    try {
        // 尝试获取块大小
        StormAllocHeader* hdr = reinterpret_cast<StormAllocHeader*>(blockHeader);
        size = hdr->Size;

        // 检查是否是我们管理的小块
        if (size > 0 && SmallBlockPool::ShouldIntercept(size)) {
            if (SmallBlockPool::Free(userPtr, size)) {
                // 我们已处理，返回成功码
                return 2;
            }
        }
    }
    catch (...) {
        // 异常处理
    }

    size_t usageBefore = StormFix_GetCurrentUsage();
    //printf("[InternalFree] Freeing block at %p\n", blockHeader);

    // 先把它真正交给 Storm 做 free => 这会把 blockHeader 改成 StormFreeBlock 结构
    char ret = s_origStormHeap_InternalFree(heap, blockHeader);

    size_t usageMid = StormFix_GetCurrentUsage();
    size_t freedByOrig = (usageBefore > usageMid ? usageBefore - usageMid : 0);

    // 紧凑
    if (heap[5] == 0)
    {
        size_t usageBeforeReset = StormFix_GetCurrentUsage();
        heap[8] = heap[7];
        for (int i = 0; i < FREE_LIST_SLOT_COUNT; i++)
            heap[FREE_LIST_SLOT_BASE + i] = 0;
        size_t usageAfterReset = StormFix_GetCurrentUsage();
        g_freedByFreeHook += (usageBeforeReset > usageAfterReset ? usageBeforeReset - usageAfterReset : 0);
    }
    else
    {
        size_t usageBeforeRebuild = StormFix_GetCurrentUsage();
        s_origStormHeap_RebuildFreeList(heap);
        size_t usageAfterRebuild = StormFix_GetCurrentUsage();
        g_freedByFreeHook += (usageBeforeRebuild > usageAfterRebuild ? usageBeforeRebuild - usageAfterRebuild : 0);
    }
    g_freedByFreeHook += freedByOrig;

    bool isFree = StormBlockIsFree(blockHeader);
    if (isFree)
    {
        size_t blockSize = StormBlockGetTotalSize(blockHeader);
        if (blockSize > 0)
        {
            // 检查：地址与大小都为系统页对齐？
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            size_t pageSize = si.dwPageSize;

            uintptr_t addr = (uintptr_t)blockHeader;

            // 如果恰好满足页对齐
            if ((addr % pageSize) == 0 && (blockSize % pageSize) == 0)
            {
                printf("[InternalFree] Decommitting block at %p, size=%zu\n", blockHeader, blockSize);
                BOOL bOK = VirtualFree(blockHeader, blockSize, MEM_DECOMMIT);
                if (bOK)
                {
                    std::lock_guard<std::mutex> lock(g_DecommitLock);
                    g_DecommittedBlocks[(void*)blockHeader] = blockSize;
                }
                else
                {
                    printf("[InternalFree] Decommit FAILED! ptr=%p, size=%zu, err=%d\n",
                        blockHeader, blockSize, GetLastError());
                }
            }
            else
            {
                // 不满足对齐: 不做 MEM_DECOMMIT 以防崩
                // 仅提示一下
                // printf("[InternalFree] block not page-aligned => skip decommit\n");
            }
        }
    }


    //printf("[InternalFree] Free completed for %p\n", blockHeader);
    return ret;
}

// ============== Hook: StormHeap_Alloc (可选) ==============
void* __fastcall StormHeap_AllocHook(DWORD* pHeap, int a2, int flags, size_t size)
{
    // 1) 检查是否是我们要拦截的小块大小
    if (SmallBlockPool::ShouldIntercept(size)) {
        void* ptr = SmallBlockPool::Allocate(size);
        if (ptr) {
            // 统计和记录
            return ptr;
        }
        // 无可用块，继续Storm分配
    }

    // 2) 调用原始
    void* pUserPtr = s_origStormHeap_Alloc(pHeap, a2, flags, size);
    if (!pUserPtr)
        return nullptr;

    // 3) 可能 Storm 又给你分配了某个“曾被 Decommit”的空闲块
    //    估计 pUserPtr = blockHeader + 12? (含StormAllocHeader)
    //    这里若你原先以 “blockPtr = pUserPtr - 4” 做记录，就保持一致:
    char* guessBlock = (char*)pUserPtr - 4;

    {
        std::lock_guard<std::mutex> lock(g_DecommitLock);
        auto it = g_DecommittedBlocks.find((void*)guessBlock);
        if (it != g_DecommittedBlocks.end())
        {
            size_t blockSize = it->second;
            //printf("[StormHeap_AllocHook] Recommit block at %p, size=%zu\n", guessBlock, blockSize);
            if (!VirtualAlloc(guessBlock, blockSize, MEM_COMMIT, PAGE_READWRITE))
            {
                printf("[StormHeap_AllocHook] Recommit FAILED: ptr=%p size=%zu err=%d\n",
                    guessBlock, blockSize, GetLastError());
            }
            else
            {
                //printf("[StormHeap_AllocHook] Recommit SUCCESS: ptr=%p, size=%zu\n", guessBlock, blockSize);
            }
            g_DecommittedBlocks.erase(it);
        }
    }

    return pUserPtr;
}

// ============== 其他 Hook (保留空壳) ==============

static int __fastcall Hooked_StormHeap_ComputeIndex(int* a1, int a2) { return 1; }
static char* __fastcall Hooked_StormHeap_ReallocImpl(
    DWORD* a1, DWORD* a2, char* Src, unsigned __int16* a4, size_t newSize, char flags)
{
    return nullptr;
}
static int __fastcall Hooked_sub_1502AE30(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4) { return 1; }
static int __fastcall Hooked_sub_1502B680(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4) { return 0; }
static void __fastcall Hooked_sub_1502B4F0(DWORD* a1, DWORD* a2, unsigned __int16* a3) {}
static void __fastcall Hooked_sub_15035850() {}

// ============== 主 Hook 安装函数 ==============
bool HookAllStormHeapFunctions()
{
    // 1) 获取Storm函数地址
    s_origStormHeap_Create = (StormHeap_Create_t)(gStormDllBase + 0x2A350);
    s_origStormHeap_AllocPage = (StormHeap_AllocPage_t)(gStormDllBase + 0x2A510);
    s_origStormHeap_RebuildFreeList = (StormHeap_RebuildFreeList_t)(gStormDllBase + 0x2A920);
    s_origStormHeap_CombineFreeBlocks = (StormHeap_CombineFreeBlocks_t)(gStormDllBase + 0x2B790);
    s_origStormHeap_CommitPages = (StormHeap_CommitPages_t)(gStormDllBase + 0x2ADE0);
    s_origStormHeap_InternalFree = (StormHeap_InternalFree_t)(gStormDllBase + 0x2ABF0);
    s_origStormHeap_ComputeIndex = (StormHeap_ComputeIndex_t)(gStormDllBase + 0x2AD60);
    s_origStormHeap_Alloc = (StormHeap_Alloc_t)(gStormDllBase + 0x2B3B0);
    s_origStormHeap_ReallocImpl = (StormHeap_ReallocImpl_t)(gStormDllBase + 0x2B560);
    s_origSub_1502AE30 = (sub_1502AE30_t)(gStormDllBase + 0x2AE30);
    s_origSub_1502B680 = (sub_1502B680_t)(gStormDllBase + 0x2B680);
    s_origSub_1502B4F0 = (sub_1502B4F0_t)(gStormDllBase + 0x2B4F0);
    s_origSub_15035850 = (sub_15035850_t)(gStormDllBase + 0x35850);

    // 2) Detour
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)s_origStormHeap_AllocPage, StormHeap_AllocPageHook);
    DetourAttach(&(PVOID&)s_origStormHeap_InternalFree, StormHeap_InternalFreeHook);
    DetourAttach(&(PVOID&)s_origStormHeap_Alloc, StormHeap_AllocHook);

    // 如果你想 Hook 更多:
    // DetourAttach(&(PVOID&)s_origStormHeap_RebuildFreeList,  Hooked_StormHeap_RebuildFreeList);
    // DetourAttach(&(PVOID&)s_origStormHeap_CombineFreeBlocks,Hooked_StormHeap_CombineFreeBlocks);
    // ...

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR)
    {
        printf("[HookAllStormHeapFunctions] Detour commit error = %d\n", error);
        return false;
    }

    printf("[HookAllStormHeapFunctions] success.\n");
    return true;
}
