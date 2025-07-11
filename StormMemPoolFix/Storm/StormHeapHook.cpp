﻿#include "pch.h"
// #include "StormHook.h" // Moved lower
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
#include "StormHook.h" // Include after StormOffsets.h
#include "MemoryPool.h"
#include <shared_mutex>
#include <Log/LogSystem.h>

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

enum class BlockState {
    Normal,      // 正常状态
    Reset,       // 已MEM_RESET
    Decommitted, // 已MEM_DECOMMIT (仅用于特殊情况)
    Invalid      // 无效状态
};

struct BlockStateInfo {
    BlockState state;
    size_t size;
    DWORD timestamp;
    std::string operation;  // 记录操作类型
};

// ============== 全局数据 ==============
static std::unordered_map<void*, size_t> g_DecommittedBlocks;
static std::mutex g_DecommitLock;

// Define static variables for hook statistics, limiting scope to this file
std::atomic<size_t> g_freedByAllocHook{ 0 };
std::atomic<size_t> g_freedByFreeHook{ 0 };
static size_t g_peakMemoryUsed = 0;

static std::unordered_map<void*, size_t> g_ResetBlocks;
static std::mutex g_ResetLock;  // 改名对应的锁

static std::unordered_map<void*, BlockStateInfo> g_BlockStates;
static std::shared_mutex g_BlockStatesLock;  // 读写分离锁

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

 // 安全的状态查询函数
BlockState GetBlockState(void* ptr) {
    std::shared_lock<std::shared_mutex> lock(g_BlockStatesLock);
    auto it = g_BlockStates.find(ptr);
    return (it != g_BlockStates.end()) ? it->second.state : BlockState::Normal;
}


static bool StormBlockIsFree(const void* pBlock)
{
    const StormFreeBlock* fb = reinterpret_cast<const StormFreeBlock*>(pBlock);
    return (fb->Flags & 0x2) != 0; // 2 => free
}

void SetBlockState(void* ptr, BlockState state, size_t size, const std::string& operation) {
    std::unique_lock<std::shared_mutex> lock(g_BlockStatesLock);
    g_BlockStates[ptr] = { state, size, GetTickCount(), operation };

    LogMessage("[BlockState] %s: ptr=%p, size=%zu, op=%s",
        state == BlockState::Reset ? "RESET" :
        state == BlockState::Decommitted ? "DECOMMIT" : "NORMAL",
        ptr, size, operation.c_str());
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
unsigned __int16* __fastcall StormHeap_AllocPageHook(char* heapBase, unsigned int requestedSize, LPVOID lpAddress) {
    CheckAndTriggerHeapCompact(heapBase);

    // 调用原函数
    unsigned __int16* pResult = s_origStormHeap_AllocPage(heapBase, requestedSize, lpAddress);
    if (!pResult) {
        LogMessage("[AllocPage] 分配失败: 大小=%u", requestedSize);
        return nullptr;
    }

    // 检查是否需要恢复之前优化的内存
    char* blockBase = (char*)pResult - sizeof(StormAllocHeader);

    // 查询块状态
    BlockState state = GetBlockState(blockBase);

    if (state == BlockState::Reset) {
        // MEM_RESET的内存被重新使用，更新状态
        LogMessage("[AllocPage] MEM_RESET块被重用: %p", blockBase);
        SetBlockState(blockBase, BlockState::Normal, 0, "AllocPage_Reuse");
    }
    else if (state == BlockState::Decommitted) {
        // 需要重新提交DECOMMIT的内存
        std::shared_lock<std::shared_mutex> lock(g_BlockStatesLock);
        auto it = g_BlockStates.find(blockBase);
        if (it != g_BlockStates.end()) {
            size_t blockSize = it->second.size;
            lock.unlock();  // 释放读锁

            LogMessage("[AllocPage] 重新提交DECOMMIT块: %p, 大小: %zu", blockBase, blockSize);

            LPVOID re = VirtualAlloc(blockBase, blockSize, MEM_COMMIT, PAGE_READWRITE);
            if (re) {
                SetBlockState(blockBase, BlockState::Normal, 0, "AllocPage_Recommit");
                LogMessage("[AllocPage] 重新提交成功: %p", blockBase);
            }
            else {
                DWORD error = GetLastError();
                LogMessage("[AllocPage] 重新提交失败: ptr=%p, size=%zu, 错误=%d",
                    blockBase, blockSize, error);

                // 提交失败，返回NULL让Storm处理
                return nullptr;
            }
        }
    }

    return pResult;
}

// ============== Hook: StormHeap_InternalFree ==============
char __fastcall StormHeap_InternalFreeHook(DWORD* heap, unsigned __int16* blockHeader) {
    // 获取原始用户指针和大小
    void* userPtr = (void*)((char*)blockHeader + sizeof(StormAllocHeader));
    size_t size = 0;

    // 检查小块池拦截
    try {
        StormAllocHeader* hdr = reinterpret_cast<StormAllocHeader*>(blockHeader);
        size = hdr->Size;

        if (size > 0 && SmallBlockPool::ShouldIntercept(size)) {
            if (SmallBlockPool::Free(userPtr, size)) {
                LogMessage("[SmallBlock] 小块池释放成功: %p, 大小: %zu", userPtr, size);
                return 2;  // 成功码
            }
        }
    }
    catch (...) {
        LogMessage("[InternalFree] 小块检查异常: %p", blockHeader);
    }

    size_t usageBefore = StormFix_GetCurrentUsage();

    // 调用原始Storm释放函数
    char ret = s_origStormHeap_InternalFree(heap, blockHeader);

    size_t usageMid = StormFix_GetCurrentUsage();
    size_t freedByOrig = (usageBefore > usageMid) ? (usageBefore - usageMid) : 0;

    // Storm内部整理逻辑
    if (heap[5] == 0) {
        size_t usageBeforeReset = StormFix_GetCurrentUsage();
        heap[8] = heap[7];
        for (int i = 0; i < FREE_LIST_SLOT_COUNT; i++)
            heap[FREE_LIST_SLOT_BASE + i] = 0;
        size_t usageAfterReset = StormFix_GetCurrentUsage();
        g_freedByFreeHook += (usageBeforeReset > usageAfterReset) ?
            (usageBeforeReset - usageAfterReset) : 0;
    }
    else {
        size_t usageBeforeRebuild = StormFix_GetCurrentUsage();
        s_origStormHeap_RebuildFreeList(heap);
        size_t usageAfterRebuild = StormFix_GetCurrentUsage();
        g_freedByFreeHook += (usageBeforeRebuild > usageAfterRebuild) ?
            (usageBeforeRebuild - usageAfterRebuild) : 0;
    }
    g_freedByFreeHook += freedByOrig;

    // 修复: 安全的内存优化处理
    bool isFree = StormBlockIsFree(blockHeader);
    if (isFree) {
        size_t blockSize = StormBlockGetTotalSize(blockHeader);
        if (blockSize > 0) {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            size_t pageSize = si.dwPageSize;
            uintptr_t addr = (uintptr_t)blockHeader;

            // 检查页对齐和大小要求
            bool isPageAligned = (addr % pageSize) == 0;
            bool isSizeAligned = (blockSize % pageSize) == 0;
            bool isLargeEnough = blockSize >= (pageSize * 4);  // 至少4页才考虑优化

            if (isPageAligned && isSizeAligned && isLargeEnough) {
                // 修复: 使用MEM_RESET而不是MEM_DECOMMIT
                // MEM_RESET保持虚拟地址映射，只是告诉系统可以丢弃物理内存
                LogMessage("[InternalFree] 使用MEM_RESET优化大块: %p, 大小: %zu",
                    blockHeader, blockSize);

                BOOL bOK = VirtualFree(blockHeader, blockSize, MEM_RESET);
                if (bOK) {
                    SetBlockState(blockHeader, BlockState::Reset, blockSize, "InternalFree");

                    // 统计优化的内存
                    static std::atomic<size_t> s_totalReset{ 0 };
                    s_totalReset += blockSize;

                    if (s_totalReset.load() % (16 * 1024 * 1024) == 0) {  // 每16MB记录一次
                        LogMessage("[优化] 累计MEM_RESET: %zu MB",
                            s_totalReset.load() / (1024 * 1024));
                    }
                }
                else {
                    DWORD error = GetLastError();
                    LogMessage("[InternalFree] MEM_RESET失败: ptr=%p, size=%zu, 错误=%d",
                        blockHeader, blockSize, error);

                    // MEM_RESET失败，尝试保守的方法
                    if (blockSize >= (pageSize * 16)) {  // 只对非常大的块使用DECOMMIT
                        LogMessage("[InternalFree] 尝试保守DECOMMIT: %p", blockHeader);
                        bOK = VirtualFree(blockHeader, blockSize, MEM_DECOMMIT);
                        if (bOK) {
                            SetBlockState(blockHeader, BlockState::Decommitted, blockSize,
                                "InternalFree_Fallback");
                        }
                    }
                }
            }
            else {
                // 不满足对齐要求，记录原因
                //LogMessage("[InternalFree] 跳过内存优化: ptr=%p, size=%zu, "
                //    "页对齐=%s, 大小对齐=%s, 足够大=%s",
                //    blockHeader, blockSize,
                //    isPageAligned ? "是" : "否",
                //    isSizeAligned ? "是" : "否",
                //    isLargeEnough ? "是" : "否");
            }
        }
    }

    return ret;
}

// ============== Hook: StormHeap_Alloc (可选) ==============
void* __fastcall StormHeap_AllocHook(DWORD* pHeap, int a2, int flags, size_t size) {
    // 检查小块池拦截
    if (SmallBlockPool::ShouldIntercept(size)) {
        void* ptr = SmallBlockPool::Allocate(size);
        if (ptr) {
            LogMessage("[SmallBlock] 小块池分配: %p, 大小: %zu", ptr, size);
            return ptr;
        }
        // 小块池分配失败，继续Storm分配
    }

    // 调用原始Storm分配
    void* pUserPtr = s_origStormHeap_Alloc(pHeap, a2, flags, size);
    if (!pUserPtr) {
        return nullptr;
    }

    // 检查是否使用了优化过的内存
    char* blockBase = (char*)pUserPtr - sizeof(StormAllocHeader);
    BlockState state = GetBlockState(blockBase);

    if (state == BlockState::Reset) {
        LogMessage("[StormAlloc] 重用MEM_RESET块: %p, 大小: %zu", pUserPtr, size);
        SetBlockState(blockBase, BlockState::Normal, 0, "StormAlloc_Reuse");
    }
    else if (state == BlockState::Decommitted) {
        // 这种情况不应该发生，因为AllocPage应该已经处理了
        LogMessage("[StormAlloc] 警告: 使用了未恢复的DECOMMIT块: %p", pUserPtr);

        std::shared_lock<std::shared_mutex> lock(g_BlockStatesLock);
        auto it = g_BlockStates.find(blockBase);
        if (it != g_BlockStates.end()) {
            size_t blockSize = it->second.size;
            lock.unlock();

            // 尝试紧急恢复
            LPVOID re = VirtualAlloc(blockBase, blockSize, MEM_COMMIT, PAGE_READWRITE);
            if (re) {
                SetBlockState(blockBase, BlockState::Normal, 0, "StormAlloc_Emergency");
                LogMessage("[StormAlloc] 紧急恢复成功: %p", blockBase);
            }
            else {
                LogMessage("[StormAlloc] 紧急恢复失败: %p", blockBase);
                // 返回NULL，让调用者处理失败
                return nullptr;
            }
        }
    }

    return pUserPtr;
}

//char* __fastcall Hook_StormHeap_CombineFreeBlocks(int a1, unsigned __int16* blockHeader, int* a3, char* a4) {
//    // 先执行原始函数
//    char* result = s_origStormHeap_CombineFreeBlocks(a1, blockHeader, a3, a4);
//
//    // 检查堆状态和碎片化程度
//    DWORD* heap = (DWORD*)a1;
//    if (heap && heap[7] > 0 && heap[8] > 0) {
//        // 计算碎片化率：已分配内存中的空闲比例
//        float fragRatio = (float)heap[8] / (float)heap[7];
//
//        // 超过75%碎片化率时，强制整理
//        if (fragRatio > 0.75f) {
//            s_origStormHeap_RebuildFreeList(heap);
//            LogMessage("[优化] 检测到高碎片化率(%.1f%%)，执行强制内存整理", fragRatio * 100.0f);
//        }
//    }
//
//    return result;
//}

//DWORD* __fastcall Hooked_StormHeap_RebuildFreeList(DWORD* heap) {
//    // 调用原始函数
//    DWORD* result = s_origStormHeap_RebuildFreeList(heap);
//
//    // 检查内存使用量，主动回收未使用的内存池
//    static DWORD lastCleanupTime = 0;
//    DWORD currentTime = GetTickCount();
//
//    if (currentTime - lastCleanupTime > 30000) { // 每30秒
//        lastCleanupTime = currentTime;
//        MemPool::CheckAndFreeUnusedPools();
//    }
//
//    return result;
//}

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
    //DetourAttach(&(PVOID&)s_origStormHeap_CombineFreeBlocks, Hook_StormHeap_CombineFreeBlocks);
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

void CleanupBlockStates() {
    std::unique_lock<std::shared_mutex> lock(g_BlockStatesLock);

    size_t resetCount = 0;
    size_t decommitCount = 0;

    for (const auto& entry : g_BlockStates) {
        if (entry.second.state == BlockState::Reset) resetCount++;
        else if (entry.second.state == BlockState::Decommitted) decommitCount++;
    }

    LogMessage("[清理] 块状态统计: MEM_RESET=%zu, MEM_DECOMMIT=%zu, 总计=%zu",
        resetCount, decommitCount, g_BlockStates.size());

    g_BlockStates.clear();
}