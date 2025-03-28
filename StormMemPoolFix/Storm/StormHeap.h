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
#include "StormHook.h"
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

// 在StormHook.h中
class PageCacheManager {
private:
    struct CachedPage {
        void* address;
        size_t size;
        DWORD timestamp;
        bool isCommitted;
    };

    std::vector<CachedPage> m_pages;
    mutable std::mutex m_mutex;  // 使用mutable允许在const方法中修改
    const size_t m_pageSize;
    const size_t MAX_CACHED_PAGES = 20;

public:
    PageCacheManager() : m_pageSize(GetSystemPageSize()) {}

    size_t GetSystemPageSize() {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return si.dwPageSize;
    }

    bool TryRecommitPage(void* address, size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 检查是否有匹配的已缓存页面
        for (auto it = m_pages.begin(); it != m_pages.end(); ++it) {
            if (it->address == address && it->size >= size && !it->isCommitted) {
                // 重新提交此页面
                if (VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE)) {
                    it->isCommitted = true;
                    it->timestamp = GetTickCount();
                    return true;
                }

                // 提交失败
                m_pages.erase(it);
                return false;
            }
        }

        return false;
    }

    void DecommitPage(void* address, size_t size) {
        // 确保大小和地址都是页对齐的
        if ((size % m_pageSize) != 0 || ((uintptr_t)address % m_pageSize) != 0) {
            return;
        }

        bool decommitSuccess = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);

            // 检查缓存是否已满
            if (m_pages.size() >= MAX_CACHED_PAGES) {
                // 查找最老的已提交页面
                auto oldestIt = std::find_if(m_pages.begin(), m_pages.end(),
                    [](const CachedPage& p) { return p.isCommitted; });

                if (oldestIt != m_pages.end()) {
                    oldestIt = std::min_element(m_pages.begin(), m_pages.end(),
                        [](const CachedPage& a, const CachedPage& b) {
                            // 只比较已提交的页面
                            if (a.isCommitted != b.isCommitted) return a.isCommitted < b.isCommitted;
                            return a.timestamp < b.timestamp;
                        });

                    // 释放最老的页面
                    VirtualFree(oldestIt->address, 0, MEM_DECOMMIT);
                    oldestIt->isCommitted = false;
                }
            }

            // 尝试释放请求的页面
            decommitSuccess = (VirtualFree(address, size, MEM_DECOMMIT) != 0);

            if (decommitSuccess) {
                // 添加到缓存
                m_pages.push_back({
                    address,
                    size,
                    GetTickCount(),
                    false  // 刚刚取消提交
                    });
            }
        }

        if (decommitSuccess) {
            LogMessage("[PageCache] 已取消提交页面: %p, 大小: %zu", address, size);
        }
    }

    void CleanupOldPages(DWORD maxAgeMs = 60000) {
        std::lock_guard<std::mutex> lock(m_mutex);
        DWORD currentTime = GetTickCount();

        // 移除超过一定时间的页面
        auto it = m_pages.begin();
        while (it != m_pages.end()) {
            if (!it->isCommitted && (currentTime - it->timestamp > maxAgeMs)) {
                LogMessage("[PageCache] 移除过时页面缓存: %p, 大小: %zu", it->address, it->size);
                it = m_pages.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    size_t GetCachedPageCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pages.size();
    }
};

// 全局实例
extern PageCacheManager g_pageCache;