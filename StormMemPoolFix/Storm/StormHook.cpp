#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <cstdio>
#include <map>
#include <mutex>
#include <vector>
#include <cstring>
#include <detours.h>
#include <unordered_map>
#include <atomic>
#include "tlsf.h"
#include <algorithm>
// 额外状态变量
static std::atomic<bool> g_afterCleanAll{ false };
static std::atomic<DWORD> g_lastCleanAllTime{ 0 };
static thread_local bool tls_inCleanAll = false;

// 全局变量定义
std::atomic<size_t> g_bigThreshold{ 512 * 1024 };      // 默认512KB为大块阈值
std::mutex g_bigBlocksMutex;
std::unordered_map<void*, BigBlockInfo> g_bigBlocks;
MemoryStats g_memStats;
std::atomic<bool> g_cleanAllInProgress{ false };
DWORD g_cleanAllThreadId = 0;

// Storm原始函数指针
Storm_MemAlloc_t    s_origStormAlloc = nullptr;
Storm_MemFree_t     s_origStormFree = nullptr;
Storm_MemReAlloc_t  s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

// 跟踪统计
size_t g_freedByAllocHook = 0;
size_t g_freedByFreeHook = 0;

// 缓存特殊大块的过滤条件（优化频繁分配的特定模式）
struct SpecialBlockFilter {
    size_t size;
    const char* name;
    int sourceLine;
    bool useCustomPool;
};

static std::vector<SpecialBlockFilter> g_specialFilters = {
    // JassVM分配，使用自定义池管理
    { 0x28A8, "Instance.cpp", 0, true },
    // Storm附近Jass虚拟机相关分配，需要特殊处理
    { 0x64, "jass.cpp", 0, true }
};

// 日志文件句柄
static FILE* g_logFile = nullptr;

///////////////////////////////////////////////////////////////////////////////
// 辅助函数
///////////////////////////////////////////////////////////////////////////////

// 日志函数
void LogMessage(const char* format, ...) {
    if (!g_logFile) {
        if (fopen_s(&g_logFile, "StormHook.log", "a") != 0) {
            return; // 文件打开失败
        }
    }

    va_list args;
    va_start(args, format);

    // 打印时间戳
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // 打印消息
    vfprintf(g_logFile, format, args);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);

    va_end(args);
}

// 设置Storm兼容的内存块头
void SetupCompatibleHeader(void* userPtr, size_t size) {
    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
        static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

    header->HeapPtr = SPECIAL_MARKER;  // 特殊标记
    header->Size = static_cast<DWORD>(size);
    header->AlignPadding = 0;
    header->Flags = 0x4;  // 标记为大块VirtualAlloc
    header->Magic = STORM_MAGIC;
}

// 检查指针是否由我们管理
bool IsOurBlock(void* ptr) {
    if (!ptr) return false;

    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        return (header->Magic == STORM_MAGIC &&
            header->HeapPtr == SPECIAL_MARKER);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 根据名称判断资源类型
ResourceType GetResourceType(const char* name) {
    if (!name) return ResourceType::Unknown;

    if (strstr(name, "Model") || strstr(name, "GEOSET") || strstr(name, "MDX"))
        return ResourceType::Model;
    if (strstr(name, "CUnit") || strstr(name, "Unit"))
        return ResourceType::Unit;
    if (strstr(name, "Terrain") || strstr(name, "Ground"))
        return ResourceType::Terrain;
    if (strstr(name, "Sound") || strstr(name, "SND") || strstr(name, "Audio"))
        return ResourceType::Sound;
    if (strstr(name, "SFile") || strstr(name, "File"))
        return ResourceType::File;
    if (strstr(name, "Instance") || strstr(name, "jass") || strstr(name, "Jass"))
        return ResourceType::JassVM;

    return ResourceType::Unknown;
}

// 检查是否为特殊块分配
bool IsSpecialBlockAllocation(size_t size, const char* name, DWORD src_line) {
    for (const auto& filter : g_specialFilters) {
        if (filter.size == size &&
            (filter.name == nullptr || (name && strstr(name, filter.name))) &&
            (filter.sourceLine == 0 || filter.sourceLine == src_line)) {
            return true;
        }
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// TLSF 内存池实现
///////////////////////////////////////////////////////////////////////////////

// 主内存池大小: 128MB
constexpr size_t TLSF_MAIN_POOL_SIZE = 128 * 1024 * 1024;

namespace MemPool {
    // 内部变量
    static void* g_mainPool = nullptr;
    static tlsf_t g_tlsf = nullptr;
    static std::mutex g_poolMutex;

    // 额外内存池结构
    struct ExtraPool {
        void* memory;
        size_t size;
    };
    static std::vector<ExtraPool> g_extraPools;

    // 检查指针是否在某个池范围内
    bool IsPointerInPool(void* ptr, void* poolStart, size_t poolSize) {
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t poolAddr = reinterpret_cast<uintptr_t>(poolStart);
        return (ptrAddr >= poolAddr && ptrAddr < poolAddr + poolSize);
    }

    // 初始化内存池
    void Initialize(size_t initialSize = TLSF_MAIN_POOL_SIZE) {
        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (g_mainPool) {
            LogMessage("[MemPool] Already initialized");
            return;
        }

        // 分配主内存池
        g_mainPool = VirtualAlloc(NULL, initialSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!g_mainPool) {
            LogMessage("[MemPool] Failed to allocate main pool of size %zu", initialSize);
            return;
        }

        // 初始化TLSF
        g_tlsf = tlsf_create_with_pool(g_mainPool, initialSize);

        if (!g_tlsf) {
            LogMessage("[MemPool] Failed to create TLSF instance");
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
            return;
        }

        LogMessage("[MemPool] Initialized with %zu bytes at %p", initialSize, g_mainPool);
    }

    // 清理资源
    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (g_tlsf) {
            // TLSF本身不需要特别的销毁步骤
            g_tlsf = nullptr;
        }

        // 释放所有额外池
        for (const auto& pool : g_extraPools) {
            if (pool.memory) {
                VirtualFree(pool.memory, 0, MEM_RELEASE);
            }
        }
        g_extraPools.clear();

        // 释放主池
        if (g_mainPool) {
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
        }

        LogMessage("[MemPool] Shutdown complete");
    }

    // 添加额外内存池
    bool AddExtraPool(size_t size) {
        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (!g_tlsf) {
            LogMessage("[MemPool] TLSF not initialized");
            return false;
        }

        // 分配新池
        void* newPool = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newPool) {
            LogMessage("[MemPool] Failed to allocate extra pool of size %zu", size);
            return false;
        }

        // 添加到TLSF
        pool_t pool = tlsf_add_pool(g_tlsf, newPool, size);
        if (!pool) {
            LogMessage("[MemPool] Failed to add pool to TLSF");
            VirtualFree(newPool, 0, MEM_RELEASE);
            return false;
        }

        // 记录池信息
        ExtraPool extraPool = { newPool, size };
        g_extraPools.push_back(extraPool);

        LogMessage("[MemPool] Added extra pool of size %zu at %p", size, newPool);
        return true;
    }

    // 分配内存
    void* Allocate(size_t size) {
        if (!g_tlsf) {
            // 懒初始化
            Initialize();
            if (!g_tlsf) return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        void* ptr = tlsf_malloc(g_tlsf, size);
        if (!ptr) {
            // 尝试扩展池
            size_t extraSize = size < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : size * 2;
            LogMessage("[MemPool] Allocate failed for %zu bytes, expanding pool by %zu bytes",
                size, extraSize);

            if (AddExtraPool(extraSize)) {
                ptr = tlsf_malloc(g_tlsf, size);
            }
        }

        return ptr;
    }

    // 释放内存
    void Free(void* ptr) {
        if (!g_tlsf || !ptr) return;

        std::lock_guard<std::mutex> lock(g_poolMutex);

        // 确保指针来自我们的池
        if (IsFromPool(ptr)) {
            tlsf_free(g_tlsf, ptr);
        }
        else {
            LogMessage("[MemPool] WARNING: Tried to free pointer %p not from our pools", ptr);
        }
    }

    // 重新分配内存
    void* Realloc(void* oldPtr, size_t newSize) {
        if (!g_tlsf) return nullptr;
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        // 确保旧指针来自我们的池
        if (!IsFromPool(oldPtr)) {
            LogMessage("[MemPool] WARNING: Tried to realloc pointer %p not from our pools", oldPtr);
            return nullptr;
        }

        void* newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
        if (!newPtr) {
            // 尝试扩展池
            size_t extraSize = newSize < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : newSize * 2;
            LogMessage("[MemPool] Realloc failed for %zu bytes, expanding pool by %zu bytes",
                newSize, extraSize);

            if (AddExtraPool(extraSize)) {
                newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
            }
        }

        return newPtr;
    }

    // 检查内存池状态
    struct PoolUsageStats {
        size_t used = 0;
        size_t total = 0;
    };

    static void GatherUsageCallback(void* /*ptr*/, size_t size, int used, void* user) {
        PoolUsageStats* stats = static_cast<PoolUsageStats*>(user);
        stats->total += size;
        if (used) stats->used += size;
    }

    // 检查指针是否来自我们的池
    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        // 检查主池
        if (IsPointerInPool(ptr, g_mainPool, TLSF_MAIN_POOL_SIZE)) {
            return true;
        }

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            if (IsPointerInPool(ptr, pool.memory, pool.size)) {
                return true;
            }
        }

        return false;
    }

    // 获取已使用大小
    size_t GetUsedSize() {
        if (!g_tlsf) return 0;

        std::lock_guard<std::mutex> lock(g_poolMutex);

        PoolUsageStats stats;

        // 检查主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        tlsf_walk_pool(mainPool, GatherUsageCallback, &stats);

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            PoolUsageStats poolStats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &poolStats);
            stats.used += poolStats.used;
            stats.total += poolStats.total;
        }

        return stats.used;
    }

    // 获取总大小
    size_t GetTotalSize() {
        if (!g_tlsf) return 0;

        std::lock_guard<std::mutex> lock(g_poolMutex);

        size_t total = TLSF_MAIN_POOL_SIZE;
        for (const auto& pool : g_extraPools) {
            total += pool.size;
        }

        return total;
    }

    // 打印统计信息
    void PrintStats() {
        if (!g_tlsf) {
            LogMessage("[MemPool] Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        LogMessage("[MemPool] === Memory Pool Statistics ===");

        // 主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        PoolUsageStats mainStats;
        tlsf_walk_pool(mainPool, GatherUsageCallback, &mainStats);

        LogMessage("[MemPool] Main pool: %zu KB used / %zu KB total (%.1f%%)",
            mainStats.used / 1024, mainStats.total / 1024,
            mainStats.total > 0 ? (mainStats.used * 100.0 / mainStats.total) : 0);

        // 额外池
        size_t totalExtra = 0;
        size_t usedExtra = 0;

        for (size_t i = 0; i < g_extraPools.size(); i++) {
            const auto& pool = g_extraPools[i];
            PoolUsageStats stats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &stats);

            LogMessage("[MemPool] Extra pool #%zu: %zu KB used / %zu KB total (%.1f%%)",
                i + 1, stats.used / 1024, stats.total / 1024,
                stats.total > 0 ? (stats.used * 100.0 / stats.total) : 0);

            totalExtra += pool.size;
            usedExtra += stats.used;
        }

        LogMessage("[MemPool] Extra pools: %zu pools, %zu KB total",
            g_extraPools.size(), totalExtra / 1024);

        // 总计
        size_t totalSize = TLSF_MAIN_POOL_SIZE + totalExtra;
        size_t totalUsed = mainStats.used + usedExtra;

        LogMessage("[MemPool] Total: %zu KB used / %zu KB allocated (%.1f%%)",
            totalUsed / 1024, totalSize / 1024,
            totalSize > 0 ? (totalUsed * 100.0 / totalSize) : 0);
    }

    // 检查并释放空闲的扩展池
    void CheckAndFreeUnusedPools() {
        if (!g_tlsf) return;

        std::lock_guard<std::mutex> lock(g_poolMutex);
        bool poolsFreed = false;

        // 从后向前扫描，释放完全空闲的扩展池
        for (auto it = g_extraPools.rbegin(); it != g_extraPools.rend(); ) {
            PoolUsageStats stats;
            tlsf_walk_pool(it->memory, GatherUsageCallback, &stats);

            if (stats.used == 0) {
                // 这个池完全空闲，可以释放
                LogMessage("[MemPool] Freeing unused extra pool at %p (size: %zu bytes)",
                    it->memory, it->size);

                // 从TLSF中移除
                tlsf_remove_pool(g_tlsf, it->memory);

                // 释放内存
                VirtualFree(it->memory, 0, MEM_RELEASE);

                // 从列表中移除(注意反向迭代器的特殊处理)
                auto normalIt = std::next(it).base();
                normalIt = g_extraPools.erase(normalIt);
                it = std::reverse_iterator<decltype(normalIt)>(normalIt);

                poolsFreed = true;
            }
            else {
                ++it;
            }
        }

        if (poolsFreed) {
            LogMessage("[MemPool] After cleanup: %zu extra pools remain", g_extraPools.size());
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// 统计信息线程
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI MemoryStatsThread(LPVOID) {
    LogMessage("[StatsThread] Memory monitoring thread started");

    DWORD lastCleanupTime = GetTickCount();
    DWORD lastStatsTime = GetTickCount();

    while (true) {
        Sleep(5000);  // 每5秒检查一次

        DWORD currentTime = GetTickCount();

        // 每30秒尝试释放未使用的扩展池
        if (currentTime - lastCleanupTime > 30000) {
            if (!g_cleanAllInProgress) {
                MemPool::CheckAndFreeUnusedPools();
            }
            lastCleanupTime = currentTime;
        }

        // 每分钟打印一次内存统计
        if (currentTime - lastStatsTime > 60000) {
            LogMessage("\n[Memory Status] ---- %u seconds since last report ----",
                (currentTime - lastStatsTime) / 1000);

            // 总体统计
            size_t allocTotal = g_memStats.totalAllocated.load();
            size_t freeTotal = g_memStats.totalFreed.load();

            LogMessage("[Memory Status] Total Tracked: Allocated=%zu MB, Freed=%zu MB, InUse=%zu MB",
                allocTotal / (1024 * 1024), freeTotal / (1024 * 1024),
                (allocTotal > freeTotal) ? (allocTotal - freeTotal) / (1024 * 1024) : 0);

            // Storm内部统计
            LogMessage("[Memory Status] Storm_TotalAllocatedMemory=%zu MB",
                Storm_g_TotalAllocatedMemory / (1024 * 1024));

            // 大块跟踪统计
            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                LogMessage("[Memory Status] TLSF-managed blocks: count=%zu", g_bigBlocks.size());

                // 按类型统计
                std::map<ResourceType, size_t> typeCount;
                std::map<ResourceType, size_t> typeSize;

                for (const auto& entry : g_bigBlocks) {
                    typeCount[entry.second.type]++;
                    typeSize[entry.second.type] += entry.second.size;
                }

                // 打印资源类型分布
                LogMessage("[Memory Status] Resource type distribution:");
                for (const auto& entry : typeCount) {
                    const char* typeName = "Unknown";
                    switch (entry.first) {
                    case ResourceType::Model: typeName = "Model"; break;
                    case ResourceType::Unit: typeName = "Unit"; break;
                    case ResourceType::Terrain: typeName = "Terrain"; break;
                    case ResourceType::Sound: typeName = "Sound"; break;
                    case ResourceType::File: typeName = "File"; break;
                    case ResourceType::JassVM: typeName = "JassVM"; break;
                    default: break;
                    }

                    LogMessage("  - %s: %zu blocks, %zu MB",
                        typeName, entry.second, typeSize[entry.first] / (1024 * 1024));
                }
            }

            // 内存池使用情况
            MemPool::PrintStats();

            lastStatsTime = currentTime;
        }
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// 钩子函数实现
///////////////////////////////////////////////////////////////////////////////

void Hooked_StormHeap_CleanupAll() {
    // 防止递归调用
    if (tls_inCleanAll) {
        LogMessage("[CleanAll] 递归调用被阻止");
        return;
    }

    // 时间节流 - 避免频繁CleanAll
    DWORD currentTime = GetTickCount();
    DWORD lastTime = g_lastCleanAllTime.load();
    if (currentTime - lastTime < 1000) { // 1秒内不重复执行
        LogMessage("[CleanAll] 触发过于频繁，已跳过");
        return;
    }

    tls_inCleanAll = true;
    g_cleanAllInProgress = true;
    g_lastCleanAllTime.store(currentTime);

    LogMessage("[CleanAll] 开始执行");

    // 保存原始的g_DebugHeapPtr值
    int originalDebugHeapPtr = Storm_g_DebugHeapPtr;

    // 执行原始CleanupAll
    s_origCleanupAll();

    // *** 关键修复点：重置Storm内部状态 ***
    // 将g_DebugHeapPtr重置为0，防止Storm再次触发CleanAll
    Storm_g_DebugHeapPtr = 0;

    // 标记CleanAll后的状态
    g_afterCleanAll = true;
    g_cleanAllInProgress = false;
    tls_inCleanAll = false;

    LogMessage("[CleanAll] 完成，已重置内部状态");
}

// Hook: SMemAlloc - 处理大块分配
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag) {
    // 检查是否在CleanAll后的第一次分配
    bool isAfterCleanAll = g_afterCleanAll.exchange(false);

    // CleanAll后的关键分配，需要特殊处理
    if (isAfterCleanAll) {
        // 直接使用Storm分配一个小块，防止Storm触发新的CleanAll
        void* smallBlock = (void*)s_origStormAlloc(ecx, edx, 16, "HookStabilizer", __LINE__, 0);
        if (smallBlock) {
            LogMessage("[StabilizerBlock] 分配成功: %p", smallBlock);
            // 故意不释放这个小块，保持Storm堆状态稳定
        }
    }
    // 在CleanAll过程中，直接使用原始分配
    if (g_cleanAllInProgress && GetCurrentThreadId() == g_cleanAllThreadId) {
        //LogMessage("[Alloc][CleanAll] Passing through: size=%zu, name=%s", size, name ? name : "(null)");
        return s_origStormAlloc(ecx, edx, size, name, src_line, flag);
    }

    // 检查特殊分配模式
    bool isSpecial = IsSpecialBlockAllocation(size, name, src_line);

    // 分配策略：特殊块或大块使用TLSF，小块使用Storm
    bool useTLSF = isSpecial || (size >= g_bigThreshold.load());

    if (useTLSF) {
        // 使用TLSF分配
        size_t totalSize = size + sizeof(StormAllocHeader);
        void* rawPtr = MemPool::Allocate(totalSize);

        if (!rawPtr) {
            LogMessage("[Alloc] TLSF allocation failed for %zu bytes, falling back to Storm", size);
            return s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        }

        // 设置用户指针和兼容头
        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        // 记录此块信息
        BigBlockInfo info;
        info.rawPtr = rawPtr;
        info.size = size;
        info.timestamp = GetTickCount();
        info.source = name ? _strdup(name) : nullptr;
        info.srcLine = src_line;
        info.type = GetResourceType(name);

        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
            g_bigBlocks[userPtr] = info;
        }

        g_memStats.OnAlloc(size);

        //LogMessage("[Alloc] TLSF allocated: ptr=%p, size=%zu, name=%s", userPtr, size, name ? name : "(null)");
        return reinterpret_cast<size_t>(userPtr);
    }
    else {
        // 小块使用Storm原始分配
        size_t ret = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        if (ret) {
            g_memStats.OnAlloc(size);
        }
        return ret;
    }
}

// Hook: SMemFree - 处理释放
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    if (!a1) return 1;  // 空指针认为成功

    void* ptr = reinterpret_cast<void*>(a1);

    // 在CleanAll过程中特殊处理
    if (g_cleanAllInProgress && GetCurrentThreadId() == g_cleanAllThreadId) {
        // 如果是我们的块，不让Storm处理它
        if (IsOurBlock(ptr)) {
            //LogMessage("[Free][CleanAll] Skipping our block: %p", ptr);
            g_freedByAllocHook++;
            return 1;  // 返回成功
        }
        return s_origStormFree(a1, name, argList, a4);
    }

    // 常规释放流程
    if (IsOurBlock(ptr)) {
        //LogMessage("[Free] Freeing our block: %p", ptr);

        std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
        auto it = g_bigBlocks.find(ptr);

        if (it != g_bigBlocks.end()) {
            g_memStats.OnFree(it->second.size);

            // 释放名称字符串
            if (it->second.source) {
                free((void*)it->second.source);
            }

            // 释放实际内存
            MemPool::Free(it->second.rawPtr);

            // 从映射中移除
            g_bigBlocks.erase(it);

            g_freedByFreeHook++;
            return 1;  // 返回成功
        }
        else {
            LogMessage("[Free] WARNING: Our block not found in registry: %p", ptr);

            // 仍然尝试释放，但这是一个异常情况
            void* rawPtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
            MemPool::Free(rawPtr);
            g_freedByFreeHook++;
            return 1;
        }
    }
    else {
        // 不是我们的块，使用Storm释放
        return s_origStormFree(a1, name, argList, a4);
    }
}

// Hook: SMemReAlloc - 处理重分配
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag) {
    // 边界情况处理
    if (!oldPtr) {
        return reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        return nullptr;
    }

    // 在CleanAll过程中特殊处理
    if (g_cleanAllInProgress && GetCurrentThreadId() == g_cleanAllThreadId) {
        // 如果是我们的块，不让Storm处理它
        if (IsOurBlock(oldPtr)) {
            LogMessage("[Realloc][CleanAll] Handling our block: %p, new size=%zu", oldPtr, newSize);

            // 在CleanAll期间，我们应该避免修改g_bigBlocks
            // 最安全的做法是分配新块但不释放旧块

            // 分配新块
            size_t totalSize = newSize + sizeof(StormAllocHeader);
            void* newRawPtr = MemPool::Allocate(totalSize);

            if (!newRawPtr) {
                LogMessage("[Realloc][CleanAll] Failed to allocate new block");
                return nullptr;
            }

            void* newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newUserPtr, newSize);

            // 复制数据
            // 尝试获取旧块大小
            StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

            size_t copySize = std::min<size_t>(oldHeader->Size, newSize);
            memcpy(newUserPtr, oldPtr, copySize);

            // 在CleanAll期间不更新g_bigBlocks

            return newUserPtr;
        }
        return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
    }

    // 常规重分配流程
    bool isOurOldBlock = IsOurBlock(oldPtr);
    bool shouldUseTLSF = (newSize >= g_bigThreshold.load()) ||
        IsSpecialBlockAllocation(newSize, name, src_line);

    if (isOurOldBlock) {
        // 旧块是我们管理的
        std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
        auto it = g_bigBlocks.find(oldPtr);

        if (it != g_bigBlocks.end()) {
            size_t oldSize = it->second.size;

            if (shouldUseTLSF) {
                // 新块也是大块，直接在TLSF中重分配
                //LogMessage("[Realloc] TLSF realloc: %zu -> %zu", oldSize, newSize);

                void* newRawPtr = MemPool::Realloc(it->second.rawPtr, newSize + sizeof(StormAllocHeader));

                if (!newRawPtr) {
                    LogMessage("[Realloc] TLSF realloc failed");
                    return nullptr;
                }

                void* newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
                SetupCompatibleHeader(newUserPtr, newSize);

                // 更新记录
                if (newUserPtr != oldPtr) {
                    // 指针改变，更新映射
                    BigBlockInfo newInfo = it->second;
                    newInfo.rawPtr = newRawPtr;
                    newInfo.size = newSize;

                    g_bigBlocks.erase(it);
                    g_bigBlocks[newUserPtr] = newInfo;
                }
                else {
                    // 指针未变，只更新大小
                    it->second.size = newSize;
                }

                g_memStats.OnFree(oldSize);
                g_memStats.OnAlloc(newSize);

                return newUserPtr;
            }
            else {
                // 新块变小，转为Storm管理
                //LogMessage("[Realloc] TLSF -> Storm: %zu -> %zu", oldSize, newSize);

                // 使用Storm分配新块
                void* newPtr = reinterpret_cast<void*>(s_origStormAlloc(ecx, edx, newSize, name, src_line, flag));

                if (!newPtr) {
                    LogMessage("[Realloc] Storm alloc failed");
                    return nullptr;
                }

                // 复制数据
                memcpy(newPtr, oldPtr, min(oldSize, newSize));

                // 释放旧TLSF块
                if (it->second.source) {
                    free((void*)it->second.source);
                }
                MemPool::Free(it->second.rawPtr);
                g_bigBlocks.erase(it);

                g_memStats.OnFree(oldSize);
                g_memStats.OnAlloc(newSize);

                return newPtr;
            }
        }
        else {
            LogMessage("[Realloc] WARNING: Our block not found in registry: %p", oldPtr);
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }
    }
    else {
        // 旧块是Storm管理的
        if (shouldUseTLSF) {
            // 新块是大块，转为TLSF管理
            //LogMessage("[Realloc] Storm -> TLSF: ptr=%p, new size=%zu", oldPtr, newSize);

            // 分配新的TLSF块
            size_t totalSize = newSize + sizeof(StormAllocHeader);
            void* newRawPtr = MemPool::Allocate(totalSize);

            if (!newRawPtr) {
                LogMessage("[Realloc] TLSF alloc failed, falling back to Storm");
                return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            }

            void* newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newUserPtr, newSize);

            // 尝试获取旧块大小并复制数据
            size_t oldSize = 0;
            try {
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                if (oldHeader->Magic == STORM_MAGIC) {
                    oldSize = oldHeader->Size;
                }
            }
            catch (...) {
                oldSize = newSize; // 无法获取大小，假设相同
            }

            size_t copySize = min(oldSize, newSize);
            memcpy(newUserPtr, oldPtr, copySize);

            // 释放Storm旧块
            s_origStormFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);

            // 记录新块
            BigBlockInfo info;
            info.rawPtr = newRawPtr;
            info.size = newSize;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : nullptr;
            info.srcLine = src_line;
            info.type = GetResourceType(name);

            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                g_bigBlocks[newUserPtr] = info;
            }

            g_memStats.OnAlloc(newSize);

            return newUserPtr;
        }
        else {
            // 新块也是小块，使用Storm
            void* result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            if (result) {
                g_memStats.OnAlloc(newSize);
            }
            return result;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// 钩子安装和初始化
///////////////////////////////////////////////////////////////////////////////

bool InitializeStormMemoryHooks() {
    // 查找Storm.dll基址
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        LogMessage("[Init] Failed to find Storm.dll module");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[Init] Found Storm.dll at base address: 0x%08X", gStormDllBase);

    // 初始化原始函数指针
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);

    LogMessage("[Init] Storm functions: Alloc=%p, Free=%p, Realloc=%p, CleanupAll=%p",
        s_origStormAlloc, s_origStormFree, s_origStormReAlloc, s_origCleanupAll);

    // 验证函数指针
    if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
        LogMessage("[Init] Failed to locate Storm memory functions");
        return false;
    }

    // 初始化TLSF内存池
    MemPool::Initialize(TLSF_MAIN_POOL_SIZE);

    // 安装钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LogMessage("[Init] Failed to install hooks, error: %ld", result);
        return false;
    }

    // 启动统计线程
    HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    void* stabilizer = (void*)s_origStormAlloc(0, 0, 32, "InitialStabilizer", __LINE__, 0);
    if (stabilizer) {
        LogMessage("[Init] 稳定块分配成功: %p", stabilizer);
    }

    // 重置Storm的g_DebugHeapPtr，防止初始CleanAll触发
    Storm_g_DebugHeapPtr = 0;

    LogMessage("[Init] Storm memory hooks installed successfully!");
    return true;
}

void ShutdownStormMemoryHooks() {
    LogMessage("[Shutdown] Removing Storm memory hooks...");

    // 卸载钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (s_origStormAlloc) DetourDetach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    if (s_origStormFree) DetourDetach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    if (s_origStormReAlloc) DetourDetach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    if (s_origCleanupAll) DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    DetourTransactionCommit();

    // 释放所有大块
    {
        std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
        LogMessage("[Shutdown] Freeing %zu tracked blocks", g_bigBlocks.size());

        for (auto& entry : g_bigBlocks) {
            if (entry.second.source) free((void*)entry.second.source);
            if (entry.second.rawPtr) MemPool::Free(entry.second.rawPtr);
        }

        g_bigBlocks.clear();
    }

    // 清理TLSF内存池
    MemPool::Shutdown();

    // 关闭日志
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = nullptr;
    }

    LogMessage("[Shutdown] Storm memory hooks removed");
}