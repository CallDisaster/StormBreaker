#pragma once
#include "pch.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <cstddef>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include <psapi.h>  // 添加这个头文件
#include <queue>
#include <algorithm>
#include <Base/MemPool/MemoryPoolManager.h>

#pragma comment(lib, "psapi.lib")

// Storm结构体定义
#pragma pack(push, 1)
struct StormAllocHeader {
    DWORD HeapPtr;      // 指向所属堆结构
    DWORD Size;         // 用户数据区大小
    BYTE  AlignPadding; // 对齐填充字节数
    BYTE  Flags;        // 标志位: 0x1=魔数校验, 0x2=已释放, 0x4=大块VirtualAlloc, 0x8=特殊指针
    WORD  Magic;        // 魔数 (0x6F6D)
};
#pragma pack(pop)

// 资源类型枚举（用于统计和泄漏分析）
enum class ResourceType {
    Unknown,
    Model,
    Unit,
    Terrain,
    Sound,
    File,
    JassVM,
    Font,    // 添加 Font 类型
    UI,      // 添加 UI 类型
    MaxType  // 用于标记枚举大小
};

// 大块内存信息结构
struct BigBlockInfo {
    void* rawPtr;      // 实际内存起始地址
    size_t size;        // 用户请求的大小
    DWORD  timestamp;   // 分配时间戳
    const char* source; // 分配来源
    DWORD  srcLine;     // 源代码行号
    ResourceType type;  // 资源类型
};

// 缓存特殊大块的过滤条件（优化频繁分配的特定模式）
struct SpecialBlockFilter {
    size_t size;           // 块大小，0表示匹配任意大小
    const char* name;      // 源名称子串匹配
    int sourceLine;        // 源代码行，0表示匹配任意行
    bool useCustomPool;    // 是否使用自定义内存池
    bool forceSystemAlloc; // 强制使用系统分配VirtualAlloc

    // 显式构造函数
    SpecialBlockFilter(size_t s, const char* n, int sl, bool ucp, bool fsa)
        : size(s), name(n), sourceLine(sl), useCustomPool(ucp) , forceSystemAlloc(fsa){
    }
};

// 内存统计结构
struct MemoryStats {
    std::atomic<size_t> totalAllocated{ 0 };
    std::atomic<size_t> totalFreed{ 0 };

    void OnAlloc(size_t size) {
        totalAllocated += size;
    }

    void OnFree(size_t size) {
        totalFreed += size;
    }
};

// Storm函数类型定义
typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();

// 常量定义
constexpr DWORD STORM_MAGIC = 0x6F6D;        // Storm块头魔数 "mo"
constexpr DWORD SPECIAL_MARKER = 0xC0DEFEED; // 特殊标记，表明是我们管理的块

// 全局变量声明
extern std::atomic<size_t> g_bigThreshold;      // 大块阈值
extern std::mutex g_bigBlocksMutex;
extern std::unordered_map<void*, BigBlockInfo> g_bigBlocks;
extern MemoryStats g_memStats;
extern Storm_MemAlloc_t s_origStormAlloc;
extern Storm_MemFree_t s_origStormFree;
extern Storm_MemReAlloc_t s_origStormReAlloc;
extern StormHeap_CleanupAll_t s_origCleanupAll;
extern std::atomic<bool> g_cleanAllInProgress;  // 是否正在进行CleanAll
extern std::atomic<bool> g_afterCleanAll;   // 是否正在进行CleanAll
extern std::atomic<DWORD> g_lastCleanAllTime;
extern thread_local bool tls_inCleanAll;
extern std::atomic<bool> g_insideUnsafePeriod; // 新增：标记不安全时期
extern DWORD g_cleanAllThreadId;
extern std::atomic<bool> g_disableMemoryReleasing;
// 分片锁数量
constexpr size_t LOCK_SHARDS = 64;

// 为MemPool分配操作提供的分片锁
extern std::mutex g_poolMutexes[LOCK_SHARDS];

// 锁等待时间统计
extern std::atomic<size_t> g_totalLockWaitTime;
extern std::atomic<size_t> g_lockWaitCount;

// 工作集内存监控相关
extern std::atomic<size_t> g_workingSetThreshold;  // 工作集清理阈值
extern std::atomic<DWORD> g_lastWorkingSetCleanTime;  // 上次清理时间
extern std::atomic<size_t> g_peakWorkingSetSize;  // 峰值工作集大小

// 获取进程工作集内存大小
size_t GetProcessWorkingSetSize();
// 主动清理工作集内存
bool TrimWorkingSet(bool aggressive = false);
// 检查并清理工作集内存(如果超过阈值)
bool CheckAndTrimWorkingSet();

// 函数声明
bool InitializeStormMemoryHooks(PoolType poolType);
bool HookAllStormHeapFunctions();
void ShutdownStormMemoryHooks();
void LogMessage(const char* format, ...);
void SetupCompatibleHeader(void* userPtr, size_t size);
bool IsOurBlock(void* ptr);
void PrintAllPoolsUsage();
void CreateStabilizingBlocks(int cleanAllCount);
bool IsSpecialBlockAllocation(size_t size, const char* name, DWORD src_line);   // 检查是否为特殊块分配，size为0表示匹配任意大小
bool IsPermanentBlock(void* ptr);
ResourceType GetResourceType(const char* name, size_t size);    // 从资源名称和大小检测资源类型
bool InitializeStormMemoryHooks(PoolType poolType = PoolType::MiMalloc); // 默认使用mimalloc
bool SwitchMemoryPoolType(PoolType newType); // 切换内存池类型
PoolType GetCurrentMemoryPoolType();    // 获取当前内存池类型

// Hook函数声明
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag);
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4);
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD src_line, DWORD flag);
void Hooked_StormHeap_CleanupAll();

// TLSF内存池封装
namespace MemPool {
    bool Initialize(size_t initialSize);
    void Shutdown();
    void* Allocate(size_t size);
    void Free(void* ptr);
    void* Realloc(void* oldPtr, size_t newSize);
    size_t GetUsedSize();
    size_t GetTotalSize();
    void PrintStats();
    bool IsFromPool(void* ptr);
    void* AllocateSafe(size_t size);
    void FreeSafe(void* ptr);
    void* ReallocSafe(void* oldPtr, size_t newSize);
}

// 定义临时稳定块结构
struct TempStabilizerBlock {
    void* ptr;
    size_t size;
    DWORD createTime;
    int ttl;  // 生存周期，按 CleanAll 计数
};

// 在StormHook.h中
class ImprovedLargeBlockCache {
private:
    struct CachedBlock {
        void* ptr;
        size_t size;
        DWORD timestamp;
    };

    // 按大小范围分组的缓存
    struct SizeGroup {
        size_t minSize;
        size_t maxSize;
        size_t maxCacheCount;
        std::vector<CachedBlock> blocks;
    };

    std::vector<SizeGroup> m_groups;
    mutable std::mutex m_mutex;

public:
    ImprovedLargeBlockCache() {
        // 创建不同大小范围的组
        m_groups = {
            { 16 * 1024,   64 * 1024,  20 }, // 16KB-64KB, 最多缓存20个
            { 64 * 1024,  256 * 1024,  15 }, // 64KB-256KB, 最多缓存15个
            { 256 * 1024,    1 * 1024 * 1024, 10 }, // 256KB-1MB, 最多缓存10个
            { 1 * 1024 * 1024, 4 * 1024 * 1024,  5 }  // 1MB-4MB, 最多缓存5个
        };
    }

    void* GetBlock(size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 找到对应的大小组
        for (auto& group : m_groups) {
            if (size >= group.minSize && size <= group.maxSize) {
                // 在此组中寻找合适的块
                auto bestFit = group.blocks.end();
                size_t minExcess = SIZE_MAX;

                for (auto it = group.blocks.begin(); it != group.blocks.end(); ++it) {
                    if (it->size >= size) {
                        size_t excess = it->size - size;
                        if (excess < minExcess) {
                            minExcess = excess;
                            bestFit = it;
                        }
                    }
                }

                if (bestFit != group.blocks.end()) {
                    void* ptr = bestFit->ptr;
                    group.blocks.erase(bestFit);
                    return ptr;
                }
            }
        }

        return nullptr;
    }

    void ReleaseBlock(void* ptr, size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 找到对应的大小组
        for (auto& group : m_groups) {
            if (size >= group.minSize && size <= group.maxSize) {
                // 检查是否已达到此组的缓存上限
                if (group.blocks.size() >= group.maxCacheCount) {
                    // 查找最老的块释放
                    auto oldest = std::min_element(group.blocks.begin(), group.blocks.end(),
                        [](const auto& a, const auto& b) { return a.timestamp < b.timestamp; });

                    if (oldest != group.blocks.end()) {
                        VirtualFree(oldest->ptr, 0, MEM_RELEASE);
                        group.blocks.erase(oldest);
                    }
                }

                // 添加新块到缓存
                group.blocks.push_back({ ptr, size, GetTickCount() });
                return;
            }
        }

        // 大小超出所有组范围，直接释放
        VirtualFree(ptr, 0, MEM_RELEASE);
    }

    size_t GetCacheSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t total = 0;
        for (const auto& group : m_groups) {
            total += group.blocks.size();
        }
        return total;
    }
};

extern ImprovedLargeBlockCache g_largeBlockCache;

class DetailedAllocProfiler {
private:
    struct SizeStats {
        size_t allocCount;       // 分配次数
        size_t totalSize;        // 总分配大小
        size_t currentCount;     // 当前活跃数量
        size_t peakCount;        // 峰值数量
        DWORD firstAllocTime;    // 首次分配时间
        DWORD lastAllocTime;     // 最近分配时间
        std::unordered_map<std::string, size_t> sourceCount; // 按源文件统计
    };

    std::mutex m_mutex;
    std::unordered_map<size_t, SizeStats> m_stats;          // 按大小统计
    std::unordered_map<ResourceType, SizeStats> m_typeStats; // 按类型统计

public:
    void RecordAllocation(size_t size, const char* source, ResourceType type) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 更新大小统计
        auto& stats = m_stats[size];
        stats.allocCount++;
        stats.totalSize += size;
        stats.currentCount++;
        stats.peakCount = max(stats.peakCount, stats.currentCount);
        stats.lastAllocTime = GetTickCount();
        if (stats.firstAllocTime == 0) stats.firstAllocTime = stats.lastAllocTime;

        // 更新源文件统计
        if (source) {
            stats.sourceCount[source]++;
        }

        // 更新类型统计
        auto& typeStats = m_typeStats[type];
        typeStats.allocCount++;
        typeStats.totalSize += size;
        typeStats.currentCount++;
        typeStats.peakCount = max(typeStats.peakCount, typeStats.currentCount);
        typeStats.lastAllocTime = GetTickCount();
        if (typeStats.firstAllocTime == 0) typeStats.firstAllocTime = typeStats.lastAllocTime;
    }

    void RecordFree(size_t size, ResourceType type) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 更新大小统计
        auto it = m_stats.find(size);
        if (it != m_stats.end() && it->second.currentCount > 0) {
            it->second.currentCount--;
        }

        // 更新类型统计
        auto typeIt = m_typeStats.find(type);
        if (typeIt != m_typeStats.end() && typeIt->second.currentCount > 0) {
            typeIt->second.currentCount--;
        }
    }

    void PrintStats() {
        std::lock_guard<std::mutex> lock(m_mutex);

        LogMessage("====== 详细内存分配统计 ======");

        // 打印最常见的10种大小
        LogMessage("--- 最常见的内存块大小 ---");
        std::vector<std::pair<size_t, SizeStats>> sizeEntries;
        for (const auto& entry : m_stats) {
            sizeEntries.push_back(entry);
        }

        std::sort(sizeEntries.begin(), sizeEntries.end(),
            [](const auto& a, const auto& b) { return a.second.allocCount > b.second.allocCount; });

        for (size_t i = 0; i < min(sizeEntries.size(), (size_t)10); i++) {
            const auto& entry = sizeEntries[i];
            LogMessage("大小: %zu 字节, 分配: %zu 次, 当前活跃: %zu, 峰值: %zu, 总内存: %.2f MB",
                entry.first, entry.second.allocCount, entry.second.currentCount,
                entry.second.peakCount, entry.second.totalSize / (1024.0 * 1024.0));
        }

        // 按类型打印统计
        LogMessage("--- 按资源类型统计 ---");
        for (const auto& entry : m_typeStats) {
            const char* typeName = "未知";
            switch (entry.first) {
            case ResourceType::Model: typeName = "模型"; break;
            case ResourceType::Unit: typeName = "单位"; break;
            case ResourceType::Terrain: typeName = "地形"; break;
            case ResourceType::Sound: typeName = "声音"; break;
            case ResourceType::File: typeName = "文件"; break;
            case ResourceType::JassVM: typeName = "JassVM"; break;
            default: break;
            }

            LogMessage("类型: %s, 分配: %zu 次, 当前活跃: %zu, 峰值: %zu, 总内存: %.2f MB",
                typeName, entry.second.allocCount, entry.second.currentCount,
                entry.second.peakCount, entry.second.totalSize / (1024.0 * 1024.0));
        }

        LogMessage("==============================");
    }
};


//class JitCompiledFunctions {
//private:
//    // JIT编译后的函数指针类型
//    typedef void* (*AllocFuncType)(size_t size);
//    typedef void (*FreeFuncType)(void* ptr);
//
//    // 编译后的函数指针
//    AllocFuncType m_fastAllocFunc;
//    FreeFuncType m_fastFreeFunc;
//
//    // JIT编译器状态
//    void* m_jitState;
//    bool m_isInitialized;
//
//public:
//    JitCompiledFunctions() : m_fastAllocFunc(nullptr), m_fastFreeFunc(nullptr),
//        m_jitState(nullptr), m_isInitialized(false) {
//    }
//
//    bool Initialize() {
//        if (m_isInitialized) return true;
//
//        // 初始化JIT编译器
//        // 这里需要使用如AsmJit等库来实现
//        // 简化起见，这里只是框架
//
//        m_isInitialized = CompileHotFunctions();
//        return m_isInitialized;
//    }
//
//    bool CompileHotFunctions() {
//        // 编译常见大小的分配函数
//        CompileAllocFunction(16);
//        CompileAllocFunction(32);
//        CompileAllocFunction(64);
//        CompileAllocFunction(128);
//        CompileAllocFunction(256);
//        CompileAllocFunction(512);
//        CompileAllocFunction(1024);
//
//        // 编译释放函数
//        CompileFreeFunction();
//
//        return true;
//    }
//
//    // JIT编译特定大小的分配函数
//    bool CompileAllocFunction(size_t size) {
//        // 实际实现需要生成机器码
//        // 这里只是概念展示
//        return true;
//    }
//
//    // JIT编译释放函数
//    bool CompileFreeFunction() {
//        // 实际实现需要生成机器码
//        // 这里只是概念展示
//        return true;
//    }
//
//    // 调用JIT编译的函数
//    void* FastAlloc(size_t size) {
//        if (!m_isInitialized) return nullptr;
//
//        // 根据不同大小使用不同的编译函数
//        // 简化起见，这里只有一个通用实现
//        return m_fastAllocFunc(size);
//    }
//
//    void FastFree(void* ptr) {
//        if (!m_isInitialized || !ptr) return;
//
//        m_fastFreeFunc(ptr);
//    }
//
//    void Shutdown() {
//        // 清理JIT编译器资源
//        if (m_isInitialized) {
//            // 释放JIT相关资源
//            m_isInitialized = false;
//        }
//    }
//};
//
//// 全局实例
//extern JitCompiledFunctions g_jitFunctions;
//
//class ThreadLocalCache {
//private:
//    struct CacheEntry {
//        void* ptr;
//        size_t size;
//    };
//
//    // 线程局部缓存数组(每种常见大小保留几个块)
//    static thread_local std::vector<CacheEntry> tls_smallCache;   // <=256字节
//    static thread_local std::vector<CacheEntry> tls_mediumCache;  // 257-4096字节
//
//    // 全局控制配置
//    static const size_t MAX_SMALL_CACHE = 32;   // 每个线程最多缓存32个小块
//    static const size_t MAX_MEDIUM_CACHE = 8;   // 每个线程最多缓存8个中等块
//
//public:
//    // 尝试从线程局部缓存获取内存
//    static void* GetFromCache(size_t size) {
//        if (size <= 256) {
//            for (auto it = tls_smallCache.begin(); it != tls_smallCache.end(); ++it) {
//                if (it->size >= size) {
//                    void* ptr = it->ptr;
//                    tls_smallCache.erase(it);
//                    return ptr;
//                }
//            }
//        }
//        else if (size <= 4096) {
//            for (auto it = tls_mediumCache.begin(); it != tls_mediumCache.end(); ++it) {
//                if (it->size >= size) {
//                    void* ptr = it->ptr;
//                    tls_mediumCache.erase(it);
//                    return ptr;
//                }
//            }
//        }
//
//        return nullptr;
//    }
//
//    // 将内存添加到线程局部缓存
//    static bool AddToCache(void* ptr, size_t size) {
//        if (!ptr) return false;
//
//        if (size <= 256) {
//            if (tls_smallCache.size() < MAX_SMALL_CACHE) {
//                tls_smallCache.push_back({ ptr, size });
//                return true;
//            }
//        }
//        else if (size <= 4096) {
//            if (tls_mediumCache.size() < MAX_MEDIUM_CACHE) {
//                tls_mediumCache.push_back({ ptr, size });
//                return true;
//            }
//        }
//
//        return false;
//    }
//
//    // 清理所有线程缓存(线程退出时调用)
//    static void FlushCache() {
//        // 将小块缓存归还
//        for (const auto& entry : tls_smallCache) {
//            MemPool::FreeSafe(entry.ptr);
//        }
//        tls_smallCache.clear();
//
//        // 将中等块缓存归还
//        for (const auto& entry : tls_mediumCache) {
//            MemPool::FreeSafe(entry.ptr);
//        }
//        tls_mediumCache.clear();
//    }
//
//    // 获取当前线程缓存统计
//    static void GetCacheStats(size_t& smallCount, size_t& mediumCount) {
//        smallCount = tls_smallCache.size();
//        mediumCount = tls_mediumCache.size();
//    }
//};
//
//// 初始化线程局部变量
//thread_local std::vector<ThreadLocalCache::CacheEntry> ThreadLocalCache::tls_smallCache;
//thread_local std::vector<ThreadLocalCache::CacheEntry> ThreadLocalCache::tls_mediumCache;

void GenerateMemoryReport(bool forceWrite = false);
size_t GetStormVirtualMemoryUsage();
size_t GetTLSFPoolUsage();
void PrintMemoryStatus();

