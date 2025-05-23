﻿#pragma
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
#include <future>
#include <Log/MemoryTracker.h>
#include <Log/LogSystem.h>
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

extern std::atomic<LogLevel> g_currentLogLevel;
class AsyncLogger; // Forward declaration
extern AsyncLogger g_asyncLogger;


// 资源类型枚举（用于统计和泄漏分析）
enum class ResourceType {
    Unknown,
    Model,
    Unit,
    Terrain,
    Sound,
    File,
    JassVM
};

// 控制内存跟踪级别
enum class MemoryTrackingLevel {
    None,       // 不跟踪
    Basic,      // 仅跟踪基础信息
    Detailed,   // 详细跟踪
    Full        // 完全跟踪
};

struct BigBlockInfoSafe {
    void* rawPtr;           // 实际内存起始地址
    size_t size;            // 用户请求的大小
    DWORD timestamp;        // 分配时间戳
    std::shared_ptr<char[]> source;  // 使用智能指针管理源字符串
    DWORD srcLine;          // 源代码行号
    ResourceType type;      // 资源类型
    std::atomic<int> refCount{ 1 };  // 引用计数

    // 构造函数
    BigBlockInfoSafe() : rawPtr(nullptr), size(0), timestamp(0), srcLine(0), type(ResourceType::Unknown) {}

    // 设置源信息（安全）
    void SetSource(const char* src) {
        if (src && *src) {
            size_t len = strlen(src) + 1;
            source = std::shared_ptr<char[]>(new char[len]);
            strcpy_s(source.get(), len, src);
        }
        else {
            source.reset();
        }
    }

    // 获取源信息（安全）
    const char* GetSource() const {
        return source ? source.get() : "";
    }

    // 复制构造函数
    BigBlockInfoSafe(const BigBlockInfoSafe& other)
        : rawPtr(other.rawPtr)
        , size(other.size)
        , timestamp(other.timestamp)
        , source(other.source)  // 共享所有权
        , srcLine(other.srcLine)
        , type(other.type)
        , refCount(1) {
    }

    // 移动构造函数
    BigBlockInfoSafe(BigBlockInfoSafe&& other) noexcept
        : rawPtr(other.rawPtr)
        , size(other.size)
        , timestamp(other.timestamp)
        , source(std::move(other.source))
        , srcLine(other.srcLine)
        , type(other.type)
        , refCount(1) {
        other.rawPtr = nullptr;
        other.size = 0;
    }

    BigBlockInfoSafe& operator=(const BigBlockInfoSafe& other) {
        if (this != &other) {
            rawPtr = other.rawPtr;
            size = other.size;
            timestamp = other.timestamp;
            source = other.source;
            srcLine = other.srcLine;
            type = other.type;
            refCount.store(1); // 拷贝/赋值后，引用计数重置或你想要的数值
        }
        return *this;
    }
};

// 缓存特殊大块的过滤条件（优化频繁分配的特定模式）
struct SpecialBlockFilter {
    size_t size;
    const char* name;
    int sourceLine;
    bool useCustomPool;
    bool forceSystemAlloc;  // 新增：强制使用系统分配

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
// extern std::mutex g_bigBlocksMutex; // This seems unused, g_bigBlocks uses its own sharded mutex now.
// extern std::unordered_map<void*, BigBlockInfo> g_bigBlocks; // This is replaced by BlockInfoShardedMap
extern MemoryStats g_memStats;
extern Storm_MemAlloc_t s_origStormAlloc;
extern Storm_MemFree_t s_origStormFree;
extern Storm_MemReAlloc_t s_origStormReAlloc;
extern StormHeap_CleanupAll_t s_origCleanupAll;
extern std::atomic<bool> g_cleanAllInProgress;
extern std::atomic<bool> g_afterCleanAll;
extern std::atomic<DWORD> g_lastCleanAllTime;
extern thread_local bool tls_inCleanAll;
extern std::atomic<bool> g_insideUnsafePeriod; // 新增：标记不安全时期
extern DWORD g_cleanAllThreadId;
extern std::atomic<bool> g_disableMemoryReleasing;
extern std::atomic<size_t> g_peakVirtualMemoryUsage; // 添加全局变量跟踪峰值内存使用量

// 全局内存跟踪器
extern MemoryTracker g_memoryTracker;

// 函数声明
bool InitializeStormMemoryHooks();
bool HookAllStormHeapFunctions();
void ShutdownStormMemoryHooks();
void LogMessage(const char* format, ...);
void SetupCompatibleHeader(void* userPtr, size_t size);
bool IsOurBlock(void* ptr);
void PrintAllPoolsUsage();
void CreateStabilizingBlocks(int cleanAllCount);
bool IsSpecialBlockAllocation(size_t size, const char* name, DWORD src_line);
bool IsPermanentBlock(void* ptr);
ResourceType GetResourceType(const char* name);
bool AddExtraPool(size_t size, bool callerHasLock = false);
void SafeExecuteCleanupAll();
void SafelyDetachHooks();
DWORD WINAPI MemoryStatsThread(LPVOID);

// 初始化内存跟踪系统
bool InitializeMemoryTracking();

// 关闭内存跟踪系统
void ShutdownMemoryTracking();

// 设置内存跟踪级别
void SetMemoryTrackingLevel(MemoryTrackingLevel level);

// 获取当前内存跟踪级别
MemoryTrackingLevel GetMemoryTrackingLevel();

// 手动设置大块阈值（超过此大小的内存块会被TLSF管理）
void SetBigBlockThreshold(size_t sizeInBytes);

// Hook函数声明
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag);
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4);
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD src_line, DWORD flag);
void Hooked_StormHeap_CleanupAll();
bool SafeValidatePointer(void* ptr, size_t expectedSize);
bool SafeValidateStormHeader(void* userPtr);


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

// Forward declare classes defined in StormHook.cpp
class LargeBlockCache;
class AsyncMemoryReleaser;
class AllocationProfiler;
struct BlockInfoShardedMapSafe; // Forward declare the map struct

// Declare global variables as extern
extern LargeBlockCache g_largeBlockCache;
extern AsyncMemoryReleaser g_asyncReleaser;
extern AllocationProfiler g_allocProfiler;
extern BlockInfoShardedMapSafe g_bigBlocks; // Use the sharded map type
// g_freedByAllocHook and g_freedByFreeHook are now static within StormHeapHook.cpp
extern std::atomic<size_t> g_freedByFreeHook;

void GenerateMemoryReport(bool forceWrite = false);
size_t GetStormVirtualMemoryUsage();
size_t GetTLSFPoolUsage();
void PrintMemoryStatus();

// SEH保护的内存操作模板
template<typename T>
bool SafeReadMemory(void* src, T& dest) {
    __try {
        dest = *static_cast<T*>(src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template<typename T>
bool SafeWriteMemory(void* dest, const T& value) {
    __try {
        *static_cast<T*>(dest) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}