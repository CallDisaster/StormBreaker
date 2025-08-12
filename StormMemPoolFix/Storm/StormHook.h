// ======================== StormHook.h 修复版本 ========================
#pragma once
#include "pch.h"
#include <Windows.h>
#include <stdint.h>
#include <atomic>
#include <unordered_map>

// 前向声明Logger，避免包含问题
class Logger;

// ======================== Storm 兼容小块头（统一10字节） ========================
#pragma pack(push, 1)
struct StormAllocHeader {
    uint16_t size;        // 用户请求大小（低16位）
    uint8_t  padding;     // 对齐填充
    uint8_t  flags;       // 标志位：不再设置0x4（大页标志）
    void* heapPtr;     // 兼容指针（不再写真实堆地址）
    uint16_t magic;       // 固定魔数 0x6F6D
};
#pragma pack(pop)

static_assert(sizeof(StormAllocHeader) == 10, "StormAllocHeader must be exactly 10 bytes");

// ======================== 统一标识常量 ========================
constexpr uint32_t STORMBREAKER_MAGIC = 0xDEADBEEF;    // 统一使用这个标识
constexpr uint16_t STORM_FRONT_MAGIC = 0x6F6D;         // Storm前置魔数

// ======================== 自管块描述结构 ========================
struct ManagedBlockInfo {
    uint32_t magic;         // STORMBREAKER_MAGIC
    size_t   originalSize;  // 原始请求大小
    void* rawPtr;        // TLSF分配的原始指针
    DWORD    timestamp;     // 分配时间戳
};

// ======================== 全局状态管理 ========================
namespace StormHook {
    // 初始化和清理
    bool Initialize();
    void Shutdown();

    // 状态查询
    bool IsOurBlock(void* userPtr);
    bool IsInUnsafePeriod();

    // 内存管理
    void* AllocateMemory(size_t size, const char* name = nullptr, DWORD srcLine = 0);
    bool  FreeMemory(void* ptr);
    void* ReallocMemory(void* oldPtr, size_t newSize, const char* name = nullptr, DWORD srcLine = 0);

    // 清理和维护
    void FlushManagedBlocks();
    void ProcessDeferredFree();

    // 统计信息
    size_t GetManagedBlockCount();
    size_t GetTotalManagedSize();

    // Reset协同
    void PrepareForReset();
    void PostReset();

    // 对齐验证
    bool IsPointerAligned(void* ptr, size_t alignment);
    bool ValidateBlockAlignment(void* userPtr);

    // 大块阈值管理
    void   SetLargeBlockThreshold(size_t bytes);
    size_t GetLargeBlockThreshold();
}

// ======================== Hook函数声明 ========================
extern "C" {
    // Storm内存分配Hook
    void* __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
        const char* name, DWORD srcLine, DWORD flags);
    int   __stdcall  Hooked_Storm_MemFree(void* ptr, const char* name, int argList, DWORD flags);
    void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
        const char* name, DWORD srcLine, DWORD flags);

    // Storm清理Hook
    void  __stdcall  Hooked_StormHeap_CleanupAll();

    // Reset协同Hook（可选）
    int   __fastcall Hooked_ResetMemoryManager(void* thiz, int edx, int a2, void (*pump)(void));
}

// ======================== 原始函数指针类型 ========================
typedef void* (__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size,
    const char* name, DWORD srcLine, DWORD flags);
typedef int(__stdcall* Storm_MemFree_t)(void* ptr, const char* name, int argList, DWORD flags);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD srcLine, DWORD flags);
typedef void(__stdcall* StormHeap_CleanupAll_t)();
typedef int(__fastcall* ResetMemoryManager_t)(void* thiz, int edx, int a2, void (*pump)(void));

// ======================== 原始函数指针（外部定义） ========================
extern Storm_MemAlloc_t       g_origStormAlloc;
extern Storm_MemFree_t        g_origStormFree;
extern Storm_MemReAlloc_t     g_origStormReAlloc;
extern StormHeap_CleanupAll_t g_origCleanupAll;
extern ResetMemoryManager_t   g_origResetMemoryManager;

// ======================== 内部状态（不暴露实现细节） ========================
namespace StormHook_Internal {
    // 自管块表管理
    bool RegisterManagedBlock(void* userPtr, const ManagedBlockInfo& info);
    bool UnregisterManagedBlock(void* userPtr);
    bool GetManagedBlockInfo(void* userPtr, ManagedBlockInfo& info);

    // 头部操作
    void SetupStormCompatibleHeader(void* userPtr, size_t size);
    bool ValidateStormHeader(void* userPtr);

    // 大小计算
    size_t GetBlockSizeFromHeader(void* userPtr);
    size_t GetBlockSizeFromManagedTable(void* userPtr);

    // 状态管理
    void EnterUnsafePeriod();
    void ExitUnsafePeriod();
}