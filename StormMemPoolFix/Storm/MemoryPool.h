#pragma once
#include "pch.h"
#include <Windows.h>
#include <stdint.h>
#include <atomic>

// ======================== TLSF内存池管理 ========================
namespace MemoryPool {

    // ======================== 初始化和清理 ========================
    bool Initialize();
    void Shutdown();
    bool IsInitialized();

    // ======================== 基本分配操作 ========================
    void* Allocate(size_t size);
    void* AllocateAligned(size_t size, size_t alignment);
    void* Reallocate(void* ptr, size_t newSize);
    void  Free(void* ptr);

    // ======================== 安全分配操作（SEH保护） ========================
    void* AllocateSafe(size_t size);
    void* AllocateAlignedSafe(size_t size, size_t alignment);
    void* ReallocateSafe(void* ptr, size_t newSize);
    void  FreeSafe(void* ptr);

    // ======================== 池状态查询 ========================
    bool  IsFromPool(void* ptr);
    size_t GetBlockSize(void* ptr);
    size_t GetUsedSize();
    size_t GetTotalSize();
    size_t GetFreeSize();

    // ======================== 池管理操作 ========================
    bool  ExtendPool(size_t additionalSize);
    void  TrimFreePages();
    void  CompactPool();

    // ======================== 调试和统计 ========================
    struct PoolStats {
        size_t totalSize;
        size_t usedSize;
        size_t freeSize;
        size_t peakUsed;
        size_t allocCount;
        size_t freeCount;
        size_t extendCount;
        size_t trimCount;
    };

    PoolStats GetStats();
    void PrintStats();
    void ResetStats();

    // ======================== 高级操作 ========================
    void* CreateStabilizingBlock(size_t size, const char* purpose = nullptr);
    void  FlushStabilizingBlocks();

    // ======================== 线程安全保证 ========================
    void EnableThreadSafety();
    void DisableThreadSafety();
    bool IsThreadSafeEnabled();

    // ======================== 内存压力响应 ========================
    void OnMemoryPressure();
    void OnMemoryAvailable();

    // ======================== 配置参数 ========================
    struct Config {
        size_t initialSize;        // 初始池大小
        size_t maxSize;           // 最大池大小
        size_t extendGranularity; // 扩展粒度
        size_t alignment;         // 默认对齐
        bool   enableDebug;       // 调试模式
        bool   enableStats;       // 统计模式
    };

    bool SetConfig(const Config& config);
    Config GetConfig();

    // ======================== 内部状态（测试用） ========================
    namespace Internal {
        void* GetTLSFHandle();
        size_t GetPoolCount();
        void DumpPoolInfo();
        bool ValidatePool();
    }
}

// ======================== JassVM专用内存池 ========================
namespace JVM_MemPool {
    bool Initialize();
    void Cleanup();

    void* Allocate(size_t size);
    void  Free(void* ptr);
    void* Realloc(void* oldPtr, size_t newSize);
    bool  IsFromPool(void* ptr);

    size_t GetUsedSize();
    void PrintStats();
}

// ======================== 小块内存池 ========================
namespace SmallBlockPool {
    bool Initialize();
    void Cleanup();

    bool ShouldIntercept(size_t size);
    void* Allocate(size_t size);
    bool Free(void* ptr, size_t size);

    void FlushCache();
    void PrintStats();
}