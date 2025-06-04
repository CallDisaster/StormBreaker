#pragma once
#include "pch.h"
#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <atomic>

// JVM内存池命名空间
namespace JVM_MemPool {
    void Initialize();
    void* Allocate(std::size_t size);
    void Free(void* p);
    void* Realloc(void* oldPtr, std::size_t newSize);
    bool IsFromPool(void* p);
    void Cleanup();
}

// 小块内存池命名空间
namespace SmallBlockPool {
    // 声明结构和函数
    void Initialize();
    bool ShouldIntercept(std::size_t size);
    void* Allocate(std::size_t size);
    bool Free(void* ptr, std::size_t size);
}

// TLSF内存池命名空间（从 StormHook 移动）
namespace MemPool {
    // 主内存池大小(64MB)
    constexpr size_t TLSF_MAIN_POOL_SIZE = 64 * 1024 * 1024;
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
    bool AddExtraPool(size_t size, bool callerHasLock = false);
    void CheckAndFreeUnusedPools();
    void* CreateStabilizingBlock(size_t size, const char* purpose);
    void DisableActualFree();
    void DisableMemoryReleasing();

    // 供外部查询TLSF操作状态
    extern std::atomic<bool> g_inTLSFOperation;
}
