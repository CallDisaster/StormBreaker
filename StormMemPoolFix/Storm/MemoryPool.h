#pragma once
#include "pch.h"
#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <mimalloc.h>  // 添加mimalloc头文件

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

// 内存池命名空间
namespace MemPool {
    // 导出适配变量
    extern std::atomic<bool> g_inOperation;  // 替代原来的g_inTLSFOperation

    // 声明函数
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
    void DisableMemoryReleasing();
    void CheckAndFreeUnusedPools();
    void* CreateStabilizingBlock(size_t size, const char* purpose);
    size_t GetBlockSize(void* ptr);
    bool ValidatePointer(void* ptr);
    void DisableActualFree();

}