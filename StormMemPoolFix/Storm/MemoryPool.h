#pragma once
#include "pch.h"
#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <mimalloc.h>  // 添加mimalloc头文件
#include "Storm/StormHook.h"

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
    void Preheat();
    void HeapCollect();
    // 分片索引计算函数
    inline size_t get_shard_index(void* ptr = nullptr, size_t size = 0) {
        size_t hash;
        if (ptr) {
            // FNV-1a哈希的简化版
            hash = (reinterpret_cast<uintptr_t>(ptr) * 2654435761) >> 16;
        }
        else {
            // 对于不同大小的分配使用更科学的分布
            if (size <= 128) {
                // 小块（16KB以下）按16字节间隔分组
                hash = size / 16;
            }
            else if (size <= 4096) {
                // 中等块（4KB以下）按64字节间隔分组
                hash = 8 + (size - 128) / 64;
            }
            else if (size <= 65536) {
                // 大块（64KB以下）按1KB间隔分组
                hash = 70 + (size / 1024);
            }
            else {
                // 超大块按16KB间隔分组
                hash = 134 + (size / 16384);
            }
        }
        return hash % LOCK_SHARDS;
    }

}