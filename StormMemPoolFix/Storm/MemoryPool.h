// MemoryPool.h修改
#pragma once
#include <Base/MemPool/MemoryPoolManager.h>

// 内存池命名空间
namespace MemPool {
    // 导出适配变量
    extern std::atomic<bool> g_inOperation;  // 替代原来的g_inTLSFOperation

    // 声明函数
    inline bool Initialize(size_t initialSize) {
        return MemoryPoolManager::Initialize(initialSize);
    }

    inline void Shutdown() {
        MemoryPoolManager::Shutdown();
    }

    inline void* Allocate(size_t size) {
        return MemoryPoolManager::Allocate(size);
    }

    inline void Free(void* ptr) {
        MemoryPoolManager::Free(ptr);
    }

    inline void* Realloc(void* oldPtr, size_t newSize) {
        return MemoryPoolManager::Realloc(oldPtr, newSize);
    }

    inline size_t GetUsedSize() {
        return MemoryPoolManager::GetUsedSize();
    }

    inline size_t GetTotalSize() {
        return MemoryPoolManager::GetTotalSize();
    }

    inline void PrintStats() {
        MemoryPoolManager::PrintStats();
    }

    inline bool IsFromPool(void* ptr) {
        return MemoryPoolManager::IsFromPool(ptr);
    }

    inline void* AllocateSafe(size_t size) {
        return MemoryPoolManager::AllocateSafe(size);
    }

    inline void FreeSafe(void* ptr) {
        MemoryPoolManager::FreeSafe(ptr);
    }

    inline void* ReallocSafe(void* oldPtr, size_t newSize) {
        return MemoryPoolManager::ReallocSafe(oldPtr, newSize);
    }

    inline void DisableMemoryReleasing() {
        MemoryPoolManager::DisableMemoryReleasing();
    }

    inline void CheckAndFreeUnusedPools() {
        MemoryPoolManager::CheckAndFreeUnusedPools();
    }

    inline void* CreateStabilizingBlock(size_t size, const char* purpose) {
        return MemoryPoolManager::CreateStabilizingBlock(size, purpose);
    }

    inline size_t GetBlockSize(void* ptr) {
        return MemoryPoolManager::GetBlockSize(ptr);
    }

    inline bool ValidatePointer(void* ptr) {
        return MemoryPoolManager::ValidatePointer(ptr);
    }

    inline void DisableActualFree() {
        MemoryPoolManager::DisableActualFree();
    }

    inline void Preheat() {
        MemoryPoolManager::Preheat();
    }

    inline void HeapCollect() {
        MemoryPoolManager::HeapCollect();
    }

    // 原有的分片索引计算函数
    inline size_t get_shard_index(void* ptr = nullptr, size_t size = 0) {
        size_t hash;
        if (ptr) {
            // FNV-1a哈希的简化版
            hash = (reinterpret_cast<uintptr_t>(ptr) * 2654435761) >> 16;
        }
        else {
            // 对于不同大小的分配使用更科学的分布
            if (size <= 128) {
                hash = size / 16;
            }
            else if (size <= 4096) {
                hash = 8 + (size - 128) / 64;
            }
            else if (size <= 65536) {
                hash = 70 + (size / 1024);
            }
            else {
                hash = 134 + (size / 16384);
            }
        }
        return hash % LOCK_SHARDS;
    }

    // 新增函数 - 切换内存池类型
    inline bool SwitchPoolType(PoolType newType) {
        return MemoryPoolManager::SwitchPoolType(newType);
    }

    // 新增函数 - 获取当前内存池类型
    inline PoolType GetCurrentPoolType() {
        return MemoryPoolManager::GetActivePoolType();
    }
}