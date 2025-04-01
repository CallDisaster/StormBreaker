// MiMallocPool.h
#pragma once
#include "MemoryPoolInterface.h"
#include <mimalloc.h>
#include <atomic>
#include <mutex>

class MiMallocPool : public MemoryPoolInterface {
private:
    // mimalloc堆实例
    mi_heap_t* m_mainHeap = nullptr;
    mi_heap_t* m_safeHeap = nullptr;  // 安全操作专用堆

    // 统计数据
    std::atomic<size_t> m_totalPoolSize{ 0 };
    std::atomic<size_t> m_usedSize{ 0 };

    // 控制标志
    std::atomic<bool> m_disableMemoryReleasing{ false };

    // 分片锁
    static constexpr size_t LOCK_SHARDS = 32;
    std::mutex m_poolMutexes[LOCK_SHARDS];

public:
    MiMallocPool();
    ~MiMallocPool();

    // MemoryPoolInterface 实现
    bool Initialize(size_t initialSize) override;
    void Shutdown() override;
    void* Allocate(size_t size) override;
    void Free(void* ptr) override;
    void* Realloc(void* oldPtr, size_t newSize) override;

    void* AllocateSafe(size_t size) override;
    void FreeSafe(void* ptr) override;
    void* ReallocSafe(void* oldPtr, size_t newSize) override;

    size_t GetUsedSize() override;
    size_t GetTotalSize() override;
    bool IsFromPool(void* ptr) override;
    size_t GetBlockSize(void* ptr) override;

    void PrintStats() override;
    void CheckAndFreeUnusedPools() override;
    void DisableMemoryReleasing() override;
    void HeapCollect() override;
    void* CreateStabilizingBlock(size_t size, const char* purpose) override;
    bool ValidatePointer(void* ptr) override;
    void Preheat() override;
    void DisableActualFree() override;

    // 分片索引计算函数
    size_t get_shard_index(void* ptr = nullptr, size_t size = 0);
};