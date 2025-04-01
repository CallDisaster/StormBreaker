// TLSFPool.h
#pragma once
#include "MemoryPoolInterface.h"
#include "tlsf.h"
#include <atomic>
#include <mutex>
#include <unordered_map>

class TLSFPool : public MemoryPoolInterface {
private:
    // TLSF内存池指针
    tlsf_t m_tlsfPool = nullptr;
    void* m_poolMemory = nullptr;

    // 安全操作池
    tlsf_t m_safeTlsfPool = nullptr;
    void* m_safePoolMemory = nullptr;

    // 统计数据
    std::atomic<size_t> m_totalPoolSize{ 0 };
    std::atomic<size_t> m_usedSize{ 0 };

    // 块跟踪
    std::mutex m_trackingMutex;
    std::unordered_map<void*, size_t> m_allocatedBlocks;

    // 控制标志
    std::atomic<bool> m_disableMemoryReleasing{ false };

    // 分片锁
    static constexpr size_t LOCK_SHARDS = 32;
    std::mutex m_poolMutexes[LOCK_SHARDS];

    void* ReallocInternal(void* oldPtr, size_t newSize) {
        // 获取旧块大小
        size_t oldSize = 0;
        {
            std::lock_guard<std::mutex> trackLock(m_trackingMutex);
            auto it = m_allocatedBlocks.find(oldPtr);
            if (it != m_allocatedBlocks.end()) {
                oldSize = it->second;
            }
        }

        // 使用TLSF的重分配
        void* newPtr = tlsf_realloc(m_tlsfPool, oldPtr, newSize);

        if (newPtr) {
            // 更新统计和跟踪信息
            std::lock_guard<std::mutex> trackLock(m_trackingMutex);

            // 如果指针变化，移除旧记录
            if (newPtr != oldPtr) {
                auto it = m_allocatedBlocks.find(oldPtr);
                if (it != m_allocatedBlocks.end()) {
                    m_allocatedBlocks.erase(it);
                }

                if (oldSize > 0) {
                    m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
            }

            // 添加新记录
            m_allocatedBlocks[newPtr] = newSize;
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }

        return newPtr;
    }

public:
    TLSFPool();
    ~TLSFPool();

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