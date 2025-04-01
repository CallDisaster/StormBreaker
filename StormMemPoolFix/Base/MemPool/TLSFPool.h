#pragma once
#include "pch.h"
#include <cstddef>
#include <atomic>
#include <mutex>

// TLSFPool类 - 使用TLSF算法的内存池实现
class TLSFPool {
public:
    TLSFPool();
    ~TLSFPool();

    // 基本内存池操作
    bool Initialize(size_t initialSize = 64 * 1024 * 1024);
    void Shutdown();

    // 常规内存操作
    void* Allocate(size_t size);
    void Free(void* ptr);
    void* Realloc(void* oldPtr, size_t newSize);

    // 安全版内存操作（适用于不安全期）
    void* AllocateSafe(size_t size);
    void FreeSafe(void* ptr);
    void* ReallocSafe(void* oldPtr, size_t newSize);

    // 辅助功能
    bool IsFromPool(void* ptr);
    size_t GetBlockSize(void* ptr);
    size_t GetUsedSize();
    size_t GetTotalSize();
    void DisableMemoryReleasing();
    void CheckAndFreeUnusedPools();
    void HeapCollect();
    void PrintStats();

private:
    std::mutex m_mutex;
    bool m_initialized;

    // 扩展内存池
    bool ExpandPool(size_t additionalSize);
};