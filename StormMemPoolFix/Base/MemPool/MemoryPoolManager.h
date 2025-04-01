// MemoryPoolManager.h
#pragma once
#include "MemoryPoolInterface.h"
#include <atomic>
#include <memory>

enum class PoolType {
    TLSF,
    MiMalloc
};

class MemoryPoolManager {
private:
    static std::unique_ptr<MemoryPoolInterface> s_currentPool;
    static std::atomic<PoolType> s_activePoolType;
    static std::atomic<bool> g_inSwapOperation;

    // 禁止直接实例化
    MemoryPoolManager() = delete;

public:
    // 初始化指定类型的内存池
    static bool Initialize(PoolType poolType, size_t initialSize);

    // 切换内存池类型 (会同步所有现有内存)
    static bool SwitchPoolType(PoolType newType);

    // 获取当前活动的内存池
    static MemoryPoolInterface* GetActivePool();

    // 获取当前活动的内存池类型
    static PoolType GetActivePoolType();

    // 关闭所有内存池
    static void Shutdown();

    // 导出原来的MemPool命名空间中的所有接口
    static bool Initialize(size_t initialSize);
    static void* Allocate(size_t size);
    static void Free(void* ptr);
    static void* Realloc(void* oldPtr, size_t newSize);

    static void* AllocateSafe(size_t size);
    static void FreeSafe(void* ptr);
    static void* ReallocSafe(void* oldPtr, size_t newSize);

    static size_t GetUsedSize();
    static size_t GetTotalSize();
    static bool IsFromPool(void* ptr);
    static size_t GetBlockSize(void* ptr);

    static void PrintStats();
    static void CheckAndFreeUnusedPools();
    static void DisableMemoryReleasing();
    static void HeapCollect();
    static void* CreateStabilizingBlock(size_t size, const char* purpose);
    static bool ValidatePointer(void* ptr);
    static void Preheat();
    static void DisableActualFree();
};