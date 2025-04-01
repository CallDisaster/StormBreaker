#pragma once
#include "pch.h"
#include <cstddef>
#include <atomic>
#include <mutex>

// 内存池类型枚举
enum class PoolType {
    TLSF,       // Two Level Segregated Fit
    MiMalloc,   // mimalloc
    Default = MiMalloc // 默认使用mimalloc
};

// 内存池管理器 - 统一管理不同类型的内存池
namespace MemoryPoolManager {
    // 初始化内存池 - 注意参数顺序和默认值
    bool Initialize(size_t initialSize = 64 * 1024 * 1024, PoolType poolType = PoolType::Default);

    // 无参数的初始化重载，用于方便调用
    bool Initialize();

    // 关闭内存池
    void Shutdown();

    // 切换内存池类型
    bool SwitchPoolType(PoolType newType);

    // 获取当前活跃的内存池类型
    PoolType GetActivePoolType();

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
    void* CreateStabilizingBlock(size_t size, const char* purpose);
    bool ValidatePointer(void* ptr);
    void DisableActualFree();
    void Preheat();
    void HeapCollect();
    void PrintStats();
}