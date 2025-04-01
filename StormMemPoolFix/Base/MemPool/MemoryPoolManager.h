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

    // ��ֱֹ��ʵ����
    MemoryPoolManager() = delete;

public:
    // ��ʼ��ָ�����͵��ڴ��
    static bool Initialize(PoolType poolType, size_t initialSize);

    // �л��ڴ������ (��ͬ�����������ڴ�)
    static bool SwitchPoolType(PoolType newType);

    // ��ȡ��ǰ����ڴ��
    static MemoryPoolInterface* GetActivePool();

    // ��ȡ��ǰ����ڴ������
    static PoolType GetActivePoolType();

    // �ر������ڴ��
    static void Shutdown();

    // ����ԭ����MemPool�����ռ��е����нӿ�
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