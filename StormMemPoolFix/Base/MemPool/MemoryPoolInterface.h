// MemoryPoolInterface.h
#pragma once
#include <cstddef>

class MemoryPoolInterface {
public:
    virtual ~MemoryPoolInterface() = default;

    // ���ķ���/�ͷŽӿ�
    virtual bool Initialize(size_t initialSize) = 0;
    virtual void Shutdown() = 0;
    virtual void* Allocate(size_t size) = 0;
    virtual void Free(void* ptr) = 0;
    virtual void* Realloc(void* oldPtr, size_t newSize) = 0;

    // ��ȫ�����ӿ�
    virtual void* AllocateSafe(size_t size) = 0;
    virtual void FreeSafe(void* ptr) = 0;
    virtual void* ReallocSafe(void* oldPtr, size_t newSize) = 0;

    // ��ѯ�ӿ�
    virtual size_t GetUsedSize() = 0;
    virtual size_t GetTotalSize() = 0;
    virtual bool IsFromPool(void* ptr) = 0;
    virtual size_t GetBlockSize(void* ptr) = 0;

    // ��������
    virtual void PrintStats() = 0;
    virtual void CheckAndFreeUnusedPools() = 0;
    virtual void DisableMemoryReleasing() = 0;
    virtual void HeapCollect() = 0;
    virtual void* CreateStabilizingBlock(size_t size, const char* purpose) = 0;
    virtual bool ValidatePointer(void* ptr) = 0;
    virtual void Preheat() = 0;
    virtual void DisableActualFree() = 0;
};