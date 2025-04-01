// MemoryPoolManager.cpp
#include "MemoryPoolManager.h"
#include "MiMallocPool.h"
#include "TLSFPool.h"
#include "Base/Logger.h"
#include <unordered_map>
#include <Storm/StormHook.h>

// ��̬��Ա��ʼ��
std::unique_ptr<MemoryPoolInterface> MemoryPoolManager::s_currentPool = nullptr;
std::atomic<PoolType> MemoryPoolManager::s_activePoolType{ PoolType::MiMalloc }; // Ĭ��ʹ��mimalloc
std::atomic<bool> MemoryPoolManager::g_inSwapOperation{ false };

// �����ռ����ʵ��
namespace MemPool {
    std::atomic<bool> g_inOperation{ false };
}

bool MemoryPoolManager::Initialize(PoolType poolType, size_t initialSize) {
    if (s_currentPool) {
        LogMessage("[MemoryPoolManager] �ѳ�ʼ�������ȵ���Shutdown");
        return false;
    }

    try {
        switch (poolType) {
        case PoolType::TLSF:
            s_currentPool = std::make_unique<TLSFPool>();
            s_activePoolType.store(PoolType::TLSF);
            LogMessage("[MemoryPoolManager] ʹ��TLSF�ڴ��");
            break;

        case PoolType::MiMalloc:
            s_currentPool = std::make_unique<MiMallocPool>();
            s_activePoolType.store(PoolType::MiMalloc);
            LogMessage("[MemoryPoolManager] ʹ��mimalloc�ڴ��");
            break;

        default:
            LogMessage("[MemoryPoolManager] δ֪�ڴ������");
            return false;
        }

        return s_currentPool->Initialize(initialSize);
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryPoolManager] ��ʼ���쳣: %s", e.what());
        return false;
    }
    catch (...) {
        LogMessage("[MemoryPoolManager] ��ʼ��δ֪�쳣");
        return false;
    }
}

bool MemoryPoolManager::Initialize(size_t initialSize) {
    return Initialize(s_activePoolType.load(), initialSize);
}

void MemoryPoolManager::Shutdown() {
    if (s_currentPool) {
        s_currentPool->Shutdown();
        s_currentPool.reset();
    }
}

MemoryPoolInterface* MemoryPoolManager::GetActivePool() {
    return s_currentPool.get();
}

PoolType MemoryPoolManager::GetActivePoolType() {
    return s_activePoolType.load();
}

bool MemoryPoolManager::SwitchPoolType(PoolType newType) {
    // ����Ƿ���ͬ
    if (newType == s_activePoolType.load()) {
        LogMessage("[MemoryPoolManager] �Ѿ���������ڴ������");
        return true;
    }

    // ����Ƿ��ѳ�ʼ��
    if (!s_currentPool) {
        LogMessage("[MemoryPoolManager] δ��ʼ�����޷��л�");
        return false;
    }

    // ��ֹ�ݹ��л�
    if (g_inSwapOperation.exchange(true)) {
        LogMessage("[MemoryPoolManager] �����л��У����Ժ�����");
        return false;
    }

    LogMessage("[MemoryPoolManager] ��ʼ�л��ڴ������ %d -> %d",
        static_cast<int>(s_activePoolType.load()), static_cast<int>(newType));

    try {
        // �������ڴ��
        std::unique_ptr<MemoryPoolInterface> newPool;
        switch (newType) {
        case PoolType::TLSF:
            newPool = std::make_unique<TLSFPool>();
            break;

        case PoolType::MiMalloc:
            newPool = std::make_unique<MiMallocPool>();
            break;

        default:
            LogMessage("[MemoryPoolManager] δ֪�ڴ������");
            g_inSwapOperation.store(false);
            return false;
        }

        // ��ȡ��ǰ�ڴ�ʹ�����
        size_t currentUsed = s_currentPool->GetUsedSize();
        size_t totalSize = s_currentPool->GetTotalSize();
        size_t newInitSize = totalSize * 2; // ȷ���³����㹻�ռ�

        // ��ʼ�����ڴ��
        if (!newPool->Initialize(newInitSize)) {
            LogMessage("[MemoryPoolManager] ���ڴ�س�ʼ��ʧ��");
            g_inSwapOperation.store(false);
            return false;
        }

        // Ԥ���³�
        newPool->Preheat();

        // �ռ���ǰ�ص�ͳ����Ϣ
        LogMessage("[MemoryPoolManager] ��ǰ�ڴ�ʹ��: %zu MB / %zu MB",
            currentUsed / (1024 * 1024), totalSize / (1024 * 1024));

        // �����ڴ��
        s_currentPool.swap(newPool);
        s_activePoolType.store(newType);

        // �ɳ�����
        newPool->Shutdown();

        LogMessage("[MemoryPoolManager] �ڴ���л����");
        g_inSwapOperation.store(false);
        return true;
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryPoolManager] �л��쳣: %s", e.what());
        g_inSwapOperation.store(false);
        return false;
    }
    catch (...) {
        LogMessage("[MemoryPoolManager] �л�δ֪�쳣");
        g_inSwapOperation.store(false);
        return false;
    }
}

// ί�к���ʵ��
void* MemoryPoolManager::Allocate(size_t size) {
    if (!s_currentPool) return nullptr;
    MemPool::g_inOperation.store(true);
    void* ptr = s_currentPool->Allocate(size);
    MemPool::g_inOperation.store(false);
    return ptr;
}

void MemoryPoolManager::Free(void* ptr) {
    if (!s_currentPool || !ptr) return;
    MemPool::g_inOperation.store(true);
    s_currentPool->Free(ptr);
    MemPool::g_inOperation.store(false);
}

void* MemoryPoolManager::Realloc(void* oldPtr, size_t newSize) {
    if (!s_currentPool) return nullptr;
    MemPool::g_inOperation.store(true);
    void* ptr = s_currentPool->Realloc(oldPtr, newSize);
    MemPool::g_inOperation.store(false);
    return ptr;
}

void* MemoryPoolManager::AllocateSafe(size_t size) {
    if (!s_currentPool) return nullptr;
    MemPool::g_inOperation.store(true);
    void* ptr = s_currentPool->AllocateSafe(size);
    MemPool::g_inOperation.store(false);
    return ptr;
}

void MemoryPoolManager::FreeSafe(void* ptr) {
    if (!s_currentPool || !ptr) return;
    MemPool::g_inOperation.store(true);
    s_currentPool->FreeSafe(ptr);
    MemPool::g_inOperation.store(false);
}

void* MemoryPoolManager::ReallocSafe(void* oldPtr, size_t newSize) {
    if (!s_currentPool) return nullptr;
    MemPool::g_inOperation.store(true);
    void* ptr = s_currentPool->ReallocSafe(oldPtr, newSize);
    MemPool::g_inOperation.store(false);
    return ptr;
}

size_t MemoryPoolManager::GetUsedSize() {
    if (!s_currentPool) return 0;
    return s_currentPool->GetUsedSize();
}

size_t MemoryPoolManager::GetTotalSize() {
    if (!s_currentPool) return 0;
    return s_currentPool->GetTotalSize();
}

bool MemoryPoolManager::IsFromPool(void* ptr) {
    if (!s_currentPool || !ptr) return false;
    return s_currentPool->IsFromPool(ptr);
}

size_t MemoryPoolManager::GetBlockSize(void* ptr) {
    if (!s_currentPool || !ptr) return 0;
    return s_currentPool->GetBlockSize(ptr);
}

void MemoryPoolManager::PrintStats() {
    if (!s_currentPool) return;

    // ��ӡ��ǰ������
    LogMessage("[MemoryPoolManager] ��ǰ�ڴ������: %s",
        s_activePoolType.load() == PoolType::TLSF ? "TLSF" : "mimalloc");

    s_currentPool->PrintStats();
}

void MemoryPoolManager::CheckAndFreeUnusedPools() {
    if (!s_currentPool) return;
    s_currentPool->CheckAndFreeUnusedPools();
}

void MemoryPoolManager::DisableMemoryReleasing() {
    if (!s_currentPool) return;
    s_currentPool->DisableMemoryReleasing();
}

void MemoryPoolManager::HeapCollect() {
    if (!s_currentPool) return;
    s_currentPool->HeapCollect();
}

void* MemoryPoolManager::CreateStabilizingBlock(size_t size, const char* purpose) {
    if (!s_currentPool) return nullptr;
    return s_currentPool->CreateStabilizingBlock(size, purpose);
}

bool MemoryPoolManager::ValidatePointer(void* ptr) {
    if (!s_currentPool || !ptr) return false;
    return s_currentPool->ValidatePointer(ptr);
}

void MemoryPoolManager::Preheat() {
    if (!s_currentPool) return;
    s_currentPool->Preheat();
}

void MemoryPoolManager::DisableActualFree() {
    if (!s_currentPool) return;
    s_currentPool->DisableActualFree();
}