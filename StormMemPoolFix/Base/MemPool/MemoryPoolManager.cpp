// MemoryPoolManager.cpp
#include "MemoryPoolManager.h"
#include "MiMallocPool.h"
#include "TLSFPool.h"
#include "Base/Logger.h"
#include <unordered_map>
#include <Storm/StormHook.h>

// 静态成员初始化
std::unique_ptr<MemoryPoolInterface> MemoryPoolManager::s_currentPool = nullptr;
std::atomic<PoolType> MemoryPoolManager::s_activePoolType{ PoolType::MiMalloc }; // 默认使用mimalloc
std::atomic<bool> MemoryPoolManager::g_inSwapOperation{ false };

// 命名空间变量实现
namespace MemPool {
    std::atomic<bool> g_inOperation{ false };
}

bool MemoryPoolManager::Initialize(PoolType poolType, size_t initialSize) {
    if (s_currentPool) {
        LogMessage("[MemoryPoolManager] 已初始化，请先调用Shutdown");
        return false;
    }

    try {
        switch (poolType) {
        case PoolType::TLSF:
            s_currentPool = std::make_unique<TLSFPool>();
            s_activePoolType.store(PoolType::TLSF);
            LogMessage("[MemoryPoolManager] 使用TLSF内存池");
            break;

        case PoolType::MiMalloc:
            s_currentPool = std::make_unique<MiMallocPool>();
            s_activePoolType.store(PoolType::MiMalloc);
            LogMessage("[MemoryPoolManager] 使用mimalloc内存池");
            break;

        default:
            LogMessage("[MemoryPoolManager] 未知内存池类型");
            return false;
        }

        return s_currentPool->Initialize(initialSize);
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryPoolManager] 初始化异常: %s", e.what());
        return false;
    }
    catch (...) {
        LogMessage("[MemoryPoolManager] 初始化未知异常");
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
    // 检查是否相同
    if (newType == s_activePoolType.load()) {
        LogMessage("[MemoryPoolManager] 已经是请求的内存池类型");
        return true;
    }

    // 检查是否已初始化
    if (!s_currentPool) {
        LogMessage("[MemoryPoolManager] 未初始化，无法切换");
        return false;
    }

    // 防止递归切换
    if (g_inSwapOperation.exchange(true)) {
        LogMessage("[MemoryPoolManager] 已在切换中，请稍后重试");
        return false;
    }

    LogMessage("[MemoryPoolManager] 开始切换内存池类型 %d -> %d",
        static_cast<int>(s_activePoolType.load()), static_cast<int>(newType));

    try {
        // 创建新内存池
        std::unique_ptr<MemoryPoolInterface> newPool;
        switch (newType) {
        case PoolType::TLSF:
            newPool = std::make_unique<TLSFPool>();
            break;

        case PoolType::MiMalloc:
            newPool = std::make_unique<MiMallocPool>();
            break;

        default:
            LogMessage("[MemoryPoolManager] 未知内存池类型");
            g_inSwapOperation.store(false);
            return false;
        }

        // 获取当前内存使用情况
        size_t currentUsed = s_currentPool->GetUsedSize();
        size_t totalSize = s_currentPool->GetTotalSize();
        size_t newInitSize = totalSize * 2; // 确保新池有足够空间

        // 初始化新内存池
        if (!newPool->Initialize(newInitSize)) {
            LogMessage("[MemoryPoolManager] 新内存池初始化失败");
            g_inSwapOperation.store(false);
            return false;
        }

        // 预热新池
        newPool->Preheat();

        // 收集当前池的统计信息
        LogMessage("[MemoryPoolManager] 当前内存使用: %zu MB / %zu MB",
            currentUsed / (1024 * 1024), totalSize / (1024 * 1024));

        // 交换内存池
        s_currentPool.swap(newPool);
        s_activePoolType.store(newType);

        // 旧池清理
        newPool->Shutdown();

        LogMessage("[MemoryPoolManager] 内存池切换完成");
        g_inSwapOperation.store(false);
        return true;
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryPoolManager] 切换异常: %s", e.what());
        g_inSwapOperation.store(false);
        return false;
    }
    catch (...) {
        LogMessage("[MemoryPoolManager] 切换未知异常");
        g_inSwapOperation.store(false);
        return false;
    }
}

// 委托函数实现
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

    // 打印当前池类型
    LogMessage("[MemoryPoolManager] 当前内存池类型: %s",
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