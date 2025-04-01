#include "pch.h"
#include "MemoryPoolManager.h"
#include "MiMallocPool.h"
#include "TLSFPool.h"
#include <mutex>
#include <memory>
#include "Storm/StormHook.h"
#include "Base/MemorySafety.h"

// 私有命名空间，不导出符号
namespace {
    // 当前活跃的内存池类型
    std::atomic<PoolType> g_activePoolType{ PoolType::Default };

    // 内存池实例
    std::unique_ptr<MiMallocPool> g_miMallocPool;
    std::unique_ptr<TLSFPool> g_tlsfPool;

    // 访问锁
    std::mutex g_managerMutex;

    // 状态标志
    std::atomic<bool> g_initialized{ false };
    std::atomic<bool> g_disableActualFree{ false };

    // 工具函数 - 获取块大小，内部使用
    size_t GetBlockSizeInternal(void* ptr)
    {
        if (!ptr) return 0;

        // 先尝试mimalloc获取
        if (g_miMallocPool) {
            size_t size = g_miMallocPool->GetBlockSize(ptr);
            if (size > 0) return size;
        }

        // 再尝试TLSF获取
        if (g_tlsfPool) {
            size_t size = g_tlsfPool->GetBlockSize(ptr);
            if (size > 0) return size;
        }

        return 0;
    }
}

// 无参数初始化重载 - 修改为调用带参数版本
bool MemoryPoolManager::Initialize() {
    // 明确调用带两个参数的版本，避免歧义
    return MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default);
}

// 实现函数
bool MemoryPoolManager::Initialize(size_t initialSize, PoolType poolType)
{
    std::lock_guard<std::mutex> lock(g_managerMutex);

    if (g_initialized) {
        LogMessage("[MemoryPoolManager] 已初始化");
        return true;
    }

    // 设置当前活跃的池类型
    g_activePoolType.store(poolType);

    // 根据指定类型创建相应内存池
    switch (poolType) {
    case PoolType::MiMalloc:
        g_miMallocPool = std::make_unique<MiMallocPool>();
        if (!g_miMallocPool->Initialize(initialSize)) {
            LogMessage("[MemoryPoolManager] mimalloc池初始化失败");
            g_miMallocPool.reset();
            return false;
        }
        LogMessage("[MemoryPoolManager] 使用mimalloc内存池");
        break;

    case PoolType::TLSF:
        g_tlsfPool = std::make_unique<TLSFPool>();
        if (!g_tlsfPool->Initialize(initialSize)) {
            LogMessage("[MemoryPoolManager] TLSF池初始化失败");
            g_tlsfPool.reset();
            return false;
        }
        LogMessage("[MemoryPoolManager] 使用TLSF内存池");
        break;

    default:
        LogMessage("[MemoryPoolManager] 未知内存池类型");
        return false;
    }

    g_initialized = true;
    return true;
}

void MemoryPoolManager::Shutdown()
{
    std::lock_guard<std::mutex> lock(g_managerMutex);

    if (!g_initialized) {
        return;
    }

    // 关闭所有已创建的内存池
    if (g_miMallocPool) {
        g_miMallocPool->Shutdown();
        g_miMallocPool.reset();
    }

    if (g_tlsfPool) {
        g_tlsfPool->Shutdown();
        g_tlsfPool.reset();
    }

    g_initialized = false;
    LogMessage("[MemoryPoolManager] 所有内存池已关闭");
}

bool MemoryPoolManager::SwitchPoolType(PoolType newType)
{
    std::lock_guard<std::mutex> lock(g_managerMutex);

    if (newType == g_activePoolType) {
        // 已经是当前类型
        return true;
    }

    // 如果新类型的池尚未创建，则创建
    switch (newType) {
    case PoolType::MiMalloc:
        if (!g_miMallocPool) {
            g_miMallocPool = std::make_unique<MiMallocPool>();
            if (!g_miMallocPool->Initialize()) {
                LogMessage("[MemoryPoolManager] 无法创建mimalloc池");
                g_miMallocPool.reset();
                return false;
            }
        }
        break;

    case PoolType::TLSF:
        if (!g_tlsfPool) {
            g_tlsfPool = std::make_unique<TLSFPool>();
            if (!g_tlsfPool->Initialize()) {
                LogMessage("[MemoryPoolManager] 无法创建TLSF池");
                g_tlsfPool.reset();
                return false;
            }
        }
        break;

    default:
        LogMessage("[MemoryPoolManager] 未知内存池类型");
        return false;
    }

    // 更新当前池类型
    PoolType oldType = g_activePoolType.load();
    g_activePoolType.store(newType);

    LogMessage("[MemoryPoolManager] 内存池已从%s切换到%s",
        oldType == PoolType::MiMalloc ? "mimalloc" : "TLSF",
        newType == PoolType::MiMalloc ? "mimalloc" : "TLSF");

    return true;
}

PoolType MemoryPoolManager::GetActivePoolType()
{
    return g_activePoolType.load();
}

void* MemoryPoolManager::Allocate(size_t size)
{
    // 确保已初始化
    if (!g_initialized) {
        // 明确调用带两个参数的版本，避免歧义
        if (!MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default)) {
            return nullptr;
        }
    }

    // 根据当前活跃池类型分配内存
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            return g_miMallocPool->Allocate(size);
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            return g_tlsfPool->Allocate(size);
        }
        break;
    }

    return nullptr;
}

void MemoryPoolManager::Free(void* ptr)
{
    if (!ptr || !g_initialized) return;

    // 特殊处理永久块
    if (IsPermanentBlock(ptr)) {
        return;
    }

    // 如果禁用实际释放，则跳过
    if (g_disableActualFree) {
        return;
    }

    // 先尝试mimalloc释放
    if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
        g_miMallocPool->Free(ptr);
        return;
    }

    // 再尝试TLSF释放
    if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
        g_tlsfPool->Free(ptr);
        return;
    }
}

void* MemoryPoolManager::Realloc(void* oldPtr, size_t newSize)
{
    if (!g_initialized) {
        // 明确调用带两个参数的版本，避免歧义
        if (!MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default)) {
            return nullptr;
        }
    }

    if (!oldPtr) {
        return Allocate(newSize);
    }

    if (newSize == 0) {
        Free(oldPtr);
        return nullptr;
    }

    // 特殊处理永久块
    if (IsPermanentBlock(oldPtr)) {
        // 分配新块并复制
        void* newPtr = Allocate(newSize);
        if (newPtr) {
            // 安全复制
            size_t copySize = min(GetBlockSizeInternal(oldPtr), newSize);
            if (copySize == 0) copySize = min(64, newSize);

            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                // 复制失败
                Free(newPtr);
                return nullptr;
            }
        }
        return newPtr;
    }

    // 先尝试mimalloc重分配
    if (g_miMallocPool && g_miMallocPool->IsFromPool(oldPtr)) {
        return g_miMallocPool->Realloc(oldPtr, newSize);
    }

    // 再尝试TLSF重分配
    if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
        return g_tlsfPool->Realloc(oldPtr, newSize);
    }

    // 如果都不是，则分配新块并复制
    void* newPtr = Allocate(newSize);
    if (newPtr) {
        // 尝试复制数据
        try {
            // 保守复制
            memcpy(newPtr, oldPtr, min(64, newSize));
        }
        catch (...) {
            // 复制失败
            Free(newPtr);
            return nullptr;
        }
    }

    return newPtr;
}

void* MemoryPoolManager::AllocateSafe(size_t size)
{
    // 确保已初始化
    if (!g_initialized) {
        // 明确调用带两个参数的版本，避免歧义
        if (!MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default)) {
            return nullptr;
        }
    }

    // 根据当前活跃池类型分配内存
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            return g_miMallocPool->AllocateSafe(size);
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            return g_tlsfPool->AllocateSafe(size);
        }
        break;
    }

    return nullptr;
}

void MemoryPoolManager::FreeSafe(void* ptr)
{
    if (!ptr || !g_initialized) return;

    // 特殊处理永久块
    if (IsPermanentBlock(ptr)) {
        return;
    }

    // 如果禁用实际释放，则跳过
    if (g_disableActualFree) {
        return;
    }

    // 不安全期特殊处理
    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSizeInternal(ptr));
        return;
    }

    // 先尝试mimalloc释放
    if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
        g_miMallocPool->FreeSafe(ptr);
        return;
    }

    // 再尝试TLSF释放
    if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
        g_tlsfPool->FreeSafe(ptr);
        return;
    }
}

void* MemoryPoolManager::ReallocSafe(void* oldPtr, size_t newSize)
{
    if (!g_initialized) {
        // 明确调用带两个参数的版本，避免歧义
        if (!MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default)) {
            return nullptr;
        }
    }

    if (!oldPtr) {
        return AllocateSafe(newSize);
    }

    if (newSize == 0) {
        FreeSafe(oldPtr);
        return nullptr;
    }

    // 特殊处理永久块
    if (IsPermanentBlock(oldPtr)) {
        // 分配新块并复制
        void* newPtr = AllocateSafe(newSize);
        if (newPtr) {
            // 安全复制
            size_t copySize = min(GetBlockSizeInternal(oldPtr), newSize);
            if (copySize == 0) copySize = min(64, newSize);

            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                // 复制失败
                FreeSafe(newPtr);
                return nullptr;
            }
        }
        return newPtr;
    }

    // 不安全期特殊处理
    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        void* newPtr = AllocateSafe(newSize);
        if (!newPtr) return nullptr;

        // 尝试复制数据
        try {
            size_t oldSize = GetBlockSizeInternal(oldPtr);
            if (oldSize > 0) {
                memcpy(newPtr, oldPtr, min(oldSize, newSize));
            }
            else {
                // 保守复制
                memcpy(newPtr, oldPtr, min(64, newSize));
            }
        }
        catch (...) {
            // 复制失败
            FreeSafe(newPtr);
            return nullptr;
        }

        // 不释放旧指针，而是放入延迟队列
        g_MemorySafety.EnqueueDeferredFree(oldPtr, GetBlockSizeInternal(oldPtr));
        return newPtr;
    }

    // 先尝试mimalloc重分配
    if (g_miMallocPool && g_miMallocPool->IsFromPool(oldPtr)) {
        return g_miMallocPool->ReallocSafe(oldPtr, newSize);
    }

    // 再尝试TLSF重分配
    if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
        return g_tlsfPool->ReallocSafe(oldPtr, newSize);
    }

    // 如果都不是，则分配新块并复制
    void* newPtr = AllocateSafe(newSize);
    if (newPtr) {
        // 尝试复制数据
        try {
            // 保守复制
            memcpy(newPtr, oldPtr, min(64, newSize));
        }
        catch (...) {
            // 复制失败
            FreeSafe(newPtr);
            return nullptr;
        }
    }

    return newPtr;
}

bool MemoryPoolManager::IsFromPool(void* ptr)
{
    if (!ptr || !g_initialized) return false;

    // 检查mimalloc池
    if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
        return true;
    }

    // 检查TLSF池
    if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
        return true;
    }

    return false;
}

size_t MemoryPoolManager::GetBlockSize(void* ptr)
{
    return GetBlockSizeInternal(ptr);
}

size_t MemoryPoolManager::GetUsedSize()
{
    size_t total = 0;

    // 累加两个内存池的使用量
    if (g_miMallocPool) {
        total += g_miMallocPool->GetUsedSize();
    }

    if (g_tlsfPool) {
        total += g_tlsfPool->GetUsedSize();
    }

    return total;
}

size_t MemoryPoolManager::GetTotalSize()
{
    size_t total = 0;

    // 累加两个内存池的总量
    if (g_miMallocPool) {
        total += g_miMallocPool->GetTotalSize();
    }

    if (g_tlsfPool) {
        total += g_tlsfPool->GetTotalSize();
    }

    return total;
}

void MemoryPoolManager::DisableMemoryReleasing()
{
    // 对两个内存池都禁用内存释放
    if (g_miMallocPool) {
        g_miMallocPool->DisableMemoryReleasing();
    }

    if (g_tlsfPool) {
        g_tlsfPool->DisableMemoryReleasing();
    }

    LogMessage("[MemoryPoolManager] 已禁用所有内存池的内存释放");
}

void MemoryPoolManager::CheckAndFreeUnusedPools()
{
    // 只对当前活跃池执行
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            g_miMallocPool->CheckAndFreeUnusedPools();
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            g_tlsfPool->CheckAndFreeUnusedPools();
        }
        break;
    }
}

void* MemoryPoolManager::CreateStabilizingBlock(size_t size, const char* purpose)
{
    // 使用系统内存分配稳定化块
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[MemoryPoolManager] 无法分配稳定化块: %zu 字节", size);
        return nullptr;
    }

    void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
    SetupCompatibleHeader(userPtr, size);

    LogMessage("[MemoryPoolManager] 创建稳定化块: %p (大小: %zu, 用途: %s)",
        userPtr, size, purpose ? purpose : "未知");

    return userPtr;
}

bool MemoryPoolManager::ValidatePointer(void* ptr)
{
    if (!ptr) return false;

    __try {
        // 尝试读取指针的第一个字节，验证可读
        volatile char test = *static_cast<char*>(ptr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void MemoryPoolManager::DisableActualFree()
{
    g_disableActualFree = true;
    LogMessage("[MemoryPoolManager] 已禁用实际内存释放");
}

void MemoryPoolManager::Preheat()
{
    LogMessage("[MemoryPoolManager] 开始预热当前内存池...");

    // 只对当前活跃池预热
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            // 预热操作
            // ...
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            // 针对TLSF的预热操作
            // ...
        }
        break;
    }

    LogMessage("[MemoryPoolManager] 内存池预热完成");
}

void MemoryPoolManager::HeapCollect()
{
    // 对当前活跃池执行垃圾收集
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            g_miMallocPool->HeapCollect();
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            g_tlsfPool->HeapCollect();
        }
        break;
    }
}

void MemoryPoolManager::PrintStats()
{
    LogMessage("[MemoryPoolManager] === 内存池管理器统计 ===");
    LogMessage("[MemoryPoolManager] 当前活跃内存池: %s",
        g_activePoolType.load() == PoolType::MiMalloc ? "mimalloc" : "TLSF");

    // 显示mimalloc统计
    if (g_miMallocPool) {
        LogMessage("[MemoryPoolManager] --- mimalloc统计 ---");
        g_miMallocPool->PrintStats();
    }

    // 显示TLSF统计
    if (g_tlsfPool) {
        LogMessage("[MemoryPoolManager] --- TLSF统计 ---");
        g_tlsfPool->PrintStats();
    }

    LogMessage("[MemoryPoolManager] 总内存使用: %zu KB", GetUsedSize() / 1024);
    LogMessage("[MemoryPoolManager] 总内存池大小: %zu KB", GetTotalSize() / 1024);
    LogMessage("[MemoryPoolManager] =====================");
}