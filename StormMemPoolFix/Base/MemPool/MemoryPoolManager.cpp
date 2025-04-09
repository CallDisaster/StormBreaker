// 在MemoryPoolManager.cpp中

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

    // 池指针归属跟踪 - 用于避免交叉释放
    std::unordered_map<void*, PoolType> g_pointerOrigin;
    std::mutex g_pointerOriginMutex;

    // 记录指针归属
    void TrackPointer(void* ptr, PoolType pool) {
        if (!ptr) return;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        g_pointerOrigin[ptr] = pool;
    }

    // 获取指针归属的池
    PoolType GetPointerPool(void* ptr) {
        if (!ptr) return PoolType::Default;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        auto it = g_pointerOrigin.find(ptr);
        if (it != g_pointerOrigin.end()) {
            return it->second;
        }
        return PoolType::Default; // 默认
    }

    // 清除指针跟踪
    void UntrackPointer(void* ptr) {
        if (!ptr) return;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        g_pointerOrigin.erase(ptr);
    }

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

    bool mimalloc_ok = false;
    bool tlsf_ok = false;

    // 创建主要池 (mimalloc)
    g_miMallocPool = std::make_unique<MiMallocPool>();
    if (g_miMallocPool->Initialize(initialSize)) {
        mimalloc_ok = true;
        LogMessage("[MemoryPoolManager] mimalloc池初始化成功");
    }
    else {
        LogMessage("[MemoryPoolManager] mimalloc池初始化失败");
        g_miMallocPool.reset();
    }

    // 创建备用池 (TLSF) - 延迟初始化，需要用时才初始化
    g_tlsfPool = std::make_unique<TLSFPool>();
    if (g_tlsfPool->Initialize(initialSize)) {
        tlsf_ok = true;
        LogMessage("[MemoryPoolManager] TLSF池初始化成功");
    }
    else {
        LogMessage("[MemoryPoolManager] TLSF池初始化失败");
        g_tlsfPool.reset();
    }

    // 根据初始化结果设置默认池
    if (poolType == PoolType::TLSF && !tlsf_ok) {
        if (mimalloc_ok) {
            LogMessage("[MemoryPoolManager] TLSF初始化失败，回退到mimalloc");
            g_activePoolType.store(PoolType::MiMalloc);
        }
        else {
            LogMessage("[MemoryPoolManager] 所有内存池初始化失败");
            return false;
        }
    }
    else if (poolType == PoolType::MiMalloc && !mimalloc_ok) {
        if (tlsf_ok) {
            LogMessage("[MemoryPoolManager] mimalloc初始化失败，回退到TLSF");
            g_activePoolType.store(PoolType::TLSF);
        }
        else {
            LogMessage("[MemoryPoolManager] 所有内存池初始化失败");
            return false;
        }
    }

    g_initialized = true;
    LogMessage("[MemoryPoolManager] 内存池管理器初始化完成，当前使用: %s",
        g_activePoolType.load() == PoolType::MiMalloc ? "mimalloc" : "TLSF");
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

    // 清空指针追踪表
    {
        std::lock_guard<std::mutex> track_lock(g_pointerOriginMutex);
        g_pointerOrigin.clear();
    }

    g_initialized = false;
    LogMessage("[MemoryPoolManager] 所有内存池已关闭");
}

bool MemoryPoolManager::SwitchPoolType(PoolType newType)
{
    if (!g_initialized) {
        // 尝试初始化
        if (!Initialize(64 * 1024 * 1024, newType)) {
            return false;
        }
    }

    if (newType == g_activePoolType) {
        // 已经是当前类型
        return true;
    }

    std::lock_guard<std::mutex> lock(g_managerMutex);

    // 检查目标池是否可用
    if (newType == PoolType::MiMalloc && !g_miMallocPool) {
        LogMessage("[MemoryPoolManager] 无法切换到mimalloc: 池不可用");
        return false;
    }

    if (newType == PoolType::TLSF && !g_tlsfPool) {
        LogMessage("[MemoryPoolManager] 无法切换到TLSF: 池不可用");
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
    void* ptr = nullptr;
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            ptr = g_miMallocPool->Allocate(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::MiMalloc);
            }
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            ptr = g_tlsfPool->Allocate(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::TLSF);
            }
        }
        break;

    default:
        // 默认使用mimalloc
        if (g_miMallocPool) {
            ptr = g_miMallocPool->Allocate(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::MiMalloc);
            }
        }
        break;
    }

    return ptr;
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

    // 检查指针归属并使用对应池释放
    PoolType origin = GetPointerPool(ptr);

    if (origin == PoolType::MiMalloc) {
        if (g_miMallocPool) {
            g_miMallocPool->Free(ptr);
            UntrackPointer(ptr);
        }
    }
    else if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            g_tlsfPool->Free(ptr);
            UntrackPointer(ptr);
        }
    }
    else {
        // 未知来源，尝试两种池都释放
        bool freed = false;
        if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
            g_miMallocPool->Free(ptr);
            freed = true;
        }
        else if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
            g_tlsfPool->Free(ptr);
            freed = true;
        }

        if (freed) {
            UntrackPointer(ptr);
        }
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

    // 根据指针归属选择池重分配
    PoolType origin = GetPointerPool(oldPtr);
    void* newPtr = nullptr;

    if (origin == PoolType::MiMalloc) {
        if (g_miMallocPool) {
            newPtr = g_miMallocPool->Realloc(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::MiMalloc);
            }
        }
    }
    else if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            newPtr = g_tlsfPool->Realloc(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::TLSF);
            }
        }
    }
    else {
        // 未知来源，尝试直接检测
        if (g_miMallocPool && g_miMallocPool->IsFromPool(oldPtr)) {
            newPtr = g_miMallocPool->Realloc(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::MiMalloc);
            }
        }
        else if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
            newPtr = g_tlsfPool->Realloc(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::TLSF);
            }
        }
        else {
            // 不是我们的池管理的内存，重新分配新块并复制
            newPtr = Allocate(newSize);
            if (newPtr) {
                // 保守复制
                try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
                }
                catch (...) {
                    Free(newPtr);
                    return nullptr;
                }
            }
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

    // 不安全期检查
    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 使用系统分配，避免内存池操作
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!sysPtr) {
            LogMessage("[MemoryPoolManager] 不安全期系统内存分配失败: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[MemoryPoolManager] 不安全期使用系统内存: %p, 大小: %zu", userPtr, size);
        return sysPtr;
    }

    // 根据当前活跃池类型分配内存
    void* ptr = nullptr;
    switch (g_activePoolType.load()) {
    case PoolType::MiMalloc:
        if (g_miMallocPool) {
            ptr = g_miMallocPool->AllocateSafe(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::MiMalloc);
            }
        }
        break;

    case PoolType::TLSF:
        if (g_tlsfPool) {
            ptr = g_tlsfPool->AllocateSafe(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::TLSF);
            }
        }
        break;

    default:
        // 默认使用mimalloc
        if (g_miMallocPool) {
            ptr = g_miMallocPool->AllocateSafe(size);
            if (ptr) {
                TrackPointer(ptr, PoolType::MiMalloc);
            }
        }
        break;
    }

    return ptr;
}

void MemoryPoolManager::FreeSafe(void* ptr)
{
    if (!ptr) return;

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

    // 检查指针归属并使用对应池释放
    PoolType origin = GetPointerPool(ptr);

    if (origin == PoolType::MiMalloc) {
        if (g_miMallocPool) {
            g_miMallocPool->FreeSafe(ptr);
            UntrackPointer(ptr);
        }
    }
    else if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            g_tlsfPool->FreeSafe(ptr);
            UntrackPointer(ptr);
        }
    }
    else {
        // 未知来源，尝试两种池都释放
        bool freed = false;
        if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
            g_miMallocPool->FreeSafe(ptr);
            freed = true;
        }
        else if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
            g_tlsfPool->FreeSafe(ptr);
            freed = true;
        }

        if (freed) {
            UntrackPointer(ptr);
        }
        else {
            // 无法确定来源，加入延迟释放队列
            g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSizeInternal(ptr));
        }
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

    // 根据指针归属选择池重分配
    PoolType origin = GetPointerPool(oldPtr);
    void* newPtr = nullptr;

    if (origin == PoolType::MiMalloc) {
        if (g_miMallocPool) {
            newPtr = g_miMallocPool->ReallocSafe(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::MiMalloc);
            }
        }
    }
    else if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            newPtr = g_tlsfPool->ReallocSafe(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::TLSF);
            }
        }
    }
    else {
        // 未知来源，尝试直接检测
        if (g_miMallocPool && g_miMallocPool->IsFromPool(oldPtr)) {
            newPtr = g_miMallocPool->ReallocSafe(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::MiMalloc);
            }
        }
        else if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
            newPtr = g_tlsfPool->ReallocSafe(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr, PoolType::TLSF);
            }
        }
        else {
            // 不是我们的池管理的内存，分配新块并复制
            newPtr = AllocateSafe(newSize);
            if (newPtr) {
                // 尝试复制数据
                try {
                    // 保守复制
                    memcpy(newPtr, oldPtr, min(64, newSize));
                }
                catch (...) {
                    FreeSafe(newPtr);
                    return nullptr;
                }
            }
        }
    }

    return newPtr;
}

bool MemoryPoolManager::IsFromPool(void* ptr)
{
    if (!ptr || !g_initialized) return false;

    // 优先通过指针归属表检查
    PoolType origin = GetPointerPool(ptr);
    if (origin == PoolType::MiMalloc || origin == PoolType::TLSF) {
        return true;
    }

    // 然后直接询问各池
    if (g_miMallocPool && g_miMallocPool->IsFromPool(ptr)) {
        return true;
    }

    if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
        return true;
    }

    return false;
}

size_t MemoryPoolManager::GetBlockSize(void* ptr)
{
    return GetBlockSizeInternal(ptr);
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
    // 使用系统内存分配稳定化块，保证不受其他池影响
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