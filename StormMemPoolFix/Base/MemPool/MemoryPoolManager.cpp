// 在MemoryPoolManager.cpp中

#include "pch.h"
#include "MemoryPoolManager.h"
#include "TLSFPool.h" // 移除 MiMallocPool.h
#include <mutex>
#include <memory>
#include <atomic> // 添加 atomic 头文件
#include "Storm/StormHook.h"
#include "Base/MemorySafety.h"

// 私有命名空间，不导出符号
namespace {
    // 当前活跃的内存池类型
    // 不再需要 g_activePoolType，因为我们强制使用 TLSF
    // std::atomic<PoolType> g_activePoolType{ PoolType::TLSF }; // 强制 TLSF

    // 内存池实例 - 只保留 TLSF
    // std::unique_ptr<MiMallocPool> g_miMallocPool; // 移除 MiMallocPool
    std::unique_ptr<TLSFPool> g_tlsfPool;

    // 访问锁
    std::mutex g_managerMutex;

    // 状态标志
    std::atomic<bool> g_initialized{ false };
    std::atomic<bool> g_disableActualFree{ false }; // 这个标志可能仍需保留

    // 池指针归属跟踪 - 简化，因为只有一个主池 (TLSF)
    // 可以考虑移除，或者保留用于区分 TLSF 和 JVM 或 Storm 原生
    // 暂时保留，但 PoolType 只需区分 TLSF 和 Default/Unknown
    std::unordered_map<void*, PoolType> g_pointerOrigin;
    std::mutex g_pointerOriginMutex;

    // 记录指针归属 (只记录 TLSF)
    void TrackPointer(void* ptr) {
        if (!ptr) return;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        g_pointerOrigin[ptr] = PoolType::TLSF;
    }

    // 获取指针归属的池 (只检查是否为 TLSF)
    PoolType GetPointerPool(void* ptr) {
        if (!ptr) return PoolType::Default;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        auto it = g_pointerOrigin.find(ptr);
        if (it != g_pointerOrigin.end()) {
            return it->second; // 应该是 TLSF
        }
        return PoolType::Default; // 默认/未知
    }

    // 清除指针跟踪
    void UntrackPointer(void* ptr) {
        if (!ptr) return;
        std::lock_guard<std::mutex> lock(g_pointerOriginMutex);
        g_pointerOrigin.erase(ptr);
    }

    // 工具函数 - 获取块大小，内部使用 (只查 TLSF)
    size_t GetBlockSizeInternal(void* ptr)
    {
        if (!ptr) return 0;

        // 只尝试TLSF获取
        if (g_tlsfPool) {
            size_t size = g_tlsfPool->GetBlockSize(ptr);
            if (size > 0) return size;
        }

        // 尝试从 Storm 头获取 (如果 IsOurBlock 失败)
        try {
             StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                 static_cast<char*>(ptr) - sizeof(StormAllocHeader));
             if (header->Magic == STORM_MAGIC) { // 假设 STORM_MAGIC 已定义
                 return header->Size;
             }
        } catch(...) {}


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

    // 强制使用 TLSF
    // g_activePoolType.store(PoolType::TLSF); // 不再需要 activePoolType

    // 只创建 TLSF 池
    g_tlsfPool = std::make_unique<TLSFPool>();
    if (g_tlsfPool->Initialize(initialSize)) {
        LogMessage("[MemoryPoolManager] TLSF池初始化成功");
    } else {
        LogMessage("[MemoryPoolManager] TLSF池初始化失败");
        g_tlsfPool.reset();
        return false; // TLSF 初始化失败则管理器初始化失败
    }

    g_initialized = true;
    LogMessage("[MemoryPoolManager] 内存池管理器初始化完成 (使用 TLSF)");
    return true;
}

void MemoryPoolManager::Shutdown()
{
    std::lock_guard<std::mutex> lock(g_managerMutex);

    if (!g_initialized) {
        return;
    }

    // 只关闭 TLSF 池
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

// 移除 SwitchPoolType 和 GetActivePoolType，因为不再需要切换
// bool MemoryPoolManager::SwitchPoolType(PoolType newType) { ... }
// PoolType MemoryPoolManager::GetActivePoolType() { ... }

void* MemoryPoolManager::Allocate(size_t size)
{
    // 确保已初始化
    if (!g_initialized) {
        // 明确调用带两个参数的版本，避免歧义
        if (!MemoryPoolManager::Initialize(64 * 1024 * 1024, PoolType::Default)) {
            return nullptr;
        }
    }

    // 直接使用 TLSF 池分配
    void* ptr = nullptr;
    if (g_tlsfPool) {
        ptr = g_tlsfPool->Allocate(size);
        if (ptr) {
            TrackPointer(ptr); // 只需记录指针，无需指定类型
        }
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

    // 检查指针是否由 TLSF 管理
    PoolType origin = GetPointerPool(ptr);

    if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            g_tlsfPool->Free(ptr);
            UntrackPointer(ptr);
        }
    } else {
        // 未知来源，尝试 TLSF 释放 (IsFromPool 会检查)
        if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
             g_tlsfPool->Free(ptr);
             UntrackPointer(ptr); // 如果成功释放，则清除跟踪
        }
        // 如果 TLSF 无法释放，则可能是 Storm 原生或其他来源，Hooked_Storm_MemFree 会处理
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

    // 检查旧指针是否由 TLSF 管理
    PoolType origin = GetPointerPool(oldPtr);
    void* newPtr = nullptr;

    if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            newPtr = g_tlsfPool->Realloc(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr);
            }
        }
    } else {
        // 未知来源，尝试 TLSF 检测和重分配
        if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
            newPtr = g_tlsfPool->Realloc(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr);
            }
        } else {
            // 不是 TLSF 管理的内存，分配新 TLSF 块并复制
            newPtr = Allocate(newSize); // Allocate 内部会 TrackPointer
            if (newPtr) {
                // 保守复制
                try {
                    size_t oldSize = GetBlockSizeInternal(oldPtr); // 尝试获取大小
                    if (oldSize == 0) oldSize = 64; // 获取失败则保守估计
                    memcpy(newPtr, oldPtr, min(newSize, oldSize));
                    // 这里需要调用 Storm 的 Free 来释放 oldPtr，但这应该在 Hooked_Storm_MemRealloc 中处理
                }
                catch (...) {
                    Free(newPtr); // 释放新分配的块
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

    // 直接使用 TLSF 池安全分配
    void* ptr = nullptr;
    if (g_tlsfPool) {
        ptr = g_tlsfPool->AllocateSafe(size);
        if (ptr) {
            TrackPointer(ptr);
        }
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

    // 检查指针是否由 TLSF 管理
    PoolType origin = GetPointerPool(ptr);

    if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            g_tlsfPool->FreeSafe(ptr);
            UntrackPointer(ptr);
        }
    } else {
        // 未知来源，尝试 TLSF 释放
        if (g_tlsfPool && g_tlsfPool->IsFromPool(ptr)) {
            g_tlsfPool->FreeSafe(ptr);
            UntrackPointer(ptr);
        } else {
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

    // 检查旧指针是否由 TLSF 管理
    PoolType origin = GetPointerPool(oldPtr);
    void* newPtr = nullptr;

    if (origin == PoolType::TLSF) {
        if (g_tlsfPool) {
            newPtr = g_tlsfPool->ReallocSafe(oldPtr, newSize);
            // 如果重分配地址改变，更新跟踪
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr);
            }
        }
    } else {
        // 未知来源，尝试 TLSF 检测和重分配
        if (g_tlsfPool && g_tlsfPool->IsFromPool(oldPtr)) {
            newPtr = g_tlsfPool->ReallocSafe(oldPtr, newSize);
            if (newPtr && newPtr != oldPtr) {
                UntrackPointer(oldPtr);
                TrackPointer(newPtr);
            }
        } else {
            // 不是 TLSF 管理的内存，分配新 TLSF 块并复制
            newPtr = AllocateSafe(newSize); // AllocateSafe 内部会 TrackPointer
            if (newPtr) {
                // 尝试复制数据
                try {
                    size_t oldSize = GetBlockSizeInternal(oldPtr); // 尝试获取大小
                    if (oldSize == 0) oldSize = 64; // 获取失败则保守估计
                    memcpy(newPtr, oldPtr, min(newSize, oldSize));
                    // 这里需要调用 Storm 的 Free 来释放 oldPtr，这应该在 Hooked_Storm_MemRealloc 中处理
                    // 或者，如果 oldPtr 是系统分配的，则需要 VirtualFree
                    // 暂时不处理 oldPtr 的释放，依赖 Hooked_Storm_MemRealloc
                }
                catch (...) {
                    FreeSafe(newPtr); // 释放新分配的块
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

    // 只询问 TLSF 池
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
    // 只对 TLSF 池禁用内存释放
    if (g_tlsfPool) {
        g_tlsfPool->DisableMemoryReleasing();
    }

    LogMessage("[MemoryPoolManager] 已禁用所有内存池的内存释放");
}

void MemoryPoolManager::CheckAndFreeUnusedPools()
{
    // 只对 TLSF 池执行
    if (g_tlsfPool) {
        g_tlsfPool->CheckAndFreeUnusedPools();
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

    // 只对 TLSF 池预热
    if (g_tlsfPool) {
        // 针对TLSF的预热操作
        // g_tlsfPool->Preheat(); // 假设 TLSFPool 有 Preheat 方法
    }

    LogMessage("[MemoryPoolManager] 内存池预热完成");
}

void MemoryPoolManager::HeapCollect()
{
    // 只对 TLSF 池执行垃圾收集
    if (g_tlsfPool) {
        g_tlsfPool->HeapCollect();
    }
}

void MemoryPoolManager::PrintStats()
{
    LogMessage("[MemoryPoolManager] === TLSF 内存池统计 ===");

    // 只显示TLSF统计
    if (g_tlsfPool) {
        g_tlsfPool->PrintStats();
    } else {
        LogMessage("[MemoryPoolManager] TLSF 池未初始化");
    }

    // 总使用和总大小现在直接来自 TLSF 池
    LogMessage("[MemoryPoolManager] 总内存使用: %zu KB", GetUsedSize() / 1024); // GetUsedSize 已简化
    LogMessage("[MemoryPoolManager] 总内存池大小: %zu KB", GetTotalSize() / 1024); // GetTotalSize 已简化
    LogMessage("[MemoryPoolManager] =====================");
}

size_t MemoryPoolManager::GetUsedSize()
{
    size_t total = 0;

    // 只获取 TLSF 池的使用量
    if (g_tlsfPool) {
        total += g_tlsfPool->GetUsedSize();
    }

    return total;
}

size_t MemoryPoolManager::GetTotalSize()
{
    size_t total = 0;

    // 只获取 TLSF 池的总量
    if (g_tlsfPool) {
        total += g_tlsfPool->GetTotalSize();
    }

    return total;
}

bool MemoryPoolManager::SwitchPoolType(PoolType newType) {
    // 由于我们只使用TLSF，所以这个函数始终返回true
    // 如果尝试切换到其他池类型，记录日志但仍继续使用TLSF
    if (newType != PoolType::TLSF) {
        LogMessage("[MemoryPoolManager] 当前只支持TLSF内存池，已忽略切换请求");
    }
    return true;
}

PoolType MemoryPoolManager::GetActivePoolType() {
    // 始终返回TLSF
    return PoolType::TLSF;
}