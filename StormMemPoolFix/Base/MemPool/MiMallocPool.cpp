// MiMallocPool.cpp
#include "MiMallocPool.h"
#include "Base/Logger.h"
#include "../../Storm/StormHook.h"
#include <Windows.h>
#include <Base/MemorySafety.h>

MiMallocPool::MiMallocPool() {
    // 构造函数不做实际初始化，等待Initialize调用
}

MiMallocPool::~MiMallocPool() {
    // 确保Shutdown被调用
    Shutdown();
}

bool MiMallocPool::Initialize(size_t initialSize) {
    if (m_mainHeap) {
        LogMessage("[MiMallocPool] 已初始化");
        return true;
    }

    // 1. 禁用急于提交内存 - 这有助于减少虚拟内存占用
    mi_option_set(mi_option_arena_eager_commit, 0);

    // 2. 减少内存归还延迟 - 让未使用内存更快归还系统
    mi_option_set(mi_option_purge_delay, 10);

    // 3. 设置较小的预留空间 - 如果总虚拟内存过高，这很关键
    mi_option_set(mi_option_arena_reserve, 16 * 1024);

    // 延迟提交 - 这可能会改善内存分配模式
    mi_option_set(mi_option_eager_commit_delay, 8);

    mi_option_set(mi_option_reset_decommits, 1);

    // 创建主要mimalloc堆
    m_mainHeap = mi_heap_new();
    if (!m_mainHeap) {
        LogMessage("[MiMallocPool] 无法创建mimalloc主堆");
        return false;
    }

    // 创建安全操作专用堆
    m_safeHeap = mi_heap_new();
    if (!m_safeHeap) {
        LogMessage("[MiMallocPool] 无法创建mimalloc安全堆");
        mi_heap_delete(m_mainHeap);
        m_mainHeap = nullptr;
        return false;
    }

    // 设置初始池大小
    m_totalPoolSize.store(initialSize);

    LogMessage("[MiMallocPool] mimalloc初始化完成，预留大小: %zu 字节", initialSize);
    return true;
}

void MiMallocPool::Shutdown() {
    if (m_disableMemoryReleasing.load()) {
        LogMessage("[MiMallocPool] 保留所有内存块，仅清理管理数据");
        m_mainHeap = nullptr;
        m_safeHeap = nullptr;
        return;
    }

    if (m_mainHeap) {
        mi_heap_destroy(m_mainHeap);
        m_mainHeap = nullptr;
    }

    if (m_safeHeap) {
        mi_heap_destroy(m_safeHeap);
        m_safeHeap = nullptr;
    }

    LogMessage("[MiMallocPool] mimalloc关闭完成");
}

void* MiMallocPool::Allocate(size_t size) {
    if (!m_mainHeap) {
        // 懒初始化
        Initialize(64 * 1024 * 1024);  // 默认64MB
        if (!m_mainHeap) return nullptr;
    }

    size_t lockIndex = get_shard_index(nullptr, size);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    void* ptr = mi_heap_malloc(m_mainHeap, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    return ptr;
}

void MiMallocPool::Free(void* ptr) {
    if (!m_mainHeap || !ptr) return;

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] 尝试释放永久块: %p，已忽略", ptr);
        return;
    }

    // 使用基于指针地址的分片锁
    size_t lockIndex = get_shard_index(ptr);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    // 先检查是否是mimalloc管理的内存
    bool isMainHeapPtr = mi_heap_check_owned(m_mainHeap, ptr);
    bool isSafeHeapPtr = m_safeHeap && mi_heap_check_owned(m_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // 如果不是mimalloc管理的内存，记录日志并跳过
        return;
    }

    // 现在安全地获取大小
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 根据所属堆选择释放方式
    if (isMainHeapPtr) {
        mi_free(ptr);
    }
    else if (isSafeHeapPtr) {
        mi_free(ptr);  // mimalloc会自动将指针路由到正确的堆
    }
}

void* MiMallocPool::Realloc(void* oldPtr, size_t newSize) {
    if (!m_mainHeap) return nullptr;
    if (!oldPtr) return Allocate(newSize);
    if (newSize == 0) {
        Free(oldPtr);
        return nullptr;
    }

    size_t oldLockIndex = get_shard_index(oldPtr);
    size_t newLockIndex = get_shard_index(nullptr, newSize);

    // 锁定两个分片
    if (oldLockIndex != newLockIndex) {
        // 按顺序锁定，避免死锁
        if (oldLockIndex < newLockIndex) {
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);

            size_t oldSize = mi_usable_size(oldPtr);
            void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

            if (newPtr) {
                if (oldSize > 0) {
                    m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
                m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
            }

            return newPtr;
        }
        else {
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);

            size_t oldSize = mi_usable_size(oldPtr);
            void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

            if (newPtr) {
                if (oldSize > 0) {
                    m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
                m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
            }

            return newPtr;
        }
    }
    else {
        std::lock_guard<std::mutex> lock(m_poolMutexes[oldLockIndex]);

        size_t oldSize = mi_usable_size(oldPtr);
        void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }

        return newPtr;
    }
}

void* MiMallocPool::AllocateSafe(size_t size) {
    if (!m_mainHeap) {
        // 懒初始化
        Initialize(64 * 1024 * 1024);  // 默认64MB
        if (!m_mainHeap) return nullptr;
    }

    // 注意：调用者应该已经持有了相应的分片锁

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 在不安全期直接用系统分配
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sysPtr) {
            LogMessage("[MiMallocPool] 不安全期间系统内存分配失败: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[MiMallocPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
        return sysPtr;
    }

    if (!m_safeHeap) {
        if (!m_mainHeap) {
            Initialize(64 * 1024 * 1024);
        }
        if (!m_safeHeap) return nullptr;
    }

    void* ptr = mi_heap_malloc(m_safeHeap, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    return ptr;
}

void MiMallocPool::FreeSafe(void* ptr) {
    if (!ptr) return;

    // 注意：调用者应该已经持有了相应的分片锁

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] 尝试释放永久块: %p，已忽略", ptr);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 将指针加入延迟释放队列
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        return;
    }

    // 检查是否是mimalloc管理的内存
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(m_mainHeap, ptr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(m_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // 如果不是mimalloc管理的内存，记录日志并跳过
        return;
    }

    // 获取大小并更新统计
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 根据所属堆选择释放方式
    if (isMainHeapPtr) {
        mi_free(ptr);
    }
    else if (isSafeHeapPtr) {
        mi_free(ptr);  // mimalloc会自动将指针路由到正确的堆
    }
}

void* MiMallocPool::ReallocSafe(void* oldPtr, size_t newSize) {
    if (!m_mainHeap) return nullptr;
    if (!oldPtr) return AllocateSafe(newSize);
    if (newSize == 0) {
        FreeSafe(oldPtr);
        return nullptr;
    }

    // 注意：调用者应该已经持有了相应的分片锁

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 分配+复制+延迟释放
        void* newPtr = AllocateSafe(newSize);
        if (!newPtr) return nullptr;

        // 尝试安全复制
        size_t oldSize = mi_usable_size(oldPtr);
        if (oldSize > 0) {
            size_t copySize = min(oldSize, newSize);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                LogMessage("[MiMallocPool] 不安全期间复制数据失败");
                return nullptr;
            }
        }
        else {
            // 如果无法获取大小，只复制少量数据
            try {
                memcpy(newPtr, oldPtr, min(64, newSize));
            }
            catch (...) {
                LogMessage("[MiMallocPool] 不安全期间复制数据失败");
                return nullptr;
            }
        }

        // 将oldPtr放入延迟释放队列（不释放，只记录）
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);

        return newPtr;
    }

    // 直接使用mimalloc的realloc功能
    void* newPtr = nullptr;

    // 检查是否是mimalloc管理的内存
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(m_mainHeap, oldPtr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(m_safeHeap, oldPtr);

    if (isMainHeapPtr) {
        size_t oldSize = mi_usable_size(oldPtr);
        newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }
    }
    else if (isSafeHeapPtr) {
        size_t oldSize = mi_usable_size(oldPtr);
        newPtr = mi_heap_realloc(m_safeHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }
    }
    else {
        // 不是我们管理的内存，分配新内存并复制
        newPtr = AllocateSafe(newSize);
        if (newPtr && oldPtr) {
            // 尝试拷贝一些数据，但我们不知道原块大小，只能保守估计
            try {
                memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
            }
            catch (...) {}
        }
    }

    return newPtr;
}

size_t MiMallocPool::GetUsedSize() {
    return m_usedSize.load(std::memory_order_relaxed);
}

size_t MiMallocPool::GetTotalSize() {
    // 确保总大小始终大于已用大小
    size_t currentUsed = GetUsedSize();
    size_t calculatedTotal = m_totalPoolSize.load(std::memory_order_relaxed);

    // 如果使用量超过了记录的总量
    if (currentUsed > calculatedTotal) {
        // 更新总大小为当前使用量的150%
        size_t newTotal = currentUsed * 3 / 2;
        m_totalPoolSize.store(newTotal, std::memory_order_relaxed);
        return newTotal;
    }

    return calculatedTotal;
}

bool MiMallocPool::IsFromPool(void* ptr) {
    if (!ptr) return false;

    __try {
        // 检查是否为mimalloc管理的内存
        if (m_mainHeap && mi_heap_check_owned(m_mainHeap, ptr)) {
            return true;
        }

        if (m_safeHeap && mi_heap_check_owned(m_safeHeap, ptr)) {
            return true;
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 访问指针出现异常
        return false;
    }
}

size_t MiMallocPool::GetBlockSize(void* ptr) {
    if (!ptr) return 0;

    __try {
        // 尝试获取StormHeader信息
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }
    }
    catch (...) {
        // 头部访问失败
    }

    // 检查是否为mimalloc管理的内存
    bool isMainHeapPtr = false;
    bool isSafeHeapPtr = false;

    try {
        if (m_mainHeap) {
            isMainHeapPtr = mi_heap_check_owned(m_mainHeap, ptr);
        }
    }
    catch (...) {}

    try {
        if (m_safeHeap) {
            isSafeHeapPtr = mi_heap_check_owned(m_safeHeap, ptr);
        }
    }
    catch (...) {}

    if (isMainHeapPtr || isSafeHeapPtr) {
        // 使用mimalloc获取块大小
        try {
            return mi_usable_size(ptr);
        }
        catch (...) {}
    }

    // 如果都不是，返回0表示未知大小
    return 0;
}

void MiMallocPool::PrintStats() {
    if (!m_mainHeap) {
        LogMessage("[MiMallocPool] mimalloc未初始化");
        return;
    }

    LogMessage("[MiMallocPool] === mimalloc内存池统计 ===");
    LogMessage("[MiMallocPool] 已用内存: %zu KB", m_usedSize.load() / 1024);

    // 收集mimalloc的统计信息 (mimalloc本身也有统计功能)
    // 打印mimalloc自己的统计信息
    mi_stats_print(NULL);

    LogMessage("[MiMallocPool] mimalloc统计完成");
}

void MiMallocPool::CheckAndFreeUnusedPools() {
    // 强制mimalloc收集可回收的内存
    if (m_mainHeap) {
        mi_heap_collect(m_mainHeap, true);
    }

    if (m_safeHeap) {
        mi_heap_collect(m_safeHeap, true);
    }
}

void MiMallocPool::DisableMemoryReleasing() {
    m_disableMemoryReleasing.store(true);
    LogMessage("[MiMallocPool] 已禁用内存释放，所有内存将保留到进程结束");
}

void MiMallocPool::HeapCollect() {
    if (m_mainHeap) {
        mi_heap_collect(m_mainHeap, true);
    }
}

void* MiMallocPool::CreateStabilizingBlock(size_t size, const char* purpose) {
    // 使用系统分配确保稳定性
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[MiMallocPool] 无法分配稳定化块: %zu", size);
        return nullptr;
    }

    void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);

    // 确保正确设置头部
    try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(rawPtr);
        header->HeapPtr = SPECIAL_MARKER;  // 特殊标记，表示我们管理的块
        header->Size = static_cast<DWORD>(size);
        header->AlignPadding = 0;
        header->Flags = 0x4;  // 标记为大块VirtualAlloc
        header->Magic = STORM_MAGIC;
    }
    catch (...) {
        LogMessage("[MiMallocPool] 设置稳定化块头部失败: %p", rawPtr);
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return nullptr;
    }

    LogMessage("[MiMallocPool] 创建稳定化块: %p (大小: %zu, 用途: %s)",
        userPtr, size, purpose ? purpose : "未知");

    return userPtr;
}

bool MiMallocPool::ValidatePointer(void* ptr) {
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

void MiMallocPool::Preheat() {
    LogMessage("[MiMallocPool] 开始预热内存池...");

    // 根据常见分配大小进行预热
    const std::pair<size_t, int> commonSizes[] = {
        {4, 50},      // 4字节，预热50个
        {16, 30},     // 16字节，预热30个
        {32, 20},     // 32字节，预热20个
        {72, 15},     // 72字节，预热15个
        {108, 15},    // 108字节，预热15个
        {128, 10},    // 128字节，预热10个
        {192, 10},    // 192字节，预热10个
        {256, 10},    // 256字节，预热10个
        {512, 5},     // 512字节，预热5个
        {1024, 5},    // 1KB，预热5个
        {4096, 3},    // 4KB，预热3个
        {16384, 2},   // 16KB，预热2个
        {65536, 1},   // 64KB，预热1个
        {262144, 1},  // 256KB，预热1个
    };

    std::vector<void*> preheatedBlocks;

    for (const auto& [size, count] : commonSizes) {
        for (int i = 0; i < count; i++) {
            void* ptr = mi_heap_malloc(m_mainHeap, size);
            if (ptr) preheatedBlocks.push_back(ptr);
        }
    }

    LogMessage("[MiMallocPool] 预热分配了 %zu 个内存块", preheatedBlocks.size());

    // 释放一半预热的块，保留一半在缓存中
    for (size_t i = 0; i < preheatedBlocks.size() / 2; i++) {
        mi_free(preheatedBlocks[i]);
    }

    LogMessage("[MiMallocPool] 内存池预热完成，释放了 %zu 个内存块", preheatedBlocks.size() / 2);
}

void MiMallocPool::DisableActualFree() {
    DisableMemoryReleasing();  // 调用已实现的函数
}

size_t MiMallocPool::get_shard_index(void* ptr, size_t size) {
    size_t hash;
    if (ptr) {
        // FNV-1a哈希的简化版
        hash = (reinterpret_cast<uintptr_t>(ptr) * 2654435761) >> 16;
    }
    else {
        // 对于不同大小的分配使用更科学的分布
        if (size <= 128) {
            hash = size / 16;
        }
        else if (size <= 4096) {
            hash = 8 + (size - 128) / 64;
        }
        else if (size <= 65536) {
            hash = 70 + (size / 1024);
        }
        else {
            hash = 134 + (size / 16384);
        }
    }
    return hash % LOCK_SHARDS;
}