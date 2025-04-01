// TLSFPool.cpp
#include "TLSFPool.h"
#include "Base/Logger.h"
#include "StormHook.h"
#include <Windows.h>
#include <Storm/StormHook.h>
#include <Base/MemorySafety.h>

TLSFPool::TLSFPool() {
    // 构造函数不做实际初始化，等待Initialize调用
}

TLSFPool::~TLSFPool() {
    // 确保Shutdown被调用
    Shutdown();
}

bool TLSFPool::Initialize(size_t initialSize) {
    if (m_tlsfPool) {
        LogMessage("[TLSFPool] 已初始化");
        return true;
    }

    // 分配内存池空间
    m_poolMemory = VirtualAlloc(NULL, initialSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!m_poolMemory) {
        LogMessage("[TLSFPool] 无法分配主池内存: %zu 字节", initialSize);
        return false;
    }

    // 创建TLSF池
    m_tlsfPool = tlsf_create(m_poolMemory);
    if (!m_tlsfPool) {
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
        LogMessage("[TLSFPool] 无法创建TLSF主池");
        return false;
    }

    // 添加主内存池
    void* pool = tlsf_add_pool(m_tlsfPool,
        static_cast<char*>(m_poolMemory) + tlsf_size(),
        initialSize - tlsf_size());
    if (!pool) {
        tlsf_destroy(m_tlsfPool);
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
        m_tlsfPool = nullptr;
        LogMessage("[TLSFPool] 无法添加主内存池");
        return false;
    }

    // 创建安全池
    size_t safePoolSize = initialSize / 10; // 10%的大小
    m_safePoolMemory = VirtualAlloc(NULL, safePoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (m_safePoolMemory) {
        m_safeTlsfPool = tlsf_create(m_safePoolMemory);
        if (m_safeTlsfPool) {
            void* safePool = tlsf_add_pool(m_safeTlsfPool,
                static_cast<char*>(m_safePoolMemory) + tlsf_size(),
                safePoolSize - tlsf_size());
            if (!safePool) {
                tlsf_destroy(m_safeTlsfPool);
                VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
                m_safePoolMemory = nullptr;
                m_safeTlsfPool = nullptr;
                LogMessage("[TLSFPool] 无法添加安全内存池，继续使用主池");
            }
        }
        else {
            VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
            m_safePoolMemory = nullptr;
            LogMessage("[TLSFPool] 无法创建TLSF安全池，继续使用主池");
        }
    }

    // 设置池大小
    m_totalPoolSize.store(initialSize);

    LogMessage("[TLSFPool] TLSF初始化完成，预留大小: %zu 字节", initialSize);
    return true;
}

void TLSFPool::Shutdown() {
    if (m_disableMemoryReleasing.load()) {
        LogMessage("[TLSFPool] 保留所有内存块，仅清理管理数据");
        m_tlsfPool = nullptr;
        m_poolMemory = nullptr;
        m_safeTlsfPool = nullptr;
        m_safePoolMemory = nullptr;
        return;
    }

    // 清理全局追踪表
    {
        std::lock_guard<std::mutex> lock(m_trackingMutex);
        m_allocatedBlocks.clear();
    }

    // 销毁TLSF池
    if (m_safeTlsfPool) {
        tlsf_destroy(m_safeTlsfPool);
        m_safeTlsfPool = nullptr;
    }

    if (m_safePoolMemory) {
        VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
        m_safePoolMemory = nullptr;
    }

    if (m_tlsfPool) {
        tlsf_destroy(m_tlsfPool);
        m_tlsfPool = nullptr;
    }

    if (m_poolMemory) {
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
    }

    LogMessage("[TLSFPool] TLSF关闭完成");
}

void* TLSFPool::Allocate(size_t size) {
    if (!m_tlsfPool) {
        // 懒初始化
        Initialize(64 * 1024 * 1024);  // 默认64MB
        if (!m_tlsfPool) return nullptr;
    }

    size_t lockIndex = get_shard_index(nullptr, size);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    void* ptr = tlsf_malloc(m_tlsfPool, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);

        // 记录分配
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        m_allocatedBlocks[ptr] = size;
    }

    return ptr;
}

void TLSFPool::Free(void* ptr) {
    if (!m_tlsfPool || !ptr) return;

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] 尝试释放永久块: %p，已忽略", ptr);
        return;
    }

    size_t lockIndex = get_shard_index(ptr);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    // 查找记录的块大小
    size_t size = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(ptr);
        if (it != m_allocatedBlocks.end()) {
            size = it->second;
            m_allocatedBlocks.erase(it);
        }
    }

    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 释放内存
    tlsf_free(m_tlsfPool, ptr);
}

void* TLSFPool::Realloc(void* oldPtr, size_t newSize) {
    if (!m_tlsfPool) return nullptr;
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
            return ReallocInternal(oldPtr, newSize);
        }
        else {
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);
            return ReallocInternal(oldPtr, newSize);
        }
    }
    else {
        std::lock_guard<std::mutex> lock(m_poolMutexes[oldLockIndex]);
        return ReallocInternal(oldPtr, newSize);
    }
}

void* TLSFPool::AllocateSafe(size_t size) {
    if (!m_tlsfPool) {
        // 懒初始化
        Initialize(64 * 1024 * 1024);
        if (!m_tlsfPool) return nullptr;
    }

    // 注意：调用者应该已经持有了相应的分片锁

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期使用系统分配
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sysPtr) {
            LogMessage("[TLSFPool] 不安全期间系统内存分配失败: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[TLSFPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
        return sysPtr;
    }

    // 优先使用安全池
    void* ptr = nullptr;
    if (m_safeTlsfPool) {
        ptr = tlsf_malloc(m_safeTlsfPool, size);
    }

    // 安全池分配失败，回退到主池
    if (!ptr && m_tlsfPool) {
        ptr = tlsf_malloc(m_tlsfPool, size);
    }

    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);

        // 记录分配
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        m_allocatedBlocks[ptr] = size;
    }

    return ptr;
}

void TLSFPool::FreeSafe(void* ptr) {
    if (!ptr) return;

    // 注意：调用者应该已经持有了相应的分片锁

    // 避免释放永久块
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] 尝试释放永久块: %p，已忽略", ptr);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // 不安全期处理: 将指针加入延迟释放队列
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        return;
    }

    // 获取块大小并更新统计
    size_t size = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(ptr);
        if (it != m_allocatedBlocks.end()) {
            size = it->second;
            m_allocatedBlocks.erase(it);
        }
    }

    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // 判断是否来自安全池
    bool isSafePoolPtr = m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool));
    bool isMainPoolPtr = m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool));

    // 根据所属池选择释放方式
    if (isSafePoolPtr) {
        tlsf_free(m_safeTlsfPool, ptr);
    }
    else if (isMainPoolPtr) {
        tlsf_free(m_tlsfPool, ptr);
    }
    else {
        // 未知来源，使用VirtualFree
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void* TLSFPool::ReallocSafe(void* oldPtr, size_t newSize) {
    if (!m_tlsfPool) return nullptr;
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

        // 尝试获取旧块大小
        size_t oldSize = GetBlockSize(oldPtr);

        // 尝试复制数据
        size_t copySize = oldSize > 0 ? min(oldSize, newSize) : min(newSize, (size_t)64);
        try {
            memcpy(newPtr, oldPtr, copySize);
        }
        catch (...) {
            LogMessage("[TLSFPool] 不安全期间复制数据失败");
            FreeSafe(newPtr);
            return nullptr;
        }

        // 不释放旧指针，而是放入延迟队列
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        return newPtr;
    }

    // 判断是否来自安全池
    bool isSafePoolPtr = m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool));
    bool isMainPoolPtr = m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool));

    // 获取旧块大小
    size_t oldSize = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(oldPtr);
        if (it != m_allocatedBlocks.end()) {
            oldSize = it->second;
        }
    }

    void* newPtr = nullptr;

    // 根据来源池选择重分配方式
    if (isSafePoolPtr) {
        newPtr = tlsf_realloc(m_safeTlsfPool, oldPtr, newSize);
    }
    else if (isMainPoolPtr) {
        newPtr = tlsf_realloc(m_tlsfPool, oldPtr, newSize);
    }
    else {
        // 未知来源，分配新内存并复制
        newPtr = AllocateSafe(newSize);
        if (newPtr && oldPtr) {
            size_t copySize = oldSize > 0 ? min(oldSize, newSize) : min(newSize, (size_t)64);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                FreeSafe(newPtr);
                return nullptr;
            }

            // 将旧指针加入延迟释放队列
            g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        }
    }

    if (newPtr) {
        // 更新统计和跟踪信息
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);

        // 如果指针变化，移除旧记录
        if (newPtr != oldPtr) {
            auto it = m_allocatedBlocks.find(oldPtr);
            if (it != m_allocatedBlocks.end()) {
                m_allocatedBlocks.erase(it);
            }

            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
        }

        // 添加新记录
        m_allocatedBlocks[newPtr] = newSize;
        m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    return newPtr;
}

size_t TLSFPool::GetUsedSize() {
    return m_usedSize.load(std::memory_order_relaxed);
}

size_t TLSFPool::GetTotalSize() {
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

bool TLSFPool::IsFromPool(void* ptr) {
    if (!ptr) return false;

    __try {
        // 检查是否为TLSF管理的内存
        if (m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool))) {
            return true;
        }

        if (m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool))) {
            return true;
        }

        // 检查全局跟踪表
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        return m_allocatedBlocks.find(ptr) != m_allocatedBlocks.end();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 访问指针出现异常
        return false;
    }
}

size_t TLSFPool::GetBlockSize(void* ptr) {
    if (!ptr) return 0;

    // 尝试从跟踪表获取大小
    std::lock_guard<std::mutex> trackLock(m_trackingMutex);
    auto it = m_allocatedBlocks.find(ptr);
    if (it != m_allocatedBlocks.end()) {
        return it->second;
    }

    // 尝试从TLSF获取大小
    return tlsf_block_size(ptr);
}

void TLSFPool::PrintStats() {
    if (!m_tlsfPool) {
        LogMessage("[TLSFPool] TLSF未初始化");
        return;
    }

    LogMessage("[TLSFPool] === TLSF内存池统计 ===");
    LogMessage("[TLSFPool] 已用内存: %zu KB", m_usedSize.load() / 1024);
    LogMessage("[TLSFPool] 总内存: %zu KB", m_totalPoolSize.load() / 1024);

    // 块大小统计
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        LogMessage("[TLSFPool] 跟踪块数量: %zu", m_allocatedBlocks.size());
    }

    LogMessage("[TLSFPool] TLSF统计完成");
}

void TLSFPool::CheckAndFreeUnusedPools() {
    // TLSF没有自动池回收机制，这里只做日志记录
    LogMessage("[TLSFPool] CheckAndFreeUnusedPools - TLSF没有自动池回收机制");
}

void TLSFPool::DisableMemoryReleasing() {
    m_disableMemoryReleasing.store(true);
    LogMessage("[TLSFPool] 已禁用内存释放，所有内存将保留到进程结束");
}

void TLSFPool::HeapCollect() {
    // TLSF没有垃圾回收机制，这里可以手动整理碎片
    LogMessage("[TLSFPool] HeapCollect - TLSF没有自动垃圾回收机制");
}

void* TLSFPool::CreateStabilizingBlock(size_t size, const char* purpose) {
    // 使用系统分配确保稳定性
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[TLSFPool] 无法分配稳定化块: %zu", size);
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
        LogMessage("[TLSFPool] 设置稳定化块头部失败: %p", rawPtr);
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return nullptr;
    }

    LogMessage("[TLSFPool] 创建稳定化块: %p (大小: %zu, 用途: %s)",
        userPtr, size, purpose ? purpose : "未知");

    return userPtr;
}

bool TLSFPool::ValidatePointer(void* ptr) {
    if (!ptr) return false;

    __try {
        // 尝试读取指针的第一个字节，验证可读
        volatile char test = *static_cast<char*>(ptr);

        // 检查全局跟踪表
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        return m_allocatedBlocks.find(ptr) != m_allocatedBlocks.end();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void TLSFPool::Preheat() {
    if (!m_tlsfPool) {
        Initialize(64 * 1024 * 1024);  // 默认64MB
        if (!m_tlsfPool) return;
    }

    LogMessage("[TLSFPool] 开始预热内存池...");

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
            void* ptr = tlsf_malloc(m_tlsfPool, size);
            if (ptr) {
                preheatedBlocks.push_back(ptr);

                // 记录分配
                std::lock_guard<std::mutex> trackLock(m_trackingMutex);
                m_allocatedBlocks[ptr] = size;
                m_usedSize.fetch_add(size, std::memory_order_relaxed);
            }
        }
    }

    LogMessage("[TLSFPool] 预热分配了 %zu 个内存块", preheatedBlocks.size());

    // 释放一半预热的块，保留一半在缓存中
    for (size_t i = 0; i < preheatedBlocks.size() / 2; i++) {
        Free(preheatedBlocks[i]);
    }

    LogMessage("[TLSFPool] 内存池预热完成，释放了 %zu 个内存块", preheatedBlocks.size() / 2);
}

void TLSFPool::DisableActualFree() {
    DisableMemoryReleasing();  // 调用已实现的函数
}

size_t TLSFPool::get_shard_index(void* ptr, size_t size) {
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