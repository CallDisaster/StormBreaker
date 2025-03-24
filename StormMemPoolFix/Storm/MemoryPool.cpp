#include "pch.h"
#include "MemoryPool.h"
#include <Windows.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cassert>
#include <dbghelp.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "StormHook.h"
#include "Base/MemorySafety.h"


#pragma comment(lib, "dbghelp.lib")

// ------- 参数可自行调整 -------
static constexpr std::size_t BlockSize    = 0x28A8;
static constexpr std::size_t PoolCapacity = 256; // 最多多少块，看你需求调整
// --------------------------------

// 每块前面的头部，用来识别是不是本池分配
struct BlockHeader {
    unsigned magic;
};

// 约定魔数
static constexpr unsigned POOL_MAGIC = 0xDEADBEEF;

// 整个池的总内存占用（含头部）
static constexpr std::size_t RealBlockSize = BlockSize + sizeof(BlockHeader);

// （演示）使用一个静态数组，长度为 PoolCapacity，每块大小为 RealBlockSize
static alignas(std::max_align_t) unsigned char s_poolMemory[PoolCapacity][RealBlockSize];

// 是否正在使用
static bool s_usedFlags[PoolCapacity];

// 统计当前池已使用的大小(累加每次分配时的块大小 RealBlockSize)，防止超 0x7FFFFFFF
static std::atomic<size_t> s_totalUsage{ 0 };

// 互斥保护
static std::mutex s_mutex;

// 在适当的头文件中
namespace JVM_MemPool {
    // 私有变量
    static mi_heap_t* g_jvmHeap = nullptr;
    static std::mutex g_jvmMutex;
    static std::unordered_map<void*, size_t> g_jvmBlocks;

    // 初始化
    void Initialize() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);
        if (!g_jvmHeap) {
            g_jvmHeap = mi_heap_new();
            if (g_jvmHeap) {
                LogMessage("[JVM_MemPool] mimalloc JVM堆创建成功");
            }
            else {
                LogMessage("[JVM_MemPool] mimalloc JVM堆创建失败");
            }
        }
    }

    // 分配
    void* Allocate(size_t size) {
        std::lock_guard<std::mutex> lock(g_jvmMutex);
        if (!g_jvmHeap) {
            Initialize();
            if (!g_jvmHeap) return nullptr;
        }

        void* ptr = mi_heap_malloc(g_jvmHeap, size);
        if (ptr) {
            g_jvmBlocks[ptr] = size;
            //LogMessage("[JVM_MemPool] 分配: %p, 大小: %zu", ptr, size);
        }

        return ptr;
    }

    // 释放
    void Free(void* ptr) {
        if (!ptr) return;

        std::lock_guard<std::mutex> lock(g_jvmMutex);
        auto it = g_jvmBlocks.find(ptr);
        if (it != g_jvmBlocks.end()) {
            g_jvmBlocks.erase(it);
            mi_free(ptr);
            //LogMessage("[JVM_MemPool] 释放: %p", ptr);
        }
    }

    // 重新分配
    void* Realloc(void* ptr, size_t newSize) {
        if (!ptr) return Allocate(newSize);
        if (newSize == 0) {
            Free(ptr);
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_jvmMutex);
        auto it = g_jvmBlocks.find(ptr);
        if (it != g_jvmBlocks.end()) {
            void* newPtr = mi_heap_realloc(g_jvmHeap, ptr, newSize);
            if (newPtr) {
                g_jvmBlocks.erase(it);
                g_jvmBlocks[newPtr] = newSize;
                //LogMessage("[JVM_MemPool] 重分配: %p -> %p, 大小: %zu",
                //    ptr, newPtr, newSize);
                return newPtr;
            }
        }

        return nullptr;
    }

    // 检查是否来自此池
    bool IsFromPool(void* ptr) {
        if (!ptr || !g_jvmHeap) return false;

        std::lock_guard<std::mutex> lock(g_jvmMutex);
        return g_jvmBlocks.find(ptr) != g_jvmBlocks.end();
    }

    // 清理
    void Cleanup() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);

        if (g_jvmHeap) {
            // 如果设置了不释放内存，则只清理数据结构
            if (g_disableMemoryReleasing.load()) {
                LogMessage("[JVM_MemPool] 保留JVM堆内存，仅清理数据结构");
                g_jvmBlocks.clear();
                g_jvmHeap = nullptr;
                return;
            }

            // 正常清理
            mi_heap_destroy(g_jvmHeap);
            g_jvmHeap = nullptr;
            g_jvmBlocks.clear();
            LogMessage("[JVM_MemPool] JVM堆已销毁");
        }
    }
}

// ------- 小块内存池实现 -------
namespace SmallBlockPool {
    // 常见块大小定义
    static const std::size_t kPoolSizes[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };

    // 每个大小的池
    struct Pool {
        std::vector<void*> freeBlocks;
        std::mutex mutex;
        std::size_t blockSize;
        std::size_t blockCount;
    };

    // 池映射
    static std::unordered_map<std::size_t, Pool> pools;

    // 判断是否要拦截处理的大小
    bool ShouldIntercept(std::size_t size) {
        for (auto poolSize : kPoolSizes) {
            if (size == poolSize) return true;
        }
        return false;
    }

    // 初始化
    void Initialize() {
        for (auto size : kPoolSizes) {
            Pool& pool = pools[size];
            pool.blockSize = size;
            pool.blockCount = 0;
        }
    }

    // 申请内存
    void* Allocate(std::size_t size) {
        auto it = pools.find(size);
        if (it == pools.end()) return nullptr;

        Pool& pool = it->second;
        std::lock_guard<std::mutex> lock(pool.mutex);

        if (!pool.freeBlocks.empty()) {
            void* ptr = pool.freeBlocks.back();
            pool.freeBlocks.pop_back();
            return ptr;
        }

        // 无可用块，从Storm分配
        return nullptr;
    }

    // 释放内存
    bool Free(void* ptr, std::size_t size) {
        auto it = pools.find(size);
        if (it == pools.end()) return false;

        Pool& pool = it->second;
        std::lock_guard<std::mutex> lock(pool.mutex);

        // 保留一定数量的块以供复用，超过则真正释放
        const std::size_t MAX_CACHED = 100; // 可根据大小调整

        if (pool.freeBlocks.size() < MAX_CACHED) {
            pool.freeBlocks.push_back(ptr);
            return true;
        }

        // 超过缓存上限，让Storm处理
        return false;
    }
}

// 全局变量
namespace MemPool {
    // mimalloc堆实例
    static mi_heap_t* g_mainHeap = nullptr;
    static mi_heap_t* g_safeHeap = nullptr;  // 安全操作专用堆

    std::atomic<bool> g_inOperation{ false };  // 替代原g_inTLSFOperation

    // 初始总池大小
    static std::atomic<size_t> g_totalPoolSize{ 0 };
    static std::atomic<size_t> g_usedSize{ 0 };

    // 分片锁数量
    constexpr size_t LOCK_SHARDS = 32;
    static std::mutex g_poolMutexes[LOCK_SHARDS];

    // 控制标志
    static std::atomic<bool> g_inMiMallocOperation{ false };
    static std::atomic<bool> g_disableMemoryReleasing{ false };

    // 获取分片索引
    inline size_t get_shard_index(void* ptr = nullptr, size_t size = 0) {
        size_t hash;
        if (ptr) {
            hash = reinterpret_cast<uintptr_t>(ptr) / 16;
        }
        else {
            hash = size / 16;
        }
        return hash % LOCK_SHARDS;
    }

    // 初始化 mimalloc
    bool Initialize(size_t initialSize) {
        // 对所有分片加锁
        std::vector<std::unique_lock<std::mutex>> locks;
        for (size_t i = 0; i < LOCK_SHARDS; i++) {
            locks.emplace_back(g_poolMutexes[i]);
        }

        if (g_mainHeap) {
            LogMessage("[MemPool] 已初始化");
            return true;
        }

        // 创建主要mimalloc堆
        g_mainHeap = mi_heap_new();
        if (!g_mainHeap) {
            LogMessage("[MemPool] 无法创建mimalloc主堆");
            return false;
        }

        // 创建安全操作专用堆
        g_safeHeap = mi_heap_new();
        if (!g_safeHeap) {
            LogMessage("[MemPool] 无法创建mimalloc安全堆");
            mi_heap_delete(g_mainHeap);
            g_mainHeap = nullptr;
            return false;
        }

        // 设置初始池大小
        g_totalPoolSize.store(initialSize);

        LogMessage("[MemPool] mimalloc初始化完成，预留大小: %zu 字节", initialSize);
        return true;
    }

    // 关闭mimalloc
    void Shutdown() {
        if (g_disableMemoryReleasing.load()) {
            LogMessage("[MemPool] 保留所有内存块，仅清理管理数据");
            g_mainHeap = nullptr;
            g_safeHeap = nullptr;
            return;
        }

        if (g_mainHeap) {
            mi_heap_destroy(g_mainHeap);
            g_mainHeap = nullptr;
        }

        if (g_safeHeap) {
            mi_heap_destroy(g_safeHeap);
            g_safeHeap = nullptr;
        }

        LogMessage("[MemPool] mimalloc关闭完成");
    }

    // 分配内存
    void* Allocate(size_t size) {
        if (!g_mainHeap) {
            // 懒初始化
            Initialize(64 * 1024 * 1024);  // 默认64MB
            if (!g_mainHeap) return nullptr;
        }

        size_t lockIndex = get_shard_index(nullptr, size);
        std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

        void* ptr = mi_heap_malloc(g_mainHeap, size);
        if (ptr) {
            g_usedSize.fetch_add(size, std::memory_order_relaxed);
        }

        return ptr;
    }

    // 获取块大小 - 适配函数
    size_t MemPool::GetBlockSize(void* ptr) {
        if (!ptr) return 0;

        // 先尝试获取StormHeader信息
        try {
            StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                static_cast<char*>(ptr) - sizeof(StormAllocHeader));

            if (header->Magic == STORM_MAGIC) {
                return header->Size;
            }
        }
        catch (...) {}

        // 检查是否为mimalloc管理的内存
        bool isMainHeapPtr = (g_mainHeap && mi_heap_check_owned(g_mainHeap, ptr));
        bool isSafeHeapPtr = (g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr));

        if (isMainHeapPtr || isSafeHeapPtr) {
            // 只有确认是mimalloc管理的内存才调用mi_usable_size
            return mi_usable_size(ptr);
        }

        // 如果都不是，返回0表示未知大小
        return 0;
    }

    void DisableActualFree() {
        DisableMemoryReleasing();  // 调用已实现的函数
    }

    // 安全分配 - 用于不安全期间
    void* AllocateSafe(size_t size) {
        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期直接用系统分配
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) {
                LogMessage("[MemPool] 不安全期间系统内存分配失败: %zu", size);
                return nullptr;
            }

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            LogMessage("[MemPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
            return userPtr;
        }

        if (!g_safeHeap) {
            if (!g_mainHeap) {
                Initialize(64 * 1024 * 1024);
            }
            if (!g_safeHeap) return nullptr;
        }

        void* ptr = mi_heap_malloc(g_safeHeap, size);
        if (ptr) {
            g_usedSize.fetch_add(size, std::memory_order_relaxed);
        }

        return ptr;
    }

    // 释放内存
    void Free(void* ptr) {
        if (!g_mainHeap || !ptr) return;

        // 避免释放永久块
        if (IsPermanentBlock(ptr)) {
            LogMessage("[MemPool] 尝试释放永久块: %p，已忽略", ptr);
            return;
        }

        // 使用基于指针地址的分片锁
        size_t lockIndex = get_shard_index(ptr);
        std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

        // 先检查是否是mimalloc管理的内存
        bool isMainHeapPtr = mi_heap_check_owned(g_mainHeap, ptr);
        bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr);

        if (!isMainHeapPtr && !isSafeHeapPtr) {
            // 如果不是mimalloc管理的内存，记录日志并跳过
            // LogMessage("[MemPool] 尝试释放非mimalloc内存: %p，已忽略", ptr);
            return;
        }

        // 现在安全地获取大小
        size_t size = mi_usable_size(ptr);
        if (size > 0) {
            g_usedSize.fetch_sub(size, std::memory_order_relaxed);
        }

        // 根据所属堆选择释放方式
        if (isMainHeapPtr) {
            mi_free(ptr);
        }
        else if (isSafeHeapPtr) {
            mi_free(ptr);  // mimalloc会自动将指针路由到正确的堆
        }
    }

    // 安全释放
    void FreeSafe(void* ptr) {
        if (!ptr) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期使用延迟释放
            g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
            return;
        }

        Free(ptr);
    }

    // 重新分配 - 需要添加指针所有权验证
    void* MemPool::Realloc(void* oldPtr, size_t newSize) {
        if (!g_mainHeap) return nullptr;
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        // 检查指针所有权
        bool isMainHeapPtr = mi_heap_check_owned(g_mainHeap, oldPtr);
        bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, oldPtr);

        if (!isMainHeapPtr && !isSafeHeapPtr) {
            // 不是我们管理的内存，分配新内存并返回
            LogMessage("[MemPool] 重新分配非mimalloc内存: %p，分配新内存", oldPtr);
            void* newPtr = Allocate(newSize);
            if (newPtr) {
                // 尝试拷贝一些数据，但我们不知道原块大小，只能保守估计
                try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
                }
                catch (...) {}
            }
            return newPtr;
        }

        size_t oldLockIndex = get_shard_index(oldPtr);
        size_t newLockIndex = get_shard_index(nullptr, newSize);

        // 锁定两个分片
        if (oldLockIndex != newLockIndex) {
            // 按顺序锁定，避免死锁
            if (oldLockIndex < newLockIndex) {
                std::lock_guard<std::mutex> lock1(g_poolMutexes[oldLockIndex]);
                std::lock_guard<std::mutex> lock2(g_poolMutexes[newLockIndex]);

                size_t oldSize = mi_usable_size(oldPtr);
                void* newPtr = mi_heap_realloc(g_mainHeap, oldPtr, newSize);

                if (newPtr) {
                    if (oldSize > 0) {
                        g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                    }
                    g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
                }

                return newPtr;
            }
            else {
                std::lock_guard<std::mutex> lock2(g_poolMutexes[newLockIndex]);
                std::lock_guard<std::mutex> lock1(g_poolMutexes[oldLockIndex]);

                size_t oldSize = mi_usable_size(oldPtr);
                void* newPtr = mi_heap_realloc(g_mainHeap, oldPtr, newSize);

                if (newPtr) {
                    if (oldSize > 0) {
                        g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                    }
                    g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
                }

                return newPtr;
            }
        }
        else {
            std::lock_guard<std::mutex> lock(g_poolMutexes[oldLockIndex]);

            size_t oldSize = mi_usable_size(oldPtr);
            void* newPtr = mi_heap_realloc(g_mainHeap, oldPtr, newSize);

            if (newPtr) {
                if (oldSize > 0) {
                    g_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
                g_usedSize.fetch_add(newSize, std::memory_order_relaxed);
            }

            return newPtr;
        }
    }

    // 安全重新分配
    void* MemPool::ReallocSafe(void* oldPtr, size_t newSize) {
        if (!oldPtr) return AllocateSafe(newSize);
        if (newSize == 0) {
            FreeSafe(oldPtr);
            return nullptr;
        }

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 不安全期处理: 分配+复制+延迟释放
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 检查指针所有权
            bool isOurPtr = IsFromPool(oldPtr);

            // 尝试复制数据
            size_t oldSize = 0;
            try {
                if (isOurPtr) {
                    oldSize = mi_usable_size(oldPtr);
                }
                else {
                    // 尝试获取 Storm 头部信息
                    StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                        static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                    if (oldHeader->Magic == STORM_MAGIC) {
                        oldSize = oldHeader->Size;
                    }
                }
            }
            catch (...) {
                oldSize = min(newSize, (size_t)64); // 无法确定大小，保守复制
            }

            size_t copySize = min(oldSize, newSize);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                LogMessage("[MemPool] 不安全期间复制数据失败");
                FreeSafe(newPtr);
                return nullptr;
            }

            // 不释放旧指针，而是放入延迟队列
            g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
            return newPtr;
        }

        // 检查指针所有权
        bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(g_mainHeap, oldPtr);
        bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(g_safeHeap, oldPtr);

        if (!isMainHeapPtr && !isSafeHeapPtr) {
            // 不是我们管理的内存，分配新内存并返回
            void* newPtr = AllocateSafe(newSize);
            if (newPtr) {
                // 尝试拷贝一些数据，但我们不知道原块大小，只能保守估计
                try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
                }
                catch (...) {}
            }
            return newPtr;
        }

        return Realloc(oldPtr, newSize);
    }

    // 添加指针验证辅助函数
    bool ValidatePointer(void* ptr) {
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

    // 检查指针是否来自我们的池
    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        __try {
            // 检查是否为mimalloc管理的内存
            if (g_mainHeap && mi_heap_check_owned(g_mainHeap, ptr)) {
                return true;
            }

            if (g_safeHeap && mi_heap_check_owned(g_safeHeap, ptr)) {
                return true;
            }

            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 访问指针出现异常
            return false;
        }
    }

    // 获取已使用大小
    size_t GetUsedSize() {
        return g_usedSize.load(std::memory_order_relaxed);
    }

    // 获取总大小
    size_t MemPool::GetTotalSize() {
        size_t currentTotal = g_totalPoolSize.load(std::memory_order_relaxed);

        // 如果使用量超过了记录的总量，更新总量为使用量+预留空间
        size_t currentUsed = GetUsedSize();
        if (currentUsed > currentTotal * 0.8) { // 使用超过80%时更新
            // 更新总大小为当前使用量的150%（提供一些缓冲）
            size_t newTotal = currentUsed * 3 / 2;
            g_totalPoolSize.store(newTotal, std::memory_order_relaxed);
            return newTotal;
        }

        return currentTotal;
    }

    // 设置内存不释放
    void DisableMemoryReleasing() {
        g_disableMemoryReleasing.store(true);
        LogMessage("[MemPool] 已禁用内存释放，所有内存将保留到进程结束");
    }

    // 检查并释放未使用的池 (mimalloc自己管理池，我们这里只做统计和日志)
    void CheckAndFreeUnusedPools() {

        // 强制mimalloc收集可回收的内存
        if (g_mainHeap) {
            mi_heap_collect(g_mainHeap, true);
        }

        if (g_safeHeap) {
            mi_heap_collect(g_safeHeap, true);
        }
    }

    // 创建稳定化块
    void* CreateStabilizingBlock(size_t size, const char* purpose) {
        // 使用系统分配确保稳定性
        void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rawPtr) {
            LogMessage("[MemPool] 无法分配稳定化块: %zu", size);
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
            LogMessage("[MemPool] 设置稳定化块头部失败: %p", rawPtr);
            VirtualFree(rawPtr, 0, MEM_RELEASE);
            return nullptr;
        }

        LogMessage("[MemPool] 创建稳定化块: %p (大小: %zu, 用途: %s)",
            userPtr, size, purpose ? purpose : "未知");

        return userPtr;
    }

    // 打印统计信息
    void PrintStats() {
        if (!g_mainHeap) {
            LogMessage("[MemPool] mimalloc未初始化");
            return;
        }

        LogMessage("[MemPool] === mimalloc内存池统计 ===");
        LogMessage("[MemPool] 已用内存: %zu KB", g_usedSize.load() / 1024);

        // 收集mimalloc的统计信息 (mimalloc本身也有统计功能)
        // 打印mimalloc自己的统计信息
        mi_stats_print(NULL);

        LogMessage("[MemPool] mimalloc统计完成");
    }
}