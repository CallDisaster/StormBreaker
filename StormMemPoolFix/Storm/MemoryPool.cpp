// MemoryPool.cpp - 完整修复版本
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
#include <unordered_set>
#include <shared_mutex>

#pragma comment(lib, "dbghelp.lib")

// ------- 参数可自行调整 -------
static constexpr std::size_t BlockSize = 0x28A8;
static constexpr std::size_t PoolCapacity = 256; // 最多多少块，看你需求调整
// --------------------------------

// 修复1: 统一的块头部结构定义
struct JVMBlockHeader {
    uint32_t magic;        // 魔数
    uint32_t size;         // 用户数据大小
    uint32_t poolId;       // 池标识符
    uint32_t checksum;     // 头部校验和
    uint64_t timestamp;    // 分配时间戳
    uint32_t threadId;     // 分配线程ID
    uint32_t reserved;     // 保留字段，用于对齐
};

// 更安全的魔数
static constexpr uint32_t JVM_POOL_MAGIC = 0xDEADBEEF;
static constexpr uint32_t JVM_POOL_MAGIC_FREED = 0xDEADDEAD;  // 释放后的魔数

// 计算校验和 - 全局函数
static uint32_t CalculateJVMChecksum(const JVMBlockHeader* header) {
    uint32_t sum = header->magic;
    sum ^= header->size;
    sum ^= header->poolId;
    sum ^= static_cast<uint32_t>(header->timestamp);
    sum ^= static_cast<uint32_t>(header->timestamp >> 32);
    sum ^= header->threadId;
    sum ^= 0x5A5A5A5A;  // 混合常数
    return sum;
}

// 验证JVM块头部 - 全局函数
static bool ValidateJVMBlockHeader(const void* ptr) {
    if (!ptr) return false;

    __try {
        const JVMBlockHeader* header = static_cast<const JVMBlockHeader*>(ptr);

        // 检查魔数
        if (header->magic != JVM_POOL_MAGIC) return false;

        // 检查大小合理性
        if (header->size == 0 || header->size > 0x10000000) return false;  // 最大256MB

        // 验证校验和
        uint32_t expectedChecksum = CalculateJVMChecksum(header);
        if (header->checksum != expectedChecksum) return false;

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 整个池的总内存占用（含头部）
static constexpr std::size_t RealJVMBlockSize = BlockSize + sizeof(JVMBlockHeader);

// 使用一个静态数组，长度为 PoolCapacity，每块大小为 RealJVMBlockSize
static alignas(std::max_align_t) unsigned char s_jvmPoolMemory[PoolCapacity][RealJVMBlockSize];

// 是否正在使用
static bool s_jvmUsedFlags[PoolCapacity];

// 统计当前池已使用的大小，防止超 0x7FFFFFFF
static std::atomic<size_t> s_jvmTotalUsage{ 0 };

// 互斥保护
static std::mutex s_jvmMutex;

// 修复2: JVM内存池命名空间实现
namespace JVM_MemPool {
    // 池统计信息
    struct PoolStats {
        std::atomic<size_t> totalAllocated{ 0 };
        std::atomic<size_t> totalFreed{ 0 };
        std::atomic<size_t> currentUsed{ 0 };
        std::atomic<size_t> peakUsed{ 0 };
        std::atomic<size_t> allocationCount{ 0 };
    };

    static PoolStats g_jvmStats;

    // 线程安全的内存跟踪
    class SafeMemoryTracker {
    private:
        mutable std::shared_mutex m_mutex;
        std::unordered_set<void*> m_allocatedBlocks;

    public:
        void TrackAllocation(void* ptr) {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            m_allocatedBlocks.insert(ptr);
        }

        bool UntrackAllocation(void* ptr) {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            auto it = m_allocatedBlocks.find(ptr);
            if (it != m_allocatedBlocks.end()) {
                m_allocatedBlocks.erase(it);
                return true;
            }
            return false;
        }

        bool IsTracked(void* ptr) const {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            return m_allocatedBlocks.find(ptr) != m_allocatedBlocks.end();
        }

        size_t GetTrackedCount() const {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            return m_allocatedBlocks.size();
        }

        void Clear() {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            m_allocatedBlocks.clear();
        }
    };

    static SafeMemoryTracker g_jvmTracker;

    void Initialize() {
        std::lock_guard<std::mutex> lock(s_jvmMutex);

        if (g_jvmStats.allocationCount.load() > 0) {
            printf("[JVM_MemPool] 已初始化，跳过重复初始化\n");
            return;
        }

        // 初始化内存池
        std::memset(s_jvmUsedFlags, false, sizeof(s_jvmUsedFlags));
        s_jvmTotalUsage = 0;

        // 重置统计
        g_jvmStats.totalAllocated = 0;
        g_jvmStats.totalFreed = 0;
        g_jvmStats.currentUsed = 0;
        g_jvmStats.peakUsed = 0;
        g_jvmStats.allocationCount = 0;

        printf("[JVM_MemPool] 初始化完成，池容量: %zu 块\n", PoolCapacity);
    }

    void* Allocate(std::size_t size) {
        // 只处理特定大小
        if (size != BlockSize) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(s_jvmMutex);

        // 检查总使用量限制
        if (s_jvmTotalUsage.load() + RealJVMBlockSize > 0x7FFFFFFF) {
            printf("[JVM_MemPool] 使用量限制达到，当前: %zu\n", s_jvmTotalUsage.load());
            return nullptr;
        }

        // 查找空闲块
        for (std::size_t i = 0; i < PoolCapacity; i++) {
            if (!s_jvmUsedFlags[i]) {
                s_jvmUsedFlags[i] = true;

                // 设置块头部
                JVMBlockHeader* header = reinterpret_cast<JVMBlockHeader*>(&s_jvmPoolMemory[i][0]);
                header->magic = JVM_POOL_MAGIC;
                header->size = static_cast<uint32_t>(BlockSize);
                header->poolId = static_cast<uint32_t>(i);
                header->timestamp = GetTickCount64();
                header->threadId = GetCurrentThreadId();
                header->checksum = CalculateJVMChecksum(header);

                // 用户指针
                void* userPtr = &s_jvmPoolMemory[i][0] + sizeof(JVMBlockHeader);

                // 清零用户区域
                std::memset(userPtr, 0, BlockSize);

                // 更新统计
                s_jvmTotalUsage += RealJVMBlockSize;
                g_jvmStats.totalAllocated += BlockSize;
                g_jvmStats.currentUsed += BlockSize;
                g_jvmStats.allocationCount++;

                // 更新峰值
                size_t currentUsed = g_jvmStats.currentUsed.load();
                size_t peakUsed = g_jvmStats.peakUsed.load();
                while (currentUsed > peakUsed) {
                    if (g_jvmStats.peakUsed.compare_exchange_weak(peakUsed, currentUsed)) {
                        break;
                    }
                }

                // 跟踪分配
                g_jvmTracker.TrackAllocation(userPtr);

                //printf("[JVM_MemPool] 分配成功: %p, 块索引: %zu, 当前使用: %zu KB\n",
                //    userPtr, i, g_jvmStats.currentUsed.load() / 1024);

                return userPtr;
            }
        }

        printf("[JVM_MemPool] 无可用块，当前使用: %zu/%zu\n",
            g_jvmStats.currentUsed.load(), PoolCapacity * BlockSize);
        return nullptr;
    }

    void Free(void* p) {
        if (!p) return;

        // 验证指针
        if (!IsFromPool(p)) {
            printf("[JVM_MemPool] 尝试释放非池内存: %p\n", p);
            return;
        }

        std::lock_guard<std::mutex> lock(s_jvmMutex);

        // 验证跟踪状态
        if (!g_jvmTracker.UntrackAllocation(p)) {
            printf("[JVM_MemPool] 警告: 释放未跟踪的指针: %p\n", p);
            return;
        }

        // 获取头部
        JVMBlockHeader* header = reinterpret_cast<JVMBlockHeader*>(
            static_cast<char*>(p) - sizeof(JVMBlockHeader));

        // 验证头部
        if (!ValidateJVMBlockHeader(header)) {
            printf("[JVM_MemPool] 头部验证失败: %p\n", p);
            return;
        }

        // 计算块索引
        std::ptrdiff_t index = (reinterpret_cast<unsigned char(*)[RealJVMBlockSize]>(header)
            - reinterpret_cast<unsigned char(*)[RealJVMBlockSize]>(&s_jvmPoolMemory[0][0]));

        if (index < 0 || index >= static_cast<std::ptrdiff_t>(PoolCapacity)) {
            printf("[JVM_MemPool] 无效块索引: %td\n", index);
            return;
        }

        // 检查是否已释放
        if (!s_jvmUsedFlags[index]) {
            printf("[JVM_MemPool] 重复释放检测: %p, 索引: %td\n", p, index);
            return;
        }

        // 标记头部为已释放
        header->magic = JVM_POOL_MAGIC_FREED;
        header->checksum = 0;  // 清零校验和

        // 清零用户数据（安全措施）
        std::memset(p, 0xDD, BlockSize);

        // 更新状态
        s_jvmUsedFlags[index] = false;
        s_jvmTotalUsage -= RealJVMBlockSize;
        g_jvmStats.totalFreed += BlockSize;
        g_jvmStats.currentUsed -= BlockSize;

        //printf("[JVM_MemPool] 释放成功: %p, 块索引: %td, 当前使用: %zu KB\n",
        //    p, index, g_jvmStats.currentUsed.load() / 1024);
    }

    void* Realloc(void* oldPtr, size_t newSize) {
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        // 验证旧指针
        if (!IsFromPool(oldPtr)) {
            printf("[JVM_MemPool] Realloc: 非池内存: %p\n", oldPtr);
            return nullptr;
        }

        // 如果新大小匹配块大小，直接返回
        if (newSize == BlockSize) {
            return oldPtr;
        }

        // 需要重新分配
        void* newPtr = Allocate(newSize);
        if (!newPtr) {
            printf("[JVM_MemPool] Realloc: 新分配失败\n");
            return nullptr;
        }

        // 复制数据
        size_t copySize = min(newSize, BlockSize);
        std::memcpy(newPtr, oldPtr, copySize);

        // 释放旧块
        Free(oldPtr);

        //printf("[JVM_MemPool] Realloc: %p -> %p, 大小: %zu -> %zu\n",
        //    oldPtr, newPtr, BlockSize, newSize);

        return newPtr;
    }

    bool IsFromPool(void* p) {
        if (!p) return false;

        // 快速范围检查
        uintptr_t ptr = reinterpret_cast<uintptr_t>(p);
        uintptr_t poolStart = reinterpret_cast<uintptr_t>(&s_jvmPoolMemory[0][0]);
        uintptr_t poolEnd = poolStart + sizeof(s_jvmPoolMemory);

        if (ptr < poolStart || ptr >= poolEnd) {
            return false;
        }

        // 验证对齐
        uintptr_t offset = ptr - poolStart;
        if (offset % RealJVMBlockSize != sizeof(JVMBlockHeader)) {
            return false;
        }

        // 验证头部
        JVMBlockHeader* header = reinterpret_cast<JVMBlockHeader*>(
            static_cast<char*>(p) - sizeof(JVMBlockHeader));

        if (!ValidateJVMBlockHeader(header)) {
            return false;
        }

        // 验证是否在跟踪列表中
        return g_jvmTracker.IsTracked(p);
    }

    void Cleanup() {
        std::lock_guard<std::mutex> lock(s_jvmMutex);

        // 统计泄漏
        size_t leakedBlocks = 0;
        for (std::size_t i = 0; i < PoolCapacity; i++) {
            if (s_jvmUsedFlags[i]) {
                leakedBlocks++;
                void* userPtr = &s_jvmPoolMemory[i][0] + sizeof(JVMBlockHeader);
                printf("[JVM_MemPool] 泄漏检测: 块 %zu, 用户指针: %p\n", i, userPtr);
            }
        }

        // 输出最终统计
        printf("[JVM_MemPool] 清理统计:\n");
        printf("  - 总分配: %zu 次, %zu KB\n",
            g_jvmStats.allocationCount.load(),
            g_jvmStats.totalAllocated.load() / 1024);
        printf("  - 总释放: %zu KB\n", g_jvmStats.totalFreed.load() / 1024);
        printf("  - 当前使用: %zu KB\n", g_jvmStats.currentUsed.load() / 1024);
        printf("  - 峰值使用: %zu KB\n", g_jvmStats.peakUsed.load() / 1024);
        printf("  - 泄漏块数: %zu\n", leakedBlocks);
        printf("  - 跟踪块数: %zu\n", g_jvmTracker.GetTrackedCount());

        // 清理跟踪
        g_jvmTracker.Clear();

        // 重置状态
        std::memset(s_jvmUsedFlags, false, sizeof(s_jvmUsedFlags));
        s_jvmTotalUsage = 0;

        printf("[JVM_MemPool] 清理完成\n");
    }
}

// 修复3: 小块内存池实现
namespace SmallBlockPool {
    // 小块头部结构
    struct SmallBlockHeader {
        uint32_t magic;        // 魔数: 0xDEADBEEF
        uint32_t size;         // 块大小
        uint32_t poolId;       // 池ID
        uint32_t checksum;     // 校验和
    };

    static constexpr uint32_t SMALL_BLOCK_MAGIC = 0xBEEFDEAD;  // 不同于JVM的魔数

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

    // 计算小块校验和
    static uint32_t CalculateSmallBlockChecksum(const SmallBlockHeader* header) {
        return header->magic ^ header->size ^ header->poolId ^ 0xAAAABBBB;
    }

    // 验证小块头部
    static bool ValidateSmallBlockHeader(void* ptr) {
        if (!ptr) return false;

        __try {
            SmallBlockHeader* header = static_cast<SmallBlockHeader*>(ptr);
            if (header->magic != SMALL_BLOCK_MAGIC) return false;

            uint32_t expectedChecksum = CalculateSmallBlockChecksum(header);
            return header->checksum == expectedChecksum;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

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
        printf("[SmallBlockPool] 初始化完成\n");
    }

    // 申请内存
    void* Allocate(std::size_t size) {
        auto it = pools.find(size);
        if (it == pools.end()) return nullptr;

        Pool& pool = it->second;
        std::lock_guard<std::mutex> lock(pool.mutex);

        if (!pool.freeBlocks.empty()) {
            void* rawPtr = pool.freeBlocks.back();
            pool.freeBlocks.pop_back();

            // 验证并设置头部
            if (ValidateSmallBlockHeader(rawPtr)) {
                void* userPtr = static_cast<char*>(rawPtr) + sizeof(SmallBlockHeader);
                printf("[SmallBlockPool] 从池分配: %p -> %p, 大小: %zu\n", rawPtr, userPtr, size);
                return userPtr;
            }
            else {
                printf("[SmallBlockPool] 头部验证失败，丢弃损坏块: %p\n", rawPtr);
                // 继续尝试其他块或分配新的
            }
        }

        // 无可用块，从系统分配新的
        size_t totalSize = size + sizeof(SmallBlockHeader);
        void* rawPtr = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rawPtr) {
            printf("[SmallBlockPool] 系统分配失败: %zu\n", totalSize);
            return nullptr;
        }

        // 设置头部
        SmallBlockHeader* header = static_cast<SmallBlockHeader*>(rawPtr);
        header->magic = SMALL_BLOCK_MAGIC;
        header->size = static_cast<uint32_t>(size);
        header->poolId = static_cast<uint32_t>(size);  // 简单使用size作为poolId
        header->checksum = CalculateSmallBlockChecksum(header);

        void* userPtr = static_cast<char*>(rawPtr) + sizeof(SmallBlockHeader);
        printf("[SmallBlockPool] 新分配: %p -> %p, 大小: %zu\n", rawPtr, userPtr, size);
        return userPtr;
    }

    // 释放内存
    bool Free(void* ptr, std::size_t size) {
        if (!ptr) return false;

        void* rawPtr = static_cast<char*>(ptr) - sizeof(SmallBlockHeader);

        // 验证头部
        if (!ValidateSmallBlockHeader(rawPtr)) {
            printf("[SmallBlockPool] 释放时头部验证失败: %p\n", ptr);
            return false;  // 不是我们的块
        }

        auto it = pools.find(size);
        if (it == pools.end()) return false;

        Pool& pool = it->second;
        std::lock_guard<std::mutex> lock(pool.mutex);

        const std::size_t MAX_CACHED = 100;
        if (pool.freeBlocks.size() < MAX_CACHED) {
            pool.freeBlocks.push_back(rawPtr);
            printf("[SmallBlockPool] 返回池缓存: %p, 池大小: %zu\n", ptr, pool.freeBlocks.size());
            return true;
        }

        // 缓存已满，直接释放
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        printf("[SmallBlockPool] 缓存已满，直接释放: %p\n", ptr);
        return true;
    }
}

///////////////////////////////////////////////////////////////////////////////

// 主内存池大小: 64MB
constexpr size_t TLSF_MAIN_POOL_SIZE = 64 * 1024 * 1024;

namespace MemPool {
    // 内部变量
    static void* g_mainPool = nullptr;
    static tlsf_t g_tlsf = nullptr;

    // 替换单一锁为分片锁
    constexpr size_t LOCK_SHARDS = 32;  // 32个锁分片
    static std::mutex g_poolMutexes[LOCK_SHARDS];

    // 根据内存地址或大小选择锁
    inline size_t get_shard_index(void* ptr = nullptr, size_t size = 0) {
        size_t hash;
        if (ptr) {
            hash = reinterpret_cast<uintptr_t>(ptr) / 16;  // 对齐到16字节
        }
        else {
            hash = size / 16;  // 使用请求大小
        }
        return hash % LOCK_SHARDS;
    }

    // 加锁辅助函数
    class MultiLockGuard {
    private:
        std::vector<size_t> indices;
    public:
        // 锁定一个分片
        MultiLockGuard(size_t index) {
            g_poolMutexes[index].lock();
            indices.push_back(index);
        }

        // 锁定所有分片
        MultiLockGuard() {
            for (size_t i = 0; i < LOCK_SHARDS; ++i) {
                g_poolMutexes[i].lock();
                indices.push_back(i);
            }
        }

        // 锁定两个分片（防止死锁）
        MultiLockGuard(size_t index1, size_t index2) {
            if (index1 != index2) {
                // 按顺序锁定，避免死锁
                if (index1 < index2) {
                    g_poolMutexes[index1].lock();
                    indices.push_back(index1);
                    g_poolMutexes[index2].lock();
                    indices.push_back(index2);
                }
                else {
                    g_poolMutexes[index2].lock();
                    indices.push_back(index2);
                    g_poolMutexes[index1].lock();
                    indices.push_back(index1);
                }
            }
            else {
                // 相同的分片只锁一次
                g_poolMutexes[index1].lock();
                indices.push_back(index1);
            }
        }

        ~MultiLockGuard() {
            // 反向顺序解锁
            for (auto it = indices.rbegin(); it != indices.rend(); ++it) {
                g_poolMutexes[*it].unlock();
            }
        }
    };

    std::atomic<bool> g_inTLSFOperation{ false };

    // 不同类型的内存操作
    enum TLSFOpType {
        OpAlloc = 0,
        OpFree = 1,
        OpRealloc = 2,
        OpExtend = 3,
        OpStat = 4,
        OpMax = 5  // 用于定义位图大小
    };

    // 用位图表示活跃操作
    static std::atomic<uint32_t> g_activeOps{ 0 };

    // 设置/清除操作状态的辅助函数
    inline bool TrySetOpActive(TLSFOpType opType) {
        uint32_t expected = g_activeOps.load(std::memory_order_relaxed);
        uint32_t desired;
        bool retry_op = false;
        do {
            // 检查此类型操作是否已活跃
            retry_op = (expected & (1u << opType));
            if (retry_op) break;

            // 设置对应位
            desired = expected | (1u << opType);
        } while (!g_activeOps.compare_exchange_weak(expected, desired,
            std::memory_order_acquire, std::memory_order_relaxed));

        return !retry_op;  // 如果没有重试，则成功
    }

    inline void SetOpInactive(TLSFOpType opType) {
        g_activeOps.fetch_and(~(1u << opType), std::memory_order_release);
    }

    // 检查是否有任何活跃操作
    inline bool AnyOpActive() {
        return g_activeOps.load(std::memory_order_acquire) != 0;
    }

    // 检查特定类型的操作是否活跃
    inline bool IsOpActive(TLSFOpType opType) {
        return (g_activeOps.load(std::memory_order_acquire) & (1u << opType)) != 0;
    }

    // 线程本地缓存结构
    struct ThreadCache {
        // 存储不同大小的块缓存
        struct SizeClass {
            std::vector<void*> blocks;  // 空闲块列表
            size_t blockSize;           // 该大小类的块大小
            size_t maxCount;            // 最大缓存数量
        };

        // 常用大小的缓存
        static constexpr size_t NUM_SIZE_CLASSES = 8;
        static constexpr size_t SIZE_CLASSES[NUM_SIZE_CLASSES] = {
            16, 32, 64, 128, 256, 512, 1024, 2048
        };

        SizeClass sizeClasses[NUM_SIZE_CLASSES];

        // 初始化缓存
        ThreadCache() {
            for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
                sizeClasses[i].blockSize = SIZE_CLASSES[i];
                // 为小块设置更多缓存数量
                sizeClasses[i].maxCount = 32 / (i + 1); // 小块缓存更多
            }
        }

        // 释放所有缓存的块
        ~ThreadCache() {
            // 添加安全释放标记
            const bool inUnsafePeriod = g_cleanAllInProgress || g_insideUnsafePeriod.load();

            for (auto& sc : sizeClasses) {
                for (void* block : sc.blocks) {
                    if (block) {
                        try {
                            // 不直接释放到TLSF池，而是执行两步检查：
                            if (inUnsafePeriod) {
                                // 不安全期间：放入延迟队列
                                g_MemSafety.EnqueueDeferredFree(block, sc.blockSize);
                            }
                            else if (IsFromPool(block)) {
                                // 安全期间：确认是我们的块才释放
                                tlsf_free(g_tlsf, block);
                            }
                            // 否则忽略此块
                        }
                        catch (...) {
                            // 捕获异常但继续处理其他块
                            LogMessage("[ThreadCache] 释放缓存块异常: %p", block);
                        }
                    }
                }
                sc.blocks.clear();
            }
        }
    };

    // 存储所有线程缓存的全局列表
    static std::mutex g_cachesMutex;
    static std::vector<ThreadCache*> g_allCaches;

    // 线程本地存储
    thread_local ThreadCache* tls_cache = nullptr;

    // 在创建线程缓存时注册
    void RegisterThreadCache(ThreadCache* cache) {
        std::lock_guard<std::mutex> lock(g_cachesMutex);
        g_allCaches.push_back(cache);
    }

    // 在销毁线程缓存时注销
    void UnregisterThreadCache(ThreadCache* cache) {
        std::lock_guard<std::mutex> lock(g_cachesMutex);
        auto it = std::find(g_allCaches.begin(), g_allCaches.end(), cache);
        if (it != g_allCaches.end()) {
            g_allCaches.erase(it);
        }
    }

    // 清理所有线程缓存
    void CleanupAllThreadCaches() {
        std::lock_guard<std::mutex> lock(g_cachesMutex);
        for (auto cache : g_allCaches) {
            delete cache;
        }
        g_allCaches.clear();
    }

    // 初始化线程缓存
    void InitThreadCache() {
        // 如果在不安全期，不创建缓存
        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            return;
        }

        if (!tls_cache) {
            tls_cache = new ThreadCache();

            // 使用写锁注册缓存
            std::lock_guard<std::mutex> lock(g_cachesMutex);
            g_allCaches.push_back(tls_cache);
        }
    }

    // 清理线程缓存
    void CleanupThreadCache() {
        // 先从全局列表移除，再清理
        ThreadCache* localCache = tls_cache;
        if (localCache) {
            {
                std::lock_guard<std::mutex> lock(g_cachesMutex);
                auto it = std::find(g_allCaches.begin(), g_allCaches.end(), localCache);
                if (it != g_allCaches.end()) {
                    g_allCaches.erase(it);
                }
            }

            // 设置线程局部变量为null，防止重复删除
            tls_cache = nullptr;

            // 安全删除，可能的异常在析构函数内部处理
            delete localCache;
        }
    }

    // 从线程缓存分配
    void* AllocateFromCache(size_t size) {
        if (!tls_cache) {
            InitThreadCache();
        }

        // 查找适合的大小类
        for (auto& sc : tls_cache->sizeClasses) {
            if (size <= sc.blockSize && !sc.blocks.empty()) {
                void* block = sc.blocks.back();
                sc.blocks.pop_back();
                return block;
            }
        }

        return nullptr; // 缓存中没有合适大小的块
    }

    // 尝试放入缓存
    bool TryReturnToCache(void* ptr, size_t size) {
        if (!tls_cache) {
            return false;
        }

        // 查找适合的大小类
        for (auto& sc : tls_cache->sizeClasses) {
            if (size == sc.blockSize && sc.blocks.size() < sc.maxCount) {
                sc.blocks.push_back(ptr);
                return true;
            }
        }

        return false; // 缓存已满或大小不匹配
    }


    // 额外内存池结构
    struct ExtraPool {
        void* memory;
        size_t size;
    };
    static std::vector<ExtraPool> g_extraPools;

    // 检查指针是否在某个池范围内
    bool IsPointerInPool(void* ptr, void* poolStart, size_t poolSize) {
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t poolAddr = reinterpret_cast<uintptr_t>(poolStart);
        return (ptrAddr >= poolAddr && ptrAddr < poolAddr + poolSize);
    }

    // 初始化内存池
    bool Initialize(size_t initialSize) {
        // 对所有分片加锁
        std::vector<std::unique_lock<std::mutex>> locks;
        for (size_t i = 0; i < LOCK_SHARDS; i++) {
            locks.emplace_back(g_poolMutexes[i]);
        }

        if (g_mainPool) {
            LogMessage("[MemPool] 已初始化");
            return true;
        }

        // 分配主内存池
        g_mainPool = VirtualAlloc(NULL, initialSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_mainPool) {
            LogMessage("[MemPool] 无法分配主内存池，大小: %zu", initialSize);
            return false;
        }

        // 初始化TLSF
        g_tlsf = tlsf_create_with_pool(g_mainPool, initialSize);
        if (!g_tlsf) {
            LogMessage("[MemPool] 无法创建TLSF实例");
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
            return false;
        }

        // 初始化线程缓存
        InitThreadCache();

        LogMessage("[MemPool] 已初始化，大小: %zu 字节，地址: %p", initialSize, g_mainPool);
        return true;
    }

    void DisableActualFree() {
        // 获取所有分片锁，确保全局设置的一致性
        std::vector<std::unique_lock<std::mutex>> locks;
        for (size_t i = 0; i < LOCK_SHARDS; i++) {
            locks.emplace_back(g_poolMutexes[i]);
        }

        g_disableActualFree = true;
        LogMessage("[MemPool] 已禁用实际内存释放");
    }

    // 设置内存不释放标志的函数
    void DisableMemoryReleasing() {
        g_disableMemoryReleasing.store(true);
        LogMessage("[MemPool] 已禁用内存释放，所有内存将保留到进程结束");
    }

    // 清理资源
    void Shutdown() {
        std::vector<std::unique_lock<std::mutex>> locks;

        // 仅清理数据结构引用，不释放实际内存
        if (g_disableMemoryReleasing.load()) {
            LogMessage("[MemPool] 保留所有内存块，仅清理管理数据");

            // 仅清理引用，不释放内存
            g_tlsf = nullptr;
            g_extraPools.clear();
            g_mainPool = nullptr;
            return;
        }

        // 原有释放逻辑（只在未禁用时执行）
        if (g_tlsf) {
            g_tlsf = nullptr;
        }

        for (const auto& pool : g_extraPools) {
            if (pool.memory) {
                VirtualFree(pool.memory, 0, MEM_RELEASE);
            }
        }
        g_extraPools.clear();

        if (g_mainPool) {
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
        }

        // 清理线程缓存
        CleanupThreadCache();

        LogMessage("[MemPool] 关闭并释放内存完成");
    }

    // 添加额外内存池
    bool AddExtraPool(size_t size, bool callerHasLock = false) {
        if (!callerHasLock && g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] AddExtraPool: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return false;
        }

        // 如果调用者没有持有锁，我们需要获取锁
        std::unique_ptr<MultiLockGuard> lockGuard;
        if (!callerHasLock) {
            lockGuard = std::make_unique<MultiLockGuard>();  // 锁定所有分片
        }

        if (!g_tlsf) {
            LogMessage("[MemPool] TLSF未初始化");
            if (!callerHasLock) g_inTLSFOperation = false;
            return false;
        }

        // 分配新池
        void* newPool = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newPool) {
            LogMessage("[MemPool] 无法分配额外内存池，大小: %zu", size);
            if (!callerHasLock) g_inTLSFOperation = false;
            return false;
        }

        // 添加到TLSF
        pool_t pool = tlsf_add_pool(g_tlsf, newPool, size);
        if (!pool) {
            LogMessage("[MemPool] 无法添加内存池到TLSF");
            VirtualFree(newPool, 0, MEM_RELEASE);
            if (!callerHasLock) g_inTLSFOperation = false;
            return false;
        }

        // 记录池信息
        ExtraPool extraPool = { newPool, size };
        g_extraPools.push_back(extraPool);

        LogMessage("[MemPool] 添加额外内存池，大小: %zu，地址: %p", size, newPool);
        if (!callerHasLock) g_inTLSFOperation = false;
        return true;
    }

    // 分配内存 - 保护版
    void* AllocateSafe(size_t size) {
        // 在不安全期间直接使用系统分配
        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
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

        // 1. 尝试从线程缓存分配
        void* cachedPtr = AllocateFromCache(size);
        if (cachedPtr) {
            // LogMessage("[MemPool] 从线程缓存分配: %p, 大小: %zu", cachedPtr, size);
            return cachedPtr;
        }

        // 2. 尝试设置Alloc操作为活跃 (如果缓存未命中)
        if (!TrySetOpActive(TLSFOpType::OpAlloc)) {
            LogMessage("[MemPool] Allocate: TLSF分配操作正在进行，回退到系统分配");

            // 使用系统分配作为备选
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) return nullptr;

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            return userPtr;
        }

        // 成功设置活跃标记，进行正常分配
        void* ptr = Allocate(size);

        // 清除活跃标记
        SetOpInactive(TLSFOpType::OpAlloc);
        return ptr;
    }


    // 分配内存
    void* Allocate(size_t size) {
        if (!g_tlsf) {
            // 懒初始化
            Initialize(TLSF_MAIN_POOL_SIZE);
            if (!g_tlsf) return nullptr;
        }

        // 使用分片锁，根据大小选择锁
        size_t lockIndex = get_shard_index(nullptr, size);
        g_poolMutexes[lockIndex].lock();
        std::vector<size_t> lockedIndices = { lockIndex };

        void* ptr = tlsf_malloc(g_tlsf, size);
        if (!ptr) {
            // 尝试扩展池
            size_t extraSize = size < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : size * 2;
            LogMessage("[MemPool] 分配失败，大小: %zu，扩展内存池: %zu 字节",
                size, extraSize);

            // 扩展池，传入当前已锁定的索引
            if (AddExtraPool(extraSize, true)) {
                ptr = tlsf_malloc(g_tlsf, size);
            }
        }

        g_poolMutexes[lockIndex].unlock();
        return ptr;
    }

    // 释放内存 - 保护版
    void FreeSafe(void* ptr) {
        if (!ptr) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期直接入队，不经过异步释放器
            size_t blockSize = 0; // 尝试获取大小
            __try {
                blockSize = tlsf_block_size(ptr); // Use tlsf_block_size
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            g_MemSafety.EnqueueDeferredFree(ptr, blockSize > 0 ? blockSize : 1); // 至少入队1字节
            return;
        }

        // 1. 尝试返回到线程缓存
        size_t blockSize = 0;
        __try {
            blockSize = tlsf_block_size(ptr); // Use tlsf_block_size
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (blockSize > 0 && TryReturnToCache(ptr, blockSize)) {
            // LogMessage("[MemPool] 返回到线程缓存: %p, 大小: %zu", ptr, blockSize);
            return; // 已缓存，无需进一步释放
        }

        // 2. 如果无法缓存，则执行实际释放
        Free(ptr);
    }

    // 释放内存
    void Free(void* ptr) {
        if (!g_tlsf || !ptr) return;

        // 避免释放永久块
        if (IsPermanentBlock(ptr)) {
            LogMessage("[MemPool] 尝试释放永久块: %p，已忽略", ptr);
            return;
        }

        // 使用基于指针地址的分片锁
        size_t lockIndex = get_shard_index(ptr);
        MultiLockGuard lock(lockIndex);

        // 确保指针来自我们的池
        if (IsFromPool(ptr)) {
            try {
                tlsf_free(g_tlsf, ptr);
            }
            catch (...) {
                LogMessage("[MemPool] 释放内存时异常: %p", ptr);
            }
        }
        else {
            // 可能是系统分配的后备内存
            try {
                StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(ptr) - sizeof(StormAllocHeader));

                if (header->Magic == STORM_MAGIC && header->HeapId == SPECIAL_MARKER) {
                    void* basePtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
                    VirtualFree(basePtr, 0, MEM_RELEASE);
                    return;
                }
            }
            catch (...) {}

            LogMessage("[MemPool] 警告: 尝试释放非内存池指针: %p", ptr);
        }
    }

    // 重新分配内存 - 保护版
    void* ReallocSafe(void* oldPtr, size_t newSize) {
        if (!oldPtr) return AllocateSafe(newSize);
        if (newSize == 0) {
            FreeSafe(oldPtr);
            return nullptr;
        }

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间，采用分配+复制+不释放的策略
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试复制数据
            size_t oldSize = 0;
            try {
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                if (oldHeader->Magic == STORM_MAGIC) {
                    oldSize = oldHeader->Size;
                }
            }
            catch (...) {
                oldSize = newSize; // 无法确定大小，假设相同
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

            // 不释放旧指针
            return newPtr;
        }

        // 尝试设置Realloc操作为活跃
        if (!TrySetOpActive(TLSFOpType::OpRealloc)) {
            LogMessage("[MemPool] Realloc: TLSF重分配操作正在进行，使用备选策略");

            // 使用分配+复制+释放的备选策略
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试复制数据
            try {
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));
                size_t copySize = min(oldHeader->Size, newSize);
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                // 复制失败，保守地尝试复制较小的块
                try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)1024));
                }
                catch (...) {
                    LogMessage("[MemPool] 无法复制内存数据");
                }
            }

            // 尝试释放旧指针
            FreeSafe(oldPtr);
            return newPtr;
        }

        // 成功设置活跃标记，进行正常重分配
        void* ptr = Realloc(oldPtr, newSize);

        // 清除活跃标记
        SetOpInactive(TLSFOpType::OpRealloc);
        return ptr;
    }

    // 重新分配内存
    void* Realloc(void* oldPtr, size_t newSize) {
        if (!g_tlsf) return nullptr;
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        // 使用两个锁
        size_t oldLockIndex = get_shard_index(oldPtr);
        size_t newLockIndex = get_shard_index(nullptr, newSize);
        MultiLockGuard lock(oldLockIndex, newLockIndex);

        // 确保旧指针来自我们的池
        if (!IsFromPool(oldPtr)) {
            LogMessage("[MemPool] 警告: 尝试重新分配非内存池指针: %p", oldPtr);
            return nullptr;
        }

        void* newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
        if (!newPtr) {
            // 尝试扩展池
            size_t extraSize = newSize < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : newSize * 2;
            LogMessage("[MemPool] 重新分配失败，大小: %zu，扩展内存池: %zu 字节",
                newSize, extraSize);

            // 扩展池需要所有锁
            // 先解锁当前锁，再获取所有锁
            if (oldLockIndex != newLockIndex) {
                g_poolMutexes[oldLockIndex].unlock();
                g_poolMutexes[newLockIndex].unlock();
            }
            else {
                g_poolMutexes[oldLockIndex].unlock();
            }

            {
                MultiLockGuard allLocks;
                bool poolAdded = AddExtraPool(extraSize, true);  // 传入true表示调用者已持有锁
                if (poolAdded) {
                    newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
                }
            }

            // 重新锁定
            if (oldLockIndex != newLockIndex) {
                g_poolMutexes[oldLockIndex].lock();
                g_poolMutexes[newLockIndex].lock();
            }
            else {
                g_poolMutexes[oldLockIndex].lock();
            }
        }

        return newPtr;
    }

    // 检查内存池状态
    struct PoolUsageStats {
        size_t used = 0;
        size_t total = 0;
    };

    static void GatherUsageCallback(void* /*ptr*/, size_t size, int used, void* user) {
        PoolUsageStats* stats = static_cast<PoolUsageStats*>(user);
        stats->total += size;
        if (used) stats->used += size;
    }

    // 检查指针是否来自我们的池
    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        // 检查主池
        if (IsPointerInPool(ptr, g_mainPool, TLSF_MAIN_POOL_SIZE)) {
            return true;
        }

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            if (IsPointerInPool(ptr, pool.memory, pool.size)) {
                return true;
            }
        }

        return false;
    }

    // 获取已使用大小
    size_t GetUsedSize() {
        if (!g_tlsf) return 0;

        // 不需要锁定特定分片，使用一个临时锁
        std::mutex tempMutex;
        std::lock_guard<std::mutex> lock(tempMutex);

        PoolUsageStats stats;

        // 检查主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        tlsf_walk_pool(mainPool, GatherUsageCallback, &stats);

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            PoolUsageStats poolStats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &poolStats);
            stats.used += poolStats.used;
            stats.total += poolStats.total;
        }

        return stats.used;
    }

    // 获取总大小
    size_t GetTotalSize() {
        if (!g_tlsf) return 0;

        // 不需要锁定特定分片，使用一个临时锁
        std::mutex tempMutex;
        std::lock_guard<std::mutex> lock(tempMutex);

        size_t total = TLSF_MAIN_POOL_SIZE;
        for (const auto& pool : g_extraPools) {
            total += pool.size;
        }

        return total;
    }


    // 打印统计信息
    void PrintStats() {
        if (!g_tlsf) {
            LogMessage("[MemPool] 未初始化");
            return;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] PrintStats: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        // 获取所有分片锁，因为我们需要一致的视图
        std::vector<std::unique_lock<std::mutex>> locks;
        for (size_t i = 0; i < LOCK_SHARDS; i++) {
            locks.emplace_back(g_poolMutexes[i]);
        }

        LogMessage("[MemPool] === 内存池统计 ===");

        // 主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        PoolUsageStats mainStats;
        tlsf_walk_pool(mainPool, GatherUsageCallback, &mainStats);

        LogMessage("[MemPool] 主池: %zu KB已用 / %zu KB总计 (%.1f%%)",
            mainStats.used / 1024, mainStats.total / 1024,
            mainStats.total > 0 ? (mainStats.used * 100.0 / mainStats.total) : 0);

        // 额外池
        size_t totalExtra = 0;
        size_t usedExtra = 0;

        for (size_t i = 0; i < g_extraPools.size(); i++) {
            const auto& pool = g_extraPools[i];
            PoolUsageStats stats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &stats);

            LogMessage("[MemPool] 额外池 #%zu: %zu KB已用 / %zu KB总计 (%.1f%%)",
                i + 1, stats.used / 1024, stats.total / 1024,
                stats.total > 0 ? (stats.used * 100.0 / stats.total) : 0);

            totalExtra += pool.size;
            usedExtra += stats.used;
        }

        LogMessage("[MemPool] 额外池: %zu 个, %zu KB总计",
            g_extraPools.size(), totalExtra / 1024);

        // 总计
        size_t totalSize = TLSF_MAIN_POOL_SIZE + totalExtra;
        size_t totalUsed = mainStats.used + usedExtra;

        LogMessage("[MemPool] 总计: %zu KB已用 / %zu KB已分配 (%.1f%%)",
            totalUsed / 1024, totalSize / 1024,
            totalSize > 0 ? (totalUsed * 100.0 / totalSize) : 0);

        g_inTLSFOperation = false;
    }

    // 检查并释放空闲的扩展池
    void CheckAndFreeUnusedPools() {
        if (!g_tlsf) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间不执行此操作
            return;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] CheckFreeUnusedPools: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        // 获取所有分片锁，因为我们需要完全控制所有内存池
        std::vector<std::unique_lock<std::mutex>> locks;
        for (size_t i = 0; i < LOCK_SHARDS; i++) {
            locks.emplace_back(g_poolMutexes[i]);
        }

        bool poolsFreed = false;

        // 从后向前扫描，释放完全空闲的扩展池
        for (auto it = g_extraPools.rbegin(); it != g_extraPools.rend(); ) {
            PoolUsageStats stats;
            tlsf_walk_pool(it->memory, GatherUsageCallback, &stats);

            if (stats.used == 0) {
                LogMessage("[MemPool] 释放未使用的额外池: %p (大小: %zu 字节)",
                    it->memory, it->size);

                tlsf_remove_pool(g_tlsf, it->memory);
                VirtualFree(it->memory, 0, MEM_RELEASE);

                auto normalIt = std::next(it).base();
                normalIt = g_extraPools.erase(normalIt);
                it = std::reverse_iterator<decltype(normalIt)>(normalIt);

                poolsFreed = true;
            }
            else {
                ++it;
            }
        }

        if (poolsFreed) {
            LogMessage("[MemPool] 清理后: 剩余%zu个额外池", g_extraPools.size());
        }

        g_inTLSFOperation = false;
    }

    // 创建稳定化块 - 新增函数
    void* CreateStabilizingBlock(size_t size, const char* purpose) {
        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] CreateStabilizingBlock: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return nullptr;
        }

        // 使用系统分配确保稳定性
        void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rawPtr) {
            LogMessage("[MemPool] 无法分配稳定化块: %zu", size);
            g_inTLSFOperation = false;
            return nullptr;
        }

        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        LogMessage("[MemPool] 创建稳定化块: %p (大小: %zu, 用途: %s)",
            userPtr, size, purpose ? purpose : "未知");

        g_inTLSFOperation = false;
        return userPtr;
    }
}

