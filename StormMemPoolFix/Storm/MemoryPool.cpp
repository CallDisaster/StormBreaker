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