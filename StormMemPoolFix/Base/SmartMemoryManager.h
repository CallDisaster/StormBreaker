#pragma once

#include <Windows.h>
#include <psapi.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <algorithm>
#include <concurrent_queue.h>
#include "../Storm/StormHook.h"

// 内存压力监控器
class MemoryPressureMonitor {
private:
    std::atomic<uint32_t> m_lastCommit{ 0 };
    std::atomic<uint32_t> m_lastCleanAllCount{ 0 };
    std::atomic<uint32_t> m_consecutiveHighPressure{ 0 };

public:
    struct MemoryInfo {
        uint32_t commitBytes;
        uint32_t largestFreeRegion;
        uint32_t cleanAllCount;
        bool needsAction;
        int pressureLevel; // 0=正常, 1=轻微, 2=中等, 3=严重
    };

    // 查询最大空闲虚拟内存区域
    uint32_t QueryLargestFreeRegion();

    // 获取当前内存信息和压力级别
    MemoryInfo GetMemoryInfo(uint32_t cleanAllCount);
};

// 智能大块缓存管理器
class SmartLargeBlockCache {
private:
    struct CachedBlock {
        void* ptr;
        size_t size;
        DWORD timestamp;

        // 构造函数
        CachedBlock(void* p, size_t s, DWORD ts);

        // 计算优先级（越大越应该被清理）
        uint32_t GetPriority() const;
    };

    struct CacheShard {
        std::mutex mutex;
        std::vector<CachedBlock> blocks;
    };

    CacheShard m_shards[16];
    std::atomic<size_t> m_totalBlocks{ 0 };
    static constexpr size_t MAX_CACHE_SIZE = 16; // 每个分片最大缓存

public:
    // 从缓存获取块
    void* GetBlock(size_t size);

    // 释放块到缓存
    void ReleaseBlock(void* rawPtr, size_t size);

    // 智能清理：根据压力级别清理不同比例的缓存
    size_t SmartFlush(int pressureLevel);

    // 清理旧块（清理一半最老的）
    void FlushOldBlocks();

    // 获取当前缓存大小
    size_t GetCacheSize() const;
};

// 异步内存释放器
class AsyncMemoryReleaser {
private:
    // 定义嵌套结构
    struct DeferredFree {
        void* ptr;
        size_t size;
        DWORD queueTime;
    };

    // 本地线程缓冲，避免频繁锁定
    thread_local static std::vector<DeferredFree> t_localBuffer;

    // 使用高效的无锁并发队列
    concurrency::concurrent_queue<DeferredFree> m_queue;
    std::atomic<size_t> m_queueSize{ 0 };
    std::thread m_thread;
    std::atomic<bool> m_shouldExit{ false };
    std::condition_variable m_wakeCondition; // 替代Sleep实现
    std::mutex m_wakeMutex;

    void WorkerThread();

public:
    AsyncMemoryReleaser();
    ~AsyncMemoryReleaser();

    // 将指针加入异步释放队列
    void QueueFree(void* ptr, size_t size);

    // 强制刷新本地缓冲区
    void FlushLocalBuffer();

    // 立即释放所有队列中的内存
    void FlushAllImmediate();

    // 获取队列大小
    size_t GetQueueSize() const;
};

// 全局实例声明
extern MemoryPressureMonitor g_pressureMonitor;
extern SmartLargeBlockCache g_smartCache;
extern AsyncMemoryReleaser g_asyncReleaser;
