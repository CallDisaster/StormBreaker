#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <cstdio>
#include <map>
#include <mutex>
#include <shared_mutex>  // 新增读写锁支持
#include <vector>
#include <cstring>
#include <detours.h>
#include <unordered_map>
#include <atomic>
#include "tlsf.h" // 确保包含 tlsf.h
#include <algorithm>
#include <Base/MemorySafety.h>
#include "MemoryPool.h"
#include <concurrent_queue.h>    // 新增并发队列支持
#include <condition_variable>    // 新增条件变量支持

#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <iostream>

// 全局常量定义 - 便于调整性能参数
constexpr size_t LOCK_SHARD_COUNT = 64;       // 哈希表分片锁数量(增加到64)
constexpr size_t LOCAL_BUFFER_SIZE = 32;      // 本地缓冲区大小
constexpr size_t MAX_CACHE_BLOCKS = 16;       // 增大缓存块上限
constexpr size_t BATCH_PROCESS_SIZE = 128;    // 批处理大小
constexpr size_t ASYNC_QUEUE_CAPACITY = 4096; // 异步队列容量

// 当前内存跟踪级别
static std::atomic<MemoryTrackingLevel> g_trackingLevel{ MemoryTrackingLevel::Basic };

MemorySafety& g_MemSafety = MemorySafety::GetInstance();

// 特殊块过滤器列表 - 无需修改
static std::vector<SpecialBlockFilter> g_specialFilters = {
    // JassVM 相关分配，使用独立的低地址内存
    { 0x28A8, "Instance.cpp", 0, true, true },  // JassVM 实例
    //{ 0x64, "jass.cpp", 0, true, true },       // JassVM 栈帧
    //{ 0, "jass", 0, true, true },              // 捕获所有包含 "jass" 的分配
    //{ 0, "Instance", 0, true, true },          // 捕获所有包含 "Instance" 的分配

    // 地形和模型可以使用 TLSF
    { 0, "terrain", 0, true, false },
    { 0, "model", 0, true, false },
};

// 额外状态变量
std::atomic<bool> g_afterCleanAll{ false };
std::atomic<DWORD> g_lastCleanAllTime{ 0 };
thread_local bool tls_inCleanAll = false;
std::atomic<bool> g_insideUnsafePeriod{ false }; // 标记不安全时期
std::atomic<bool> g_shouldExit{ false };
std::atomic<bool> g_disableActualFree{ false };
static std::atomic<bool> g_disableMemoryReleasing{ false };
HANDLE g_statsThreadHandle = NULL;
std::condition_variable g_shutdownCondition; // 新增：优雅关闭条件变量
std::mutex g_shutdownMutex;                 // 新增：关闭互斥量
std::atomic<size_t> g_peakVirtualMemoryUsage{ 0 }; // 初始化为0

// 全局变量定义
std::atomic<size_t> g_bigThreshold{ 128 * 1024 };      // 默认128KB为大块阈值

// 优化：使用分片读写锁代替单一互斥锁
struct BlockInfoShardedMap {
    struct Shard {
        mutable std::shared_mutex rwMutex; // 修改：添加 mutable
        std::unordered_map<void*, BigBlockInfo> blocks;
    };

    Shard shards[LOCK_SHARD_COUNT];

    // 根据指针计算分片索引
    size_t getShardIndex(void* ptr) const {
        return (reinterpret_cast<uintptr_t>(ptr) / 16) % LOCK_SHARD_COUNT;
    }

    // 查找操作 - 使用共享锁(读锁)
    bool find(void* ptr, BigBlockInfo& info) const { // 修改：添加 const
        size_t idx = getShardIndex(ptr);
        std::shared_lock<std::shared_mutex> lock(shards[idx].rwMutex);
        auto it = shards[idx].blocks.find(ptr);
        if (it != shards[idx].blocks.end()) {
            info = it->second;
            return true;
        }
        return false;
    }

    // 插入操作 - 使用独占锁(写锁)
    void insert(void* ptr, const BigBlockInfo& info) {
        size_t idx = getShardIndex(ptr);
        std::unique_lock<std::shared_mutex> lock(shards[idx].rwMutex);
        shards[idx].blocks[ptr] = info;
    }

    // 移除操作 - 使用独占锁(写锁)
    bool erase(void* ptr) {
        size_t idx = getShardIndex(ptr);
        std::unique_lock<std::shared_mutex> lock(shards[idx].rwMutex);
        auto it = shards[idx].blocks.find(ptr);
        if (it != shards[idx].blocks.end()) {
            // 释放源信息字符串
            if (it->second.source) {
                free((void*)it->second.source);
            }
            shards[idx].blocks.erase(it);
            return true;
        }
        return false;
    }

    // 获取总块数 - 加读锁
    size_t size() const {
        size_t total = 0;
        for (size_t i = 0; i < LOCK_SHARD_COUNT; ++i) {
            std::shared_lock<std::shared_mutex> lock(shards[i].rwMutex);
            total += shards[i].blocks.size();
        }
        return total;
    }

    // 类型统计 - 加读锁
    void collectTypeStats(std::map<ResourceType, size_t>& typeCount,
        std::map<ResourceType, size_t>& typeSize) const {
        for (size_t i = 0; i < LOCK_SHARD_COUNT; ++i) {
            std::shared_lock<std::shared_mutex> lock(shards[i].rwMutex);
            for (const auto& entry : shards[i].blocks) {
                typeCount[entry.second.type]++;
                typeSize[entry.second.type] += entry.second.size;
            }
        }
    }

    // 清除所有数据 - 加写锁
    void clear() {
        for (size_t i = 0; i < LOCK_SHARD_COUNT; ++i) {
            std::unique_lock<std::shared_mutex> lock(shards[i].rwMutex);
            for (auto& entry : shards[i].blocks) {
                if (entry.second.source) {
                    free((void*)entry.second.source);
                }
            }
            shards[i].blocks.clear();
        }
    }
};

// 定义全局哈希表 (已在 .h 中声明为 extern)
BlockInfoShardedMap g_bigBlocks;
// 定义全局内存统计 (已在 .h 中声明为 extern)
MemoryStats g_memStats;
// 其他全局状态变量 (已在 .h 中声明为 extern)
std::atomic<bool> g_cleanAllInProgress{ false };
DWORD g_cleanAllThreadId = 0;

// 线程安全的永久块列表 (类定义)
class ThreadSafePermanentBlocks {
private:
    mutable std::shared_mutex m_mutex; // 修改：添加 mutable
    std::vector<void*> m_blocks;

public:
    void add(void* ptr) {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_blocks.push_back(ptr);
    }

    bool contains(void* ptr) const {
        std::shared_lock lock(m_mutex); // C++17
        return std::find(m_blocks.begin(), m_blocks.end(), ptr) != m_blocks.end();
    }

    void clear() {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_blocks.clear();
    }

    size_t size() const {
        std::shared_lock lock(m_mutex); // C++17
        return m_blocks.size();
    }
};

// 替换静态向量为线程安全容器
ThreadSafePermanentBlocks g_permanentBlocks;

// 优化临时稳定区块存储
class ThreadSafeTempStabilizers {
private:
    mutable std::mutex m_mutex; // 修改：添加 mutable
    std::vector<TempStabilizerBlock> m_blocks;

public:
    void add(const TempStabilizerBlock& block) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_blocks.push_back(block);
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex); // const 函数中使用 lock_guard 需要 mutable mutex
        return m_blocks.size();
    }

    // 更新TTL并移除过期块 - 返回移除的块数
    size_t updateAndRemoveExpired() {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t removedCount = 0;
        auto it = m_blocks.begin();
        while (it != m_blocks.end()) {
            it->ttl--;
            if (it->ttl <= 0) {
                // 将要从列表移除的块加入移除列表
                void* ptr = it->ptr;

                // 从BigBlocks中移除 - 不在此处加锁，避免死锁
                g_bigBlocks.erase(ptr);

                // 安全释放 - 不在持有当前锁的情况下调用，避免死锁
                MemPool::FreeSafe(ptr);

                // 从列表移除
                it = m_blocks.erase(it);
                removedCount++;
            }
            else {
                ++it;
            }
        }
        return removedCount;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_blocks.clear();
    }
};

ThreadSafeTempStabilizers g_tempStabilizers;

// Storm原始函数指针
Storm_MemAlloc_t    s_origStormAlloc = nullptr;
Storm_MemFree_t     s_origStormFree = nullptr;
Storm_MemReAlloc_t  s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;

// 日志文件句柄 (保持 static，仅限此文件)
static FILE* g_logFile = nullptr;

///////////////////////////////////////////////////////////////////////////////
// 优化实现
///////////////////////////////////////////////////////////////////////////////

// 优化大块缓存 - 使用分片锁和更高效的查找
class LargeBlockCache {
private:
    // 缓存块结构
    struct CachedBlock {
        void* ptr;
        size_t size;
        DWORD timestamp;
    };

    // 分片结构
    struct CacheShard {
        std::mutex mutex;
        std::vector<CachedBlock> blocks;
    };

    // 分片数组
    CacheShard m_shards[16]; // 16个分片
    std::atomic<size_t> m_totalBlocks{ 0 }; // 总块数计数器
    const size_t MAX_CACHE_SIZE = MAX_CACHE_BLOCKS; // 每个分片的最大缓存大小

    // 获取分片索引
    size_t getShardIndex(size_t size) const {
        return (size / 1024) % 16; // 基于大小分片
    }

public:
    void* GetBlock(size_t size) {
        size_t idx = getShardIndex(size);
        std::lock_guard<std::mutex> lock(m_shards[idx].mutex);

        // 查找适合大小的块
        auto& blocks = m_shards[idx].blocks;
        for (auto it = blocks.begin(); it != blocks.end(); ++it) {
            if (it->size >= size) {
                void* ptr = it->ptr;
                blocks.erase(it);
                m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);
                return ptr;
            }
        }

        // 如果当前分片没有找到，尝试其他分片
        if (idx != 0) { // 避免重复检查第0分片
            std::lock_guard<std::mutex> lock(m_shards[0].mutex);
            auto& blocks = m_shards[0].blocks;
            for (auto it = blocks.begin(); it != blocks.end(); ++it) {
                if (it->size >= size) {
                    void* ptr = it->ptr;
                    blocks.erase(it);
                    m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);
                    return ptr;
                }
            }
        }

        return nullptr;
    }

    void ReleaseBlock(void* ptr, size_t size) {
        size_t idx = getShardIndex(size);
        std::lock_guard<std::mutex> lock(m_shards[idx].mutex);

        auto& blocks = m_shards[idx].blocks;

        // 如果缓存已满，释放最老的块
        if (blocks.size() >= MAX_CACHE_SIZE) {
            auto oldest = std::min_element(blocks.begin(), blocks.end(),
                [](const CachedBlock& a, const CachedBlock& b) {
                    return a.timestamp < b.timestamp;
                });

            if (oldest != blocks.end()) {
                VirtualFree(oldest->ptr, 0, MEM_RELEASE);
                blocks.erase(oldest);
                m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        // 添加新块到缓存
        CachedBlock block{ ptr, size, GetTickCount() };
        blocks.push_back(block);
        m_totalBlocks.fetch_add(1, std::memory_order_relaxed);
    }

    size_t GetCacheSize() const {
        return m_totalBlocks.load(std::memory_order_relaxed);
    }
};

// 定义全局大块缓存 (已在 .h 中声明为 extern)
LargeBlockCache g_largeBlockCache;

// 优化异步内存释放器 - 使用并发队列和本地缓冲
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

    void WorkerThread() {
        std::vector<DeferredFree> itemsToFree;
        itemsToFree.reserve(BATCH_PROCESS_SIZE);

        while (!m_shouldExit.load(std::memory_order_acquire)) {
            // 批量取出项目处理
            DeferredFree item;
            size_t processedCount = 0;

            // 批量获取项目
            while (processedCount < BATCH_PROCESS_SIZE && m_queue.try_pop(item)) {
                itemsToFree.push_back(item);
                processedCount++;
                m_queueSize.fetch_sub(1, std::memory_order_relaxed);
            }

            // 处理取出的项目
            for (const auto& item : itemsToFree) {
                if (!g_disableActualFree) {
                    LogMessage("[AsyncFree] 实际释放: ptr=%p, size=%zu", item.ptr, item.size);
                    VirtualFree(item.ptr, 0, MEM_RELEASE);
                }
            }

            if (!itemsToFree.empty()) {
                // 只在实际释放了内存时才记录日志
                LogMessage("[AsyncFree] 本批次释放完成, count=%zu", itemsToFree.size());
                itemsToFree.clear();
            }
            else {
                // 如果队列为空，等待条件变量通知
                std::unique_lock<std::mutex> lock(m_wakeMutex);
                m_wakeCondition.wait_for(lock, std::chrono::milliseconds(100),
                    [this]() {
                        return m_shouldExit.load(std::memory_order_acquire) ||
                            m_queueSize.load(std::memory_order_acquire) > 0;
                    });
            }
        }

        // 程序结束时处理剩余项目
        if (g_disableActualFree) {
            return; // 如果禁用了实际释放，则直接返回
        }

        LogMessage("[异步释放] 程序结束，清理剩余队列项");
        DeferredFree item;
        while (m_queue.try_pop(item)) {
            VirtualFree(item.ptr, 0, MEM_RELEASE);
        }
    }

public:
    AsyncMemoryReleaser() : m_thread(&AsyncMemoryReleaser::WorkerThread, this) {
        LogMessage("[异步释放] 工作线程已启动");
    }

    ~AsyncMemoryReleaser() {
        m_shouldExit.store(true, std::memory_order_release);
        m_wakeCondition.notify_all(); // 通知所有可能等待的线程

        if (m_thread.joinable()) {
            m_thread.join();
        }

        LogMessage("[异步释放] 工作线程已关闭");
    }

    void QueueFree(void* ptr, size_t size) {
        if (!ptr) return;

        LogMessage("[AsyncFree] 入队: ptr=%p, size=%zu, t_localBuffer.size=%zu, queueSize=%zu",
            ptr, size, t_localBuffer.size(), m_queueSize.load());

        // 使用线程本地缓冲区
        if (t_localBuffer.size() < LOCAL_BUFFER_SIZE) {
            // 本地缓冲未满，直接添加
            t_localBuffer.push_back({ ptr, size, GetTickCount() });
            LogMessage("[AsyncFree] 本地缓冲添加: ptr=%p, size=%zu, 缓冲区剩余=%zu",
                ptr, size, LOCAL_BUFFER_SIZE - t_localBuffer.size());
        }
        else {
            // 本地缓冲已满，批量提交
            for (const auto& item : t_localBuffer) {
                LogMessage("[AsyncFree] 批量入队: ptr=%p, size=%zu", item.ptr, item.size);
                m_queue.push(item);
                m_queueSize.fetch_add(1, std::memory_order_relaxed);
            }
            t_localBuffer.clear();

            // 添加当前项
            m_queue.push({ ptr, size, GetTickCount() });
            m_queueSize.fetch_add(1, std::memory_order_relaxed);
            LogMessage("[AsyncFree] 批量提交后入队: ptr=%p, size=%zu, queueSize=%zu",
                ptr, size, m_queueSize.load());

            // 通知工作线程
            m_wakeCondition.notify_one();
        }
    }

    // 强制刷新本地缓冲区
    void FlushLocalBuffer() {
        if (!t_localBuffer.empty()) {
            for (const auto& item : t_localBuffer) {
                m_queue.push(item);
                m_queueSize.fetch_add(1, std::memory_order_relaxed);
            }
            t_localBuffer.clear();
            m_wakeCondition.notify_one();
        }
    }

    size_t GetQueueSize() const {
        return m_queueSize.load(std::memory_order_relaxed) + t_localBuffer.size();
    }
};

// 定义全局异步释放器 (已在 .h 中声明为 extern)
AsyncMemoryReleaser g_asyncReleaser;

// 将线程本地缓冲区的定义移到 AsyncMemoryReleaser 构造函数之后，确保 DeferredFree 已定义
thread_local std::vector<AsyncMemoryReleaser::DeferredFree> AsyncMemoryReleaser::t_localBuffer;

///////////////////////////////////////////////////////////////////////////////
// 辅助函数
///////////////////////////////////////////////////////////////////////////////

// 设置内存跟踪级别
void SetMemoryTrackingLevel(MemoryTrackingLevel level) {
    MemoryTrackingLevel oldLevel = g_trackingLevel.exchange(level);

    // 如果从低级别提升到 Detailed 或以上，且统计线程未运行，则启动统计线程
    if (oldLevel < MemoryTrackingLevel::Detailed &&
        level >= MemoryTrackingLevel::Detailed &&
        !g_statsThreadHandle) {

        HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
        if (hThread) {
            g_statsThreadHandle = hThread;
            LOG_INFO("内存统计线程已启动（跟踪级别提升）");
        }
    }

    // 如果从高级别降到 Basic 或以下，且统计线程正在运行，则停止统计线程
    if (oldLevel >= MemoryTrackingLevel::Detailed &&
        level < MemoryTrackingLevel::Detailed &&
        g_statsThreadHandle) {

        g_shouldExit.store(true);
        DWORD waitResult = WaitForSingleObject(g_statsThreadHandle, 1000);
        if (waitResult != WAIT_OBJECT_0) {
            LOG_WARNING("统计线程未能在1秒内结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }

        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
        LOG_INFO("内存统计线程已停止（跟踪级别降低）");
    }

    // 根据级别调整日志系统
    switch (level) {
    case MemoryTrackingLevel::None:
        LogSystem::GetInstance().SetLogLevel(LogLevel::Error);
        break;
    case MemoryTrackingLevel::Basic:
        LogSystem::GetInstance().SetLogLevel(LogLevel::Info);
        break;
    case MemoryTrackingLevel::Detailed:
    case MemoryTrackingLevel::Full:
        LogSystem::GetInstance().SetLogLevel(LogLevel::Debug);
        break;
    }

    LOG_INFO("内存跟踪级别已更改: %d -> %d",
        static_cast<int>(oldLevel), static_cast<int>(level));
}

// 获取当前内存跟踪级别
MemoryTrackingLevel GetMemoryTrackingLevel() {
    return g_trackingLevel.load();
}

size_t GetProcessVirtualMemoryUsage() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc))) {
        return pmc.PrivateUsage; // 返回进程的虚拟内存使用量（Private Bytes）
    }

    return 0; // 获取失败则返回0
}

void UpdatePeakMemoryUsage() {
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t currentPeak = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    while (currentVMUsage > currentPeak) {
        if (g_peakVirtualMemoryUsage.compare_exchange_weak(currentPeak, currentVMUsage, std::memory_order_relaxed)) {
            // 仅在有显著变化时记录日志（如增加1MB以上）
            if (currentVMUsage - currentPeak > 1024 * 1024) {
                LogMessage("[内存] 新程序虚拟内存峰值: %zu MB (+%zu KB)",
                    currentVMUsage / (1024 * 1024),
                    (currentVMUsage - currentPeak) / 1024);
            }
            break;
        }
        // 如果CAS失败，获取最新的峰值再尝试
        currentPeak = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);
    }
}

// 设置大块阈值
void SetBigBlockThreshold(size_t sizeInBytes) {
    size_t oldThreshold = g_bigThreshold.exchange(sizeInBytes);
    LOG_INFO("大块阈值已更改: %zu -> %zu 字节", oldThreshold, sizeInBytes);
}

// 获取 Storm 虚拟内存占用
size_t GetStormVirtualMemoryUsage() {
    // 使用原子读取，无需优化
    return Storm_g_TotalAllocatedMemory ? Storm_g_TotalAllocatedMemory : 0;
}

// 获取 TLSF 内存池已用大小
size_t GetTLSFPoolUsage() {
    return MemPool::GetUsedSize();
}

// 获取 TLSF 内存池总大小
size_t GetTLSFPoolTotal() {
    return MemPool::GetTotalSize();
}

// 优化内存报告生成逻辑 - 减少频繁报告导致的性能影响
void GenerateMemoryReport(bool forceWrite) {
    static std::atomic<DWORD> lastReportTime{ 0 };
    DWORD currentTime = GetTickCount();
    DWORD lastTime = lastReportTime.load(std::memory_order_relaxed);

    // 默认每30秒生成一次报告，除非强制生成
    if (!forceWrite && (currentTime - lastTime < 30000)) {
        return;
    }

    // 使用CAS确保只有一个线程更新报告
    if (!forceWrite && !lastReportTime.compare_exchange_strong(lastTime, currentTime,
        std::memory_order_acquire)) {
        return; // 另一个线程已经在生成报告
    }

    // 获取内存数据
    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t tlsfUsed = GetTLSFPoolUsage();
    size_t tlsfTotal = GetTLSFPoolTotal();
    size_t managed = g_bigBlocks.size();
    size_t cachedBlocks = g_largeBlockCache.GetCacheSize();
    size_t asyncQueueSize = g_asyncReleaser.GetQueueSize();

    // 获取当前程序虚拟内存使用量和峰值
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t peakVMUsage = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    // 确保峰值不小于当前值
    if (currentVMUsage > peakVMUsage) {
        peakVMUsage = currentVMUsage;
        g_peakVirtualMemoryUsage.store(currentVMUsage, std::memory_order_relaxed);
    }

    // 计算使用率
    double tlsfUsagePercent = tlsfTotal > 0 ? (tlsfUsed * 100.0 / tlsfTotal) : 0.0;

    // 获取进程整体内存使用情况
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);

    size_t workingSetMB = 0;

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
    }

    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 生成报告文本，添加程序虚拟内存峰值
    char reportBuffer[2048];
    int len = sprintf_s(reportBuffer,
        "===== 内存使用报告 =====\n"
        "时间: %02d:%02d:%02d\n"
        "程序虚拟内存: %zu MB (峰值: %zu MB)\n"
        "Storm 虚拟内存: %zu MB\n"
        "TLSF 内存池: %zu MB / %zu MB (%.1f%%)\n"
        "TLSF 管理块数量: %zu\n"
        "大块缓存: %zu 个\n"
        "异步释放队列: %zu 个\n"
        "工作集大小: %zu MB\n"
        "========================\n",
        st.wHour, st.wMinute, st.wSecond,
        currentVMUsage / (1024 * 1024), peakVMUsage / (1024 * 1024),  // 添加程序虚拟内存和峰值
        stormVMUsage / (1024 * 1024),
        tlsfUsed / (1024 * 1024), tlsfTotal / (1024 * 1024), tlsfUsagePercent,
        managed,
        cachedBlocks,
        asyncQueueSize,
        workingSetMB
    );

    // 同时输出到控制台和日志
    LogMessage("\n%s", reportBuffer);
}

// 简化版状态输出，适合频繁调用 - 使用线程本地存储减少内存分配
void PrintMemoryStatus() {
    // 使用线程本地缓冲区
    thread_local char buffer[512];

    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t tlsfUsed = GetTLSFPoolUsage();
    size_t tlsfTotal = GetTLSFPoolTotal();

    // 获取当前程序虚拟内存和峰值
    size_t currentVMUsage = GetProcessVirtualMemoryUsage();
    size_t peakVMUsage = g_peakVirtualMemoryUsage.load(std::memory_order_relaxed);

    // 确保峰值不小于当前值
    if (currentVMUsage > peakVMUsage) {
        peakVMUsage = currentVMUsage;
        g_peakVirtualMemoryUsage.store(currentVMUsage, std::memory_order_relaxed);
    }

    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 格式化到缓冲区，添加程序虚拟内存峰值
    sprintf_s(buffer, sizeof(buffer),
        "[%02d:%02d:%02d] [内存] 程序VM: %zu/%zu MB, Storm: %zu MB, TLSF: %zu/%zu MB (%.1f%%)",
        st.wHour, st.wMinute, st.wSecond,
        currentVMUsage / (1024 * 1024), peakVMUsage / (1024 * 1024),
        stormVMUsage / (1024 * 1024),
        tlsfUsed / (1024 * 1024),
        tlsfTotal / (1024 * 1024),
        tlsfTotal > 0 ? (tlsfUsed * 100.0 / tlsfTotal) : 0.0);

    // 控制台输出
    printf("%s\n", buffer);

    // 日志输出
    LogMessage("%s", buffer);
}

// 使用SEH包装SafeMemCopy实现，优化异常处理
bool SafeMemCopy(void* dest, const void* src, size_t size) noexcept {
    if (!dest || !src || size == 0) return false;

    __try {
        // 使用固定分块大小减少循环开销
        const size_t CHUNK_SIZE = 4096;
        const char* srcPtr = static_cast<const char*>(src);
        char* destPtr = static_cast<char*>(dest);

        // 主要复制部分 - 完整块
        size_t fullChunks = size / CHUNK_SIZE;
        for (size_t i = 0; i < fullChunks; i++) {
            memcpy(destPtr + i * CHUNK_SIZE, srcPtr + i * CHUNK_SIZE, CHUNK_SIZE);
        }

        // 剩余部分
        size_t remainder = size % CHUNK_SIZE;
        if (remainder > 0) {
            memcpy(destPtr + fullChunks * CHUNK_SIZE, srcPtr + fullChunks * CHUNK_SIZE, remainder);
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[SafeMemCopy] 复制失败: dest=%p, src=%p, size=%zu, 错误=0x%x",
            dest, src, size, GetExceptionCode());
        return false;
    }
}

// 优化内存块大小获取函数
size_t GetBlockSize(void* ptr) noexcept {
    if (!ptr) return 0;

    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        // 快速检查指针和魔数
        if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
            return 0;
        }

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 什么都不做，只是捕获异常
    }

    return 0;
}

// 使用异步执行CleanupAll
void SafeExecuteCleanupAll() {
    // 通知内存安全系统进入不安全期
    g_MemSafety.EnterUnsafePeriod();

    // 保存旧的异常处理器并设置新的
    LPTOP_LEVEL_EXCEPTION_FILTER oldFilter =
        SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* pExceptionInfo) -> LONG {
        // 使用线程本地存储跟踪异常信息
        thread_local DWORD lastExceptionCode = 0;
        thread_local void* lastExceptionAddress = nullptr;

        // 只有在异常不同时才记录日志，避免重复日志
        if (lastExceptionCode != pExceptionInfo->ExceptionRecord->ExceptionCode ||
            lastExceptionAddress != pExceptionInfo->ExceptionRecord->ExceptionAddress) {

            lastExceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
            lastExceptionAddress = pExceptionInfo->ExceptionRecord->ExceptionAddress;

            LogMessage("[CleanAll] 捕获到异常: 0x%08X 位置: %p",
                pExceptionInfo->ExceptionRecord->ExceptionCode,
                pExceptionInfo->ExceptionRecord->ExceptionAddress);
        }

        return EXCEPTION_EXECUTE_HANDLER;
            });

    __try {
        // 执行原始函数
        s_origCleanupAll();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[CleanAll] 清理过程中捕获到异常");
    }

    // 恢复之前的异常处理器
    SetUnhandledExceptionFilter(oldFilter);

    // 清理完成后退出不安全期
    g_MemSafety.ExitUnsafePeriod();

    // 刷新释放队列
    g_asyncReleaser.FlushLocalBuffer();
}

// 优化兼容头设置
void SetupCompatibleHeader(void* userPtr, size_t size) {
    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        header->HeapPtr = SPECIAL_MARKER;  // 特殊标记
        header->Size = static_cast<DWORD>(size);
        header->AlignPadding = 0;
        header->Flags = 0x4;  // 标记为大块VirtualAlloc
        header->Magic = STORM_MAGIC;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[ERROR] 设置兼容头失败: %p, 错误=0x%x", userPtr, GetExceptionCode());
    }
}

// 优化块识别函数
bool IsOurBlock(void* ptr) {
    if (!ptr) return false;

    __try {
        // 快速检查指针有效性
        if (IsBadReadPtr(ptr, sizeof(void*))) {
            return false;
        }

        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        // 检查头部指针有效性
        if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
            return false;
        }

        return (header->Magic == STORM_MAGIC &&
            header->HeapPtr == SPECIAL_MARKER);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 永久块检查优化 - 直接调用线程安全容器
bool IsPermanentBlock(void* ptr) {
    if (!ptr) return false;
    return g_permanentBlocks.contains(ptr);
}

// 根据名称判断资源类型 - 使用哈希表加速
ResourceType GetResourceType(const char* name) {
    if (!name) return ResourceType::Unknown;

    // 使用线程本地缓存的哈希表加速查找
    thread_local std::unordered_map<const char*, ResourceType> t_typeCache;

    // 先在缓存中查找
    auto it = t_typeCache.find(name);
    if (it != t_typeCache.end()) {
        return it->second;
    }

    // 缓存未命中，执行完整的字符串匹配
    ResourceType type = ResourceType::Unknown;

    if (strstr(name, "Model") || strstr(name, "GEOSET") || strstr(name, "MDX"))
        type = ResourceType::Model;
    else if (strstr(name, "CUnit") || strstr(name, "Unit"))
        type = ResourceType::Unit;
    else if (strstr(name, "Terrain") || strstr(name, "Ground"))
        type = ResourceType::Terrain;
    else if (strstr(name, "Sound") || strstr(name, "SND") || strstr(name, "Audio"))
        type = ResourceType::Sound;
    else if (strstr(name, "SFile") || strstr(name, "File"))
        type = ResourceType::File;
    else if (strstr(name, "Instance") || strstr(name, "jass") || strstr(name, "Jass"))
        type = ResourceType::JassVM;

    // 将结果加入缓存
    if (t_typeCache.size() < 1000) { // 避免缓存无限增长
        t_typeCache[name] = type;
    }

    return type;
}

// 优化特殊块检查 - 使用更高效的实现
bool IsSpecialBlockAllocation(size_t size, const char* name, DWORD src_line) {
    // 先快速检查大小过滤
    bool hasSpecificSize = false;
    for (const auto& filter : g_specialFilters) {
        if (filter.size != 0 && filter.size == size) {
            hasSpecificSize = true;

            // 如果只要求匹配大小
            if (filter.name == nullptr && filter.sourceLine == 0) {
                return true;
            }

            // 如果要求匹配名称和大小
            if (name && filter.name && strstr(name, filter.name)) {
                // 如果不要求匹配源码行或者行也匹配
                if (filter.sourceLine == 0 || filter.sourceLine == src_line) {
                    return true;
                }
            }
        }
    }

    // 如果没找到匹配的大小，检查只匹配名称的过滤器
    if (!hasSpecificSize && name) {
        for (const auto& filter : g_specialFilters) {
            if (filter.size == 0 && filter.name && strstr(name, filter.name)) {
                if (filter.sourceLine == 0 || filter.sourceLine == src_line) {
                    return true;
                }
            }
        }
    }

    return false;
}

// JassVM内存分配函数优化
void* AllocateJassVMMemory(size_t size) {
    // 使用 VirtualAlloc 直接分配而非 TLSF
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rawPtr) {
        LogMessage("[JassVM] 内存分配失败: %zu 字节", size);
        return nullptr;
    }

    void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
    SetupCompatibleHeader(userPtr, size);

    // 记录此块信息
    BigBlockInfo info;
    info.rawPtr = rawPtr;
    info.size = size;
    info.timestamp = GetTickCount();
    info.source = _strdup("JassVM_专用内存");
    info.srcLine = 0;
    info.type = ResourceType::JassVM;

    // 添加到分片哈希表
    g_bigBlocks.insert(userPtr, info);

    return userPtr;
}

///////////////////////////////////////////////////////////////////////////////
// TLSF 内存池实现
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

    static std::atomic<bool> g_inTLSFOperation{ false };

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
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
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

                if (header->Magic == STORM_MAGIC && header->HeapPtr == SPECIAL_MARKER) {
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
        void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
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

///////////////////////////////////////////////////////////////////////////////
// 统计信息线程
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI MemoryStatsThread(LPVOID) {
    LogMessage("[StatsThread] 内存监控线程已启动");

    // 使用条件变量替代Sleep实现优雅退出
    std::unique_lock<std::mutex> lock(g_shutdownMutex, std::defer_lock);

    DWORD lastCleanupTime = GetTickCount();
    DWORD lastStatsTime = GetTickCount();
    DWORD lastReportTime = GetTickCount();
    DWORD lastProfileTime = GetTickCount();

    while (!g_shouldExit.load(std::memory_order_acquire)) {
        // 使用条件变量等待而不是Sleep
        lock.lock();
        // 修复 lambda 捕获和变量访问：应检查全局 g_shouldExit
        bool shouldExit = g_shutdownCondition.wait_for(lock, std::chrono::milliseconds(5000),
            [] { return g_shouldExit.load(std::memory_order_acquire); }); // 使用全局退出标志
        lock.unlock();

        if (shouldExit) break;

        DWORD currentTime = GetTickCount();

        // 使用批处理减少锁争用，同一时间只做一种操作
        // 1. 每30秒生成内存报告
        if (currentTime - lastReportTime > 30000) {
            GenerateMemoryReport();
            lastReportTime = currentTime;
            continue; // 跳过其他操作，减少同一周期的工作量
        }

        // 2. 每30秒尝试释放未使用的扩展池
        if (currentTime - lastCleanupTime > 30000) {
            if (!g_cleanAllInProgress && !g_insideUnsafePeriod.load(std::memory_order_acquire)) {
                MemPool::CheckAndFreeUnusedPools();
            }
            lastCleanupTime = currentTime;
            continue;
        }

        // 4. 每分钟打印一次内存统计
        if (currentTime - lastStatsTime > 60000) {
            // 分配统计打印
            size_t allocTotal = g_memStats.totalAllocated.load(std::memory_order_relaxed);
            size_t freeTotal = g_memStats.totalFreed.load(std::memory_order_relaxed);
            size_t inUse = (allocTotal > freeTotal) ? (allocTotal - freeTotal) : 0;

            LogMessage("\n[内存状态] ---- 距上次报告%u秒 ----",
                (currentTime - lastStatsTime) / 1000);

            LogMessage("[内存状态] 总计追踪: 已分配=%zu MB, 已释放=%zu MB, 使用中=%zu MB",
                allocTotal / (1024 * 1024), freeTotal / (1024 * 1024), inUse / (1024 * 1024));

            // Storm内部统计
            LogMessage("[内存状态] Storm_TotalAllocatedMemory=%zu MB",
                Storm_g_TotalAllocatedMemory / (1024 * 1024));

            // 缓存和队列状态
            LogMessage("[内存状态] 大块缓存大小: %zu", g_largeBlockCache.GetCacheSize());
            LogMessage("[内存状态] 异步释放队列大小: %zu", g_asyncReleaser.GetQueueSize());

            // 资源类型分布统计
            std::map<ResourceType, size_t> typeCount;
            std::map<ResourceType, size_t> typeSize;
            g_bigBlocks.collectTypeStats(typeCount, typeSize);

            LogMessage("[内存状态] TLSF管理块: 数量=%zu", g_bigBlocks.size());
            LogMessage("[内存状态] 资源类型分布:");

            for (const auto& entry : typeCount) {
                const char* typeName = "未知";
                switch (entry.first) {
                case ResourceType::Model: typeName = "模型"; break;
                case ResourceType::Unit: typeName = "单位"; break;
                case ResourceType::Terrain: typeName = "地形"; break;
                case ResourceType::Sound: typeName = "声音"; break;
                case ResourceType::File: typeName = "文件"; break;
                case ResourceType::JassVM: typeName = "JassVM"; break;
                default: break;
                }

                LogMessage("  - %s: %zu 块, %zu MB",
                    typeName, entry.second, typeSize[entry.first] / (1024 * 1024));
            }

            // 打印分配分析和内存池统计
            MemPool::PrintStats();

            lastStatsTime = currentTime;
        }
    }

    LogMessage("[StatsThread] 内存监控线程安全退出");
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// 钩子函数实现优化
///////////////////////////////////////////////////////////////////////////////

// 优化创建永久稳定块 - 使用批量分配减少锁争用
void CreatePermanentStabilizers(int count, const char* reason) {
    LogMessage("[稳定化] 创建%d个永久稳定块 (%s)", count, reason);

    // 使用黄金比例分布的大小
    std::vector<size_t> sizes;
    size_t size = 16;  // 起始大小

    for (int i = 0; i < count; i++) {
        sizes.push_back(size);
        size = (size_t)(size * 1.618);  // 黄金比例
        if (size > 4096) size = 16;     // 重置循环
    }

    // 确保有些特殊大小
    if (count > 10) {
        sizes[3] = 64;
        sizes[7] = 128;
    }

    // 批量创建稳定块
    std::vector<void*> newStabilizers;
    newStabilizers.reserve(count);

    for (size_t blockSize : sizes) {
        void* stabilizer = MemPool::CreateStabilizingBlock(blockSize, "永久稳定块");
        if (stabilizer) {
            newStabilizers.push_back(stabilizer);
            LogMessage("[稳定化] 永久块: %p (大小: %zu)", stabilizer, blockSize);
        }
    }

    // 批量添加到永久块列表，减少锁争用
    for (void* ptr : newStabilizers) {
        g_permanentBlocks.add(ptr);
    }
}

// 优化 StormHeap_CleanupAll 钩子实现
void Hooked_StormHeap_CleanupAll() {
    // 防止递归调用
    if (tls_inCleanAll) {
        LogMessage("[CleanAll] 递归调用被阻止");
        return;
    }

    // 时间节流 - 避免频繁CleanAll
    DWORD currentTime = GetTickCount();
    DWORD lastTime = g_lastCleanAllTime.load(std::memory_order_relaxed);

    if (currentTime - lastTime < 5000) {
        return; // 5秒内不重复执行
    }

    // 使用原子操作更新最后执行时间
    if (!g_lastCleanAllTime.compare_exchange_strong(lastTime, currentTime,
        std::memory_order_acquire)) {
        return; // 另一个线程已经在执行
    }

    // 设置线程局部标志和全局标志
    tls_inCleanAll = true;
    g_cleanAllInProgress.store(true, std::memory_order_release);
    g_cleanAllThreadId = GetCurrentThreadId();

    // 记录当前TLSF块数量 - 使用无锁操作
    size_t bigBlocksCount = g_bigBlocks.size();
    if (bigBlocksCount > 0) {
        LogMessage("[CleanAll] 开始执行，当前管理%zu个TLSF块", bigBlocksCount);
    }

    // 保存原始的g_DebugHeapPtr值
    int originalDebugHeapPtr = Storm_g_DebugHeapPtr;

    // 使用增强的安全执行方法
    SafeExecuteCleanupAll();

    // 重置Storm内部状态
    Storm_g_DebugHeapPtr = 0;

    // 再次检查TLSF块数量
    if (bigBlocksCount > 0) {
        size_t newBlockCount = g_bigBlocks.size();
        LogMessage("[CleanAll] 完成后，TLSF管理块数量: %zu -> %zu",
            bigBlocksCount, newBlockCount);
    }

    // 设置清理完成标志
    g_afterCleanAll.store(true, std::memory_order_release);
    g_cleanAllInProgress.store(false, std::memory_order_release);
    g_cleanAllThreadId = 0;

    // 立即结束不安全期
    g_insideUnsafePeriod.store(false, std::memory_order_release);

    tls_inCleanAll = false;

    LogMessage("[CleanAll] 完成，已重置内部状态");

    // 验证所有内存块和处理延迟释放队列
    // 改为异步执行，避免阻塞主线程
    std::thread([] {
        // 延时执行，让当前操作完全结束
        Sleep(100);
        g_MemSafety.ValidateAllBlocks();
        g_MemSafety.ProcessDeferredFreeQueue();
        }).detach();
}

// 优化创建稳定化块的函数
void CreateStabilizingBlocks(int cleanAllCount) {
    static std::atomic<int> lastCleanAllCount{ 0 };
    int lastCount = lastCleanAllCount.load(std::memory_order_relaxed);

    // 仅每 20 次 CleanAll 执行一次
    if (cleanAllCount - lastCount < 20) {
        return;
    }

    // 使用CAS确保只有一个线程更新计数器
    if (!lastCleanAllCount.compare_exchange_strong(lastCount, cleanAllCount,
        std::memory_order_acquire)) {
        return; // 另一个线程已经在处理
    }

    // 清理过期的临时块 - 直接使用优化后的线程安全容器
    size_t removedCount = g_tempStabilizers.updateAndRemoveExpired();
    if (removedCount > 0) {
        LogMessage("[StabilizerBlocks] 释放过期临时块，数量=%zu", removedCount);
    }

    // 如果已有足够的临时块，不再创建
    if (g_tempStabilizers.size() >= 5) {
        return;
    }

    // 创建新块
    int numBlocks = 2;
    LogMessage("[StabilizerBlocks] 创建%d个临时稳定块 (第%d次CleanAll)",
        numBlocks, cleanAllCount);

    for (int i = 0; i < numBlocks; i++) {
        // 使用更大间隔的块大小
        size_t blockSize = 16 * (1 << i);  // 16, 32, 64...
        void* stabilizer = MemPool::CreateStabilizingBlock(blockSize, "临时稳定块");

        if (stabilizer) {
            LogMessage("[StabilizerBlock] 分配稳定块: %p (大小: %zu)",
                stabilizer, blockSize);

            // 添加到临时块列表
            TempStabilizerBlock block;
            block.ptr = stabilizer;
            block.size = blockSize;
            block.createTime = GetTickCount();
            block.ttl = 10;  // 10次 CleanAll 生命周期

            // 使用优化后的线程安全容器
            g_tempStabilizers.add(block);

            // 记录到大块管理
            BigBlockInfo info;
            info.rawPtr = static_cast<char*>(stabilizer) - sizeof(StormAllocHeader);
            info.size = blockSize;
            info.timestamp = GetTickCount();
            info.source = _strdup("临时稳定块");
            info.srcLine = 0;
            info.type = ResourceType::Unknown;

            // 添加到分片哈希表
            g_bigBlocks.insert(stabilizer, info);
        }
    }

    LogMessage("[StabilizerBlocks] 稳定化块创建完成");
}

// 优化分配钩子
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag) {
    // 记录内存分配
    g_memoryTracker.RecordAlloc(size, name);

    // 检查是否在 CleanAll 后的第一次分配
    bool isAfterCleanAll = g_afterCleanAll.exchange(false, std::memory_order_acq_rel);
    if (isAfterCleanAll) {
        static std::atomic<int> cleanAllCounter{ 0 };
        int newCounter = cleanAllCounter.fetch_add(1, std::memory_order_relaxed) + 1;

        // 使用异步方式创建稳定块，避免阻塞主线程
        std::thread([newCounter] {
            CreateStabilizingBlocks(newCounter);
            }).detach();
    }

    // 检查是否为 JassVM 相关分配 - 使用严格的识别
    if (name && size == 10408 && strstr(name, "Instance.cpp")) {
        // 先记录分配（仅计数，不累加大小，因为JassVM池会单独记录）
        g_memoryTracker.RecordAlloc(size, "Instance.cpp", true);

        void* jassPtr = JVM_MemPool::Allocate(size);
        if (jassPtr) {
            g_memStats.OnAlloc(size);

            // 更新程序虚拟内存峰值
            UpdatePeakMemoryUsage();

            return reinterpret_cast<size_t>(jassPtr);
        }
        // 分配失败回退到 Storm
        LogMessage("[JassVM] 分配失败，回退到 Storm: %zu 字节", size);
    }

    // 分配策略：大块使用 TLSF，小块使用 Storm
    bool useTLSF = (size >= g_bigThreshold.load(std::memory_order_relaxed));

    if (useTLSF) {
        // 先尝试从缓存获取大块
        void* cachedPtr = g_largeBlockCache.GetBlock(size + sizeof(StormAllocHeader));
        if (cachedPtr) {
            void* userPtr = static_cast<char*>(cachedPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);

            // 记录此块信息
            BigBlockInfo info;
            info.rawPtr = cachedPtr;
            info.size = size;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : nullptr;
            info.srcLine = src_line;
            info.type = GetResourceType(name);

            // 添加到分片哈希表
            g_bigBlocks.insert(userPtr, info);

            g_memStats.OnAlloc(size);

            // 更新程序虚拟内存峰值
            UpdatePeakMemoryUsage();

            return reinterpret_cast<size_t>(userPtr);
        }

        // 缓存未命中，使用 TLSF 分配
        size_t totalSize = size + sizeof(StormAllocHeader);
        void* rawPtr = MemPool::AllocateSafe(totalSize);

        if (!rawPtr) {
            LogMessage("[Alloc] TLSF 分配失败: %zu 字节, 回退到 Storm", size);
            size_t ret = s_origStormAlloc(ecx, edx, size, name, src_line, flag);

            if (ret) {
                g_memStats.OnAlloc(size);

                // 更新程序虚拟内存峰值
                UpdatePeakMemoryUsage();
            }

            return ret;
        }

        // 设置用户指针和兼容头
        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        // 注册到内存安全系统 - 使用异步注册减少主线程开销
        if (!g_cleanAllInProgress && !g_insideUnsafePeriod.load(std::memory_order_acquire)) {
            g_MemSafety.RegisterMemoryBlock(rawPtr, userPtr, size, name, src_line);
        }

        // 记录此块信息
        BigBlockInfo info;
        info.rawPtr = rawPtr;
        info.size = size;
        info.timestamp = GetTickCount();
        info.source = name ? _strdup(name) : nullptr;
        info.srcLine = src_line;
        info.type = GetResourceType(name);

        // 添加到分片哈希表
        g_bigBlocks.insert(userPtr, info);

        g_memStats.OnAlloc(size);

        // 更新程序虚拟内存峰值
        UpdatePeakMemoryUsage();

        return reinterpret_cast<size_t>(userPtr);
    }
    else {
        // 小块使用 Storm 原始分配
        size_t ret = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        if (ret) {
            g_memStats.OnAlloc(size);

            // 更新程序虚拟内存峰值
            UpdatePeakMemoryUsage();
        }
        return ret;
    }
}

int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    if (!a1) return 1;  // 空指针认为成功

    void* ptr = reinterpret_cast<void*>(a1);

    // 获取块信息用于记录
    size_t blockSize = 0;
    const char* blockSource = nullptr;

    // 尝试从g_bigBlocks获取块信息
    BigBlockInfo blockInfo;
    bool blockFound = g_bigBlocks.find(ptr, blockInfo);
    if (blockFound) {
        blockSize = blockInfo.size;
        blockSource = blockInfo.source;
    }
    else {
        // 尝试使用GetBlockSize获取大小
        blockSize = GetBlockSize(ptr);
    }

    // 记录内存释放，使用找到的源信息
    g_memoryTracker.RecordFree(blockSize, blockSource ? blockSource : name);

    // 先检查是否为 JVM_MemPool 指针
    if (JVM_MemPool::IsFromPool(ptr)) {
        // 使用 JVM_MemPool 专用释放
        g_memoryTracker.RecordFree(10408, "Instance.cpp");
        JVM_MemPool::Free(ptr);
        return 1;
    }

    bool ourBlock = false;
    bool permanentBlock = false;

    // 使用异常处理检查指针
    __try {
        // 先执行最轻量级的检查 - 永久块检查
        permanentBlock = IsPermanentBlock(ptr);
        if (permanentBlock) {
            return 1; // 假装成功，无需记录日志
        }

        // 检查是否为我们管理的块
        ourBlock = IsOurBlock(ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 如果检查过程中出现异常，认为不是我们的块
        return s_origStormFree(a1, name, argList, a4);
    }

    // 常规释放流程
    if (ourBlock) {
        // 获取块信息
        BigBlockInfo blockInfo;
        bool blockFound = g_bigBlocks.find(ptr, blockInfo);

        if (blockFound) {
            // 从哈希表中移除块信息 - 在erase内部释放source指针
            g_bigBlocks.erase(ptr);

            // 更新统计
            g_memStats.OnFree(blockInfo.size);

            // 安全取消注册 - 只在安全期间执行
            if (!g_cleanAllInProgress && !g_insideUnsafePeriod.load(std::memory_order_acquire)) {
                g_MemSafety.TryUnregisterBlock(ptr);
            }

            // 对于大块，考虑放入缓存或异步释放
            if (blockInfo.size >= g_bigThreshold.load(std::memory_order_relaxed)) {
                // 如果在不安全期，使用异步释放
                if (g_cleanAllInProgress || g_insideUnsafePeriod.load(std::memory_order_acquire)) {
                    g_asyncReleaser.QueueFree(blockInfo.rawPtr, blockInfo.size);
                }
                // 否则尝试放入缓存
                else if (g_largeBlockCache.GetCacheSize() < MAX_CACHE_BLOCKS) {
                    g_largeBlockCache.ReleaseBlock(blockInfo.rawPtr, blockInfo.size);
                }
                // 缓存已满，直接释放
                else {
                    MemPool::FreeSafe(blockInfo.rawPtr);
                }
            }
            // 小块直接释放
            else {
                MemPool::FreeSafe(blockInfo.rawPtr);
            }

            g_freedByFreeHook.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            // 未找到注册的块，尝试释放原始内存
            void* rawPtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
            MemPool::FreeSafe(rawPtr);
            g_freedByFreeHook.fetch_add(1, std::memory_order_relaxed);
        }

        return 1;
    }
    else {
        // 不是我们的块，使用 Storm 释放
        return s_origStormFree(a1, name, argList, a4);
    }
}

// 优化重分配钩子
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag)
{

    // 基本边界情况处理
    if (!oldPtr) {
        return reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        return nullptr;
    }

    // 检查是否是 JVM_MemPool 内存
    if (JVM_MemPool::IsFromPool(oldPtr)) {
        // 使用 JVM_MemPool 专用重分配
        return JVM_MemPool::Realloc(oldPtr, newSize);
    }

    // 永久块特殊处理
    if (IsPermanentBlock(oldPtr)) {
        void* newPtr = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));

        if (newPtr) {
            // 只复制最少必要数据
            SafeMemCopy(newPtr, oldPtr, min(64, newSize));
        }

        return newPtr;
    }

    // 不安全期特殊处理
    bool inUnsafePeriod = g_cleanAllInProgress || g_insideUnsafePeriod.load(std::memory_order_acquire);
    if (inUnsafePeriod) {
        if (IsOurBlock(oldPtr)) {
            // 只分配，不释放
            void* newPtr = reinterpret_cast<void*>(
                Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));

            if (!newPtr) {
                return nullptr;
            }

            // 尝试安全复制
            size_t oldSize = GetBlockSize(oldPtr);
            if (oldSize > 0) {
                SafeMemCopy(newPtr, oldPtr, min(oldSize, newSize));
            }
            else {
                // 如果无法获取大小，只复制少量数据
                SafeMemCopy(newPtr, oldPtr, min(64, newSize));
            }

            // 将oldPtr放入延迟释放队列
            g_MemSafety.EnqueueDeferredFree(oldPtr, oldSize);

            return newPtr;
        }

        // 不是我们的块，使用原始函数
        return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
    }

    // 确定重分配策略
    bool isOurOldBlock = IsOurBlock(oldPtr);
    bool shouldUseTLSF = (newSize >= g_bigThreshold.load(std::memory_order_relaxed)) ||
        IsSpecialBlockAllocation(newSize, name, src_line);

    // 情况1: 我们的块重分配为我们的块
    if (isOurOldBlock && shouldUseTLSF) {
        BigBlockInfo oldInfo;
        bool blockFound = g_bigBlocks.find(oldPtr, oldInfo);

        if (!blockFound) {
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }

        // 尝试重新分配
        void* newRawPtr = nullptr;
        void* newPtr = nullptr;

        __try {
            newRawPtr = MemPool::ReallocSafe(oldInfo.rawPtr, newSize + sizeof(StormAllocHeader));
            if (!newRawPtr) {
                LogMessage("[Realloc] TLSF重分配失败, 大小=%zu", newSize);
                return nullptr;
            }

            newPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newPtr, newSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[Realloc] TLSF重分配异常: %p", oldPtr);
            return nullptr;
        }

        // 更新安全系统
        if (!inUnsafePeriod) {
            g_MemSafety.UnregisterMemoryBlock(oldPtr);
            g_MemSafety.RegisterMemoryBlock(newRawPtr, newPtr, newSize, name, src_line);
        }

        // 更新大块跟踪
        if (newPtr != oldPtr) {
            // 指针变化，更新映射
            g_bigBlocks.erase(oldPtr);

            BigBlockInfo info;
            info.rawPtr = newRawPtr;
            info.size = newSize;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : (oldInfo.source ? _strdup(oldInfo.source) : nullptr);
            info.srcLine = src_line;
            info.type = oldInfo.type;

            g_bigBlocks.insert(newPtr, info);

            // 注意：这里不需要释放 oldInfo.source，因为 erase 已经处理了
        }
        else {
            // 指针未变，通过移除再插入更新信息
            g_bigBlocks.erase(oldPtr);

            BigBlockInfo info;
            info.rawPtr = newRawPtr;
            info.size = newSize;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : (oldInfo.source ? _strdup(oldInfo.source) : nullptr);
            info.srcLine = src_line;
            info.type = oldInfo.type;

            g_bigBlocks.insert(newPtr, info);
        }

        // 更新统计
        g_memStats.OnFree(oldInfo.size);
        g_memStats.OnAlloc(newSize);

        return newPtr;
    }

    // 情况2: 我们的块重分配为Storm块（变小）
    else if (isOurOldBlock && !shouldUseTLSF) {
        BigBlockInfo oldInfo;
        bool blockFound = g_bigBlocks.find(oldPtr, oldInfo);

        if (!blockFound) {
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }

        // 使用Storm分配新块
        void* newPtr = nullptr;

        __try {
            newPtr = reinterpret_cast<void*>(s_origStormAlloc(ecx, edx, newSize, name, src_line, flag));
            if (!newPtr) {
                return nullptr;
            }

            // 安全复制数据
            SafeMemCopy(newPtr, oldPtr, min(oldInfo.size, newSize));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            if (newPtr) {
                s_origStormFree(reinterpret_cast<int>(newPtr), const_cast<char*>(name), src_line, flag);
            }
            return nullptr;
        }

        // 取消注册
        if (!inUnsafePeriod) {
            g_MemSafety.UnregisterMemoryBlock(oldPtr);
        }

        // 移除块信息
        g_bigBlocks.erase(oldPtr);

        // 释放TLSF旧块
        if (g_largeBlockCache.GetCacheSize() < MAX_CACHE_BLOCKS) {
            g_largeBlockCache.ReleaseBlock(oldInfo.rawPtr, oldInfo.size);
        }
        else {
            MemPool::FreeSafe(oldInfo.rawPtr);
        }

        // 更新统计
        g_memStats.OnFree(oldInfo.size);
        g_memStats.OnAlloc(newSize);

        return newPtr;
    }

    // 情况3: Storm块重分配为我们的块（变大）
    else if (!isOurOldBlock && shouldUseTLSF) {
        void* newRawPtr = nullptr;
        void* newUserPtr = nullptr;

        __try {
            // 分配新的TLSF块
            size_t totalSize = newSize + sizeof(StormAllocHeader);
            newRawPtr = MemPool::AllocateSafe(totalSize);
            if (!newRawPtr) {
                return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            }

            newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newUserPtr, newSize);

            // 尝试获取旧块大小
            size_t oldSize = GetBlockSize(oldPtr);

            // 安全复制数据
            if (oldSize > 0) {
                SafeMemCopy(newUserPtr, oldPtr, min(oldSize, newSize));
            }
            else {
                // 保守估计复制大小
                SafeMemCopy(newUserPtr, oldPtr, min(newSize, (size_t)128));
            }

            // 释放Storm旧块
            s_origStormFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[Realloc] Storm到TLSF转换异常");
            if (newRawPtr) {
                MemPool::FreeSafe(newRawPtr);
            }
            return nullptr;
        }

        // 注册新块
        if (!inUnsafePeriod) {
            g_MemSafety.RegisterMemoryBlock(newRawPtr, newUserPtr, newSize, name, src_line);
        }

        // 记录大块信息
        BigBlockInfo info;
        info.rawPtr = newRawPtr;
        info.size = newSize;
        info.timestamp = GetTickCount();
        info.source = name ? _strdup(name) : nullptr;
        info.srcLine = src_line;
        info.type = GetResourceType(name);

        g_bigBlocks.insert(newUserPtr, info);

        g_memStats.OnAlloc(newSize);
        return newUserPtr;
    }

    // 情况4: Storm块重分配为Storm块
    else {
        // 小块使用Storm重分配
        void* result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        if (result) {
            g_memStats.OnAlloc(newSize);
        }
        return result;
    }
}

///////////////////////////////////////////////////////////////////////////////
// 钩子安装和初始化
///////////////////////////////////////////////////////////////////////////////

// 初始化内存跟踪系统
bool InitializeMemoryTracking() {
    // 初始化日志系统
    if (!LogSystem::GetInstance().Initialize("MemoryTracker.log", LogLevel::Info)) {
        // 如果无法初始化日志，输出到标准错误
        std::cerr << "无法初始化日志系统" << std::endl;
        return false;
    }

    LOG_INFO("内存跟踪系统初始化开始");

    // 根据跟踪级别决定是否启动统计线程
    if (g_trackingLevel.load() >= MemoryTrackingLevel::Detailed) {
        // 创建统计线程
        HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
        if (hThread) {
            g_statsThreadHandle = hThread;
            LOG_INFO("内存统计线程已启动");
        }
        else {
            LOG_WARNING("无法启动内存统计线程");
        }
    }

    LOG_INFO("内存跟踪系统初始化完成");
    return true;
}

bool InitializeStormMemoryHooks() {
    // 初始化日志系统
    if (!LogSystem::GetInstance().Initialize()) {
        printf("[错误] 无法初始化日志系统\n");
        return false;
    }

    LogMessage("[Init] 正在初始化Storm内存钩子...");

    // 初始化内存安全系统
    if (!g_MemSafety.Initialize()) {
        LogMessage("[Init] 内存安全系统初始化失败");
        return false;
    }

    // 记录初始化信息
    LogMessage("[Init] 内存跟踪系统已启用，将记录所有分配/释放操作");

    // 查找Storm.dll基址
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        LogMessage("[Init] 未找到Storm.dll模块");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[Init] 找到Storm.dll，基址: 0x%08X", gStormDllBase);

    // 初始化原始函数指针
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);

    LogMessage("[Init] Storm函数地址: Alloc=%p, Free=%p, Realloc=%p, CleanupAll=%p",
        s_origStormAlloc, s_origStormFree, s_origStormReAlloc, s_origCleanupAll);

    // 验证函数指针
    if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
        LogMessage("[Init] 无法找到Storm内存函数");
        return false;
    }

    // 初始化 JassVM 内存管理
    JVM_MemPool::Initialize();

    // 初始化TLSF内存池
    MemPool::Initialize(TLSF_MAIN_POOL_SIZE);

    // 创建永久稳定块，使用更广泛的大小分布
    CreatePermanentStabilizers(25, "全周期保护");

    // 安装钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LogMessage("[Init] 安装钩子失败，错误: %ld", result);
        return false;
    }

    // 启动统计线程
    HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
    if (hThread) {
        g_statsThreadHandle = hThread;
    }

    // 启动定期HTML报告生成（为测试设置为30秒）
    g_memoryTracker.StartPeriodicReporting(30000);
    LogMessage("[Init] 已启动定期内存报告生成 (测试模式: 30秒一次)");

    void* stabilizer = MemPool::CreateStabilizingBlock(32, "初始稳定块");
    if (stabilizer) {
        LogMessage("[Init] 稳定块分配成功: %p", stabilizer);
        g_permanentBlocks.add(stabilizer);
    }

    // 重置Storm的g_DebugHeapPtr，防止初始CleanAll触发
    Storm_g_DebugHeapPtr = 0;

    // 输出初始内存报告
    GenerateMemoryReport(true);

    LogMessage("[Init] Storm内存钩子安装成功！");
    return true;
}


// 优化内存所有权转移
void TransferMemoryOwnership() {
    LogMessage("[关闭] 转移内存管理权限...");

    // 禁用异步释放队列
    g_disableActualFree = true;
    g_disableMemoryReleasing = true;

    // 放弃对所有块的管理权
    size_t blockCount = g_bigBlocks.size();
    LogMessage("[关闭] 放弃管理%zu个TLSF块的所有权", blockCount);

    // 清空哈希表 - 会自动释放每个块的 source 字符串
    g_bigBlocks.clear();

    // 禁止TLSF中的实际内存释放操作
    LogMessage("[关闭] 禁用TLSF内存池释放...");
    MemPool::DisableActualFree();
    MemPool::DisableMemoryReleasing();
}

// 优化停止所有工作线程
void StopAllWorkThreads() {
    LogMessage("[关闭] 停止所有工作线程...");

    // 设置退出标志并通知等待的线程
    g_shouldExit.store(true, std::memory_order_release);
    g_shutdownCondition.notify_all();

    // 确保统计线程退出
    if (g_statsThreadHandle) {
        // 等待线程结束，使用更短的超时
        DWORD waitResult = WaitForSingleObject(g_statsThreadHandle, 500);
        if (waitResult != WAIT_OBJECT_0) {
            LogMessage("[关闭] 统计线程未能在500ms内结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }

        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
    }

    // 等待所有进行中的内存操作完成
    LogMessage("[关闭] 等待进行中的关键操作完成...");

    // 使用自旋等待减少等待时间
    int checkCount = 0;
    while ((MemPool::g_inTLSFOperation.load(std::memory_order_acquire) ||
        g_cleanAllInProgress.load(std::memory_order_acquire)) &&
        checkCount < 10) {
        Sleep(10); // 减少等待时间到10毫秒
        checkCount++;
    }

    LogMessage("[关闭] 所有工作线程已停止");
}

// 关闭内存跟踪系统
void ShutdownMemoryTracking() {
    LOG_INFO("内存跟踪系统关闭开始");

    // 生成最终内存报告
    g_memoryTracker.GenerateReport("FinalMemoryAllocation.log");
    g_memoryTracker.GenerateMemoryChartReport("FinalMemoryChart.html");

    // 停止统计线程
    if (g_statsThreadHandle) {
        // 设置退出标志
        g_shouldExit.store(true);

        // 等待线程结束
        DWORD waitResult = WaitForSingleObject(g_statsThreadHandle, 1000);
        if (waitResult != WAIT_OBJECT_0) {
            LOG_WARNING("统计线程未能在1秒内结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }

        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
    }

    // 关闭日志系统
    LogSystem::GetInstance().Shutdown();
}

// 优化安全卸载钩子函数
void SafelyDetachHooks() {
    LogMessage("[关闭] 安全卸载钩子...");

    // 确保不在关键操作中
    if (g_cleanAllInProgress.load(std::memory_order_acquire)) {
        LogMessage("[关闭] 等待CleanAll完成...");

        // 使用自旋等待
        int waitAttempts = 0;
        while (g_cleanAllInProgress.load(std::memory_order_acquire) && waitAttempts < 10) {
            Sleep(10);
            waitAttempts++;
        }
    }

    // 开始钩子卸载事务
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 按特定顺序卸载钩子 - 先卸载不太活跃的钩子
    if (s_origCleanupAll) {
        LogMessage("[关闭] 卸载CleanupAll钩子");
        DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);
    }

    // 短暂等待
    Sleep(50);

    // 然后卸载核心内存操作钩子
    if (s_origStormReAlloc) {
        LogMessage("[关闭] 卸载ReAlloc钩子");
        DetourDetach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    }

    if (s_origStormFree) {
        LogMessage("[关闭] 卸载Free钩子");
        DetourDetach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    }

    if (s_origStormAlloc) {
        LogMessage("[关闭] 卸载Alloc钩子");
        DetourDetach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    }

    // 提交事务
    LONG result = DetourTransactionCommit();
    LogMessage("[关闭] 钩子卸载%s", (result == NO_ERROR ? "成功" : "失败"));
}

// 优化关闭函数
void ShutdownStormMemoryHooks() {
    LogMessage("[关闭] 退出程序...");

    // 停止定期报告线程
    LogMessage("[关闭] 停止定期报告生成...");
    g_memoryTracker.StopPeriodicReporting();

    // 生成内存分配报告
    LogMessage("[关闭] 正在生成内存分配报告...");
    g_memoryTracker.GenerateReport("StormMemoryAllocation.log");
    g_memoryTracker.GenerateMemoryChartReport("MemoryChart.html");

    // 1. 标记不安全期开始——必须最先执行
    g_insideUnsafePeriod.store(true, std::memory_order_release);

    // 2. 最后的内存报告
    GenerateMemoryReport(true);

    // 3. 等待任何进行中的内存操作完成
    LogMessage("[关闭] 等待进行中的内存操作完成...");

    // 减少等待时间
    Sleep(50);

    // 4. 停止统计线程和其他工作线程
    StopAllWorkThreads();

    // 5. 处理内存归属转移
    TransferMemoryOwnership();

    // 6. 关闭内存安全系统
    LogMessage("[关闭] 关闭内存安全系统...");
    g_MemSafety.Shutdown();

    // 7. 安全卸载钩子
    SafelyDetachHooks();

    // 8. 释放永久块引用但不实际释放内存
    LogMessage("[关闭] 释放永久块引用...");
    g_permanentBlocks.clear();
    g_tempStabilizers.clear();

    // 9. 清理JassVM内存池 - 同样禁用实际释放
    LogMessage("[关闭] 关闭JassVM内存管理...");
    JVM_MemPool::Cleanup();

    // 10. 清理TLSF内存池 - 上面已经禁用了实际释放
    LogMessage("[关闭] 关闭TLSF内存池...");
    MemPool::Shutdown();

    // 11. 关闭日志系统
    LogMessage("[关闭] 关闭完成，正在关闭日志系统");
    LogSystem::GetInstance().Shutdown();
}