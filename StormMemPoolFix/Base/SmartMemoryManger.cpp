#include "pch.h"
#include "SmartMemoryManager.h"
#include <Storm/StormOffsets.h>

// 定义全局变量
MemoryPressureMonitor g_pressureMonitor;
SmartLargeBlockCache g_smartCache;
AsyncMemoryReleaser g_asyncReleaser;

// 全局常量定义
constexpr size_t LOCAL_BUFFER_SIZE = 32;
constexpr size_t BATCH_PROCESS_SIZE = 128;
constexpr size_t MAX_CACHE_BLOCKS = 16;

// 线程本地缓冲区定义
thread_local std::vector<AsyncMemoryReleaser::DeferredFree> AsyncMemoryReleaser::t_localBuffer;

// 临时的全局禁用标志（为兼容性保留）
static std::atomic<bool> g_disableActualFree{ false };

//=============================================================================
// MemoryPressureMonitor 实现
//=============================================================================

uint32_t MemoryPressureMonitor::QueryLargestFreeRegion() {
    uint32_t maxFree = 0;
    uint32_t currentFree = 0;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0x10000; // 从用户空间开始

    while (address < 0x7FFF0000 && VirtualQuery((PVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_FREE) {
            // 检查是否与前一个空闲区域相邻
            if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) == address) {
                currentFree += mbi.RegionSize;
            }
            else {
                maxFree = max(maxFree, currentFree);
                currentFree = mbi.RegionSize;
            }
        }
        else {
            maxFree = max(maxFree, currentFree);
            currentFree = 0;
        }
        address += mbi.RegionSize;
    }

    return max(maxFree, currentFree);
}

MemoryPressureMonitor::MemoryInfo MemoryPressureMonitor::GetMemoryInfo(uint32_t cleanAllCount) {
    MemoryInfo info;

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc));

    info.commitBytes = static_cast<uint32_t>(pmc.PrivateUsage);
    info.largestFreeRegion = QueryLargestFreeRegion();
    info.cleanAllCount = cleanAllCount;

    // 计算压力级别
    uint32_t lastCount = m_lastCleanAllCount.load();
    uint32_t cleanAllDelta = cleanAllCount - lastCount;

    info.pressureLevel = 0;
    info.needsAction = false;

    // 判断条件（渐进式）
    if (info.commitBytes > 1300 * 1024 * 1024) { // >1.3GB
        info.pressureLevel = max(info.pressureLevel, 1);
    }

    if (info.largestFreeRegion < 200 * 1024 * 1024) { // <200MB空闲
        info.pressureLevel = max(info.pressureLevel, 2);
    }

    if (cleanAllDelta > 10000 && lastCount > 0) { // 1万次CleanAll增量
        info.pressureLevel = max(info.pressureLevel, 2);
    }

    if (info.largestFreeRegion < 128 * 1024 * 1024) { // <128MB空闲，危险
        info.pressureLevel = 3;
    }

    // 连续高压力检测
    if (info.pressureLevel >= 2) {
        m_consecutiveHighPressure.fetch_add(1);
    }
    else {
        m_consecutiveHighPressure.store(0);
    }

    // 连续3次高压力就必须行动
    if (m_consecutiveHighPressure.load() >= 3) {
        info.needsAction = true;
    }

    // 更新记录
    m_lastCommit.store(info.commitBytes);
    m_lastCleanAllCount.store(cleanAllCount);

    return info;
}

//=============================================================================
// SmartLargeBlockCache 实现
//=============================================================================

SmartLargeBlockCache::CachedBlock::CachedBlock(void* p, size_t s, DWORD ts)
    : ptr(p), size(s), timestamp(ts) {
}

uint32_t SmartLargeBlockCache::CachedBlock::GetPriority() const {
    DWORD now = GetTickCount();
    return now - timestamp; // 越老的块优先级越高（越容易被清理）
}

void* SmartLargeBlockCache::GetBlock(size_t size) {
    // 使用LargeBlockCache自己的分片逻辑（基于大小）
    size_t idx = (size / 1024) % 16;
    std::lock_guard<std::mutex> lock(m_shards[idx].mutex);

    auto& blocks = m_shards[idx].blocks;
    for (auto it = blocks.begin(); it != blocks.end(); ++it) {
        if (it->size >= size + sizeof(StormAllocHeader)) { // 确保包含头部大小
            void* rawPtr = it->ptr; // 这是原始指针（包含Storm头）
            blocks.erase(it);
            m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);

            // ★ 关键修复：重新设置Storm头部
            void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);

            return userPtr; // 返回用户指针
        }
    }

    // 缓存未命中，尝试其他分片
    for (size_t i = 0; i < 16; ++i) {
        if (i == idx) continue; // 跳过已检查的分片

        std::lock_guard<std::mutex> lock(m_shards[i].mutex);
        auto& otherBlocks = m_shards[i].blocks;

        for (auto it = otherBlocks.begin(); it != otherBlocks.end(); ++it) {
            if (it->size >= size + sizeof(StormAllocHeader)) {
                void* rawPtr = it->ptr;
                otherBlocks.erase(it);
                m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);

                void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
                SetupCompatibleHeader(userPtr, size);

                return userPtr;
            }
        }
    }

    return nullptr; // 完全未命中
}

void SmartLargeBlockCache::ReleaseBlock(void* rawPtr, size_t size) {
    // 基于大小分片，不是指针
    size_t idx = (size / 1024) % 16;
    std::lock_guard<std::mutex> lock(m_shards[idx].mutex);

    auto& blocks = m_shards[idx].blocks;

    // 如果缓存已满，释放最老的块
    if (blocks.size() >= MAX_CACHE_SIZE) { // 修复：使用正确的常量名
        auto oldest = std::min_element(blocks.begin(), blocks.end(),
            [](const CachedBlock& a, const CachedBlock& b) {
                return a.timestamp < b.timestamp;
            });

        if (oldest != blocks.end()) {

            // 安全清零头部，防止use-after-free
            memset(oldest->ptr, 0xCC, sizeof(StormAllocHeader));
            VirtualFree(oldest->ptr, 0, MEM_RELEASE);
            blocks.erase(oldest);
            m_totalBlocks.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // 添加新块到缓存 - 存储原始指针（包含Storm头）
    blocks.emplace_back(rawPtr, size, GetTickCount());
    m_totalBlocks.fetch_add(1, std::memory_order_relaxed);
}

size_t SmartLargeBlockCache::SmartFlush(int pressureLevel) {
    size_t totalFreed = 0;

    for (auto& shard : m_shards) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        auto& blocks = shard.blocks;

        if (blocks.empty()) continue;

        // 根据压力级别决定清理比例
        size_t targetRemove = 0;
        switch (pressureLevel) {
        case 1: targetRemove = blocks.size() / 4; break; // 清理25%
        case 2: targetRemove = blocks.size() / 2; break; // 清理50%  
        case 3: targetRemove = blocks.size(); break;     // 清理100%
        default: continue;
        }

        if (targetRemove == 0) continue;

        // 按优先级排序，清理最老的块
        std::sort(blocks.begin(), blocks.end(),
            [](const CachedBlock& a, const CachedBlock& b) {
                return a.GetPriority() > b.GetPriority(); // 优先级高的排在前面
            });

        size_t actualRemove = min(targetRemove, blocks.size());
        for (size_t i = 0; i < actualRemove; ++i) {
            memset(blocks[i].ptr, 0xCC, sizeof(StormAllocHeader));
            VirtualFree(blocks[i].ptr, 0, MEM_RELEASE);
            totalFreed++;
        }

        blocks.erase(blocks.begin(), blocks.begin() + actualRemove);
        m_totalBlocks.fetch_sub(actualRemove, std::memory_order_relaxed);
    }

    return totalFreed;
}

void SmartLargeBlockCache::FlushOldBlocks() {
    size_t totalFreed = 0;

    for (auto& shard : m_shards) {
        std::lock_guard<std::mutex> lock(shard.mutex);
        if (shard.blocks.empty()) continue;

        // 按时间排序，移除最老的一半
        std::sort(shard.blocks.begin(), shard.blocks.end(),
            [](const CachedBlock& a, const CachedBlock& b) {
                return a.timestamp < b.timestamp;
            });

        size_t removeCount = shard.blocks.size() / 2; // 只移除一半
        if (removeCount == 0) continue;

        for (size_t i = 0; i < removeCount; ++i) {
            // 安全清零并释放
            memset(shard.blocks[i].ptr, 0xCC, sizeof(StormAllocHeader));
            VirtualFree(shard.blocks[i].ptr, 0, MEM_RELEASE);
            totalFreed++;
        }

        shard.blocks.erase(shard.blocks.begin(), shard.blocks.begin() + removeCount);
        m_totalBlocks.fetch_sub(removeCount, std::memory_order_relaxed);
    }

    LogMessage("[Cache] 压力清理完成，释放块数: %zu", totalFreed);
}

size_t SmartLargeBlockCache::GetCacheSize() const {
    return m_totalBlocks.load(std::memory_order_relaxed);
}

//=============================================================================
// AsyncMemoryReleaser 实现
//=============================================================================

void AsyncMemoryReleaser::WorkerThread() {
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
            if (!g_disableActualFree.load()) {
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
    if (g_disableActualFree.load()) {
        return; // 如果禁用了实际释放，则直接返回
    }

    LogMessage("[异步释放] 程序结束，清理剩余队列项");
    DeferredFree item;
    while (m_queue.try_pop(item)) {
        VirtualFree(item.ptr, 0, MEM_RELEASE);
    }
}

AsyncMemoryReleaser::AsyncMemoryReleaser() : m_thread(&AsyncMemoryReleaser::WorkerThread, this) {
    LogMessage("[异步释放] 工作线程已启动");
}

AsyncMemoryReleaser::~AsyncMemoryReleaser() {
    m_shouldExit.store(true, std::memory_order_release);
    m_wakeCondition.notify_all(); // 通知所有可能等待的线程

    if (m_thread.joinable()) {
        m_thread.join();
    }

    LogMessage("[异步释放] 工作线程已关闭");
}

void AsyncMemoryReleaser::QueueFree(void* ptr, size_t size) {
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

void AsyncMemoryReleaser::FlushLocalBuffer() {
    if (!t_localBuffer.empty()) {
        for (const auto& item : t_localBuffer) {
            m_queue.push(item);
            m_queueSize.fetch_add(1, std::memory_order_relaxed);
        }
        t_localBuffer.clear();
        m_wakeCondition.notify_one();
    }
}

void AsyncMemoryReleaser::FlushAllImmediate() {
    // 先处理本地缓冲区
    for (const auto& item : t_localBuffer) {
        VirtualFree(item.ptr, 0, MEM_RELEASE);
    }
    t_localBuffer.clear();

    // 处理队列中的所有项目
    DeferredFree item;
    while (m_queue.try_pop(item)) {
        VirtualFree(item.ptr, 0, MEM_RELEASE);
        m_queueSize.fetch_sub(1, std::memory_order_relaxed);
    }
}

size_t AsyncMemoryReleaser::GetQueueSize() const {
    return m_queueSize.load(std::memory_order_relaxed) + t_localBuffer.size();
}