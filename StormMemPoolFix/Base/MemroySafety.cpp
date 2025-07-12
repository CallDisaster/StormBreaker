// MemorySafety.cpp - 修复后的完整实现
#include "pch.h"
#include "MemorySafety.h"
#include <psapi.h>
#include <algorithm>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

///////////////////////////////////////////////////////////////////////////////
// 单例实现
///////////////////////////////////////////////////////////////////////////////

MemorySafety& MemorySafety::GetInstance() noexcept {
    static MemorySafety instance;
    return instance;
}

MemorySafety::MemorySafety() noexcept {
    // 初始化大小分档缓存
    m_sizeClassCaches.resize(MAX_SIZE_CLASSES);
    for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
        m_sizeClassCaches[i] = std::make_unique<SizeClassCache>();
    }
}

MemorySafety::~MemorySafety() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
}

///////////////////////////////////////////////////////////////////////////////
// 生命周期管理
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::Initialize(const MemorySafetyConfig& config) noexcept {
    return SafeExecuteBool([this, &config]() -> bool {
        bool expected = false;
        if (!m_initialized.compare_exchange_strong(expected, true)) {
            return true; // 已初始化
        }

        // 保存配置
        {
            std::lock_guard<std::mutex> lock(m_configMutex);
            m_holdTimeMs = config.holdBufferTimeMs;
            m_watermarkMB = config.memoryWatermarkMB;
            m_maxCacheSizeMB = config.maxCacheSizeMB;
        }

        // 初始化大小分档缓存
        m_sizeClassCaches.resize(MAX_SIZE_CLASSES);
        for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
            m_sizeClassCaches[i] = std::make_unique<SizeClassCache>();
        }

        // 重置统计
        m_totalAllocated = 0;
        m_totalFreed = 0;
        m_currentCached = 0;
        m_cacheHits = 0;
        m_cacheMisses = 0;
        m_forceCleanups = 0;
        m_lastCleanupTime = GetTickCount();

        LogMessage("[MemorySafety] 初始化完成");
        return true;
        }, "MemorySafety::Initialize");
}

void MemorySafety::Shutdown() noexcept {
    SafeExecuteVoid([this]() {
        bool expected = true;
        if (!m_initialized.compare_exchange_strong(expected, false)) {
            return; // 已关闭
        }

        LogMessage("[MemorySafety] 开始关闭");

        // 强制处理剩余的Hold队列
        DrainHoldQueue();

        // 清理所有缓存
        for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
            if (m_sizeClassCaches[i]) {
                auto& cache = *m_sizeClassCaches[i];
                std::lock_guard<std::mutex> lock(cache.mutex);

                for (auto& item : cache.freeBlocks) {
                    VirtualFree(item.rawPtr, 0, MEM_RELEASE);
                }
                cache.freeBlocks.clear();
                cache.totalCached = 0;
            }
        }

        // 清理块映射
        {
            std::lock_guard<std::mutex> lock(m_blockMapMutex);
            m_blockMap.clear();
        }

        LogMessage("[MemorySafety] 关闭完成");
        }, "MemorySafety::Shutdown");
}

///////////////////////////////////////////////////////////////////////////////
// 内存分配接口
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::AllocateBlock(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecutePtr([this, userSize, sourceName, sourceLine]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        return InternalAllocate(userSize, sourceName, sourceLine);
        }, "MemorySafety::AllocateBlock");
}

bool MemorySafety::FreeBlock(void* userPtr) noexcept {
    return SafeExecuteBool([this, userPtr]() -> bool {
        if (!userPtr || !m_initialized.load()) {
            return false;
        }

        return InternalFree(userPtr);
        }, "MemorySafety::FreeBlock");
}

void* MemorySafety::ReallocateBlock(void* userPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecutePtr([this, userPtr, newSize, sourceName, sourceLine]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        return InternalRealloc(userPtr, newSize, sourceName, sourceLine);
        }, "MemorySafety::ReallocateBlock");
}

///////////////////////////////////////////////////////////////////////////////
// 块信息查询
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::IsOurBlock(void* userPtr) const noexcept {
    return SafeExecuteBool([this, userPtr]() -> bool {
        if (!userPtr || !m_initialized.load()) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        return m_blockMap.find(userPtr) != m_blockMap.end();
        }, "MemorySafety::IsOurBlock");
}

size_t MemorySafety::GetBlockSize(void* userPtr) const noexcept {
    return SafeExecuteValue([this, userPtr]() -> size_t {
        if (!userPtr || !m_initialized.load()) {
            return 0;
        }

        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        if (it != m_blockMap.end()) {
            return it->second.userSize;
        }
        return 0;
        }, "MemorySafety::GetBlockSize");
}

BlockInfo MemorySafety::GetBlockInfo(void* userPtr) const noexcept {
    return SafeExecuteWithDefault([this, userPtr]() -> BlockInfo {
        if (!userPtr || !m_initialized.load()) {
            return BlockInfo();
        }

        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        if (it != m_blockMap.end()) {
            return it->second;
        }
        return BlockInfo();
        }, "MemorySafety::GetBlockInfo", BlockInfo());
}

///////////////////////////////////////////////////////////////////////////////
// 内部实现
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::InternalAllocate(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    // 尝试从缓存获取
    size_t sizeClass = GetSizeClass(userSize);
    void* rawPtr = TryGetFromCache(sizeClass, CalculateTotalSize(userSize));

    if (rawPtr) {
        void* userPtr = GetUserPtrFromRaw(rawPtr);
        SetupStormHeader(userPtr, userSize, CalculateTotalSize(userSize));

        // 更新块映射
        {
            std::lock_guard<std::mutex> lock(m_blockMapMutex);
            m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, CalculateTotalSize(userSize), userSize, sourceName, sourceLine);
        }

        m_totalAllocated.fetch_add(userSize);
        return userPtr;
    }

    // 缓存未命中，分配新块
    size_t totalSize = CalculateTotalSize(userSize);
    rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rawPtr) {
        return nullptr;
    }

    void* userPtr = GetUserPtrFromRaw(rawPtr);
    SetupStormHeader(userPtr, userSize, totalSize);

    // 更新块映射
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, totalSize, userSize, sourceName, sourceLine);
    }

    m_totalAllocated.fetch_add(userSize);
    return userPtr;
}

bool MemorySafety::InternalFree(void* userPtr) noexcept {
    // 查找块信息
    BlockInfo info;
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        if (it == m_blockMap.end()) {
            return false; // 不是我们管理的块
        }
        info = it->second;
        m_blockMap.erase(it);
    }

    // 添加到Hold队列而不是立即释放
    AddToHoldQueue(info.rawPtr, info.totalSize);

    m_totalFreed.fetch_add(info.userSize);
    return true;
}

void* MemorySafety::InternalRealloc(void* userPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!userPtr) {
        return InternalAllocate(newSize, sourceName, sourceLine);
    }

    if (newSize == 0) {
        InternalFree(userPtr);
        return nullptr;
    }

    // 获取旧块信息
    BlockInfo oldInfo;
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        if (it == m_blockMap.end()) {
            return nullptr; // 不是我们管理的块
        }
        oldInfo = it->second;
    }

    // 分配新块
    void* newPtr = InternalAllocate(newSize, sourceName, sourceLine);
    if (!newPtr) {
        return nullptr;
    }

    // 复制数据
    size_t copySize = min(oldInfo.userSize, newSize);
    memcpy(newPtr, userPtr, copySize);

    // 释放旧块
    InternalFree(userPtr);

    return newPtr;
}

///////////////////////////////////////////////////////////////////////////////
// 缓存管理
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::GetSizeClass(size_t size) const noexcept {
    size_t sizeClass = (size + SIZE_CLASS_UNIT - 1) / SIZE_CLASS_UNIT;
    return min(sizeClass, static_cast<size_t>(MAX_SIZE_CLASSES - 1));
}

void* MemorySafety::TryGetFromCache(size_t sizeClass, size_t minSize) noexcept {
    if (sizeClass >= MAX_SIZE_CLASSES) {
        return nullptr;
    }

    auto& cache = *m_sizeClassCaches[sizeClass];
    std::lock_guard<std::mutex> lock(cache.mutex);

    // 查找合适大小的块
    for (auto it = cache.freeBlocks.begin(); it != cache.freeBlocks.end(); ++it) {
        if (it->totalSize >= minSize) {
            void* rawPtr = it->rawPtr;
            m_currentCached.fetch_sub(it->totalSize);
            cache.totalCached -= it->totalSize;
            cache.freeBlocks.erase(it);
            cache.hitCount++;
            m_cacheHits.fetch_add(1);
            return rawPtr;
        }
    }

    // 尝试其他分档
    for (size_t i = sizeClass + 1; i < MAX_SIZE_CLASSES; ++i) {
        auto& otherCache = *m_sizeClassCaches[i];
        std::lock_guard<std::mutex> otherLock(otherCache.mutex);

        for (auto it = otherCache.freeBlocks.begin(); it != otherCache.freeBlocks.end(); ++it) {
            if (it->totalSize >= minSize) {
                void* rawPtr = it->rawPtr;
                m_currentCached.fetch_sub(it->totalSize);
                otherCache.totalCached -= it->totalSize;
                otherCache.freeBlocks.erase(it);
                otherCache.hitCount++;
                m_cacheHits.fetch_add(1);
                return rawPtr;
            }
        }
    }

    cache.missCount++;
    m_cacheMisses.fetch_add(1);
    return nullptr;
}

void MemorySafety::AddToCache(void* rawPtr, size_t totalSize) noexcept {
    size_t sizeClass = GetSizeClass(totalSize);
    if (sizeClass >= MAX_SIZE_CLASSES) {
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return;
    }

    auto& cache = *m_sizeClassCaches[sizeClass];
    std::lock_guard<std::mutex> lock(cache.mutex);

    // 检查缓存大小限制
    size_t maxCacheBytes = m_maxCacheSizeMB * 1024 * 1024;
    if (GetTotalCached() > maxCacheBytes) {
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return;
    }

    cache.freeBlocks.emplace_back(rawPtr, totalSize);
    cache.totalCached += totalSize;
    m_currentCached.fetch_add(totalSize);
}

///////////////////////////////////////////////////////////////////////////////
// Hold队列管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept {
    SafeExecuteVoid([this, rawPtr, totalSize]() {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);
        size_t sizeClass = GetSizeClass(totalSize);
        m_holdQueue.emplace_back(rawPtr, totalSize, GetTickCount(), sizeClass);

        // 定期处理过期项
        ProcessExpiredItems();
        }, "MemorySafety::AddToHoldQueue");
}

void MemorySafety::ProcessExpiredItems() noexcept {
    DWORD currentTime = GetTickCount();
    DWORD holdTime = m_holdTimeMs;

    auto it = m_holdQueue.begin();
    while (it != m_holdQueue.end()) {
        if (currentTime - it->queueTime >= holdTime) {
            // 过期，添加到缓存或释放
            AddToCache(it->rawPtr, it->totalSize);
            it = m_holdQueue.erase(it);
        }
        else {
            ++it;
        }
    }
}

void MemorySafety::ProcessHoldQueue() noexcept {
    SafeExecuteVoid([this]() {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);
        ProcessExpiredItems();
        }, "MemorySafety::ProcessHoldQueue");
}

void MemorySafety::DrainHoldQueue() noexcept {
    SafeExecuteVoid([this]() {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);

        for (auto& item : m_holdQueue) {
            VirtualFree(item.rawPtr, 0, MEM_RELEASE);
        }
        m_holdQueue.clear();
        }, "MemorySafety::DrainHoldQueue");
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    return SafeExecuteValue([this]() -> size_t {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);
        return m_holdQueue.size();
        }, "MemorySafety::GetHoldQueueSize");
}

///////////////////////////////////////////////////////////////////////////////
// 内存压力管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::ForceCleanup() noexcept {
    SafeExecuteVoid([this]() {
        DWORD currentTime = GetTickCount();
        DWORD lastCleanup = m_lastCleanupTime.load();

        if (currentTime - lastCleanup < MIN_CLEANUP_INTERVAL_MS) {
            return; // 避免频繁清理
        }

        // 处理Hold队列
        ProcessExpiredItems();

        // 根据压力清理缓存
        FlushCacheByPressure();

        m_lastCleanupTime.store(currentTime);
        m_forceCleanups.fetch_add(1);
        }, "MemorySafety::ForceCleanup");
}

void MemorySafety::FlushCacheByPressure() noexcept {
    for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
        auto& cache = *m_sizeClassCaches[i];
        std::lock_guard<std::mutex> lock(cache.mutex);

        // 按时间排序，清理最老的一半
        std::sort(cache.freeBlocks.begin(), cache.freeBlocks.end(),
            [](const CacheItem& a, const CacheItem& b) {
                return a.cacheTime < b.cacheTime;
            });

        size_t removeCount = cache.freeBlocks.size() / 2;
        for (size_t j = 0; j < removeCount && !cache.freeBlocks.empty(); ++j) {
            auto& item = cache.freeBlocks.front();
            VirtualFree(item.rawPtr, 0, MEM_RELEASE);
            m_currentCached.fetch_sub(item.totalSize);
            cache.totalCached -= item.totalSize;
            cache.freeBlocks.erase(cache.freeBlocks.begin());
        }
    }
}

bool MemorySafety::IsMemoryUnderPressure() const noexcept {
    size_t vmUsage = MemorySafetyUtils::GetProcessVirtualMemoryUsage();
    size_t watermarkBytes = m_watermarkMB * 1024 * 1024;
    return vmUsage > watermarkBytes;
}

void MemorySafety::TriggerPressureCleanup() noexcept {
    if (IsMemoryUnderPressure()) {
        DWORD currentTime = GetTickCount();
        DWORD lastCleanup = m_lastCleanupTime.load();

        if (currentTime - lastCleanup >= MIN_CLEANUP_INTERVAL_MS) {
            ForceCleanup();
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Storm兼容性
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept {
    SafeExecuteVoid([userPtr, userSize, totalSize]() {
        if (!userPtr) return;

        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader)
            );

        header->HeapPtr = STORM_SPECIAL_HEAP;
        header->Size = static_cast<DWORD>(userSize);
        header->AlignPadding = 0;
        header->Flags = 0x1; // 启用魔数校验
        header->Magic = STORM_FRONT_MAGIC;

        // 设置尾部魔数
        if (header->Flags & 0x1) {
            WORD* tailMagic = reinterpret_cast<WORD*>(
                static_cast<char*>(userPtr) + userSize
                );
            *tailMagic = STORM_TAIL_MAGIC;
        }
        }, "MemorySafety::SetupStormHeader");
}

bool MemorySafety::ValidateStormHeader(void* userPtr) const noexcept {
    return SafeExecuteBool([userPtr]() -> bool {
        if (!userPtr) return false;

        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader)
            );

        // 检查前魔数
        if (header->Magic != STORM_FRONT_MAGIC) {
            return false;
        }

        // 检查尾魔数（如果启用）
        if (header->Flags & 0x1) {
            WORD* tailMagic = reinterpret_cast<WORD*>(
                static_cast<char*>(userPtr) + header->Size
                );
            if (*tailMagic != STORM_TAIL_MAGIC) {
                return false;
            }
        }

        return true;
        }, "MemorySafety::ValidateStormHeader");
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::CalculateTotalSize(size_t userSize) const noexcept {
    return AlignSize(sizeof(StormAllocHeader) + userSize + sizeof(WORD), 16);
}

void* MemorySafety::GetUserPtrFromRaw(void* rawPtr) const noexcept {
    if (!rawPtr) return nullptr;
    return static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
}

void* MemorySafety::GetRawPtrFromUser(void* userPtr) const noexcept {
    if (!userPtr) return nullptr;
    return static_cast<char*>(userPtr) - sizeof(StormAllocHeader);
}

size_t MemorySafety::AlignSize(size_t size, size_t alignment) const noexcept {
    return (size + alignment - 1) & ~(alignment - 1);
}

size_t MemorySafety::GetTotalCached() const noexcept {
    return m_currentCached.load();
}

///////////////////////////////////////////////////////////////////////////////
// 配置和统计
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetHoldTimeMs(DWORD timeMs) noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_holdTimeMs = timeMs;
}

void MemorySafety::SetWatermarkMB(size_t watermarkMB) noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_watermarkMB = watermarkMB;
}

void MemorySafety::SetMaxCacheSize(size_t maxSizeMB) noexcept {
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_maxCacheSizeMB = maxSizeMB;
}

MemorySafety::Statistics MemorySafety::GetStatistics() const noexcept {
    Statistics stats;
    stats.totalAllocated = m_totalAllocated.load();
    stats.totalFreed = m_totalFreed.load();
    stats.currentCached = m_currentCached.load();
    stats.holdQueueSize = GetHoldQueueSize();
    stats.cacheHits = m_cacheHits.load();
    stats.cacheMisses = m_cacheMisses.load();
    stats.forceCleanups = m_forceCleanups.load();

    size_t total = stats.cacheHits + stats.cacheMisses;
    stats.hitRate = total > 0 ? (stats.cacheHits * 100.0 / total) : 0.0;

    return stats;
}

void MemorySafety::PrintStatistics() const noexcept {
    Statistics stats = GetStatistics();

    LogMessage("[MemorySafety] === 统计报告 ===");
    LogMessage("  分配: 总计=%zuMB", stats.totalAllocated / (1024 * 1024));
    LogMessage("  释放: 总计=%zuMB", stats.totalFreed / (1024 * 1024));
    LogMessage("  缓存: %zuMB, 命中率=%.1f%%", stats.currentCached / (1024 * 1024), stats.hitRate);
    LogMessage("  Hold队列: %zu项", stats.holdQueueSize);
    LogMessage("  强制清理: %zu次", stats.forceCleanups);
    LogMessage("========================");
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数实现
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    size_t GetProcessVirtualMemoryUsage() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PrivateUsage;
        }
        return 0;
    }

    size_t GetSystemMemoryLoad() noexcept {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        if (GlobalMemoryStatusEx(&ms)) {
            return ms.dwMemoryLoad;
        }
        return 0;
    }

    DWORD GetTickCount() noexcept {
        return static_cast<DWORD>(::GetTickCount64() & 0xFFFFFFFF);
    }

    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept {
        DWORD currentTime = GetTickCount();
        return (currentTime - startTime) >= intervalMs;
    }

    size_t AlignSize(size_t size, size_t alignment) noexcept {
        return (size + alignment - 1) & ~(alignment - 1);
    }

    size_t GetPageAlignedSize(size_t size) noexcept {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return AlignSize(size, si.dwPageSize);
    }
}