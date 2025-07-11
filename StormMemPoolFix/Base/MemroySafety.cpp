// MemorySafety.cpp - 完整重写的内存安全管理器实现
// 基于GPT研究的"缓冲窗口+大小分档+内存压力监控"方案
#include "pch.h"
#include "MemorySafety.h"
#include <algorithm>
#include <cassert>

///////////////////////////////////////////////////////////////////////////////
// 独立的Storm兼容头部设置函数
///////////////////////////////////////////////////////////////////////////////

void SetupCompatibleHeader(void* userPtr, size_t userSize) noexcept {
    if (!userPtr || userSize == 0) return;

    SafeExecute([=]() -> void {
        // 获取Storm兼容头部的位置（用户指针前面）
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        // 设置Storm兼容的头部信息（基于逆向文档）
        header->HeapPtr = STORM_SPECIAL_HEAP;  // 特殊堆标记
        header->Size = static_cast<DWORD>(userSize);
        header->AlignPadding = 0;
        header->Flags = 0x1 | 0x4;  // 魔数校验 + 大块标记
        header->Magic = STORM_FRONT_MAGIC;

        // 如果启用了尾魔数，设置尾部魔数
        if (header->Flags & 0x1) {
            WORD* tailMagic = reinterpret_cast<WORD*>(
                static_cast<char*>(userPtr) + userSize);
            *tailMagic = STORM_TAIL_MAGIC;
        }
        }, "SetupCompatibleHeader");
}

///////////////////////////////////////////////////////////////////////////////
// MemorySafety类实现
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::Initialize() noexcept {
    return SafeExecute([this]() -> bool {
        bool expected = false;
        if (!m_initialized.compare_exchange_strong(expected, true)) {
            return true; // 已经初始化
        }

        printf("[MemorySafety] 初始化开始\n");
        printf("[MemorySafety] 配置: Hold时间=%dms, 水位=%zuMB, 最大缓存=%zuMB\n",
            m_holdTimeMs.load(), m_watermarkMB.load(), m_maxCacheSizeMB.load());
        printf("[MemorySafety] Size Class: %zu档, 每档%zuKB\n",
            MAX_SIZE_CLASSES, SIZE_CLASS_UNIT / 1024);

        // 初始化所有Size Class缓存
        for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
            m_sizeClassCaches[i].totalSize.store(0);
            m_sizeClassCaches[i].items.reserve(32); // 预分配避免频繁重分配
        }

        // 重置统计
        m_cacheHits.store(0);
        m_cacheMisses.store(0);
        m_totalAllocated.store(0);
        m_totalFreed.store(0);
        m_currentCached.store(0);
        m_lastCleanupTime.store(MemorySafetyUtils::GetTickCount());

        printf("[MemorySafety] 初始化完成\n");
        return true;
        }, "Initialize");
}

void MemorySafety::Shutdown() noexcept {
    SafeExecute([this]() -> void {
        bool expected = true;
        if (!m_initialized.compare_exchange_strong(expected, false)) {
            return; // 已经关闭
        }

        printf("[MemorySafety] 开始关闭\n");
        m_shutdownRequested.store(true);

        // 强制处理所有Hold队列项
        DrainHoldQueue();

        // 清理所有Size Class缓存
        size_t totalFreed = 0;
        for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
            std::lock_guard<std::mutex> lock(m_sizeClassCaches[i].mutex);
            for (const auto& item : m_sizeClassCaches[i].items) {
                VirtualFree(item.rawPtr, 0, MEM_RELEASE);
                totalFreed += item.totalSize;
            }
            m_sizeClassCaches[i].items.clear();
            m_sizeClassCaches[i].totalSize.store(0);
        }

        // 清理块追踪
        {
            std::lock_guard<std::mutex> lock(m_blockMapMutex);
            m_blockMap.clear();
        }

        // 打印最终统计
        printf("[MemorySafety] 关闭统计:\n");
        printf("  - 总分配: %zu MB\n", m_totalAllocated.load() / (1024 * 1024));
        printf("  - 总释放: %zu MB\n", m_totalFreed.load() / (1024 * 1024));
        printf("  - 缓存命中: %zu 次\n", m_cacheHits.load());
        printf("  - 缓存未命中: %zu 次\n", m_cacheMisses.load());
        printf("  - 关闭时清理: %zu MB\n", totalFreed / (1024 * 1024));

        double hitRate = 0.0;
        size_t totalTries = m_cacheHits.load() + m_cacheMisses.load();
        if (totalTries > 0) {
            hitRate = (m_cacheHits.load() * 100.0) / totalTries;
        }
        printf("  - 缓存命中率: %.1f%%\n", hitRate);

        printf("[MemorySafety] 关闭完成\n");
        }, "Shutdown");
}

void* MemorySafety::AllocateBlock(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    if (!m_initialized.load() || size == 0) {
        return nullptr;
    }

    return SafeExecute([=]() -> void* {
        return InternalAllocate(size, sourceName, sourceLine);
        }, "AllocateBlock");
}

bool MemorySafety::FreeBlock(void* userPtr) noexcept {
    if (!m_initialized.load() || !userPtr) {
        return false;
    }

    return SafeExecute([=]() -> bool {
        return InternalFree(userPtr);
        }, "FreeBlock");
}

void* MemorySafety::ReallocateBlock(void* oldUserPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!m_initialized.load()) {
        return nullptr;
    }

    return SafeExecute([=]() -> void* {
        return InternalRealloc(oldUserPtr, newSize, sourceName, sourceLine);
        }, "ReallocateBlock");
}

bool MemorySafety::IsOurBlock(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return false;
    }

    return SafeExecute([=]() -> bool {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        return m_blockMap.find(userPtr) != m_blockMap.end();
        }, "IsOurBlock");
}

size_t MemorySafety::GetBlockSize(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return 0;
    }

    return SafeExecute([=]() -> size_t {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        return (it != m_blockMap.end()) ? it->second.userSize : 0;
        }, "GetBlockSize");
}

BlockInfo MemorySafety::GetBlockInfo(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return BlockInfo();
    }

    return SafeExecute([=]() -> BlockInfo {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        return (it != m_blockMap.end()) ? it->second : BlockInfo();
        }, "GetBlockInfo");
}

///////////////////////////////////////////////////////////////////////////////
// 内部实现函数
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    // 1. 尝试从缓存获取
    void* rawPtr = TryGetFromCache(size);
    if (rawPtr) {
        // 从缓存命中，重新设置用户区
        void* userPtr = GetUserPtrFromRaw(rawPtr, size);
        if (userPtr) {
            SetupStormHeader(userPtr, size);

            // 更新块追踪
            {
                std::lock_guard<std::mutex> lock(m_blockMapMutex);
                m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, CalculateTotalSize(size),
                    size, sourceName, sourceLine);
            }

            m_totalAllocated.fetch_add(size);
            return userPtr;
        }
    }

    // 2. 缓存未命中，分配新块
    size_t totalSize = CalculateTotalSize(size);
    rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rawPtr) {
        return nullptr;
    }

    void* userPtr = GetUserPtrFromRaw(rawPtr, size);
    if (!userPtr) {
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return nullptr;
    }

    // 3. 设置Storm兼容头部
    SetupStormHeader(userPtr, size);

    // 4. 记录块信息
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, totalSize, size, sourceName, sourceLine);
    }

    m_totalAllocated.fetch_add(size);
    return userPtr;
}

bool MemorySafety::InternalFree(void* userPtr) noexcept {
    // 1. 验证并获取块信息
    BlockInfo blockInfo;
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(userPtr);
        if (it == m_blockMap.end()) {
            return false; // 不是我们管理的块
        }
        blockInfo = it->second;
        m_blockMap.erase(it);
    }

    // 2. 验证Storm头部
    if (!ValidateStormHeader(userPtr)) {
        printf("[MemorySafety] 警告: Storm头部校验失败 %p\n", userPtr);
        // 继续处理，但记录警告
    }

    // 3. 加入Hold队列（缓冲窗口机制）
    AddToHoldQueue(blockInfo.rawPtr, blockInfo.totalSize);

    m_totalFreed.fetch_add(blockInfo.userSize);
    return true;
}

void* MemorySafety::InternalRealloc(void* oldUserPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!oldUserPtr) {
        return InternalAllocate(newSize, sourceName, sourceLine);
    }

    if (newSize == 0) {
        InternalFree(oldUserPtr);
        return nullptr;
    }

    // 获取旧块信息
    BlockInfo oldInfo;
    {
        std::lock_guard<std::mutex> lock(m_blockMapMutex);
        auto it = m_blockMap.find(oldUserPtr);
        if (it == m_blockMap.end()) {
            return nullptr; // 不是我们管理的块
        }
        oldInfo = it->second;
    }

    // 如果新大小小于等于旧大小，可以原地复用
    if (newSize <= oldInfo.userSize) {
        // 更新头部信息
        SetupStormHeader(oldUserPtr, newSize);

        // 更新块追踪
        {
            std::lock_guard<std::mutex> lock(m_blockMapMutex);
            auto& info = m_blockMap[oldUserPtr];
            info.userSize = newSize;
            info.sourceName = sourceName;
            info.sourceLine = sourceLine;
            info.allocTime = MemorySafetyUtils::GetTickCount();
        }

        return oldUserPtr;
    }

    // 需要分配新块
    void* newUserPtr = InternalAllocate(newSize, sourceName, sourceLine);
    if (!newUserPtr) {
        return nullptr;
    }

    // 复制数据
    size_t copySize = min(newSize, oldInfo.userSize);
    memcpy(newUserPtr, oldUserPtr, copySize);

    // 释放旧块
    InternalFree(oldUserPtr);

    return newUserPtr;
}

///////////////////////////////////////////////////////////////////////////////
// Storm兼容头部管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetupStormHeader(void* userPtr, size_t userSize) noexcept {
    SetupCompatibleHeader(userPtr, userSize);
}

bool MemorySafety::ValidateStormHeader(void* userPtr) const noexcept {
    if (!userPtr) return false;

    return SafeExecute([=]() -> bool {
        const StormAllocHeader* header = reinterpret_cast<const StormAllocHeader*>(
            static_cast<const char*>(userPtr) - sizeof(StormAllocHeader));

        // 检查魔数
        if (header->Magic != STORM_FRONT_MAGIC) {
            return false;
        }

        // 检查特殊堆标记
        if (header->HeapPtr != STORM_SPECIAL_HEAP) {
            return false;
        }

        // 检查尾魔数（如果启用）
        if (header->Flags & 0x1) {
            const WORD* tailMagic = reinterpret_cast<const WORD*>(
                static_cast<const char*>(userPtr) + header->Size);
            if (*tailMagic != STORM_TAIL_MAGIC) {
                return false;
            }
        }

        return true;
        }, "ValidateStormHeader");
}

///////////////////////////////////////////////////////////////////////////////
// Size Class缓存管理
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::TryGetFromCache(size_t size) noexcept {
    size_t sizeClass = GetSizeClass(size);
    auto& cache = m_sizeClassCaches[sizeClass];

    return SafeExecute([&]() -> void* {
        std::lock_guard<std::mutex> lock(cache.mutex);

        for (auto it = cache.items.begin(); it != cache.items.end(); ++it) {
            size_t requiredTotal = CalculateTotalSize(size);
            if (it->totalSize >= requiredTotal) {
                // 找到合适的块
                void* rawPtr = it->rawPtr;
                size_t totalSize = it->totalSize;

                cache.items.erase(it);
                cache.totalSize.fetch_sub(totalSize);
                m_currentCached.fetch_sub(totalSize);

                m_cacheHits.fetch_add(1);
                return rawPtr;
            }
        }

        // 尝试其他Size Class
        for (size_t i = sizeClass + 1; i < MAX_SIZE_CLASSES; ++i) {
            auto& otherCache = m_sizeClassCaches[i];
            std::lock_guard<std::mutex> otherLock(otherCache.mutex);

            if (!otherCache.items.empty()) {
                auto& item = otherCache.items.front();
                size_t requiredTotal = CalculateTotalSize(size);
                if (item.totalSize >= requiredTotal) {
                    void* rawPtr = item.rawPtr;
                    size_t totalSize = item.totalSize;

                    otherCache.items.erase(otherCache.items.begin());
                    otherCache.totalSize.fetch_sub(totalSize);
                    m_currentCached.fetch_sub(totalSize);

                    m_cacheHits.fetch_add(1);
                    return rawPtr;
                }
            }
        }

        m_cacheMisses.fetch_add(1);
        return nullptr;
        }, "TryGetFromCache");
}

void MemorySafety::AddToCache(void* rawPtr, size_t totalSize) noexcept {
    if (!rawPtr || totalSize == 0) return;

    size_t sizeClass = GetSizeClass(totalSize);
    auto& cache = m_sizeClassCaches[sizeClass];

    SafeExecute([&]() -> void {
        std::lock_guard<std::mutex> lock(cache.mutex);

        // 检查缓存大小限制
        size_t maxCacheBytes = m_maxCacheSizeMB.load() * 1024 * 1024;
        if (GetTotalCached() + totalSize > maxCacheBytes) {
            // 缓存已满，直接释放
            VirtualFree(rawPtr, 0, MEM_RELEASE);
            return;
        }

        // 添加到缓存
        cache.items.emplace_back(rawPtr, totalSize);
        cache.totalSize.fetch_add(totalSize);
        m_currentCached.fetch_add(totalSize);
        }, "AddToCache");
}

size_t MemorySafety::GetSizeClass(size_t size) const noexcept {
    // 按64KB为单位分档
    size_t sizeClass = (size + SIZE_CLASS_UNIT - 1) / SIZE_CLASS_UNIT;
    if (sizeClass == 0) sizeClass = 1;
    if (sizeClass > MAX_SIZE_CLASSES) sizeClass = MAX_SIZE_CLASSES;
    return sizeClass - 1;  // 转换为0-based索引
}

///////////////////////////////////////////////////////////////////////////////
// Hold队列管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept {
    if (!rawPtr) return;

    SafeExecute([=]() -> void {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);
        m_holdQueue.emplace(rawPtr, totalSize);
        }, "AddToHoldQueue");
}

void MemorySafety::ProcessHoldQueue() noexcept {
    ProcessExpiredItems();
}

void MemorySafety::ProcessExpiredItems() noexcept {
    SafeExecute([this]() -> void {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);

        DWORD currentTime = MemorySafetyUtils::GetTickCount();
        DWORD holdTime = m_holdTimeMs.load();

        while (!m_holdQueue.empty()) {
            const auto& item = m_holdQueue.front();

            if (MemorySafetyUtils::HasTimeElapsed(item.releaseTime, holdTime)) {
                // 过期了，尝试加入缓存或直接释放
                AddToCache(item.rawPtr, item.totalSize);
                m_holdQueue.pop();
            }
            else {
                // 还没过期，后面的也不会过期（队列是按时间顺序的）
                break;
            }
        }
        }, "ProcessExpiredItems");
}

void MemorySafety::DrainHoldQueue() noexcept {
    SafeExecute([this]() -> void {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);

        size_t count = 0;
        while (!m_holdQueue.empty()) {
            const auto& item = m_holdQueue.front();
            VirtualFree(item.rawPtr, 0, MEM_RELEASE);
            m_holdQueue.pop();
            count++;
        }

        if (count > 0) {
            printf("[MemorySafety] DrainHoldQueue: 释放 %zu 个项目\n", count);
        }
        }, "DrainHoldQueue");
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    return SafeExecute([this]() -> size_t {
        std::lock_guard<std::mutex> lock(m_holdQueueMutex);
        return m_holdQueue.size();
        }, "GetHoldQueueSize");
}

///////////////////////////////////////////////////////////////////////////////
// 压力清理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::ForceCleanup() noexcept {
    SafeExecute([this]() -> void {
        printf("[MemorySafety] 开始强制清理\n");

        // 1. 处理Hold队列
        ProcessExpiredItems();

        // 2. 检查内存压力并清理缓存
        if (IsMemoryUnderPressure()) {
            size_t freedSize = FlushCacheByPressure(2); // 中等压力
            printf("[MemorySafety] 压力清理释放: %zu MB\n", freedSize / (1024 * 1024));
        }

        m_lastCleanupTime.store(MemorySafetyUtils::GetTickCount());
        printf("[MemorySafety] 强制清理完成\n");
        }, "ForceCleanup");
}

size_t MemorySafety::FlushCacheByPressure(int pressureLevel) noexcept {
    size_t totalFreed = 0;

    SafeExecute([&]() -> void {
        for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
            auto& cache = m_sizeClassCaches[i];
            std::lock_guard<std::mutex> lock(cache.mutex);

            if (cache.items.empty()) continue;

            // 根据压力级别决定清理比例
            size_t targetRemove = 0;
            switch (pressureLevel) {
            case 1: targetRemove = cache.items.size() / 4; break; // 清理25%
            case 2: targetRemove = cache.items.size() / 2; break; // 清理50%  
            case 3: targetRemove = cache.items.size(); break;     // 清理100%
            default: continue;
            }

            if (targetRemove == 0) continue;

            // 按时间排序，清理最老的项
            std::sort(cache.items.begin(), cache.items.end(),
                [](const CacheItem& a, const CacheItem& b) {
                    return a.cacheTime < b.cacheTime;
                });

            size_t actualRemove = min(targetRemove, cache.items.size());
            for (size_t j = 0; j < actualRemove; ++j) {
                VirtualFree(cache.items[j].rawPtr, 0, MEM_RELEASE);
                totalFreed += cache.items[j].totalSize;
                cache.totalSize.fetch_sub(cache.items[j].totalSize);
                m_currentCached.fetch_sub(cache.items[j].totalSize);
            }

            cache.items.erase(cache.items.begin(), cache.items.begin() + actualRemove);
        }
        }, "FlushCacheByPressure");

    return totalFreed;
}

bool MemorySafety::IsMemoryUnderPressure() const noexcept {
    size_t vmUsage = MemorySafetyUtils::GetProcessVirtualMemoryUsage();
    size_t watermarkBytes = m_watermarkMB.load() * 1024 * 1024;
    return vmUsage > watermarkBytes;
}

void MemorySafety::TriggerPressureCleanup() noexcept {
    DWORD currentTime = MemorySafetyUtils::GetTickCount();
    DWORD lastCleanup = m_lastCleanupTime.load();

    // 避免过于频繁的清理
    if (!MemorySafetyUtils::HasTimeElapsed(lastCleanup, MIN_CLEANUP_INTERVAL_MS)) {
        return;
    }

    m_lastCleanupTime.store(currentTime);

    SafeExecute([this]() -> void {
        printf("[MemorySafety] 触发压力清理\n");

        // 清理Hold队列中的过期项
        ProcessExpiredItems();

        // 根据压力级别清理缓存
        FlushCacheByPressure(2);  // 中等压力清理
        }, "TriggerPressureCleanup");
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::CalculateTotalSize(size_t userSize) const noexcept {
    // 计算总需要的大小：StormHeader + 用户数据 + 尾魔数 + 对齐
    size_t totalSize = sizeof(StormAllocHeader) + userSize + sizeof(WORD);
    return AlignSize(totalSize, 16); // 16字节对齐
}

void* MemorySafety::GetRawPtrFromUser(void* userPtr) const noexcept {
    if (!userPtr) return nullptr;
    return static_cast<char*>(userPtr) - sizeof(StormAllocHeader);
}

void* MemorySafety::GetUserPtrFromRaw(void* rawPtr, size_t userSize) const noexcept {
    if (!rawPtr) return nullptr;
    return static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
}

size_t MemorySafety::GetTotalCached() const noexcept {
    size_t total = 0;
    for (size_t i = 0; i < MAX_SIZE_CLASSES; ++i) {
        total += m_sizeClassCaches[i].totalSize.load();
    }
    return total;
}