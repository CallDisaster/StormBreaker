// MemorySafety.cpp - 修复版本：解决虚拟内存过度使用和清理策略问题
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
    InitializeCriticalSection(&m_configCs);
    InitializeCriticalSection(&m_blockMapCs);
    InitializeCriticalSection(&m_holdQueueCs);
}

MemorySafety::~MemorySafety() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }

    DeleteCriticalSection(&m_holdQueueCs);
    DeleteCriticalSection(&m_blockMapCs);
    DeleteCriticalSection(&m_configCs);
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
            EnterCriticalSection(&m_configCs);
            m_config = config;
            LeaveCriticalSection(&m_configCs);
        }

        // 初始化大小分档缓存（不预分配内存池）
        for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
            m_sizeClassCaches[i] = std::make_unique<SizeClassCache>();
        }

        // 重置统计
        ResetStatistics();

        m_lastCleanupTime = GetTickCount();
        m_lastPressureCheckTime = GetTickCount();

        LogMessage("[MemorySafety] 初始化完成 - 按需分配模式");
        LogMessage("[MemorySafety] 配置: Hold=%ums, 工作集限制=%uMB, 缓存限制=%uMB",
            m_config.holdBufferTimeMs, m_config.workingSetLimitMB, m_config.maxCacheSizeMB);

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

        // 清理所有缓存（只释放真正空闲的块）
        CleanupCache(true);  // aggressive cleanup

        // 清理块映射
        {
            EnterCriticalSection(&m_blockMapCs);
            size_t leakedBlocks = m_blockMap.size();
            if (leakedBlocks > 0) {
                LogMessage("[MemorySafety] 检测到%zu个可能泄漏的块", leakedBlocks);
            }
            m_blockMap.clear();
            LeaveCriticalSection(&m_blockMapCs);
        }

        // 清理缓存数组
        for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
            if (m_sizeClassCaches[i]) {
                auto& cache = *m_sizeClassCaches[i];
                EnterCriticalSection(&cache.cs);

                for (auto& block : cache.freeBlocks) {
                    if (!block.isInUse) {
                        VirtualFree(block.rawPtr, 0, MEM_RELEASE);
                    }
                }
                cache.freeBlocks.clear();
                cache.totalCached = 0;

                LeaveCriticalSection(&cache.cs);
                m_sizeClassCaches[i].reset();
            }
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
// 内部实现
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::InternalAllocate(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    // 检查是否为超大块（直接VirtualAlloc）
    if (userSize > SIZE_CLASS_THRESHOLDS[SIZE_CLASS_COUNT - 2]) {  // 大于4MB
        return DirectVirtualAlloc(userSize, sourceName, sourceLine);
    }

    // 获取大小分档
    size_t sizeClass = GetSizeClass(userSize);
    size_t totalSize = CalculateTotalSize(userSize);

    // 尝试从缓存获取
    void* rawPtr = TryGetFromCache(sizeClass, totalSize);

    if (!rawPtr) {
        // 缓存未命中，分配新块
        rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rawPtr) {
            LogError("[MemorySafety] VirtualAlloc失败: 大小=%zu", totalSize);
            return nullptr;
        }
    }

    void* userPtr = GetUserPtrFromRaw(rawPtr);
    SetupStormHeader(userPtr, userSize, totalSize);

    // 更新块映射
    {
        EnterCriticalSection(&m_blockMapCs);
        m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, totalSize, userSize, sizeClass, sourceName, sourceLine);
        LeaveCriticalSection(&m_blockMapCs);
    }

    m_totalAllocated.fetch_add(userSize);
    UpdateStatistics(userSize, true, sizeClass);

    return userPtr;
}

bool MemorySafety::InternalFree(void* userPtr) noexcept {
    // 查找块信息
    BlockInfo info;
    {
        EnterCriticalSection(&m_blockMapCs);
        auto it = m_blockMap.find(userPtr);
        if (it == m_blockMap.end()) {
            LeaveCriticalSection(&m_blockMapCs);
            return false; // 不是我们管理的块
        }
        info = it->second;
        m_blockMap.erase(it);
        LeaveCriticalSection(&m_blockMapCs);
    }

    // 验证Storm头部
    if (!ValidateStormHeader(userPtr)) {
        LogError("[MemorySafety] Storm头部验证失败: %p", userPtr);
        // 仍然尝试释放以避免泄漏
    }

    // 添加到Hold队列而不是立即释放
    if (m_config.enableHoldQueue) {
        AddToHoldQueue(userPtr, info.rawPtr, info.userSize, info.sizeClass);
    }
    else {
        // 直接释放
        VirtualFree(info.rawPtr, 0, MEM_RELEASE);
    }

    m_totalFreed.fetch_add(info.userSize);
    UpdateStatistics(info.userSize, false, info.sizeClass);

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
        EnterCriticalSection(&m_blockMapCs);
        auto it = m_blockMap.find(userPtr);
        if (it == m_blockMap.end()) {
            LeaveCriticalSection(&m_blockMapCs);
            return nullptr; // 不是我们管理的块
        }
        oldInfo = it->second;
        LeaveCriticalSection(&m_blockMapCs);
    }

    // 如果新大小与旧大小在同一分档且总大小足够，就地重用
    size_t newSizeClass = GetSizeClass(newSize);
    if (newSizeClass == oldInfo.sizeClass &&
        CalculateTotalSize(newSize) <= oldInfo.totalSize) {

        // 更新块信息
            {
                EnterCriticalSection(&m_blockMapCs);
                auto it = m_blockMap.find(userPtr);
                if (it != m_blockMap.end()) {
                    it->second.userSize = newSize;
                    it->second.sourceName = sourceName;
                    it->second.sourceLine = sourceLine;
                }
                LeaveCriticalSection(&m_blockMapCs);
            }

            // 更新Storm头部
            SetupStormHeader(userPtr, newSize, oldInfo.totalSize);
            return userPtr;
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
    for (size_t i = 0; i < SIZE_CLASS_COUNT - 1; ++i) {
        if (size <= SIZE_CLASS_THRESHOLDS[i]) {
            return i;
        }
    }
    return SIZE_CLASS_COUNT - 1;
}

void* MemorySafety::TryGetFromCache(size_t sizeClass, size_t minSize) noexcept {
    if (sizeClass >= SIZE_CLASS_COUNT) {
        return nullptr;
    }

    auto& cache = *m_sizeClassCaches[sizeClass];
    EnterCriticalSection(&cache.cs);

    // 查找合适大小的空闲块
    for (auto it = cache.freeBlocks.begin(); it != cache.freeBlocks.end(); ++it) {
        if (!it->isInUse && it->totalSize >= minSize) {
            void* rawPtr = it->rawPtr;
            it->isInUse = true;
            it->lastUsedTime = GetTickCount();
            cache.hitCount++;
            LeaveCriticalSection(&cache.cs);
            return rawPtr;
        }
    }

    cache.missCount++;
    LeaveCriticalSection(&cache.cs);
    return nullptr;
}

void MemorySafety::AddToCache(void* rawPtr, size_t totalSize, size_t userSize, size_t sizeClass) noexcept {
    if (sizeClass >= SIZE_CLASS_COUNT) {
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return;
    }

    // 检查缓存大小限制
    if (GetTotalCached() > m_config.maxCacheSizeMB * 1024 * 1024) {
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return;
    }

    auto& cache = *m_sizeClassCaches[sizeClass];
    EnterCriticalSection(&cache.cs);

    // 添加到缓存
    cache.freeBlocks.emplace_back(rawPtr, totalSize, userSize, sizeClass);
    cache.freeBlocks.back().isInUse = false;
    cache.totalCached += totalSize;
    m_currentCached.fetch_add(totalSize);

    LeaveCriticalSection(&cache.cs);
}

void MemorySafety::CleanupCache(bool aggressiveCleanup) noexcept {
    DWORD currentTime = GetTickCount();
    size_t cleanupThreshold = aggressiveCleanup ? 0 : 30000; // 30秒未使用

    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        auto& cache = *m_sizeClassCaches[i];
        EnterCriticalSection(&cache.cs);

        auto it = cache.freeBlocks.begin();
        while (it != cache.freeBlocks.end()) {
            bool shouldRemove = false;

            if (aggressiveCleanup) {
                shouldRemove = !it->isInUse;
            }
            else {
                shouldRemove = !it->isInUse &&
                    (currentTime - it->lastUsedTime) > cleanupThreshold;
            }

            if (shouldRemove) {
                VirtualFree(it->rawPtr, 0, MEM_RELEASE);
                cache.totalCached -= it->totalSize;
                m_currentCached.fetch_sub(it->totalSize);
                it = cache.freeBlocks.erase(it);
            }
            else {
                ++it;
            }
        }

        LeaveCriticalSection(&cache.cs);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Hold队列管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::AddToHoldQueue(void* userPtr, void* rawPtr, size_t userSize, size_t sizeClass) noexcept {
    SafeExecuteVoid([this, userPtr, rawPtr, userSize, sizeClass]() {
        EnterCriticalSection(&m_holdQueueCs);

        // 检查队列大小限制
        if (m_holdQueue.size() >= m_config.maxHoldQueueSize) {
            // 释放最老的项
            auto& oldItem = m_holdQueue.front();
            VirtualFree(oldItem.rawPtr, 0, MEM_RELEASE);
            m_holdQueue.pop_front();
        }

        m_holdQueue.emplace_back(userPtr, rawPtr, userSize, sizeClass);

        // 定期处理过期项
        ProcessExpiredItems();

        LeaveCriticalSection(&m_holdQueueCs);
        }, "MemorySafety::AddToHoldQueue");
}

void MemorySafety::ProcessExpiredItems() noexcept {
    DWORD currentTime = GetTickCount();
    DWORD holdTime = m_config.holdBufferTimeMs;

    auto it = m_holdQueue.begin();
    while (it != m_holdQueue.end()) {
        if (currentTime - it->queueTime >= holdTime) {
            // 过期，尝试添加到缓存或直接释放
            AddToCache(it->rawPtr, CalculateTotalSize(it->userSize), it->userSize, it->sizeClass);
            it = m_holdQueue.erase(it);
        }
        else {
            ++it;
        }
    }
}

void MemorySafety::ProcessHoldQueue() noexcept {
    SafeExecuteVoid([this]() {
        EnterCriticalSection(&m_holdQueueCs);
        ProcessExpiredItems();
        LeaveCriticalSection(&m_holdQueueCs);
        }, "MemorySafety::ProcessHoldQueue");
}

void MemorySafety::DrainHoldQueue() noexcept {
    SafeExecuteVoid([this]() {
        EnterCriticalSection(&m_holdQueueCs);

        for (auto& item : m_holdQueue) {
            VirtualFree(item.rawPtr, 0, MEM_RELEASE);
        }
        m_holdQueue.clear();

        LeaveCriticalSection(&m_holdQueueCs);
        }, "MemorySafety::DrainHoldQueue");
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    return SafeExecuteValue([this]() -> size_t {
        EnterCriticalSection(&m_holdQueueCs);
        size_t size = m_holdQueue.size();
        LeaveCriticalSection(&m_holdQueueCs);
        return size;
        }, "MemorySafety::GetHoldQueueSize");
}

///////////////////////////////////////////////////////////////////////////////
// 内存压力管理 - 修复版本
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::IsMemoryUnderPressure() const noexcept {
    return CheckWorkingSetPressure() || CheckCommittedMemoryPressure();
}

bool MemorySafety::CheckWorkingSetPressure() const noexcept {
    size_t workingSet = GetWorkingSetSize();
    size_t limit = m_config.workingSetLimitMB * 1024 * 1024;
    return workingSet > limit;
}

bool MemorySafety::CheckCommittedMemoryPressure() const noexcept {
    size_t committed = GetCommittedSize();
    size_t limit = m_config.commitLimitMB * 1024 * 1024;
    return committed > limit;
}

void MemorySafety::ForceCleanup() noexcept {
    SafeExecuteVoid([this]() {
        DWORD currentTime = GetTickCount();
        DWORD lastCleanup = m_lastCleanupTime.load();

        if (currentTime - lastCleanup < MIN_CLEANUP_INTERVAL_MS) {
            return; // 避免频繁清理
        }

        LogMessage("[MemorySafety] 开始强制清理");

        // 处理Hold队列
        ProcessExpiredItems();

        // 保守清理缓存
        if (m_config.enableConservativeCleanup) {
            ConservativeCleanup();
        }
        else {
            CleanupCache(false);  // 非激进清理
        }

        m_lastCleanupTime.store(currentTime);
        m_forceCleanups.fetch_add(1);

        LogMessage("[MemorySafety] 强制清理完成");
        }, "MemorySafety::ForceCleanup");
}

void MemorySafety::ConservativeCleanup() noexcept {
    // 模拟Storm的"整堆空闲"策略：只清理长时间未使用的分档
    DWORD currentTime = GetTickCount();
    constexpr DWORD CONSERVATIVE_THRESHOLD = 60000;  // 60秒未使用

    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        auto& cache = *m_sizeClassCaches[i];
        EnterCriticalSection(&cache.cs);

        // 只有当整个分档都长时间未使用时才清理
        bool canCleanThisClass = true;
        for (const auto& block : cache.freeBlocks) {
            if (block.isInUse || (currentTime - block.lastUsedTime) < CONSERVATIVE_THRESHOLD) {
                canCleanThisClass = false;
                break;
            }
        }

        if (canCleanThisClass && !cache.freeBlocks.empty()) {
            LogMessage("[MemorySafety] 保守清理分档%zu: %zu个块", i, cache.freeBlocks.size());

            for (auto& block : cache.freeBlocks) {
                VirtualFree(block.rawPtr, 0, MEM_RELEASE);
                cache.totalCached -= block.totalSize;
                m_currentCached.fetch_sub(block.totalSize);
            }
            cache.freeBlocks.clear();

            m_conservativeCleanups.fetch_add(1);
        }

        LeaveCriticalSection(&cache.cs);
    }
}

void MemorySafety::TriggerPressureCleanup() noexcept {
    DWORD currentTime = GetTickCount();
    DWORD lastCheck = m_lastPressureCheckTime.load();

    if (currentTime - lastCheck < 5000) {  // 5秒检查一次
        return;
    }

    m_lastPressureCheckTime.store(currentTime);

    if (IsMemoryUnderPressure()) {
        LogMessage("[MemorySafety] 检测到内存压力，触发清理");
        ForceCleanup();
    }
}

///////////////////////////////////////////////////////////////////////////////
// 直接VirtualAlloc分配
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::DirectVirtualAlloc(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    size_t totalSize = CalculateTotalSize(size);
    void* rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rawPtr) {
        LogError("[MemorySafety] 直接VirtualAlloc失败: 大小=%zu", totalSize);
        return nullptr;
    }

    void* userPtr = GetUserPtrFromRaw(rawPtr);
    SetupStormHeader(userPtr, size, totalSize);

    // 超大块不加入缓存，直接记录
    {
        EnterCriticalSection(&m_blockMapCs);
        m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, totalSize, size, SIZE_MAX, sourceName, sourceLine);
        LeaveCriticalSection(&m_blockMapCs);
    }

    m_totalAllocated.fetch_add(size);

    return userPtr;
}

bool MemorySafety::DirectVirtualFree(void* ptr) noexcept {
    return VirtualFree(ptr, 0, MEM_RELEASE) != 0;
}

///////////////////////////////////////////////////////////////////////////////
// 块信息查询
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::IsOurBlock(void* userPtr) const noexcept {
    return SafeExecuteBool([this, userPtr]() -> bool {
        if (!userPtr || !m_initialized.load()) {
            return false;
        }

        EnterCriticalSection(&m_blockMapCs);
        bool found = m_blockMap.find(userPtr) != m_blockMap.end();
        LeaveCriticalSection(&m_blockMapCs);
        return found;
        }, "MemorySafety::IsOurBlock");
}

size_t MemorySafety::GetBlockSize(void* userPtr) const noexcept {
    return SafeExecuteValue([this, userPtr]() -> size_t {
        if (!userPtr || !m_initialized.load()) {
            return 0;
        }

        EnterCriticalSection(&m_blockMapCs);
        auto it = m_blockMap.find(userPtr);
        size_t size = (it != m_blockMap.end()) ? it->second.userSize : 0;
        LeaveCriticalSection(&m_blockMapCs);
        return size;
        }, "MemorySafety::GetBlockSize");
}

BlockInfo MemorySafety::GetBlockInfo(void* userPtr) const noexcept {
    return SafeExecuteWithDefault([this, userPtr]() -> BlockInfo {
        if (!userPtr || !m_initialized.load()) {
            return BlockInfo();
        }

        EnterCriticalSection(&m_blockMapCs);
        auto it = m_blockMap.find(userPtr);
        BlockInfo info = (it != m_blockMap.end()) ? it->second : BlockInfo();
        LeaveCriticalSection(&m_blockMapCs);
        return info;
        }, "MemorySafety::GetBlockInfo", BlockInfo());
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
        header->Size = static_cast<DWORD>(min(userSize, static_cast<size_t>(MAXDWORD)));
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

void MemorySafety::UpdateStatistics(size_t size, bool isAllocation, size_t sizeClass) noexcept {
    // 基础统计已在调用处更新，这里可以添加其他统计逻辑
}

size_t MemorySafety::GetTotalCached() const noexcept {
    return m_currentCached.load();
}

///////////////////////////////////////////////////////////////////////////////
// 内存使用情况获取
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::GetWorkingSetSize() const noexcept {
    return MemorySafetyUtils::GetProcessWorkingSetSize();
}

size_t MemorySafety::GetCommittedSize() const noexcept {
    return MemorySafetyUtils::GetProcessCommittedSize();
}

size_t MemorySafety::GetVirtualSize() const noexcept {
    return MemorySafetyUtils::GetProcessVirtualSize();
}

void MemorySafety::PrintMemoryUsage() const noexcept {
    size_t workingSet = GetWorkingSetSize();
    size_t committed = GetCommittedSize();
    size_t virtual_size = GetVirtualSize();
    size_t cached = GetTotalCached();

    LogMessage("[MemorySafety] 内存使用情况:");
    LogMessage("  工作集: %zu MB", workingSet / (1024 * 1024));
    LogMessage("  已提交: %zu MB", committed / (1024 * 1024));
    LogMessage("  虚拟内存: %zu MB", virtual_size / (1024 * 1024));
    LogMessage("  缓存: %zu MB", cached / (1024 * 1024));
}

///////////////////////////////////////////////////////////////////////////////
// 配置管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetHoldTimeMs(DWORD timeMs) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.holdBufferTimeMs = timeMs;
    LeaveCriticalSection(&m_configCs);
}

void MemorySafety::SetWorkingSetLimit(size_t limitMB) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.workingSetLimitMB = limitMB;
    LeaveCriticalSection(&m_configCs);
}

void MemorySafety::SetMaxCacheSize(size_t maxSizeMB) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.maxCacheSizeMB = maxSizeMB;
    LeaveCriticalSection(&m_configCs);
}

void MemorySafety::SetWatermarkMB(size_t watermarkMB) noexcept {
    // 兼容接口：将水位线映射到工作集限制
    SetWorkingSetLimit(watermarkMB);
}

///////////////////////////////////////////////////////////////////////////////
// 统计信息
///////////////////////////////////////////////////////////////////////////////

MemorySafety::Statistics MemorySafety::GetStatistics() const noexcept {
    Statistics stats;
    stats.totalAllocated = m_totalAllocated.load();
    stats.totalFreed = m_totalFreed.load();
    stats.currentCached = m_currentCached.load();
    stats.holdQueueSize = GetHoldQueueSize();
    stats.forceCleanups = m_forceCleanups.load();
    stats.conservativeCleanups = m_conservativeCleanups.load();

    // 各分档统计
    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        auto& cache = *m_sizeClassCaches[i];
        EnterCriticalSection(&cache.cs);

        stats.sizeClassStats[i].totalCached = cache.totalCached;
        stats.sizeClassStats[i].hitCount = cache.hitCount;
        stats.sizeClassStats[i].missCount = cache.missCount;

        size_t total = cache.hitCount + cache.missCount;
        stats.sizeClassStats[i].hitRate = total > 0 ? (cache.hitCount * 100.0 / total) : 0.0;

        LeaveCriticalSection(&cache.cs);
    }

    // 内存使用统计
    stats.workingSetSize = GetWorkingSetSize();
    stats.committedSize = GetCommittedSize();
    stats.virtualSize = GetVirtualSize();

    return stats;
}

void MemorySafety::PrintStatistics() const noexcept {
    Statistics stats = GetStatistics();

    LogMessage("[MemorySafety] === 统计报告 ===");
    LogMessage("  分配: 总计=%zuMB", stats.totalAllocated / (1024 * 1024));
    LogMessage("  释放: 总计=%zuMB", stats.totalFreed / (1024 * 1024));
    LogMessage("  缓存: %zuMB", stats.currentCached / (1024 * 1024));
    LogMessage("  Hold队列: %zu项", stats.holdQueueSize);
    LogMessage("  强制清理: %zu次", stats.forceCleanups);
    LogMessage("  保守清理: %zu次", stats.conservativeCleanups);

    LogMessage("  内存使用:");
    LogMessage("    工作集: %zuMB", stats.workingSetSize / (1024 * 1024));
    LogMessage("    已提交: %zuMB", stats.committedSize / (1024 * 1024));
    LogMessage("    虚拟内存: %zuMB", stats.virtualSize / (1024 * 1024));

    LogMessage("  各分档命中率:");
    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        if (stats.sizeClassStats[i].hitCount + stats.sizeClassStats[i].missCount > 0) {
            LogMessage("    分档%zu: %.1f%% (%zu/%zu)",
                i, stats.sizeClassStats[i].hitRate,
                stats.sizeClassStats[i].hitCount,
                stats.sizeClassStats[i].missCount);
        }
    }
    LogMessage("========================");
}

void MemorySafety::ResetStatistics() noexcept {
    m_totalAllocated = 0;
    m_totalFreed = 0;
    m_currentCached = 0;
    m_forceCleanups = 0;
    m_conservativeCleanups = 0;

    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        auto& cache = *m_sizeClassCaches[i];
        EnterCriticalSection(&cache.cs);
        cache.hitCount = 0;
        cache.missCount = 0;
        LeaveCriticalSection(&cache.cs);
    }
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数实现
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    size_t GetProcessWorkingSetSize() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }

    size_t GetProcessCommittedSize() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PagefileUsage;  // 已提交的内存
        }
        return 0;
    }

    size_t GetProcessVirtualSize() noexcept {
        PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
        if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            return pmc.PrivateUsage;  // 进程私有虚拟内存
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

    bool IsValidMemoryRange(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return false;

        __try {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
                return false;
            }

            return (mbi.State & MEM_COMMIT) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool IsMemoryCommitted(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return false;

        __try {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T remaining = size;
            char* current = static_cast<char*>(ptr);

            while (remaining > 0) {
                if (!VirtualQuery(current, &mbi, sizeof(mbi))) {
                    return false;
                }

                if (!(mbi.State & MEM_COMMIT)) {
                    return false;
                }

                SIZE_T blockSize = min(remaining, mbi.RegionSize - (current - static_cast<char*>(mbi.BaseAddress)));
                remaining -= blockSize;
                current += blockSize;
            }

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
}