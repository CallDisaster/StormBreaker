// MemorySafety.cpp - 基于TLSF的高效内存管理实现（完整重写）
#include "pch.h"
#include "MemorySafety.h"
#include <psapi.h>
#include <algorithm>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

///////////////////////////////////////////////////////////////////////////////
// 结构体实现
///////////////////////////////////////////////////////////////////////////////

TLSFPoolInstance::TLSFPoolInstance()
    : baseMemory(nullptr), totalSize(0), tlsfHandle(nullptr), usedBytes(0), allocCount(0), freeCount(0) {
    InitializeCriticalSection(&cs);
}

TLSFPoolInstance::~TLSFPoolInstance() {
    if (tlsfHandle) {
        tlsf_destroy(tlsfHandle);
    }
    if (baseMemory) {
        VirtualFree(baseMemory, 0, MEM_RELEASE);
    }
    DeleteCriticalSection(&cs);
}

HoldItem::HoldItem(void* user, void* raw, size_t size, size_t pool)
    : userPtr(user), rawPtr(raw), userSize(size), poolIndex(pool), queueTime(GetTickCount()) {
}

BlockInfo::BlockInfo()
    : rawPtr(nullptr), userPtr(nullptr), totalSize(0), userSize(0),
    poolIndex(SIZE_MAX), allocTime(0), sourceName(nullptr),
    sourceLine(0), isInHoldQueue(false) {
}

BlockInfo::BlockInfo(void* raw, void* user, size_t total, size_t userSz, size_t pool,
    const char* name, DWORD line)
    : rawPtr(raw), userPtr(user), totalSize(total), userSize(userSz),
    poolIndex(pool), allocTime(GetTickCount()), sourceName(name),
    sourceLine(line), isInHoldQueue(false) {
}

///////////////////////////////////////////////////////////////////////////////
// 单例实现
///////////////////////////////////////////////////////////////////////////////

MemorySafety& MemorySafety::GetInstance() noexcept {
    static MemorySafety instance;
    return instance;
}

MemorySafety::MemorySafety() noexcept
    : m_initialized(false), m_shutdownRequested(false),
    m_totalAllocated(0), m_totalFreed(0), m_forceCleanups(0),
    m_directVirtualAllocCount(0), m_directVirtualAllocBytes(0),
    m_lastCleanupTime(0) {

    InitializeCriticalSection(&m_configCs);
    InitializeCriticalSection(&m_blockMapCs);
    InitializeCriticalSection(&m_holdQueueCs);

    // 初始化池指针为nullptr
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        m_pools[i] = nullptr;
    }
}

MemorySafety::~MemorySafety() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
    DeleteCriticalSection(&m_configCs);
    DeleteCriticalSection(&m_blockMapCs);
    DeleteCriticalSection(&m_holdQueueCs);
}

///////////////////////////////////////////////////////////////////////////////
// 生命周期管理
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::Initialize(const MemorySafetyConfig& config) noexcept {
    bool expected = false;
    if (!m_initialized.compare_exchange_strong(expected, true)) {
        return true; // 已初始化
    }

    // 保存配置
    EnterCriticalSection(&m_configCs);
    m_config = config;
    LeaveCriticalSection(&m_configCs);

    // 初始化TLSF池
    if (!InitializePools()) {
        LogError("[MemorySafety] TLSF池初始化失败");
        m_initialized.store(false);
        return false;
    }

    // 重置统计
    ResetStatistics();
    m_lastCleanupTime.store(MemorySafetyUtils::GetTickCount());

    LogMessage("[MemorySafety] 初始化完成，创建%d个TLSF池", POOL_COUNT);
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        LogMessage("  池%zu: %zuMB (阈值≤%zuKB)", i, POOL_SIZES[i] / (1024 * 1024), POOL_THRESHOLDS[i] / 1024);
    }

    return true;
}

void MemorySafety::Shutdown() noexcept {
    bool expected = true;
    if (!m_initialized.compare_exchange_strong(expected, false)) {
        return; // 已关闭
    }

    LogMessage("[MemorySafety] 开始关闭");

    // 强制处理剩余的Hold队列
    DrainHoldQueue();

    // 打印最终统计
    PrintStatistics();

    // 销毁TLSF池
    DestroyPools();

    // 清理块映射
    EnterCriticalSection(&m_blockMapCs);
    m_blockMap.clear();
    LeaveCriticalSection(&m_blockMapCs);

    LogMessage("[MemorySafety] 关闭完成");
}

bool MemorySafety::IsInitialized() const noexcept {
    return m_initialized.load();
}

///////////////////////////////////////////////////////////////////////////////
// TLSF池管理
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::InitializePools() noexcept {
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        m_pools[i] = new TLSFPoolInstance();
        TLSFPoolInstance& pool = *m_pools[i];

        // 分配大块内存
        pool.totalSize = POOL_SIZES[i];
        pool.baseMemory = VirtualAlloc(nullptr, pool.totalSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!pool.baseMemory) {
            LogError("[MemorySafety] 池%zu VirtualAlloc失败: %zuMB", i, pool.totalSize / (1024 * 1024));
            return false;
        }

        // 创建TLSF实例
        pool.tlsfHandle = tlsf_create_with_pool(pool.baseMemory, pool.totalSize);
        if (!pool.tlsfHandle) {
            LogError("[MemorySafety] 池%zu TLSF创建失败", i);
            VirtualFree(pool.baseMemory, 0, MEM_RELEASE);
            pool.baseMemory = nullptr;
            return false;
        }

        LogMessage("[MemorySafety] 池%zu初始化成功: %p, %zuMB",
            i, pool.baseMemory, pool.totalSize / (1024 * 1024));
    }
    return true;
}

void MemorySafety::DestroyPools() noexcept {
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        if (m_pools[i]) {
            TLSFPoolInstance& pool = *m_pools[i];

            LogMessage("[MemorySafety] 销毁池%zu: 分配%zu次, 释放%zu次, 使用率%.1f%%",
                i, pool.allocCount.load(), pool.freeCount.load(),
                pool.totalSize > 0 ? (pool.usedBytes.load() * 100.0 / pool.totalSize) : 0.0);

            delete m_pools[i];
            m_pools[i] = nullptr;
        }
    }
}

size_t MemorySafety::SelectPool(size_t size) const noexcept {
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        if (size <= POOL_THRESHOLDS[i]) {
            return i;
        }
    }
    return SIZE_MAX; // 超过所有池限制，需要直接VirtualAlloc
}

void* MemorySafety::AllocateFromPool(size_t poolIndex, size_t totalSize) noexcept {
    if (poolIndex >= POOL_COUNT || !m_pools[poolIndex]) {
        return nullptr;
    }

    TLSFPoolInstance& pool = *m_pools[poolIndex];
    EnterCriticalSection(&pool.cs);

    void* ptr = tlsf_malloc(pool.tlsfHandle, totalSize);
    if (ptr) {
        pool.usedBytes.fetch_add(totalSize);
        pool.allocCount.fetch_add(1);
    }

    LeaveCriticalSection(&pool.cs);
    return ptr;
}

bool MemorySafety::FreeToPool(size_t poolIndex, void* ptr) noexcept {
    if (poolIndex >= POOL_COUNT || !m_pools[poolIndex] || !ptr) {
        return false;
    }

    TLSFPoolInstance& pool = *m_pools[poolIndex];
    EnterCriticalSection(&pool.cs);

    // 获取块大小（用于统计）
    size_t blockSize = tlsf_block_size(ptr);

    tlsf_free(pool.tlsfHandle, ptr);

    if (blockSize > 0) {
        pool.usedBytes.fetch_sub(blockSize);
    }
    pool.freeCount.fetch_add(1);

    LeaveCriticalSection(&pool.cs);
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// 大块直接分配
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::DirectVirtualAlloc(size_t size) noexcept {
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

bool MemorySafety::DirectVirtualFree(void* ptr) noexcept {
    return VirtualFree(ptr, 0, MEM_RELEASE) != FALSE;
}

///////////////////////////////////////////////////////////////////////////////
// 内存分配接口
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::AllocateBlock(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!m_initialized.load()) {
        return nullptr;
    }

    return InternalAllocate(userSize, sourceName, sourceLine);
}

bool MemorySafety::FreeBlock(void* userPtr) noexcept {
    if (!userPtr || !m_initialized.load()) {
        return false;
    }

    return InternalFree(userPtr);
}

void* MemorySafety::ReallocateBlock(void* userPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!m_initialized.load()) {
        return nullptr;
    }

    return InternalRealloc(userPtr, newSize, sourceName, sourceLine);
}

///////////////////////////////////////////////////////////////////////////////
// 内部实现
///////////////////////////////////////////////////////////////////////////////

void* MemorySafety::InternalAllocate(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    // 计算总大小（包含Storm头部）
    size_t totalSize = CalculateTotalSize(userSize);

    // 选择合适的池
    size_t poolIndex = SelectPool(totalSize);
    void* rawPtr = nullptr;

    if (poolIndex != SIZE_MAX) {
        // 从TLSF池分配
        rawPtr = AllocateFromPool(poolIndex, totalSize);
        if (!rawPtr) {
            // 池满了，尝试使用下一个池
            if (poolIndex + 1 < POOL_COUNT) {
                rawPtr = AllocateFromPool(poolIndex + 1, totalSize);
                if (rawPtr) {
                    poolIndex = poolIndex + 1;
                }
            }
        }
    }

    if (!rawPtr) {
        // 所有池都失败，直接VirtualAlloc
        rawPtr = DirectVirtualAlloc(totalSize);
        if (!rawPtr) {
            return nullptr;
        }
        poolIndex = SIZE_MAX; // 标记为直接分配
        m_directVirtualAllocCount.fetch_add(1);
        m_directVirtualAllocBytes.fetch_add(totalSize);
    }

    // 计算用户指针
    void* userPtr = GetUserPtrFromRaw(rawPtr);

    // 设置Storm兼容头部
    SetupStormHeader(userPtr, userSize, totalSize);

    // 更新块映射
    EnterCriticalSection(&m_blockMapCs);
    m_blockMap[userPtr] = BlockInfo(rawPtr, userPtr, totalSize, userSize, poolIndex, sourceName, sourceLine);
    LeaveCriticalSection(&m_blockMapCs);

    // 更新统计
    UpdateStatistics(userSize, true, poolIndex);

    return userPtr;
}

bool MemorySafety::InternalFree(void* userPtr) noexcept {
    // 查找块信息
    BlockInfo info;
    bool found = false;

    EnterCriticalSection(&m_blockMapCs);
    auto it = m_blockMap.find(userPtr);
    if (it != m_blockMap.end()) {
        info = it->second;
        found = true;

        EnterCriticalSection(&m_configCs);
        bool enableHoldQueue = m_config.enableHoldQueue;
        LeaveCriticalSection(&m_configCs);

        if (enableHoldQueue && !info.isInHoldQueue) {
            // 标记为在Hold队列中，但不删除映射
            it->second.isInHoldQueue = true;
        }
        else {
            // 已经在Hold队列中或禁用Hold队列，直接删除映射
            m_blockMap.erase(it);
        }
    }
    LeaveCriticalSection(&m_blockMapCs);

    if (!found) {
        return false; // 不是我们管理的块
    }

    EnterCriticalSection(&m_configCs);
    bool enableHoldQueue = m_config.enableHoldQueue;
    LeaveCriticalSection(&m_configCs);

    if (enableHoldQueue && !info.isInHoldQueue) {
        // 添加到Hold队列而不是立即释放
        AddToHoldQueue(userPtr, info.rawPtr, info.userSize, info.poolIndex);
    }
    else {
        // 立即释放
        if (info.poolIndex != SIZE_MAX) {
            FreeToPool(info.poolIndex, info.rawPtr);
        }
        else {
            DirectVirtualFree(info.rawPtr);
        }
    }

    // 更新统计
    UpdateStatistics(info.userSize, false, info.poolIndex);

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
    bool found = false;

    EnterCriticalSection(&m_blockMapCs);
    auto it = m_blockMap.find(userPtr);
    if (it != m_blockMap.end()) {
        oldInfo = it->second;
        found = true;
    }
    LeaveCriticalSection(&m_blockMapCs);

    if (!found) {
        return nullptr; // 不是我们管理的块
    }

    // 如果新大小和旧大小差不多，且在同一个池中，可以尝试原地扩展
    size_t newTotalSize = CalculateTotalSize(newSize);
    size_t newPoolIndex = SelectPool(newTotalSize);

    if (newPoolIndex == oldInfo.poolIndex && oldInfo.poolIndex != SIZE_MAX) {
        // 尝试原地重分配（TLSF支持）
        TLSFPoolInstance& pool = *m_pools[oldInfo.poolIndex];
        EnterCriticalSection(&pool.cs);

        void* newRawPtr = tlsf_realloc(pool.tlsfHandle, oldInfo.rawPtr, newTotalSize);
        if (newRawPtr) {
            // 原地扩展成功
            void* newUserPtr = GetUserPtrFromRaw(newRawPtr);

            // 更新块信息
            EnterCriticalSection(&m_blockMapCs);
            m_blockMap.erase(userPtr);
            m_blockMap[newUserPtr] = BlockInfo(newRawPtr, newUserPtr, newTotalSize, newSize,
                newPoolIndex, sourceName, sourceLine);
            LeaveCriticalSection(&m_blockMapCs);

            // 重新设置Storm头部
            SetupStormHeader(newUserPtr, newSize, newTotalSize);

            LeaveCriticalSection(&pool.cs);
            return newUserPtr;
        }

        LeaveCriticalSection(&pool.cs);
    }

    // 原地扩展失败，分配新块并复制数据
    void* newPtr = InternalAllocate(newSize, sourceName, sourceLine);
    if (!newPtr) {
        return nullptr;
    }

    // 复制数据
    size_t copySize = (oldInfo.userSize < newSize) ? oldInfo.userSize : newSize;
    memcpy(newPtr, userPtr, copySize);

    // 释放旧块
    InternalFree(userPtr);

    return newPtr;
}

///////////////////////////////////////////////////////////////////////////////
// Hold队列管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::AddToHoldQueue(void* userPtr, void* rawPtr, size_t userSize, size_t poolIndex) noexcept {
    EnterCriticalSection(&m_holdQueueCs);

    // 检查队列大小限制
    EnterCriticalSection(&m_configCs);
    size_t maxSize = m_config.maxHoldQueueSize;
    LeaveCriticalSection(&m_configCs);

    if (m_holdQueue.size() >= maxSize) {
        // 队列满了，强制处理最老的项
        ProcessExpiredItems();
    }

    m_holdQueue.emplace_back(userPtr, rawPtr, userSize, poolIndex);

    LeaveCriticalSection(&m_holdQueueCs);
}

void MemorySafety::ProcessHoldQueue() noexcept {
    EnterCriticalSection(&m_holdQueueCs);
    ProcessExpiredItems();
    LeaveCriticalSection(&m_holdQueueCs);
}

void MemorySafety::ProcessExpiredItems() noexcept {
    DWORD currentTime = MemorySafetyUtils::GetTickCount();

    EnterCriticalSection(&m_configCs);
    DWORD holdTime = m_config.holdBufferTimeMs;
    LeaveCriticalSection(&m_configCs);

    auto it = m_holdQueue.begin();
    while (it != m_holdQueue.end()) {
        if (currentTime - it->queueTime >= holdTime) {
            // 过期，实际释放
            if (it->poolIndex != SIZE_MAX) {
                FreeToPool(it->poolIndex, it->rawPtr);
            }
            else {
                DirectVirtualFree(it->rawPtr);
            }

            // 从块映射中删除
            EnterCriticalSection(&m_blockMapCs);
            m_blockMap.erase(it->userPtr);
            LeaveCriticalSection(&m_blockMapCs);

            it = m_holdQueue.erase(it);
        }
        else {
            ++it;
        }
    }
}

void MemorySafety::DrainHoldQueue() noexcept {
    EnterCriticalSection(&m_holdQueueCs);

    for (auto& item : m_holdQueue) {
        if (item.poolIndex != SIZE_MAX) {
            FreeToPool(item.poolIndex, item.rawPtr);
        }
        else {
            DirectVirtualFree(item.rawPtr);
        }

        // 从块映射中删除
        EnterCriticalSection(&m_blockMapCs);
        m_blockMap.erase(item.userPtr);
        LeaveCriticalSection(&m_blockMapCs);
    }

    m_holdQueue.clear();
    LeaveCriticalSection(&m_holdQueueCs);
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    EnterCriticalSection(&m_holdQueueCs);
    size_t size = m_holdQueue.size();
    LeaveCriticalSection(&m_holdQueueCs);
    return size;
}

///////////////////////////////////////////////////////////////////////////////
// 块信息查询
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::IsOurBlock(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return false;
    }

    EnterCriticalSection(&m_blockMapCs);
    bool found = m_blockMap.find(userPtr) != m_blockMap.end();
    LeaveCriticalSection(&m_blockMapCs);
    return found;
}

size_t MemorySafety::GetBlockSize(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return 0;
    }

    EnterCriticalSection(&m_blockMapCs);
    auto it = m_blockMap.find(userPtr);
    size_t size = (it != m_blockMap.end()) ? it->second.userSize : 0;
    LeaveCriticalSection(&m_blockMapCs);
    return size;
}

BlockInfo MemorySafety::GetBlockInfo(void* userPtr) const noexcept {
    if (!userPtr || !m_initialized.load()) {
        return BlockInfo();
    }

    EnterCriticalSection(&m_blockMapCs);
    auto it = m_blockMap.find(userPtr);
    BlockInfo info = (it != m_blockMap.end()) ? it->second : BlockInfo();
    LeaveCriticalSection(&m_blockMapCs);
    return info;
}

///////////////////////////////////////////////////////////////////////////////
// Storm兼容性
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept {
    if (!userPtr) return;

    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
        static_cast<char*>(userPtr) - sizeof(StormAllocHeader)
        );

    // 设置Storm兼容的头部 - 使用正确的字段名
    header->HeapPtr = 0xC0DEFEED; // 特殊标记，表示我们管理的块
    header->Size = static_cast<DWORD>(userSize);
    header->AlignPadding = 0;
    header->Flags = 0x1; // 启用尾魔数
    header->Magic = STORM_FRONT_MAGIC;

    // 设置尾部魔数（如果启用）
    if (header->Flags & 0x1) {
        uint16_t* tailMagic = reinterpret_cast<uint16_t*>(
            static_cast<char*>(userPtr) + userSize
            );
        *tailMagic = STORM_TAIL_MAGIC;
    }
}

bool MemorySafety::ValidateStormHeader(void* userPtr) const noexcept {
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
        uint16_t* tailMagic = reinterpret_cast<uint16_t*>(
            static_cast<char*>(userPtr) + header->Size
            );
        if (*tailMagic != STORM_TAIL_MAGIC) {
            return false;
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::CalculateTotalSize(size_t userSize) const noexcept {
    return AlignSize(sizeof(StormAllocHeader) + userSize + sizeof(uint16_t), 16);
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

void MemorySafety::UpdateStatistics(size_t size, bool isAllocation, size_t poolIndex) noexcept {
    if (isAllocation) {
        m_totalAllocated.fetch_add(size);
    }
    else {
        m_totalFreed.fetch_add(size);
    }
}

///////////////////////////////////////////////////////////////////////////////
// 内存压力管理
///////////////////////////////////////////////////////////////////////////////

bool MemorySafety::IsMemoryUnderPressure() const noexcept {
    size_t vmUsage = MemorySafetyUtils::GetProcessVirtualMemoryUsage();

    EnterCriticalSection(&m_configCs);
    size_t watermarkBytes = m_config.memoryWatermarkMB * 1024 * 1024;
    LeaveCriticalSection(&m_configCs);

    return vmUsage > watermarkBytes;
}

void MemorySafety::ForceCleanup() noexcept {
    DWORD currentTime = MemorySafetyUtils::GetTickCount();
    DWORD lastCleanup = m_lastCleanupTime.load();

    if (currentTime - lastCleanup < MIN_CLEANUP_INTERVAL_MS) {
        return; // 避免频繁清理
    }

    // 处理Hold队列
    ProcessHoldQueue();

    m_lastCleanupTime.store(currentTime);
    m_forceCleanups.fetch_add(1);

    LogMessage("[MemorySafety] 强制清理完成");
}

void MemorySafety::TriggerPressureCleanup() noexcept {
    if (IsMemoryUnderPressure()) {
        ForceCleanup();
    }
}

///////////////////////////////////////////////////////////////////////////////
// 配置管理
///////////////////////////////////////////////////////////////////////////////

void MemorySafety::SetHoldTimeMs(DWORD timeMs) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.holdBufferTimeMs = timeMs;
    LeaveCriticalSection(&m_configCs);
}

void MemorySafety::SetWatermarkMB(size_t watermarkMB) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.memoryWatermarkMB = watermarkMB;
    LeaveCriticalSection(&m_configCs);
}

void MemorySafety::SetMaxHoldQueueSize(size_t maxSize) noexcept {
    EnterCriticalSection(&m_configCs);
    m_config.maxHoldQueueSize = maxSize;
    LeaveCriticalSection(&m_configCs);
}

///////////////////////////////////////////////////////////////////////////////
// 兼容性方法（为MemoryPool提供）
///////////////////////////////////////////////////////////////////////////////

size_t MemorySafety::GetTotalCached() const noexcept {
    size_t totalCached = 0;

    // 统计所有池的已分配内存
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        if (m_pools[i]) {
            totalCached += m_pools[i]->usedBytes.load();
        }
    }

    // 加上Hold队列中的内存
    totalCached += GetHoldQueueSize() * 1024; // 粗略估算

    return totalCached;
}

void MemorySafety::SetMaxCacheSize(size_t maxSizeMB) noexcept {
    // 这里可以调整池的行为，暂时只记录配置
    LogMessage("[MemorySafety] 设置最大缓存大小: %zuMB", maxSizeMB);
}

///////////////////////////////////////////////////////////////////////////////
// 统计信息
///////////////////////////////////////////////////////////////////////////////

MemorySafety::Statistics MemorySafety::GetStatistics() const noexcept {
    Statistics stats;
    stats.totalAllocated = m_totalAllocated.load();
    stats.totalFreed = m_totalFreed.load();
    stats.currentUsed = stats.totalAllocated - stats.totalFreed;
    stats.holdQueueSize = GetHoldQueueSize();
    stats.forceCleanups = m_forceCleanups.load();
    stats.directVirtualAllocCount = m_directVirtualAllocCount.load();
    stats.directVirtualAllocBytes = m_directVirtualAllocBytes.load();

    // 各池统计
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        if (m_pools[i]) {
            TLSFPoolInstance& pool = *m_pools[i];
            auto& poolStat = stats.poolStats[i];

            poolStat.totalSize = pool.totalSize;
            poolStat.usedBytes = pool.usedBytes.load();
            poolStat.allocCount = pool.allocCount.load();
            poolStat.freeCount = pool.freeCount.load();
            poolStat.utilization = pool.totalSize > 0 ?
                (poolStat.usedBytes * 100.0 / pool.totalSize) : 0.0;
        }
    }

    return stats;
}

void MemorySafety::PrintStatistics() const noexcept {
    Statistics stats = GetStatistics();

    LogMessage("[MemorySafety] === 统计报告 ===");
    LogMessage("  总体: 分配=%zuMB, 释放=%zuMB, 使用中=%zuMB",
        stats.totalAllocated / (1024 * 1024), stats.totalFreed / (1024 * 1024), stats.currentUsed / (1024 * 1024));
    LogMessage("  Hold队列: %zu项", stats.holdQueueSize);
    LogMessage("  强制清理: %zu次", stats.forceCleanups);
    LogMessage("  直接VirtualAlloc: %zu次, %zuMB",
        stats.directVirtualAllocCount, stats.directVirtualAllocBytes / (1024 * 1024));

    for (size_t i = 0; i < POOL_COUNT; ++i) {
        auto& ps = stats.poolStats[i];
        LogMessage("  池%zu: %zuMB, 使用率%.1f%%, 分配%zu次, 释放%zu次",
            i, ps.totalSize / (1024 * 1024), ps.utilization, ps.allocCount, ps.freeCount);
    }

    size_t processVM = MemorySafetyUtils::GetProcessVirtualMemoryUsage();
    LogMessage("  进程虚拟内存: %zuMB", processVM / (1024 * 1024));
    LogMessage("========================");
}

void MemorySafety::ResetStatistics() noexcept {
    m_totalAllocated.store(0);
    m_totalFreed.store(0);
    m_forceCleanups.store(0);
    m_directVirtualAllocCount.store(0);
    m_directVirtualAllocBytes.store(0);
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

    bool IsTLSFPointer(const void* ptr, const TLSFPoolInstance& pool) noexcept {
        if (!ptr || !pool.baseMemory) return false;

        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t poolStart = reinterpret_cast<uintptr_t>(pool.baseMemory);
        uintptr_t poolEnd = poolStart + pool.totalSize;

        return ptrAddr >= poolStart && ptrAddr < poolEnd;
    }

    size_t GetTLSFBlockSize(tlsf_t tlsf, void* ptr) noexcept {
        if (!tlsf || !ptr) return 0;
        return tlsf_block_size(ptr);
    }
}