#include "pch.h"
#include "MemorySafety.h"
#include "Logger.h"
#include "Storm/MemoryPool.h"
#include <algorithm>
#include <cstring>
#include <Storm/StormOffsets.h>
#include <Storm/StormHook.h>
#include <Psapi.h>

// ======================== 常量定义 ========================
namespace {
    constexpr size_t DEFAULT_MAX_DEFERRED_ITEMS = 1000;
    constexpr DWORD  DEFAULT_DEFERRED_TIMEOUT = 30000;  // 30秒
    constexpr size_t DEFAULT_MAX_TRACKED_BLOCKS = 10000;
    constexpr DWORD  MONITOR_INTERVAL = 5000;           // 5秒
}

// ======================== MemorySafety实现 ========================

MemorySafety& MemorySafety::GetInstance() {
    static MemorySafety instance;
    return instance;
}

MemorySafetyConfig MemorySafety::GetDefaultConfig() {
    MemorySafetyConfig config;
    config.enableTracking = true;
    config.enableValidation = true;
    config.enableDeferredFree = true;
    config.maxDeferredItems = DEFAULT_MAX_DEFERRED_ITEMS;
    config.deferredTimeout = DEFAULT_DEFERRED_TIMEOUT;
    config.enableLeakDetection = true;
    config.enableCorruptionDetection = true;
    config.maxTrackedBlocks = DEFAULT_MAX_TRACKED_BLOCKS;
    return config;
}

bool MemorySafety::Initialize(const MemorySafetyConfig& config) {
    if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
        return true; // 已初始化
    }

    m_config = config;

    // 初始化临界区
    InitializeCriticalSection(&m_deferredLock);

    // 重置统计
    memset(&m_stats, 0, sizeof(m_stats));

    Logger::GetInstance().LogInfo("内存安全系统已初始化");
    Logger::GetInstance().LogInfo("配置: 跟踪=%s, 验证=%s, 延迟释放=%s, 泄漏检测=%s",
        m_config.enableTracking ? "启用" : "禁用",
        m_config.enableValidation ? "启用" : "禁用",
        m_config.enableDeferredFree ? "启用" : "禁用",
        m_config.enableLeakDetection ? "启用" : "禁用");

    return true;
}

void MemorySafety::Shutdown() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return; // 未初始化
    }

    Logger::GetInstance().LogInfo("内存安全系统正在关闭...");

    // 输出最终统计
    PrintStats();

    // 检测泄漏
    if (m_config.enableLeakDetection) {
        auto leaks = DetectLeaks(0); // 检测所有未释放的块
        if (!leaks.empty()) {
            Logger::GetInstance().LogWarning("检测到%zu个潜在内存泄漏", leaks.size());
            ReportLeaks(leaks);
        }
    }

    // 处理剩余的延迟释放项
    FlushDeferredFreeQueue();

    // 清理跟踪数据
    ClearAllTracking();

    // 清理临界区
    DeleteCriticalSection(&m_deferredLock);

    Logger::GetInstance().LogInfo("内存安全系统已关闭");
}

bool MemorySafety::IsInitialized() const {
    return m_initialized.load(std::memory_order_acquire);
}

bool MemorySafety::RegisterMemoryBlock(void* rawPtr, void* userPtr, size_t size,
    const char* sourceName, DWORD sourceLine) {
    if (!IsInitialized() || !m_config.enableTracking || !userPtr) {
        return false;
    }

    // 检查是否超过最大跟踪数量
    if (m_trackedBlocks.size() >= m_config.maxTrackedBlocks) {
        Logger::GetInstance().LogWarning("达到最大跟踪块数量限制: %zu", m_config.maxTrackedBlocks);
        return false;
    }

    MemoryBlockInfo info;
    info.rawPtr = rawPtr;
    info.userPtr = userPtr;
    info.size = size;
    info.sourceName = sourceName;
    info.sourceLine = sourceLine;
    info.timestamp = GetTickCount();
    info.threadId = GetCurrentThreadId();
    info.isValid = true;

    AcquireSRWLockExclusive(&m_blocksLock);

    // 检查是否已存在
    if (m_trackedBlocks.find(userPtr) != m_trackedBlocks.end()) {
        ReleaseSRWLockExclusive(&m_blocksLock);
        Logger::GetInstance().LogWarning("尝试重复注册内存块: %p", userPtr);
        return false;
    }

    m_trackedBlocks[userPtr] = info;

    // 更新统计
    m_stats.totalRegistered++;
    m_stats.currentBlocks++;
    m_stats.currentSize += size;

    if (m_stats.currentBlocks > m_stats.peakBlocks) {
        m_stats.peakBlocks = m_stats.currentBlocks;
    }
    if (m_stats.currentSize > m_stats.peakSize) {
        m_stats.peakSize = m_stats.currentSize;
    }

    ReleaseSRWLockExclusive(&m_blocksLock);

    Logger::GetInstance().LogDebug("注册内存块: ptr=%p, size=%zu, source=%s:%lu",
        userPtr, size, sourceName ? sourceName : "unknown", sourceLine);

    return true;
}

bool MemorySafety::UnregisterMemoryBlock(void* userPtr) {
    if (!IsInitialized() || !m_config.enableTracking || !userPtr) {
        return false;
    }

    AcquireSRWLockExclusive(&m_blocksLock);

    auto it = m_trackedBlocks.find(userPtr);
    if (it == m_trackedBlocks.end()) {
        ReleaseSRWLockExclusive(&m_blocksLock);
        return false;
    }

    size_t blockSize = it->second.size;
    m_trackedBlocks.erase(it);

    // 更新统计
    m_stats.totalUnregistered++;
    m_stats.currentBlocks--;
    m_stats.currentSize -= blockSize;

    ReleaseSRWLockExclusive(&m_blocksLock);

    Logger::GetInstance().LogDebug("注销内存块: ptr=%p, size=%zu", userPtr, blockSize);

    return true;
}

bool MemorySafety::TryUnregisterBlock(void* userPtr) {
    // 安全版本，不输出错误日志
    if (!IsInitialized() || !m_config.enableTracking || !userPtr) {
        return false;
    }

    AcquireSRWLockExclusive(&m_blocksLock);

    auto it = m_trackedBlocks.find(userPtr);
    if (it == m_trackedBlocks.end()) {
        ReleaseSRWLockExclusive(&m_blocksLock);
        return false;
    }

    size_t blockSize = it->second.size;
    m_trackedBlocks.erase(it);

    // 更新统计
    m_stats.totalUnregistered++;
    m_stats.currentBlocks--;
    m_stats.currentSize -= blockSize;

    ReleaseSRWLockExclusive(&m_blocksLock);

    return true;
}

bool MemorySafety::GetMemoryBlockInfo(void* userPtr, MemoryBlockInfo& info) const {
    if (!IsInitialized() || !userPtr) {
        return false;
    }

    AcquireSRWLockShared(&m_blocksLock);

    auto it = m_trackedBlocks.find(userPtr);
    if (it == m_trackedBlocks.end()) {
        ReleaseSRWLockShared(&m_blocksLock);
        return false;
    }

    info = it->second;
    ReleaseSRWLockShared(&m_blocksLock);

    return true;
}

bool MemorySafety::ValidateMemoryBlock(void* userPtr) const {
    if (!IsInitialized() || !m_config.enableValidation || !userPtr) {
        return false;
    }

    MemoryBlockInfo info;
    if (!GetMemoryBlockInfo(userPtr, info)) {
        NotifyValidationFailure(userPtr, "块未注册");
        return false;
    }

    if (!info.isValid) {
        NotifyValidationFailure(userPtr, "块已标记为无效");
        return false;
    }

    // 验证块是否来自我们的内存池
    if (!MemoryPool::IsFromPool(info.rawPtr)) {
        NotifyValidationFailure(userPtr, "块不来自TLSF池");
        return false;
    }

    // 验证块大小
    size_t actualSize = MemoryPool::GetBlockSize(info.rawPtr);
    if (actualSize == 0) {
        NotifyValidationFailure(userPtr, "无法获取块大小");
        return false;
    }

    const_cast<MemorySafety*>(this)->m_stats.validationCount++;

    return true;
}

bool MemorySafety::ValidateAllBlocks() const {
    if (!IsInitialized() || !m_config.enableValidation) {
        return true;
    }

    Logger::GetInstance().LogInfo("开始验证所有内存块...");

    AcquireSRWLockShared(&m_blocksLock);

    size_t totalBlocks = m_trackedBlocks.size();
    size_t validBlocks = 0;
    size_t invalidBlocks = 0;

    for (const auto& pair : m_trackedBlocks) {
        ReleaseSRWLockShared(&m_blocksLock);

        if (ValidateMemoryBlock(pair.first)) {
            validBlocks++;
        }
        else {
            invalidBlocks++;
        }

        AcquireSRWLockShared(&m_blocksLock);
    }

    ReleaseSRWLockShared(&m_blocksLock);

    const_cast<MemorySafety*>(this)->m_stats.lastValidationTime = GetTickCount();
    const_cast<MemorySafety*>(this)->m_stats.validationFailures += invalidBlocks;

    Logger::GetInstance().LogInfo("内存块验证完成: 总计=%zu, 有效=%zu, 无效=%zu",
        totalBlocks, validBlocks, invalidBlocks);

    return invalidBlocks == 0;
}

size_t MemorySafety::ValidateAndRepairBlocks() {
    if (!IsInitialized() || !m_config.enableValidation) {
        return 0;
    }

    Logger::GetInstance().LogInfo("开始验证并修复内存块...");

    std::vector<void*> blocksToRemove;

    AcquireSRWLockShared(&m_blocksLock);

    for (const auto& pair : m_trackedBlocks) {
        void* userPtr = pair.first;
        const MemoryBlockInfo& info = pair.second;

        ReleaseSRWLockShared(&m_blocksLock);

        if (IsBlockCorrupted(info)) {
            blocksToRemove.push_back(userPtr);
            Logger::GetInstance().LogWarning("发现损坏块，将移除跟踪: %p", userPtr);
        }

        AcquireSRWLockShared(&m_blocksLock);
    }

    ReleaseSRWLockShared(&m_blocksLock);

    // 移除损坏的块
    for (void* ptr : blocksToRemove) {
        TryUnregisterBlock(ptr);
    }

    Logger::GetInstance().LogInfo("修复完成，移除了%zu个损坏块", blocksToRemove.size());

    return blocksToRemove.size();
}

void MemorySafety::EnqueueDeferredFree(void* ptr, size_t size) {
    if (!IsInitialized() || !m_config.enableDeferredFree || !ptr) {
        return;
    }

    DeferredFreeItem item;
    item.ptr = ptr;
    item.size = size;
    item.queueTime = GetTickCount();
    item.threadId = GetCurrentThreadId();

    EnterCriticalSection(&m_deferredLock);

    // 检查队列大小限制
    if (m_deferredQueue.size() >= m_config.maxDeferredItems) {
        // 处理最老的项目为新项目腾出空间
        ProcessDeferredFreeItem(m_deferredQueue.front());
        m_deferredQueue.erase(m_deferredQueue.begin());
    }

    m_deferredQueue.push_back(item);
    m_stats.deferredFreeCount++;

    LeaveCriticalSection(&m_deferredLock);

    Logger::GetInstance().LogDebug("延迟释放入队: ptr=%p, size=%zu, 队列大小=%zu",
        ptr, size, m_deferredQueue.size());
}

void MemorySafety::ProcessDeferredFreeQueue() {
    if (!IsInitialized() || !m_config.enableDeferredFree) {
        return;
    }

    DWORD currentTime = GetTickCount();
    std::vector<DeferredFreeItem> itemsToProcess;

    EnterCriticalSection(&m_deferredLock);

    // 收集超时的项目
    auto it = m_deferredQueue.begin();
    while (it != m_deferredQueue.end()) {
        if (currentTime - it->queueTime >= m_config.deferredTimeout) {
            itemsToProcess.push_back(*it);
            it = m_deferredQueue.erase(it);
        }
        else {
            ++it;
        }
    }

    LeaveCriticalSection(&m_deferredLock);

    // 处理项目
    for (const auto& item : itemsToProcess) {
        ProcessDeferredFreeItem(item);
    }

    if (!itemsToProcess.empty()) {
        Logger::GetInstance().LogDebug("处理了%zu个延迟释放项", itemsToProcess.size());
    }
}

void MemorySafety::FlushDeferredFreeQueue() {
    if (!IsInitialized()) {
        return;
    }

    Logger::GetInstance().LogInfo("刷新延迟释放队列...");

    std::vector<DeferredFreeItem> allItems;

    EnterCriticalSection(&m_deferredLock);
    allItems = m_deferredQueue;
    m_deferredQueue.clear();
    LeaveCriticalSection(&m_deferredLock);

    // 处理所有项目
    for (const auto& item : allItems) {
        ProcessDeferredFreeItem(item);
    }

    Logger::GetInstance().LogInfo("刷新完成，处理了%zu个项目", allItems.size());
}

size_t MemorySafety::GetDeferredFreeQueueSize() const {
    if (!IsInitialized()) {
        return 0;
    }

    EnterCriticalSection(&m_deferredLock);
    size_t size = m_deferredQueue.size();
    LeaveCriticalSection(&m_deferredLock);

    return size;
}

void MemorySafety::EnterUnsafePeriod() {
    m_inUnsafePeriod.store(true, std::memory_order_release);

    if (m_unsafePeriodCallback) {
        m_unsafePeriodCallback(true);
    }

    Logger::GetInstance().LogInfo("进入不安全期");
}

void MemorySafety::ExitUnsafePeriod() {
    m_inUnsafePeriod.store(false, std::memory_order_release);

    if (m_unsafePeriodCallback) {
        m_unsafePeriodCallback(false);
    }

    Logger::GetInstance().LogInfo("退出不安全期");
}

bool MemorySafety::IsInUnsafePeriod() const {
    return m_inUnsafePeriod.load(std::memory_order_acquire);
}

void MemorySafety::SetUnsafePeriodCallback(void (*callback)(bool entering)) {
    m_unsafePeriodCallback = callback;
}

std::vector<MemorySafety::LeakInfo> MemorySafety::DetectLeaks(DWORD minAge) const {
    std::vector<LeakInfo> leaks;

    if (!IsInitialized() || !m_config.enableLeakDetection) {
        return leaks;
    }

    DWORD currentTime = GetTickCount();

    AcquireSRWLockShared(&m_blocksLock);

    for (const auto& pair : m_trackedBlocks) {
        const MemoryBlockInfo& info = pair.second;
        DWORD age = currentTime - info.timestamp;

        if (age >= minAge) {
            LeakInfo leak;
            leak.userPtr = info.userPtr;
            leak.size = info.size;
            leak.sourceName = info.sourceName;
            leak.sourceLine = info.sourceLine;
            leak.age = age;

            leaks.push_back(leak);
        }
    }

    ReleaseSRWLockShared(&m_blocksLock);

    const_cast<MemorySafety*>(this)->m_stats.leakDetections++;

    return leaks;
}

void MemorySafety::ReportLeaks(const std::vector<LeakInfo>& leaks) const {
    if (leaks.empty()) {
        return;
    }

    Logger::GetInstance().LogWarning("=== 内存泄漏报告 ===");
    Logger::GetInstance().LogWarning("检测到%zu个潜在泄漏:", leaks.size());

    size_t totalSize = 0;
    for (const auto& leak : leaks) {
        totalSize += leak.size;

        Logger::GetInstance().LogWarning("泄漏: ptr=%p, size=%zu, age=%lu ms, source=%s:%lu",
            leak.userPtr, leak.size, leak.age,
            leak.sourceName ? leak.sourceName : "unknown",
            leak.sourceLine);

        if (m_leakDetectedCallback) {
            m_leakDetectedCallback(leak);
        }
    }

    Logger::GetInstance().LogWarning("总泄漏大小: %zu 字节 (%.2f MB)",
        totalSize, totalSize / (1024.0 * 1024.0));
    Logger::GetInstance().LogWarning("================");
}

std::vector<MemorySafety::CorruptionInfo> MemorySafety::DetectCorruption() const {
    std::vector<CorruptionInfo> corruptions;

    if (!IsInitialized() || !m_config.enableCorruptionDetection) {
        return corruptions;
    }

    AcquireSRWLockShared(&m_blocksLock);

    for (const auto& pair : m_trackedBlocks) {
        const MemoryBlockInfo& info = pair.second;

        ReleaseSRWLockShared(&m_blocksLock);

        if (IsBlockCorrupted(info)) {
            CorruptionInfo corruption;
            corruption.userPtr = info.userPtr;
            corruption.expectedSize = info.size;
            corruption.actualSize = MemoryPool::GetBlockSize(info.rawPtr);
            corruption.description = "块大小不匹配或块已损坏";

            corruptions.push_back(corruption);
        }

        AcquireSRWLockShared(&m_blocksLock);
    }

    ReleaseSRWLockShared(&m_blocksLock);

    const_cast<MemorySafety*>(this)->m_stats.corruptionDetections++;

    return corruptions;
}

void MemorySafety::ReportCorruption(const std::vector<CorruptionInfo>& corruptions) const {
    if (corruptions.empty()) {
        return;
    }

    Logger::GetInstance().LogError("=== 内存损坏报告 ===");
    Logger::GetInstance().LogError("检测到%zu个损坏块:", corruptions.size());

    for (const auto& corruption : corruptions) {
        Logger::GetInstance().LogError("损坏: ptr=%p, 期望大小=%zu, 实际大小=%zu, 描述=%s",
            corruption.userPtr, corruption.expectedSize,
            corruption.actualSize, corruption.description);

        if (m_corruptionDetectedCallback) {
            m_corruptionDetectedCallback(corruption);
        }
    }

    Logger::GetInstance().LogError("================");
}

MemorySafety::MemorySafetyStats MemorySafety::GetStats() const {
    return m_stats;
}

void MemorySafety::ResetStats() {
    memset(&m_stats, 0, sizeof(m_stats));
    Logger::GetInstance().LogInfo("内存安全统计已重置");
}

void MemorySafety::PrintStats() const {
    Logger::GetInstance().LogInfo("=== 内存安全系统统计 ===");
    Logger::GetInstance().LogInfo("注册块: %zu, 注销块: %zu, 当前块: %zu",
        m_stats.totalRegistered, m_stats.totalUnregistered, m_stats.currentBlocks);
    Logger::GetInstance().LogInfo("当前大小: %zu MB, 峰值块数: %zu, 峰值大小: %zu MB",
        m_stats.currentSize / (1024 * 1024), m_stats.peakBlocks,
        m_stats.peakSize / (1024 * 1024));
    Logger::GetInstance().LogInfo("验证: %zu 次, 失败: %zu 次",
        m_stats.validationCount, m_stats.validationFailures);
    Logger::GetInstance().LogInfo("延迟释放: %zu 次, 泄漏检测: %zu 次, 损坏检测: %zu 次",
        m_stats.deferredFreeCount, m_stats.leakDetections, m_stats.corruptionDetections);
    Logger::GetInstance().LogInfo("延迟队列大小: %zu", GetDeferredFreeQueueSize());
    Logger::GetInstance().LogInfo("=====================");
}

void MemorySafety::SetConfig(const MemorySafetyConfig& config) {
    m_config = config;
    Logger::GetInstance().LogInfo("内存安全配置已更新");
}

MemorySafetyConfig MemorySafety::GetConfig() const {
    return m_config;
}

void MemorySafety::DumpAllBlocks() const {
    if (!IsInitialized()) {
        return;
    }

    Logger::GetInstance().LogInfo("=== 所有跟踪的内存块 ===");

    AcquireSRWLockShared(&m_blocksLock);

    for (const auto& pair : m_trackedBlocks) {
        const MemoryBlockInfo& info = pair.second;
        DWORD age = GetTickCount() - info.timestamp;

        Logger::GetInstance().LogInfo("块: ptr=%p, raw=%p, size=%zu, age=%lu ms, thread=%lu, source=%s:%lu",
            info.userPtr, info.rawPtr, info.size, age, info.threadId,
            info.sourceName ? info.sourceName : "unknown", info.sourceLine);
    }

    ReleaseSRWLockShared(&m_blocksLock);

    Logger::GetInstance().LogInfo("总计: %zu 个块", m_trackedBlocks.size());
    Logger::GetInstance().LogInfo("===================");
}

void MemorySafety::DumpDeferredQueue() const {
    if (!IsInitialized()) {
        return;
    }

    Logger::GetInstance().LogInfo("=== 延迟释放队列 ===");

    EnterCriticalSection(&m_deferredLock);

    DWORD currentTime = GetTickCount();
    for (size_t i = 0; i < m_deferredQueue.size(); i++) {
        const auto& item = m_deferredQueue[i];
        DWORD age = currentTime - item.queueTime;

        Logger::GetInstance().LogInfo("项目 #%zu: ptr=%p, size=%zu, age=%lu ms, thread=%lu",
            i, item.ptr, item.size, age, item.threadId);
    }

    LeaveCriticalSection(&m_deferredLock);

    Logger::GetInstance().LogInfo("总计: %zu 个项目", m_deferredQueue.size());
    Logger::GetInstance().LogInfo("================");
}

void MemorySafety::ClearAllTracking() {
    Logger::GetInstance().LogInfo("清理所有跟踪数据...");

    AcquireSRWLockExclusive(&m_blocksLock);
    m_trackedBlocks.clear();
    ReleaseSRWLockExclusive(&m_blocksLock);

    EnterCriticalSection(&m_deferredLock);
    m_deferredQueue.clear();
    LeaveCriticalSection(&m_deferredLock);

    Logger::GetInstance().LogInfo("跟踪数据清理完成");
}

void MemorySafety::SetValidationFailureCallback(ValidationFailureCallback callback) {
    m_validationFailureCallback = callback;
}

void MemorySafety::SetLeakDetectedCallback(LeakDetectedCallback callback) {
    m_leakDetectedCallback = callback;
}

void MemorySafety::SetCorruptionDetectedCallback(CorruptionDetectedCallback callback) {
    m_corruptionDetectedCallback = callback;
}

// ======================== 内部实现 ========================

void MemorySafety::ProcessDeferredFreeItem(const DeferredFreeItem& item) {
    // 1) 查询rawPtr（item.ptr 是 userPtr）
    MemoryBlockInfo info{};
    bool got = GetMemoryBlockInfo(item.ptr, info);

    // 2) 从跟踪移除（安全版本，不报错）
    TryUnregisterBlock(item.ptr);

    // 3) 释放：仅当拿到 rawPtr 才释放；否则跳过，避免 TLSF 损坏
    if (got && info.rawPtr) {
        MemoryPool::FreeSafe(info.rawPtr);
        Logger::GetInstance().LogDebug(
            "处理延迟释放(raw): user=%p, raw=%p, size=%zu",
            item.ptr, info.rawPtr, item.size);
    }
    else {
        Logger::GetInstance().LogError(
            "延迟释放缺rawPtr，已跳过以避免TLSF损坏: user=%p, size=%zu",
            item.ptr, item.size);
        // 关键：绝不fallback到 free(userPtr)，这会破坏TLSF池
        // 可选：将其计入泄漏统计或重试队列，但切忌直接释放userPtr
    }
}
bool MemorySafety::IsBlockCorrupted(const MemoryBlockInfo& info) const {
    // 检查块是否仍在池中
    if (!MemoryPool::IsFromPool(info.rawPtr)) {
        return true;
    }

    // 检查块大小是否一致
    size_t actualSize = MemoryPool::GetBlockSize(info.rawPtr);
    if (actualSize == 0) {
        return true;
    }

    // 大小差异太大可能表示损坏
    if (actualSize < info.size) {
        return true;
    }

    return false;
}

void MemorySafety::NotifyValidationFailure(void* userPtr, const char* reason) const {
    Logger::GetInstance().LogError("内存验证失败: ptr=%p, 原因=%s", userPtr, reason);

    if (m_validationFailureCallback) {
        m_validationFailureCallback(userPtr, reason);
    }
}

void MemorySafety::NotifyLeakDetected(const LeakInfo& leak) const {
    if (m_leakDetectedCallback) {
        m_leakDetectedCallback(leak);
    }
}

void MemorySafety::NotifyCorruptionDetected(const CorruptionInfo& corruption) const {
    if (m_corruptionDetectedCallback) {
        m_corruptionDetectedCallback(corruption);
    }
}

// ======================== MemoryMonitor实现 ========================

MemoryMonitor::MemoryMonitor() : m_thread(nullptr), m_stopEvent(nullptr), m_interval(5000) {
}

MemoryMonitor::~MemoryMonitor() {
    StopMonitoring();
}

void MemoryMonitor::StartMonitoring(DWORD intervalMs) {
    if (m_running.exchange(true, std::memory_order_acq_rel)) {
        return; // 已在运行
    }

    m_interval = intervalMs;
    m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    if (!m_stopEvent) {
        m_running.store(false, std::memory_order_release);
        return;
    }

    // 初始化时间戳
    DWORD currentTime = GetTickCount();
    m_lastReportTime = currentTime;
    m_lastStatsTime = currentTime;
    m_lastValidationTime = currentTime;
    m_lastLeakCheckTime = currentTime;

    m_thread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);

    if (!m_thread) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
        m_running.store(false, std::memory_order_release);
        return;
    }

    Logger::GetInstance().LogInfo("增强版内存监控器已启动，间隔=%lu ms", intervalMs);
}

void MemoryMonitor::StopMonitoring() {
    if (!m_running.exchange(false, std::memory_order_acq_rel)) {
        return; // 未运行
    }

    if (m_stopEvent) {
        SetEvent(m_stopEvent);
    }

    if (m_thread) {
        WaitForSingleObject(m_thread, 5000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }

    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }

    Logger::GetInstance().LogInfo("增强版内存监控器已停止");
}

bool MemoryMonitor::IsMonitoring() const {
    return m_running.load(std::memory_order_acquire);
}

DWORD WINAPI MemoryMonitor::MonitorThreadProc(LPVOID param) {
    MemoryMonitor* monitor = static_cast<MemoryMonitor*>(param);
    monitor->MonitorLoop();
    return 0;
}

void MemoryMonitor::MonitorLoop() {
    Logger::GetInstance().LogInfo("增强版内存监控线程已启动");

    while (m_running.load(std::memory_order_acquire)) {
        DWORD waitResult = WaitForSingleObject(m_stopEvent, m_interval);

        if (waitResult == WAIT_OBJECT_0) {
            break; // 收到停止信号
        }

        DWORD currentTime = GetTickCount();
        MemorySafety& safety = MemorySafety::GetInstance();

        if (!safety.IsInitialized()) {
            continue;
        }

        // 使用批处理减少锁争用，同一时间只做一种操作

        // 1. 每30秒生成详细报告
        if (currentTime - m_lastReportTime > 30000) {
            GenerateDetailedReport();
            m_lastReportTime = currentTime;
            continue;
        }

        // 2. 每60秒打印完整内存统计
        if (currentTime - m_lastStatsTime > 60000) {
            PrintMemoryStats();
            m_lastStatsTime = currentTime;
            continue;
        }

        // 3. 每30秒验证所有块
        if (currentTime - m_lastValidationTime > 30000) {
            safety.ValidateAllBlocks();
            m_lastValidationTime = currentTime;
            continue;
        }

        // 4. 每60秒检测泄漏
        if (currentTime - m_lastLeakCheckTime > 60000) {
            auto leaks = safety.DetectLeaks(120000); // 检测存活超过2分钟的块
            if (!leaks.empty()) {
                safety.ReportLeaks(leaks);
            }
            m_lastLeakCheckTime = currentTime;
            continue;
        }

        // 5. 每次循环都处理延迟释放队列
        safety.ProcessDeferredFreeQueue();
    }

    Logger::GetInstance().LogInfo("增强版内存监控线程已退出");
}

void MemoryMonitor::GenerateDetailedReport() {
    Logger::GetInstance().LogInfo("=== 详细内存报告 ===");

    // OS口径
    PrintProcessMemory();

    // MemorySafety统计
    auto safetyStats = MemorySafety::GetInstance().GetStats();
    Logger::GetInstance().LogInfo("内存安全: 当前块=%zu, 当前大小=%zu MB, 峰值=%zu MB",
        safetyStats.currentBlocks,
        safetyStats.currentSize / (1024 * 1024),
        safetyStats.peakSize / (1024 * 1024));

    // StormHook统计
    size_t managedBlocks = StormHook::GetManagedBlockCount();
    size_t managedSize = StormHook::GetTotalManagedSize();
    Logger::GetInstance().LogInfo("StormHook: 管理块=%zu, 总大小=%zu MB",
        managedBlocks, managedSize / (1024 * 1024));

    // TLSF内存池统计
    PrintTLSFPoolStats();

    // Storm内部统计
    PrintStormInternalStats();

    Logger::GetInstance().LogInfo("==================");
}

void MemoryMonitor::PrintMemoryStats() {
    DWORD currentTime = GetTickCount();
    Logger::GetInstance().LogInfo("\n[内存状态] ---- 距上次报告%u秒 ----",
        (currentTime - m_lastStatsTime) / 1000);

    // OS口径
    PrintProcessMemory();

    // MemoryPool统计
    MemoryPool::PrintStats();

    // MemorySafety统计
    MemorySafety::GetInstance().PrintStats();

    // StormHook统计
    Logger::GetInstance().LogInfo("[内存状态] StormHook管理块: %zu个, 总大小: %zu MB",
        StormHook::GetManagedBlockCount(),
        StormHook::GetTotalManagedSize() / (1024 * 1024));

    // TLSF详细统计
    PrintTLSFPoolStats();

    // Storm内部统计
    PrintStormInternalStats();
}

void MemoryMonitor::PrintStormInternalStats() {
    // 需要确保Storm.dll已加载且偏移有效
    if (gStormDllBase == 0) {
        Logger::GetInstance().LogWarning("Storm.dll基址未设置，跳过内部统计");
        return;
    }

    __try {
        Logger::GetInstance().LogInfo("=== Storm内部统计 ===");

        // 内存系统状态
        bool memSysInit = Storm_g_MemorySystemInitialized;
        bool errorHandling = Storm_g_ErrorHandlingEnabled;
        Logger::GetInstance().LogInfo("Storm内存系统: 已初始化=%s, 错误处理=%s",
            memSysInit ? "是" : "否", errorHandling ? "是" : "否");

        // 总分配内存
        size_t totalAlloc = Storm_g_TotalAllocatedMemory;
        Logger::GetInstance().LogInfo("Storm总分配内存: %zu MB", totalAlloc / (1024 * 1024));

        // 调试相关
        uint32_t forceAlign = Storm_ForceAllocSizeToFour;
        uint32_t extraPadding = Storm_ExtraAlignPadding;
        Logger::GetInstance().LogInfo("Storm调试标志: ForceAlign=%u, ExtraPadding=%u",
            forceAlign, extraPadding);

        // 堆活跃状态（检查前几个堆）
        int activeHeaps = 0;
        for (int i = 0; i < 16; i++) { // 只检查前16个堆，避免过多输出
            if (Storm_g_HeapActiveFlag(i) != 0) {
                activeHeaps++;
            }
        }
        Logger::GetInstance().LogInfo("Storm活跃堆数量: %d (前16个检查)", activeHeaps);

        Logger::GetInstance().LogInfo("===================");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError("访问Storm内部统计时发生异常: 0x%08X", GetExceptionCode());
    }
}

void MemoryMonitor::PrintTLSFPoolStats() {
    Logger::GetInstance().LogInfo("=== TLSF内存池详细统计 ===");

    auto poolStats = MemoryPool::GetStats();
    Logger::GetInstance().LogInfo("总大小: %zu MB, 已用: %zu MB (%.1f%%)",
        poolStats.totalSize / (1024 * 1024),
        poolStats.usedSize / (1024 * 1024),
        poolStats.totalSize > 0 ? (poolStats.usedSize * 100.0 / poolStats.totalSize) : 0.0);

    Logger::GetInstance().LogInfo("空闲: %zu MB, 峰值使用: %zu MB",
        poolStats.freeSize / (1024 * 1024),
        poolStats.peakUsed / (1024 * 1024));

    Logger::GetInstance().LogInfo("分配次数: %zu, 释放次数: %zu, 扩展次数: %zu",
        poolStats.allocCount, poolStats.freeCount, poolStats.extendCount);

    // 池数量信息
    size_t poolCount = MemoryPool::Internal::GetPoolCount();
    Logger::GetInstance().LogInfo("内存池数量: %zu", poolCount);

    Logger::GetInstance().LogInfo("========================");
}

void MemoryMonitor::PrintProcessMemory() {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {

        size_t privateBytes = pmc.PrivateUsage;      // 提交量（推荐）
        size_t workingSet = pmc.WorkingSetSize;    // 常驻集
        size_t wsPeak = pmc.PeakWorkingSetSize;
        size_t pagefileUse = pmc.PagefileUsage;     // 兼容字段
        size_t pagefilePeak = pmc.PeakPagefileUsage;

        Logger::GetInstance().LogInfo("=== 进程内存 (OS口径) ===");
        Logger::GetInstance().LogInfo("PrivateBytes(提交量): %zu MB", privateBytes / (1024 * 1024));
        Logger::GetInstance().LogInfo("WorkingSet(常驻):     %zu MB (峰值 %zu MB)",
            workingSet / (1024 * 1024), wsPeak / (1024 * 1024));
        Logger::GetInstance().LogInfo("PagefileUsage(兼容):  %zu MB (峰值 %zu MB)",
            pagefileUse / (1024 * 1024), pagefilePeak / (1024 * 1024));
        Logger::GetInstance().LogInfo("========================");
    }
    else {
        Logger::GetInstance().LogError("GetProcessMemoryInfo失败: %lu", GetLastError());
    }
}