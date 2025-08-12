#pragma once
#include "pch.h"
#include <Windows.h>
#include <stdint.h>
#include <atomic>
#include <vector>
#include <unordered_map>

// ======================== 内存块信息 ========================
struct MemoryBlockInfo {
    void* rawPtr;         // 原始分配指针
    void* userPtr;        // 用户指针
    size_t      size;           // 块大小
    const char* sourceName;     // 分配来源名称
    DWORD       sourceLine;     // 分配来源行号
    DWORD       timestamp;      // 分配时间戳
    DWORD       threadId;       // 分配线程ID
    bool        isValid;        // 是否有效
};

// ======================== 延迟释放项 ========================
struct DeferredFreeItem {
    void* ptr;                 // 待释放指针
    size_t size;                // 块大小
    DWORD  queueTime;           // 入队时间
    DWORD  threadId;            // 入队线程ID
};

// ======================== 内存安全配置 ========================
struct MemorySafetyConfig {
    bool   enableTracking;      // 启用内存跟踪
    bool   enableValidation;    // 启用内存验证
    bool   enableDeferredFree;  // 启用延迟释放
    size_t maxDeferredItems;    // 最大延迟释放项数
    DWORD  deferredTimeout;     // 延迟释放超时时间(ms)
    bool   enableLeakDetection; // 启用泄漏检测
    bool   enableCorruptionDetection; // 启用损坏检测
    size_t maxTrackedBlocks;    // 最大跟踪块数
};

// ======================== 内存安全系统 ========================
class MemorySafety {
public:
    // ======================== 单例访问 ========================
    static MemorySafety& GetInstance();

    // ======================== 初始化和清理 ========================
    bool Initialize(const MemorySafetyConfig& config = GetDefaultConfig());
    void Shutdown();
    bool IsInitialized() const;

    // ======================== 内存块管理 ========================
    bool RegisterMemoryBlock(void* rawPtr, void* userPtr, size_t size,
        const char* sourceName = nullptr, DWORD sourceLine = 0);
    bool UnregisterMemoryBlock(void* userPtr);
    bool GetMemoryBlockInfo(void* userPtr, MemoryBlockInfo& info) const;

    // ======================== 内存验证 ========================
    bool ValidateMemoryBlock(void* userPtr) const;
    bool ValidateAllBlocks() const;
    size_t ValidateAndRepairBlocks();

    // ======================== 延迟释放管理 ========================
    void EnqueueDeferredFree(void* ptr, size_t size);
    void ProcessDeferredFreeQueue();
    void FlushDeferredFreeQueue();
    size_t GetDeferredFreeQueueSize() const;

    // ======================== 不安全期管理 ========================
    void EnterUnsafePeriod();
    void ExitUnsafePeriod();
    bool IsInUnsafePeriod() const;
    void SetUnsafePeriodCallback(void (*callback)(bool entering));

    // ======================== 泄漏检测 ========================
    struct LeakInfo {
        void* userPtr;
        size_t      size;
        const char* sourceName;
        DWORD       sourceLine;
        DWORD       age;        // 存活时间(ms)
    };

    std::vector<LeakInfo> DetectLeaks(DWORD minAge = 60000) const; // 默认1分钟
    void ReportLeaks(const std::vector<LeakInfo>& leaks) const;

    // ======================== 损坏检测 ========================
    struct CorruptionInfo {
        void* userPtr;
        size_t      expectedSize;
        size_t      actualSize;
        const char* description;
    };

    std::vector<CorruptionInfo> DetectCorruption() const;
    void ReportCorruption(const std::vector<CorruptionInfo>& corruptions) const;

    // ======================== 统计信息 ========================
    struct MemorySafetyStats {
        size_t  totalRegistered;       // 总注册块数
        size_t  totalUnregistered;     // 总注销块数
        size_t  currentBlocks;         // 当前块数
        size_t  currentSize;           // 当前总大小
        size_t  peakBlocks;            // 峰值块数
        size_t  peakSize;              // 峰值大小
        size_t  validationCount;       // 验证次数
        size_t  validationFailures;    // 验证失败次数
        size_t  deferredFreeCount;     // 延迟释放次数
        size_t  leakDetections;        // 泄漏检测次数
        size_t  corruptionDetections;  // 损坏检测次数
        DWORD   lastValidationTime;    // 最后验证时间
    };

    MemorySafetyStats GetStats() const;
    void ResetStats();
    void PrintStats() const;

    // ======================== 配置管理 ========================
    void SetConfig(const MemorySafetyConfig& config);
    MemorySafetyConfig GetConfig() const;
    static MemorySafetyConfig GetDefaultConfig();

    // ======================== 调试和维护 ========================
    void DumpAllBlocks() const;
    void DumpDeferredQueue() const;
    bool TryUnregisterBlock(void* userPtr); // 安全版本，不报错
    void ClearAllTracking();

    // ======================== 回调接口 ========================
    typedef void (*ValidationFailureCallback)(void* userPtr, const char* reason);
    typedef void (*LeakDetectedCallback)(const LeakInfo& leak);
    typedef void (*CorruptionDetectedCallback)(const CorruptionInfo& corruption);

    void SetValidationFailureCallback(ValidationFailureCallback callback);
    void SetLeakDetectedCallback(LeakDetectedCallback callback);
    void SetCorruptionDetectedCallback(CorruptionDetectedCallback callback);

private:
    MemorySafety() = default;
    ~MemorySafety() = default;
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;

    // 内部实现
    void ProcessDeferredFreeItem(const DeferredFreeItem& item);
    bool IsBlockCorrupted(const MemoryBlockInfo& info) const;
    void NotifyValidationFailure(void* userPtr, const char* reason) const;
    void NotifyLeakDetected(const LeakInfo& leak) const;
    void NotifyCorruptionDetected(const CorruptionInfo& corruption) const;

private:
    MemorySafetyConfig m_config;
    std::atomic<bool>  m_initialized{ false };
    std::atomic<bool>  m_inUnsafePeriod{ false };

    // 内存块跟踪
    mutable SRWLOCK m_blocksLock = SRWLOCK_INIT;
    std::unordered_map<void*, MemoryBlockInfo> m_trackedBlocks;

    // 延迟释放队列
    mutable CRITICAL_SECTION m_deferredLock;
    std::vector<DeferredFreeItem> m_deferredQueue;

    // 统计信息
    mutable MemorySafetyStats m_stats{};

    // 回调函数
    ValidationFailureCallback m_validationFailureCallback = nullptr;
    LeakDetectedCallback m_leakDetectedCallback = nullptr;
    CorruptionDetectedCallback m_corruptionDetectedCallback = nullptr;
    void (*m_unsafePeriodCallback)(bool entering) = nullptr;
};

// ======================== 便利宏 ========================
#define MEMORY_SAFETY MemorySafety::GetInstance()

#define REGISTER_MEMORY_BLOCK(raw, user, size) \
    MEMORY_SAFETY.RegisterMemoryBlock(raw, user, size, __FILE__, __LINE__)

#define UNREGISTER_MEMORY_BLOCK(user) \
    MEMORY_SAFETY.UnregisterMemoryBlock(user)

#define VALIDATE_MEMORY_BLOCK(user) \
    MEMORY_SAFETY.ValidateMemoryBlock(user)

#define ENQUEUE_DEFERRED_FREE(ptr, size) \
    MEMORY_SAFETY.EnqueueDeferredFree(ptr, size)

// ======================== RAII辅助类 ========================
class UnsafePeriodGuard {
public:
    UnsafePeriodGuard() {
        MemorySafety::GetInstance().EnterUnsafePeriod();
    }

    ~UnsafePeriodGuard() {
        MemorySafety::GetInstance().ExitUnsafePeriod();
    }

private:
    UnsafePeriodGuard(const UnsafePeriodGuard&) = delete;
    UnsafePeriodGuard& operator=(const UnsafePeriodGuard&) = delete;
};

#define UNSAFE_PERIOD_GUARD() UnsafePeriodGuard _unsafe_guard

// ======================== 内存监控器 ========================
class MemoryMonitor {
public:
    MemoryMonitor();
    ~MemoryMonitor();

    void StartMonitoring(DWORD intervalMs = 5000);
    void StopMonitoring();
    bool IsMonitoring() const;
    void PrintProcessMemory();

private:
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();
    void GenerateDetailedReport();
    void PrintMemoryStats();
    void PrintStormInternalStats();
    void PrintTLSFPoolStats();

private:
    HANDLE m_thread;
    HANDLE m_stopEvent;
    DWORD  m_interval;
    std::atomic<bool> m_running{ false };

    // 统计时间跟踪
    DWORD m_lastReportTime{ 0 };
    DWORD m_lastStatsTime{ 0 };
    DWORD m_lastValidationTime{ 0 };
    DWORD m_lastLeakCheckTime{ 0 };
};