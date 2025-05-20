#pragma once
#include <Windows.h>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <string>
#include <future>
#include <vector>
#include <thread>
#include "LogSystem.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// 报告数据结构 - 用于存储历史报告
struct MemoryReportData {
    std::string sessionId;        // 会话ID
    std::string timestamp;        // 时间戳
    size_t totalAllocations;      // 总分配次数
    size_t totalFrees;            // 总释放次数
    size_t unreleased;            // 未释放数量
    double totalAllocatedMB;      // 总分配内存(MB)
    double totalFreedMB;          // 总释放内存(MB)
    double leakedMemoryMB;        // 泄漏内存(MB)
    std::string reportPath;       // 报告文件路径

    // 类型统计数据
    std::unordered_map<std::string, double> typeAllocation; // 各类型分配内存(MB)
};

// --- Memory Tracker Record ---
struct MemoryTrackRecord {
    std::atomic<size_t> allocCount{ 0 };     // Use atomics for simple counters
    std::atomic<size_t> freeCount{ 0 };
    std::atomic<size_t> totalAllocSize{ 0 };
    std::atomic<size_t> totalFreeSize{ 0 };
    size_t peakAlloc{ 0 }; // Peak needs careful handling, maybe update less frequently or approximate

    // 显式定义复制构造函数 - 解决atomic不可复制问题
    MemoryTrackRecord() = default;

    MemoryTrackRecord(const MemoryTrackRecord& other) {
        allocCount.store(other.allocCount.load(std::memory_order_relaxed));
        freeCount.store(other.freeCount.load(std::memory_order_relaxed));
        totalAllocSize.store(other.totalAllocSize.load(std::memory_order_relaxed));
        totalFreeSize.store(other.totalFreeSize.load(std::memory_order_relaxed));
        peakAlloc = other.peakAlloc;
    }

    MemoryTrackRecord& operator=(const MemoryTrackRecord& other) {
        if (this != &other) {
            allocCount.store(other.allocCount.load(std::memory_order_relaxed));
            freeCount.store(other.freeCount.load(std::memory_order_relaxed));
            totalAllocSize.store(other.totalAllocSize.load(std::memory_order_relaxed));
            totalFreeSize.store(other.totalFreeSize.load(std::memory_order_relaxed));
            peakAlloc = other.peakAlloc;
        }
        return *this;
    }

    // Getters load atomic values
    size_t GetAllocCount() const { return allocCount.load(std::memory_order_relaxed); }
    size_t GetFreeCount() const { return freeCount.load(std::memory_order_relaxed); }
    size_t GetTotalAllocSize() const { return totalAllocSize.load(std::memory_order_relaxed); }
    size_t GetTotalFreeSize() const { return totalFreeSize.load(std::memory_order_relaxed); }

    size_t GetUnreleasedCount() const {
        size_t allocs = GetAllocCount();
        size_t frees = GetFreeCount();
        return allocs > frees ? allocs - frees : 0;
    }

    size_t GetUnreleasedMemory() const {
        size_t allocSize = GetTotalAllocSize();
        size_t freeSize = GetTotalFreeSize();
        return allocSize > freeSize ? allocSize - freeSize : 0;
    }
};

// --- Optimized Memory Tracker ---
class MemoryTracker {
public:
    // 初始化内存追踪器
    bool Initialize(const char* reportsDir = "MemoryReports");

    // 关闭内存追踪器
    void Shutdown();

    // Record functions potentially optimized with atomics
    void RecordAlloc(size_t size, const char* name, bool countOnly = false);
    void RecordFree(size_t size, const char* name);

    // 开始定时生成报告 (每隔period_ms毫秒生成一次)
    void StartPeriodicReporting(unsigned int period_ms = 600000); // 默认10分钟

    // 停止定时生成报告
    void StopPeriodicReporting();

    // Generates the simple text report
    void GenerateReport(const char* filename = "StormMemoryAllocation.log");

    // Generates HTML chart report for memory usage visualization
    void GenerateMemoryChartReport(const char* filename = "MemoryChart.html", bool compareWithPrevious = true);

    // 获取当前会话ID
    const std::string& GetSessionId() const { return m_sessionId; }

    // 生成报告并存储数据到历史记录
    MemoryReportData GenerateAndStoreReport(const char* filename = nullptr);

    // 从目录中加载所有历史报告数据
    bool LoadReports(const char* directory = nullptr);

    // 清除非当前会话的报告
    void CleanupOldReports();

    // 获取所有报告数据的列表
    const std::vector<MemoryReportData>& GetReportHistory() const { return m_reportHistory; }

    // 异步HTML chart report generation - 简化实现，移除std::filesystem相关依赖
    void GenerateMemoryChartReportAsync(
        const char* html_filename = "MemoryChart.html",
        const char* data_dir = "." // Directory to store json data files
    );

    // 获取当前时间字符串 - 公开此方法供其他模块使用
    std::string GetTimeString();

    // 生成唯一ID字符串
    static std::string GenerateUniqueId();

    // 创建报告目录
    bool EnsureDirectoryExists(const std::string& dirPath);

    // 生成累积时间序列数据到JSON文件
    bool GenerateTimeSeriesData(const char* jsonFilePath = "data.json");

    // 在浏览器中打开内存监控界面
    bool OpenInBrowser() const;

private:
    std::mutex m_mutex; // Protects the map structure and peak updates
    std::unordered_map<std::string, MemoryTrackRecord> m_records;
    std::atomic<bool> m_isGeneratingReport{ false }; // Prevent concurrent report generation

    // 新增字段
    std::string m_sessionId;              // 当前会话ID
    std::string m_reportsDirectory;       // 报告存储目录
    std::vector<MemoryReportData> m_reportHistory; // 报告历史记录
    std::thread m_periodicReportThread;  // 定时报告线程
    std::atomic<bool> m_stopReporting{ false }; // 停止报告标志

    // 定时报告线程函数
    void PeriodicReportThreadFunc(unsigned int period_ms);

    // Internal function executed by the background thread
    void GenerateMemoryChartReportInternal(
        std::unordered_map<std::string, MemoryTrackRecord> records_snapshot, // Pass snapshot by value
        std::string html_filename,
        std::string data_dir
    );

    // 读取现有的JSON数据文件
    std::vector<nlohmann::json> ReadExistingJsonData(const char* jsonFilePath);

    // 生成当前时间点的数据快照
    nlohmann::json GenerateCurrentDataPoint();

    // Helper to get a standardized key
    std::string GetKey(size_t size, const char* name);

    // Helper to safely update peak count (might need locking)
    void UpdatePeak(MemoryTrackRecord& record, size_t current_allocs);

    //// 生成基于Bootstrap的现代HTML报告
    //bool GenerateBootstrapHtmlReport(
    //    const char* filename,
    //    const std::unordered_map<std::string, MemoryTrackRecord>& records,
    //    bool compareWithPrevious = true
    //);

    // 解析HTML报告中的数据
    bool ParseReportData(const std::string& filePath, MemoryReportData& reportData);

    // 获取目录下的所有HTML报告文件
    std::vector<std::string> GetReportFiles(const std::string& directory);
};

// Interface functions for logging
void LogMessage(const char* format, ...);

// Global memory tracker instance
extern std::atomic<LogLevel> g_currentLogLevel;

// 全局内存追踪器实例
extern MemoryTracker g_memoryTracker;

// Logging macro
#define LOG_MESSAGE(level, format, ...) \
    if (level >= g_currentLogLevel.load(std::memory_order_relaxed)) { \
        LogMessage(format, ##__VA_ARGS__); \
    }