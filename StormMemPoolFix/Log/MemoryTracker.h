#pragma once
#include <Windows.h>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <string>
#include <future>
#include "LogSystem.h"

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
    // Record functions potentially optimized with atomics
    void RecordAlloc(size_t size, const char* name, bool countOnly = false);
    void RecordFree(size_t size, const char* name);

    // Generates the simple text report
    void GenerateReport(const char* filename = "StormMemoryAllocation.log");

    // Generates HTML chart report for memory usage visualization
    void GenerateMemoryChartReport(const char* filename = "MemoryChart.html");

    // Async HTML chart report generation - 简化实现，移除std::filesystem相关依赖
    void GenerateMemoryChartReportAsync(
        const char* html_filename = "MemoryChart.html",
        const char* data_dir = "." // Directory to store json data files
    );

    // 获取当前时间字符串 - 公开此方法供其他模块使用
    std::string GetTimeString();

private:
    std::mutex m_mutex; // Protects the map structure and peak updates
    std::unordered_map<std::string, MemoryTrackRecord> m_records;
    std::atomic<bool> m_isGeneratingReport{ false }; // Prevent concurrent report generation

    // Internal function executed by the background thread
    void GenerateMemoryChartReportInternal(
        std::unordered_map<std::string, MemoryTrackRecord> records_snapshot, // Pass snapshot by value
        std::string html_filename,
        std::string data_dir
    );

    // Helper to get a standardized key
    std::string GetKey(size_t size, const char* name);

    // Helper to safely update peak count (might need locking)
    void UpdatePeak(MemoryTrackRecord& record, size_t current_allocs);
};

// Interface functions for logging
void LogMessage(const char* format, ...);

// Global memory tracker instance
extern std::atomic<LogLevel> g_currentLogLevel;

// Logging macro
#define LOG_MESSAGE(level, format, ...) \
    if (level >= g_currentLogLevel.load(std::memory_order_relaxed)) { \
        LogMessage(format, ##__VA_ARGS__); \
    }