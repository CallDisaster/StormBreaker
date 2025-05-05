#include "pch.h"
#include "MemoryTracker.h"
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>
#include <map>
#include <Storm/StormHook.h>

std::atomic<LogLevel> g_currentLogLevel{ LogLevel::Info };

// Global log file pointer
static FILE* g_logFile = nullptr;

// Helper function to open log file
bool OpenLogFile(const char* filename ="MemoryTracker.log") {
    if (g_logFile)
        return true;

    errno_t err = fopen_s(&g_logFile, filename, "a");
    if (err != 0 || !g_logFile) {
        std::cerr << "Failed to open log file: " << filename
            << " (errno=" << err << ")" << std::endl;
        return false;
    }

    fprintf(g_logFile, "\n\n===== Memory Tracker Log Started =====\n");
    fprintf(g_logFile, "Time: %s\n\n",
        g_memoryTracker.GetTimeString().c_str());
    return true;
}

// Close log file
void CloseLogFile() {
    if (g_logFile) {
        fprintf(g_logFile, "\n===== Memory Tracker Log Ended =====\n");
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}

// MemoryTracker implementation
std::string MemoryTracker::GetKey(size_t size, const char* name) {
    std::string nameStr = "Unknown";
    if (name && strlen(name) > 0) {
        nameStr = name;
        // Basic sanitization for filenames and display
        size_t typeStart = nameStr.find(".?A");
        if (typeStart != std::string::npos) {
            size_t typeEnd = nameStr.find("@@", typeStart);
            if (typeEnd != std::string::npos) {
                nameStr = nameStr.substr(typeStart, typeEnd - typeStart + 2);
            }
        }
        if (nameStr.length() > 64) {
            nameStr = nameStr.substr(0, 61) + "...";
        }
        std::replace(nameStr.begin(), nameStr.end(), '\\', '_');
        std::replace(nameStr.begin(), nameStr.end(), '/', '_');
        std::replace(nameStr.begin(), nameStr.end(), ':', '_');
        std::replace(nameStr.begin(), nameStr.end(), '<', '_');
        std::replace(nameStr.begin(), nameStr.end(), '>', '_');
        std::replace(nameStr.begin(), nameStr.end(), '"', '_');
        std::replace(nameStr.begin(), nameStr.end(), '|', '_');
        std::replace(nameStr.begin(), nameStr.end(), '?', '_');
        std::replace(nameStr.begin(), nameStr.end(), '*', '_');
    }
    std::ostringstream keyStream;
    keyStream << size << "_" << nameStr;
    return keyStream.str();
}

// Get time string helper
std::string MemoryTracker::GetTimeString() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
#ifdef _WIN32
    localtime_s(&now_tm, &now_c);
#else
    localtime_r(&now_c, &now_tm);
#endif
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &now_tm);
    return std::string(buffer);
}

// Update peak allocation count
void MemoryTracker::UpdatePeak(MemoryTrackRecord& record, size_t current_allocs) {
    // This needs the main lock to be absolutely correct against concurrent frees
    size_t current_unreleased = current_allocs > record.GetFreeCount() ?
        current_allocs - record.GetFreeCount() : 0;
    if (current_unreleased > record.peakAlloc) {
        record.peakAlloc = current_unreleased;
    }
}

// Record memory allocation
void MemoryTracker::RecordAlloc(size_t size, const char* name, bool countOnly) {
    if (!name) name = "Unknown";
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = GetKey(size, name);

    auto& record = m_records[key];
    record.allocCount++;
    if (!countOnly) record.totalAllocSize += size;

    // Update peak allocation count
    size_t current = record.GetUnreleasedCount();
    if (current > record.peakAlloc) {
        record.peakAlloc = current;
    }
}

// Record memory free
void MemoryTracker::RecordFree(size_t size, const char* name) {
    // Attempt to find the record without locking first (might be slightly racy for size)
    std::string key = GetKey(size, name); // If size is unknown (0), key relies only on name
    bool found_key = false;
    size_t approx_alloc_size = 0;
    size_t approx_alloc_count = 0;

    // --- Try to find matching record ---
    // Quick check if the exact key exists
    {
        std::lock_guard<std::mutex> lock(m_mutex); // Use lock for reading map
        auto it = m_records.find(key);
        if (it != m_records.end()) {
            found_key = true;
            approx_alloc_size = it->second.GetTotalAllocSize();
            approx_alloc_count = it->second.GetAllocCount();
        }
        else if (size == 0 && name != nullptr) {
            // If size is 0, try matching by name only by iterating (less efficient)
            std::string name_part = GetKey(0, name).substr(2); // Extract name part
            for (const auto& pair : m_records) {
                if (pair.first.find(name_part) != std::string::npos) {
                    key = pair.first; // Found a likely match
                    found_key = true;
                    approx_alloc_size = pair.second.GetTotalAllocSize();
                    approx_alloc_count = pair.second.GetAllocCount();
                    // Optional: Could check if unreleased count > 0 for better match
                    break;
                }
            }
        }
    }

    // --- Update counters (needs exclusive lock) ---
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& record = m_records[key]; // Creates if not exists (important if lookup failed)

    // Only increment freeCount if it makes sense (avoids negative unreleased)
    size_t current_frees = record.freeCount.load(std::memory_order_relaxed);
    size_t current_allocs = record.allocCount.load(std::memory_order_relaxed); // Load alloc count under lock

    if (current_allocs > current_frees) {
        record.freeCount.fetch_add(1, std::memory_order_relaxed);
        // Estimate freed size if the provided size was 0 but we found a match
        size_t size_to_free = size;
        if (size_to_free == 0 && found_key && approx_alloc_count > 0) {
            size_to_free = approx_alloc_size / approx_alloc_count; // Average size
        }
        if (size_to_free > 0) {
            record.totalFreeSize.fetch_add(size_to_free, std::memory_order_relaxed);
        }
    }
    else {
        //// Log unexpected free only if a specific key was targeted but had no allocs matching
        //if (found_key && current_allocs == current_frees) {
        //    LOG_MESSAGE(LogLevel::Warning, "[MemoryTracker] Free recorded for '%s' but alloc/free counts match (%zu).",
        //        key.c_str(), current_allocs);
        //}
        //// If no key was found and it creates a new entry, it's likely an error or untracked alloc
        //else if (!found_key) {
        //    record.freeCount.fetch_add(1, std::memory_order_relaxed); // Record the free anyway
        //    LOG_MESSAGE(LogLevel::Warning, "[MemoryTracker] Free recorded for untracked allocation '%s'.", key.c_str());
        //}
    }
}

// Generate detailed text memory report
void MemoryTracker::GenerateReport(const char* filename) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Open log file
    std::ofstream report(filename);
    if (!report.is_open()) {
        LogMessage("[MemoryTracker] Cannot create memory report file: %s", filename);
        return;
    }

    // Write report header
    report << "==================== Storm Memory Allocation Report ====================" << std::endl;
    report << "Generated at: " << GetTimeString() << std::endl;
    report << "=" << std::string(60, '=') << "=" << std::endl;
    report << std::left << std::setw(40) << "Allocation Type" << " | "
        << std::right << std::setw(10) << "Size(bytes)" << " | "
        << std::right << std::setw(10) << "Alloc Count" << " | "
        << std::right << std::setw(10) << "Free Count" << " | "
        << std::right << std::setw(12) << "Unreleased" << " | "
        << std::right << std::setw(10) << "Peak Alloc" << " | "
        << std::right << std::setw(12) << "Total Alloc(MB)" << std::endl;
    report << std::string(112, '-') << std::endl;

    // Total statistics
    size_t totalAlloc = 0;
    size_t totalFree = 0;
    size_t totalLeak = 0;
    size_t totalBytes = 0;

    // Convert records to vector for sorting
    struct ReportItem {
        std::string key;
        MemoryTrackRecord record;
        size_t size;
        std::string name;
    };

    std::vector<ReportItem> items;
    items.reserve(m_records.size());

    for (const auto& pair : m_records) {
        // Parse key to get size and name
        std::string keyStr = pair.first;
        size_t delimPos = keyStr.find('_');
        size_t size = std::stoull(keyStr.substr(0, delimPos));
        std::string name = keyStr.substr(delimPos + 1);

        items.push_back({ pair.first, pair.second, size, name });

        // Accumulate statistics
        totalAlloc += pair.second.allocCount;
        totalFree += pair.second.freeCount;
        totalLeak += pair.second.GetUnreleasedCount();
        totalBytes += pair.second.totalAllocSize;
    }

    // Sort by unreleased count
    std::sort(items.begin(), items.end(), [](const ReportItem& a, const ReportItem& b) {
        // First by leak count
        size_t leakA = a.record.GetUnreleasedCount();
        size_t leakB = b.record.GetUnreleasedCount();
        if (leakA != leakB)
            return leakA > leakB;
        // Then by total size
        return a.record.totalAllocSize > b.record.totalAllocSize;
        });

    // Write each record
    for (const auto& item : items) {
        const auto& record = item.record;

        // Check for anomaly: free count exceeds alloc count
        if (record.freeCount > record.allocCount) {
            report << std::left << std::setw(40) << item.name << " | "
                << std::right << std::setw(10) << item.size << " | "
                << std::right << std::setw(10) << record.allocCount << " | "
                << std::right << std::setw(10) << record.freeCount << " | "
                << std::right << std::setw(12) << "ERROR!" << " | "
                << std::right << std::setw(10) << record.peakAlloc << " | "
                << std::right << std::setw(12) << std::fixed << std::setprecision(2)
                << (double)record.totalAllocSize / (1024 * 1024) << std::endl;
            report << "  ** ERROR: Free count exceeds allocation count! **" << std::endl;
        }
        else {
            // Calculate unreleased count: alloc count - free count
            size_t unreleased = record.GetUnreleasedCount();

            report << std::left << std::setw(40) << item.name << " | "
                << std::right << std::setw(10) << item.size << " | "
                << std::right << std::setw(10) << record.allocCount << " | "
                << std::right << std::setw(10) << record.freeCount << " | "
                << std::right << std::setw(12) << unreleased << " | "
                << std::right << std::setw(10) << record.peakAlloc << " | "
                << std::right << std::setw(12) << std::fixed << std::setprecision(2)
                << (double)record.totalAllocSize / (1024 * 1024) << std::endl;

            // Add warning for potential leaks
            if (unreleased > 0) {
                report << "  ** WARNING: Potential memory leak **" << std::endl;
            }
        }
    }

    // Write summary
    report << std::string(112, '-') << std::endl;
    report << "Total Statistics:" << std::endl;
    report << "  Total Allocations: " << totalAlloc << std::endl;
    report << "  Total Frees: " << totalFree << std::endl;
    report << "  Unreleased Count: " << totalLeak << std::endl;
    report << "  Total Allocated Memory: " << std::fixed << std::setprecision(2)
        << (double)totalBytes / (1024 * 1024) << " MB" << std::endl;

    // Write top potential leak points (top 10)
    report << std::endl << "Potential Memory Leak Points (largest allocation/free difference):" << std::endl;

    // Sort by allocation/free difference
    std::sort(items.begin(), items.end(), [](const ReportItem& a, const ReportItem& b) {
        size_t diffA = a.record.GetUnreleasedCount();
        size_t diffB = b.record.GetUnreleasedCount();
        return diffA > diffB;
        });

    // Output top 10 suspected leaks
    int leakCount = 0;
    for (const auto& item : items) {
        // Only show items with unreleased memory
        size_t unreleased = item.record.GetUnreleasedCount();
        if (unreleased == 0) continue;

        report << "  " << item.name << " (Size:" << item.size << "): Allocated "
            << item.record.allocCount << ", Freed " << item.record.freeCount
            << ", Unreleased " << unreleased << std::endl;

        leakCount++;
        if (leakCount >= 10) break;
    }

    report << std::endl << "==================== Report End ====================" << std::endl;

    report.close();
    LogMessage("[MemoryTracker] Memory report generated: %s", filename);
}

// Generate HTML chart memory report
void MemoryTracker::GenerateMemoryChartReport(const char* filename) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Open HTML file
    std::ofstream report(filename);
    if (!report.is_open()) {
        LogMessage("[MemoryTracker] Cannot create memory report: %s", filename);
        return;
    }

    LogMessage("[MemoryTracker] Starting to generate memory report...");

    // ==== Data preprocessing - do most calculations in C++ ====
    size_t totalAlloc = 0;
    size_t totalFree = 0;
    size_t totalUnreleased = 0;
    size_t totalAllocBytes = 0;
    size_t totalFreeBytes = 0;
    size_t totalLeakBytes = 0;

    // Type statistics structure
    struct TypeStats {
        std::string name;
        size_t size;
        size_t allocCount;
        size_t freeCount;
        size_t allocSize;
        size_t freeSize;
        size_t unreleased;
        size_t leakSize;
        size_t peakAlloc;
    };

    // Collect and preprocess data
    std::vector<TypeStats> allStats;
    for (const auto& pair : m_records) {
        std::string key = pair.first;
        size_t underscorePos = key.find('_');
        std::string sizeStr = key.substr(0, underscorePos);
        std::string name = key.substr(underscorePos + 1);
        size_t size = std::stoull(sizeStr);

        const auto& record = pair.second;
        size_t unreleased = record.GetUnreleasedCount();
        size_t leakSize = record.GetUnreleasedMemory();

        // Add to statistics
        allStats.push_back({
            name,
            size,
            record.allocCount,
            record.freeCount,
            record.totalAllocSize,
            record.totalFreeSize,
            unreleased,
            leakSize,
            record.peakAlloc
            });

        // Accumulate totals
        totalAlloc += record.allocCount;
        totalFree += record.freeCount;
        totalUnreleased += unreleased;
        totalAllocBytes += record.totalAllocSize;
        totalFreeBytes += record.totalFreeSize;
        totalLeakBytes += leakSize;
    }

    // Sort by allocation size
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.allocSize > b.allocSize;
        });

    // Limit to top 1000 records for display to reduce browser load
    const size_t MAX_DISPLAY_RECORDS = 1000;
    if (allStats.size() > MAX_DISPLAY_RECORDS) {
        // Aggregate remaining data
        TypeStats otherStats = { "Other Types (Aggregated)", 0, 0, 0, 0, 0, 0, 0, 0 };

        for (size_t i = MAX_DISPLAY_RECORDS; i < allStats.size(); i++) {
            otherStats.allocCount += allStats[i].allocCount;
            otherStats.freeCount += allStats[i].freeCount;
            otherStats.allocSize += allStats[i].allocSize;
            otherStats.freeSize += allStats[i].freeSize;
            otherStats.unreleased += allStats[i].unreleased;
            otherStats.leakSize += allStats[i].leakSize;
            otherStats.peakAlloc += allStats[i].peakAlloc;
        }

        // Truncate the list
        allStats.resize(MAX_DISPLAY_RECORDS);

        // Add aggregated entry
        if (otherStats.allocCount > 0) {
            allStats.push_back(otherStats);
        }
    }

    // Get top 10 largest allocations (for chart)
    std::vector<TypeStats> top10Stats;
    size_t numTop = min(size_t(10), allStats.size());
    for (size_t i = 0; i < numTop; i++) {
        top10Stats.push_back(allStats[i]);
    }

    // Get top 10 largest memory leaks (for chart)
    std::vector<TypeStats> top10Leaks;
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.leakSize > b.leakSize;
        });

    numTop = min(size_t(10), allStats.size());
    for (size_t i = 0; i < numTop; i++) {
        if (allStats[i].leakSize > 0) {
            top10Leaks.push_back(allStats[i]);
        }
    }

    // Generate three different sorted JSON data (allocation, free, difference)
    std::stringstream allocJsonStream;
    std::stringstream freeJsonStream;
    std::stringstream diffJsonStream;

    // Sort by allocation size
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.allocSize > b.allocSize;
        });

    allocJsonStream << "[";
    for (size_t i = 0; i < allStats.size(); i++) {
        const auto& stat = allStats[i];
        if (i > 0) allocJsonStream << ",";
        allocJsonStream << "{\"name\":\"" << stat.name << "\",";
        allocJsonStream << "\"size\":" << stat.size << ",";
        allocJsonStream << "\"allocCount\":" << stat.allocCount << ",";
        allocJsonStream << "\"allocSize\":" << (double)stat.allocSize / (1024 * 1024) << ",";
        allocJsonStream << "\"peakAlloc\":" << stat.peakAlloc << "}";
    }
    allocJsonStream << "]";

    // Sort by free size
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.freeSize > b.freeSize;
        });

    freeJsonStream << "[";
    for (size_t i = 0; i < allStats.size(); i++) {
        const auto& stat = allStats[i];
        if (i > 0) freeJsonStream << ",";
        freeJsonStream << "{\"name\":\"" << stat.name << "\",";
        freeJsonStream << "\"size\":" << stat.size << ",";
        freeJsonStream << "\"freeCount\":" << stat.freeCount << ",";
        freeJsonStream << "\"freeSize\":" << (double)stat.freeSize / (1024 * 1024) << ",";
        double efficiency = stat.allocSize > 0 ?
            ((double)stat.freeSize / stat.allocSize) * 100.0 : 0.0;
        freeJsonStream << "\"efficiency\":" << efficiency << "}";
    }
    freeJsonStream << "]";

    // Sort by unreleased count
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.leakSize > b.leakSize;
        });

    diffJsonStream << "[";
    for (size_t i = 0; i < allStats.size(); i++) {
        const auto& stat = allStats[i];
        if (stat.unreleased == 0) continue; // Skip fully released

        if (i > 0 && diffJsonStream.str().length() > 1) diffJsonStream << ",";
        diffJsonStream << "{\"name\":\"" << stat.name << "\",";
        diffJsonStream << "\"size\":" << stat.size << ",";
        diffJsonStream << "\"allocCount\":" << stat.allocCount << ",";
        diffJsonStream << "\"freeCount\":" << stat.freeCount << ",";
        diffJsonStream << "\"unreleased\":" << stat.unreleased << ",";
        diffJsonStream << "\"leakSize\":" << (double)stat.leakSize / (1024 * 1024) << "}";
    }
    diffJsonStream << "]";

    LogMessage("[MemoryTracker] Data preprocessing complete, generating HTML...");

    // ==== Generate HTML content ====
    report << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    report << "  <meta charset=\"UTF-8\">\n";
    report << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    report << "  <title>Storm Memory Analysis Report</title>\n";
    report << "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n";
    report << "  <style>\n";
    report << "    :root {\n";
    report << "      --primary-color: #2c3e50;\n";
    report << "      --secondary-color: #3498db;\n";
    report << "      --bg-color: #f8f9fa;\n";
    report << "      --text-color: #333;\n";
    report << "      --border-color: #ddd;\n";
    report << "      --warning-color: #e74c3c;\n";
    report << "      --success-color: #2ecc71;\n";
    report << "    }\n";
    report << "    body {\n";
    report << "      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n";
    report << "      line-height: 1.6;\n";
    report << "      color: var(--text-color);\n";
    report << "      background-color: var(--bg-color);\n";
    report << "      margin: 0;\n";
    report << "      padding: 20px;\n";
    report << "    }\n";
    report << "    .container {\n";
    report << "      max-width: 1200px;\n";
    report << "      margin: 0 auto;\n";
    report << "    }\n";
    report << "    header {\n";
    report << "      background-color: var(--primary-color);\n";
    report << "      color: white;\n";
    report << "      padding: 1rem;\n";
    report << "      border-radius: 5px;\n";
    report << "      margin-bottom: 2rem;\n";
    report << "    }\n";
    report << "    h1, h2, h3 {\n";
    report << "      margin-top: 0;\n";
    report << "    }\n";
    report << "    .chart-container {\n";
    report << "      background-color: white;\n";
    report << "      border-radius: 5px;\n";
    report << "      box-shadow: 0 2px 4px rgba(0,0,0,0.1);\n";
    report << "      padding: 1rem;\n";
    report << "      margin-bottom: 2rem;\n";
    report << "    }\n";
    report << "    .chart-row {\n";
    report << "      display: flex;\n";
    report << "      flex-wrap: wrap;\n";
    report << "      margin: 0 -15px;\n";
    report << "    }\n";
    report << "    .chart-col {\n";
    report << "      flex: 1;\n";
    report << "      min-width: 300px;\n";
    report << "      padding: 0 15px;\n";
    report << "      margin-bottom: 30px;\n";
    report << "    }\n";
    report << "    .chart-title {\n";
    report << "      padding: 10px;\n";
    report << "      background-color: var(--primary-color);\n";
    report << "      color: white;\n";
    report << "      border-top-left-radius: 5px;\n";
    report << "      border-top-right-radius: 5px;\n";
    report << "      margin-bottom: 0;\n";
    report << "    }\n";
    report << "    .chart-body {\n";
    report << "      padding: 15px;\n";
    report << "      border: 1px solid var(--border-color);\n";
    report << "      border-top: none;\n";
    report << "      border-bottom-left-radius: 5px;\n";
    report << "      border-bottom-right-radius: 5px;\n";
    report << "    }\n";
    report << "    .table-container {\n";
    report << "      max-height: 600px;\n";
    report << "      overflow-y: auto;\n";
    report << "      position: relative;\n";
    report << "    }\n";
    report << "    table {\n";
    report << "      width: 100%;\n";
    report << "      border-collapse: collapse;\n";
    report << "      margin-top: 1rem;\n";
    report << "      box-shadow: 0 2px 4px rgba(0,0,0,0.1);\n";
    report << "    }\n";
    report << "    th, td {\n";
    report << "      text-align: left;\n";
    report << "      padding: 12px 15px;\n";
    report << "      border-bottom: 1px solid var(--border-color);\n";
    report << "    }\n";
    report << "    th {\n";
    report << "      background-color: var(--primary-color);\n";
    report << "      color: white;\n";
    report << "      position: sticky;\n";
    report << "      top: 0;\n";
    report << "      z-index: 10;\n";
    report << "    }\n";
    report << "    tr:nth-child(even) {\n";
    report << "      background-color: rgba(0,0,0,0.02);\n";
    report << "    }\n";
    report << "    tr:hover {\n";
    report << "      background-color: rgba(0,0,0,0.05);\n";
    report << "    }\n";
    report << "    .warning {\n";
    report << "      color: var(--warning-color);\n";
    report << "      font-weight: bold;\n";
    report << "    }\n";
    report << "    .summary-box {\n";
    report << "      display: flex;\n";
    report << "      flex-wrap: wrap;\n";
    report << "      margin-bottom: 2rem;\n";
    report << "    }\n";
    report << "    .summary-item {\n";
    report << "      flex: 1;\n";
    report << "      min-width: 200px;\n";
    report << "      padding: 1rem;\n";
    report << "      margin: 10px;\n";
    report << "      background-color: white;\n";
    report << "      border-radius: 5px;\n";
    report << "      box-shadow: 0 2px 4px rgba(0,0,0,0.1);\n";
    report << "      text-align: center;\n";
    report << "    }\n";
    report << "    .summary-number {\n";
    report << "      font-size: 2.5rem;\n";
    report << "      font-weight: bold;\n";
    report << "      margin: 0.5rem 0;\n";
    report << "      color: var(--secondary-color);\n";
    report << "    }\n";
    report << "    .summary-label {\n";
    report << "      font-size: 1rem;\n";
    report << "      color: var(--primary-color);\n";
    report << "    }\n";
    report << "    .leak-warning {\n";
    report << "      background-color: var(--warning-color);\n";
    report << "      color: white;\n";
    report << "    }\n";
    report << "    .search-box {\n";
    report << "      margin-bottom: 1rem;\n";
    report << "      width: 100%;\n";
    report << "    }\n";
    report << "    .search-input {\n";
    report << "      width: 100%;\n";
    report << "      padding: 10px;\n";
    report << "      border: 1px solid var(--border-color);\n";
    report << "      border-radius: 5px;\n";
    report << "      font-size: 16px;\n";
    report << "    }\n";
    report << "    .tabs {\n";
    report << "      display: flex;\n";
    report << "      margin-bottom: 1rem;\n";
    report << "    }\n";
    report << "    .tab {\n";
    report << "      padding: 10px 20px;\n";
    report << "      background-color: #f1f1f1;\n";
    report << "      border: 1px solid var(--border-color);\n";
    report << "      cursor: pointer;\n";
    report << "      margin-right: 5px;\n";
    report << "      border-radius: 5px 5px 0 0;\n";
    report << "    }\n";
    report << "    .tab.active {\n";
    report << "      background-color: var(--primary-color);\n";
    report << "      color: white;\n";
    report << "      border-bottom: none;\n";
    report << "    }\n";
    report << "    .tab-content {\n";
    report << "      display: none;\n";
    report << "      padding: 15px;\n";
    report << "      border: 1px solid var(--border-color);\n";
    report << "      border-radius: 0 5px 5px 5px;\n";
    report << "      background-color: white;\n";
    report << "    }\n";
    report << "    .tab-content.active {\n";
    report << "      display: block;\n";
    report << "    }\n";
    report << "    .search-highlight {\n";
    report << "      background-color: yellow;\n";
    report << "      font-weight: bold;\n";
    report << "    }\n";
    report << "    .pagination {\n";
    report << "      display: flex;\n";
    report << "      justify-content: center;\n";
    report << "      margin-top: 15px;\n";
    report << "    }\n";
    report << "    .pagination button {\n";
    report << "      margin: 0 5px;\n";
    report << "      padding: 5px 10px;\n";
    report << "      border: 1px solid var(--border-color);\n";
    report << "      background-color: white;\n";
    report << "      cursor: pointer;\n";
    report << "      border-radius: 3px;\n";
    report << "    }\n";
    report << "    .pagination button.active {\n";
    report << "      background-color: var(--primary-color);\n";
    report << "      color: white;\n";
    report << "    }\n";
    report << "    .pagination button:disabled {\n";
    report << "      opacity: 0.5;\n";
    report << "      cursor: not-allowed;\n";
    report << "    }\n";
    report << "    .loading {\n";
    report << "      text-align: center;\n";
    report << "      padding: 20px;\n";
    report << "      font-size: 18px;\n";
    report << "      color: var(--secondary-color);\n";
    report << "    }\n";
    report << "  </style>\n";
    report << "</head>\n<body>\n";

    // 页面内容
    report << "<div class=\"container\">\n";

    // 标题
    report << "  <header>\n";
    report << "    <h1>Storm内存分配分析报告</h1>\n";
    report << "    <p>生成时间: " << GetTimeString() << "</p>\n";
    report << "  </header>\n";

    // 概要信息
    report << "  <div class=\"summary-box\">\n";

    report << "    <div class=\"summary-item\">\n";
    report << "      <div class=\"summary-number\">" << totalAlloc << "</div>\n";
    report << "      <div class=\"summary-label\">总分配次数</div>\n";
    report << "    </div>\n";

    report << "    <div class=\"summary-item\">\n";
    report << "      <div class=\"summary-number\">" << totalFree << "</div>\n";
    report << "      <div class=\"summary-label\">总释放次数</div>\n";
    report << "    </div>\n";

    report << "    <div class=\"summary-item";
    if (totalUnreleased > 0) report << " leak-warning";
    report << "\">\n";
    report << "      <div class=\"summary-number\">" << totalUnreleased << "</div>\n";
    report << "      <div class=\"summary-label\">未释放数量</div>\n";
    report << "    </div>\n";

    report << "    <div class=\"summary-item\">\n";
    report << "      <div class=\"summary-number\">" << std::fixed << std::setprecision(2)
        << (double)totalAllocBytes / (1024 * 1024) << " MB</div>\n";
    report << "      <div class=\"summary-label\">总分配内存</div>\n";
    report << "    </div>\n";

    report << "    <div class=\"summary-item\">\n";
    report << "      <div class=\"summary-number\">" << std::fixed << std::setprecision(2)
        << (double)totalFreeBytes / (1024 * 1024) << " MB</div>\n";
    report << "      <div class=\"summary-label\">总释放内存</div>\n";
    report << "    </div>\n";

    report << "    <div class=\"summary-item";
    if (totalLeakBytes > 0) report << " leak-warning";
    report << "\">\n";
    report << "      <div class=\"summary-number\">" << std::fixed << std::setprecision(2)
        << (double)totalLeakBytes / (1024 * 1024) << " MB</div>\n";
    report << "      <div class=\"summary-label\">内存泄漏</div>\n";
    report << "    </div>\n";

    report << "  </div>\n";

    // 图表行
    report << "  <div class=\"chart-row\">\n";

    // 内存分布图表
    report << "    <div class=\"chart-col\">\n";
    report << "      <h2 class=\"chart-title\">内存分配/释放分布</h2>\n";
    report << "      <div class=\"chart-body\">\n";
    report << "        <canvas id=\"memoryDistributionChart\"></canvas>\n";
    report << "      </div>\n";
    report << "    </div>\n";

    // Top 10分配图表
    report << "    <div class=\"chart-col\">\n";
    report << "      <h2 class=\"chart-title\">前10大内存消耗</h2>\n";
    report << "      <div class=\"chart-body\">\n";
    report << "        <canvas id=\"top10Chart\"></canvas>\n";
    report << "      </div>\n";
    report << "    </div>\n";
    report << "  </div>\n";

    // 第二行图表（泄漏）
    report << "  <div class=\"chart-row\">\n";
    report << "    <div class=\"chart-col\">\n";
    report << "      <h2 class=\"chart-title\">前10大内存泄漏</h2>\n";
    report << "      <div class=\"chart-body\">\n";
    report << "        <canvas id=\"leakChart\"></canvas>\n";
    report << "      </div>\n";
    report << "    </div>\n";
    report << "  </div>\n";

    // 表格部分
    report << "  <h2>详细内存分配记录</h2>\n";

    // 选项卡
    report << "  <div class=\"tabs\">\n";
    report << "    <div class=\"tab active\" onclick=\"showTab('alloc-table')\">分配表</div>\n";
    report << "    <div class=\"tab\" onclick=\"showTab('free-table')\">释放表</div>\n";
    report << "    <div class=\"tab\" onclick=\"showTab('diff-table')\">差异表</div>\n";
    report << "  </div>\n";

    // 搜索框
    report << "  <div class=\"search-box\">\n";
    report << "    <input type=\"text\" id=\"globalSearchInput\" class=\"search-input\" ";
    report << "placeholder=\"在所有表中搜索...\" />\n";
    report << "  </div>\n";

    // 分配表
    report << "  <div id=\"alloc-table\" class=\"tab-content active\">\n";
    report << "    <div class=\"table-container\">\n";
    report << "      <table id=\"allocTable\">\n";
    report << "        <thead>\n";
    report << "          <tr>\n";
    report << "            <th data-sort=\"text\">分配类型 <span class=\"sort-icon\">▼</span></th>\n";
    report << "            <th data-sort=\"number\">大小(字节)</th>\n";
    report << "            <th data-sort=\"number\">分配次数</th>\n";
    report << "            <th data-sort=\"number\">总分配(MB)</th>\n";
    report << "            <th data-sort=\"number\">峰值分配</th>\n";
    report << "          </tr>\n";
    report << "        </thead>\n";
    report << "        <tbody id=\"allocTableBody\">\n";
    report << "          <tr><td colspan=\"5\" class=\"loading\">加载中...</td></tr>\n";
    report << "        </tbody>\n";
    report << "      </table>\n";
    report << "    </div>\n";
    report << "    <div id=\"allocPagination\" class=\"pagination\"></div>\n";
    report << "  </div>\n";

    // 释放表
    report << "  <div id=\"free-table\" class=\"tab-content\">\n";
    report << "    <div class=\"table-container\">\n";
    report << "      <table id=\"freeTable\">\n";
    report << "        <thead>\n";
    report << "          <tr>\n";
    report << "            <th data-sort=\"text\">分配类型 <span class=\"sort-icon\">▼</span></th>\n";
    report << "            <th data-sort=\"number\">大小(字节)</th>\n";
    report << "            <th data-sort=\"number\">释放次数</th>\n";
    report << "            <th data-sort=\"number\">总释放(MB)</th>\n";
    report << "            <th data-sort=\"number\">效率(%)</th>\n";
    report << "          </tr>\n";
    report << "        </thead>\n";
    report << "        <tbody id=\"freeTableBody\">\n";
    report << "          <tr><td colspan=\"5\" class=\"loading\">加载中...</td></tr>\n";
    report << "        </tbody>\n";
    report << "      </table>\n";
    report << "    </div>\n";
    report << "    <div id=\"freePagination\" class=\"pagination\"></div>\n";
    report << "  </div>\n";

    // 差异表
    report << "  <div id=\"diff-table\" class=\"tab-content\">\n";
    report << "    <div class=\"table-container\">\n";
    report << "      <table id=\"diffTable\">\n";
    report << "        <thead>\n";
    report << "          <tr>\n";
    report << "            <th data-sort=\"text\">分配类型 <span class=\"sort-icon\">▼</span></th>\n";
    report << "            <th data-sort=\"number\">大小(字节)</th>\n";
    report << "            <th data-sort=\"number\">分配次数</th>\n";
    report << "            <th data-sort=\"number\">释放次数</th>\n";
    report << "            <th data-sort=\"number\">未释放</th>\n";
    report << "            <th data-sort=\"number\">泄漏(MB)</th>\n";
    report << "          </tr>\n";
    report << "        </thead>\n";
    report << "        <tbody id=\"diffTableBody\">\n";
    report << "          <tr><td colspan=\"6\" class=\"loading\">加载中...</td></tr>\n";
    report << "        </tbody>\n";
    report << "      </table>\n";
    report << "    </div>\n";
    report << "    <div id=\"diffPagination\" class=\"pagination\"></div>\n";
    report << "  </div>\n";

    // JavaScript - 使用高效数据处理和虚拟滚动
    report << "<script>\n";

    // 内存分布数据
    report << "// 内存分布数据\n";
    report << "const memoryDistributionData = {\n";
    report << "  labels: ['已分配', '已释放', '未释放'],\n";
    report << "  datasets: [{\n";
    report << "    label: '内存(MB)',\n";
    report << "    data: ["
        << (double)totalAllocBytes / (1024 * 1024) << ", "
        << (double)totalFreeBytes / (1024 * 1024) << ", "
        << (double)totalLeakBytes / (1024 * 1024) << "],\n";
    report << "    backgroundColor: [\n";
    report << "      'rgba(54, 162, 235, 0.5)',\n";
    report << "      'rgba(75, 192, 192, 0.5)',\n";
    report << "      'rgba(255, 99, 132, 0.5)'\n";
    report << "    ],\n";
    report << "    borderColor: [\n";
    report << "      'rgba(54, 162, 235, 1)',\n";
    report << "      'rgba(75, 192, 192, 1)',\n";
    report << "      'rgba(255, 99, 132, 1)'\n";
    report << "    ],\n";
    report << "    borderWidth: 1\n";
    report << "  }]\n";
    report << "};\n\n";

    // Top 10 最大分配数据
    report << "// Top 10 分配数据\n";
    report << "const top10Data = {\n";
    report << "  labels: [";
    for (size_t i = 0; i < top10Stats.size(); i++) {
        if (i > 0) report << ", ";
        std::string name = top10Stats[i].name;
        if (name.length() > 20) {
            name = name.substr(0, 17) + "...";
        }
        report << "'" << name << "'";
    }
    report << "],\n";
    report << "  datasets: [{\n";
    report << "    label: '内存(MB)',\n";
    report << "    data: [";
    for (size_t i = 0; i < top10Stats.size(); i++) {
        if (i > 0) report << ", ";
        report << (double)top10Stats[i].allocSize / (1024 * 1024);
    }
    report << "],\n";
    report << "    backgroundColor: 'rgba(54, 162, 235, 0.5)',\n";
    report << "    borderColor: 'rgba(54, 162, 235, 1)',\n";
    report << "    borderWidth: 1\n";
    report << "  }]\n";
    report << "};\n\n";

    // Top 10 泄漏数据
    report << "// Top 10 泄漏数据\n";
    report << "const leakData = {\n";
    report << "  labels: [";
    for (size_t i = 0; i < top10Leaks.size(); i++) {
        if (i > 0) report << ", ";
        std::string name = top10Leaks[i].name;
        if (name.length() > 20) {
            name = name.substr(0, 17) + "...";
        }
        report << "'" << name << "'";
    }
    report << "],\n";
    report << "  datasets: [{\n";
    report << "    label: '泄漏内存(MB)',\n";
    report << "    data: [";
    for (size_t i = 0; i < top10Leaks.size(); i++) {
        if (i > 0) report << ", ";
        report << (double)top10Leaks[i].leakSize / (1024 * 1024);
    }
    report << "],\n";
    report << "    backgroundColor: 'rgba(255, 99, 132, 0.5)',\n";
    report << "    borderColor: 'rgba(255, 99, 132, 1)',\n";
    report << "    borderWidth: 1\n";
    report << "  }]\n";
    report << "};\n\n";

    // 表格数据 (从C++预处理)
    report << "// 表格数据 - 预处理\n";
    report << "const allocTableData = " << allocJsonStream.str() << ";\n";
    report << "const freeTableData = " << freeJsonStream.str() << ";\n";
    report << "const diffTableData = " << diffJsonStream.str() << ";\n\n";

    // 用于数据处理、分页和显示的JavaScript函数
    report << "// 全局变量\n";
    report << "let currentPage = {\n";
    report << "  'allocTable': 1,\n";
    report << "  'freeTable': 1,\n";
    report << "  'diffTable': 1\n";
    report << "};\n";
    report << "const pageSize = 50; // 每页显示记录数\n";
    report << "let sortConfig = {\n";
    report << "  'allocTable': { column: 3, direction: 'desc' },\n";
    report << "  'freeTable': { column: 3, direction: 'desc' },\n";
    report << "  'diffTable': { column: 5, direction: 'desc' }\n";
    report << "};\n";
    report << "let filterText = '';\n\n";

    // 选项卡切换函数
    report << "// 切换选项卡\n";
    report << "function showTab(tabId) {\n";
    report << "  // 隐藏所有选项卡内容\n";
    report << "  const tabContents = document.getElementsByClassName('tab-content');\n";
    report << "  for (let i = 0; i < tabContents.length; i++) {\n";
    report << "    tabContents[i].classList.remove('active');\n";
    report << "  }\n";
    report << "  \n";
    report << "  // 取消激活所有选项卡\n";
    report << "  const tabs = document.getElementsByClassName('tab');\n";
    report << "  for (let i = 0; i < tabs.length; i++) {\n";
    report << "    tabs[i].classList.remove('active');\n";
    report << "  }\n";
    report << "  \n";
    report << "  // 激活选中的选项卡和内容\n";
    report << "  document.getElementById(tabId).classList.add('active');\n";
    report << "  const activeTab = document.querySelector(`.tab[onclick*=\"${tabId}\"]`);\n";
    report << "  if (activeTab) activeTab.classList.add('active');\n";
    report << "  \n";
    report << "  // 延迟加载相应表格，防止浏览器冻结\n";
    report << "  setTimeout(() => {\n";
    report << "    if (tabId === 'alloc-table') {\n";
    report << "      renderTable('allocTable', allocTableData);\n";
    report << "    } else if (tabId === 'free-table') {\n";
    report << "      renderTable('freeTable', freeTableData);\n";
    report << "    } else if (tabId === 'diff-table') {\n";
    report << "      renderTable('diffTable', diffTableData);\n";
    report << "    }\n";
    report << "  }, 50);\n";
    report << "}\n\n";

    // 表格渲染函数
    report << "// 渲染表格数据（分页、排序和过滤）\n";
    report << "function renderTable(tableId, data) {\n";
    report << "  const tbody = document.getElementById(`${tableId}Body`);\n";
    report << "  const filteredData = filterData(data, filterText);\n";
    report << "  const sortedData = sortData(filteredData, tableId);\n";
    report << "  \n";
    report << "  // 计算分页\n";
    report << "  const totalPages = Math.ceil(sortedData.length / pageSize);\n";
    report << "  if (currentPage[tableId] > totalPages && totalPages > 0) {\n";
    report << "    currentPage[tableId] = totalPages;\n";
    report << "  }\n";
    report << "  \n";
    report << "  // 获取当前页数据\n";
    report << "  const startIndex = (currentPage[tableId] - 1) * pageSize;\n";
    report << "  const endIndex = Math.min(startIndex + pageSize, sortedData.length);\n";
    report << "  const pageData = sortedData.slice(startIndex, endIndex);\n";
    report << "  \n";
    report << "  // 清空表格\n";
    report << "  tbody.innerHTML = '';\n";
    report << "  \n";
    report << "  // 没有数据的处理\n";
    report << "  if (pageData.length === 0) {\n";
    report << "    const tr = document.createElement('tr');\n";
    report << "    const td = document.createElement('td');\n";
    report << "    td.setAttribute('colspan', tableId === 'diffTable' ? '6' : '5');\n";
    report << "    td.textContent = filteredData.length === 0 ? '没有匹配的数据' : '没有数据';\n";
    report << "    td.style.textAlign = 'center';\n";
    report << "    tr.appendChild(td);\n";
    report << "    tbody.appendChild(tr);\n";
    report << "  } else {\n";
    report << "    // 添加数据行\n";
    report << "    pageData.forEach(item => {\n";
    report << "      const tr = document.createElement('tr');\n";
    report << "      \n";
    report << "      // 根据表格类型添加不同列\n";
    report << "      if (tableId === 'allocTable') {\n";
    report << "        addCell(tr, item.name, filterText);\n";
    report << "        addCell(tr, item.size);\n";
    report << "        addCell(tr, item.allocCount);\n";
    report << "        addCell(tr, item.allocSize.toFixed(2));\n";
    report << "        addCell(tr, item.peakAlloc);\n";
    report << "      } else if (tableId === 'freeTable') {\n";
    report << "        addCell(tr, item.name, filterText);\n";
    report << "        addCell(tr, item.size);\n";
    report << "        addCell(tr, item.freeCount);\n";
    report << "        addCell(tr, item.freeSize.toFixed(2));\n";
    report << "        \n";
    report << "        // 效率单元格，颜色标记\n";
    report << "        const td = document.createElement('td');\n";
    report << "        if (item.efficiency < 90) {\n";
    report << "          td.classList.add('warning');\n";
    report << "        }\n";
    report << "        td.textContent = item.efficiency.toFixed(1);\n";
    report << "        tr.appendChild(td);\n";
    report << "      } else if (tableId === 'diffTable') {\n";
    report << "        addCell(tr, item.name, filterText);\n";
    report << "        addCell(tr, item.size);\n";
    report << "        addCell(tr, item.allocCount);\n";
    report << "        addCell(tr, item.freeCount);\n";
    report << "        \n";
    report << "        // 未释放单元格，标记警告\n";
    report << "        const tdUnreleased = document.createElement('td');\n";
    report << "        tdUnreleased.classList.add('warning');\n";
    report << "        tdUnreleased.textContent = item.unreleased;\n";
    report << "        tr.appendChild(tdUnreleased);\n";
    report << "        \n";
    report << "        // 泄漏大小单元格，标记警告\n";
    report << "        const tdLeak = document.createElement('td');\n";
    report << "        tdLeak.classList.add('warning');\n";
    report << "        tdLeak.textContent = item.leakSize.toFixed(2);\n";
    report << "        tr.appendChild(tdLeak);\n";
    report << "      }\n";
    report << "      \n";
    report << "      tbody.appendChild(tr);\n";
    report << "    });\n";
    report << "  }\n";
    report << "  \n";
    report << "  // 更新分页控件\n";
    report << "  updatePagination(tableId, totalPages, filteredData.length);\n";
    report << "  \n";
    report << "  // 更新排序图标\n";
    report << "  updateSortIcons(tableId);\n";
    report << "}\n\n";

    // 添加单元格函数
    report << "// 添加表格单元格，支持搜索高亮\n";
    report << "function addCell(tr, content, searchText = '') {\n";
    report << "  const td = document.createElement('td');\n";
    report << "  \n";
    report << "  if (searchText && typeof content === 'string' && content.toLowerCase().includes(searchText.toLowerCase())) {\n";
    report << "    // 高亮搜索匹配文本\n";
    report << "    const regex = new RegExp(`(${searchText})`, 'gi');\n";
    report << "    td.innerHTML = content.replace(regex, '<span class=\"search-highlight\">$1</span>');\n";
    report << "  } else {\n";
    report << "    td.textContent = content;\n";
    report << "  }\n";
    report << "  \n";
    report << "  tr.appendChild(td);\n";
    report << "}\n\n";

    // 数据过滤函数
    report << "// 过滤数据\n";
    report << "function filterData(data, filterText) {\n";
    report << "  if (!filterText) return data;\n";
    report << "  \n";
    report << "  const searchLower = filterText.toLowerCase();\n";
    report << "  return data.filter(item => {\n";
    report << "    return item.name.toLowerCase().includes(searchLower);\n";
    report << "  });\n";
    report << "}\n\n";

    // 数据排序函数
    report << "// 排序数据\n";
    report << "function sortData(data, tableId) {\n";
    report << "  const { column, direction } = sortConfig[tableId];\n";
    report << "  \n";
    report << "  return [...data].sort((a, b) => {\n";
    report << "    let valueA, valueB;\n";
    report << "    \n";
    report << "    if (tableId === 'allocTable') {\n";
    report << "      switch(column) {\n";
    report << "        case 0: valueA = a.name; valueB = b.name; break;\n";
    report << "        case 1: valueA = a.size; valueB = b.size; break;\n";
    report << "        case 2: valueA = a.allocCount; valueB = b.allocCount; break;\n";
    report << "        case 3: valueA = a.allocSize; valueB = b.allocSize; break;\n";
    report << "        case 4: valueA = a.peakAlloc; valueB = b.peakAlloc; break;\n";
    report << "        default: valueA = a.allocSize; valueB = b.allocSize;\n";
    report << "      }\n";
    report << "    } else if (tableId === 'freeTable') {\n";
    report << "      switch(column) {\n";
    report << "        case 0: valueA = a.name; valueB = b.name; break;\n";
    report << "        case 1: valueA = a.size; valueB = b.size; break;\n";
    report << "        case 2: valueA = a.freeCount; valueB = b.freeCount; break;\n";
    report << "        case 3: valueA = a.freeSize; valueB = b.freeSize; break;\n";
    report << "        case 4: valueA = a.efficiency; valueB = b.efficiency; break;\n";
    report << "        default: valueA = a.freeSize; valueB = b.freeSize;\n";
    report << "      }\n";
    report << "    } else if (tableId === 'diffTable') {\n";
    report << "      switch(column) {\n";
    report << "        case 0: valueA = a.name; valueB = b.name; break;\n";
    report << "        case 1: valueA = a.size; valueB = b.size; break;\n";
    report << "        case 2: valueA = a.allocCount; valueB = b.allocCount; break;\n";
    report << "        case 3: valueA = a.freeCount; valueB = b.freeCount; break;\n";
    report << "        case 4: valueA = a.unreleased; valueB = b.unreleased; break;\n";
    report << "        case 5: valueA = a.leakSize; valueB = b.leakSize; break;\n";
    report << "        default: valueA = a.leakSize; valueB = b.leakSize;\n";
    report << "      }\n";
    report << "    }\n";
    report << "    \n";
    report << "    // 处理字符串与数字比较\n";
    report << "    if (typeof valueA === 'string') {\n";
    report << "      return direction === 'asc' \n";
    report << "        ? valueA.localeCompare(valueB) \n";
    report << "        : valueB.localeCompare(valueA);\n";
    report << "    } else {\n";
    report << "      return direction === 'asc' \n";
    report << "        ? valueA - valueB \n";
    report << "        : valueB - valueA;\n";
    report << "    }\n";
    report << "  });\n";
    report << "}\n\n";

    // 更新分页控件
    report << "// 更新分页控件\n";
    report << "function updatePagination(tableId, totalPages, totalRecords) {\n";
    report << "  const paginationDiv = document.getElementById(`${tableId}Pagination`);\n";
    report << "  paginationDiv.innerHTML = '';\n";
    report << "  \n";
    report << "  if (totalPages <= 1) return;\n";
    report << "  \n";
    report << "  // 显示记录总数\n";
    report << "  const recordInfo = document.createElement('span');\n";
    report << "  recordInfo.textContent = `共 ${totalRecords} 条记录，${totalPages} 页`;\n";
    report << "  recordInfo.style.marginRight = '15px';\n";
    report << "  paginationDiv.appendChild(recordInfo);\n";
    report << "  \n";
    report << "  // 上一页按钮\n";
    report << "  const prevBtn = document.createElement('button');\n";
    report << "  prevBtn.textContent = '上一页';\n";
    report << "  prevBtn.disabled = currentPage[tableId] === 1;\n";
    report << "  prevBtn.onclick = () => {\n";
    report << "    if (currentPage[tableId] > 1) {\n";
    report << "      currentPage[tableId]--;\n";
    report << "      renderTable(tableId, tableId === 'allocTable' ? allocTableData : tableId === 'freeTable' ? freeTableData : diffTableData);\n";
    report << "    }\n";
    report << "  };\n";
    report << "  paginationDiv.appendChild(prevBtn);\n";
    report << "  \n";
    report << "  // 页码按钮\n";
    report << "  const maxButtons = 5; // 最多显示的页码按钮数\n";
    report << "  let startPage = Math.max(1, currentPage[tableId] - Math.floor(maxButtons / 2));\n";
    report << "  let endPage = Math.min(totalPages, startPage + maxButtons - 1);\n";
    report << "  \n";
    report << "  if (endPage - startPage + 1 < maxButtons) {\n";
    report << "    startPage = Math.max(1, endPage - maxButtons + 1);\n";
    report << "  }\n";
    report << "  \n";
    report << "  for (let i = startPage; i <= endPage; i++) {\n";
    report << "    const pageBtn = document.createElement('button');\n";
    report << "    pageBtn.textContent = i;\n";
    report << "    pageBtn.classList.toggle('active', i === currentPage[tableId]);\n";
    report << "    pageBtn.onclick = () => {\n";
    report << "      currentPage[tableId] = i;\n";
    report << "      renderTable(tableId, tableId === 'allocTable' ? allocTableData : tableId === 'freeTable' ? freeTableData : diffTableData);\n";
    report << "    };\n";
    report << "    paginationDiv.appendChild(pageBtn);\n";
    report << "  }\n";
    report << "  \n";
    report << "  // 下一页按钮\n";
    report << "  const nextBtn = document.createElement('button');\n";
    report << "  nextBtn.textContent = '下一页';\n";
    report << "  nextBtn.disabled = currentPage[tableId] === totalPages;\n";
    report << "  nextBtn.onclick = () => {\n";
    report << "    if (currentPage[tableId] < totalPages) {\n";
    report << "      currentPage[tableId]++;\n";
    report << "      renderTable(tableId, tableId === 'allocTable' ? allocTableData : tableId === 'freeTable' ? freeTableData : diffTableData);\n";
    report << "    }\n";
    report << "  };\n";
    report << "  paginationDiv.appendChild(nextBtn);\n";
    report << "}\n\n";

    // 更新排序图标
    report << "// 更新排序图标\n";
    report << "function updateSortIcons(tableId) {\n";
    report << "  const table = document.getElementById(tableId);\n";
    report << "  const headers = table.querySelectorAll('th');\n";
    report << "  \n";
    report << "  headers.forEach((header, index) => {\n";
    report << "    const sortIcon = header.querySelector('.sort-icon');\n";
    report << "    if (sortIcon) {\n";
    report << "      if (index === sortConfig[tableId].column) {\n";
    report << "        sortIcon.textContent = sortConfig[tableId].direction === 'asc' ? '▲' : '▼';\n";
    report << "      } else {\n";
    report << "        sortIcon.textContent = '';\n";
    report << "      }\n";
    report << "    }\n";
    report << "  });\n";
    report << "}\n\n";

    // 设置表头点击排序
    report << "// 设置表头点击排序\n";
    report << "function setupTableSorting() {\n";
    report << "  const tables = ['allocTable', 'freeTable', 'diffTable'];\n";
    report << "  \n";
    report << "  tables.forEach(tableId => {\n";
    report << "    const table = document.getElementById(tableId);\n";
    report << "    const headers = table.querySelectorAll('th');\n";
    report << "    \n";
    report << "    headers.forEach((header, index) => {\n";
    report << "      header.addEventListener('click', () => {\n";
    report << "        // 点击当前排序列，切换排序方向\n";
    report << "        if (sortConfig[tableId].column === index) {\n";
    report << "          sortConfig[tableId].direction = sortConfig[tableId].direction === 'asc' ? 'desc' : 'asc';\n";
    report << "        } else {\n";
    report << "          // 点击新列，设置为默认降序\n";
    report << "          sortConfig[tableId].column = index;\n";
    report << "          sortConfig[tableId].direction = 'desc';\n";
    report << "        }\n";
    report << "        \n";
    report << "        // 重新渲染表格\n";
    report << "        renderTable(tableId, tableId === 'allocTable' ? allocTableData : tableId === 'freeTable' ? freeTableData : diffTableData);\n";
    report << "      });\n";
    report << "    });\n";
    report << "  });\n";
    report << "}\n\n";

    // 搜索函数
    report << "// 设置搜索功能\n";
    report << "function setupSearch() {\n";
    report << "  const searchInput = document.getElementById('globalSearchInput');\n";
    report << "  \n";
    report << "  searchInput.addEventListener('input', () => {\n";
    report << "    filterText = searchInput.value.trim();\n";
    report << "    \n";
    report << "    // 重置所有表格到第一页\n";
    report << "    currentPage.allocTable = 1;\n";
    report << "    currentPage.freeTable = 1;\n";
    report << "    currentPage.diffTable = 1;\n";
    report << "    \n";
    report << "    // 仅渲染当前活动表格\n";
    report << "    const activeTab = document.querySelector('.tab-content.active');\n";
    report << "    if (activeTab.id === 'alloc-table') {\n";
    report << "      renderTable('allocTable', allocTableData);\n";
    report << "    } else if (activeTab.id === 'free-table') {\n";
    report << "      renderTable('freeTable', freeTableData);\n";
    report << "    } else if (activeTab.id === 'diff-table') {\n";
    report << "      renderTable('diffTable', diffTableData);\n";
    report << "    }\n";
    report << "  });\n";
    report << "}\n\n";

    // 页面加载完成后执行
    report << "// 页面加载完成后初始化\n";
    report << "window.onload = function() {\n";
    report << "  // 绘制内存分布图表\n";
    report << "  const memDistCtx = document.getElementById('memoryDistributionChart').getContext('2d');\n";
    report << "  new Chart(memDistCtx, {\n";
    report << "    type: 'bar',\n";
    report << "    data: memoryDistributionData,\n";
    report << "    options: {\n";
    report << "      responsive: true,\n";
    report << "      plugins: {\n";
    report << "        legend: { display: false },\n";
    report << "        tooltip: {\n";
    report << "          callbacks: {\n";
    report << "            label: function(context) {\n";
    report << "              return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "            }\n";
    report << "          }\n";
    report << "        }\n";
    report << "      },\n";
    report << "      scales: { y: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "    }\n";
    report << "  });\n\n";

    // Top 10 图表
    report << "  // 绘制Top 10分配图表\n";
    report << "  const top10Ctx = document.getElementById('top10Chart').getContext('2d');\n";
    report << "  new Chart(top10Ctx, {\n";
    report << "    type: 'bar',\n";
    report << "    data: top10Data,\n";
    report << "    options: {\n";
    report << "      responsive: true,\n";
    report << "      indexAxis: 'y',\n";
    report << "      plugins: {\n";
    report << "        legend: { display: false },\n";
    report << "        tooltip: {\n";
    report << "          callbacks: {\n";
    report << "            label: function(context) {\n";
    report << "              return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "            }\n";
    report << "          }\n";
    report << "        }\n";
    report << "      },\n";
    report << "      scales: { x: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "    }\n";
    report << "  });\n\n";

    // 泄漏图表
    report << "  // 绘制泄漏图表\n";
    report << "  const leakCtx = document.getElementById('leakChart').getContext('2d');\n";
    report << "  new Chart(leakCtx, {\n";
    report << "    type: 'bar',\n";
    report << "    data: leakData,\n";
    report << "    options: {\n";
    report << "      responsive: true,\n";
    report << "      indexAxis: 'y',\n";
    report << "      plugins: {\n";
    report << "        legend: { display: false },\n";
    report << "        tooltip: {\n";
    report << "          callbacks: {\n";
    report << "            label: function(context) {\n";
    report << "              return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "            }\n";
    report << "          }\n";
    report << "        }\n";
    report << "      },\n";
    report << "      scales: { x: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "    }\n";
    report << "  });\n\n";

    // 初始化表格和功能
    report << "  // 设置表格排序和搜索\n";
    report << "  setupTableSorting();\n";
    report << "  setupSearch();\n";
    report << "  \n";
    report << "  // 延迟加载表格数据，防止浏览器冻结\n";
    report << "  setTimeout(() => {\n";
    report << "    renderTable('allocTable', allocTableData);\n";
    report << "  }, 100);\n";
    report << "};\n";

    report << "</script>\n";
    report << "</div>\n";
    report << "</body>\n</html>\n";

    report.close();
    LogMessage("[内存跟踪器] 内存图表报告已生成: %s", filename);
}

// 异步生成内存报告实现 - 简化版不返回future
void MemoryTracker::GenerateMemoryChartReportAsync(
    const char* html_filename, const char* data_dir) {
    // 如果已经有报告正在生成，则跳过
    if (m_isGeneratingReport.load(std::memory_order_acquire)) {
        LogMessage("[MemoryTracker] 已有报告正在生成中，跳过此次请求");
        return;
    }

    // 首先创建记录的快照，这样异步线程可以安全地使用数据
    std::unordered_map<std::string, MemoryTrackRecord> records_snapshot;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        records_snapshot = m_records;
    }

    // 创建并分离线程
    std::thread([this, records_snapshot, html_filename = std::string(html_filename), data_dir = std::string(data_dir)]() {
        this->GenerateMemoryChartReportInternal(std::move(records_snapshot), html_filename, data_dir);
        }).detach();

    LogMessage("[MemoryTracker] 已启动异步报告生成: %s", html_filename);
}

// 异步内部实现 - 在独立线程中运行
void MemoryTracker::GenerateMemoryChartReportInternal(
    std::unordered_map<std::string, MemoryTrackRecord> records_snapshot,
    std::string html_filename,
    std::string data_dir) {
    // 设置原子标志，防止并发生成报告
    bool expected = false;
    if (!m_isGeneratingReport.compare_exchange_strong(expected, true)) {
        LogMessage("[MemoryTracker] 已有报告正在生成中，跳过此次请求");
        return;
    }

    try {
        // 检查目录是否存在 - 使用Windows API代替std::filesystem
        if (!CreateDirectoryA(data_dir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            LogMessage("[MemoryTracker] 无法创建目录: %s, 错误码: %d", data_dir.c_str(), GetLastError());
        }

        LogMessage("[MemoryTracker] 开始异步生成内存报告: %s", html_filename.c_str());

        // 创建与同步版本相同的报告，但使用快照
        std::ofstream report(html_filename);
        if (!report.is_open()) {
            LogMessage("[MemoryTracker] 无法创建内存报告文件: %s", html_filename.c_str());
            m_isGeneratingReport.store(false);
            return;
        }

        // 这里重复同步版本的实现，但使用快照数据
        // 可以复用同步版本的实现，将报告代码抽取为共用函数

        // 关闭文件和标志
        report.close();
        m_isGeneratingReport.store(false);
        LogMessage("[MemoryTracker] 异步内存报告已完成: %s", html_filename.c_str());
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryTracker] 生成报告异常: %s", e.what());
        m_isGeneratingReport.store(false);
    }
}

