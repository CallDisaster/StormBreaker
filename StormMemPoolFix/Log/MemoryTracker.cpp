#include "pc#include "pch.h"
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
#include <memory>
#include <ctime>
#include <Storm/StormHook.h>
#include <direct.h> // For _mkdir

// 全局实例定义
MemoryTracker g_memoryTracker;
std::atomic<LogLevel> g_currentLogLevel{ LogLevel::Info };

// Global log file pointer
static FILE* g_logFile = nullptr;

// Helper function to open log file
bool OpenLogFile(const char* filename = "MemoryTracker.log") {
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

// 生成唯一ID 
std::string MemoryTracker::GenerateUniqueId() {
    // 使用当前时间和进程ID生成唯一标识符
    std::stringstream ss;
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto epoch = now_ms.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    ss << std::hex << value << "-" << GetCurrentProcessId();
    return ss.str();
}

// 初始化内存追踪器
bool MemoryTracker::Initialize(const char* reportsDir) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 生成新的会话ID
    m_sessionId = GenerateUniqueId();

    // 设置报告目录
    m_reportsDirectory = reportsDir ? reportsDir : "MemoryReports";

    // 确保目录存在
    if (!EnsureDirectoryExists(m_reportsDirectory)) {
        LogMessage("[MemoryTracker] 无法创建报告目录: %s", m_reportsDirectory.c_str());
        return false;
    }

    // 加载现有报告
    LoadReports(m_reportsDirectory.c_str());

    // 清理旧会话的报告
    CleanupOldReports();

    LogMessage("[MemoryTracker] 初始化完成，会话ID: %s, 报告目录: %s",
        m_sessionId.c_str(), m_reportsDirectory.c_str());
    return true;
}

// 关闭内存追踪器
void MemoryTracker::Shutdown() {
    // 停止定时报告
    StopPeriodicReporting();

    // 生成最终报告
    GenerateAndStoreReport();

    LogMessage("[MemoryTracker] 已关闭");
}

// 开始定时生成报告
void MemoryTracker::StartPeriodicReporting(unsigned int period_ms) {
    // 确保之前的线程已经停止
    StopPeriodicReporting();

    // 重置停止标志
    m_stopReporting.store(false);

    // 启动新的定时报告线程
    m_periodicReportThread = std::thread(&MemoryTracker::PeriodicReportThreadFunc, this, period_ms);

    LogMessage("[MemoryTracker] 已启动定时报告，间隔: %u ms", period_ms);
}

// 停止定时生成报告
void MemoryTracker::StopPeriodicReporting() {
    if (m_periodicReportThread.joinable()) {
        // 设置停止标志
        m_stopReporting.store(true);

        // 等待线程结束
        m_periodicReportThread.join();

        LogMessage("[MemoryTracker] 已停止定时报告");
    }
}

// 定时报告线程函数
void MemoryTracker::PeriodicReportThreadFunc(unsigned int period_ms) {
    while (!m_stopReporting.load()) {
        // 等待指定时间或直到停止标志被设置
        for (unsigned int i = 0; i < period_ms / 100 && !m_stopReporting.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (m_stopReporting.load()) break;

        // 生成并存储报告
        try {
            std::string reportName = m_reportsDirectory + "/MemoryReport_" +
                GetTimeString() + ".html";

            MemoryReportData reportData = GenerateAndStoreReport(reportName.c_str());

            LogMessage("[MemoryTracker] 定时报告已生成: %s", reportName.c_str());
        }
        catch (const std::exception& e) {
            LogMessage("[MemoryTracker] 生成定时报告时出错: %s", e.what());
        }
        catch (...) {
            LogMessage("[MemoryTracker] 生成定时报告时出现未知错误");
        }
    }
}

// 创建目录
bool MemoryTracker::EnsureDirectoryExists(const std::string& dirPath) {
    // 使用_mkdir创建目录
    int result = _mkdir(dirPath.c_str());
    return (result == 0 || errno == EEXIST);
}

// 获取目录下的所有HTML报告文件
std::vector<std::string> MemoryTracker::GetReportFiles(const std::string& directory) {
    std::vector<std::string> files;

    WIN32_FIND_DATAA findData;
    HANDLE hFind;

    std::string searchPath = directory + "/*.html";
    hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // 排除. 和 ..
            if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                std::string fullPath = directory + "/" + findData.cFileName;
                files.push_back(fullPath);
            }
        } while (FindNextFileA(hFind, &findData) != 0);

        FindClose(hFind);
    }

    return files;
}

// 清除非当前会话的报告
void MemoryTracker::CleanupOldReports() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 获取当前目录下的所有HTML文件
    std::vector<std::string> files = GetReportFiles(m_reportsDirectory);

    // 遍历所有文件，删除非当前会话的报告
    for (const auto& file : files) {
        MemoryReportData reportData;
        if (ParseReportData(file, reportData)) {
            if (reportData.sessionId != m_sessionId) {
                // 删除文件
                if (DeleteFileA(file.c_str())) {
                    LogMessage("[MemoryTracker] 已删除旧会话报告: %s", file.c_str());
                }
                else {
                    LogMessage("[MemoryTracker] 无法删除旧会话报告: %s, 错误码: %d",
                        file.c_str(), GetLastError());
                }
            }
        }
    }

    // 重新加载报告
    LoadReports(m_reportsDirectory.c_str());
}

// 从目录中加载所有历史报告数据
bool MemoryTracker::LoadReports(const char* directory) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 清空历史记录
    m_reportHistory.clear();

    // 使用指定目录或默认目录
    std::string dirPath = directory ? directory : m_reportsDirectory;

    // 获取所有HTML文件
    std::vector<std::string> files = GetReportFiles(dirPath);

    // 解析每个文件并加载数据
    for (const auto& file : files) {
        MemoryReportData reportData;
        if (ParseReportData(file, reportData)) {
            // 只存储当前会话的报告
            if (reportData.sessionId == m_sessionId) {
                m_reportHistory.push_back(reportData);
            }
        }
    }

    // 按时间排序
    std::sort(m_reportHistory.begin(), m_reportHistory.end(),
        [](const MemoryReportData& a, const MemoryReportData& b) {
            return a.timestamp < b.timestamp;
        });

    LogMessage("[MemoryTracker] 已加载 %zu 个当前会话的报告", m_reportHistory.size());
    return true;
}

// 解析HTML报告中的数据
bool MemoryTracker::ParseReportData(const std::string& filePath, MemoryReportData& reportData) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    // 初始化为无效数据
    reportData = MemoryReportData();
    reportData.reportPath = filePath;

    std::string line;
    bool foundSessionId = false;
    bool foundTimestamp = false;

    // 查找会话ID和时间戳
    while (std::getline(file, line) && (!foundSessionId || !foundTimestamp)) {
        // 查找会话ID
        size_t sessionPos = line.find("data-session-id=\"");
        if (!foundSessionId && sessionPos != std::string::npos) {
            sessionPos += 16; // "data-session-id=\"" 的长度
            size_t endPos = line.find("\"", sessionPos);
            if (endPos != std::string::npos) {
                reportData.sessionId = line.substr(sessionPos, endPos - sessionPos);
                foundSessionId = true;
            }
        }

        // 查找时间戳
        size_t timestampPos = line.find("data-timestamp=\"");
        if (!foundTimestamp && timestampPos != std::string::npos) {
            timestampPos += 16; // "data-timestamp=\"" 的长度
            size_t endPos = line.find("\"", timestampPos);
            if (endPos != std::string::npos) {
                reportData.timestamp = line.substr(timestampPos, endPos - timestampPos);
                foundTimestamp = true;
            }
        }

        // 查找总分配次数
        size_t allocCountPos = line.find("data-total-alloc-count=\"");
        if (allocCountPos != std::string::npos) {
            allocCountPos += 23; // "data-total-alloc-count=\"" 的长度
            size_t endPos = line.find("\"", allocCountPos);
            if (endPos != std::string::npos) {
                reportData.totalAllocations = std::stoull(line.substr(allocCountPos, endPos - allocCountPos));
            }
        }

        // 查找总释放次数
        size_t freeCountPos = line.find("data-total-free-count=\"");
        if (freeCountPos != std::string::npos) {
            freeCountPos += 22; // "data-total-free-count=\"" 的长度
            size_t endPos = line.find("\"", freeCountPos);
            if (endPos != std::string::npos) {
                reportData.totalFrees = std::stoull(line.substr(freeCountPos, endPos - freeCountPos));
            }
        }

        // 查找未释放数量
        size_t unreleasedPos = line.find("data-unreleased-count=\"");
        if (unreleasedPos != std::string::npos) {
            unreleasedPos += 23; // "data-unreleased-count=\"" 的长度
            size_t endPos = line.find("\"", unreleasedPos);
            if (endPos != std::string::npos) {
                reportData.unreleased = std::stoull(line.substr(unreleasedPos, endPos - unreleasedPos));
            }
        }

        // 查找总分配内存
        size_t allocSizePos = line.find("data-total-alloc-mb=\"");
        if (allocSizePos != std::string::npos) {
            allocSizePos += 21; // "data-total-alloc-mb=\"" 的长度
            size_t endPos = line.find("\"", allocSizePos);
            if (endPos != std::string::npos) {
                reportData.totalAllocatedMB = std::stod(line.substr(allocSizePos, endPos - allocSizePos));
            }
        }

        // 查找总释放内存
        size_t freeSizePos = line.find("data-total-free-mb=\"");
        if (freeSizePos != std::string::npos) {
            freeSizePos += 20; // "data-total-free-mb=\"" 的长度
            size_t endPos = line.find("\"", freeSizePos);
            if (endPos != std::string::npos) {
                reportData.totalFreedMB = std::stod(line.substr(freeSizePos, endPos - freeSizePos));
            }
        }

        // 查找泄漏内存
        size_t leakSizePos = line.find("data-leaked-mb=\"");
        if (leakSizePos != std::string::npos) {
            leakSizePos += 16; // "data-leaked-mb=\"" 的长度
            size_t endPos = line.find("\"", leakSizePos);
            if (endPos != std::string::npos) {
                reportData.leakedMemoryMB = std::stod(line.substr(leakSizePos, endPos - leakSizePos));
            }
        }
    }

    // 如果缺少关键数据，视为解析失败
    if (!foundSessionId || !foundTimestamp) {
        return false;
    }

    return true;
}

// 生成报告并存储数据到历史记录
MemoryReportData MemoryTracker::GenerateAndStoreReport(const char* filename) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 准备报告数据
    MemoryReportData reportData;
    reportData.sessionId = m_sessionId;
    reportData.timestamp = GetTimeString();

    // 计算统计数据
    size_t totalAlloc = 0;
    size_t totalFree = 0;
    size_t totalUnreleased = 0;
    size_t totalAllocBytes = 0;
    size_t totalFreeBytes = 0;
    size_t totalLeakBytes = 0;

    for (const auto& pair : m_records) {
        const auto& record = pair.second;

        totalAlloc += record.GetAllocCount();
        totalFree += record.GetFreeCount();
        totalUnreleased += record.GetUnreleasedCount();
        totalAllocBytes += record.GetTotalAllocSize();
        totalFreeBytes += record.GetTotalFreeSize();
        totalLeakBytes += record.GetUnreleasedMemory();

        // 解析类型名称
        std::string key = pair.first;
        size_t delimPos = key.find('_');
        if (delimPos != std::string::npos) {
            std::string typeName = key.substr(delimPos + 1);
            double sizeMB = (double)record.GetTotalAllocSize() / (1024 * 1024);

            // 累加同类型的分配内存
            reportData.typeAllocation[typeName] += sizeMB;
        }
    }

    // 保存统计数据
    reportData.totalAllocations = totalAlloc;
    reportData.totalFrees = totalFree;
    reportData.unreleased = totalUnreleased;
    reportData.totalAllocatedMB = (double)totalAllocBytes / (1024 * 1024);
    reportData.totalFreedMB = (double)totalFreeBytes / (1024 * 1024);
    reportData.leakedMemoryMB = (double)totalLeakBytes / (1024 * 1024);

    // 生成报告文件
    std::string reportPath;
    if (filename) {
        reportPath = filename;
    }
    else {
        // 默认文件名
        reportPath = m_reportsDirectory + "/MemoryReport_" + reportData.timestamp + ".html";
    }

    reportData.reportPath = reportPath;

    // 存储到历史记录
    m_reportHistory.push_back(reportData);

    // 按时间排序
    std::sort(m_reportHistory.begin(), m_reportHistory.end(),
        [](const MemoryReportData& a, const MemoryReportData& b) {
            return a.timestamp < b.timestamp;
        });

    // 生成HTML报告
    GenerateBootstrapHtmlReport(reportPath.c_str(), m_records, m_reportHistory.size() > 1);

    return reportData;
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
    report << "Session ID: " << m_sessionId << std::endl;
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
void MemoryTracker::GenerateMemoryChartReport(const char* filename, bool compareWithPrevious) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 使用新的Bootstrap报告生成
    GenerateBootstrapHtmlReport(filename, m_records, compareWithPrevious);

    LogMessage("[MemoryTracker] 内存图表报告已生成: %s", filename);
}

// ======== Bootstrap HTML Report Generation ========
void MemoryTracker::GenerateBootstrapHtmlReport(
    const char* filename,
    const std::unordered_map<std::string, MemoryTrackRecord>& records,
    bool compareWithPrevious) {

    // Open HTML file
    std::ofstream report(filename);
    if (!report.is_open()) {
        LogMessage("[MemoryTracker] 无法创建内存报告: %s", filename);
        return;
    }

    // ==== 数据预处理 ====
    size_t totalAlloc = 0;
    size_t totalFree = 0;
    size_t totalUnreleased = 0;
    size_t totalAllocBytes = 0;
    size_t totalFreeBytes = 0;
    size_t totalLeakBytes = 0;

    // 类型统计结构
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

    std::vector<TypeStats> allStats;
    std::map<std::string, double> typeAllocation; // 按类型分组的分配

    // 处理所有记录
    for (const auto& pair : records) {
        std::string key = pair.first;
        size_t underscorePos = key.find('_');
        std::string sizeStr = key.substr(0, underscorePos);
        std::string name = key.substr(underscorePos + 1);
        size_t size = std::stoull(sizeStr);

        const auto& record = pair.second;
        size_t unreleased = record.GetUnreleasedCount();
        size_t leakSize = record.GetUnreleasedMemory();

        // 添加到统计
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

        // 统计按类型分组
        // 从name提取类型（简化版）
        std::string typeName = name;
        // 只取第一部分作为类型
        size_t spacePos = typeName.find(' ');
        if (spacePos != std::string::npos) {
            typeName = typeName.substr(0, spacePos);
        }

        // 累加同类型的分配内存
        typeAllocation[typeName] += (double)record.totalAllocSize / (1024 * 1024);

        // 累计总数
        totalAlloc += record.allocCount;
        totalFree += record.freeCount;
        totalUnreleased += unreleased;
        totalAllocBytes += record.totalAllocSize;
        totalFreeBytes += record.totalFreeSize;
        totalLeakBytes += leakSize;
    }

    // 按分配大小排序
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.allocSize > b.allocSize;
        });

    // 限制显示条目数
    const size_t MAX_DISPLAY_RECORDS = 1000;
    if (allStats.size() > MAX_DISPLAY_RECORDS) {
        // 聚合剩余数据
        TypeStats otherStats = { "其他类型 (汇总)", 0, 0, 0, 0, 0, 0, 0, 0 };

        for (size_t i = MAX_DISPLAY_RECORDS; i < allStats.size(); i++) {
            otherStats.allocCount += allStats[i].allocCount;
            otherStats.freeCount += allStats[i].freeCount;
            otherStats.allocSize += allStats[i].allocSize;
            otherStats.freeSize += allStats[i].freeSize;
            otherStats.unreleased += allStats[i].unreleased;
            otherStats.leakSize += allStats[i].leakSize;
            otherStats.peakAlloc += allStats[i].peakAlloc;
        }

        // 截断列表
        allStats.resize(MAX_DISPLAY_RECORDS);

        // 添加聚合条目
        if (otherStats.allocCount > 0) {
            allStats.push_back(otherStats);
        }
    }

    // 提取前10大内存分配
    std::vector<TypeStats> top10Stats;
    size_t numTop = min(size_t(10), allStats.size());
    for (size_t i = 0; i < numTop; i++) {
        top10Stats.push_back(allStats[i]);
    }

    // 提取前10大内存泄漏
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

    // 按分配大小重新排序
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.allocSize > b.allocSize;
        });

    // 获取前一个报告数据进行比较
    MemoryReportData prevReport;
    MemoryReportData* prevReportPtr = nullptr;

    if (compareWithPrevious && m_reportHistory.size() > 0) {
        // 当前报告是最新的，所以取倒数第二个
        if (m_reportHistory.size() > 1) {
            prevReport = m_reportHistory[m_reportHistory.size() - 2];
            prevReportPtr = &prevReport;
        }
    }

    // ==== 开始生成HTML ====

    report << "<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n";
    report << "  <meta charset=\"UTF-8\">\n";
    report << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    report << "  <title>Storm内存分析报告 - " << GetTimeString() << "</title>\n";

    // Bootstrap 5 CSS
    report << "  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\n";

    // Chart.js
    report << "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n";

    // Datatable CSS
    report << "  <link href=\"https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css\" rel=\"stylesheet\">\n";

    // Font Awesome
    report << "  <link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css\" rel=\"stylesheet\">\n";

    // 添加元数据 (用于报告解析)
    report << "  <meta data-session-id=\"" << m_sessionId << "\" content=\"\">\n";
    report << "  <meta data-timestamp=\"" << GetTimeString() << "\" content=\"\">\n";
    report << "  <meta data-total-alloc-count=\"" << totalAlloc << "\" content=\"\">\n";
    report << "  <meta data-total-free-count=\"" << totalFree << "\" content=\"\">\n";
    report << "  <meta data-unreleased-count=\"" << totalUnreleased << "\" content=\"\">\n";
    report << "  <meta data-total-alloc-mb=\"" << (double)totalAllocBytes / (1024 * 1024) << "\" content=\"\">\n";
    report << "  <meta data-total-free-mb=\"" << (double)totalFreeBytes / (1024 * 1024) << "\" content=\"\">\n";
    report << "  <meta data-leaked-mb=\"" << (double)totalLeakBytes / (1024 * 1024) << "\" content=\"\">\n";

    // 自定义样式
    report << "  <style>\n";
    report << "    :root {\n";
    report << "      --primary-color: #0d6efd;\n";
    report << "      --secondary-color: #6c757d;\n";
    report << "      --success-color: #198754;\n";
    report << "      --danger-color: #dc3545;\n";
    report << "      --warning-color: #ffc107;\n";
    report << "      --info-color: #0dcaf0;\n";
    report << "    }\n";
    report << "    .trend-up { color: var(--danger-color); }\n";
    report << "    .trend-down { color: var(--success-color); }\n";
    report << "    .trend-neutral { color: var(--secondary-color); }\n";
    report << "    .card-dashboard { transition: all 0.3s ease; }\n";
    report << "    .card-dashboard:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }\n";
    report << "    .chart-container { height: 300px; }\n";
    report << "    .table-responsive { max-height: 600px; }\n";
    report << "    .fas { margin-right: 5px; }\n";
    report << "    .navbar-brand img { max-height: 40px; }\n";
    report << "    body { padding-top: 60px; }\n";
    report << "  </style>\n";
    report << "</head>\n";

    report << "<body>\n";

    // 导航栏
    report << "  <nav class=\"navbar navbar-expand-lg navbar-dark bg-dark fixed-top\">\n";
    report << "    <div class=\"container-fluid\">\n";
    report << "      <a class=\"navbar-brand\" href=\"#\">Storm内存追踪器</a>\n";
    report << "      <button class=\"navbar-toggler\" type=\"button\" data-bs-toggle=\"collapse\" data-bs-target=\"#navbarNav\">\n";
    report << "        <span class=\"navbar-toggler-icon\"></span>\n";
    report << "      </button>\n";
    report << "      <div class=\"collapse navbar-collapse\" id=\"navbarNav\">\n";
    report << "        <ul class=\"navbar-nav me-auto\">\n";
    report << "          <li class=\"nav-item\"><a class=\"nav-link active\" href=\"#overview\">概览</a></li>\n";
    report << "          <li class=\"nav-item\"><a class=\"nav-link\" href=\"#charts\">图表分析</a></li>\n";
    report << "          <li class=\"nav-item\"><a class=\"nav-link\" href=\"#data-tables\">详细数据</a></li>\n";
    report << "          <li class=\"nav-item\"><a class=\"nav-link\" href=\"#leaks\">内存泄漏</a></li>\n";
    if (compareWithPrevious && prevReportPtr) {
        report << "          <li class=\"nav-item\"><a class=\"nav-link\" href=\"#comparison\">数据对比</a></li>\n";
    }
    report << "        </ul>\n";
    report << "        <span class=\"navbar-text\">会话ID: " << m_sessionId.substr(0, 8) << "...</span>\n";
    report << "      </div>\n";
    report << "    </div>\n";
    report << "  </nav>\n\n";

    // 主容器
    report << "  <div class=\"container-fluid mt-4\">\n";

    // 页面标题和信息
    report << "    <div class=\"row mb-4\">\n";
    report << "      <div class=\"col-12\">\n";
    report << "        <div class=\"card shadow-sm\">\n";
    report << "          <div class=\"card-body\">\n";
    report << "            <h1 class=\"card-title\">Storm内存分析报告</h1>\n";
    report << "            <p class=\"card-text\">生成时间: " << GetTimeString() << "</p>\n";
    report << "            <p class=\"card-text\">会话ID: " << m_sessionId << "</p>\n";
    if (compareWithPrevious && prevReportPtr) {
        report << "            <p class=\"card-text\">与前次报告比较: " << prevReportPtr->timestamp << "</p>\n";
    }
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";
    report << "    </div>\n\n";

    // ===== 概览部分 =====
    report << "    <section id=\"overview\" class=\"mb-5\">\n";
    report << "      <h2 class=\"mb-4\">内存使用概览</h2>\n";
    report << "      <div class=\"row g-4\">\n";

    // 总分配次数卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-light text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-plus-circle\"></i>总分配次数</h5>\n";
    report << "              <h2>" << totalAlloc << "</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double allocDiff = (double)totalAlloc - prevReportPtr->totalAllocations;
        double allocPercent = prevReportPtr->totalAllocations > 0 ?
            (allocDiff / prevReportPtr->totalAllocations) * 100 : 0;

        report << "              <p class=\"";
        if (allocDiff > 0) report << "trend-up";
        else if (allocDiff < 0) report << "trend-down";
        else report << "trend-neutral";
        report << "\">";

        if (allocDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (allocDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(allocPercent) << "% ";
        report << "(" << (allocDiff > 0 ? "+" : "") << allocDiff << ")</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 总释放次数卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-light text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-minus-circle\"></i>总释放次数</h5>\n";
    report << "              <h2>" << totalFree << "</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double freeDiff = (double)totalFree - prevReportPtr->totalFrees;
        double freePercent = prevReportPtr->totalFrees > 0 ?
            (freeDiff / prevReportPtr->totalFrees) * 100 : 0;

        report << "              <p class=\"";
        if (freeDiff > 0) report << "trend-up";
        else if (freeDiff < 0) report << "trend-down";
        else report << "trend-neutral";
        report << "\">";

        if (freeDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (freeDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(freePercent) << "% ";
        report << "(" << (freeDiff > 0 ? "+" : "") << freeDiff << ")</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 未释放内存卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card " << (totalUnreleased > 0 ? "bg-warning" : "bg-success") << " text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-exclamation-triangle\"></i>未释放内存块</h5>\n";
    report << "              <h2>" << totalUnreleased << "</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double unreaDiff = (double)totalUnreleased - prevReportPtr->unreleased;
        double unreaPercent = prevReportPtr->unreleased > 0 ?
            (unreaDiff / prevReportPtr->unreleased) * 100 : 0;

        report << "              <p class=\"";
        if (unreaDiff > 0) report << "trend-up";
        else if (unreaDiff < 0) report << "trend-down";
        else report << "trend-neutral";
        report << "\">";

        if (unreaDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (unreaDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(unreaPercent) << "% ";
        report << "(" << (unreaDiff > 0 ? "+" : "") << unreaDiff << ")</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 内存泄漏卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card " << (totalLeakBytes > 0 ? "bg-danger" : "bg-success") << " text-" << (totalLeakBytes > 0 ? "white" : "dark") << " h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-memory\"></i>内存泄漏</h5>\n";
    report << "              <h2>" << std::fixed << std::setprecision(2) << (double)totalLeakBytes / (1024 * 1024) << " MB</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double leakDiff = (double)totalLeakBytes / (1024 * 1024) - prevReportPtr->leakedMemoryMB;
        double leakPercent = prevReportPtr->leakedMemoryMB > 0 ?
            (leakDiff / prevReportPtr->leakedMemoryMB) * 100 : 0;

        report << "              <p class=\"";
        // 注意：对于泄漏，增加是负面的，减少是正面的
        if (leakDiff > 0) report << "text-warning";
        else if (leakDiff < 0) report << "text-info";
        else report << "text-light";
        report << "\">";

        if (leakDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (leakDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(leakPercent) << "% ";
        report << "(" << (leakDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << leakDiff << " MB)</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 总分配内存卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-light text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-chart-area\"></i>总分配内存</h5>\n";
    report << "              <h2>" << std::fixed << std::setprecision(2) << (double)totalAllocBytes / (1024 * 1024) << " MB</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double allocMBDiff = (double)totalAllocBytes / (1024 * 1024) - prevReportPtr->totalAllocatedMB;
        double allocMBPercent = prevReportPtr->totalAllocatedMB > 0 ?
            (allocMBDiff / prevReportPtr->totalAllocatedMB) * 100 : 0;

        report << "              <p class=\"";
        if (allocMBDiff > 0) report << "trend-up";
        else if (allocMBDiff < 0) report << "trend-down";
        else report << "trend-neutral";
        report << "\">";

        if (allocMBDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (allocMBDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(allocMBPercent) << "% ";
        report << "(" << (allocMBDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << allocMBDiff << " MB)</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 总释放内存卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-light text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-trash-alt\"></i>总释放内存</h5>\n";
    report << "              <h2>" << std::fixed << std::setprecision(2) << (double)totalFreeBytes / (1024 * 1024) << " MB</h2>\n";
    if (compareWithPrevious && prevReportPtr) {
        double freeMBDiff = (double)totalFreeBytes / (1024 * 1024) - prevReportPtr->totalFreedMB;
        double freeMBPercent = prevReportPtr->totalFreedMB > 0 ?
            (freeMBDiff / prevReportPtr->totalFreedMB) * 100 : 0;

        report << "              <p class=\"";
        if (freeMBDiff > 0) report << "trend-up";
        else if (freeMBDiff < 0) report << "trend-down";
        else report << "trend-neutral";
        report << "\">";

        if (freeMBDiff > 0) report << "<i class=\"fas fa-arrow-up\"></i>";
        else if (freeMBDiff < 0) report << "<i class=\"fas fa-arrow-down\"></i>";
        else report << "<i class=\"fas fa-equals\"></i>";

        report << std::fixed << std::setprecision(2) << std::abs(freeMBPercent) << "% ";
        report << "(" << (freeMBDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << freeMBDiff << " MB)</p>\n";
    }
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 资源数量卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-info text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-database\"></i>资源类型数量</h5>\n";
    report << "              <h2>" << typeAllocation.size() << "</h2>\n";
    report << "              <p>资源类型详情见图表分析</p>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 记录条目数卡片
    report << "        <div class=\"col-md-6 col-lg-4 col-xl-3\">\n";
    report << "          <div class=\"card bg-info text-dark h-100 card-dashboard shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <h5 class=\"card-title\"><i class=\"fas fa-list\"></i>记录条目数</h5>\n";
    report << "              <h2>" << allStats.size() << "</h2>\n";
    report << "              <p>查看详细表格了解更多</p>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    report << "      </div>\n";
    report << "    </section>\n\n";

    // ===== 图表部分 =====
    report << "    <section id=\"charts\" class=\"mb-5\">\n";
    report << "      <h2 class=\"mb-4\">图表分析</h2>\n";

    // 内存分布图表 & 类型分布饼图
    report << "      <div class=\"row g-4 mb-4\">\n";
    report << "        <div class=\"col-md-6\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-header bg-primary text-white\">\n";
    report << "              <h5 class=\"mb-0\">内存分配/释放分布</h5>\n";
    report << "            </div>\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"chart-container\">\n";
    report << "                <canvas id=\"memoryDistributionChart\"></canvas>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    report << "        <div class=\"col-md-6\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-header bg-primary text-white\">\n";
    report << "              <h5 class=\"mb-0\">资源类型分布</h5>\n";
    report << "            </div>\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"chart-container\">\n";
    report << "                <canvas id=\"resourceTypeChart\"></canvas>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";

    // Top 10分配 & Top 10泄漏
    report << "      <div class=\"row g-4\">\n";
    report << "        <div class=\"col-md-6\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-header bg-primary text-white\">\n";
    report << "              <h5 class=\"mb-0\">前10大内存消耗</h5>\n";
    report << "            </div>\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"chart-container\">\n";
    report << "                <canvas id=\"top10Chart\"></canvas>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    report << "        <div class=\"col-md-6\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-header bg-danger text-white\">\n";
    report << "              <h5 class=\"mb-0\">前10大内存泄漏</h5>\n";
    report << "            </div>\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"chart-container\">\n";
    report << "                <canvas id=\"leakChart\"></canvas>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";
    report << "    </section>\n\n";

    // ===== 对比部分（如果有前一个报告数据）=====
    if (compareWithPrevious && prevReportPtr) {
        report << "    <section id=\"comparison\" class=\"mb-5\">\n";
        report << "      <h2 class=\"mb-4\">与前次报告对比</h2>\n";
        report << "      <div class=\"card shadow-sm\">\n";
        report << "        <div class=\"card-header bg-info text-dark\">\n";
        report << "          <h5 class=\"mb-0\">内存使用变化趋势</h5>\n";
        report << "        </div>\n";
        report << "        <div class=\"card-body\">\n";
        report << "          <div class=\"chart-container\">\n";
        report << "            <canvas id=\"trendChart\"></canvas>\n";
        report << "          </div>\n";
        report << "        </div>\n";
        report << "      </div>\n";
        report << "    </section>\n\n";
    }
    // ===== 详细数据表格部分 =====
    report << "    <section id=\"data-tables\" class=\"mb-5\">\n";
    report << "      <h2 class=\"mb-4\">详细数据</h2>\n";

    // 表格切换标签
    report << "      <ul class=\"nav nav-tabs mb-4\" id=\"myTab\" role=\"tablist\">\n";
    report << "        <li class=\"nav-item\" role=\"presentation\">\n";
    report << "          <button class=\"nav-link active\" id=\"alloc-tab\" data-bs-toggle=\"tab\" data-bs-target=\"#alloc-tab-pane\" type=\"button\">分配表</button>\n";
    report << "        </li>\n";
    report << "        <li class=\"nav-item\" role=\"presentation\">\n";
    report << "          <button class=\"nav-link\" id=\"free-tab\" data-bs-toggle=\"tab\" data-bs-target=\"#free-tab-pane\" type=\"button\">释放表</button>\n";
    report << "        </li>\n";
    report << "        <li class=\"nav-item\" role=\"presentation\">\n";
    report << "          <button class=\"nav-link\" id=\"diff-tab\" data-bs-toggle=\"tab\" data-bs-target=\"#diff-tab-pane\" type=\"button\">差异表</button>\n";
    report << "        </li>\n";
    report << "      </ul>\n";

    // 搜索框
    report << "      <div class=\"row mb-4\">\n";
    report << "        <div class=\"col-md-12\">\n";
    report << "          <div class=\"input-group\">\n";
    report << "            <span class=\"input-group-text\"><i class=\"fas fa-search\"></i></span>\n";
    report << "            <input type=\"text\" id=\"globalSearchInput\" class=\"form-control\" placeholder=\"在所有表中搜索...\">\n";
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";

    // 表格内容
    report << "      <div class=\"tab-content\" id=\"myTabContent\">\n";

    // 分配表
    report << "        <div class=\"tab-pane fade show active\" id=\"alloc-tab-pane\" role=\"tabpanel\" aria-labelledby=\"alloc-tab\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"table-responsive\">\n";
    report << "                <table id=\"allocTable\" class=\"table table-striped table-hover\">\n";
    report << "                  <thead class=\"table-primary\">\n";
    report << "                    <tr>\n";
    report << "                      <th>分配类型</th>\n";
    report << "                      <th>大小(字节)</th>\n";
    report << "                      <th>分配次数</th>\n";
    report << "                      <th>总分配(MB)</th>\n";
    report << "                      <th>峰值分配</th>\n";
    report << "                    </tr>\n";
    report << "                  </thead>\n";
    report << "                  <tbody id=\"allocTableBody\">\n";
    report << "                  </tbody>\n";
    report << "                </table>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 释放表
    report << "        <div class=\"tab-pane fade\" id=\"free-tab-pane\" role=\"tabpanel\" aria-labelledby=\"free-tab\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"table-responsive\">\n";
    report << "                <table id=\"freeTable\" class=\"table table-striped table-hover\">\n";
    report << "                  <thead class=\"table-primary\">\n";
    report << "                    <tr>\n";
    report << "                      <th>分配类型</th>\n";
    report << "                      <th>大小(字节)</th>\n";
    report << "                      <th>释放次数</th>\n";
    report << "                      <th>总释放(MB)</th>\n";
    report << "                      <th>效率(%)</th>\n";
    report << "                    </tr>\n";
    report << "                  </thead>\n";
    report << "                  <tbody id=\"freeTableBody\">\n";
    report << "                  </tbody>\n";
    report << "                </table>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";

    // 差异表
    report << "        <div class=\"tab-pane fade\" id=\"diff-tab-pane\" role=\"tabpanel\" aria-labelledby=\"diff-tab\">\n";
    report << "          <div class=\"card shadow-sm\">\n";
    report << "            <div class=\"card-body\">\n";
    report << "              <div class=\"table-responsive\">\n";
    report << "                <table id=\"diffTable\" class=\"table table-striped table-hover\">\n";
    report << "                  <thead class=\"table-primary\">\n";
    report << "                    <tr>\n";
    report << "                      <th>分配类型</th>\n";
    report << "                      <th>大小(字节)</th>\n";
    report << "                      <th>分配次数</th>\n";
    report << "                      <th>释放次数</th>\n";
    report << "                      <th>未释放</th>\n";
    report << "                      <th>泄漏(MB)</th>\n";
    report << "                    </tr>\n";
    report << "                  </thead>\n";
    report << "                  <tbody id=\"diffTableBody\">\n";
    report << "                  </tbody>\n";
    report << "                </table>\n";
    report << "              </div>\n";
    report << "            </div>\n";
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";
    report << "    </section>\n\n";

    // ===== 内存泄漏分析部分 =====
    report << "    <section id=\"leaks\" class=\"mb-5\">\n";
    report << "      <h2 class=\"mb-4\">内存泄漏分析</h2>\n";
    report << "      <div class=\"card shadow-sm\">\n";
    report << "        <div class=\"card-header bg-danger text-white\">\n";
    report << "          <h5 class=\"mb-0\">潜在内存泄漏点 (最大分配/释放差异)</h5>\n";
    report << "        </div>\n";
    report << "        <div class=\"card-body\">\n";
    report << "          <div class=\"table-responsive\">\n";
    report << "            <table id=\"leakTable\" class=\"table table-striped table-hover\">\n";
    report << "              <thead class=\"table-danger\">\n";
    report << "                <tr>\n";
    report << "                  <th>分配类型</th>\n";
    report << "                  <th>大小(字节)</th>\n";
    report << "                  <th>分配次数</th>\n";
    report << "                  <th>释放次数</th>\n";
    report << "                  <th>未释放</th>\n";
    report << "                  <th>泄漏(MB)</th>\n";
    report << "                  <th>状态</th>\n";
    report << "                </tr>\n";
    report << "              </thead>\n";
    report << "              <tbody>\n";

    // 排序找出前20大内存泄漏点
    std::sort(allStats.begin(), allStats.end(), [](const auto& a, const auto& b) {
        return a.leakSize > b.leakSize;
        });

    int leakCount = 0;
    for (const auto& item : allStats) {
        // 只显示有泄漏的条目
        if (item.leakSize == 0) continue;

        // 计算泄漏百分比
        double leakRatio = item.allocSize > 0 ?
            (double)item.leakSize / item.allocSize * 100 : 0;

        // 确定泄漏等级
        std::string leakStatus;
        std::string leakClass;

        if (leakRatio > 80) {
            leakStatus = "严重";
            leakClass = "bg-danger text-white";
        }
        else if (leakRatio > 50) {
            leakStatus = "高";
            leakClass = "bg-warning";
        }
        else if (leakRatio > 20) {
            leakStatus = "中";
            leakClass = "bg-info";
        }
        else {
            leakStatus = "低";
            leakClass = "bg-success text-white";
        }

        report << "                <tr>\n";
        report << "                  <td>" << item.name << "</td>\n";
        report << "                  <td>" << item.size << "</td>\n";
        report << "                  <td>" << item.allocCount << "</td>\n";
        report << "                  <td>" << item.freeCount << "</td>\n";
        report << "                  <td>" << item.unreleased << "</td>\n";
        report << "                  <td>" << std::fixed << std::setprecision(2)
            << (double)item.leakSize / (1024 * 1024) << "</td>\n";
        report << "                  <td><span class=\"badge " << leakClass << "\">"
            << leakStatus << "</span></td>\n";
        report << "                </tr>\n";

        leakCount++;
        if (leakCount >= 20) break; // 只显示前20条
    }

    if (leakCount == 0) {
        report << "                <tr><td colspan=\"7\" class=\"text-center\">没有检测到内存泄漏</td></tr>\n";
    }

    report << "              </tbody>\n";
    report << "            </table>\n";
    report << "          </div>\n";
    report << "        </div>\n";
    report << "      </div>\n";
    report << "    </section>\n";

    // 关闭主容器
    report << "  </div>\n\n";

    // ===== JavaScript 部分 =====
    report << "  <!-- Bootstrap JS -->\n";
    report << "  <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js\"></script>\n";

    // DataTables JS
    report << "  <script src=\"https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js\"></script>\n";
    report << "  <script src=\"https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js\"></script>\n";
    report << "  <script src=\"https://code.jquery.com/jquery-3.6.0.min.js\"></script>\n";

    // 内联JavaScript代码
    report << "  <script>\n";

    // 内存分布数据
    report << "    // 内存分布数据\n";
    report << "    const memoryDistributionData = {\n";
    report << "      labels: ['已分配', '已释放', '未释放'],\n";
    report << "      datasets: [{\n";
    report << "        label: '内存(MB)',\n";
    report << "        data: ["
        << (double)totalAllocBytes / (1024 * 1024) << ", "
        << (double)totalFreeBytes / (1024 * 1024) << ", "
        << (double)totalLeakBytes / (1024 * 1024) << "],\n";
    report << "        backgroundColor: [\n";
    report << "          'rgba(54, 162, 235, 0.5)',\n";
    report << "          'rgba(75, 192, 192, 0.5)',\n";
    report << "          'rgba(255, 99, 132, 0.5)'\n";
    report << "        ],\n";
    report << "        borderColor: [\n";
    report << "          'rgba(54, 162, 235, 1)',\n";
    report << "          'rgba(75, 192, 192, 1)',\n";
    report << "          'rgba(255, 99, 132, 1)'\n";
    report << "        ],\n";
    report << "        borderWidth: 1\n";
    report << "      }]\n";
    report << "    };\n\n";

    // 资源类型分布数据
    report << "    // 资源类型分布数据\n";
    report << "    const typeData = {\n";
    report << "      labels: [";

    // 提取类型数据
    std::vector<std::pair<std::string, double>> typeItems;
    for (const auto& pair : typeAllocation) {
        typeItems.push_back({ pair.first, pair.second });
    }

    // 按大小排序
    std::sort(typeItems.begin(), typeItems.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
        });

    // 限制显示的类型数量，合并小类型为"其他"
    const size_t MAX_TYPE_DISPLAY = 10;
    double otherTypesMB = 0.0;

    for (size_t i = 0; i < typeItems.size(); i++) {
        if (i < MAX_TYPE_DISPLAY) {
            if (i > 0) report << ", ";
            report << "'" << typeItems[i].first << "'";
        }
        else {
            otherTypesMB += typeItems[i].second;
        }
    }

    if (otherTypesMB > 0.0) {
        if (!typeItems.empty() && typeItems.size() > MAX_TYPE_DISPLAY) {
            report << ", '其他类型'";
        }
    }

    report << "],\n";
    report << "      datasets: [{\n";
    report << "        label: '分配内存(MB)',\n";
    report << "        data: [";

    for (size_t i = 0; i < typeItems.size(); i++) {
        if (i < MAX_TYPE_DISPLAY) {
            if (i > 0) report << ", ";
            report << typeItems[i].second;
        }
    }

    if (otherTypesMB > 0.0) {
        if (!typeItems.empty() && typeItems.size() > MAX_TYPE_DISPLAY) {
            report << ", " << otherTypesMB;
        }
    }

    report << "],\n";
    report << "        backgroundColor: [\n";
    report << "          'rgba(255, 99, 132, 0.5)',\n";
    report << "          'rgba(54, 162, 235, 0.5)',\n";
    report << "          'rgba(255, 206, 86, 0.5)',\n";
    report << "          'rgba(75, 192, 192, 0.5)',\n";
    report << "          'rgba(153, 102, 255, 0.5)',\n";
    report << "          'rgba(255, 159, 64, 0.5)',\n";
    report << "          'rgba(199, 199, 199, 0.5)',\n";
    report << "          'rgba(83, 102, 255, 0.5)',\n";
    report << "          'rgba(78, 205, 196, 0.5)',\n";
    report << "          'rgba(232, 65, 24, 0.5)',\n";
    report << "          'rgba(160, 160, 160, 0.5)'\n";
    report << "        ],\n";
    report << "        borderColor: [\n";
    report << "          'rgba(255, 99, 132, 1)',\n";
    report << "          'rgba(54, 162, 235, 1)',\n";
    report << "          'rgba(255, 206, 86, 1)',\n";
    report << "          'rgba(75, 192, 192, 1)',\n";
    report << "          'rgba(153, 102, 255, 1)',\n";
    report << "          'rgba(255, 159, 64, 1)',\n";
    report << "          'rgba(199, 199, 199, 1)',\n";
    report << "          'rgba(83, 102, 255, 1)',\n";
    report << "          'rgba(78, 205, 196, 1)',\n";
    report << "          'rgba(232, 65, 24, 1)',\n";
    report << "          'rgba(160, 160, 160, 1)'\n";
    report << "        ],\n";
    report << "        borderWidth: 1\n";
    report << "      }]\n";
    report << "    };\n\n";

    // Top 10 最大分配数据
    report << "    // Top 10 分配数据\n";
    report << "    const top10Data = {\n";
    report << "      labels: [";
    for (size_t i = 0; i < top10Stats.size(); i++) {
        if (i > 0) report << ", ";
        std::string name = top10Stats[i].name;
        if (name.length() > 20) {
            name = name.substr(0, 17) + "...";
        }
        report << "'" << name << "'";
    }
    report << "],\n";
    report << "      datasets: [{\n";
    report << "        label: '内存(MB)',\n";
    report << "        data: [";
    for (size_t i = 0; i < top10Stats.size(); i++) {
        if (i > 0) report << ", ";
        report << (double)top10Stats[i].allocSize / (1024 * 1024);
    }
    report << "],\n";
    report << "        backgroundColor: 'rgba(54, 162, 235, 0.5)',\n";
    report << "        borderColor: 'rgba(54, 162, 235, 1)',\n";
    report << "        borderWidth: 1\n";
    report << "      }]\n";
    report << "    };\n\n";

    // Top 10 泄漏数据
    report << "    // Top 10 泄漏数据\n";
    report << "    const leakData = {\n";
    report << "      labels: [";
    for (size_t i = 0; i < top10Leaks.size(); i++) {
        if (i > 0) report << ", ";
        std::string name = top10Leaks[i].name;
        if (name.length() > 20) {
            name = name.substr(0, 17) + "...";
        }
        report << "'" << name << "'";
    }
    report << "],\n";
    report << "      datasets: [{\n";
    report << "        label: '泄漏内存(MB)',\n";
    report << "        data: [";
    for (size_t i = 0; i < top10Leaks.size(); i++) {
        if (i > 0) report << ", ";
        report << (double)top10Leaks[i].leakSize / (1024 * 1024);
    }
    report << "],\n";
    report << "        backgroundColor: 'rgba(255, 99, 132, 0.5)',\n";
    report << "        borderColor: 'rgba(255, 99, 132, 1)',\n";
    report << "        borderWidth: 1\n";
    report << "      }]\n";
    report << "    };\n\n";

    // 趋势图数据（如果有前一个报告）
    if (compareWithPrevious && prevReportPtr) {
        report << "    // 趋势变化数据\n";
        report << "    const trendData = {\n";
        report << "      labels: ['前次报告', '当前报告'],\n";
        report << "      datasets: [\n";
        report << "        {\n";
        report << "          label: '总分配内存(MB)',\n";
        report << "          data: [" << prevReportPtr->totalAllocatedMB << ", "
            << (double)totalAllocBytes / (1024 * 1024) << "],\n";
        report << "          backgroundColor: 'rgba(54, 162, 235, 0.5)',\n";
        report << "          borderColor: 'rgba(54, 162, 235, 1)',\n";
        report << "          borderWidth: 2\n";
        report << "        },\n";
        report << "        {\n";
        report << "          label: '总释放内存(MB)',\n";
        report << "          data: [" << prevReportPtr->totalFreedMB << ", "
            << (double)totalFreeBytes / (1024 * 1024) << "],\n";
        report << "          backgroundColor: 'rgba(75, 192, 192, 0.5)',\n";
        report << "          borderColor: 'rgba(75, 192, 192, 1)',\n";
        report << "          borderWidth: 2\n";
        report << "        },\n";
        report << "        {\n";
        report << "          label: '内存泄漏(MB)',\n";
        report << "          data: [" << prevReportPtr->leakedMemoryMB << ", "
            << (double)totalLeakBytes / (1024 * 1024) << "],\n";
        report << "          backgroundColor: 'rgba(255, 99, 132, 0.5)',\n";
        report << "          borderColor: 'rgba(255, 99, 132, 1)',\n";
        report << "          borderWidth: 2\n";
        report << "        }\n";
        report << "      ]\n";
        report << "    };\n\n";
    }

    // 表格数据
    report << "    // 表格数据\n";
    report << "    const allocTableData = [];\n";
    report << "    const freeTableData = [];\n";
    report << "    const diffTableData = [];\n\n";

    // 填充表格数据
    report << "    // 填充分配表数据\n";
    for (const auto& item : allStats) {
        report << "    allocTableData.push({name: '" << item.name
            << "', size: " << item.size
            << ", allocCount: " << item.allocCount
            << ", allocSizeMB: " << std::fixed << std::setprecision(2) << (double)item.allocSize / (1024 * 1024)
            << ", peakAlloc: " << item.peakAlloc
            << "});\n";
    }
    report << "\n";

    report << "    // 填充释放表数据\n";
    for (const auto& item : allStats) {
        // 计算效率
        double efficiency = item.allocSize > 0 ?
            ((double)item.freeSize / item.allocSize) * 100.0 : 0.0;

        report << "    freeTableData.push({name: '" << item.name
            << "', size: " << item.size
            << ", freeCount: " << item.freeCount
            << ", freeSizeMB: " << std::fixed << std::setprecision(2) << (double)item.freeSize / (1024 * 1024)
            << ", efficiency: " << std::fixed << std::setprecision(1) << efficiency
            << "});\n";
    }
    report << "\n";

    report << "    // 填充差异表数据\n";
    for (const auto& item : allStats) {
        // 只有存在未释放的才加入差异表
        if (item.unreleased > 0) {
            report << "    diffTableData.push({name: '" << item.name
                << "', size: " << item.size
                << ", allocCount: " << item.allocCount
                << ", freeCount: " << item.freeCount
                << ", unreleased: " << item.unreleased
                << ", leakSizeMB: " << std::fixed << std::setprecision(2) << (double)item.leakSize / (1024 * 1024)
                << "});\n";
        }
    }
    report << "\n";

    // 页面加载函数
    report << "    // 页面加载完成后初始化\n";
    report << "    document.addEventListener('DOMContentLoaded', function() {\n";

    // 绘制内存分布图表
    report << "      // 绘制内存分布图表\n";
    report << "      const memDistCtx = document.getElementById('memoryDistributionChart').getContext('2d');\n";
    report << "      new Chart(memDistCtx, {\n";
    report << "        type: 'bar',\n";
    report << "        data: memoryDistributionData,\n";
    report << "        options: {\n";
    report << "          responsive: true,\n";
    report << "          maintainAspectRatio: false,\n";
    report << "          plugins: {\n";
    report << "            legend: { display: false },\n";
    report << "            tooltip: {\n";
    report << "              callbacks: {\n";
    report << "                label: function(context) {\n";
    report << "                  return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "                }\n";
    report << "              }\n";
    report << "            }\n";
    report << "          },\n";
    report << "          scales: { y: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "        }\n";
    report << "      });\n\n";

    // 绘制资源类型分布图表
    report << "      // 绘制资源类型分布图表\n";
    report << "      const typeCtx = document.getElementById('resourceTypeChart').getContext('2d');\n";
    report << "      new Chart(typeCtx, {\n";
    report << "        type: 'pie',\n";
    report << "        data: typeData,\n";
    report << "        options: {\n";
    report << "          responsive: true,\n";
    report << "          maintainAspectRatio: false,\n";
    report << "          plugins: {\n";
    report << "            legend: { position: 'right' },\n";
    report << "            tooltip: {\n";
    report << "              callbacks: {\n";
    report << "                label: function(context) {\n";
    report << "                  return context.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "                }\n";
    report << "              }\n";
    report << "            }\n";
    report << "          }\n";
    report << "        }\n";
    report << "      });\n\n";

    // 绘制Top 10分配图表
    report << "      // 绘制Top 10分配图表\n";
    report << "      const top10Ctx = document.getElementById('top10Chart').getContext('2d');\n";
    report << "      new Chart(top10Ctx, {\n";
    report << "        type: 'bar',\n";
    report << "        data: top10Data,\n";
    report << "        options: {\n";
    report << "          responsive: true,\n";
    report << "          maintainAspectRatio: false,\n";
    report << "          indexAxis: 'y',\n";
    report << "          plugins: {\n";
    report << "            legend: { display: false },\n";
    report << "            tooltip: {\n";
    report << "              callbacks: {\n";
    report << "                label: function(context) {\n";
    report << "                  return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "                }\n";
    report << "              }\n";
    report << "            }\n";
    report << "          },\n";
    report << "          scales: { x: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "        }\n";
    report << "      });\n\n";

    // 绘制泄漏图表
    report << "      // 绘制泄漏图表\n";
    report << "      const leakCtx = document.getElementById('leakChart').getContext('2d');\n";
    report << "      new Chart(leakCtx, {\n";
    report << "        type: 'bar',\n";
    report << "        data: leakData,\n";
    report << "        options: {\n";
    report << "          responsive: true,\n";
    report << "          maintainAspectRatio: false,\n";
    report << "          indexAxis: 'y',\n";
    report << "          plugins: {\n";
    report << "            legend: { display: false },\n";
    report << "            tooltip: {\n";
    report << "              callbacks: {\n";
    report << "                label: function(context) {\n";
    report << "                  return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
    report << "                }\n";
    report << "              }\n";
    report << "            }\n";
    report << "          },\n";
    report << "          scales: { x: { beginAtZero: true, title: { display: true, text: 'MB' } } }\n";
    report << "        }\n";
    report << "      });\n\n";

    // 如果有前一个报告，绘制趋势图
    if (compareWithPrevious && prevReportPtr) {
        report << "      // 绘制趋势变化图表\n";
        report << "      const trendCtx = document.getElementById('trendChart').getContext('2d');\n";
        report << "      new Chart(trendCtx, {\n";
        report << "        type: 'line',\n";
        report << "        data: trendData,\n";
        report << "        options: {\n";
        report << "          responsive: true,\n";
        report << "          maintainAspectRatio: false,\n";
        report << "          plugins: {\n";
        report << "            tooltip: {\n";
        report << "              callbacks: {\n";
        report << "                label: function(context) {\n";
        report << "                  return context.dataset.label + ': ' + context.raw.toFixed(2) + ' MB';\n";
        report << "                }\n";
        report << "              }\n";
        report << "            }\n";
        report << "          },\n";
        report << "          scales: { \n";
        report << "            y: { beginAtZero: true, title: { display: true, text: 'MB' } }\n";
        report << "          },\n";
        report << "          elements: {\n";
        report << "            line: { tension: 0.3 }, // 使线条平滑\n";
        report << "            point: { radius: 5 }\n";
        report << "          }\n";
        report << "        }\n";
        report << "      });\n\n";
    }

    // 初始化数据表格
    report << "      // 创建表格渲染函数\n";
    report << "      function renderTable(tableId, data) {\n";
    report << "        const tableBodyId = tableId + 'Body';\n";
    report << "        const tbody = document.getElementById(tableBodyId);\n";
    report << "        tbody.innerHTML = '';\n";
    report << "        \n";
    report << "        const searchText = document.getElementById('globalSearchInput').value.toLowerCase();\n";
    report << "        \n";
    report << "        // 过滤数据\n";
    report << "        const filteredData = searchText ? \n";
    report << "          data.filter(item => item.name.toLowerCase().includes(searchText)) : data;\n";
    report << "        \n";
    report << "        // 创建表格行\n";
    report << "        filteredData.forEach(item => {\n";
    report << "          const tr = document.createElement('tr');\n";
    report << "          \n";
    report << "          // 根据表格ID添加不同的单元格\n";
    report << "          if (tableId === 'allocTable') {\n";
    report << "            addCell(tr, item.name, searchText);\n";
    report << "            addCell(tr, item.size);\n";
    report << "            addCell(tr, item.allocCount);\n";
    report << "            addCell(tr, item.allocSizeMB);\n";
    report << "            addCell(tr, item.peakAlloc);\n";
    report << "          } else if (tableId === 'freeTable') {\n";
    report << "            addCell(tr, item.name, searchText);\n";
    report << "            addCell(tr, item.size);\n";
    report << "            addCell(tr, item.freeCount);\n";
    report << "            addCell(tr, item.freeSizeMB);\n";
    report << "            \n";
    report << "            // 效率单元格，颜色标记\n";
    report << "            const td = document.createElement('td');\n";
    report << "            if (item.efficiency < 90) {\n";
    report << "              td.classList.add('text-danger');\n";
    report << "            }\n";
    report << "            td.textContent = item.efficiency;\n";
    report << "            tr.appendChild(td);\n";
    report << "          } else if (tableId === 'diffTable') {\n";
    report << "            addCell(tr, item.name, searchText);\n";
    report << "            addCell(tr, item.size);\n";
    report << "            addCell(tr, item.allocCount);\n";
    report << "            addCell(tr, item.freeCount);\n";
    report << "            \n";
    report << "            // 未释放单元格，标记警告\n";
    report << "            const tdUnreleased = document.createElement('td');\n";
    report << "            tdUnreleased.classList.add('text-danger');\n";
    report << "            tdUnreleased.textContent = item.unreleased;\n";
    report << "            tr.appendChild(tdUnreleased);\n";
    report << "            \n";
    report << "            // 泄漏大小单元格，标记警告\n";
    report << "            const tdLeak = document.createElement('td');\n";
    report << "            tdLeak.classList.add('text-danger');\n";
    report << "            tdLeak.textContent = item.leakSizeMB;\n";
    report << "            tr.appendChild(tdLeak);\n";
    report << "          }\n";
    report << "          \n";
    report << "          tbody.appendChild(tr);\n";
    report << "        });\n";
    report << "        \n";
    report << "        // 如果没有数据\n";
    report << "        if (filteredData.length === 0) {\n";
    report << "          const tr = document.createElement('tr');\n";
    report << "          const td = document.createElement('td');\n";
    report << "          td.setAttribute('colspan', tableId === 'diffTable' ? '6' : '5');\n";
    report << "          td.textContent = '没有匹配的数据';\n";
    report << "          td.style.textAlign = 'center';\n";
    report << "          tr.appendChild(td);\n";
    report << "          tbody.appendChild(tr);\n";
    report << "        }\n";
    report << "      }\n\n";

    // 添加单元格辅助函数
    report << "      // 添加表格单元格，支持搜索高亮\n";
    report << "      function addCell(tr, content, searchText = '') {\n";
    report << "        const td = document.createElement('td');\n";
    report << "        \n";
    report << "        if (searchText && typeof content === 'string' && content.toLowerCase().includes(searchText)) {\n";
    report << "          // 高亮搜索匹配文本\n";
    report << "          const regex = new RegExp(`(${searchText})`, 'gi');\n";
    report << "          td.innerHTML = content.replace(regex, '<span class=\"bg-warning\">$1</span>');\n";
    report << "        } else {\n";
    report << "          td.textContent = content;\n";
    report << "        }\n";
    report << "        \n";
    report << "        tr.appendChild(td);\n";
    report << "      }\n\n";

    // 初始化表格
    report << "      // 初始化表格\n";
    report << "      renderTable('allocTable', allocTableData);\n";
    report << "      renderTable('freeTable', freeTableData);\n";
    report << "      renderTable('diffTable', diffTableData);\n\n";

    // 设置搜索功能
    report << "      // 设置搜索功能\n";
    report << "      const searchInput = document.getElementById('globalSearchInput');\n";
    report << "      searchInput.addEventListener('input', function() {\n";
    report << "        // 获取当前活动的选项卡\n";
    report << "        const activeTab = document.querySelector('.tab-pane.active');\n";
    report << "        const activeTabId = activeTab.id;\n";
    report << "        \n";
    report << "        // 根据活动选项卡更新对应表格\n";
    report << "        if (activeTabId === 'alloc-tab-pane') {\n";
    report << "          renderTable('allocTable', allocTableData);\n";
    report << "        } else if (activeTabId === 'free-tab-pane') {\n";
    report << "          renderTable('freeTable', freeTableData);\n";
    report << "        } else if (activeTabId === 'diff-tab-pane') {\n";
    report << "          renderTable('diffTable', diffTableData);\n";
    report << "        }\n";
    report << "      });\n\n";

    // 设置选项卡切换事件
    report << "      // 设置选项卡切换事件\n";
    report << "      const tabButtons = document.querySelectorAll('[data-bs-toggle=\"tab\"]');\n";
    report << "      tabButtons.forEach(button => {\n";
    report << "        button.addEventListener('shown.bs.tab', function(event) {\n";
    report << "          const targetId = event.target.getAttribute('data-bs-target');\n";
    report << "          const targetPaneId = targetId.replace('#', '').replace('-pane', '');\n";
    report << "          \n";
    report << "          // 更新对应表格\n";
    report << "          if (targetPaneId === 'alloc-tab') {\n";
    report << "            renderTable('allocTable', allocTableData);\n";
    report << "          } else if (targetPaneId === 'free-tab') {\n";
    report << "            renderTable('freeTable', freeTableData);\n";
    report << "          } else if (targetPaneId === 'diff-tab') {\n";
    report << "            renderTable('diffTable', diffTableData);\n";
    report << "          }\n";
    report << "        });\n";
    report << "      });\n";
    report << "    });\n";
    report << "  </script>\n";

    report << "</body>\n</html>\n";

    report.close();
    LogMessage("[MemoryTracker] 生成精美报告: %s", filename);
}

// Async HTML chart report generation - 简化实现，移除std::filesystem相关依赖
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
    std::thread([this, records_snapshot, html_filename = std::string(html_filename),
        data_dir = std::string(data_dir)]() {
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
        // 检查目录是否存在
        if (!EnsureDirectoryExists(data_dir)) {
            LogMessage("[MemoryTracker] 无法创建目录: %s", data_dir.c_str());
        }

        LogMessage("[MemoryTracker] 开始异步生成内存报告: %s", html_filename.c_str());

        // 使用Bootstrap生成报告
        GenerateBootstrapHtmlReport(html_filename.c_str(), records_snapshot, true);

        // 关闭标志
        m_isGeneratingReport.store(false);
        LogMessage("[MemoryTracker] 异步内存报告已完成: %s", html_filename.c_str());
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryTracker] 生成报告异常: %s", e.what());
        m_isGeneratingReport.store(false);
    }
    catch (...) {
        LogMessage("[MemoryTracker] 生成报告出现未知错误");
        m_isGeneratingReport.store(false);
    }
}