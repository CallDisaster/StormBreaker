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
#include <memory>
#include <ctime>
#include <Storm/StormHook.h>
#include <direct.h> // For _mkdir
#include <Utils/Resource/WebResourceExtractor.h>

// 全局实例定义
MemoryTracker g_memoryTracker;
std::atomic<LogLevel> g_currentLogLevel{ LogLevel::Info };

// Global log file pointer
static FILE* g_logFile = nullptr;
bool g_fastMode = false;

//class SafeFileOperations {
//private:
//    static std::mutex fileMutex_;
//    static std::atomic<bool> fileOperationInProgress_;
//
//public:
//    static bool SafeRename_SEH(const char* oldPath, const char* newPath) {
//        // 只做无对象/无RAII的裸C风格操作
//        // 注意这里不能有std::string/lock_guard等C++对象
//        // 检查源文件
//        if (GetFileAttributesA(oldPath) == INVALID_FILE_ATTRIBUTES) {
//            return false;
//        }
//        // 如果目标文件存在，先删除
//        if (GetFileAttributesA(newPath) != INVALID_FILE_ATTRIBUTES) {
//            DeleteFileA(newPath); // 失败直接跳过
//        }
//        // 重命名
//        if (MoveFileA(oldPath, newPath)) {
//            return true;
//        }
//        // 尝试复制+删除
//        if (CopyFileA(oldPath, newPath, FALSE)) {
//            if (DeleteFileA(oldPath)) {
//                LogMessage("[FileOp] 通过复制+删除完成重命名: %s", newPath);
//                return true;
//            }
//        }
//        return false;
//    }
//
//    static bool SafeRename(const std::string& oldPath, const std::string& newPath) {
//        if (fileOperationInProgress_.exchange(true)) return false;
//
//        bool result = false;
//        {
//            std::lock_guard<std::mutex> lock(fileMutex_);
//            __try {
//                result = SafeRename_SEH(oldPath.c_str(), newPath.c_str());
//            }
//            __except (EXCEPTION_EXECUTE_HANDLER) {
//                LogMessage("[FileOp] 文件操作异常: 0x%08X", GetExceptionCode());
//                result = false;
//            }
//        }
//        fileOperationInProgress_.store(false);
//        return result;
//    }
//
//    static bool SafeWrite_SEH(const char* filePath, const char* content, size_t contentLen) {
//        HANDLE hFile = CreateFileA(
//            filePath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
//        );
//        if (hFile == INVALID_HANDLE_VALUE) {
//            return false;
//        }
//        DWORD bytesWritten = 0;
//        BOOL ok = WriteFile(hFile, content, static_cast<DWORD>(contentLen), &bytesWritten, nullptr);
//        CloseHandle(hFile);
//        return ok && bytesWritten == contentLen;
//    }
//
//    static bool SafeWrite(const std::string& filePath, const std::string& content) {
//        if (g_fastMode) return true;
//        if (fileOperationInProgress_.exchange(true)) return false;
//        bool result = false;
//        {
//            std::lock_guard<std::mutex> lock(fileMutex_);
//            __try {
//                result = SafeWrite_SEH(filePath.c_str(), content.c_str(), content.length());
//            }
//            __except (EXCEPTION_EXECUTE_HANDLER) {
//                LogMessage("[FileOp] 写文件异常: 0x%08X", GetExceptionCode());
//                result = false;
//            }
//        }
//        fileOperationInProgress_.store(false);
//        return result;
//    }
//
//};
//
//std::mutex SafeFileOperations::fileMutex_;
//std::atomic<bool> SafeFileOperations::fileOperationInProgress_{ false };

class NonBlockingMemoryTracker {
private:
    std::atomic<bool> reportingEnabled_{ true };
    std::atomic<DWORD> lastReportTime_{ 0 };
    HANDLE reportThread_{ nullptr };
    std::atomic<bool> shouldStop_{ false };

    // 轻量级统计
    std::atomic<size_t> allocCount_{ 0 };
    std::atomic<size_t> freeCount_{ 0 };
    std::atomic<size_t> totalAllocated_{ 0 };
    std::atomic<size_t> totalFreed_{ 0 };

public:
    void StartPeriodicReporting(DWORD intervalMs) {
        if (g_fastMode) {
            LogMessage("[MemoryTracker] 快速模式：跳过定时报告");
            return;
        }

        if (reportThread_) {
            return; // 已经启动
        }

        shouldStop_.store(false);
        reportThread_ = CreateThread(
            nullptr, 0,
            [](LPVOID param) -> DWORD {
                NonBlockingMemoryTracker* tracker = static_cast<NonBlockingMemoryTracker*>(param);
                return tracker->ReportThreadProc();
            },
            this, 0, nullptr
        );

        if (reportThread_) {
            LogMessage("[MemoryTracker] 非阻塞报告线程启动成功");
        }
    }

    void StopPeriodicReporting() {
        shouldStop_.store(true);
        if (reportThread_) {
            WaitForSingleObject(reportThread_, 2000);
            CloseHandle(reportThread_);
            reportThread_ = nullptr;
        }
    }

    void RecordAlloc(size_t size, const char* name) {
        if (!g_fastMode) {
            allocCount_.fetch_add(1, std::memory_order_relaxed);
            totalAllocated_.fetch_add(size, std::memory_order_relaxed);
        }
        // 在快速模式下什么都不做
    }

    void RecordFree(size_t size, const char* name) {
        if (!g_fastMode) {
            freeCount_.fetch_add(1, std::memory_order_relaxed);
            totalFreed_.fetch_add(size, std::memory_order_relaxed);
        }
    }

private:
    DWORD ReportThreadProc() {
        LogMessage("[MemoryTracker] 报告线程开始运行");

        while (!shouldStop_.load()) {
            // 等待30秒或直到收到停止信号
            if (WaitForSingleObject(GetCurrentThread(), 30000) == WAIT_OBJECT_0) {
                break;
            }

            if (shouldStop_.load()) {
                break;
            }

            // 生成轻量级报告
            GenerateLightweightReport();
        }

        LogMessage("[MemoryTracker] 报告线程结束");
        return 0;
    }

    void GenerateLightweightReport() {
        __try {
            DWORD currentTime = GetTickCount();

            // 只生成基本统计，不写文件
            size_t allocs = allocCount_.load();
            size_t frees = freeCount_.load();
            size_t allocated = totalAllocated_.load();
            size_t freed = totalFreed_.load();

            LogMessage("[MemoryTracker] 轻量级报告: 分配=%zu次, 释放=%zu次, 净使用=%zuMB",
                allocs, frees, (allocated - freed) / (1024 * 1024));

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 静默处理异常
        }
    }
};

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

    // 设置报告目录为硬编码的当前目录下的MemoryReports
    char currentDirBuffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDirBuffer);
    std::string currentDir = currentDirBuffer;

    // 设置报告目录
    m_reportsDirectory = currentDir + "\\MemoryReports";

    // 确保目录存在
    std::string dirPath = m_reportsDirectory;
    if (!std::filesystem::exists(dirPath)) {
        if (!std::filesystem::create_directories(dirPath)) {
            LogMessage("[MemoryTracker] 无法创建报告目录: %s", dirPath.c_str());
            // 继续执行，但后续可能会失败
        }
    }

    // 提取HTML资源到报告目录
    std::string htmlPath = dirPath + "\\index.html";
    if (!WebResourceExtractor::ExtractHtmlResource(htmlPath)) {
        LogMessage("[MemoryTracker] 警告: 无法提取HTML资源，可能无法使用可视化界面");
        // 继续执行，因为数据生成仍然可以工作
    }
    else {
        LogMessage("[MemoryTracker] 已准备可视化界面: %s", htmlPath.c_str());
    }


    LogMessage("[MemoryTracker] 初始化完成，会话ID: %s", m_sessionId.c_str());
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
// 在 MemoryTracker::PeriodicReportThreadFunc 函数中修改
void MemoryTracker::PeriodicReportThreadFunc(unsigned int period_ms) {
    while (!m_stopReporting.load()) {
        // 等待指定时间或直到停止标志被设置
        for (unsigned int i = 0; i < period_ms / 100 && !m_stopReporting.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (m_stopReporting.load()) break;

        // 生成并存储报告
        try {
            // 获取当前工作目录
            char currentDirBuffer[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, currentDirBuffer);
            std::string currentDir = currentDirBuffer;

            // 确保MemoryReports目录存在
            std::string reportsDir = currentDir + "\\MemoryReports";
            CreateDirectoryA(reportsDir.c_str(), NULL); // 创建目录，忽略已存在的情况

            // 构建JSON数据文件路径
            std::string jsonPath = reportsDir + "\\data.json";

            LogMessage("[MemoryTracker] 开始生成时间序列数据: %s", jsonPath.c_str());

            // 生成累积的JSON数据
            bool success = GenerateTimeSeriesData(jsonPath.c_str());

            if (success) {
                LogMessage("[MemoryTracker] 时间序列数据已成功更新: %s", jsonPath.c_str());
            }
            else {
                LogMessage("[MemoryTracker] 时间序列数据更新失败");
            }

            // 可选：仍然生成传统的HTML报告作为备份或兼容旧版本
            // 获取时间戳（无空格）
            //std::string timeStr = GetTimeString();
            //std::string fileName = "MemoryReport_" + timeStr + ".html";
            //std::string fullPath = reportsDir + "\\" + fileName;

            //// 生成HTML报告
            //MemoryReportData reportData = GenerateAndStoreReport(fullPath.c_str());
        }
        catch (const std::exception& e) {
            LogMessage("[MemoryTracker] 生成报告时出错: %s", e.what());
        }
        catch (...) {
            LogMessage("[MemoryTracker] 生成报告时出现未知错误");
        }
    }
}

// 创建目录
bool MemoryTracker::EnsureDirectoryExists(const std::string& dirPath) {
    if (dirPath.empty()) {
        return false;
    }

    // 检查目录是否已存在
    DWORD fileAttributes = GetFileAttributesA(dirPath.c_str());
    if (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true; // 目录已存在
    }

    // 创建父目录
    std::string parentDir;
    size_t lastSlash = dirPath.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        parentDir = dirPath.substr(0, lastSlash);
        if (!parentDir.empty() && !EnsureDirectoryExists(parentDir)) {
            LogMessage("[MemoryTracker] 无法创建父目录: %s", parentDir.c_str());
            return false;
        }
    }

    // 创建当前目录
    if (CreateDirectoryA(dirPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        LogMessage("[MemoryTracker] 成功创建目录: %s", dirPath.c_str());
        return true;
    }
    else {
        DWORD lastError = GetLastError();
        LogMessage("[MemoryTracker] 无法创建目录: %s (错误码: %d)", dirPath.c_str(), lastError);

        // 尝试使用_mkdir作为备选方法
        int result = _mkdir(dirPath.c_str());
        if (result == 0 || errno == EEXIST) {
            LogMessage("[MemoryTracker] 使用_mkdir成功创建目录: %s", dirPath.c_str());
            return true;
        }

        return false;
    }
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

    // 收集所有报告数据
    std::vector<std::pair<std::string, MemoryReportData>> allReports;

    for (const auto& file : files) {
        MemoryReportData reportData;
        if (ParseReportData(file, reportData)) {
            allReports.push_back({ file, reportData });
        }
    }

    // 按时间戳排序（最新的在前）
    std::sort(allReports.begin(), allReports.end(),
        [](const auto& a, const auto& b) {
            return a.second.timestamp > b.second.timestamp;
        });

    // 保留最近10个报告，删除其余的
    const size_t reportsToKeep = 10;
    if (allReports.size() > reportsToKeep) {
        for (size_t i = reportsToKeep; i < allReports.size(); i++) {
            if (DeleteFileA(allReports[i].first.c_str())) {
                LogMessage("[MemoryTracker] 已删除旧报告: %s", allReports[i].first.c_str());
            }
            else {
                LogMessage("[MemoryTracker] 无法删除旧报告: %s, 错误码: %d",
                    allReports[i].first.c_str(), GetLastError());
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
            // 加载所有报告，不仅限于当前会话
            m_reportHistory.push_back(reportData);
        }
    }

    // 按时间排序
    std::sort(m_reportHistory.begin(), m_reportHistory.end(),
        [](const MemoryReportData& a, const MemoryReportData& b) {
            return a.timestamp < b.timestamp;
        });

    LogMessage("[MemoryTracker] 已加载 %zu 个报告", m_reportHistory.size());
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

    // 生成报告文件路径
    std::string reportPath;

    if (filename && *filename) {
        // 检查是否路径包含目录分隔符，如果不包含，则加上目录前缀
        std::string inputPath = filename;
        if (inputPath.find('/') == std::string::npos && inputPath.find('\\') == std::string::npos) {
            // 纯文件名，添加目录前缀
            reportPath = m_reportsDirectory + "\\" + inputPath;
        }
        else {
            // 已包含路径，直接使用
            reportPath = inputPath;
        }
    }
    else {
        // 构建默认文件名
        reportPath = m_reportsDirectory + "\\MemoryReport_" + reportData.timestamp + ".html";
    }

    // 确保报告目录存在
    std::string dirPath = reportPath.substr(0, reportPath.find_last_of("\\/"));
    if (!dirPath.empty()) {
        CreateDirectoryA(dirPath.c_str(), NULL);
    }

    reportData.reportPath = reportPath;
    LogMessage("[MemoryTracker] 报告文件路径: %s", reportPath.c_str());

    // 保存到历史记录
    m_reportHistory.push_back(reportData);

    // 按时间排序
    std::sort(m_reportHistory.begin(), m_reportHistory.end(),
        [](const MemoryReportData& a, const MemoryReportData& b) {
            return a.timestamp < b.timestamp;
        });

    // 生成HTML报告
    //GenerateBootstrapHtmlReport(reportPath.c_str(), m_records, m_reportHistory.size() > 1);

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
    // 使用下划线替换空格
    strftime(buffer, sizeof(buffer), "%Y-%m-%d_%H-%M-%S", &now_tm);
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
    //GenerateBootstrapHtmlReport(filename, m_records, compareWithPrevious);

    LogMessage("[MemoryTracker] 内存图表报告已生成: %s", filename);
}

// 生成时间序列数据到JSON文件
bool MemoryTracker::GenerateTimeSeriesData(const char* jsonFilePath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    try {
        // 读取现有的JSON数据（如果有）
        std::vector<json> existingData = ReadExistingJsonData(jsonFilePath);

        // 生成当前数据点
        json currentDataPoint = GenerateCurrentDataPoint();

        // 追加当前数据点
        existingData.push_back(currentDataPoint);

        // 将整个数据数组写入临时文件
        std::string tempFilePath = std::string(jsonFilePath) + ".tmp";
        std::ofstream outFile(tempFilePath);
        if (!outFile.is_open()) {
            LogMessage("[MemoryTracker] 无法创建临时JSON文件: %s", tempFilePath.c_str());
            return false;
        }

        // 写入格式化的JSON数组
        outFile << json(existingData).dump(2);
        outFile.close();

        // 原子替换文件（重命名）
        if (std::rename(tempFilePath.c_str(), jsonFilePath) != 0) {
            LogMessage("[MemoryTracker] 无法重命名临时文件: %s -> %s",
                tempFilePath.c_str(), jsonFilePath);
            return false;
        }

        LogMessage("[MemoryTracker] 已成功更新时间序列数据，总采样点: %zu", existingData.size());
        return true;
    }
    catch (const std::exception& e) {
        LogMessage("[MemoryTracker] 生成JSON数据时出错: %s", e.what());
        return false;
    }
}

// 读取现有的JSON数据文件
std::vector<json> MemoryTracker::ReadExistingJsonData(const char* jsonFilePath) {
    std::vector<json> data;

    // 尝试打开并读取现有文件
    std::ifstream inFile(jsonFilePath);
    if (inFile.is_open()) {
        try {
            json existingData = json::parse(inFile);

            // 确保它是一个数组
            if (existingData.is_array()) {
                // 将每个元素添加到返回的向量中
                for (const auto& item : existingData) {
                    data.push_back(item);
                }
            }
        }
        catch (const std::exception& e) {
            LogMessage("[MemoryTracker] 解析现有JSON文件时出错: %s", e.what());
            // 如果解析失败，返回空数组，从头开始
        }
        inFile.close();
    }

    return data;
}

bool MemoryTracker::OpenInBrowser() const {
    // 构建HTML文件的完整路径
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);

    std::string htmlPath = std::string(currentDir) + "\\" + m_reportsDirectory + "\\index.html";

    // 使用Windows API打开默认浏览器
    HINSTANCE result = ShellExecuteA(NULL, "open", htmlPath.c_str(), NULL, NULL, SW_SHOWNORMAL);

    // 如果返回值大于32，则表示成功启动
    bool success = (reinterpret_cast<INT_PTR>(result) > 32);

    if (success) {
        LogMessage("[MemoryTracker] 已在浏览器中打开内存监控界面");
    }
    else {
        LogMessage("[MemoryTracker] 无法打开浏览器，错误码: %d", GetLastError());
    }

    return success;
}

// 生成当前时间点的数据快照
json MemoryTracker::GenerateCurrentDataPoint() {
    json dataPoint;

    // 设置时间戳（ISO 8601格式）
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
    localtime_s(&now_tm, &now_c);
    char timeBuffer[40];
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%dT%H:%M:%S%z", &now_tm);

    // 包装时区格式为标准ISO 8601格式（在+0800变为+08:00）
    std::string timeStr = timeBuffer;
    if (timeStr.length() > 5) {
        // 插入冒号到时区部分
        size_t len = timeStr.length();
        timeStr.insert(len - 2, ":");
    }

    // 设置基本字段
    dataPoint["ts"] = timeStr;
    dataPoint["sessionId"] = m_sessionId;

    // 设置当前内存使用量
    // 从GetProcessMemoryInfo获取数据（添加相应代码或从其他部分获取）
    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc))) {
        dataPoint["vmMB"] = pmc.PrivateUsage / (1024.0 * 1024.0);
    }
    else {
        dataPoint["vmMB"] = 0.0;
    }

    // 设置各类型内存分配情况
    json categories = json::object();

    for (const auto& pair : m_records) {
        std::string key = pair.first;
        const auto& record = pair.second;

        // 从键中提取类型名称
        std::string typeName = key;
        size_t delimPos = key.find('_');
        if (delimPos != std::string::npos) {
            typeName = key.substr(delimPos + 1);
        }

        // 创建此类型的数据
        json typeData;
        typeData["allocCnt"] = record.GetAllocCount();
        typeData["allocMB"] = record.GetTotalAllocSize() / (1024.0 * 1024.0);
        typeData["freeCnt"] = record.GetFreeCount();
        typeData["freeMB"] = record.GetTotalFreeSize() / (1024.0 * 1024.0);

        // 添加到分类中
        categories[typeName] = typeData;
    }

    dataPoint["categories"] = categories;

    return dataPoint;
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
        //GenerateBootstrapHtmlReport(html_filename.c_str(), records_snapshot, true);

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