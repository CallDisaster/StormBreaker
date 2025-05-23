#include "pch.h"
#include "StormDiagnostic.h"
#include "StormCompatible.h" 
#include "StormHook.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

namespace StormDiagnostic {

    std::unique_ptr<DiagnosticTool> DiagnosticTool::instance_;
    std::once_flag DiagnosticTool::initFlag_;

    DiagnosticTool::DiagnosticTool() : level_(DiagnosticLevel::None), logToFile_(false) {
        memset(&systemInfo_, 0, sizeof(systemInfo_));
    }

    DiagnosticTool::~DiagnosticTool() {
        Shutdown();
    }

    DiagnosticTool& DiagnosticTool::GetInstance() {
        std::call_once(initFlag_, []() {
            instance_ = std::make_unique<DiagnosticTool>();
            });
        return *instance_;
    }

    bool DiagnosticTool::Initialize(DiagnosticLevel level, bool logToFile) {
        std::lock_guard<std::mutex> lock(mutex_);

        level_ = level;
        logToFile_ = logToFile;

        if (logToFile_ && level_ != DiagnosticLevel::None) {
            logFile_.open("StormDiagnostic.log", std::ios::out | std::ios::app);
            if (!logFile_.is_open()) {
                printf("[Diagnostic] 无法打开诊断日志文件\n");
                return false;
            }

            auto now = std::chrono::system_clock::now();
            std::time_t t = std::time(nullptr);

            char buf[64]; // 足够保存时间字符串

            // ctime_s(目标缓冲区, 缓冲区大小, 时间指针)
            if (ctime_s(buf, sizeof(buf), &t) == 0) {
                size_t len = std::strlen(buf);
                if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

                logFile_ << "\n=== Storm 诊断工具启动 (" << buf << ") ===\n";
            }
            else {
                logFile_ << "\n=== Storm 诊断工具启动 (无法获取当前时间) ===\n";
            }
            logFile_.flush();
        }

        blockInfos_.clear();
        LogMessage("[Diagnostic] 诊断工具初始化完成，级别: " + std::to_string(static_cast<int>(level_)));
        return true;
    }

    void DiagnosticTool::Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);

        if (level_ != DiagnosticLevel::None) {
            LogMessage("[Diagnostic] 诊断工具关闭");

            if (level_ >= DiagnosticLevel::Detailed) {
                GenerateTextReport("FinalDiagnostic.txt");
                GenerateHtmlReport("FinalDiagnostic.html");
            }

            auto leaks = DetectMemoryLeaks();
            if (!leaks.empty()) {
                LogMessage("[Diagnostic] 检测到 " + std::to_string(leaks.size()) + " 个内存泄漏");
            }
        }

        if (logFile_.is_open()) {
            logFile_.close();
        }

        level_ = DiagnosticLevel::None;
    }

    void DiagnosticTool::SetDiagnosticLevel(DiagnosticLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        level_ = level;
        LogMessage("[Diagnostic] 诊断级别更改为: " + std::to_string(static_cast<int>(level_)));
    }

    void DiagnosticTool::RecordBlockAllocation(void* userPtr, void* rawPtr, size_t size,
        const char* source, DWORD srcLine, DWORD flags) {

        if (level_ < DiagnosticLevel::Detailed) return;

        std::lock_guard<std::mutex> lock(mutex_);

        BlockDiagnosticInfo info;
        info.userPtr = userPtr;
        info.rawPtr = rawPtr;
        info.size = size;
        info.totalSize = size + sizeof(StormCompatible::StormBlockHeader);
        info.allocTime = GetTickCount();
        info.flags = flags;
        info.source = source ? source : "unknown";
        info.srcLine = srcLine;
        info.threadId = GetCurrentThreadId();
        info.isValid = true;

        blockInfos_[userPtr] = info;

        if (level_ >= DiagnosticLevel::Full) {
            LogMessage("[Diagnostic] 记录分配: " + std::to_string(reinterpret_cast<uintptr_t>(userPtr)) +
                ", 大小: " + std::to_string(size) + ", 源: " + info.source);
        }
    }

    void DiagnosticTool::RecordBlockDeallocation(void* userPtr) {
        if (level_ < DiagnosticLevel::Detailed) return;

        std::lock_guard<std::mutex> lock(mutex_);

        auto it = blockInfos_.find(userPtr);
        if (it != blockInfos_.end()) {
            if (level_ >= DiagnosticLevel::Full) {
                DWORD lifetime = GetTickCount() - it->second.allocTime;
                LogMessage("[Diagnostic] 记录释放: " + std::to_string(reinterpret_cast<uintptr_t>(userPtr)) +
                    ", 生存期: " + FormatTime(lifetime));
            }
            blockInfos_.erase(it);
        }
    }

    bool DiagnosticTool::ValidateBlock(void* userPtr, std::string& errorMsg) {
        if (!userPtr) {
            errorMsg = "空指针";
            return false;
        }

        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        if (!allocator.IsOurPointer(userPtr)) {
            errorMsg = "不是我们管理的指针";
            return false;
        }

        StormCompatible::StormBlockHeader* header = StormCompatible::StormBlockHeader::FromUserPtr(userPtr);

        if (!header) {
            errorMsg = "无法获取块头";
            return false;
        }

        if (!header->IsValid()) {
            errorMsg = "块头魔数无效";
            return false;
        }

        if (header->IsFree()) {
            errorMsg = "块已被释放";
            return false;
        }

        if (header->HasBoundaryCheck()) {
            WORD* boundaryMagic = header->GetBoundaryMagic();
            if (boundaryMagic && *boundaryMagic != 0x12B1) {
                errorMsg = "边界魔数损坏";
                return false;
            }
        }

        return true;
    }

    void DiagnosticTool::UpdateSystemInfo() {
        if (level_ < DiagnosticLevel::Basic) return;

        std::lock_guard<std::mutex> lock(mutex_);

        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        size_t allocated, freed, allocCount, freeCount;
        allocator.GetStatistics(allocated, freed, allocCount, freeCount);

        systemInfo_.totalAllocated = allocated;
        systemInfo_.totalFreed = freed;
        systemInfo_.currentUsed = (allocated > freed) ? (allocated - freed) : 0;
        systemInfo_.peakUsed = max(systemInfo_.peakUsed, systemInfo_.currentUsed);
        systemInfo_.fragmentationRate = 0.0;
        systemInfo_.hitRate = (allocCount + freeCount > 0) ?
            (static_cast<double>(allocCount) / (allocCount + freeCount)) : 0.0;
        systemInfo_.uptime = GetTickCount();
    }

    SystemDiagnosticInfo DiagnosticTool::GetSystemInfo() {
        UpdateSystemInfo();
        std::lock_guard<std::mutex> lock(mutex_);
        return systemInfo_;
    }

    void DiagnosticTool::GenerateTextReport(const std::string& filename) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::ofstream file(filename);
        if (!file.is_open()) {
            LogMessage("[Diagnostic] 无法打开报告文件: " + filename);
            return;
        }

        file << "=== Storm 内存池诊断报告 ===\n";
        file << "生成时间: " << FormatTime(GetTickCount()) << "\n\n";

        file << "=== 系统统计 ===\n";
        file << "总分配: " << FormatSize(systemInfo_.totalAllocated) << "\n";
        file << "总释放: " << FormatSize(systemInfo_.totalFreed) << "\n";
        file << "当前使用: " << FormatSize(systemInfo_.currentUsed) << "\n";
        file << "峰值使用: " << FormatSize(systemInfo_.peakUsed) << "\n";
        file << "运行时间: " << FormatTime(systemInfo_.uptime) << "\n\n";

        if (level_ >= DiagnosticLevel::Detailed && !blockInfos_.empty()) {
            file << "=== 活跃内存块 (" << blockInfos_.size() << " 个) ===\n";

            for (const auto& pair : blockInfos_) {
                const auto& info = pair.second;
                file << "地址: " << std::hex << reinterpret_cast<uintptr_t>(info.userPtr) << std::dec;
                file << ", 大小: " << FormatSize(info.size);
                file << ", 源: " << info.source;
                if (info.srcLine > 0) {
                    file << ":" << info.srcLine;
                }
                file << ", 生存期: " << FormatTime(GetTickCount() - info.allocTime) << "\n";
            }
            file << "\n";
        }

        file.close();
        LogMessage("[Diagnostic] 文本报告已生成: " + filename);
    }

    void DiagnosticTool::GenerateHtmlReport(const std::string& filename) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::ofstream file(filename);
        if (!file.is_open()) {
            LogMessage("[Diagnostic] 无法打开HTML报告文件: " + filename);
            return;
        }

        file << "<!DOCTYPE html>\n<html>\n<head>\n";
        file << "<title>Storm 内存池诊断报告</title>\n";
        file << "<style>\n";
        file << "body { font-family: 'Consolas', monospace; margin: 20px; }\n";
        file << "table { border-collapse: collapse; width: 100%; }\n";
        file << "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
        file << "th { background-color: #f2f2f2; }\n";
        file << ".metric { background-color: #e6f3ff; padding: 10px; margin: 10px 0; }\n";
        file << "</style>\n</head>\n<body>\n";

        file << "<h1>Storm 内存池诊断报告</h1>\n";
        file << "<p>生成时间: " << FormatTime(GetTickCount()) << "</p>\n";

        file << "<div class='metric'>\n";
        file << "<h2>系统统计</h2>\n";
        file << "<p>总分配: " << FormatSize(systemInfo_.totalAllocated) << "</p>\n";
        file << "<p>总释放: " << FormatSize(systemInfo_.totalFreed) << "</p>\n";
        file << "<p>当前使用: " << FormatSize(systemInfo_.currentUsed) << "</p>\n";
        file << "<p>峰值使用: " << FormatSize(systemInfo_.peakUsed) << "</p>\n";
        file << "<p>运行时间: " << FormatTime(systemInfo_.uptime) << "</p>\n";
        file << "</div>\n";

        if (level_ >= DiagnosticLevel::Detailed && !blockInfos_.empty()) {
            file << "<h2>活跃内存块 (" << blockInfos_.size() << " 个)</h2>\n";
            file << "<table>\n<tr><th>地址</th><th>大小</th><th>源</th><th>行号</th><th>生存期</th></tr>\n";

            for (const auto& pair : blockInfos_) {
                const auto& info = pair.second;
                file << "<tr>";
                file << "<td>0x" << std::hex << reinterpret_cast<uintptr_t>(info.userPtr) << std::dec << "</td>";
                file << "<td>" << FormatSize(info.size) << "</td>";
                file << "<td>" << info.source << "</td>";
                file << "<td>" << info.srcLine << "</td>";
                file << "<td>" << FormatTime(GetTickCount() - info.allocTime) << "</td>";
                file << "</tr>\n";
            }
            file << "</table>\n";
        }

        file << "</body>\n</html>\n";
        file.close();

        LogMessage("[Diagnostic] HTML报告已生成: " + filename);
    }

    std::vector<BlockDiagnosticInfo> DiagnosticTool::DetectMemoryLeaks() {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<BlockDiagnosticInfo> leaks;
        DWORD currentTime = GetTickCount();

        for (const auto& pair : blockInfos_) {
            const auto& info = pair.second;
            if (currentTime - info.allocTime > 30000) {
                leaks.push_back(info);
            }
        }

        return leaks;
    }

    void DiagnosticTool::PrintMemoryLeaks() {
        auto leaks = DetectMemoryLeaks();

        if (leaks.empty()) {
            LogMessage("[Diagnostic] 未检测到内存泄漏");
            return;
        }

        LogMessage("[Diagnostic] 检测到 " + std::to_string(leaks.size()) + " 个可能的内存泄漏:");

        size_t totalLeaked = 0;
        for (const auto& leak : leaks) {
            totalLeaked += leak.size;
            LogMessage("[Diagnostic] 泄漏: " + std::to_string(reinterpret_cast<uintptr_t>(leak.userPtr)) +
                ", 大小: " + FormatSize(leak.size) +
                ", 源: " + leak.source +
                ", 生存期: " + FormatTime(GetTickCount() - leak.allocTime));
        }

        LogMessage("[Diagnostic] 总泄漏: " + FormatSize(totalLeaked));
    }

    void DiagnosticTool::LogMessage(const std::string& message) {
        printf("%s\n", message.c_str());

        if (logFile_.is_open()) {
            logFile_ << message << std::endl;
            logFile_.flush();
        }
    }

    std::string DiagnosticTool::FormatSize(size_t bytes) {
        std::ostringstream oss;

        if (bytes >= 1024 * 1024 * 1024) {
            oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
        }
        else if (bytes >= 1024 * 1024) {
            oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0)) << " MB";
        }
        else if (bytes >= 1024) {
            oss << std::fixed << std::setprecision(2) << (bytes / 1024.0) << " KB";
        }
        else {
            oss << bytes << " B";
        }

        return oss.str();
    }

    std::string DiagnosticTool::FormatTime(DWORD timeMs) {
        DWORD seconds = timeMs / 1000;
        DWORD minutes = seconds / 60;
        DWORD hours = minutes / 60;

        std::ostringstream oss;
        if (hours > 0) {
            oss << hours << "h " << (minutes % 60) << "m " << (seconds % 60) << "s";
        }
        else if (minutes > 0) {
            oss << minutes << "m " << (seconds % 60) << "s";
        }
        else {
            oss << seconds << "s";
        }

        return oss.str();
    }

    // 便利函数实现
    void EnableDiagnostics(DiagnosticLevel level) {
        DiagnosticTool::GetInstance().Initialize(level, true);
    }

    void DisableDiagnostics() {
        DiagnosticTool::GetInstance().Shutdown();
    }

    void GenerateDiagnosticReport(const std::string& filename) {
        DiagnosticTool::GetInstance().GenerateHtmlReport(filename);
    }

    void CheckMemoryLeaks() {
        DiagnosticTool::GetInstance().PrintMemoryLeaks();
    }

    void PrintQuickStats() {
        auto info = DiagnosticTool::GetInstance().GetSystemInfo();

        printf("[快速统计] 当前使用: %s, 峰值: %s, 运行时间: %s\n",
            DiagnosticTool::GetInstance().FormatSize(info.currentUsed).c_str(),
            DiagnosticTool::GetInstance().FormatSize(info.peakUsed).c_str(),
            DiagnosticTool::GetInstance().FormatTime(info.uptime).c_str());
    }
} // namespace StormDiagnostic