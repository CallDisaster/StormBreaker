#pragma once
#include "pch.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <mutex>

namespace StormDiagnostic {

    // 诊断级别
    enum class DiagnosticLevel {
        None = 0,
        Basic = 1,
        Detailed = 2,
        Full = 3
    };

    // 内存块诊断信息
    struct BlockDiagnosticInfo {
        void* userPtr;
        void* rawPtr;
        size_t size;
        size_t totalSize;
        DWORD allocTime;
        DWORD flags;
        std::string source;
        DWORD srcLine;
        DWORD threadId;
        bool isValid;
        std::string errorMsg;

        BlockDiagnosticInfo() : userPtr(nullptr), rawPtr(nullptr), size(0), totalSize(0),
            allocTime(0), flags(0), srcLine(0), threadId(0), isValid(false) {
        }
    };

    // 系统诊断信息
    struct SystemDiagnosticInfo {
        size_t totalAllocated;
        size_t totalFreed;
        size_t currentUsed;
        size_t peakUsed;
        double fragmentationRate;
        double hitRate;
        size_t hookInterceptions;
        size_t hookFallbacks;
        DWORD uptime;
    };

    // 诊断工具类
    class DiagnosticTool {
    private:
        DiagnosticLevel level_;
        std::mutex mutex_;
        std::ofstream logFile_;
        bool logToFile_;

        std::unordered_map<void*, BlockDiagnosticInfo> blockInfos_;
        SystemDiagnosticInfo systemInfo_;

        static std::unique_ptr<DiagnosticTool> instance_;
        static std::once_flag initFlag_;

    public:
        DiagnosticTool();
        ~DiagnosticTool();

        std::string FormatSize(size_t bytes);
        std::string FormatTime(DWORD timeMs);

        static DiagnosticTool& GetInstance();

        bool Initialize(DiagnosticLevel level = DiagnosticLevel::Basic, bool logToFile = true);
        void Shutdown();

        void SetDiagnosticLevel(DiagnosticLevel level);
        DiagnosticLevel GetDiagnosticLevel() const { return level_; }

        void RecordBlockAllocation(void* userPtr, void* rawPtr, size_t size, const char* source, DWORD srcLine, DWORD flags);
        void RecordBlockDeallocation(void* userPtr);
        bool ValidateBlock(void* userPtr, std::string& errorMsg);

        void UpdateSystemInfo();
        SystemDiagnosticInfo GetSystemInfo();

        void GenerateTextReport(const std::string& filename);
        void GenerateHtmlReport(const std::string& filename);

        std::vector<BlockDiagnosticInfo> DetectMemoryLeaks();
        void PrintMemoryLeaks();

    private:
        void LogMessage(const std::string& message);
    };

    // 便利函数
    void EnableDiagnostics(DiagnosticLevel level = DiagnosticLevel::Basic);
    void DisableDiagnostics();
    void GenerateDiagnosticReport(const std::string& filename = "StormDiagnostic.html");
    void CheckMemoryLeaks();
    void PrintQuickStats();

} // namespace StormDiagnostic