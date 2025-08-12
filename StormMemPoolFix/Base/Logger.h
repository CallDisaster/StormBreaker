#pragma once
#include "pch.h"
#include <Windows.h>
#include <stdint.h>
#include <atomic>

// ======================== 日志级别 ========================
enum class LogLevel : int {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Fatal = 4
};

// ======================== 日志系统配置 ========================
struct LoggerConfig {
    LogLevel    minLevel;           // 最小日志级别
    bool        enableConsole;      // 控制台输出
    bool        enableDebugOutput;  // 调试输出
    bool        enableFile;         // 文件输出
    bool        enableRotation;     // 日志轮转
    size_t      maxFileSize;        // 最大文件大小
    size_t      maxBackupFiles;     // 最大备份文件数
    const char* logDirectory;       // 日志目录
    const char* logFileName;        // 日志文件名
    bool        useTimestamp;       // 时间戳
    bool        useThreadId;        // 线程ID
    bool        flushImmediate;     // 立即刷新
};

// ======================== 日志系统类 ========================
class Logger {
public:
    // ======================== 单例访问 ========================
    static Logger& GetInstance();

    // ======================== 初始化和清理 ========================
    bool Initialize(const LoggerConfig& config = GetDefaultConfig());
    void Shutdown();
    bool IsInitialized() const;

    // ======================== 基础日志方法 ========================
    void LogDebug(const char* format, ...);
    void LogInfo(const char* format, ...);
    void LogWarning(const char* format, ...);
    void LogError(const char* format, ...);
    void LogFatal(const char* format, ...);

    // ======================== 通用日志方法 ========================
    void Log(LogLevel level, const char* format, ...);
    void LogV(LogLevel level, const char* format, va_list args);

    // ======================== 条件日志 ========================
    void LogIf(bool condition, LogLevel level, const char* format, ...);
    void LogDebugIf(bool condition, const char* format, ...);
    void LogInfoIf(bool condition, const char* format, ...);
    void LogWarningIf(bool condition, const char* format, ...);
    void LogErrorIf(bool condition, const char* format, ...);

    // ======================== 特殊日志类型 ========================
    void LogMemory(const char* operation, void* ptr, size_t size, const char* context = nullptr);
    void LogPerformance(const char* operation, DWORD timeMs, const char* details = nullptr);
    void LogException(DWORD exceptionCode, void* exceptionAddress, const char* context = nullptr);

    // ======================== 配置管理 ========================
    void SetMinLevel(LogLevel level);
    LogLevel GetMinLevel() const;
    void SetConfig(const LoggerConfig& config);
    LoggerConfig GetConfig() const;

    // ======================== 运行时控制 ========================
    void EnableConsoleOutput(bool enable);
    void EnableFileOutput(bool enable);
    void EnableDebugOutput(bool enable);
    void SetFlushImmediate(bool enable);
    void FlushLogs();

    // ======================== 文件管理 ========================
    void RotateLogFile();
    void ClearLogFile();
    size_t GetLogFileSize() const;
    const char* GetLogFilePath() const;

    // ======================== 统计信息 ========================
    struct LogStats {
        uint64_t debugCount;
        uint64_t infoCount;
        uint64_t warningCount;
        uint64_t errorCount;
        uint64_t fatalCount;
        uint64_t totalLines;
        uint64_t totalBytes;
        uint64_t droppedMessages;
        DWORD    lastLogTime;
    };

    LogStats GetStats() const;
    void ResetStats();

    // ======================== 默认配置 ========================
    static LoggerConfig GetDefaultConfig();
    static LoggerConfig GetDebugConfig();
    static LoggerConfig GetReleaseConfig();

    // ======================== 工具方法 ========================
    static const char* LevelToString(LogLevel level);
    static LogLevel StringToLevel(const char* str);
    static const char* GetTimeStamp();
    static DWORD GetCurrentThreadId();

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // 内部实现
    void WriteLog(LogLevel level, const char* message);
    void WriteToConsole(LogLevel level, const char* message);
    void WriteToDebugOutput(LogLevel level, const char* message);
    void WriteToFile(LogLevel level, const char* message);
    bool OpenLogFile();
    void CloseLogFile();
    void PerformRotation();
    void FormatMessage(char* buffer, size_t bufferSize, LogLevel level, const char* message);

private:
    LoggerConfig        m_config;
    std::atomic<bool>   m_initialized{ false };
    HANDLE              m_logFile{ INVALID_HANDLE_VALUE };
    mutable CRITICAL_SECTION m_criticalSection;

    // 统计信息
    mutable std::atomic<uint64_t> m_stats[5]; // Debug, Info, Warning, Error, Fatal
    mutable std::atomic<uint64_t> m_totalLines{ 0 };
    mutable std::atomic<uint64_t> m_totalBytes{ 0 };
    mutable std::atomic<uint64_t> m_droppedMessages{ 0 };
    mutable std::atomic<DWORD>    m_lastLogTime{ 0 };

    // 文件信息
    char m_logFilePath[MAX_PATH];
    std::atomic<size_t> m_currentFileSize{ 0 };
};

// ======================== 便利宏 ========================
#define LOG_DEBUG(...)    Logger::GetInstance().LogDebug(__VA_ARGS__)
#define LOG_INFO(...)     Logger::GetInstance().LogInfo(__VA_ARGS__)
#define LOG_WARNING(...)  Logger::GetInstance().LogWarning(__VA_ARGS__)
#define LOG_ERROR(...)    Logger::GetInstance().LogError(__VA_ARGS__)
#define LOG_FATAL(...)    Logger::GetInstance().LogFatal(__VA_ARGS__)

#define LOG_DEBUG_IF(cond, ...)    Logger::GetInstance().LogDebugIf(cond, __VA_ARGS__)
#define LOG_INFO_IF(cond, ...)     Logger::GetInstance().LogInfoIf(cond, __VA_ARGS__)
#define LOG_WARNING_IF(cond, ...)  Logger::GetInstance().LogWarningIf(cond, __VA_ARGS__)
#define LOG_ERROR_IF(cond, ...)    Logger::GetInstance().LogErrorIf(cond, __VA_ARGS__)

#define LOG_MEMORY(op, ptr, size)  Logger::GetInstance().LogMemory(op, ptr, size, __FUNCTION__)
#define LOG_PERF(op, time)         Logger::GetInstance().LogPerformance(op, time, __FUNCTION__)

// ======================== 条件编译 ========================
#ifdef _DEBUG
#define LOG_DEBUG_ENABLED 1
#else
#define LOG_DEBUG_ENABLED 0
#endif

#if LOG_DEBUG_ENABLED
#define DEBUG_LOG(...) LOG_DEBUG(__VA_ARGS__)
#else
#define DEBUG_LOG(...) ((void)0)
#endif

// ======================== 性能监控器 ========================
class PerformanceTimer {
public:
    explicit PerformanceTimer(const char* operation);
    ~PerformanceTimer();

    void Stop();
    DWORD GetElapsedMs() const;

private:
    const char* m_operation;
    DWORD m_startTime;
    bool m_stopped;
};

#define PERF_TIMER(op) PerformanceTimer _timer(op)
#define PERF_SCOPE(op) PerformanceTimer _scope_timer(op)