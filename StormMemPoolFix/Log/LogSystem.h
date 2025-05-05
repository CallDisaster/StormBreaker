#ifndef LOG_SYSTEM_H
#define LOG_SYSTEM_H
#pragma message("Including LogSystem.h")
#include <Windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <thread>
#include <queue>
#include <condition_variable>

// 日志级别枚举
enum class LogLevel {
    Debug,   // 调试信息
    Info,    // 一般信息
    Warning, // 警告信息
    Error,   // 错误信息
    None     // 不记录日志
};

// 日志条目结构
struct LogEntry {
    std::string message;
    LogLevel level;
    SYSTEMTIME timestamp;
};

// 异步日志系统类 - 单例模式
class LogSystem {
public:
    // 获取唯一实例
    static LogSystem& GetInstance();

    // 禁止复制构造和赋值操作
    LogSystem(const LogSystem&) = delete;
    LogSystem& operator=(const LogSystem&) = delete;

    // 初始化日志系统
    bool Initialize(const char* logFileName = "MemoryTracker.log", LogLevel minLevel = LogLevel::Info);

    // 关闭日志系统
    void Shutdown();

    // 记录日志消息
    void Log(const char* format, ...);

    // 带级别的日志记录
    void LogWithLevel(LogLevel level, const char* format, ...);

    // 设置日志级别
    void SetLogLevel(LogLevel level);

    // 获取当前日志级别
    LogLevel GetLogLevel() const;

    // 刷新缓冲区，确保所有日志都写入文件
    void Flush();

private:
    // 私有构造函数 - 单例模式
    LogSystem();
    ~LogSystem();

    // 日志处理线程函数
    void LogThreadFunc();

    // 添加日志条目到队列
    void AddLogEntry(LogEntry&& entry);

    // 格式化日志消息
    std::string FormatLogMessage(const char* format, va_list args);

    // 将日志级别转换为字符串
    const char* LogLevelToString(LogLevel level);

    // 成员变量
    std::atomic<bool> m_initialized;         // 初始化标志
    std::atomic<bool> m_shuttingDown;        // 关闭标志
    std::atomic<LogLevel> m_logLevel;        // 当前日志级别

    std::string m_logFileName;               // 日志文件名
    FILE* m_logFile;                         // 日志文件句柄

    std::mutex m_queueMutex;                 // 队列互斥锁
    std::condition_variable m_queueCV;       // 队列条件变量
    std::queue<LogEntry> m_logQueue;         // 日志队列

    std::thread m_logThread;                 // 日志处理线程
};

// 全局日志函数 - 这些将替代原有 LogMessage 函数
void LogMessage(const char* format, ...);
void LogDebug(const char* format, ...);
void LogInfo(const char* format, ...);
void LogWarning(const char* format, ...);
void LogError(const char* format, ...);

// 日志宏 - 提供更方便的调用方式
#define LOG_DEBUG(format, ...) LogSystem::GetInstance().LogWithLevel(LogLevel::Debug, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LogSystem::GetInstance().LogWithLevel(LogLevel::Info, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) LogSystem::GetInstance().LogWithLevel(LogLevel::Warning, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LogSystem::GetInstance().LogWithLevel(LogLevel::Error, format, ##__VA_ARGS__)

// 条件日志宏 - 仅在符合条件时记录日志
#define LOG_IF(condition, level, format, ...) \
    if (condition) { LogSystem::GetInstance().LogWithLevel(level, format, ##__VA_ARGS__); }

#endif // LOG_SYSTEM_H