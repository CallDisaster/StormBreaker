#include "pch.h"
#include "LogSystem.h"
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

// 单例实例获取
LogSystem& LogSystem::GetInstance() {
    static LogSystem instance;
    return instance;
}

// 构造函数
LogSystem::LogSystem()
    : m_initialized(false),
    m_shuttingDown(false),
    m_logLevel(LogLevel::Info),
    m_logFile(nullptr) {
}

// 析构函数
LogSystem::~LogSystem() {
    // 确保关闭
    Shutdown();
}

// 初始化日志系统
bool LogSystem::Initialize(const char* logFileName, LogLevel minLevel) {
    if (m_initialized.exchange(true))
        return true;

    m_logFileName = logFileName;
    m_logLevel.store(minLevel);
    m_shuttingDown.store(false);

    errno_t err = fopen_s(&m_logFile, logFileName, "a");
    if (err != 0 || !m_logFile) {
        std::cerr << "无法打开日志文件: " << logFileName
            << " (errno=" << err << ")" << std::endl;
        m_initialized.store(false);
        return false;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(m_logFile, "\n\n===== 日志系统启动 =====\n");
    fprintf(m_logFile, "时间: %04d-%02d-%02d %02d:%02d:%02d\n\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    fflush(m_logFile);

    m_logThread = std::thread(&LogSystem::LogThreadFunc, this);
    return true;
}

// 关闭日志系统
void LogSystem::Shutdown() {
    // 防止重复关闭
    if (!m_initialized.load() || m_shuttingDown.exchange(true)) {
        return;
    }

    // 通知日志线程退出
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_queueCV.notify_all();
    }

    // 等待日志线程完成
    if (m_logThread.joinable()) {
        m_logThread.join();
    }

    // 写入日志尾部并关闭文件
    if (m_logFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(m_logFile, "\n===== 日志系统关闭 =====\n");
        fprintf(m_logFile, "时间: %04d-%02d-%02d %02d:%02d:%02d\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fclose(m_logFile);
        m_logFile = nullptr;
    }

    m_initialized.store(false);
}

// 记录日志消息（默认使用 Info 级别）
void LogSystem::Log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::string message = FormatLogMessage(format, args);
    va_end(args);

    LogEntry entry;
    entry.message = std::move(message);
    entry.level = LogLevel::Info;
    GetLocalTime(&entry.timestamp);

    AddLogEntry(std::move(entry));
}

// 带级别的日志记录
void LogSystem::LogWithLevel(LogLevel level, const char* format, ...) {
    // 检查日志级别
    if (level < m_logLevel.load() || !m_initialized.load()) {
        return;
    }

    va_list args;
    va_start(args, format);
    std::string message = FormatLogMessage(format, args);
    va_end(args);

    LogEntry entry;
    entry.message = std::move(message);
    entry.level = level;
    GetLocalTime(&entry.timestamp);

    AddLogEntry(std::move(entry));
}

// 设置日志级别
void LogSystem::SetLogLevel(LogLevel level) {
    m_logLevel.store(level);
}

// 获取当前日志级别
LogLevel LogSystem::GetLogLevel() const {
    return m_logLevel.load();
}

// 刷新缓冲区
void LogSystem::Flush() {
    if (m_logFile) {
        fflush(m_logFile);
    }
}

// 日志处理线程函数
void LogSystem::LogThreadFunc() {
    std::queue<LogEntry> localQueue;

    while (!m_shuttingDown.load()) {
        // 等待新的日志条目或关闭信号
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // 使用条件变量等待，避免忙等
            m_queueCV.wait_for(lock, std::chrono::milliseconds(100),
                [this] { return !m_logQueue.empty() || m_shuttingDown.load(); });

            // 如果队列为空且正在关闭，则退出
            if (m_logQueue.empty() && m_shuttingDown.load()) {
                break;
            }

            // 快速交换队列，减少锁持有时间
            if (!m_logQueue.empty()) {
                localQueue.swap(m_logQueue);
            }
        }

        // 处理本地队列中的日志
        while (!localQueue.empty()) {
            const LogEntry& entry = localQueue.front();

            if (m_logFile) {
                // 格式化日志条目并写入文件
                fprintf(m_logFile, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
                    entry.timestamp.wYear, entry.timestamp.wMonth, entry.timestamp.wDay,
                    entry.timestamp.wHour, entry.timestamp.wMinute, entry.timestamp.wSecond,
                    LogLevelToString(entry.level), entry.message.c_str());

                // 同时输出到控制台
                printf("[%02d:%02d:%02d] [%s] %s\n",
                    entry.timestamp.wHour, entry.timestamp.wMinute, entry.timestamp.wSecond,
                    LogLevelToString(entry.level), entry.message.c_str());

                // 定期刷新，确保日志及时写入文件
                if (localQueue.size() % 10 == 0 || localQueue.size() == 1) {
                    fflush(m_logFile);
                }
            }

            localQueue.pop();
        }
    }

    // 最终刷新，确保所有日志都写入文件
    if (m_logFile) {
        fflush(m_logFile);
    }
}

// 添加日志条目到队列
void LogSystem::AddLogEntry(LogEntry&& entry) {
    if (!m_initialized.load() || m_shuttingDown.load()) {
        return;
    }

    // 添加到队列并通知处理线程
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_logQueue.push(std::move(entry));
    }

    m_queueCV.notify_one();
}

// 格式化日志消息
std::string LogSystem::FormatLogMessage(const char* format, va_list args) {
    // 使用线程本地存储缓冲区
    thread_local char buffer[4096];

    vsnprintf(buffer, sizeof(buffer), format, args);
    return std::string(buffer);
}

// 将日志级别转换为字符串
const char* LogSystem::LogLevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::Debug:   return "调试";
    case LogLevel::Info:    return "信息";
    case LogLevel::Warning: return "警告";
    case LogLevel::Error:   return "错误";
    default:                return "未知";
    }
}

// 全局日志函数实现
void LogMessage(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogSystem::GetInstance().Log("%s", buffer);
}

void LogDebug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogSystem::GetInstance().LogWithLevel(LogLevel::Debug, "%s", buffer);
}

void LogInfo(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogSystem::GetInstance().LogWithLevel(LogLevel::Info, "%s", buffer);
}

void LogWarning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogSystem::GetInstance().LogWithLevel(LogLevel::Warning, "%s", buffer);
}

void LogError(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogSystem::GetInstance().LogWithLevel(LogLevel::Error, "%s", buffer);
}