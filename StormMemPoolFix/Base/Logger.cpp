#include "pch.h"
#include "Logger.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <algorithm>

// ======================== 常量定义 ========================
namespace {
    constexpr size_t MAX_LOG_MESSAGE_SIZE = 4096;
    constexpr size_t MAX_FORMATTED_MESSAGE_SIZE = 4608; // message + timestamp + thread ID
    constexpr size_t DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    constexpr size_t DEFAULT_MAX_BACKUP_FILES = 5;
    constexpr char DEFAULT_LOG_DIRECTORY[] = "StormBreaker";
    constexpr char DEFAULT_LOG_FILENAME[] = "StormMemory.log";
}

// ======================== Logger实现 ========================

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

LoggerConfig Logger::GetDefaultConfig() {
    LoggerConfig config;
    config.minLevel = LogLevel::Warning;  // 默认只显示Warning及以上级别
    config.enableConsole = true;
    config.enableDebugOutput = true;
    config.enableFile = true;
    config.enableRotation = true;
    config.maxFileSize = DEFAULT_MAX_FILE_SIZE;
    config.maxBackupFiles = DEFAULT_MAX_BACKUP_FILES;
    config.logDirectory = DEFAULT_LOG_DIRECTORY;
    config.logFileName = DEFAULT_LOG_FILENAME;
    config.useTimestamp = true;
    config.useThreadId = true;
    config.flushImmediate = false;
    return config;
}

LoggerConfig Logger::GetDebugConfig() {
    LoggerConfig config = GetDefaultConfig();
    config.minLevel = LogLevel::Info;  // Debug配置显示Info及以上级别
    config.flushImmediate = true;
    return config;
}

LoggerConfig Logger::GetReleaseConfig() {
    LoggerConfig config = GetDefaultConfig();
    config.minLevel = LogLevel::Info;
    config.enableConsole = false;
    config.enableDebugOutput = false;
    config.flushImmediate = false;
    return config;
}

bool Logger::Initialize(const LoggerConfig& config) {
    if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
        return true; // 已初始化
    }

    m_config = config;

    // 初始化临界区
    InitializeCriticalSection(&m_criticalSection);

    // 重置统计
    for (int i = 0; i < 5; i++) {
        m_stats[i].store(0, std::memory_order_relaxed);
    }
    m_totalLines.store(0, std::memory_order_relaxed);
    m_totalBytes.store(0, std::memory_order_relaxed);
    m_droppedMessages.store(0, std::memory_order_relaxed);

    // 初始化文件输出
    if (m_config.enableFile) {
        if (!OpenLogFile()) {
            m_config.enableFile = false;
        }
    }

    // 记录初始化消息
    LogInfo("StormBreaker Logger 已初始化");
    LogInfo("日志级别: %s", LevelToString(m_config.minLevel));
    LogInfo("输出目标: %s%s%s",
        m_config.enableConsole ? "控制台 " : "",
        m_config.enableDebugOutput ? "调试输出 " : "",
        m_config.enableFile ? "文件" : "");

    if (m_config.enableFile) {
        LogInfo("日志文件: %s", m_logFilePath);
        LogInfo("文件轮转: %s (最大%zu MB, 保留%zu个备份)",
            m_config.enableRotation ? "启用" : "禁用",
            m_config.maxFileSize / (1024 * 1024),
            m_config.maxBackupFiles);
    }

    return true;
}

void Logger::Shutdown() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return; // 未初始化
    }

    LogInfo("Logger 正在关闭...");

    // 输出统计信息
    LogStats stats = GetStats();
    LogInfo("日志统计: Debug=%llu, Info=%llu, Warning=%llu, Error=%llu, Fatal=%llu",
        stats.debugCount, stats.infoCount, stats.warningCount,
        stats.errorCount, stats.fatalCount);
    LogInfo("总计: %llu 行, %llu 字节, 丢弃: %llu",
        stats.totalLines, stats.totalBytes, stats.droppedMessages);

    // 最后刷新
    FlushLogs();

    // 关闭文件
    CloseLogFile();

    // 清理临界区
    DeleteCriticalSection(&m_criticalSection);
}

bool Logger::IsInitialized() const {
    return m_initialized.load(std::memory_order_acquire);
}

void Logger::LogDebug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Debug, format, args);
    va_end(args);
}

void Logger::LogInfo(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::LogWarning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Warning, format, args);
    va_end(args);
}

void Logger::LogError(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::LogFatal(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Fatal, format, args);
    va_end(args);
}

void Logger::Log(LogLevel level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(level, format, args);
    va_end(args);
}

void Logger::LogV(LogLevel level, const char* format, va_list args) {
    if (!IsInitialized() || level < m_config.minLevel) {
        return;
    }

    // 格式化消息
    char messageBuffer[MAX_LOG_MESSAGE_SIZE];
    int result = _vsnprintf_s(messageBuffer, sizeof(messageBuffer), _TRUNCATE, format, args);

    if (result < 0) {
        // 消息被截断
        strcpy_s(messageBuffer + sizeof(messageBuffer) - 4, 4, "...");
        m_droppedMessages.fetch_add(1, std::memory_order_relaxed);
    }

    // 写入日志
    WriteLog(level, messageBuffer);

    // 更新统计
    int levelIndex = static_cast<int>(level);
    if (levelIndex >= 0 && levelIndex < 5) {
        m_stats[levelIndex].fetch_add(1, std::memory_order_relaxed);
    }
    m_totalLines.fetch_add(1, std::memory_order_relaxed);
    m_lastLogTime.store(GetTickCount(), std::memory_order_relaxed);
}

void Logger::LogIf(bool condition, LogLevel level, const char* format, ...) {
    if (!condition) return;

    va_list args;
    va_start(args, format);
    LogV(level, format, args);
    va_end(args);
}

void Logger::LogDebugIf(bool condition, const char* format, ...) {
    if (!condition) return;

    va_list args;
    va_start(args, format);
    LogV(LogLevel::Debug, format, args);
    va_end(args);
}

void Logger::LogInfoIf(bool condition, const char* format, ...) {
    if (!condition) return;

    va_list args;
    va_start(args, format);
    LogV(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::LogWarningIf(bool condition, const char* format, ...) {
    if (!condition) return;

    va_list args;
    va_start(args, format);
    LogV(LogLevel::Warning, format, args);
    va_end(args);
}

void Logger::LogErrorIf(bool condition, const char* format, ...) {
    if (!condition) return;

    va_list args;
    va_start(args, format);
    LogV(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::LogMemory(const char* operation, void* ptr, size_t size, const char* context) {
    LogDebug("[内存] %s: ptr=%p, size=%zu%s%s",
        operation, ptr, size,
        context ? ", context=" : "",
        context ? context : "");
}

void Logger::LogPerformance(const char* operation, DWORD timeMs, const char* details) {
    LogInfo("[性能] %s: %lu ms%s%s",
        operation, timeMs,
        details ? ", " : "",
        details ? details : "");
}

void Logger::LogException(DWORD exceptionCode, void* exceptionAddress, const char* context) {
    LogError("[异常] 代码=0x%08X, 地址=%p%s%s",
        exceptionCode, exceptionAddress,
        context ? ", 上下文=" : "",
        context ? context : "");
}

void Logger::SetMinLevel(LogLevel level) {
    m_config.minLevel = level;
    LogInfo("日志级别已设置为: %s", LevelToString(level));
}

LogLevel Logger::GetMinLevel() const {
    return m_config.minLevel;
}

void Logger::SetConfig(const LoggerConfig& config) {
    EnterCriticalSection(&m_criticalSection);

    bool fileConfigChanged = (m_config.enableFile != config.enableFile) ||
        (strcmp(m_config.logDirectory, config.logDirectory) != 0) ||
        (strcmp(m_config.logFileName, config.logFileName) != 0);

    m_config = config;

    if (fileConfigChanged) {
        CloseLogFile();
        if (m_config.enableFile) {
            OpenLogFile();
        }
    }

    LeaveCriticalSection(&m_criticalSection);

    LogInfo("Logger配置已更新");
}

LoggerConfig Logger::GetConfig() const {
    return m_config;
}

void Logger::EnableConsoleOutput(bool enable) {
    m_config.enableConsole = enable;
    LogInfo("控制台输出: %s", enable ? "启用" : "禁用");
}

void Logger::EnableFileOutput(bool enable) {
    if (m_config.enableFile == enable) return;

    m_config.enableFile = enable;

    if (enable) {
        OpenLogFile();
    }
    else {
        CloseLogFile();
    }

    LogInfo("文件输出: %s", enable ? "启用" : "禁用");
}

void Logger::EnableDebugOutput(bool enable) {
    m_config.enableDebugOutput = enable;
    LogInfo("调试输出: %s", enable ? "启用" : "禁用");
}

void Logger::SetFlushImmediate(bool enable) {
    m_config.flushImmediate = enable;
    LogInfo("立即刷新: %s", enable ? "启用" : "禁用");
}

void Logger::FlushLogs() {
    if (m_logFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_logFile);
    }
}

void Logger::RotateLogFile() {
    if (!m_config.enableFile || m_logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    LogInfo("开始日志轮转...");

    EnterCriticalSection(&m_criticalSection);

    CloseLogFile();
    PerformRotation();
    OpenLogFile();

    LeaveCriticalSection(&m_criticalSection);

    LogInfo("日志轮转完成");
}

void Logger::ClearLogFile() {
    if (!m_config.enableFile) return;

    EnterCriticalSection(&m_criticalSection);

    CloseLogFile();

    // 直接删除现有文件
    DeleteFileA(m_logFilePath);

    OpenLogFile();

    LeaveCriticalSection(&m_criticalSection);

    LogInfo("日志文件已清空");
}

size_t Logger::GetLogFileSize() const {
    return m_currentFileSize.load(std::memory_order_relaxed);
}

const char* Logger::GetLogFilePath() const {
    return m_logFilePath;
}

Logger::LogStats Logger::GetStats() const {
    return LogStats{
        .debugCount = m_stats[0].load(std::memory_order_relaxed),
        .infoCount = m_stats[1].load(std::memory_order_relaxed),
        .warningCount = m_stats[2].load(std::memory_order_relaxed),
        .errorCount = m_stats[3].load(std::memory_order_relaxed),
        .fatalCount = m_stats[4].load(std::memory_order_relaxed),
        .totalLines = m_totalLines.load(std::memory_order_relaxed),
        .totalBytes = m_totalBytes.load(std::memory_order_relaxed),
        .droppedMessages = m_droppedMessages.load(std::memory_order_relaxed),
        .lastLogTime = m_lastLogTime.load(std::memory_order_relaxed)
    };
}

void Logger::ResetStats() {
    for (int i = 0; i < 5; i++) {
        m_stats[i].store(0, std::memory_order_relaxed);
    }
    m_totalLines.store(0, std::memory_order_relaxed);
    m_totalBytes.store(0, std::memory_order_relaxed);
    m_droppedMessages.store(0, std::memory_order_relaxed);

    LogInfo("日志统计已重置");
}

const char* Logger::LevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::Debug:   return "DEBUG";
    case LogLevel::Info:    return "INFO";
    case LogLevel::Warning: return "WARNING";
    case LogLevel::Error:   return "ERROR";
    case LogLevel::Fatal:   return "FATAL";
    default:                return "UNKNOWN";
    }
}

LogLevel Logger::StringToLevel(const char* str) {
    if (!str) return LogLevel::Info;

    if (_stricmp(str, "debug") == 0)   return LogLevel::Debug;
    if (_stricmp(str, "info") == 0)    return LogLevel::Info;
    if (_stricmp(str, "warning") == 0) return LogLevel::Warning;
    if (_stricmp(str, "error") == 0)   return LogLevel::Error;
    if (_stricmp(str, "fatal") == 0)   return LogLevel::Fatal;

    return LogLevel::Info;
}

const char* Logger::GetTimeStamp() {
    static thread_local char timeBuffer[32];

    SYSTEMTIME st;
    GetLocalTime(&st);

    _snprintf_s(timeBuffer, sizeof(timeBuffer), _TRUNCATE,
        "%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return timeBuffer;
}

DWORD Logger::GetCurrentThreadId() {
    return ::GetCurrentThreadId();
}

// ======================== 内部实现 ========================

void Logger::WriteLog(LogLevel level, const char* message) {
    if (!IsInitialized()) return;

    EnterCriticalSection(&m_criticalSection);

    // 检查文件轮转
    if (m_config.enableFile && m_config.enableRotation &&
        m_currentFileSize.load(std::memory_order_relaxed) >= m_config.maxFileSize) {
        CloseLogFile();
        PerformRotation();
        OpenLogFile();
    }

    // 写入各个输出目标
    if (m_config.enableConsole) {
        WriteToConsole(level, message);
    }

    if (m_config.enableDebugOutput) {
        WriteToDebugOutput(level, message);
    }

    if (m_config.enableFile && m_logFile != INVALID_HANDLE_VALUE) {
        WriteToFile(level, message);
    }

    // 立即刷新
    if (m_config.flushImmediate && m_logFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_logFile);
    }

    LeaveCriticalSection(&m_criticalSection);
}

void Logger::WriteToConsole(LogLevel level, const char* message) {
    // 设置控制台颜色
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD originalColor = 7; // 默认白色

    if (hConsole != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
        if (GetConsoleScreenBufferInfo(hConsole, &consoleInfo)) {
            originalColor = consoleInfo.wAttributes;
        }

        WORD color = originalColor;
        switch (level) {
        case LogLevel::Debug:   color = FOREGROUND_INTENSITY; break; // 灰色
        case LogLevel::Info:    color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; break; // 白色
        case LogLevel::Warning: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break; // 黄色
        case LogLevel::Error:   color = FOREGROUND_RED | FOREGROUND_INTENSITY; break; // 红色
        case LogLevel::Fatal:   color = FOREGROUND_RED | BACKGROUND_RED | FOREGROUND_INTENSITY; break; // 红底红字
        }

        SetConsoleTextAttribute(hConsole, color);
    }

    // 格式化并输出
    char formattedBuffer[MAX_FORMATTED_MESSAGE_SIZE];
    FormatMessage(formattedBuffer, sizeof(formattedBuffer), level, message);

    printf("%s\n", formattedBuffer);

    // 恢复颜色
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, originalColor);
    }
}

void Logger::WriteToDebugOutput(LogLevel level, const char* message) {
    char formattedBuffer[MAX_FORMATTED_MESSAGE_SIZE];
    FormatMessage(formattedBuffer, sizeof(formattedBuffer), level, message);

    strcat_s(formattedBuffer, sizeof(formattedBuffer), "\n");
    OutputDebugStringA(formattedBuffer);
}

void Logger::WriteToFile(LogLevel level, const char* message) {
    if (m_logFile == INVALID_HANDLE_VALUE) return;

    char formattedBuffer[MAX_FORMATTED_MESSAGE_SIZE];
    FormatMessage(formattedBuffer, sizeof(formattedBuffer), level, message);

    strcat_s(formattedBuffer, sizeof(formattedBuffer), "\r\n");

    DWORD bytesWritten = 0;
    DWORD messageLength = static_cast<DWORD>(strlen(formattedBuffer));

    if (WriteFile(m_logFile, formattedBuffer, messageLength, &bytesWritten, nullptr)) {
        m_currentFileSize.fetch_add(bytesWritten, std::memory_order_relaxed);
        m_totalBytes.fetch_add(bytesWritten, std::memory_order_relaxed);
    }
}

bool Logger::OpenLogFile() {
    // 创建日志目录
    CreateDirectoryA(m_config.logDirectory, nullptr);

    // 构建完整路径
    _snprintf_s(m_logFilePath, sizeof(m_logFilePath), _TRUNCATE,
        "%s\\%s", m_config.logDirectory, m_config.logFileName);

    // 打开文件
    m_logFile = CreateFileA(
        m_logFilePath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_logFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    // 获取当前文件大小
    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(m_logFile, &fileSize)) {
        m_currentFileSize.store(static_cast<size_t>(fileSize.QuadPart), std::memory_order_relaxed);
    }

    return true;
}

void Logger::CloseLogFile() {
    if (m_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_logFile);
        m_logFile = INVALID_HANDLE_VALUE;
    }
}

void Logger::PerformRotation() {
    char backupPath[MAX_PATH];

    // 移动现有备份文件
    for (int i = static_cast<int>(m_config.maxBackupFiles) - 1; i > 0; i--) {
        char oldPath[MAX_PATH], newPath[MAX_PATH];

        if (i == 1) {
            strcpy_s(oldPath, m_logFilePath);
        }
        else {
            _snprintf_s(oldPath, sizeof(oldPath), _TRUNCATE,
                "%s.%d", m_logFilePath, i - 1);
        }

        _snprintf_s(newPath, sizeof(newPath), _TRUNCATE,
            "%s.%d", m_logFilePath, i);

        MoveFileA(oldPath, newPath);
    }

    // 重置文件大小计数
    m_currentFileSize.store(0, std::memory_order_relaxed);
}

void Logger::FormatMessage(char* buffer, size_t bufferSize, LogLevel level, const char* message) {
    char timeStr[32] = { 0 };
    char threadStr[16] = { 0 };

    if (m_config.useTimestamp) {
        strcpy_s(timeStr, GetTimeStamp());
    }

    if (m_config.useThreadId) {
        _snprintf_s(threadStr, sizeof(threadStr), _TRUNCATE, "[%lu]", GetCurrentThreadId());
    }

    _snprintf_s(buffer, bufferSize, _TRUNCATE,
        "%s%s%s[%s] %s",
        m_config.useTimestamp ? timeStr : "",
        m_config.useTimestamp ? " " : "",
        m_config.useThreadId ? threadStr : "",
        LevelToString(level),
        message);
}

// ======================== PerformanceTimer实现 ========================

PerformanceTimer::PerformanceTimer(const char* operation)
    : m_operation(operation), m_startTime(GetTickCount()), m_stopped(false) {
}

PerformanceTimer::~PerformanceTimer() {
    if (!m_stopped) {
        Stop();
    }
}

void PerformanceTimer::Stop() {
    if (m_stopped) return;

    DWORD elapsed = GetTickCount() - m_startTime;
    Logger::GetInstance().LogPerformance(m_operation, elapsed);
    m_stopped = true;
}

DWORD PerformanceTimer::GetElapsedMs() const {
    return GetTickCount() - m_startTime;
}