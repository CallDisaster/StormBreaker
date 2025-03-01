#pragma once

#include <memory>
#include <fileapi.h>
#include <winerror.h>
#include <errhandlingapi.h>
#include <mutex>
#include <sysinfoapi.h>
#include <cstdarg>
#include <WinBase.h>

// 创建一个新的日志系统类
class LogSystem {
public:
    static LogSystem& GetInstance() {
        static LogSystem instance;
        return instance;
    }

    bool Initialize() {
        // 创建 StormBreaker 文件夹
        if (!CreateDirectoryA("StormBreaker", NULL) &&
            GetLastError() != ERROR_ALREADY_EXISTS) {
            printf("无法创建 StormBreaker 文件夹\n");
            return false;
        }

        // 打开主日志文件
        if (m_mainLogFile) {
            fclose(m_mainLogFile);
            m_mainLogFile = nullptr;
        }

        fopen_s(&m_mainLogFile, "StormBreaker/StormMemory.log", "w");
        if (!m_mainLogFile) {
            printf("无法创建主日志文件\n");
            return false;
        }

        // 创建备份日志文件
        if (m_backupLogFile) {
            fclose(m_backupLogFile);
            m_backupLogFile = nullptr;
        }

        fopen_s(&m_backupLogFile, "StormBreaker/StormMemory_Startup.log", "w");
        if (!m_backupLogFile) {
            printf("无法创建备份日志文件\n");
            return false;
        }

        m_initialized = true;
        Log("日志系统初始化完成");
        return true;
    }

    void Shutdown() {
        if (m_mainLogFile) {
            fclose(m_mainLogFile);
            m_mainLogFile = nullptr;
        }

        if (m_backupLogFile) {
            fclose(m_backupLogFile);
            m_backupLogFile = nullptr;
        }

        m_initialized = false;
    }

    void Log(const char* format, ...) {
        if (!m_initialized) return;

        std::lock_guard<std::mutex> lock(m_logMutex);

        // 获取当前时间
        SYSTEMTIME st;
        GetLocalTime(&st);

        // 格式化时间前缀
        char timeBuffer[32];
        sprintf_s(timeBuffer, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        // 格式化日志内容
        char logBuffer[4096];
        va_list args;
        va_start(args, format);
        vsnprintf(logBuffer, sizeof(logBuffer), format, args);
        va_end(args);

        // 完整日志行
        char fullLog[4096 + 32];
        sprintf_s(fullLog, "%s%s\n", timeBuffer, logBuffer);

        // 写入主日志
        if (m_mainLogFile) {
            fputs(fullLog, m_mainLogFile);

            // 检查文件大小，如果超过限制，进行轮转
            m_mainLogSize += strlen(fullLog);
            if (m_mainLogSize >= MAX_LOG_SIZE) {
                RotateMainLog();
            }

            // 每5秒或日志达到一定量时刷新
            DWORD currentTime = GetTickCount();
            if (currentTime - m_lastFlushTime > 5000 || m_mainLogSize > 16384) {
                fflush(m_mainLogFile);
                m_lastFlushTime = currentTime;
            }
        }

        // 如果还在启动备份阶段，同时写入备份日志
        if (m_backupLogFile && m_backupLogSize < BACKUP_LOG_SIZE) {
            fputs(fullLog, m_backupLogFile);
            m_backupLogSize += strlen(fullLog);

            if (m_backupLogSize >= BACKUP_LOG_SIZE) {
                printf("备份日志已达到最大大小，已停止备份\n");
                fflush(m_backupLogFile);
            }
        }

        // 同时输出到控制台
        printf("%s", fullLog);
    }

private:
    LogSystem() : m_mainLogFile(nullptr), m_backupLogFile(nullptr),
        m_mainLogSize(0), m_backupLogSize(0),
        m_lastFlushTime(0), m_initialized(false) {
    }

    ~LogSystem() {
        Shutdown();
    }

    void RotateMainLog() {
        // 关闭当前日志
        if (m_mainLogFile) {
            fclose(m_mainLogFile);
            m_mainLogFile = nullptr;
        }

        // 重命名当前日志为备份
        char oldPath[MAX_PATH] = "StormBreaker/StormBreaker.log";
        char newPath[MAX_PATH];

        SYSTEMTIME st;
        GetLocalTime(&st);
        sprintf_s(newPath, "StormBreaker/StormBreaker_%04d%02d%02d_%02d%02d%02d.log",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        MoveFileA(oldPath, newPath);

        // 创建新的日志文件
        fopen_s(&m_mainLogFile, oldPath, "w");
        if (m_mainLogFile) {
            m_mainLogSize = 0;
            fprintf(m_mainLogFile, "[%02d:%02d:%02d.%03d] --- 日志已轮转，上一个日志已保存为 %s ---\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, newPath);
        }
    }

    static const size_t MAX_LOG_SIZE = 10 * 1024 * 1024;  // 10MB
    static const size_t BACKUP_LOG_SIZE = 1 * 1024 * 1024;  // 1MB

    FILE* m_mainLogFile;
    FILE* m_backupLogFile;
    size_t m_mainLogSize;
    size_t m_backupLogSize;
    DWORD m_lastFlushTime;
    bool m_initialized;
    std::mutex m_logMutex;
};

