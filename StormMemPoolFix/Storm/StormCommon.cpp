// StormCommon.cpp - Storm相关的共享定义实现
#include "pch.h"
#include "StormCommon.h"

///////////////////////////////////////////////////////////////////////////////
// 常量定义
///////////////////////////////////////////////////////////////////////////////

const WORD STORM_FRONT_MAGIC = 0x6F6D;
const WORD STORM_TAIL_MAGIC = 0x12B1;
const DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

const size_t DEFAULT_BIG_BLOCK_THRESHOLD = 128 * 1024;  // 128KB
const size_t JASSVM_BLOCK_SIZE = 0x28A8;                // JassVM特殊块大小

///////////////////////////////////////////////////////////////////////////////
// 日志系统实现
///////////////////////////////////////////////////////////////////////////////

static CRITICAL_SECTION g_logCs;
static FILE* g_logFile = nullptr;
static bool g_logInitialized = false;

// 初始化日志系统（如果需要的话）
static void InitializeLoggingIfNeeded() {
    if (!g_logInitialized) {
        InitializeCriticalSection(&g_logCs);

        // 使用fopen_s避免安全警告
        errno_t err = fopen_s(&g_logFile, "StormHook.log", "w");
        if (err == 0 && g_logFile) {
            g_logInitialized = true;
        }
        else {
            printf("[错误] 无法创建日志文件\n");
        }
    }
}

//void LogMessage(const char* format, ...) noexcept {
//    if (!format) return;
//
//    InitializeLoggingIfNeeded();
//    if (!g_logInitialized) return;
//
//    EnterCriticalSection(&g_logCs);
//
//    // 获取时间戳
//    SYSTEMTIME st;
//    GetLocalTime(&st);
//
//    // 格式化消息
//    char buffer[2048];
//    va_list args;
//    va_start(args, format);
//    int len = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
//    va_end(args);
//
//    if (len > 0) {
//        buffer[len] = '\0';
//
//        // 控制台输出
//        printf("[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buffer);
//
//        // 文件输出
//        if (g_logFile) {
//            fprintf(g_logFile, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buffer);
//            fflush(g_logFile);
//        }
//    }
//
//    LeaveCriticalSection(&g_logCs);
//}
//
//void LogError(const char* format, ...) noexcept {
//    if (!format) return;
//
//    char buffer[2048];
//    va_list args;
//    va_start(args, format);
//    vsnprintf(buffer, sizeof(buffer), format, args);
//    va_end(args);
//
//    LogMessage("[ERROR] %s", buffer);
//}