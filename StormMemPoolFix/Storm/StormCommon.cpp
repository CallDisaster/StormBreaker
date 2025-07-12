// StormCommon.cpp - Storm��صĹ�����ʵ��
#include "pch.h"
#include "StormCommon.h"

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////

const WORD STORM_FRONT_MAGIC = 0x6F6D;
const WORD STORM_TAIL_MAGIC = 0x12B1;
const DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

const size_t DEFAULT_BIG_BLOCK_THRESHOLD = 128 * 1024;  // 128KB
const size_t JASSVM_BLOCK_SIZE = 0x28A8;                // JassVM������С

///////////////////////////////////////////////////////////////////////////////
// ��־ϵͳʵ��
///////////////////////////////////////////////////////////////////////////////

static CRITICAL_SECTION g_logCs;
static FILE* g_logFile = nullptr;
static bool g_logInitialized = false;

// ��ʼ����־ϵͳ�������Ҫ�Ļ���
static void InitializeLoggingIfNeeded() {
    if (!g_logInitialized) {
        InitializeCriticalSection(&g_logCs);

        // ʹ��fopen_s���ⰲȫ����
        errno_t err = fopen_s(&g_logFile, "StormHook.log", "w");
        if (err == 0 && g_logFile) {
            g_logInitialized = true;
        }
        else {
            printf("[����] �޷�������־�ļ�\n");
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
//    // ��ȡʱ���
//    SYSTEMTIME st;
//    GetLocalTime(&st);
//
//    // ��ʽ����Ϣ
//    char buffer[2048];
//    va_list args;
//    va_start(args, format);
//    int len = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
//    va_end(args);
//
//    if (len > 0) {
//        buffer[len] = '\0';
//
//        // ����̨���
//        printf("[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buffer);
//
//        // �ļ����
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