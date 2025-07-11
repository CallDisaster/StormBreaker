// pch.h - 预编译头文件，解决缺失定义问题
#pragma once

// 标准C/C++头文件
#include <Windows.h>
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <functional>
#include <type_traits>

// Windows相关头文件
#include <psapi.h>
#include <TlHelp32.h>

// 确保链接必要的库
#pragma comment(lib, "psapi.lib")

// 解决安全函数警告
#define _CRT_SECURE_NO_WARNINGS

// 常用的内存对齐宏
#define ALIGN_UP(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define ALIGN_DOWN(value, alignment) ((value) & ~((alignment) - 1))

// 常用的大小计算宏
#define KB(x) ((x) * 1024)
#define MB(x) ((x) * 1024 * 1024)
#define GB(x) ((x) * 1024 * 1024 * 1024)

// SEH辅助宏
#define SAFE_TRY __try {
#define SAFE_EXCEPT(operation) } __except(EXCEPTION_EXECUTE_HANDLER) { \
    printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation); \
}

// 调试输出宏
#ifdef _DEBUG
#define DEBUG_PRINT(format, ...) printf("[DEBUG] " format "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(format, ...) ((void)0)
#endif

// 内存池相关常量
namespace MemPoolConstants {
    constexpr size_t DEFAULT_ALIGNMENT = 16;
    constexpr size_t PAGE_SIZE = 4096;
    constexpr size_t LARGE_BLOCK_THRESHOLD = 128 * 1024;  // 128KB
    constexpr DWORD DEFAULT_HOLD_TIME = 500;              // 500ms
}