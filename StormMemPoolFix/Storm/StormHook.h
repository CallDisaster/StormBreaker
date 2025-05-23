#pragma once
#include "pch.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <cstddef>
#include <atomic>
#include <mutex>
#include <psapi.h>
#include <Log/MemoryTracker.h>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

// Storm结构体定义
#pragma pack(push, 1)
struct StormAllocHeader {
    DWORD HeapPtr;
    DWORD Size;
    BYTE  AlignPadding;
    BYTE  Flags;
    WORD  Magic;
};
#pragma pack(pop)

// 内存统计结构
struct MemoryStats {
    std::atomic<size_t> totalAllocated{ 0 };
    std::atomic<size_t> totalFreed{ 0 };
    std::atomic<size_t> allocationCount{ 0 };
    std::atomic<size_t> freeCount{ 0 };

    void OnAlloc(size_t size) {
        totalAllocated += size;
        allocationCount++;
    }

    void OnFree(size_t size) {
        totalFreed += size;
        freeCount++;
    }
};

// Storm函数类型定义
typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, const char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();

// 常量定义
constexpr DWORD STORM_MAGIC = 0x6F6D;
constexpr DWORD SPECIAL_MARKER = 0xC0DEFEED;

// 全局变量声明
extern MemoryStats g_memStats;
extern Storm_MemAlloc_t s_origStormAlloc;
extern Storm_MemFree_t s_origStormFree;
extern Storm_MemReAlloc_t s_origStormReAlloc;
extern StormHeap_CleanupAll_t s_origCleanupAll;

extern std::atomic<bool> g_cleanAllInProgress;
extern std::atomic<bool> g_shouldExit;
extern std::atomic<size_t> g_peakVirtualMemoryUsage;
extern HANDLE g_statsThreadHandle;
extern std::condition_variable g_shutdownCondition;
extern std::mutex g_shutdownMutex;

// 全局内存跟踪器
extern MemoryTracker g_memoryTracker;

// 函数声明
bool InitializeStormMemoryHooks();
void ShutdownStormMemoryHooks();
void LogMessage(const char* format, ...);
bool IsOurBlock(void* ptr);
void PrintMemoryStatus();
DWORD WINAPI MemoryStatsThread(LPVOID);

// Hook函数声明
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag);
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4);
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD src_line, DWORD flag);
void Hooked_StormHeap_CleanupAll();

// 辅助函数
bool SafeValidatePointer(void* ptr, size_t expectedSize);
size_t GetProcessVirtualMemoryUsage();
void UpdatePeakMemoryUsage();
void GenerateMemoryReport(bool forceWrite = false);
size_t GetStormVirtualMemoryUsage();

// SEH保护的内存操作模板
template<typename T>
bool SafeReadMemory(void* src, T& dest) {
    __try {
        dest = *static_cast<T*>(src);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template<typename T>
bool SafeWriteMemory(void* dest, const T& value) {
    __try {
        *static_cast<T*>(dest) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 安全的内存验证函数
inline bool SafeIsBadReadPtr(const void* lp, UINT_PTR ucb) {
    if (!lp) return true;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(lp, &mbi, sizeof(mbi))) {
            return true;
        }

        if (mbi.State != MEM_COMMIT) {
            return true;
        }

        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            return true;
        }

        // 检查是否可读
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            return true;
        }

        // 检查范围
        uintptr_t start = reinterpret_cast<uintptr_t>(lp);
        uintptr_t end = start + ucb;
        uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        if (end > regionEnd) {
            return true;
        }

        // 尝试读取第一个和最后一个字节
        volatile char test1 = *static_cast<const char*>(lp);
        if (ucb > 1) {
            volatile char test2 = *static_cast<const char*>(static_cast<const char*>(lp) + ucb - 1);
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

inline bool SafeIsBadWritePtr(void* lp, UINT_PTR ucb) {
    if (!lp) return true;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(lp, &mbi, sizeof(mbi))) {
            return true;
        }

        if (mbi.State != MEM_COMMIT) {
            return true;
        }

        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            return true;
        }

        // 检查是否可写
        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            return true;
        }

        // 检查范围
        uintptr_t start = reinterpret_cast<uintptr_t>(lp);
        uintptr_t end = start + ucb;
        uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        if (end > regionEnd) {
            return true;
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

inline bool SafeIsBadCodePtr(FARPROC lpfn) {
    if (!lpfn) return true;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(lpfn, &mbi, sizeof(mbi))) {
            return true;
        }

        if (mbi.State != MEM_COMMIT) {
            return true;
        }

        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            return true;
        }

        // 检查是否可执行
        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            return true;
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}