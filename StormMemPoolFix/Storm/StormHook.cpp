﻿// StormHook.cpp
#include "pch.h"
#include "StormHook.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <cstdio>
#include <map>
#include <mutex>
#include <vector>
#include <cstring>
#include <detours.h>
#include <unordered_map>
#include <atomic>
#include "tlsf.h"
#include <algorithm>
#include <Base/MemorySafety.h>
#include "../Base/Logger.h"
#include "MemoryPool.h"

MemorySafety& g_MemSafety = MemorySafety::GetInstance();

static std::vector<SpecialBlockFilter> g_specialFilters = {
    // JassVM 相关分配，使用独立的低地址内存
    { 0x28A8, "Instance.cpp", 0, true, true },  // JassVM 实例
    //{ 0x64, "jass.cpp", 0, true, true },       // JassVM 栈帧
    //{ 0, "jass", 0, true, true },              // 捕获所有包含 "jass" 的分配
    //{ 0, "Instance", 0, true, true },          // 捕获所有包含 "Instance" 的分配

    // 地形和模型可以使用 TLSF
    { 0, "terrain", 0, true, false },
    { 0, "model", 0, true, false },
};

// 额外状态变量
std::atomic<bool> g_afterCleanAll{ false };
std::atomic<DWORD> g_lastCleanAllTime{ 0 };
thread_local bool tls_inCleanAll = false;
std::atomic<bool> g_insideUnsafePeriod{ false }; // 新增：标记不安全时期

// 全局变量定义
std::atomic<size_t> g_bigThreshold{ 512 * 1024 };      // 默认512KB为大块阈值,若您要修改该数值最好不要低于128KB，256已经比较危险了。
std::mutex g_bigBlocksMutex;
std::unordered_map<void*, BigBlockInfo> g_bigBlocks;
MemoryStats g_memStats;
std::atomic<bool> g_cleanAllInProgress{ false };
DWORD g_cleanAllThreadId = 0;
static std::vector<void*> g_permanentBlocks; // 新增：永久保留块
std::vector<TempStabilizerBlock> g_tempStabilizers;
// Storm原始函数指针
Storm_MemAlloc_t    s_origStormAlloc = nullptr;
Storm_MemFree_t     s_origStormFree = nullptr;
Storm_MemReAlloc_t  s_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t s_origCleanupAll = nullptr;
// 跟踪统计
size_t g_freedByAllocHook = 0;
size_t g_freedByFreeHook = 0;

// 日志文件句柄
static FILE* g_logFile = nullptr;

///////////////////////////////////////////////////////////////////////////////
// 辅助函数
///////////////////////////////////////////////////////////////////////////////

// 替换原来的 LogMessage 函数
void LogMessage(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);

    va_end(args);

    // 使用新的日志系统记录
    LogSystem::GetInstance().Log("%s", buffer);
}

// StormHook.cpp 中添加实现
size_t GetStormVirtualMemoryUsage() {
    // 获取 Storm 虚拟内存占用
    if (Storm_g_TotalAllocatedMemory) {
        return Storm_g_TotalAllocatedMemory;
    }
    return 0;
}

size_t GetTLSFPoolUsage() {
    // 获取 TLSF 内存池已用大小
    return MemPool::GetUsedSize();
}

size_t GetTLSFPoolTotal() {
    // 获取 TLSF 内存池总大小
    return MemPool::GetTotalSize();
}

// 生成完整的内存报告
void GenerateMemoryReport(bool forceWrite) {
    static DWORD lastReportTime = 0;
    DWORD currentTime = GetTickCount();

    // 默认每30秒生成一次报告，除非强制生成
    if (!forceWrite && (currentTime - lastReportTime < 30000)) {
        return;
    }

    lastReportTime = currentTime;

    // 获取内存数据
    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t tlsfUsed = GetTLSFPoolUsage();
    size_t tlsfTotal = GetTLSFPoolTotal();
    size_t managed = g_bigBlocks.size();

    // 计算使用率
    double tlsfUsagePercent = tlsfTotal > 0 ? (tlsfUsed * 100.0 / tlsfTotal) : 0.0;

    // 获取进程整体内存使用情况
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);

    size_t workingSetMB = 0;
    size_t virtualMemMB = 0;

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
        virtualMemMB = pmc.PagefileUsage / (1024 * 1024);  // 使用 PagefileUsage 替代 PrivateUsage
    }

    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 生成报告文本
    char reportBuffer[2048];
    int len = sprintf_s(reportBuffer,
        "===== 内存使用报告 =====\n"
        "时间: %02d:%02d:%02d\n"
        "Storm 虚拟内存: %zu MB\n"
        "TLSF 内存池: %zu MB / %zu MB (%.1f%%)\n"
        "TLSF 管理块数量: %zu\n"
        "工作集大小: %zu MB\n"
        "虚拟内存总量: %zu MB\n"
        "========================\n",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        tlsfUsed / (1024 * 1024), tlsfTotal / (1024 * 1024), tlsfUsagePercent,
        managed,
        workingSetMB,
        virtualMemMB
    );

    // 同时输出到控制台和日志
    printf("%s", reportBuffer);
    LogMessage("\n%s", reportBuffer);
}

// 简化版状态输出，适合频繁调用
void PrintMemoryStatus() {
    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t tlsfUsed = GetTLSFPoolUsage();
    size_t tlsfTotal = GetTLSFPoolTotal();

    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    printf("[%02d:%02d:%02d] [内存] Storm: %zu MB, TLSF: %zu/%zu MB (%.1f%%)\n",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        tlsfUsed / (1024 * 1024),
        tlsfTotal / (1024 * 1024),
        tlsfTotal > 0 ? (tlsfUsed * 100.0 / tlsfTotal) : 0.0);

    LogMessage("[%02d:%02d:%02d] [内存] Storm: %zu MB, TLSF: %zu/%zu MB (%.1f%%)",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        tlsfUsed / (1024 * 1024),
        tlsfTotal / (1024 * 1024),
        tlsfTotal > 0 ? (tlsfUsed * 100.0 / tlsfTotal) : 0.0);
}

// 替代方案：使用SEH和函数封装
LONG WINAPI CustomUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo) {
    LogMessage("[CleanAll] 捕获到异常: 0x%08X", pExceptionInfo->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER; // 继续执行
}

// 安全内存复制函数
bool SafeMemCopy(void* dest, const void* src, size_t size) noexcept {
    if (!dest || !src || size == 0) return false;

    __try {
        // 分块复制，降低崩溃风险
        const size_t CHUNK_SIZE = 4096;
        const char* srcPtr = static_cast<const char*>(src);
        char* destPtr = static_cast<char*>(dest);

        for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
            size_t bytesToCopy = (offset + CHUNK_SIZE > size) ? (size - offset) : CHUNK_SIZE;
            memcpy(destPtr + offset, srcPtr + offset, bytesToCopy);
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[SafeMemCopy] 复制失败: dest=%p, src=%p, size=%zu, 错误=0x%x",
            dest, src, size, GetExceptionCode());
        return false;
    }
}


// 尝试获取内存块的大小
size_t GetBlockSize(void* ptr) noexcept {
    if (!ptr) return 0;

    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 什么都不做，只是捕获异常
    }

    return 0;
}

// 执行函数
void SafeExecuteCleanupAll() {
    // 通知内存安全系统进入不安全期
    g_MemSafety.EnterUnsafePeriod();

    LPTOP_LEVEL_EXCEPTION_FILTER oldFilter =
        SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* pExceptionInfo) -> LONG {
        LogMessage("[CleanAll] 捕获到异常: 0x%08X 位置: %p",
            pExceptionInfo->ExceptionRecord->ExceptionCode,
            pExceptionInfo->ExceptionRecord->ExceptionAddress);
        return EXCEPTION_EXECUTE_HANDLER;
            });

    __try {
        // 执行原始函数
        s_origCleanupAll();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[CleanAll] 清理过程中捕获到异常");
    }

    // 恢复之前的异常处理器
    SetUnhandledExceptionFilter(oldFilter);

    // 清理完成后退出不安全期
    g_MemSafety.ExitUnsafePeriod();
}


// 设置Storm兼容的内存块头
void SetupCompatibleHeader(void* userPtr, size_t size) {
    try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        header->HeapPtr = SPECIAL_MARKER;  // 特殊标记
        header->Size = static_cast<DWORD>(size);
        header->AlignPadding = 0;
        header->Flags = 0x4;  // 标记为大块VirtualAlloc
        header->Magic = STORM_MAGIC;
    }
    catch (...) {
        LogMessage("[ERROR] 设置兼容头失败: %p", userPtr);
    }
}

// 检查指针是否由我们管理
bool IsOurBlock(void* ptr) {
    if (!ptr) return false;

    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        return (header->Magic == STORM_MAGIC &&
            header->HeapPtr == SPECIAL_MARKER);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 是否为我们的永久块
bool IsPermanentBlock(void* ptr) {
    if (!ptr) return false;

    for (void* block : g_permanentBlocks) {
        if (block == ptr) return true;
    }
    return false;
}

// 根据名称判断资源类型
ResourceType GetResourceType(const char* name) {
    if (!name) return ResourceType::Unknown;

    if (strstr(name, "Model") || strstr(name, "GEOSET") || strstr(name, "MDX"))
        return ResourceType::Model;
    if (strstr(name, "CUnit") || strstr(name, "Unit"))
        return ResourceType::Unit;
    if (strstr(name, "Terrain") || strstr(name, "Ground"))
        return ResourceType::Terrain;
    if (strstr(name, "Sound") || strstr(name, "SND") || strstr(name, "Audio"))
        return ResourceType::Sound;
    if (strstr(name, "SFile") || strstr(name, "File"))
        return ResourceType::File;
    if (strstr(name, "Instance") || strstr(name, "jass") || strstr(name, "Jass"))
        return ResourceType::JassVM;

    return ResourceType::Unknown;
}

// 检查是否为特殊块分配
bool IsSpecialBlockAllocation(size_t size, const char* name, DWORD src_line) {
    for (const auto& filter : g_specialFilters) {
        if (filter.size == size &&
            (filter.name == nullptr || (name && strstr(name, filter.name))) &&
            (filter.sourceLine == 0 || filter.sourceLine == src_line)) {
            return true;
        }
    }
    return false;
}

void* AllocateJassVMMemory(size_t size) {
    // 使用 VirtualAlloc 直接分配而非 TLSF
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rawPtr) {
        LogMessage("[JassVM] 内存分配失败: %zu 字节", size);
        return nullptr;
    }

    void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
    SetupCompatibleHeader(userPtr, size);

    LogMessage("[JassVM] 专用内存分配: %p (大小: %zu)", userPtr, size);

    // 记录此块信息
    BigBlockInfo info;
    info.rawPtr = rawPtr;
    info.size = size;
    info.timestamp = GetTickCount();
    info.source = _strdup("JassVM_专用内存");
    info.srcLine = 0;
    info.type = ResourceType::JassVM;

    std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
    g_bigBlocks[userPtr] = info;

    return userPtr;
}

///////////////////////////////////////////////////////////////////////////////
// TLSF 内存池实现
///////////////////////////////////////////////////////////////////////////////

// 主内存池大小: 64MB
// 由于当前内存池安全性过高动态扩容有问题请您重新编译的时候针对自己地图调整内存池大小。
constexpr size_t TLSF_MAIN_POOL_SIZE = 64 * 1024 * 1024;

namespace MemPool {
    // 内部变量
    static void* g_mainPool = nullptr;
    static tlsf_t g_tlsf = nullptr;
    static std::mutex g_poolMutex;
    static std::atomic<bool> g_inTLSFOperation{ false }; // 新增：标记TLSF操作

    // 额外内存池结构
    struct ExtraPool {
        void* memory;
        size_t size;
    };
    static std::vector<ExtraPool> g_extraPools;

    // 检查指针是否在某个池范围内
    bool IsPointerInPool(void* ptr, void* poolStart, size_t poolSize) {
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t poolAddr = reinterpret_cast<uintptr_t>(poolStart);
        return (ptrAddr >= poolAddr && ptrAddr < poolAddr + poolSize);
    }

    // 初始化内存池
    void Initialize(size_t initialSize = TLSF_MAIN_POOL_SIZE) {
        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (g_mainPool) {
            LogMessage("[MemPool] 已初始化");
            return;
        }

        // 分配主内存池
        g_mainPool = VirtualAlloc(NULL, initialSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!g_mainPool) {
            LogMessage("[MemPool] 无法分配主内存池，大小: %zu", initialSize);
            return;
        }

        // 初始化TLSF
        g_tlsf = tlsf_create_with_pool(g_mainPool, initialSize);

        if (!g_tlsf) {
            LogMessage("[MemPool] 无法创建TLSF实例");
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
            return;
        }

        LogMessage("[MemPool] 已初始化，大小: %zu 字节，地址: %p", initialSize, g_mainPool);
    }

    // 清理资源
    void Shutdown() {
        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] 关闭期间TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (g_tlsf) {
            // TLSF本身不需要特别的销毁步骤
            g_tlsf = nullptr;
        }

        // 释放所有额外池
        for (const auto& pool : g_extraPools) {
            if (pool.memory) {
                VirtualFree(pool.memory, 0, MEM_RELEASE);
            }
        }
        g_extraPools.clear();

        // 释放主池
        if (g_mainPool) {
            VirtualFree(g_mainPool, 0, MEM_RELEASE);
            g_mainPool = nullptr;
        }

        g_inTLSFOperation = false;
        LogMessage("[MemPool] 关闭完成");
    }

    // 添加额外内存池
    bool AddExtraPool(size_t size) {
        // 改用带超时的重试机制
        int retryCount = 0;
        const int MAX_RETRIES = 5;

        while (g_inTLSFOperation.exchange(true)) {
            // 释放并短暂等待
            g_inTLSFOperation = false;
            if (++retryCount >= MAX_RETRIES) {
                LogMessage("[MemPool] AddExtraPool: 尝试%d次后仍无法获取TLSF操作权限", MAX_RETRIES);
                return false;
            }
            Sleep(10); // 稍微等待一下再重试
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        if (!g_tlsf) {
            LogMessage("[MemPool] TLSF未初始化");
            g_inTLSFOperation = false;
            return false;
        }

        // 分配新池
        void* newPool = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newPool) {
            LogMessage("[MemPool] 无法分配额外内存池，大小: %zu", size);
            g_inTLSFOperation = false;
            return false;
        }

        // 添加到TLSF
        pool_t pool = tlsf_add_pool(g_tlsf, newPool, size);
        if (!pool) {
            LogMessage("[MemPool] 无法添加内存池到TLSF");
            VirtualFree(newPool, 0, MEM_RELEASE);
            g_inTLSFOperation = false;
            return false;
        }

        // 记录池信息
        ExtraPool extraPool = { newPool, size };
        g_extraPools.push_back(extraPool);

        LogMessage("[MemPool] 添加额外内存池，大小: %zu，地址: %p", size, newPool);
        g_inTLSFOperation = false;
        return true;
    }

    // 分配内存 - 保护版
    void* AllocateSafe(size_t size) {
        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间使用系统分配
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) {
                LogMessage("[MemPool] 不安全期间系统内存分配失败: %zu", size);
                return nullptr;
            }

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            LogMessage("[MemPool] 不安全期间使用系统内存: %p, 大小: %zu", userPtr, size);
            return userPtr;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] Allocate: TLSF操作正在进行，回退到系统分配");
            g_inTLSFOperation = false;

            // 使用系统分配作为备选
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) return nullptr;

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            return userPtr;
        }

        void* ptr = Allocate(size);
        g_inTLSFOperation = false;
        return ptr;
    }

    // 分配内存
    void* Allocate(size_t size) {
        if (!g_tlsf) {
            // 懒初始化
            Initialize();
            if (!g_tlsf) return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        void* ptr = tlsf_malloc(g_tlsf, size);
        if (!ptr) {
            // 尝试扩展池
            size_t extraSize = size < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : size * 2;
            LogMessage("[MemPool] 分配失败，大小: %zu，扩展内存池: %zu 字节",
                size, extraSize);

            if (AddExtraPool(extraSize)) {
                ptr = tlsf_malloc(g_tlsf, size);
            }
        }

        return ptr;
    }

    // 释放内存 - 保护版
    void FreeSafe(void* ptr) {
        if (!ptr) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间，不释放内存
            return;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] Free: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        Free(ptr);
        g_inTLSFOperation = false;
    }

    // 释放内存
    void Free(void* ptr) {
        if (!g_tlsf || !ptr) return;

        // 避免释放永久块
        if (IsPermanentBlock(ptr)) {
            LogMessage("[MemPool] 尝试释放永久块: %p，已忽略", ptr);
            return;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        // 确保指针来自我们的池
        if (IsFromPool(ptr)) {
            try {
                tlsf_free(g_tlsf, ptr);
            }
            catch (...) {
                LogMessage("[MemPool] 释放内存时异常: %p", ptr);
            }
        }
        else {
            // 可能是系统分配的后备内存
            try {
                StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(ptr) - sizeof(StormAllocHeader));

                if (header->Magic == STORM_MAGIC && header->HeapPtr == SPECIAL_MARKER) {
                    void* basePtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
                    VirtualFree(basePtr, 0, MEM_RELEASE);
                    return;
                }
            }
            catch (...) {}

            LogMessage("[MemPool] 警告: 尝试释放非内存池指针: %p", ptr);
        }
    }

    // 重新分配内存 - 保护版
    void* ReallocSafe(void* oldPtr, size_t newSize) {
        if (!oldPtr) return AllocateSafe(newSize);
        if (newSize == 0) {
            FreeSafe(oldPtr);
            return nullptr;
        }

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间，采用分配+复制+不释放的策略
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试复制数据
            size_t oldSize = 0;
            try {
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                if (oldHeader->Magic == STORM_MAGIC) {
                    oldSize = oldHeader->Size;
                }
            }
            catch (...) {
                oldSize = newSize; // 无法确定大小，假设相同
            }

            size_t copySize = min(oldSize, newSize);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                LogMessage("[MemPool] 不安全期间复制数据失败");
                FreeSafe(newPtr);
                return nullptr;
            }

            // 不释放旧指针
            return newPtr;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] Realloc: TLSF操作正在进行，使用备选策略");
            g_inTLSFOperation = false;

            // 使用分配+复制+释放的备选策略
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试复制数据
            try {
                StormAllocHeader* oldHeader = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));
                size_t copySize = min(oldHeader->Size, newSize);
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                // 复制失败，保守地尝试复制较小的块
                try {
                    memcpy(newPtr, oldPtr, min(newSize, (size_t)1024));
                }
                catch (...) {
                    LogMessage("[MemPool] 无法复制内存数据");
                }
            }

            // 尝试释放旧指针
            FreeSafe(oldPtr);
            return newPtr;
        }

        void* ptr = Realloc(oldPtr, newSize);
        g_inTLSFOperation = false;
        return ptr;
    }

    // 重新分配内存
    void* Realloc(void* oldPtr, size_t newSize) {
        if (!g_tlsf) return nullptr;
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        // 确保旧指针来自我们的池
        if (!IsFromPool(oldPtr)) {
            LogMessage("[MemPool] 警告: 尝试重新分配非内存池指针: %p", oldPtr);
            return nullptr;
        }

        void* newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
        if (!newPtr) {
            // 尝试扩展池
            size_t extraSize = newSize < (4 * 1024 * 1024) ? (4 * 1024 * 1024) : newSize * 2;
            LogMessage("[MemPool] 重新分配失败，大小: %zu，扩展内存池: %zu 字节",
                newSize, extraSize);

            if (AddExtraPool(extraSize)) {
                newPtr = tlsf_realloc(g_tlsf, oldPtr, newSize);
            }
        }

        return newPtr;
    }

    // 检查内存池状态
    struct PoolUsageStats {
        size_t used = 0;
        size_t total = 0;
    };

    static void GatherUsageCallback(void* /*ptr*/, size_t size, int used, void* user) {
        PoolUsageStats* stats = static_cast<PoolUsageStats*>(user);
        stats->total += size;
        if (used) stats->used += size;
    }

    // 检查指针是否来自我们的池
    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        // 检查主池
        if (IsPointerInPool(ptr, g_mainPool, TLSF_MAIN_POOL_SIZE)) {
            return true;
        }

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            if (IsPointerInPool(ptr, pool.memory, pool.size)) {
                return true;
            }
        }

        return false;
    }

    // 获取已使用大小
    size_t GetUsedSize() {
        if (!g_tlsf) return 0;

        if (g_inTLSFOperation.exchange(true)) {
            g_inTLSFOperation = false;
            return 0; // 正在进行TLSF操作时返回0
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        PoolUsageStats stats;

        // 检查主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        tlsf_walk_pool(mainPool, GatherUsageCallback, &stats);

        // 检查额外池
        for (const auto& pool : g_extraPools) {
            PoolUsageStats poolStats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &poolStats);
            stats.used += poolStats.used;
            stats.total += poolStats.total;
        }

        g_inTLSFOperation = false;
        return stats.used;
    }

    // 获取总大小
    size_t GetTotalSize() {
        if (!g_tlsf) return 0;

        if (g_inTLSFOperation.exchange(true)) {
            g_inTLSFOperation = false;
            return 0; // 正在进行TLSF操作时返回0
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        size_t total = TLSF_MAIN_POOL_SIZE;
        for (const auto& pool : g_extraPools) {
            total += pool.size;
        }

        g_inTLSFOperation = false;
        return total;
    }

    // 打印统计信息
    void PrintStats() {
        if (!g_tlsf) {
            LogMessage("[MemPool] 未初始化");
            return;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] PrintStats: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);

        LogMessage("[MemPool] === 内存池统计 ===");

        // 主池
        pool_t mainPool = tlsf_get_pool(g_tlsf);
        PoolUsageStats mainStats;
        tlsf_walk_pool(mainPool, GatherUsageCallback, &mainStats);

        LogMessage("[MemPool] 主池: %zu KB已用 / %zu KB总计 (%.1f%%)",
            mainStats.used / 1024, mainStats.total / 1024,
            mainStats.total > 0 ? (mainStats.used * 100.0 / mainStats.total) : 0);

        // 额外池
        size_t totalExtra = 0;
        size_t usedExtra = 0;

        for (size_t i = 0; i < g_extraPools.size(); i++) {
            const auto& pool = g_extraPools[i];
            PoolUsageStats stats;
            tlsf_walk_pool(pool.memory, GatherUsageCallback, &stats);

            LogMessage("[MemPool] 额外池 #%zu: %zu KB已用 / %zu KB总计 (%.1f%%)",
                i + 1, stats.used / 1024, stats.total / 1024,
                stats.total > 0 ? (stats.used * 100.0 / stats.total) : 0);

            totalExtra += pool.size;
            usedExtra += stats.used;
        }

        LogMessage("[MemPool] 额外池: %zu 个, %zu KB总计",
            g_extraPools.size(), totalExtra / 1024);

        // 总计
        size_t totalSize = TLSF_MAIN_POOL_SIZE + totalExtra;
        size_t totalUsed = mainStats.used + usedExtra;

        LogMessage("[MemPool] 总计: %zu KB已用 / %zu KB已分配 (%.1f%%)",
            totalUsed / 1024, totalSize / 1024,
            totalSize > 0 ? (totalUsed * 100.0 / totalSize) : 0);

        g_inTLSFOperation = false;
    }

    // 检查并释放空闲的扩展池
    void CheckAndFreeUnusedPools() {
        if (!g_tlsf) return;

        if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
            // 在不安全期间不执行此操作
            return;
        }

        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] CheckFreeUnusedPools: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return;
        }

        std::lock_guard<std::mutex> lock(g_poolMutex);
        bool poolsFreed = false;

        // 从后向前扫描，释放完全空闲的扩展池
        for (auto it = g_extraPools.rbegin(); it != g_extraPools.rend(); ) {
            PoolUsageStats stats;
            tlsf_walk_pool(it->memory, GatherUsageCallback, &stats);

            if (stats.used == 0) {
                // 这个池完全空闲，可以释放
                LogMessage("[MemPool] 释放未使用的额外池: %p (大小: %zu 字节)",
                    it->memory, it->size);

                // 从TLSF中移除
                tlsf_remove_pool(g_tlsf, it->memory);

                // 释放内存
                VirtualFree(it->memory, 0, MEM_RELEASE);

                // 从列表中移除(注意反向迭代器的特殊处理)
                auto normalIt = std::next(it).base();
                normalIt = g_extraPools.erase(normalIt);
                it = std::reverse_iterator<decltype(normalIt)>(normalIt);

                poolsFreed = true;
            }
            else {
                ++it;
            }
        }

        if (poolsFreed) {
            LogMessage("[MemPool] 清理后: 剩余%zu个额外池", g_extraPools.size());
        }

        g_inTLSFOperation = false;
    }

    // 创建稳定化块 - 新增函数
    void* CreateStabilizingBlock(size_t size, const char* purpose) {
        if (g_inTLSFOperation.exchange(true)) {
            LogMessage("[MemPool] CreateStabilizingBlock: TLSF操作正在进行，跳过");
            g_inTLSFOperation = false;
            return nullptr;
        }

        // 使用系统分配确保稳定性
        void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rawPtr) {
            LogMessage("[MemPool] 无法分配稳定化块: %zu", size);
            g_inTLSFOperation = false;
            return nullptr;
        }

        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        LogMessage("[MemPool] 创建稳定化块: %p (大小: %zu, 用途: %s)",
            userPtr, size, purpose ? purpose : "未知");

        g_inTLSFOperation = false;
        return userPtr;
    }
}

///////////////////////////////////////////////////////////////////////////////
// 统计信息线程
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI MemoryStatsThread(LPVOID) {
    LogMessage("[StatsThread] 内存监控线程已启动");

    DWORD lastCleanupTime = GetTickCount();
    DWORD lastStatsTime = GetTickCount();
    DWORD lastReportTime = GetTickCount();

    while (true) {
        Sleep(5000);  // 每5秒检查一次

        DWORD currentTime = GetTickCount();

        // 每30秒生成内存报告
        if (currentTime - lastReportTime > 30000) {
            GenerateMemoryReport();
            lastReportTime = currentTime;
        }

        // 每30秒尝试释放未使用的扩展池
        if (currentTime - lastCleanupTime > 30000) {
            if (!g_cleanAllInProgress && !g_insideUnsafePeriod.load()) {
                MemPool::CheckAndFreeUnusedPools();
            }
            lastCleanupTime = currentTime;
        }

        // 每分钟打印一次内存统计
        if (currentTime - lastStatsTime > 60000) {
            LogMessage("\n[内存状态] ---- 距上次报告%u秒 ----",
                (currentTime - lastStatsTime) / 1000);

            // 总体统计
            size_t allocTotal = g_memStats.totalAllocated.load();
            size_t freeTotal = g_memStats.totalFreed.load();

            LogMessage("[内存状态] 总计追踪: 已分配=%zu MB, 已释放=%zu MB, 使用中=%zu MB",
                allocTotal / (1024 * 1024), freeTotal / (1024 * 1024),
                (allocTotal > freeTotal) ? (allocTotal - freeTotal) / (1024 * 1024) : 0);

            // Storm内部统计
            LogMessage("[内存状态] Storm_TotalAllocatedMemory=%zu MB",
                Storm_g_TotalAllocatedMemory / (1024 * 1024));

            // 大块跟踪统计
            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                LogMessage("[内存状态] TLSF管理块: 数量=%zu", g_bigBlocks.size());

                // 按类型统计
                std::map<ResourceType, size_t> typeCount;
                std::map<ResourceType, size_t> typeSize;

                for (const auto& entry : g_bigBlocks) {
                    typeCount[entry.second.type]++;
                    typeSize[entry.second.type] += entry.second.size;
                }

                // 打印资源类型分布
                LogMessage("[内存状态] 资源类型分布:");
                for (const auto& entry : typeCount) {
                    const char* typeName = "未知";
                    switch (entry.first) {
                    case ResourceType::Model: typeName = "模型"; break;
                    case ResourceType::Unit: typeName = "单位"; break;
                    case ResourceType::Terrain: typeName = "地形"; break;
                    case ResourceType::Sound: typeName = "声音"; break;
                    case ResourceType::File: typeName = "文件"; break;
                    case ResourceType::JassVM: typeName = "JassVM"; break;
                    default: break;
                    }

                    LogMessage("  - %s: %zu 块, %zu MB",
                        typeName, entry.second, typeSize[entry.first] / (1024 * 1024));
                }
            }

            // 内存池使用情况
            MemPool::PrintStats();

            lastStatsTime = currentTime;
        }
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// 钩子函数实现
///////////////////////////////////////////////////////////////////////////////

// 创建永久稳定块
void CreatePermanentStabilizers(int count, const char* reason) {
    // 针对Storm堆索引的科学分布
    // 确保覆盖最常用的堆索引范围
    LogMessage("[稳定化] 创建%d个永久稳定块 (%s)", count, reason);

    // 科学分布的大小 - 确保覆盖关键堆索引
    // 黄金比例分布，每个块大小是前一个的约1.618倍
    std::vector<size_t> sizes;
    size_t size = 16;  // 起始大小

    for (int i = 0; i < count; i++) {
        sizes.push_back(size);
        size = (size_t)(size * 1.618);  // 黄金比例
        if (size > 4096) size = 16;     // 重置循环
    }

    // 确保有些特殊大小
    if (count > 10) {
        sizes[3] = 64;
        sizes[7] = 128;
    }

    // 创建稳定块
    for (size_t blockSize : sizes) {
        void* stabilizer = MemPool::CreateStabilizingBlock(blockSize, "永久稳定块");
        if (stabilizer) {
            g_permanentBlocks.push_back(stabilizer);
            LogMessage("[稳定化] 永久块: %p (大小: %zu)", stabilizer, blockSize);
        }
    }
}

void Hooked_StormHeap_CleanupAll() {
    // 防止递归调用
    if (tls_inCleanAll) {
        LogMessage("[CleanAll] 递归调用被阻止");
        return;
    }

    // 时间节流 - 避免频繁CleanAll
    DWORD currentTime = GetTickCount();
    DWORD lastTime = g_lastCleanAllTime.load();
    if (currentTime - lastTime < 2000) {
        //LogMessage("[CleanAll] 触发过于频繁，已跳过");
        return;
    }

    tls_inCleanAll = true;
    g_cleanAllInProgress = true;
    g_lastCleanAllTime.store(currentTime);
    g_cleanAllThreadId = GetCurrentThreadId();

    // 记录当前TLSF块数量
    size_t bigBlocksCount = g_bigBlocks.size();
    if (bigBlocksCount > 0) {
        LogMessage("[CleanAll] 开始执行，当前管理%zu个TLSF块", bigBlocksCount);
    }

    // 保存原始的g_DebugHeapPtr值
    int originalDebugHeapPtr = Storm_g_DebugHeapPtr;

    // 使用增强的安全执行方法
    SafeExecuteCleanupAll();

    // 重置Storm内部状态
    Storm_g_DebugHeapPtr = 0;

    // 检查TLSF块数量变化
    if (bigBlocksCount > 0) {
        LogMessage("[CleanAll] 完成后，TLSF管理块数量: %zu", g_bigBlocks.size());
    }

    // 设置清理完成标志
    g_afterCleanAll = true;
    g_cleanAllInProgress = false;
    g_cleanAllThreadId = 0;

    // 立即结束不安全期
    g_insideUnsafePeriod.store(false);

    tls_inCleanAll = false;

    LogMessage("[CleanAll] 完成，已重置内部状态");

    // 定期验证所有内存块
    g_MemSafety.ValidateAllBlocks();

    // 处理延迟释放队列
    g_MemSafety.ProcessDeferredFreeQueue();
}

// 创建稳定化块的改进函数
void CreateStabilizingBlocks(int cleanAllCount) {
    static int lastCleanAllCount = 0;

    // 仅每 20 次 CleanAll 执行一次
    if (cleanAllCount - lastCleanAllCount < 20) {
        return;
    }

    lastCleanAllCount = cleanAllCount;

    // 清理过期的临时块
    auto it = g_tempStabilizers.begin();
    while (it != g_tempStabilizers.end()) {
        it->ttl--;
        if (it->ttl <= 0) {
            // 释放块
            MemPool::FreeSafe(it->ptr);

            // 从大块管理中移除
            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                g_bigBlocks.erase(it->ptr);
            }

            // 从列表移除
            it = g_tempStabilizers.erase(it);
            LogMessage("[StabilizerBlocks] 释放过期临时块，剩余%zu个",
                g_tempStabilizers.size());
        }
        else {
            ++it;
        }
    }

    // 如果已有足够的临时块，不再创建
    if (g_tempStabilizers.size() >= 5) {
        return;
    }

    // 只创建几个块
    int numBlocks = 2;

    LogMessage("[StabilizerBlocks] 创建%d个临时稳定块 (第%d次CleanAll)",
        numBlocks, cleanAllCount);

    for (int i = 0; i < numBlocks; i++) {
        // 使用更大间隔的块大小
        size_t blockSize = 16 * (1 << i);  // 16, 32, 64...
        void* stabilizer = MemPool::CreateStabilizingBlock(blockSize, "临时稳定块");

        if (stabilizer) {
            LogMessage("[StabilizerBlock] 分配稳定块: %p (大小: %zu)",
                stabilizer, blockSize);

            // 添加到临时块列表
            TempStabilizerBlock block;
            block.ptr = stabilizer;
            block.size = blockSize;
            block.createTime = GetTickCount();
            block.ttl = 10;  // 10次 CleanAll 生命周期

            g_tempStabilizers.push_back(block);

            // 记录到大块管理
            BigBlockInfo info;
            info.rawPtr = static_cast<char*>(stabilizer) - sizeof(StormAllocHeader);
            info.size = blockSize;
            info.timestamp = GetTickCount();
            info.source = _strdup("临时稳定块");
            info.srcLine = 0;
            info.type = ResourceType::Unknown;

            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                g_bigBlocks[stabilizer] = info;
            }
        }
    }

    LogMessage("[StabilizerBlocks] 稳定化块创建完成");
}

void ManageTempStabilizers(int currentCleanCount) {
    // 移除过期的临时块
    auto it = g_tempStabilizers.begin();
    while (it != g_tempStabilizers.end()) {
        it->ttl--;
        if (it->ttl <= 0) {
            // 释放此块
            MemPool::FreeSafe(it->ptr);

            // 从大块管理中移除
            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                g_bigBlocks.erase(it->ptr);
            }

            // 从列表移除
            it = g_tempStabilizers.erase(it);
            LogMessage("[StabilizerBlocks] 释放过期临时块，剩余%zu个",
                g_tempStabilizers.size());
        }
        else {
            ++it;
        }
    }
}
// Hook: SMemAlloc - 处理大块分配
size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, const char* name, DWORD src_line, DWORD flag) {
    // 检查是否在 CleanAll 后的第一次分配
    bool isAfterCleanAll = g_afterCleanAll.exchange(false);
    if (isAfterCleanAll) {
        static int cleanAllCounter = 0;
        cleanAllCounter++;
        CreateStabilizingBlocks(cleanAllCounter);
    }

    // 检查是否为 JassVM 相关分配 - 使用严格的识别
    bool isJassVM = false;

    if (name) {
        if (size == 10408 && strstr(name, "Instance.cpp")) {
            void* jassPtr = JVM_MemPool::Allocate(size);
            if (jassPtr) {
                g_memStats.OnAlloc(size);
                return reinterpret_cast<size_t>(jassPtr);
            }
            // 分配失败回退到 Storm
            LogMessage("[JassVM] 分配失败，回退到 Storm: %zu 字节", size);
        }
    }
    // 分配策略：大块使用 TLSF，小块使用 Storm
    bool useTLSF = (size >= g_bigThreshold.load());

    if (useTLSF) {
        // 使用 TLSF 分配
        size_t totalSize = size + sizeof(StormAllocHeader);
        void* rawPtr = MemPool::AllocateSafe(totalSize);

        if (!rawPtr) {
            LogMessage("[Alloc] TLSF 分配失败: %zu 字节, 回退到 Storm", size);
            return s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        }

        // 设置用户指针和兼容头
        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        // 注册到内存安全系统
        g_MemSafety.RegisterMemoryBlock(rawPtr, userPtr, size, name, src_line);

        // 记录此块信息
        BigBlockInfo info;
        info.rawPtr = rawPtr;
        info.size = size;
        info.timestamp = GetTickCount();
        info.source = name ? _strdup(name) : nullptr;
        info.srcLine = src_line;
        info.type = GetResourceType(name);

        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
            g_bigBlocks[userPtr] = info;
        }

        g_memStats.OnAlloc(size);
        return reinterpret_cast<size_t>(userPtr);
    }
    else {
        // 小块使用 Storm 原始分配
        size_t ret = s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        if (ret) {
            g_memStats.OnAlloc(size);
        }
        return ret;
    }
}

// Hook: SMemFree - 处理释放
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4) {
    if (!a1) return 1;  // 空指针认为成功

    void* ptr = reinterpret_cast<void*>(a1);

    // 先检查是否为 JVM_MemPool 指针
    if (JVM_MemPool::IsFromPool(ptr)) {
        // 使用 JVM_MemPool 专用释放
        JVM_MemPool::Free(ptr);
        return 1;
    }

    bool ourBlock = false;
    bool permanentBlock = false;

    __try {
        // 先执行最轻量级的检查
        permanentBlock = IsPermanentBlock(ptr);
        if (permanentBlock) {
            LogMessage("[Free] 忽略永久块释放: %p", ptr);
            return 1; // 假装成功
        }

        // 检查是否为我们管理的块
        ourBlock = IsOurBlock(ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 如果检查过程中出现异常，认为不是我们的块
        LogMessage("[Free] 检查指针时出现异常: %p", ptr);
        return s_origStormFree(a1, name, argList, a4);
    }

    // 常规释放流程
    if (ourBlock) {
        __try {
            // 使用专用安全区域包装释放流程
            CRITICAL_SECTION safeCS;
            __try {
                InitializeCriticalSection(&safeCS);
                EnterCriticalSection(&safeCS);

                // 获取块信息
                bool blockFound = false;
                BigBlockInfo blockInfo = {};

                auto it = g_bigBlocks.find(ptr);
                if (it != g_bigBlocks.end()) {
                    blockInfo = it->second;
                    g_bigBlocks.erase(it);
                    blockFound = true;
                }

                LeaveCriticalSection(&safeCS);

                if (blockFound) {
                    g_memStats.OnFree(blockInfo.size);

                    // 安全取消注册
                    g_MemSafety.TryUnregisterBlock(ptr);

                    // 释放名称字符串
                    if (blockInfo.source) {
                        free((void*)blockInfo.source);
                    }

                    // 释放实际内存
                    MemPool::FreeSafe(blockInfo.rawPtr);
                    g_freedByFreeHook++;
                }
                else {
                    LogMessage("[Free] 未找到注册的块: %p", ptr);

                    // 尝试释放原始内存
                    void* rawPtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
                    MemPool::FreeSafe(rawPtr);
                    g_freedByFreeHook++;
                }
            }
            __finally {
                DeleteCriticalSection(&safeCS);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[Free] 释放过程异常: %p, 错误=0x%x", ptr, GetExceptionCode());
        }
        return 1;
    }
    else {
        // 不是我们的块，使用 Storm 释放
        return s_origStormFree(a1, name, argList, a4);
    }
}

// Hook: SMemReAlloc - 处理重分配
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag)
{
    // 1. 基本边界情况处理
    if (!oldPtr) {
        return reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        return nullptr;
    }

    // 2. 检查是否是 JVM_MemPool 内存
    if (JVM_MemPool::IsFromPool(oldPtr)) {
        // 使用 JVM_MemPool 专用重分配
        return JVM_MemPool::Realloc(oldPtr, newSize);
    }

    // 3. 永久块特殊处理
    if (IsPermanentBlock(oldPtr)) {
        LogMessage("[Realloc] 检测到永久块重分配: %p, 新大小=%zu", oldPtr, newSize);
        void* newPtr = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));

        if (newPtr) {
            // 只复制最少必要数据
            SafeMemCopy(newPtr, oldPtr, min(64, newSize));
        }

        return newPtr;
    }

    // 3. 不安全期特殊处理
    bool inUnsafePeriod = g_cleanAllInProgress || g_insideUnsafePeriod.load();
    if (inUnsafePeriod) {
        if (IsOurBlock(oldPtr)) {
            LogMessage("[Realloc] 不安全期间处理: %p, 新大小=%zu", oldPtr, newSize);

            // 只分配，不释放
            void* newPtr = reinterpret_cast<void*>(
                Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));

            if (!newPtr) {
                return nullptr;
            }

            // 尝试安全复制
            size_t oldSize = GetBlockSize(oldPtr);
            if (oldSize > 0) {
                SafeMemCopy(newPtr, oldPtr, min(oldSize, newSize));
            }
            else {
                // 如果无法获取大小，只复制少量数据
                SafeMemCopy(newPtr, oldPtr, min(64, newSize));
            }

            // 将oldPtr放入延迟释放队列
            g_MemSafety.EnqueueDeferredFree(oldPtr, oldSize);

            return newPtr;
        }

        // 不是我们的块，使用原始函数
        return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
    }

    // 4. 确定重分配策略
    bool isOurOldBlock = IsOurBlock(oldPtr);
    bool shouldUseTLSF = (newSize >= g_bigThreshold.load()) ||
        IsSpecialBlockAllocation(newSize, name, src_line);

    // 5. 我们管理的块重分配
    if (isOurOldBlock) {
        // 先声明所有需要的变量
        void* newPtr = nullptr;
        void* newRawPtr = nullptr;
        size_t oldSize = 0;
        const char* oldSource = nullptr;
        DWORD oldTime = 0;
        DWORD oldLine = 0;
        ResourceType oldType = ResourceType::Unknown;
        void* oldRawPtr = nullptr;

        // 使用SafeCriticalSection而不是std::lock_guard
        SafeCriticalSection* blockLock = new SafeCriticalSection();
        blockLock->Enter();

        // 获取块信息
        auto it = g_bigBlocks.find(oldPtr);
        bool blockFound = (it != g_bigBlocks.end());

        if (blockFound) {
            oldSize = it->second.size;
            oldSource = it->second.source;
            oldTime = it->second.timestamp;
            oldLine = it->second.srcLine;
            oldType = it->second.type;
            oldRawPtr = it->second.rawPtr;
        }

        blockLock->Leave();
        delete blockLock;

        if (!blockFound) {
            LogMessage("[Realloc] 警告: 未找到注册的块: %p", oldPtr);
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }

        if (shouldUseTLSF) {
            // 仍然使用TLSF重分配
            __try {
                // 重新分配
                newRawPtr = MemPool::ReallocSafe(oldRawPtr, newSize + sizeof(StormAllocHeader));

                if (!newRawPtr) {
                    LogMessage("[Realloc] TLSF重分配失败, 大小=%zu", newSize);
                    return nullptr;
                }

                newPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
                SetupCompatibleHeader(newPtr, newSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[Realloc] TLSF重分配异常: %p, 错误=0x%x",
                    oldPtr, GetExceptionCode());
                return nullptr;
            }

            // 更新安全系统
            g_MemSafety.UnregisterMemoryBlock(oldPtr);
            g_MemSafety.RegisterMemoryBlock(newRawPtr, newPtr, newSize, name, src_line);

            // 更新大块跟踪
            SafeCriticalSection* updateLock = new SafeCriticalSection();
            updateLock->Enter();

            if (newPtr != oldPtr) {
                // 指针变化，更新映射
                g_bigBlocks.erase(oldPtr);

                BigBlockInfo info;
                info.rawPtr = newRawPtr;
                info.size = newSize;
                info.timestamp = GetTickCount();
                info.source = name ? _strdup(name) : (oldSource ? _strdup(oldSource) : nullptr);
                info.srcLine = src_line;
                info.type = oldType;

                g_bigBlocks[newPtr] = info;
            }
            else {
                // 指针未变，只更新大小
                auto it2 = g_bigBlocks.find(oldPtr);
                if (it2 != g_bigBlocks.end()) {
                    it2->second.size = newSize;
                }
            }

            updateLock->Leave();
            delete updateLock;

            // 更新统计
            g_memStats.OnFree(oldSize);
            g_memStats.OnAlloc(newSize);

            return newPtr;
        }
        else {
            // 新块变小，转为Storm管理
            __try {
                // 使用Storm分配新块
                newPtr = reinterpret_cast<void*>(s_origStormAlloc(ecx, edx, newSize, name, src_line, flag));

                if (!newPtr) {
                    LogMessage("[Realloc] Storm分配失败");
                    return nullptr;
                }

                // 安全复制数据
                SafeMemCopy(newPtr, oldPtr, min(oldSize, newSize));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[Realloc] Storm分配或复制异常: %p, 错误=0x%x",
                    oldPtr, GetExceptionCode());
                return nullptr;
            }

            // 取消注册
            g_MemSafety.UnregisterMemoryBlock(oldPtr);

            // 释放TLSF旧块
            SafeCriticalSection* freeLock = new SafeCriticalSection();
            freeLock->Enter();

            auto it2 = g_bigBlocks.find(oldPtr);
            if (it2 != g_bigBlocks.end()) {
                if (it2->second.source) {
                    free((void*)it2->second.source);
                }
                MemPool::FreeSafe(it2->second.rawPtr);
                g_bigBlocks.erase(it2);
            }

            freeLock->Leave();
            delete freeLock;

            // 更新统计
            g_memStats.OnFree(oldSize);
            g_memStats.OnAlloc(newSize);

            return newPtr;
        }
    }

    // 6. Storm管理的块重分配
    else {
        if (shouldUseTLSF) {
            // 新块是大块，转为TLSF管理
            void* newRawPtr = nullptr;
            void* newUserPtr = nullptr;

            __try {
                // 分配新的TLSF块
                size_t totalSize = newSize + sizeof(StormAllocHeader);
                newRawPtr = MemPool::AllocateSafe(totalSize);

                if (!newRawPtr) {
                    LogMessage("[Realloc] TLSF分配失败，回退到Storm");
                    return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
                }

                newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
                SetupCompatibleHeader(newUserPtr, newSize);

                // 尝试获取旧块大小
                size_t oldSize = GetBlockSize(oldPtr);

                // 安全复制数据
                if (oldSize > 0) {
                    SafeMemCopy(newUserPtr, oldPtr, min(oldSize, newSize));
                }
                else {
                    // 保守估计复制大小
                    SafeMemCopy(newUserPtr, oldPtr, min(newSize, (size_t)128));
                }

                // 释放Storm旧块
                s_origStormFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[Realloc] Storm到TLSF转换异常: %p, 错误=0x%x",
                    oldPtr, GetExceptionCode());

                if (newRawPtr) {
                    MemPool::FreeSafe(newRawPtr);
                }

                return nullptr;
            }

            // 注册新块
            g_MemSafety.RegisterMemoryBlock(newRawPtr, newUserPtr, newSize, name, src_line);

            // 记录大块信息
            SafeCriticalSection* blockLock = new SafeCriticalSection();
            blockLock->Enter();

            BigBlockInfo info;
            info.rawPtr = newRawPtr;
            info.size = newSize;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : nullptr;
            info.srcLine = src_line;
            info.type = GetResourceType(name);

            g_bigBlocks[newUserPtr] = info;

            blockLock->Leave();
            delete blockLock;

            g_memStats.OnAlloc(newSize);
            return newUserPtr;
        }
        else {
            // 小块使用Storm重分配
            void* result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            if (result) {
                g_memStats.OnAlloc(newSize);
            }
            return result;
        }
    }
}


///////////////////////////////////////////////////////////////////////////////
// 钩子安装和初始化
///////////////////////////////////////////////////////////////////////////////

bool InitializeStormMemoryHooks() {
    // 初始化新的日志系统
    if (!LogSystem::GetInstance().Initialize()) {
        printf("[错误] 无法初始化日志系统\n");
        return false;
    }

    LogMessage("[Init] 正在初始化Storm内存钩子...");

    // 初始化内存安全系统
    if (!g_MemSafety.Initialize()) {
        LogMessage("[Init] 内存安全系统初始化失败");
        return false;
    }

    // 查找Storm.dll基址
    HMODULE stormDll = GetModuleHandleA("Storm.dll");
    if (!stormDll) {
        LogMessage("[Init] 未找到Storm.dll模块");
        return false;
    }

    gStormDllBase = reinterpret_cast<uintptr_t>(stormDll);
    LogMessage("[Init] 找到Storm.dll，基址: 0x%08X", gStormDllBase);

    // 初始化原始函数指针
    s_origStormAlloc = reinterpret_cast<Storm_MemAlloc_t>(gStormDllBase + 0x2B830);
    s_origStormFree = reinterpret_cast<Storm_MemFree_t>(gStormDllBase + 0x2BE40);
    s_origStormReAlloc = reinterpret_cast<Storm_MemReAlloc_t>(gStormDllBase + 0x2C8B0);
    s_origCleanupAll = reinterpret_cast<StormHeap_CleanupAll_t>(gStormDllBase + 0x2AB50);

    LogMessage("[Init] Storm函数地址: Alloc=%p, Free=%p, Realloc=%p, CleanupAll=%p",
        s_origStormAlloc, s_origStormFree, s_origStormReAlloc, s_origCleanupAll);

    // 验证函数指针
    if (!s_origStormAlloc || !s_origStormFree || !s_origStormReAlloc || !s_origCleanupAll) {
        LogMessage("[Init] 无法找到Storm内存函数");
        return false;
    }

    // 初始化 JassVM 内存管理
    JVM_MemPool::Initialize();

    // 初始化TLSF内存池
    MemPool::Initialize(TLSF_MAIN_POOL_SIZE);

    // 创建永久稳定块，使用更广泛的大小分布
    CreatePermanentStabilizers(25, "全周期保护");

    // 安装钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    DetourAttach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    DetourAttach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    DetourAttach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LogMessage("[Init] 安装钩子失败，错误: %ld", result);
        return false;
    }

    // 启动统计线程
    HANDLE hThread = CreateThread(nullptr, 0, MemoryStatsThread, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    void* stabilizer = MemPool::CreateStabilizingBlock(32, "初始稳定块");
    if (stabilizer) {
        LogMessage("[Init] 稳定块分配成功: %p", stabilizer);
        g_permanentBlocks.push_back(stabilizer);
    }

    // 重置Storm的g_DebugHeapPtr，防止初始CleanAll触发
    Storm_g_DebugHeapPtr = 0;

    // 输出初始内存报告
    GenerateMemoryReport(true);

    LogMessage("[Init] Storm内存钩子安装成功！");
    return true;
}

// 修改 ShutdownStormMemoryHooks 函数，关闭日志系统
void ShutdownStormMemoryHooks() {
    LogMessage("[关闭] 正在移除Storm内存钩子...");

    // 最后的内存报告
    GenerateMemoryReport(true);

    // 关闭内存安全系统
    g_MemSafety.Shutdown();

    // 标记进入不安全期，防止后续内存操作
    g_insideUnsafePeriod.store(true);

    // 等待任何进行中的内存操作完成
    Sleep(100);

    // 卸载钩子
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (s_origStormAlloc) DetourDetach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    if (s_origStormFree) DetourDetach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    if (s_origStormReAlloc) DetourDetach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    if (s_origCleanupAll) DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);

    DetourTransactionCommit();

    // 释放所有永久块的引用（但不实际释放内存）
    g_permanentBlocks.clear();

    // 释放所有大块
    {
        std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
        LogMessage("[关闭] 释放%zu个追踪块", g_bigBlocks.size());

        for (auto& entry : g_bigBlocks) {
            if (entry.second.source) free((void*)entry.second.source);
        }

        g_bigBlocks.clear();
    }

    // 清理TLSF内存池
    MemPool::Shutdown();

    // 关闭 JassVM 内存管理
    JVM_MemPool::Cleanup();

    // 关闭日志系统
    LogSystem::GetInstance().Shutdown();

    LogMessage("[关闭] Storm内存钩子已移除");
}