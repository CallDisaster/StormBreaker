// StormHook.cpp 修复版

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
std::atomic<bool> g_shouldExit{ false };
std::atomic<bool> g_disableActualFree{ false };
std::atomic<bool> g_disableMemoryReleasing{ false };
HANDLE g_statsThreadHandle = NULL;

// 全局变量定义
std::atomic<size_t> g_bigThreshold{ 128 * 1024 };      // 默认512KB为大块阈值
// 主内存池大小: 32MB
constexpr size_t TLSF_MAIN_POOL_SIZE = 64 * 1024 * 1024;
std::mutex g_bigBlocksMutex;
std::unordered_map<void*, BigBlockInfo> g_bigBlocks;
MemoryStats g_memStats;
std::atomic<bool> g_cleanAllInProgress{ false };
DWORD g_cleanAllThreadId = 0;
static std::vector<void*> g_permanentBlocks;
std::vector<TempStabilizerBlock> g_tempStabilizers;
std::mutex g_poolMutexes[LOCK_SHARDS];
std::atomic<size_t> g_totalLockWaitTime{ 0 };
std::atomic<size_t> g_lockWaitCount{ 0 };
ImprovedLargeBlockCache g_largeBlockCache;
DetailedAllocProfiler g_detailedProfiler;
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
// 优化实现
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// 辅助函数
///////////////////////////////////////////////////////////////////////////////

// 锁等待时间统计报告函数
void PrintLockStats() {
    size_t totalWait = g_totalLockWaitTime.load();
    size_t waitCount = g_lockWaitCount.load();

    LogMessage("[锁统计] 总等待时间: %zu ms", totalWait);
    LogMessage("[锁统计] 锁操作次数: %zu", waitCount);

    if (waitCount > 0) {
        double avgWait = (double)totalWait / waitCount;
        LogMessage("[锁统计] 平均等待时间: %.2f ms", avgWait);
    }

    // 重置统计
    g_totalLockWaitTime.store(0);
    g_lockWaitCount.store(0);
}

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

// 使用mimalloc替代TLSF，但保持函数名称和行为一致，方便兼容现有代码
size_t GetTLSFPoolUsage() {
    // 获取mimalloc内存池已用大小
    return MemPool::GetUsedSize();
}

size_t GetTLSFPoolTotal() {
    // 获取mimalloc内存池总大小
    return MemPool::GetTotalSize();
}

// 生成完整的内存报告，兼容现有函数逻辑但引用mimalloc
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
    size_t miUsed = GetTLSFPoolUsage();     // 实际使用mimalloc，但函数名保持一致
    size_t miTotal = GetTLSFPoolTotal();    // 实际使用mimalloc，但函数名保持一致
    size_t managed = g_bigBlocks.size();
    size_t cachedBlocks = g_largeBlockCache.GetCacheSize();

    // 计算使用率
    double miUsagePercent = miTotal > 0 ? (miUsed * 100.0 / miTotal) : 0.0;

    // 获取进程整体内存使用情况
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);

    size_t workingSetMB = 0;
    size_t virtualMemMB = 0;

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
        virtualMemMB = pmc.PagefileUsage / (1024 * 1024);
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
        "mimalloc 内存池: %zu MB / %zu MB (%.1f%%)\n"
        "mimalloc 管理块数量: %zu\n"
        "大块缓存: %zu 个\n"
        "工作集大小: %zu MB\n"
        "虚拟内存总量: %zu MB\n"
        "========================\n",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        miUsed / (1024 * 1024), miTotal / (1024 * 1024), miUsagePercent,
        managed,
        cachedBlocks,
        workingSetMB,
        virtualMemMB
    );

    // 同时输出到控制台和日志
    printf("%s", reportBuffer);
    LogMessage("\n%s", reportBuffer);
}

// 简化版状态输出，适合频繁调用，兼容原有函数
void PrintMemoryStatus() {
    // 获取当前系统时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    size_t stormVMUsage = GetStormVirtualMemoryUsage();
    size_t miUsed = GetTLSFPoolUsage();     // 实际使用量
    size_t miTotal = GetTLSFPoolTotal();    // 总容量

    // 确保值的合理性
    if (miUsed > miTotal) {
        LogMessage("[警告] 内存使用量(%zu MB)超过总容量(%zu MB)，调整显示",
            miUsed / (1024 * 1024), miTotal / (1024 * 1024));
        miTotal = miUsed * 3 / 2;  // 总容量应该至少比已用量大50%
    }

    // 正确计算使用率
    double miUsagePercent = miTotal > 0 ? (miUsed * 100.0 / miTotal) : 0.0;

    printf("[%02d:%02d:%02d] [内存] Storm: %zu MB, mimalloc: %zu/%zu MB (%.1f%%)\n",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        miUsed / (1024 * 1024),
        miTotal / (1024 * 1024),
        miUsagePercent);

    LogMessage("[%02d:%02d:%02d] [内存] Storm: %zu MB, mimalloc: %zu/%zu MB (%.1f%%)",
        st.wHour, st.wMinute, st.wSecond,
        stormVMUsage / (1024 * 1024),
        miUsed / (1024 * 1024),
        miTotal / (1024 * 1024),
        miUsagePercent);
}

// 替代方案：使用SEH和函数封装
LONG WINAPI CustomUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo) {
    LogMessage("[CleanAll] 捕获到异常: 0x%08X", pExceptionInfo->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER; // 继续执行
}

// 安全内存复制函数
bool SafeMemCopy(void* dest, const void* src, size_t size) noexcept {
    if (!dest || !src || size == 0) return false;

    // 先检查源和目标指针的有效性
    if (!IsValidPointer(dest) || !IsValidPointer(src)) {
        LogMessage("[SafeMemCopy] 无效指针: dest=%p, src=%p", dest, src);
        return false;
    }

    // 检查目标内存大小是否足够
    size_t destSize = MemPool::GetBlockSize(dest);
    if (destSize > 0 && destSize < size) {
        LogMessage("[SafeMemCopy] 目标内存不足: dest=%p, destSize=%zu, copySize=%zu",
            dest, destSize, size);
        // 只复制安全范围内的数据
        size = destSize;
    }

    __try {
        // 分块复制，避免大块复制时出现问题
        const size_t CHUNK_SIZE = 4096;
        const char* srcPtr = static_cast<const char*>(src);
        char* destPtr = static_cast<char*>(dest);

        for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
            size_t bytesToCopy = (offset + CHUNK_SIZE > size) ? (size - offset) : CHUNK_SIZE;

            // 再次检查每个分块的指针有效性
            if (!IsValidPointer(destPtr + offset) || !IsValidPointer(srcPtr + offset)) {
                LogMessage("[SafeMemCopy] 分块指针无效: offset=%zu", offset);
                return offset > 0; // 如果已经复制了一部分，返回部分成功
            }

            __try {
                memcpy(destPtr + offset, srcPtr + offset, bytesToCopy);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[SafeMemCopy] 内存复制异常: offset=%zu, 错误=0x%x",
                    offset, GetExceptionCode());
                return offset > 0; // 如果已经复制了一部分，返回部分成功
            }
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[SafeMemCopy] 内存复制总异常: dest=%p, src=%p, size=%zu, 错误=0x%x",
            dest, src, size, GetExceptionCode());
        return false;
    }
}

// 辅助函数 - 检查指针有效性
bool IsValidPointer(const void* ptr) {
    if (!ptr) return false;

    __try {
        // 尝试读取第一个字节验证可读
        volatile char test = *static_cast<const char*>(ptr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool IsValidMemoryBlock(void* ptr, size_t expectedSize = 0) {
    if (!ptr) return false;

    __try {
        // 先读取第一个字节验证可访问性
        volatile unsigned char firstByte = *(volatile unsigned char*)ptr;

        // 如果指定了期望大小，验证整个块是否可访问
        if (expectedSize > 0) {
            volatile unsigned char lastByte = *(volatile unsigned char*)((char*)ptr + expectedSize - 1);
        }

        // 如果是我们的块，验证头部
        if (IsOurBlock(ptr)) {
            StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                static_cast<char*>(ptr) - sizeof(StormAllocHeader));
            return (header->Magic == STORM_MAGIC);
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[安全] 内存块验证失败: %p", ptr);
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
ResourceType GetResourceType(const char* name, size_t size) {
    if (!name) return ResourceType::Unknown;

    // 基于源文件路径和函数名判断
    if (strstr(name, "Model") || strstr(name, "GEOSET") || strstr(name, "MDX") ||
        strstr(name, "model") || strstr(name, "geoset")) {
        return ResourceType::Model;
    }

    if (strstr(name, "CUnit") || strstr(name, "Unit") ||
        strstr(name, "unit") || strstr(name, "Actor")) {
        return ResourceType::Unit;
    }

    if (strstr(name, "Terrain") || strstr(name, "Ground") ||
        strstr(name, "terrain") || strstr(name, "TerrainImage")) {
        return ResourceType::Terrain;
    }

    if (strstr(name, "Sound") || strstr(name, "SND") || strstr(name, "Audio") ||
        strstr(name, "OsSnd.cpp") || strstr(name, "sound")) {
        return ResourceType::Sound;
    }

    if (strstr(name, "SFile") || strstr(name, "File") ||
        strstr(name, "file") || strstr(name, ".mpq")) {
        return ResourceType::File;
    }

    if (strstr(name, "Instance.cpp") || strstr(name, "jass") ||
        strstr(name, "Jass") || strstr(name, "script")) {
        return ResourceType::JassVM;
    }

    if (strstr(name, "GxuFont") || strstr(name, "Font") ||
        strstr(name, "text") || strstr(name, "Text")) {
        return ResourceType::Font;
    }

    if (strstr(name, "UI") || strstr(name, "Interface") ||
        strstr(name, "Window") || strstr(name, "Panel")) {
        return ResourceType::UI;
    }

    // 基于大小的启发式判断
    if (size > 1024 * 1024) { // 超过1MB
        if (strstr(name, ".M")) return ResourceType::Model;
        if (size > 10 * 1024 * 1024) return ResourceType::Terrain; // 超大块可能是地形
    }

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
// 统计信息线程
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI MemoryStatsThread(LPVOID) {
    LogMessage("[StatsThread] 内存监控线程已启动");

    DWORD lastCleanupTime = GetTickCount();
    DWORD lastStatsTime = GetTickCount();
    DWORD lastReportTime = GetTickCount();
    DWORD lastLockStatsTime = GetTickCount(); // 锁统计时间戳

    while (!g_shouldExit.load()) {
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

            // 大块缓存状态
            LogMessage("[内存状态] 大块缓存大小: %zu", g_largeBlockCache.GetCacheSize());

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
                    case ResourceType::Font: typeName = "字体"; break;
                    case ResourceType::UI: typeName = "界面"; break;
                    default: break;
                    }

                    LogMessage("  - %s: %zu 块, %zu MB",
                        typeName, entry.second, typeSize[entry.first] / (1024 * 1024));
                }
            }

            // 打印分配分析统计
            g_detailedProfiler.PrintStats();

            // 内存池使用情况
            MemPool::PrintStats();

            lastStatsTime = currentTime;
        }

        // 每分钟报告一次锁等待统计
        if (currentTime - lastLockStatsTime > 60000) {
            PrintLockStats();
            lastLockStatsTime = currentTime;
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
    if (currentTime - lastTime < 5000) {
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
    static int verifyCounter = 0;
    if (++verifyCounter >= 10) {
        g_MemSafety.ValidateAllBlocks();
        verifyCounter = 0;
    }

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
            // 检查指针有效性
            if (it->ptr) {
                // 先从big blocks中移除
                {
                    std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                    g_bigBlocks.erase(it->ptr);
                }

                // 不直接调用Free，使用VirtualFree
                void* rawPtr = static_cast<char*>(it->ptr) - sizeof(StormAllocHeader);
                VirtualFree(rawPtr, 0, MEM_RELEASE);
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
    // 记录分配类型和大小（锁外完成）
    ResourceType type = GetResourceType(name, size);
    g_detailedProfiler.RecordAllocation(size, name, type);

    // 检查是否在 CleanAll 后的第一次分配（锁外完成）
    bool isAfterCleanAll = g_afterCleanAll.exchange(false);
    if (isAfterCleanAll) {
        static int cleanAllCounter = 0;
        cleanAllCounter++;
        CreateStabilizingBlocks(cleanAllCounter);
    }

    // 检查是否为 JassVM 相关分配（锁外完成）
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

    // 分配策略判断（锁外完成）
    bool useMiMalloc = (size >= g_bigThreshold.load());

    if (useMiMalloc) {
        // 先尝试从缓存获取大块（只需要缓存的锁，不需要全局锁）
        void* cachedPtr = g_largeBlockCache.GetBlock(size + sizeof(StormAllocHeader));
        if (cachedPtr) {
            void* userPtr = static_cast<char*>(cachedPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);

            // 记录此块信息（需要锁保护）
            BigBlockInfo info;
            info.rawPtr = cachedPtr;
            info.size = size;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : nullptr;
            info.srcLine = src_line;
            info.type = GetResourceType(name, size);

            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                g_bigBlocks[userPtr] = info;
            }

            g_memStats.OnAlloc(size);
            return reinterpret_cast<size_t>(userPtr);
        }

        // 缓存未命中，使用 mimalloc 分配（使用分片锁）
        size_t totalSize = size + sizeof(StormAllocHeader);
        void* rawPtr = nullptr;

        // 获取分片索引
        size_t lockIndex = MemPool::get_shard_index(nullptr, size);

        // 开始计时
        DWORD lockStartTime = GetTickCount();

        {
            // 使用分片锁保护分配操作
            std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

            // 记录锁等待时间
            DWORD lockWaitTime = GetTickCount() - lockStartTime;
            g_totalLockWaitTime.fetch_add(lockWaitTime);
            g_lockWaitCount.fetch_add(1);

            rawPtr = MemPool::AllocateSafe(totalSize);
        }

        if (!rawPtr) {
            LogMessage("[Alloc] mimalloc 分配失败: %zu 字节, 回退到 Storm", size);
            return s_origStormAlloc(ecx, edx, size, name, src_line, flag);
        }

        // 设置用户指针和兼容头（锁外完成）
        void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size);

        // 注册到内存安全系统（锁外完成）
        g_MemSafety.RegisterMemoryBlock(rawPtr, userPtr, size, name, src_line);

        // 记录此块信息（需要锁保护）
        BigBlockInfo info;
        info.rawPtr = rawPtr;
        info.size = size;
        info.timestamp = GetTickCount();
        info.source = name ? _strdup(name) : nullptr;
        info.srcLine = src_line;
        info.type = GetResourceType(name,size);

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

    // 先检查是否为 JVM_MemPool 指针（锁外完成）
    if (JVM_MemPool::IsFromPool(ptr)) {
        // 使用 JVM_MemPool 专用释放
        JVM_MemPool::Free(ptr);
        return 1;
    }

    bool ourBlock = false;
    bool permanentBlock = false;

    // 使用C++异常处理检查指针（锁外完成）
    try {
        // 先执行最轻量级的检查
        permanentBlock = IsPermanentBlock(ptr);
        if (permanentBlock) {
            LogMessage("[Free] 忽略永久块释放: %p", ptr);
            return 1; // 假装成功
        }

        // 检查是否为我们管理的块
        ourBlock = IsOurBlock(ptr);
    }
    catch (...) {
        // 如果检查过程中出现异常，认为不是我们的块
        LogMessage("[Free] 检查指针时出现异常: %p", ptr);
        return s_origStormFree(a1, name, argList, a4);
    }

    // 常规释放流程
    if (ourBlock) {
        // 获取块信息
        bool blockFound = false;
        BigBlockInfo blockInfo = {};

        try {
            // 获取块信息（需要锁保护）
            {
                std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
                auto it = g_bigBlocks.find(ptr);
                if (it != g_bigBlocks.end()) {
                    blockInfo = it->second;
                    g_bigBlocks.erase(it);
                    blockFound = true;
                }
            }

            if (blockFound) {
                g_memStats.OnFree(blockInfo.size);

                // 在找到块信息后添加记录
                g_detailedProfiler.RecordFree(blockInfo.size, blockInfo.type);

                // 安全取消注册（锁外完成）
                g_MemSafety.TryUnregisterBlock(ptr);

                // 释放名称字符串（锁外完成）
                if (blockInfo.source) {
                    free((void*)blockInfo.source);
                }

                // 获取分片索引
                size_t lockIndex = MemPool::get_shard_index(ptr);

                // 开始计时
                DWORD lockStartTime = GetTickCount();

                // 根据大小决定是否放入缓存
                if (blockInfo.size >= g_bigThreshold.load()) {
                    // 尝试放入缓存
                    if (g_largeBlockCache.GetCacheSize() < 10) {
                        g_largeBlockCache.ReleaseBlock(blockInfo.rawPtr, blockInfo.size);
                    }
                    // 缓存已满，直接释放
                    else {
                        // 使用分片锁保护释放操作
                        std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

                        // 记录锁等待时间
                        DWORD lockWaitTime = GetTickCount() - lockStartTime;
                        g_totalLockWaitTime.fetch_add(lockWaitTime);
                        g_lockWaitCount.fetch_add(1);

                        MemPool::FreeSafe(ptr);
                    }
                }
                // 小块直接释放
                else {
                    // 使用分片锁保护释放操作
                    std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

                    // 记录锁等待时间
                    DWORD lockWaitTime = GetTickCount() - lockStartTime;
                    g_totalLockWaitTime.fetch_add(lockWaitTime);
                    g_lockWaitCount.fetch_add(1);

                    MemPool::FreeSafe(ptr);
                }

                g_freedByFreeHook++;
            }
            else {
                LogMessage("[Free] 未找到注册的块: %p", ptr);

                // 尝试释放原始内存
                void* rawPtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);

                // 获取分片索引
                size_t lockIndex = MemPool::get_shard_index(ptr);

                // 使用分片锁保护释放操作
                std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);
                MemPool::FreeSafe(rawPtr);
                g_freedByFreeHook++;
            }
        }
        catch (const std::exception& e) {
            LogMessage("[Free] 释放过程异常: %p, 错误=%s", ptr, e.what());
        }
        catch (...) {
            LogMessage("[Free] 释放过程未知异常: %p", ptr);
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

    // 基本边界情况处理（锁外完成）
    if (!oldPtr) {
        return reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));
    }

    if (newSize == 0) {
        Hooked_Storm_MemFree(reinterpret_cast<int>(oldPtr), const_cast<char*>(name), src_line, flag);
        return nullptr;
    }

    // 检查是否是 JVM_MemPool 内存（锁外完成）
    if (JVM_MemPool::IsFromPool(oldPtr)) {
        // 使用 JVM_MemPool 专用重分配
        return JVM_MemPool::Realloc(oldPtr, newSize);
    }

    // 永久块特殊处理（锁外完成）
    if (IsPermanentBlock(oldPtr)) {
        LogMessage("[Realloc] 检测到永久块重分配: %p, 新大小=%zu", oldPtr, newSize);
        void* newPtr = reinterpret_cast<void*>(Hooked_Storm_MemAlloc(ecx, edx, newSize, name, src_line, flag));

        if (newPtr) {
            // 只复制最少必要数据（锁外完成）
            SafeMemCopy(newPtr, oldPtr, min(64, newSize));
        }

        return newPtr;
    }

    // 不安全期特殊处理（锁外完成）
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

            // 尝试安全复制（锁外完成）
            size_t oldSize = MemPool::GetBlockSize(oldPtr);
            if (oldSize > 0) {
                SafeMemCopy(newPtr, oldPtr, min(oldSize, newSize));
            }
            else {
                // 如果无法获取大小，只复制少量数据
                SafeMemCopy(newPtr, oldPtr, min(64, newSize));
            }

            // 将oldPtr放入延迟释放队列（不释放，只记录）
            g_MemSafety.EnqueueDeferredFree(oldPtr, oldSize);

            return newPtr;
        }

        // 不是我们的块，使用原始函数
        return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
    }

    // 确定重分配策略（锁外完成）
    bool isOurOldBlock = IsOurBlock(oldPtr);
    bool shouldUseMimalloc = (newSize >= g_bigThreshold.load()) ||
        IsSpecialBlockAllocation(newSize, name, src_line);

    // 情况1: 我们的块重分配为我们的块
    if (isOurOldBlock && shouldUseMimalloc) {
        BigBlockInfo oldInfo = {};
        bool blockFound = false;

        // 获取旧块信息（需要锁保护）
        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
            auto it = g_bigBlocks.find(oldPtr);
            if (it != g_bigBlocks.end()) {
                oldInfo = it->second;
                blockFound = true;
            }
        }

        if (!blockFound) {
            LogMessage("[Realloc] 未找到注册的块: %p", oldPtr);
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }

        // 尝试重新分配
        void* newRawPtr = nullptr;
        void* newPtr = nullptr;

        try {
            // 获取分片索引
            size_t lockIndex = MemPool::get_shard_index(oldPtr);

            // 开始计时
            DWORD lockStartTime = GetTickCount();

            {
                // 使用分片锁保护重分配操作
                std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

                // 记录锁等待时间
                DWORD lockWaitTime = GetTickCount() - lockStartTime;
                g_totalLockWaitTime.fetch_add(lockWaitTime);
                g_lockWaitCount.fetch_add(1);

                newRawPtr = MemPool::ReallocSafe(oldInfo.rawPtr, newSize + sizeof(StormAllocHeader));
            }

            if (!newRawPtr) {
                LogMessage("[Realloc] mimalloc重分配失败, 大小=%zu", newSize);
                return nullptr;
            }

            newPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newPtr, newSize);
        }
        catch (...) {
            LogMessage("[Realloc] mimalloc重分配异常: %p", oldPtr);
            return nullptr;
        }

        // 更新安全系统（锁外完成）
        g_MemSafety.UnregisterMemoryBlock(oldPtr);
        g_MemSafety.RegisterMemoryBlock(newRawPtr, newPtr, newSize, name, src_line);

        // 更新大块跟踪
        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);

            if (newPtr != oldPtr) {
                // 指针变化，更新映射
                g_bigBlocks.erase(oldPtr);

                BigBlockInfo info;
                info.rawPtr = newRawPtr;
                info.size = newSize;
                info.timestamp = GetTickCount();
                info.source = name ? _strdup(name) : (oldInfo.source ? _strdup(oldInfo.source) : nullptr);
                info.srcLine = src_line;
                info.type = oldInfo.type;

                g_bigBlocks[newPtr] = info;
            }
            else {
                // 指针未变，只更新大小
                auto it = g_bigBlocks.find(oldPtr);
                if (it != g_bigBlocks.end()) {
                    it->second.size = newSize;
                }
            }
        }

        // 更新统计（锁外完成）
        g_memStats.OnFree(oldInfo.size);
        g_memStats.OnAlloc(newSize);

        // 释放原始源信息字符串（如果存在且已经复制）
        if (oldInfo.source && newPtr != oldPtr) {
            free((void*)oldInfo.source);
        }

        return newPtr;
    }

    // 情况2: 我们的块重分配为Storm块（变小）
    else if (isOurOldBlock && !shouldUseMimalloc) {
        BigBlockInfo oldInfo = {};
        bool blockFound = false;

        // 获取旧块信息（需要锁保护）
        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
            auto it = g_bigBlocks.find(oldPtr);
            if (it != g_bigBlocks.end()) {
                oldInfo = it->second;
                blockFound = true;
            }
        }

        if (!blockFound) {
            LogMessage("[Realloc] 未找到注册的块: %p", oldPtr);
            return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        }

        // 使用Storm分配新块
        void* newPtr = nullptr;

        try {
            newPtr = reinterpret_cast<void*>(s_origStormAlloc(ecx, edx, newSize, name, src_line, flag));
            if (!newPtr) {
                LogMessage("[Realloc] Storm分配失败");
                return nullptr;
            }

            // 安全复制数据（锁外完成）
            SafeMemCopy(newPtr, oldPtr, min(oldInfo.size, newSize));
        }
        catch (...) {
            LogMessage("[Realloc] Storm分配或复制异常");
            if (newPtr) {
                s_origStormFree(reinterpret_cast<int>(newPtr), const_cast<char*>(name), src_line, flag);
            }
            return nullptr;
        }

        // 取消注册（锁外完成）
        g_MemSafety.UnregisterMemoryBlock(oldPtr);

        // 释放mimalloc旧块
        {
            // 从大块映射中移除
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);
            auto it = g_bigBlocks.find(oldPtr);
            if (it != g_bigBlocks.end()) {
                if (it->second.source) {
                    free((void*)it->second.source);
                }

                // 获取分片索引
                size_t lockIndex = MemPool::get_shard_index(oldPtr);

                // 尝试放入大块缓存
                if (g_largeBlockCache.GetCacheSize() < 10) {
                    g_largeBlockCache.ReleaseBlock(it->second.rawPtr, it->second.size);
                }
                else {
                    // 使用分片锁保护释放操作
                    std::lock_guard<std::mutex> memLock(g_poolMutexes[lockIndex]);
                    MemPool::FreeSafe(it->second.rawPtr);
                }

                g_bigBlocks.erase(it);
            }
        }

        // 更新统计（锁外完成）
        g_memStats.OnFree(oldInfo.size);
        g_memStats.OnAlloc(newSize);

        return newPtr;
    }

    // 情况3: Storm块重分配为我们的块（变大）
    else if (!isOurOldBlock && shouldUseMimalloc) {
        void* newRawPtr = nullptr;
        void* newUserPtr = nullptr;

        try {
            // 分配新的mimalloc块
            size_t totalSize = newSize + sizeof(StormAllocHeader);

            // 获取分片索引
            size_t lockIndex = MemPool::get_shard_index(nullptr, newSize);

            // 开始计时
            DWORD lockStartTime = GetTickCount();

            {
                // 使用分片锁保护分配操作
                std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);

                // 记录锁等待时间
                DWORD lockWaitTime = GetTickCount() - lockStartTime;
                g_totalLockWaitTime.fetch_add(lockWaitTime);
                g_lockWaitCount.fetch_add(1);

                newRawPtr = MemPool::AllocateSafe(totalSize);
            }

            if (!newRawPtr) {
                LogMessage("[Realloc] mimalloc分配失败，回退到Storm");
                return s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
            }

            newUserPtr = static_cast<char*>(newRawPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(newUserPtr, newSize);

            // 尝试获取旧块大小（锁外完成）
            size_t oldSize = MemPool::GetBlockSize(oldPtr);

            // 安全复制数据（锁外完成）
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
        catch (...) {
            LogMessage("[Realloc] Storm到mimalloc转换异常");
            if (newRawPtr) {
                // 获取分片索引
                size_t lockIndex = MemPool::get_shard_index(newRawPtr);

                // 使用分片锁保护释放操作
                std::lock_guard<std::mutex> lock(g_poolMutexes[lockIndex]);
                MemPool::FreeSafe(newRawPtr);
            }
            return nullptr;
        }

        // 注册新块（锁外完成）
        g_MemSafety.RegisterMemoryBlock(newRawPtr, newUserPtr, newSize, name, src_line);

        // 记录大块信息
        {
            std::lock_guard<std::mutex> lock(g_bigBlocksMutex);

            BigBlockInfo info;
            info.rawPtr = newRawPtr;
            info.size = newSize;
            info.timestamp = GetTickCount();
            info.source = name ? _strdup(name) : nullptr;
            info.srcLine = src_line;
            info.type = GetResourceType(name, newSize);

            g_bigBlocks[newUserPtr] = info;
        }

        g_memStats.OnAlloc(newSize);
        return newUserPtr;
    }

    // 情况4: Storm块重分配为Storm块
    else {
        // 小块使用Storm重分配
        void* result = s_origStormReAlloc(ecx, edx, oldPtr, newSize, name, src_line, flag);
        if (result) {
            g_memStats.OnAlloc(newSize);
        }
        return result;
    }
}

///////////////////////////////////////////////////////////////////////////////
// 钩子安装和初始化
///////////////////////////////////////////////////////////////////////////////

bool InitializeStormMemoryHooks() {
    // 初始化日志系统
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
    if (hThread) {
        g_statsThreadHandle = hThread;
    }

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

void TransferMemoryOwnership() {
    LogMessage("[关闭] 转移内存管理权限...");

    // 锁住统计数据，防止在转移过程中修改
    std::lock_guard<std::mutex> blockLock(g_bigBlocksMutex);

    // 所有当前由mimalloc管理的块都"放弃"而非释放
    // 只记录日志用于调试，但不实际释放
    LogMessage("[关闭] 放弃管理%zu个mimalloc块的所有权", g_bigBlocks.size());

    for (auto& entry : g_bigBlocks) {
        if (entry.second.source) {
            // 只释放源信息字符串，不释放实际内存块
            free((void*)entry.second.source);
        }
    }

    g_bigBlocks.clear();

    // 禁止mimalloc实际内存释放
    LogMessage("[关闭] 禁用mimalloc内存池释放...");
    // 向mimalloc传递一个全局标志，阻止实际的内存释放
    MemPool::DisableMemoryReleasing();
}

void StopAllWorkThreads() {
    LogMessage("[关闭] 停止所有工作线程...");

    // 设置一个全局退出标志
    g_shouldExit.store(true);

    // 确保统计线程退出
    if (g_statsThreadHandle) {
        // 等待线程自然结束
        WaitForSingleObject(g_statsThreadHandle, 1000);

        // 如果超时，强制结束线程
        if (WaitForSingleObject(g_statsThreadHandle, 0) != WAIT_OBJECT_0) {
            LogMessage("[关闭] 统计线程未能自然结束，强制终止");
            TerminateThread(g_statsThreadHandle, 0);
        }

        CloseHandle(g_statsThreadHandle);
        g_statsThreadHandle = NULL;
    }

    // 等待所有进行中的内存操作完成
    LogMessage("[关闭] 等待进行中的关键操作完成...");
    int checkCount = 0;
    while ((MemPool::g_inOperation.load() || g_cleanAllInProgress.load()) && checkCount < 10) {
        Sleep(100);
        checkCount++;
    }

    LogMessage("[关闭] 所有工作线程已停止");
}

void SafelyDetachHooks() {
    LogMessage("[关闭] 安全卸载钩子...");

    // 确保不在关键操作中
    if (g_cleanAllInProgress.load()) {
        LogMessage("[关闭] 等待CleanAll完成...");
        // 等待直到CleanAll完成
        int waitAttempts = 0;
        while (g_cleanAllInProgress.load() && waitAttempts < 10) {
            Sleep(100);
            waitAttempts++;
        }
    }

    // 开始钩子卸载事务
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 按特定顺序卸载钩子 - 先卸载不太活跃的钩子
    if (s_origCleanupAll) {
        LogMessage("[关闭] 卸载CleanupAll钩子");
        DetourDetach(&(PVOID&)s_origCleanupAll, Hooked_StormHeap_CleanupAll);
    }

    // 等待100毫秒，确保没有正在进行的清理操作
    Sleep(100);

    // 然后卸载核心内存操作钩子
    if (s_origStormReAlloc) {
        LogMessage("[关闭] 卸载ReAlloc钩子");
        DetourDetach(&(PVOID&)s_origStormReAlloc, Hooked_Storm_MemReAlloc);
    }

    if (s_origStormFree) {
        LogMessage("[关闭] 卸载Free钩子");
        DetourDetach(&(PVOID&)s_origStormFree, Hooked_Storm_MemFree);
    }

    if (s_origStormAlloc) {
        LogMessage("[关闭] 卸载Alloc钩子");
        DetourDetach(&(PVOID&)s_origStormAlloc, Hooked_Storm_MemAlloc);
    }

    // 提交事务
    LONG result = DetourTransactionCommit();
    LogMessage("[关闭] 钩子卸载%s", (result == NO_ERROR ? "成功" : "失败"));
}

// 修改 ShutdownStormMemoryHooks 函数，关闭日志系统
void ShutdownStormMemoryHooks() {
    LogMessage("[关闭] 退出程序...");

    // 1. 标记不安全期开始——必须最先执行
    g_insideUnsafePeriod.store(true);

    // 2. 最后的内存报告
    GenerateMemoryReport(true);

    // 3. 等待任何进行中的内存操作完成
    LogMessage("[关闭] 等待进行中的内存操作完成...");
    Sleep(500);

    // 4. 停止统计线程和其他工作线程
    StopAllWorkThreads();

    // 5. 处理内存归属转移
    TransferMemoryOwnership();

    // 6. 关闭内存安全系统
    LogMessage("[关闭] 关闭内存安全系统...");
    g_MemSafety.Shutdown();

    // 7. 安全卸载钩子
    SafelyDetachHooks();

    // 8. 释放永久块引用但不实际释放内存
    LogMessage("[关闭] 释放永久块引用...");
    g_permanentBlocks.clear();

    // 9. 清理JassVM内存池 - 同样禁用实际释放
    LogMessage("[关闭] 关闭JassVM内存管理...");
    JVM_MemPool::Cleanup();

    // 10. 清理mimalloc内存池
    LogMessage("[关闭] 关闭mimalloc内存池...");
    MemPool::Shutdown();

    // 11. 关闭日志系统
    LogMessage("[关闭] 关闭完成，正在关闭日志系统");
    LogSystem::GetInstance().Shutdown();
}