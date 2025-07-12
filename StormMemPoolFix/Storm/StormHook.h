// StormHook.h - 配合修复后内存系统的版本
#pragma once

#include "pch.h"
#include "StormCommon.h"
#include "StormOffsets.h"
#include "MemoryPool.h"
#include "../Base/SafeExecute.h"
#include <Windows.h>
#include <atomic>
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// 常量定义
///////////////////////////////////////////////////////////////////////////////

// 默认大块阈值：8KB（降低以减少虚拟内存使用）
constexpr size_t DEFAULT_BIG_BLOCK_THRESHOLD = 8192;

// JassVM特殊分配大小
constexpr size_t JASSVM_BLOCK_SIZE = 0x28A8;

// Storm清理间隔
constexpr DWORD MIN_STORM_CLEANUP_INTERVAL = 20000;  // 20秒最小间隔

///////////////////////////////////////////////////////////////////////////////
// C风格SEH安全包装（避免C++对象和SEH混用）
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    // C风格操作函数指针类型
    typedef int(__stdcall* SafeOperationFunc)(void* context);

    // SEH安全执行函数 - 纯C实现，无RAII
    int __stdcall SafeExecuteVoid(SafeOperationFunc func, void* context, const char* operation);
    int __stdcall SafeExecuteInt(SafeOperationFunc func, void* context, const char* operation);
    void* __stdcall SafeExecutePtr(SafeOperationFunc func, void* context, const char* operation);
}

// C++包装宏 - 简化使用
#define SAFE_CALL_VOID(operation, func, context) \
    SafeExecuteVoid(func, context, operation)

#define SAFE_CALL_INT(operation, func, context) \
    SafeExecuteInt(func, context, operation)

#define SAFE_CALL_PTR(operation, func, context) \
    SafeExecutePtr(func, context, operation)

///////////////////////////////////////////////////////////////////////////////
// 操作上下文结构体定义
///////////////////////////////////////////////////////////////////////////////

struct AllocContext {
    int ecx, edx;
    size_t size;
    const char* name;
    DWORD src_line;
    DWORD flag;
    size_t result;
};

struct FreeContext {
    int a1;
    char* name;
    int argList;
    int a4;
    int result;
};

struct ReallocContext {
    int ecx, edx;
    void* oldPtr;
    size_t newSize;
    const char* name;
    DWORD src_line;
    DWORD flag;
    void* result;
};

struct CleanupContext {
    int cleanAllCount;
    size_t workingSetMB;
    size_t commitMB;
    bool forceTrigger;
};

struct StabilizerContext {
    int count;
    const char* reason;
    int cleanAllCount;
};

///////////////////////////////////////////////////////////////////////////////
// 全局状态变量声明
///////////////////////////////////////////////////////////////////////////////

// 初始化状态
extern std::atomic<bool> g_hooksInitialized;
extern std::atomic<bool> g_shutdownRequested;
extern std::atomic<bool> g_cleanAllInProgress;
extern std::atomic<bool> g_insideUnsafePeriod;

// 配置参数
extern std::atomic<size_t> g_bigThreshold;
extern std::atomic<size_t> g_workingSetLimit;
extern std::atomic<size_t> g_commitLimit;

// 统计数据
extern std::atomic<size_t> g_totalAllocated;
extern std::atomic<size_t> g_totalFreed;
extern std::atomic<size_t> g_hookAllocCount;
extern std::atomic<size_t> g_hookFreeCount;

// Storm原始函数指针
extern Storm_MemAlloc_t s_origStormAlloc;
extern Storm_MemFree_t s_origStormFree;
extern Storm_MemReAlloc_t s_origStormReAlloc;
extern StormHeap_CleanupAll_t s_origCleanupAll;

// CleanAll相关
extern std::atomic<int> g_cleanAllCounter;
extern thread_local bool tls_inCleanAll;

// 永久稳定块管理（简化版本）
class PermanentBlockManager {
private:
    mutable CRITICAL_SECTION m_cs;
    std::vector<void*> m_blocks;
    std::atomic<size_t> m_blockCount{ 0 };

public:
    PermanentBlockManager() noexcept;
    ~PermanentBlockManager() noexcept;

    void Add(void* ptr) noexcept;
    bool Contains(void* ptr) const noexcept;
    void Clear() noexcept;
    size_t Size() const noexcept { return m_blockCount.load(); }
};

extern PermanentBlockManager g_permanentBlocks;

///////////////////////////////////////////////////////////////////////////////
// 主要接口函数
///////////////////////////////////////////////////////////////////////////////

/**
 * 初始化Storm内存Hook系统
 * @return 成功返回true，失败返回false
 */
bool InitializeStormMemoryHooks() noexcept;

/**
 * 关闭Storm内存Hook系统
 * 安全卸载所有Hook并清理资源
 */
void ShutdownStormMemoryHooks() noexcept;

/**
 * 检查Hook系统是否已初始化
 * @return 已初始化返回true
 */
bool IsHooksInitialized() noexcept;

///////////////////////////////////////////////////////////////////////////////
// 配置和监控接口
///////////////////////////////////////////////////////////////////////////////

/**
 * 设置大块内存阈值
 * 超过此大小的分配将使用MemoryPool管理
 * @param sizeInBytes 阈值大小（字节）
 */
void SetBigBlockThreshold(size_t sizeInBytes) noexcept;

/**
 * 设置工作集内存限制
 * @param limitMB 限制大小（MB）
 */
void SetWorkingSetLimit(size_t limitMB) noexcept;

/**
 * 设置提交内存限制
 * @param limitMB 限制大小（MB）
 */
void SetCommitLimit(size_t limitMB) noexcept;

/**
 * 获取内存统计信息
 * @param allocated 总分配字节数
 * @param freed 总释放字节数
 * @param allocCount 分配次数
 * @param freeCount 释放次数
 */
void GetMemoryStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) noexcept;

/**
 * 打印当前内存状态到日志
 */
void PrintMemoryStatus() noexcept;

/**
 * 强制触发内存清理
 * 立即清理MemoryPool中的缓存和队列
 */
void ForceMemoryCleanup() noexcept;

/**
 * 检查内存压力并根据需要触发清理
 */
void CheckMemoryPressureAndCleanup() noexcept;

///////////////////////////////////////////////////////////////////////////////
// Hook函数声明 - 内部使用
///////////////////////////////////////////////////////////////////////////////

size_t __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag);
int __stdcall Hooked_Storm_MemFree(int a1, char* name, int argList, int a4);
void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag);
void Hooked_StormHeap_CleanupAll();

///////////////////////////////////////////////////////////////////////////////
// 工具函数声明
///////////////////////////////////////////////////////////////////////////////

/**
 * 检查指针是否为永久稳定块
 * @param ptr 要检查的指针
 * @return 是永久块返回true
 */
bool IsPermanentBlock(void* ptr) noexcept;

/**
 * 检查是否为JassVM相关分配
 * @param size 分配大小
 * @param name 分配来源名称
 * @return 是JassVM分配返回true
 */
bool IsJassVMAllocation(size_t size, const char* name) noexcept;

/**
 * 获取当前进程工作集大小
 * @return 工作集大小（字节）
 */
size_t GetProcessWorkingSetSize() noexcept;

/**
 * 获取当前进程提交内存大小
 * @return 提交内存大小（字节）
 */
size_t GetProcessCommittedSize() noexcept;

/**
 * 检查是否需要触发Storm清理
 * @return 需要清理返回true
 */
bool ShouldTriggerStormCleanup() noexcept;

/**
 * 创建少量永久稳定块（降低频率）
 * @param count 创建数量
 * @param reason 创建原因
 */
void CreatePermanentStabilizers(int count, const char* reason) noexcept;

/**
 * 创建临时稳定块（大幅降低频率）
 * @param cleanAllCount CleanAll计数
 */
void CreateTemporaryStabilizers(int cleanAllCount) noexcept;

///////////////////////////////////////////////////////////////////////////////
// 内存压力检测和管理
///////////////////////////////////////////////////////////////////////////////

/**
 * 检查工作集内存压力
 * @return 有压力返回true
 */
bool IsWorkingSetUnderPressure() noexcept;

/**
 * 检查提交内存压力
 * @return 有压力返回true
 */
bool IsCommittedMemoryUnderPressure() noexcept;

/**
 * 智能内存清理（基于真实内存使用情况）
 */
void SmartMemoryCleanup() noexcept;

///////////////////////////////////////////////////////////////////////////////
// 初始化相关函数
///////////////////////////////////////////////////////////////////////////////

/**
 * 初始化日志系统
 * @return 成功返回true
 */
bool InitializeLogging() noexcept;

/**
 * 查找Storm函数地址
 * @return 成功返回true
 */
bool FindStormFunctions() noexcept;

/**
 * 安装Hook
 * @return 成功返回true
 */
bool InstallHooks() noexcept;

/**
 * 卸载Hook
 */
void UninstallHooks() noexcept;

///////////////////////////////////////////////////////////////////////////////
// 操作函数声明（C风格，用于SEH安全调用）
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    int __stdcall AllocOperation(void* ctx);
    int __stdcall FreeOperation(void* ctx);
    int __stdcall ReallocOperation(void* ctx);
    int __stdcall CleanAllOperation(void* ctx);
    int __stdcall CreatePermanentStabilizersOperation(void* ctx);
    int __stdcall CreateTemporaryStabilizersOperation(void* ctx);
    int __stdcall SmartCleanupOperation(void* ctx);
}