// StormHook.h - 修复后的Storm Hook系统
#pragma once

#include "pch.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <atomic>
#include <cstddef>
#include <vector>
#include <mutex>

///////////////////////////////////////////////////////////////////////////////
// Storm结构体定义 - 基于IDA Pro逆向分析
///////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
struct StormAllocHeader {
    DWORD HeapPtr;      // 指向所属堆结构 (我们使用0xC0DEFEED特殊标记)
    DWORD Size;         // 用户数据区大小
    BYTE  AlignPadding; // 对齐填充字节数
    BYTE  Flags;        // 标志位: 0x1=魔数校验, 0x2=已释放, 0x4=大块VirtualAlloc, 0x8=特殊指针
    WORD  Magic;        // 前魔数 (0x6F6D)
    // 用户数据从这里开始
    // 如果 Flags & 1，则在用户数据末尾还有 WORD tailMagic = 0x12B1
};
#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////
// 常量定义
///////////////////////////////////////////////////////////////////////////////

// Storm魔数常量
constexpr WORD STORM_FRONT_MAGIC = 0x6F6D;
constexpr WORD STORM_TAIL_MAGIC = 0x12B1;
constexpr DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED;

// 默认配置
constexpr size_t DEFAULT_BIG_BLOCK_THRESHOLD = 128 * 1024;  // 128KB
constexpr size_t JASSVM_BLOCK_SIZE = 0x28A8;                // JassVM特殊块大小

///////////////////////////////////////////////////////////////////////////////
// Storm函数类型定义 - 基于IDA Pro确认的地址
///////////////////////////////////////////////////////////////////////////////

typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();

///////////////////////////////////////////////////////////////////////////////
// C风格SEH安全包装 - 避免RAII混用问题
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

///////////////////////////////////////////////////////////////////////////////
// 永久块管理
///////////////////////////////////////////////////////////////////////////////

class ThreadSafePermanentBlocks {
private:
    mutable CRITICAL_SECTION m_cs;
    std::vector<void*> m_blocks;

public:
    ThreadSafePermanentBlocks() noexcept;
    ~ThreadSafePermanentBlocks() noexcept;

    void Add(void* ptr) noexcept;
    bool Contains(void* ptr) const noexcept;
    void Clear() noexcept;
    size_t Size() const noexcept;
};

extern ThreadSafePermanentBlocks g_permanentBlocks;

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
 * 线程安全的日志记录函数
 * @param format 格式字符串
 * @param ... 参数
 */
void LogMessage(const char* format, ...) noexcept;

/**
 * 错误日志记录函数
 * @param format 格式字符串
 * @param ... 参数
 */
void LogError(const char* format, ...) noexcept;

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
 * 获取当前进程虚拟内存使用量
 * @return 虚拟内存使用字节数
 */
size_t GetProcessVirtualMemoryUsage() noexcept;

/**
 * 创建永久稳定块
 * @param count 创建数量
 * @param reason 创建原因
 */
void CreatePermanentStabilizers(int count, const char* reason) noexcept;

/**
 * 创建临时稳定块
 * @param cleanAllCount CleanAll计数
 */
void CreateTemporaryStabilizers(int cleanAllCount) noexcept;

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