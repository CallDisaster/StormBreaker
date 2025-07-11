#pragma once

#include "pch.h"
#include "StormOffsets.h"
#include <Windows.h>
#include <atomic>
#include <cstddef>

///////////////////////////////////////////////////////////////////////////////
// Storm结构体定义 - 基于逆向文档
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
// Storm函数类型定义
///////////////////////////////////////////////////////////////////////////////

typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();

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
// 主要接口函数
///////////////////////////////////////////////////////////////////////////////

/**
 * 初始化Storm内存Hook系统
 * @return 成功返回true，失败返回false
 */
bool InitializeStormMemoryHooks();

/**
 * 关闭Storm内存Hook系统
 * 安全卸载所有Hook并清理资源
 */
void ShutdownStormMemoryHooks();

/**
 * 检查Hook系统是否已初始化
 * @return 已初始化返回true
 */
bool IsHooksInitialized();

///////////////////////////////////////////////////////////////////////////////
// 配置和监控接口
///////////////////////////////////////////////////////////////////////////////

/**
 * 设置大块内存阈值
 * 超过此大小的分配将使用MemoryPool管理
 * @param sizeInBytes 阈值大小（字节）
 */
void SetBigBlockThreshold(size_t sizeInBytes);

/**
 * 获取内存统计信息
 * @param allocated 总分配字节数
 * @param freed 总释放字节数
 * @param allocCount 分配次数
 * @param freeCount 释放次数
 */
void GetMemoryStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount);

/**
 * 打印当前内存状态到日志
 */
void PrintMemoryStatus();

/**
 * 强制触发内存清理
 * 立即清理MemoryPool中的缓存和队列
 */
void ForceMemoryCleanup();

///////////////////////////////////////////////////////////////////////////////
// Hook函数声明
///////////////////////////////////////////////////////////////////////////////

// 这些函数是内部实现，外部代码不应直接调用
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

///////////////////////////////////////////////////////////////////////////////
// SEH异常安全包装
///////////////////////////////////////////////////////////////////////////////

/**
 * SEH异常安全执行模板
 * 捕获异常并返回默认值，确保不会崩溃
 * @param func 要执行的函数
 * @param operation 操作名称（用于日志）
 * @param defaultValue 异常时返回的默认值
 * @return 函数执行结果或默认值
 */
template<typename Func>
auto SafeExecute(Func&& func, const char* operation, auto defaultValue) noexcept -> decltype(func());

///////////////////////////////////////////////////////////////////////////////
// 兼容性说明
///////////////////////////////////////////////////////////////////////////////

/*
 * 本Hook系统基于以下架构：
 *
 * 应用层: StormHook.cpp/h (Hook安装、分配路由、异常处理)
 *    ↓
 * 业务层: MemoryPool.cpp/h (策略管理、后台任务、Storm集成)
 *    ↓
 * 安全层: MemorySafety.cpp/h (缓冲队列、分档缓存、压力监控)
 *
 * 设计原则：
 * 1. 每个操作都有SEH异常保护，确保游戏不会因我们的代码崩溃
 * 2. 总是提供回退路径：我们的实现失败时使用Storm原生函数
 * 3. 最小化对游戏的影响：只hook必要的函数，其他保持原样
 * 4. 内存安全第一：宁可泄漏也不要野指针，通过缓冲机制避免Race Condition
 *
 * 故障恢复：
 * - 如果MemoryPool分配失败 → 回退到Storm原生分配
 * - 如果释放时发生异常 → 记录日志但不崩溃
 * - 如果CleanAll时异常 → 仍然调用Storm原生清理
 * - 如果内存压力过高 → 自动触发清理和Storm CleanupAll
 */