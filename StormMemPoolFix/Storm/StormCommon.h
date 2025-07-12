// StormCommon.h - Storm相关的共享定义，避免重复定义
#pragma once

#include "pch.h"
#include <Windows.h>

// 禁用不安全函数警告
#define _CRT_SECURE_NO_WARNINGS

///////////////////////////////////////////////////////////////////////////////
// Storm常量定义 - 只在此处定义一次
///////////////////////////////////////////////////////////////////////////////

// Storm魔数常量
extern const WORD STORM_FRONT_MAGIC;
extern const WORD STORM_TAIL_MAGIC;
extern const DWORD STORM_SPECIAL_HEAP;

// 默认配置
extern const size_t DEFAULT_BIG_BLOCK_THRESHOLD;
extern const size_t JASSVM_BLOCK_SIZE;

///////////////////////////////////////////////////////////////////////////////
// Storm结构体定义 - 只在此处定义一次
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
// Storm函数类型定义
///////////////////////////////////////////////////////////////////////////////

typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();