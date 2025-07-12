// StormCommon.h - Storm��صĹ����壬�����ظ�����
#pragma once

#include "pch.h"
#include <Windows.h>

// ���ò���ȫ��������
#define _CRT_SECURE_NO_WARNINGS

///////////////////////////////////////////////////////////////////////////////
// Storm�������� - ֻ�ڴ˴�����һ��
///////////////////////////////////////////////////////////////////////////////

// Stormħ������
extern const WORD STORM_FRONT_MAGIC;
extern const WORD STORM_TAIL_MAGIC;
extern const DWORD STORM_SPECIAL_HEAP;

// Ĭ������
extern const size_t DEFAULT_BIG_BLOCK_THRESHOLD;
extern const size_t JASSVM_BLOCK_SIZE;

///////////////////////////////////////////////////////////////////////////////
// Storm�ṹ�嶨�� - ֻ�ڴ˴�����һ��
///////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
struct StormAllocHeader {
    DWORD HeapPtr;      // ָ�������ѽṹ (����ʹ��0xC0DEFEED������)
    DWORD Size;         // �û���������С
    BYTE  AlignPadding; // ��������ֽ���
    BYTE  Flags;        // ��־λ: 0x1=ħ��У��, 0x2=���ͷ�, 0x4=���VirtualAlloc, 0x8=����ָ��
    WORD  Magic;        // ǰħ�� (0x6F6D)
    // �û����ݴ����￪ʼ
    // ��� Flags & 1�������û�����ĩβ���� WORD tailMagic = 0x12B1
};
#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////
// Storm�������Ͷ���
///////////////////////////////////////////////////////////////////////////////

typedef size_t(__fastcall* Storm_MemAlloc_t)(int ecx, int edx, size_t size,
    const char* name, DWORD src_line, DWORD flag);
typedef int(__stdcall* Storm_MemFree_t)(int a1, char* name, int argList, int a4);
typedef void* (__fastcall* Storm_MemReAlloc_t)(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD src_line, DWORD flag);
typedef void(*StormHeap_CleanupAll_t)();