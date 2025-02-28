/************************************************************
 * StormMemoryInternal.h
 *
 * 声明本内存管理器中使用的各种内部函数原型，不对外公开。
 * 以及Storm.dll里的外部函数(逆向分析到的)，如错误回调等。
 ************************************************************/
#pragma once
#include "pch.h"
#include <windows.h>
#include <cstddef>
#include <cstdint>

 /**
  * 逆向显示的函数：
  *  Storm_SetLastError, Storm_AllocErrorHandler, Storm_MemErrorCallback,
  *  Storm_502, Storm_506
  * 实际上它们位于Storm.dll的其他位置(或是导出函数)。
  * 这里仅声明，方便本项目引用。
  */
#ifdef __cplusplus
extern "C" {
#endif
	extern void* pStorm_502;
	extern void* pStorm_506;

	void  __stdcall Storm_SetLastError(DWORD errorCode);
	void  __stdcall Storm_AllocErrorHandler(DWORD dwMessageId, const char* msg, int argList, int a4, int a5, unsigned int a6);
	void  __stdcall Storm_MemErrorCallback(DWORD errorCode, const char* msg, int argList);

	/**
	 * 检查指针是否合法(对应Storm_CheckMemPointer)
	 */
	int __fastcall Storm_CheckMemPointer(int ptr, int checkFlag, const char* sourceName, int argList);

#ifdef __cplusplus
}
#endif

