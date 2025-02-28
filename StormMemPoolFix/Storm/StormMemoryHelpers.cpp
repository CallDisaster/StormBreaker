/************************************************************
 * StormMemoryHelpers.cpp
 *
 * 提供Storm.dll某些函数的“存根”实现。
 * 如在真实环境中不需要自行实现，可通过导入Storm原函数替换这些。
 ************************************************************/
#include "pch.h"
#include "StormMemoryInternal.h"
#include "StormOffsets.h"
#include <cstdio>
#include <cstring>

void __stdcall Storm_SetLastError(DWORD errorCode)
{
    // 逆向说明：设置Storm中的LastError? 这里做一个简单的打印示例
    std::printf("[Storm_SetLastError] errorCode=0x%08X\n", errorCode);
}

void __stdcall Storm_AllocErrorHandler(DWORD dwMessageId, const char* msg, int argList, int a4, int a5, unsigned int a6)
{
    // 逆向中可看到会调用ExitProcess(1)等，这里简单演示
    std::printf("[Storm_AllocErrorHandler] dwMessageId=0x%08X, msg=%s, argList=%d\n",
        dwMessageId, msg ? msg : "(null)", argList);
}

void __stdcall Storm_MemErrorCallback(DWORD errorCode, const char* msg, int argList)
{
    std::printf("[Storm_MemErrorCallback] error=0x%08X, msg=%s, argList=%d\n",
        errorCode, msg ? msg : "(null)", argList);
}

/**
 * Storm_CheckMemPointer:
 *    用来检查指针是否合法 (0x8510007C / 0x8510007A 等错误)。
 *    若不合法就调用 Storm_AllocErrorHandler
 */
int __fastcall Storm_CheckMemPointer(int ptr, int checkFlag, const char* sourceName, int argList)
{
    if (!ptr)
    {
        if (checkFlag)
        {
            Storm_SetLastError(0x85100081);
            if (Storm_g_ErrorHandlingEnabled)
            {
                Storm_AllocErrorHandler(0x85100081, sourceName, argList, 0, 1, 1u);
            }
        }
        return 0;
    }

    // 检查末尾WORD == 28525
    if (*(reinterpret_cast<WORD*>(ptr - 2)) != 28525)
    {
        if (checkFlag)
        {
            Storm_SetLastError(0x8510007C);
            if (Storm_g_ErrorHandlingEnabled)
            {
                Storm_AllocErrorHandler(0x8510007C, sourceName, argList, 0, 1, 1u);
                return 0;
            }
        }
        return 0;
    }

    char flags = *reinterpret_cast<char*>(ptr - 5);
    if (flags & 2)
    {
        if (!checkFlag)
            return 0;
        Storm_SetLastError(0x8510007A);
        if (Storm_g_ErrorHandlingEnabled)
        {
            Storm_AllocErrorHandler(0x8510007A, sourceName, argList, 0, 1, 1u);
            return 0;
        }
        return 0;
    }
    else
    {
        if ((flags & 1) != 0)
        {
            unsigned short tailCheck =
                *reinterpret_cast<unsigned short*>(
                    (ptr - 8) + (*reinterpret_cast<unsigned char*>(ptr - 6)) - 2
                    );
            if (tailCheck != 4785 && checkFlag)
            {
                Storm_MemErrorCallback(0x8510007B, sourceName, argList);
            }
        }
        return 1;
    }
}
