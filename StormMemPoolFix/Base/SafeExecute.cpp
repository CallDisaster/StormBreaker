// SafeExecute.cpp - C���SEH��װʵ��
#include "pch.h"
#include "SafeExecute.h"

///////////////////////////////////////////////////////////////////////////////
// C���SEH��װʵ��
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    int __stdcall SafeExecuteOperation(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation ? operation : "Unknown");
            return 0;  // ʧ��
        }
    }
}