// SafeExecute.cpp - C风格SEH包装实现
#include "pch.h"
#include "SafeExecute.h"

///////////////////////////////////////////////////////////////////////////////
// C风格SEH包装实现
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    int __stdcall SafeExecuteOperation(SafeOperationFunc func, void* context, const char* operation) {
        __try {
            return func(context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation ? operation : "Unknown");
            return 0;  // 失败
        }
    }
}