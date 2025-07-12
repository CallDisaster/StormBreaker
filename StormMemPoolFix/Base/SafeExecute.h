// SafeExecute.h - 修复的SEH安全包装，避免C++对象和SEH混用
#pragma once

#include "pch.h"

///////////////////////////////////////////////////////////////////////////////
// SEH安全包装 - 修复返回类型推导问题
///////////////////////////////////////////////////////////////////////////////

// 专门为void返回类型设计的模板特化
template<typename Func>
void SafeExecuteVoid(Func&& func, const char* operation) noexcept {
    __try {
        func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
    }
}

// 专门为指针返回类型设计的模板
template<typename Func>
auto SafeExecutePtr(Func&& func, const char* operation) noexcept -> decltype(func()) {
    using ReturnType = decltype(func());
    static_assert(std::is_pointer_v<ReturnType>, "SafeExecutePtr only for pointer types");

    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
        return nullptr;
    }
}

// 专门为bool返回类型设计的模板
template<typename Func>
bool SafeExecuteBool(Func&& func, const char* operation) noexcept {
    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
        return false;
    }
}

// 专门为数值返回类型设计的模板
template<typename Func>
auto SafeExecuteValue(Func&& func, const char* operation) noexcept -> decltype(func()) {
    using ReturnType = decltype(func());
    static_assert(std::is_arithmetic_v<ReturnType>, "SafeExecuteValue only for arithmetic types");

    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
        return static_cast<ReturnType>(0);
    }
}

// 通用的SafeExecute，带默认值参数
template<typename Func, typename DefaultType>
auto SafeExecuteWithDefault(Func&& func, const char* operation, DefaultType&& defaultValue) noexcept -> decltype(func()) {
    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
        return defaultValue;
    }
}

// 兼容旧代码的SafeExecute和SafeExecuteNonConst
template<typename Func>
auto SafeExecute(Func&& func, const char* operation) noexcept -> decltype(func()) {
    using ReturnType = decltype(func());

    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);

        if constexpr (std::is_same_v<ReturnType, void>) {
            return;
        }
        else if constexpr (std::is_pointer_v<ReturnType>) {
            return nullptr;
        }
        else if constexpr (std::is_same_v<ReturnType, bool>) {
            return false;
        }
        else if constexpr (std::is_arithmetic_v<ReturnType>) {
            return static_cast<ReturnType>(0);
        }
        else {
            return ReturnType{};
        }
    }
}

// SafeExecuteNonConst别名（向后兼容）
template<typename Func>
auto SafeExecuteNonConst(Func&& func, const char* operation) noexcept -> decltype(func()) {
    return SafeExecute(std::forward<Func>(func), operation);
}

///////////////////////////////////////////////////////////////////////////////
// C风格SEH包装 - 用于更复杂的场景
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    typedef int(__stdcall* SafeOperationFunc)(void* context);

    // C风格SEH包装函数
    int __stdcall SafeExecuteOperation(SafeOperationFunc func, void* context, const char* operation);
}

///////////////////////////////////////////////////////////////////////////////
// 便利宏定义
///////////////////////////////////////////////////////////////////////////////

#define SAFE_VOID(operation, func) \
    SafeExecuteVoid([&]() { func; }, operation)

#define SAFE_PTR(operation, func) \
    SafeExecutePtr([&]() -> auto { return func; }, operation)

#define SAFE_BOOL(operation, func) \
    SafeExecuteBool([&]() -> bool { return func; }, operation)

#define SAFE_VALUE(operation, func) \
    SafeExecuteValue([&]() -> auto { return func; }, operation)

#define SAFE_DEFAULT(operation, func, default_val) \
    SafeExecuteWithDefault([&]() -> auto { return func; }, operation, default_val)