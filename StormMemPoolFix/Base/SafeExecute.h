// SafeExecute.h - �޸���SEH��ȫ��װ������C++�����SEH����
#pragma once

#include "pch.h"

///////////////////////////////////////////////////////////////////////////////
// SEH��ȫ��װ - �޸����������Ƶ�����
///////////////////////////////////////////////////////////////////////////////

// ר��Ϊvoid����������Ƶ�ģ���ػ�
template<typename Func>
void SafeExecuteVoid(Func&& func, const char* operation) noexcept {
    __try {
        func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] Exception 0x%08X in %s\n", GetExceptionCode(), operation);
    }
}

// ר��Ϊָ�뷵��������Ƶ�ģ��
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

// ר��Ϊbool����������Ƶ�ģ��
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

// ר��Ϊ��ֵ����������Ƶ�ģ��
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

// ͨ�õ�SafeExecute����Ĭ��ֵ����
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

// ���ݾɴ����SafeExecute��SafeExecuteNonConst
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

// SafeExecuteNonConst�����������ݣ�
template<typename Func>
auto SafeExecuteNonConst(Func&& func, const char* operation) noexcept -> decltype(func()) {
    return SafeExecute(std::forward<Func>(func), operation);
}

///////////////////////////////////////////////////////////////////////////////
// C���SEH��װ - ���ڸ����ӵĳ���
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    typedef int(__stdcall* SafeOperationFunc)(void* context);

    // C���SEH��װ����
    int __stdcall SafeExecuteOperation(SafeOperationFunc func, void* context, const char* operation);
}

///////////////////////////////////////////////////////////////////////////////
// �����궨��
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