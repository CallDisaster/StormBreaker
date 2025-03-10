// SafeExecutionGuard.h
#pragma once
#include <atomic>
#include <string>
#include <Windows.h>
#include "Logger.h"
#include <Storm/StormHook.h>

// 安全执行状态守卫 - 确保状态标志在所有路径上被恢复
class SafeExecutionGuard {
public:
    // 构造函数接收状态标志引用和操作名
    SafeExecutionGuard(std::atomic<bool>& flag, const char* operationName)
        : m_flag(flag), m_operationName(operationName) {
        // 尝试设置标志
        m_acquired = !m_flag.exchange(true);
        if (!m_acquired) {
            LogMessage("[安全] %s: 操作已在进行，被阻止", m_operationName);
        }
    }

    // 析构函数确保标志被重置
    ~SafeExecutionGuard() {
        if (m_acquired) {
            m_flag.store(false);
        }
    }

    // 检查是否获得了执行权
    bool CanProceed() const { return m_acquired; }

    // 禁止复制
    SafeExecutionGuard(const SafeExecutionGuard&) = delete;
    SafeExecutionGuard& operator=(const SafeExecutionGuard&) = delete;

private:
    std::atomic<bool>& m_flag;
    const char* m_operationName;
    bool m_acquired;
};

// 安全执行任意操作的函数模板
template<typename Func>
auto SafeExecute(std::atomic<bool>& flag, const char* operationName, Func&& func)
-> decltype(func())
{
    SafeExecutionGuard guard(flag, operationName);
    if (!guard.CanProceed()) {
        return decltype(func()){}; // 返回默认结构
    }

    try {
        return func();
    }
    catch (const std::exception& ex) {
        LogMessage("[安全] %s 发生标准异常: %s", operationName, ex.what());
        return decltype(func()){}; // 返回默认值
    }
    catch (...) {
        LogMessage("[安全] %s 发生未知异常", operationName);
        return decltype(func()){}; // 返回默认值
    }
}

// 带SEH异常保护的操作执行
template<typename Func>
auto SafeExecuteWithSEH(std::atomic<bool>& flag, const char* operationName, Func&& func)
-> decltype(func())
{
    SafeExecutionGuard guard(flag, operationName);
    if (!guard.CanProceed()) {
        return decltype(func()){}; // 返回默认结构
    }

    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        LogMessage("[安全] %s 发生SEH异常: 0x%X", operationName, exceptionCode);
        return decltype(func()){}; // 返回默认值
    }
}