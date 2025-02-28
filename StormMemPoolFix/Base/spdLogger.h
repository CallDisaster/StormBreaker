#pragma once

#include <memory>
#include <spdlog/spdlog.h>

namespace SPDLogger
{
    // 声明一个全局的 Logger 指针
    extern std::shared_ptr<spdlog::logger> g_logger;

    // 初始化 Logger 的函数
    bool InitializeLogger();
}
