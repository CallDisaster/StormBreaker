#include "pch.h"
#include "spdLogger.h"

// spdlog
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <chrono>
#include <cstdio>
#include <ctime>

#ifdef _WIN32
#include <filesystem>  // C++17
#endif
#include <spdlog/sinks/rotating_file_sink.h>

namespace SPDLogger
{
    // 定义全局 Logger
    std::shared_ptr<spdlog::logger> g_logger = nullptr;

    bool InitializeLogger()
    {
        try
        {
//#ifdef _WIN32
//            // 如果使用相对路径 "Logger/..."，需要先确保目录存在
//            if (!std::filesystem::exists("Logger")) {
//                std::filesystem::create_directory("Logger");
//            }
//#endif
//            // 设置日志文件名（所有日志写入一个文件，支持大小限制）
//            std::string log_file = "Logger/ICC_game.log";

            //// 创建文件输出 sink（支持大小限制和文件轮转）
            //auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            //    log_file,          // 日志文件路径
            //    10 * 1024 * 1024,  // 单个文件最大 10 MB
            //    1                 // 最多保留 1 个文件（无历史文件，始终覆盖）
            //);
            //file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

            // 创建控制台输出 sink
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(spdlog::level::debug);  // 控制台记录 info 及以上日志
            console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

            //// 创建 Logger，同时使用文件和控制台输出
            //auto multi_sink_logger = std::make_shared<spdlog::logger>(
            //    "global_logger",
            //    spdlog::sinks_init_list{ file_sink, console_sink } // Sink 列表
            //);

            //// 设置全局日志等级
            //multi_sink_logger->set_level(spdlog::level::info);  // 默认全局 info 等级
            //multi_sink_logger->flush_on(spdlog::level::err);    // 立即刷新的日志等级

            //// 注册 Logger 并赋值到全局变量
            //spdlog::register_logger(multi_sink_logger);
            //g_logger = multi_sink_logger;

            return true;
        }
        catch (const std::exception& ex)
        {
            std::printf("[Error] spdlog init failed: %s\n", ex.what());
            return false;
        }
    }

} // namespace SPDLogger