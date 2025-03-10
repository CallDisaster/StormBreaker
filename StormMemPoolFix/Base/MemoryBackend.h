// MemoryBackend.h
#pragma once
#include <atomic>
#include <Windows.h>
#include "Base/Logger.h"

// 多后端分配器类型
enum class MemBackendType {
    TLSF,
    Mimalloc,
    System
};

// 全局内存配置
struct MemoryConfig {
    // 后端选择
    MemBackendType backend = MemBackendType::TLSF;

    // 大块阈值
    size_t bigBlockThreshold = 512 * 1024;

    // JassVM专门处理
    bool useSpecialJassVMPool = true;

    // 调试和日志
    bool verboseLogging = false;
    bool trackAllocations = true;

    // 单例访问
    static MemoryConfig& Get() {
        static MemoryConfig config;
        return config;
    }
};

// 统一的内存池接口
namespace MemoryPool {
    // 初始化
    void Initialize();

    // 关闭
    void Shutdown();

    // 分配函数
    void* AllocateSafe(size_t size);
    void* Allocate(size_t size);

    // 释放函数
    void FreeSafe(void* ptr);
    void Free(void* ptr);

    // 重分配函数
    void* ReallocSafe(void* oldPtr, size_t newSize);
    void* Realloc(void* oldPtr, size_t newSize);

    // JassVM专用分配
    void* AllocateJassVM(size_t size);
    void* AllocateJassVMSafe(size_t size);

    // 验证函数
    bool IsFromPool(void* ptr);

    // 统计函数
    size_t GetUsedSize();
    size_t GetTotalSize();
    void PrintStats();

    // 维护函数
    void CollectUnused();
}