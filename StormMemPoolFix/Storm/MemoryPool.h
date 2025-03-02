// MemoryPool.h

#pragma once
#include "pch.h"

namespace JVM_MemPool {
    // 初始化内存池（可选，如果使用全局静态数组，不一定要这么做）
    void Initialize();

    // 分配一个大小为 0x28A8 的块（只在 size == 0x28A8 时才会真正使用）
    void* Allocate(size_t size);

    // 释放 Allocate 获得的指针
    void  Free(void* p);

    // 重新分配内存块
    void* Realloc(void* oldPtr, size_t newSize);

    // 判断是否来自本内存池
    bool  IsFromPool(void* p);

    // 清理内存池（程序退出或需要时调用）
    void  Cleanup();
}