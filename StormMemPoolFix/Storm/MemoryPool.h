#pragma once
#include "pch.h"
#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>

// JVM内存池命名空间
namespace JVM_MemPool {
    void Initialize();
    void* Allocate(std::size_t size);
    void Free(void* p);
    void* Realloc(void* oldPtr, std::size_t newSize);
    bool IsFromPool(void* p);
    void Cleanup();
}

// 小块内存池命名空间
namespace SmallBlockPool {
    // 声明结构和函数
    void Initialize();
    bool ShouldIntercept(std::size_t size);
    void* Allocate(std::size_t size);
    bool Free(void* ptr, std::size_t size);
}