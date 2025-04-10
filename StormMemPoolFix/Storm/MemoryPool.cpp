#include "pch.h"
#include "MemoryPool.h"
#include <Windows.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cassert>
#include <dbghelp.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "StormHook.h"
#include "Base/MemorySafety.h"
#include <mimalloc.h> // Keep mimalloc include for JVM_MemPool

#pragma comment(lib, "dbghelp.lib")

// Removed obsolete static pool code (BlockSize, PoolCapacity, etc.)

// 安全执行功能的辅助函数 (Keep this helper)
template<typename Func>
bool SafeExecute(Func func, const char* errorMsg = nullptr) {
    try {
        func();
        return true;
    }
    catch (const std::exception& e) {
        if (errorMsg) {
            LogMessage("[SAFE] %s: %s", errorMsg, e.what());
        }
        return false;
    }
    catch (...) {
        if (errorMsg) {
            LogMessage("[SAFE] %s: 未知异常", errorMsg);
        }
        return false;
    }
}

// 在适当的头文件中
namespace JVM_MemPool {
    // 私有变量
    static mi_heap_t* g_jvmHeap = nullptr;
    static std::mutex g_jvmMutex;
    static std::unordered_map<void*, size_t> g_jvmBlocks;
    static std::atomic<bool> g_initializing{ false }; // 添加初始化标志

    // 初始化
    void Initialize() {
        // 防止重入死锁
        bool expected = false;
        if (!g_initializing.compare_exchange_strong(expected, true)) {
            // 已经在初始化中，直接返回
            return;
        }

        // 用作用域减小锁持有时间
        {
            std::lock_guard<std::mutex> lock(g_jvmMutex);
            if (!g_jvmHeap) {
                g_jvmHeap = mi_heap_new();
                if (g_jvmHeap) {
                    LogMessage("[JVM_MemPool] mimalloc JVM堆创建成功");
                }
                else {
                    LogMessage("[JVM_MemPool] mimalloc JVM堆创建失败");
                }
            }
        }

        g_initializing.store(false);
    }

    // 分配
    void* Allocate(size_t size) {
        // 先检查g_jvmHeap并初始化，避免持有锁时调用Initialize
        if (!g_jvmHeap) {
            Initialize();
            if (!g_jvmHeap) return nullptr;
        }

        // 分配内存
        void* ptr = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_jvmMutex);
            ptr = mi_heap_malloc(g_jvmHeap, size);
            if (ptr) {
                g_jvmBlocks[ptr] = size;
            }
        }

        return ptr;
    }

    // 释放 - 同样修改加锁逻辑
    void Free(void* ptr) {
        if (!ptr || !g_jvmHeap) return;

        std::lock_guard<std::mutex> lock(g_jvmMutex);
        auto it = g_jvmBlocks.find(ptr);
        if (it != g_jvmBlocks.end()) {
            g_jvmBlocks.erase(it);
            mi_free(ptr);
        }
    }

    // 重新分配 - 也需要修改
    void* Realloc(void* ptr, size_t newSize) {
        if (!g_jvmHeap) {
            Initialize();
            if (!g_jvmHeap) return nullptr;
        }

        if (!ptr) return Allocate(newSize);
        if (newSize == 0) {
            Free(ptr);
            return nullptr;
        }

        void* newPtr = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_jvmMutex);
            auto it = g_jvmBlocks.find(ptr);
            if (it != g_jvmBlocks.end()) {
                newPtr = mi_heap_realloc(g_jvmHeap, ptr, newSize);
                if (newPtr) {
                    g_jvmBlocks.erase(it);
                    g_jvmBlocks[newPtr] = newSize;
                }
            }
        }

        return newPtr;
    }

    // 检查是否来自此池
    bool IsFromPool(void* ptr) {
        if (!ptr || !g_jvmHeap) return false;

        std::lock_guard<std::mutex> lock(g_jvmMutex);
        return g_jvmBlocks.find(ptr) != g_jvmBlocks.end();
    }

    // 清理
    void Cleanup() {
        std::lock_guard<std::mutex> lock(g_jvmMutex);

        if (g_jvmHeap) {
            // 如果设置了不释放内存，则只清理数据结构
            if (g_disableMemoryReleasing.load()) {
                LogMessage("[JVM_MemPool] 保留JVM堆内存，仅清理数据结构");
                g_jvmBlocks.clear();
                g_jvmHeap = nullptr;
                return;
            }

            // 正常清理
            mi_heap_destroy(g_jvmHeap);
            g_jvmHeap = nullptr;
            g_jvmBlocks.clear();
            LogMessage("[JVM_MemPool] JVM堆已销毁");
        }
    }
} // <-- 添加缺失的右花括号来结束 JVM_MemPool 命名空间

// 在 Storm/MemoryPool.cpp 文件中添加定义
namespace MemPool {
    std::atomic<bool> g_inOperation{ false };  // 初始化为false
}
// Removed obsolete SmallBlockPool namespace
// Removed obsolete MemPool namespace and its commented-out code
