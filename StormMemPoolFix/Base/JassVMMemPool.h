// JassVMMemPool.h
#pragma once
#include "MemoryBackend.h"
#include "Logger.h"
#include "MemorySafety.h"
#include <Storm/StormHook.h>

// JassVM专用内存管理
namespace JassVMMemPool {
    // 全局变量
    namespace {
        std::atomic<bool> g_initialized{ false };
        std::mutex g_mutex;

        // 保存所有分配的JassVM块
        std::vector<void*> g_jassBlocks;
    }

    // 初始化
    void Initialize() {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (g_initialized.load()) return;

        LogMessage("[JassVM] 初始化专用内存池");
        g_initialized.store(true);

        // 确保主内存后端已初始化
        MemoryPool::Initialize();
    }

    // 分配内存
    void* Allocate(size_t size) {
        if (!g_initialized.load()) {
            Initialize();
        }

        // 使用后端JassVM专用分配或通用分配
        void* ptr = MemoryPool::AllocateJassVM(size);

        if (ptr) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_jassBlocks.push_back(ptr);

            LogMessage("[JassVM] 分配块: %p, 大小=%zu", ptr, size);
        }

        return ptr;
    }

    // 释放内存
    void Free(void* ptr) {
        if (!ptr) return;

        // 从跟踪列表中移除
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            auto it = std::find(g_jassBlocks.begin(), g_jassBlocks.end(), ptr);
            if (it != g_jassBlocks.end()) {
                g_jassBlocks.erase(it);
            }
        }

        MemoryPool::FreeSafe(ptr);
    }

    // 重分配内存
    void* Realloc(void* oldPtr, size_t newSize) {
        if (!oldPtr) return Allocate(newSize);
        if (newSize == 0) {
            Free(oldPtr);
            return nullptr;
        }

        // 从跟踪列表移除旧指针
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            auto it = std::find(g_jassBlocks.begin(), g_jassBlocks.end(), oldPtr);
            if (it != g_jassBlocks.end()) {
                g_jassBlocks.erase(it);
            }
        }

        // 使用通用重分配
        void* newPtr = MemoryPool::ReallocSafe(oldPtr, newSize);

        // 添加新指针到跟踪列表
        if (newPtr) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_jassBlocks.push_back(newPtr);

            LogMessage("[JassVM] 重分配块: %p -> %p, 新大小=%zu",
                oldPtr, newPtr, newSize);
        }

        return newPtr;
    }

    // 检查是否JassVM分配
    bool IsJassVMPointer(void* ptr) {
        if (!ptr) return false;

        std::lock_guard<std::mutex> lock(g_mutex);
        return std::find(g_jassBlocks.begin(), g_jassBlocks.end(), ptr) != g_jassBlocks.end();
    }

    // 获取统计
    void GetStats(size_t& blockCount, size_t& totalSize) {
        std::lock_guard<std::mutex> lock(g_mutex);

        blockCount = g_jassBlocks.size();
        totalSize = 0;

        for (void* ptr : g_jassBlocks) {
            size_t size = MemorySafetyUtils::GetBlockSize(ptr);
            if (size > 0) {
                totalSize += size;
            }
        }
    }

    // 打印统计
    void PrintStats() {
        size_t blockCount = 0;
        size_t totalSize = 0;

        GetStats(blockCount, totalSize);

        LogMessage("[JassVM] 内存池统计: 块数量=%zu, 总大小=%zu KB",
            blockCount, totalSize / 1024);
    }

    // 关闭
    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (!g_initialized.load()) return;

        size_t count = g_jassBlocks.size();
        LogMessage("[JassVM] 关闭内存池，释放%zu个块", count);

        // 释放所有跟踪的块
        for (void* ptr : g_jassBlocks) {
            MemoryPool::FreeSafe(ptr);
        }

        g_jassBlocks.clear();
        g_initialized.store(false);
    }
};