#pragma once
#include "pch.h"
#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <memory>

// ====================================================
// 简化的内存池接口 - 仅保留必要功能
// ====================================================

namespace MemoryPoolUtils {
    // 内存池统计信息
    struct PoolStatistics {
        std::atomic<size_t> totalAllocated{ 0 };
        std::atomic<size_t> totalFreed{ 0 };
        std::atomic<size_t> currentUsed{ 0 };
        std::atomic<size_t> peakUsed{ 0 };
        std::atomic<size_t> allocationCount{ 0 };
        std::atomic<size_t> freeCount{ 0 };

        void OnAlloc(size_t size) {
            totalAllocated.fetch_add(size, std::memory_order_relaxed);
            currentUsed.fetch_add(size, std::memory_order_relaxed);
            allocationCount.fetch_add(1, std::memory_order_relaxed);

            // 更新峰值
            size_t current = currentUsed.load(std::memory_order_relaxed);
            size_t peak = peakUsed.load(std::memory_order_relaxed);
            while (current > peak) {
                if (peakUsed.compare_exchange_weak(peak, current, std::memory_order_relaxed)) {
                    break;
                }
            }
        }

        void OnFree(size_t size) {
            totalFreed.fetch_add(size, std::memory_order_relaxed);
            currentUsed.fetch_sub(size, std::memory_order_relaxed);
            freeCount.fetch_add(1, std::memory_order_relaxed);
        }

        void Reset() {
            totalAllocated.store(0);
            totalFreed.store(0);
            currentUsed.store(0);
            peakUsed.store(0);
            allocationCount.store(0);
            freeCount.store(0);
        }
    };

    // 全局统计实例
    extern PoolStatistics g_globalStats;

    // 辅助函数
    void UpdateGlobalStats(size_t size, bool isAlloc);
    void PrintMemoryPoolStats();
    void ResetMemoryPoolStats();
}