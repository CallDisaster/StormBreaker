// MemoryPool.cpp - 完整修复版本
#include "pch.h"
#include "pch.h"
#include "MemoryPool.h"
#include <Windows.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "StormHook.h"

namespace MemoryPoolUtils {
    // 全局统计实例
    PoolStatistics g_globalStats;

    void UpdateGlobalStats(size_t size, bool isAlloc) {
        if (isAlloc) {
            g_globalStats.OnAlloc(size);
        }
        else {
            g_globalStats.OnFree(size);
        }
    }

    void PrintMemoryPoolStats() {
        size_t allocated = g_globalStats.totalAllocated.load();
        size_t freed = g_globalStats.totalFreed.load();
        size_t current = g_globalStats.currentUsed.load();
        size_t peak = g_globalStats.peakUsed.load();
        size_t allocCount = g_globalStats.allocationCount.load();
        size_t freeCount = g_globalStats.freeCount.load();

        LogMessage("[MemoryPool] === 内存池统计 ===");
        LogMessage("[MemoryPool] 总分配: %zu 次, %zu MB", allocCount, allocated / (1024 * 1024));
        LogMessage("[MemoryPool] 总释放: %zu 次, %zu MB", freeCount, freed / (1024 * 1024));
        LogMessage("[MemoryPool] 当前使用: %zu MB", current / (1024 * 1024));
        LogMessage("[MemoryPool] 峰值使用: %zu MB", peak / (1024 * 1024));

        if (allocCount > freeCount) {
            LogMessage("[MemoryPool] 可能泄漏: %zu 个块, %zu MB",
                allocCount - freeCount, (allocated - freed) / (1024 * 1024));
        }
    }

    void ResetMemoryPoolStats() {
        g_globalStats.Reset();
        LogMessage("[MemoryPool] 统计已重置");
    }
}
