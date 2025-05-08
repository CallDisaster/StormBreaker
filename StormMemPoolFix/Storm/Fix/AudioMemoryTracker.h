// AudioMemoryPool.h
#pragma once
#include <Windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_map>
#include "Log/LogSystem.h"

class AudioMemoryPool {
private:
    // 音频分配信息
    struct AudioAllocation {
        size_t offset;         // 在块内的偏移
        size_t size;           // 分配大小
        DWORD timestamp;       // 上次访问时间
        bool isActive;         // 是否活跃（正在播放）
    };

    // 块结构定义
    struct PoolBlock {
        void* memory;          // 内存起始地址
        size_t totalSize;      // 总大小
        size_t usedSize;       // 已使用大小
        bool isFull;           // 是否已满
        DWORD lastAccessTime;  // 最后访问时间
        int id;                // 块ID（用于日志）

        // 跟踪块内分配
        std::unordered_map<void*, AudioAllocation> allocations;
    };

    // 块列表及锁
    std::vector<PoolBlock> m_blocks;
    std::mutex m_poolMutex;

    // 配置参数
    const size_t BLOCK_SIZE = 256 * 1024;  // 256KB/块
    const size_t MAX_BLOCKS = 8;           // 最多8个块
    const size_t MIN_ALLOC_SIZE = 64;      // 最小分配单位

    // 统计信息 - 静态成员以便在多个实例间共享
    static std::atomic<size_t> s_totalAllocations;
    static std::atomic<size_t> s_totalBytes;
    static std::atomic<size_t> s_wastedBytes;

public:
    AudioMemoryPool();
    ~AudioMemoryPool();

    // 单例访问
    static AudioMemoryPool& GetInstance();

    // 从池中分配内存
    // 参数:
    //   size - 请求的大小
    //   isActiveAudio - 是否是正在播放的音频
    void* Allocate(size_t size, bool isActiveAudio = false);

    // 标记音频为活跃或非活跃
    void MarkActive(void* ptr, bool isActive);

    // 打印统计信息
    void PrintStats();

    // 清理非活跃的音频分配
    // 参数:
    //   ageThresholdMs - 非活跃时间阈值（毫秒）
    void CleanupInactive(DWORD ageThresholdMs);

    // 清理所有内存
    void Cleanup();
};

extern bool IsAudioMemoryAllocation(const char* name, DWORD src_line);

// 全局访问
#define g_AudioPool AudioMemoryPool::GetInstance()