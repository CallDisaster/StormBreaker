// AudioMemoryPool.cpp
#include "pch.h"
#include "AudioMemoryTracker.h"
#include "Log/LogSystem.h"

// 初始化静态成员
std::atomic<size_t> AudioMemoryPool::s_totalAllocations{ 0 };
std::atomic<size_t> AudioMemoryPool::s_totalBytes{ 0 };
std::atomic<size_t> AudioMemoryPool::s_wastedBytes{ 0 };

AudioMemoryPool::AudioMemoryPool() {
    LogMessage("[AudioPool] 初始化音频内存池");
}

AudioMemoryPool::~AudioMemoryPool() {
    Cleanup();
}

AudioMemoryPool& AudioMemoryPool::GetInstance() {
    static AudioMemoryPool instance;
    return instance;
}

void* AudioMemoryPool::Allocate(size_t size, bool isActiveAudio) {
    if (size == 0) return nullptr;

    // 对齐到MIN_ALLOC_SIZE
    size = (size + MIN_ALLOC_SIZE - 1) & ~(MIN_ALLOC_SIZE - 1);

    std::lock_guard<std::mutex> lock(m_poolMutex);

    // 1. 尝试在现有块中分配
    for (auto& block : m_blocks) {
        if (!block.isFull && block.usedSize + size <= block.totalSize) {
            void* ptr = static_cast<char*>(block.memory) + block.usedSize;

            // 记录分配信息
            AudioAllocation alloc;
            alloc.offset = block.usedSize;
            alloc.size = size;
            alloc.timestamp = GetTickCount();
            alloc.isActive = isActiveAudio;
            block.allocations[ptr] = alloc;

            block.usedSize += size;
            block.isFull = (block.usedSize + MIN_ALLOC_SIZE > block.totalSize);
            block.lastAccessTime = GetTickCount();

            s_totalAllocations++;
            s_totalBytes += size;

            return ptr;
        }
    }

    // 2. 如果没有合适的块，创建新块
    if (m_blocks.size() < MAX_BLOCKS) {
        size_t blockSize = max(BLOCK_SIZE, size + MIN_ALLOC_SIZE);
        void* newMemory = VirtualAlloc(NULL, blockSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (newMemory) {
            PoolBlock newBlock;
            newBlock.memory = newMemory;
            newBlock.totalSize = blockSize;
            newBlock.usedSize = size;
            newBlock.isFull = (size + MIN_ALLOC_SIZE > blockSize);
            newBlock.lastAccessTime = GetTickCount();
            newBlock.id = m_blocks.size();

            // 记录分配信息
            AudioAllocation alloc;
            alloc.offset = 0;
            alloc.size = size;
            alloc.timestamp = GetTickCount();
            alloc.isActive = isActiveAudio;
            newBlock.allocations[newMemory] = alloc;

            // 添加新块
            m_blocks.push_back(newBlock);

            s_totalAllocations++;
            s_totalBytes += size;

            LogMessage("[AudioPool] 创建新内存块: ID=%d, 大小=%zu KB",
                newBlock.id, blockSize / 1024);

            return newMemory;
        }
    }

    // 3. 如果块数已达上限，找出可以部分重用的块
    if (!m_blocks.empty()) {
        // 找出可以安全重用的块（不包含活跃音频）
        int bestBlockIdx = -1;
        size_t bestFreeSpace = 0;
        DWORD oldestTime = MAXDWORD;

        for (size_t i = 0; i < m_blocks.size(); i++) {
            // 如果有足够空间，直接使用
            if (!m_blocks[i].isFull && m_blocks[i].usedSize + size <= m_blocks[i].totalSize) {
                bestBlockIdx = i;
                break;
            }

            // 检查是否有活跃音频
            bool hasActiveAudio = false;
            for (const auto& entry : m_blocks[i].allocations) {
                if (entry.second.isActive) {
                    hasActiveAudio = true;
                    break;
                }
            }

            // 如果没有活跃音频，考虑重用
            if (!hasActiveAudio) {
                // 找最老的非活跃块
                if (m_blocks[i].lastAccessTime < oldestTime) {
                    bestBlockIdx = i;
                    oldestTime = m_blocks[i].lastAccessTime;
                }
            }
        }

        // 如果找到可以重用的块
        if (bestBlockIdx >= 0) {
            auto& block = m_blocks[bestBlockIdx];

            // 记录浪费的字节
            s_wastedBytes += block.usedSize;

            // 完全重置块
            if (block.usedSize + size > block.totalSize) {
                // 清空allocations表
                block.allocations.clear();

                // 记录新分配
                AudioAllocation alloc;
                alloc.offset = 0;
                alloc.size = size;
                alloc.timestamp = GetTickCount();
                alloc.isActive = isActiveAudio;
                block.allocations[block.memory] = alloc;

                block.usedSize = size;
                block.isFull = (size + MIN_ALLOC_SIZE > block.totalSize);
                block.lastAccessTime = GetTickCount();

                s_totalAllocations++;
                s_totalBytes += size;

                LogMessage("[AudioPool] 重用内存块: ID=%d, 完全重置", block.id);

                return block.memory;
            }
            // 部分重用块 - 在现有空间后添加
            else {
                void* ptr = static_cast<char*>(block.memory) + block.usedSize;

                // 记录分配信息
                AudioAllocation alloc;
                alloc.offset = block.usedSize;
                alloc.size = size;
                alloc.timestamp = GetTickCount();
                alloc.isActive = isActiveAudio;
                block.allocations[ptr] = alloc;

                block.usedSize += size;
                block.isFull = (block.usedSize + MIN_ALLOC_SIZE > block.totalSize);
                block.lastAccessTime = GetTickCount();

                s_totalAllocations++;
                s_totalBytes += size;

                return ptr;
            }
        }
    }

    // 所有策略都失败，回退到常规分配
    LogMessage("[AudioPool] 所有策略失败，回退到常规分配: 大小=%zu", size);
    return nullptr;
}

void AudioMemoryPool::MarkActive(void* ptr, bool isActive) {
    std::lock_guard<std::mutex> lock(m_poolMutex);

    // 在所有块中查找该指针
    for (auto& block : m_blocks) {
        auto it = block.allocations.find(ptr);
        if (it != block.allocations.end()) {
            // 更新活跃状态
            it->second.isActive = isActive;
            // 更新时间戳
            it->second.timestamp = GetTickCount();
            return;
        }
    }
}

void AudioMemoryPool::PrintStats() {
    std::lock_guard<std::mutex> lock(m_poolMutex);

    size_t totalPoolSize = 0;
    size_t totalUsed = 0;
    size_t totalWasted = 0;
    size_t activeAllocations = 0;

    for (const auto& block : m_blocks) {
        totalPoolSize += block.totalSize;
        totalUsed += block.usedSize;

        // 计算活跃分配数
        for (const auto& entry : block.allocations) {
            if (entry.second.isActive) {
                activeAllocations++;
            }
        }
    }

    totalWasted = s_wastedBytes.load(std::memory_order_relaxed);

    LogMessage("[AudioPool] 状态: 块数=%zu/%zu, 总池大小=%zu KB, 已使用=%zu KB, 活跃分配=%zu",
        m_blocks.size(), MAX_BLOCKS,
        totalPoolSize / 1024, totalUsed / 1024, activeAllocations);

    LogMessage("[AudioPool] 统计: 总分配=%zu, 总字节=%zu KB, 浪费=%zu KB",
        s_totalAllocations.load(std::memory_order_relaxed),
        s_totalBytes.load(std::memory_order_relaxed) / 1024,
        totalWasted / 1024);

    // 打印每个块的详细信息
    if (LogSystem::GetInstance().GetLogLevel() == LogLevel::Debug) {
        for (const auto& block : m_blocks) {
            LogMessage("[AudioPool]     块 #%d: 大小=%zu KB, 已用=%zu KB, 分配数=%zu",
                block.id, block.totalSize / 1024, block.usedSize / 1024, block.allocations.size());
        }
    }
}

void AudioMemoryPool::CleanupInactive(DWORD ageThresholdMs) {
    std::lock_guard<std::mutex> lock(m_poolMutex);

    DWORD currentTime = GetTickCount();
    size_t freedCount = 0;
    size_t reclaimedSpace = 0;

    for (auto& block : m_blocks) {
        // 收集过期的分配
        std::vector<void*> toRemove;
        for (auto& entry : block.allocations) {
            // 如果不是活跃的且超过阈值
            if (!entry.second.isActive &&
                (currentTime - entry.second.timestamp) > ageThresholdMs) {
                toRemove.push_back(entry.first);
                reclaimedSpace += entry.second.size;
            }
        }

        // 移除过期分配
        for (void* ptr : toRemove) {
            block.allocations.erase(ptr);
            freedCount++;
        }

        // 如果块完全空了，可以考虑整块重新组织
        if (block.allocations.empty() && m_blocks.size() > 1) {
            // 释放块内存，记录浪费
            s_wastedBytes += block.usedSize;

            // 仅标记为空闲，但保留内存以备将来使用
            block.usedSize = 0;
            block.isFull = false;
        }
    }

    if (freedCount > 0) {
        LogMessage("[AudioPool] 非活跃清理: 移除=%zu项, 回收大小=%zu KB",
            freedCount, reclaimedSpace / 1024);
    }
}

void AudioMemoryPool::Cleanup() {
    std::lock_guard<std::mutex> lock(m_poolMutex);

    LogMessage("[AudioPool] 开始完全清理...");

    for (auto& block : m_blocks) {
        if (block.memory) {
            VirtualFree(block.memory, 0, MEM_RELEASE);
        }
    }

    m_blocks.clear();
    LogMessage("[AudioPool] 已清理所有内存块");
}

// 确定是否为音频相关内存分配
bool IsAudioMemoryAllocation(const char* name, DWORD src_line) {
    if (!name) return false;

    // 识别W32\OsSnd.cpp的内存分配
    if (strstr(name, "OsSnd.cpp")) {
        // 特别关注的关键行号
        if (src_line == 377 || src_line == 2147) {
            return true;
        }
        return true; // 所有OsSnd.cpp的分配都视为音频相关
    }

    // 其他可能的音频相关文件
    if (strstr(name, "Snd") || strstr(name, "Audio") || strstr(name, "Sound")) {
        return true;
    }

    return false;
}