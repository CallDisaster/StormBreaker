#include "pch.h"
//#include "MemoryPool.h"
//#include <Windows.h>
//#include <mutex>
//#include <unordered_map>
//#include <vector>
//#include <algorithm>
//#include <cassert>
//#include <dbghelp.h>
//#include <iostream>
//#include <spdlog/spdlog.h>
//
//
//#pragma comment(lib, "dbghelp.lib")
//
//// ------- 参数可自行调整 -------
//static constexpr std::size_t BlockSize    = 0x28A8;
//static constexpr std::size_t PoolCapacity = 256; // 最多多少块，看你需求调整
//// --------------------------------
//
//// 每块前面的头部，用来识别是不是本池分配
//struct BlockHeader {
//    unsigned magic;
//};
//
//// 约定魔数
//static constexpr unsigned POOL_MAGIC = 0xDEADBEEF;
//
//// 整个池的总内存占用（含头部）
//static constexpr std::size_t RealBlockSize = BlockSize + sizeof(BlockHeader);
//
//// （演示）使用一个静态数组，长度为 PoolCapacity，每块大小为 RealBlockSize
//static alignas(std::max_align_t) unsigned char s_poolMemory[PoolCapacity][RealBlockSize];
//
//// 是否正在使用
//static bool s_usedFlags[PoolCapacity];
//
//// 统计当前池已使用的大小(累加每次分配时的块大小 RealBlockSize)，防止超 0x7FFFFFFF
//static std::atomic<size_t> s_totalUsage{ 0 };
//
//// 互斥保护
//static std::mutex s_mutex;
//
//namespace MemPool {
//
//void Initialize() {
//    // 这里如果你想用动态分配，可以在此处 malloc/VirtualAlloc 大片内存
//    // 再拆分成 PoolCapacity 个块。演示就不写了。
//    std::lock_guard<std::mutex> lock(s_mutex);
//    std::memset(s_usedFlags, false, sizeof(s_usedFlags));
//    s_totalUsage = 0;
//    printf("[MemPool] Initialize done.\n");
//}
//
//void* Allocate(std::size_t size) {
//    // 只处理特定 size
//    if (size != BlockSize) {
//        return nullptr; // 返回空, 让外部去走原来或别的分配器
//    }
//    std::lock_guard<std::mutex> lock(s_mutex);
//
//    // 检查是否会超 0x7FFFFFFF
//    // 注：这里假设每个分配都是 RealBlockSize，如果你想更精确，可以记录已用块 * RealBlockSize
//    if (s_totalUsage.load() + RealBlockSize > 0x7FFFFFFF) {
//        // 超过了 => 分配失败，让外面走原 Storm
//        printf("[MemPool] usage limit exceeded (>=0x7FFFFFFF), fallback.\n");
//        return nullptr;
//    }
//
//    // 找到一个空闲块
//    for (std::size_t i = 0; i < PoolCapacity; i++) {
//        if (!s_usedFlags[i]) {
//            // 占用它
//            s_usedFlags[i] = true;
//            // 写header
//            BlockHeader* header = reinterpret_cast<BlockHeader*>(&s_poolMemory[i][0]);
//            header->magic = POOL_MAGIC;
//            s_totalUsage += RealBlockSize;
//
//            // 用户指针在头部之后
//            unsigned char* userPtr = &s_poolMemory[i][0] + sizeof(BlockHeader);
//            // 清空下用户区(可选)
//            std::memset(userPtr, 0, BlockSize);
//            return userPtr;
//        }
//    }
//
//    // 没有可用空闲块 => 返回 nullptr，走原始分配
//    // 也可以自行扩容或其他策略
//    return nullptr;
//}
//
//void Free(void* p) {
//    if (!p) return;
//    // 找到对应 header
//    unsigned char* rawPtr = reinterpret_cast<unsigned char*>(p) - sizeof(BlockHeader);
//    BlockHeader* header = reinterpret_cast<BlockHeader*>(rawPtr);
//    if (header->magic != POOL_MAGIC) {
//        // 不是我们分配的
//        return;
//    }
//
//    std::lock_guard<std::mutex> lock(s_mutex);
//
//    // 计算出是第几个块
//    std::ptrdiff_t index = (reinterpret_cast<unsigned char(*)[RealBlockSize]>(rawPtr)
//                           - reinterpret_cast<unsigned char(*)[RealBlockSize]>(&s_poolMemory[0][0]));
//    // 安全检查
//    if (index < 0 || index >= (std::ptrdiff_t)PoolCapacity) {
//        // 理论上不该发生
//        return;
//    }
//
//    // 标记为空闲
//    s_usedFlags[index] = false;
//    s_totalUsage -= RealBlockSize; // 释放
//}
//
//bool IsFromPool(void* p) {
//    if (!p) return false;
//    // 检查 magic
//    unsigned char* rawPtr = reinterpret_cast<unsigned char*>(p) - sizeof(BlockHeader);
//    BlockHeader* header = reinterpret_cast<BlockHeader*>(rawPtr);
//    return (header->magic == POOL_MAGIC);
//}
//
//void Cleanup() {
//    std::lock_guard<std::mutex> lock(s_mutex);
//    // 如果是静态数组，这里啥也不用真的 free；把标记置空即可
//    std::memset(s_usedFlags, false, sizeof(s_usedFlags));
//    s_totalUsage = 0;
//    printf("[MemPool] Cleanup done.\n");
//}
//
//} // namespace MemPool