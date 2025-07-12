#pragma once

#include "pch.h"

//
// 这是根据IDA Pro对Storm.dll中0x1502A510 (StormHeap_AllocPage)函数
// 的反编译结果逆向出的真实内存块头部结构。
//

#pragma pack(push, 1)

// 标准Storm内存块头部（8字节）
// 用于从堆的空闲链表中分配的块
struct StormBlockHeader {
    // 块的总大小，包括头部本身。
    // 例如，如果用户请求10字节，实际分配可能是10(用户)+8(头)+6(对齐)=24字节。
    // 这里的size就是24。
    uint16_t size;

    // 为了使块的用户区指针按8字节对齐而填充的字节数。
    // (user_ptr - raw_ptr - 8)
    uint8_t align_padding;

    // 标志位
    // 0x01: 启用尾部魔数校验 (0x12B1)
    // 0x02: 块已释放
    // 0x04: 通过VirtualAlloc直接分配的大块（非来自堆）
    // 0x08: 对齐分配（此时头部之前有额外数据）
    // 0x10: 前一个物理块是空闲的
    uint8_t flags;

    // 魔数，固定为0x6F6D (ASCII "mo")
    uint16_t magic;

    // 指向所属堆控制块的高16位。
    // Storm通过这个值来快速定位堆。
    // 我们可以用一个特殊值（如0xC0DE）来标记这是我们管理的块。
    uint16_t heap_ptr_high;
};

#pragma pack(pop)

// 确保结构体大小正确
static_assert(sizeof(StormBlockHeader) == 8, "StormBlockHeader size must be 8 bytes.");

// 尾部魔数，如果flags & 0x01，则在块的末尾存在此值
constexpr uint16_t STORM_TAIL_MAGIC_INTERNAL = 0x12B1;

// 我们用来标记自定义块的特殊堆指针高位
constexpr uint16_t CUSTOM_HEAP_MARKER = 0xC0DE;
