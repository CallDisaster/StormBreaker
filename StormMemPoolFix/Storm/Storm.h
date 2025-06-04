#pragma once
#include <cstdint>
#include <cstddef>
#include <Windows.h>
#include <stdio.h>

//---------------------------------------------------------------------------
//  Storm 内存块常量与结构（完全贴合原版 Storm.dll）
//---------------------------------------------------------------------------
namespace StormConst {
    // ---- 标志位定义 ----
    constexpr uint8_t FLAG_TAIL_SENTINEL = 0x1;   // 尾部守卫标志（2字节 0x12B1）
    constexpr uint8_t FLAG_FREED = 0x2;   // 已释放
    constexpr uint8_t FLAG_BIG_BLOCK = 0x4;   // 大块（VirtualAlloc 路径）
    constexpr uint8_t FLAG_ALIGNED = 0x8;   // 对齐分配（userPtr - 12 处存原始指针）

    // ---- 魔数/守卫 ----
    constexpr uint16_t MAGIC_WORD = 0x6F6D; // 固定 "mo"
    constexpr uint16_t TAIL_SENTINEL = 0x12B1; // 尾部守卫值

    // ---- 大小常量 ----
    constexpr size_t HEADER_SIZE = 8;    // 标准头部
    constexpr size_t ALIGNED_HEADER_SIZE = 12;   // 对齐分配头部
    constexpr size_t TAIL_GUARD_SIZE = 2;    // 尾部守卫本身
    constexpr size_t LINK_POINTER_SIZE = 8;    // 链表指针区域大小
    constexpr size_t TOTAL_TAIL_SIZE = LINK_POINTER_SIZE + TAIL_GUARD_SIZE; // 总尾部大小：10字节

    // ---- 大小限制 ----
    constexpr size_t MAX_SMALL_BLOCK = 0xFFFF;   // 最大小块大小
    constexpr size_t MIN_ALLOC_SIZE = 16;       // 最小分配大小
}

//---------------------------------------------------------------------------
//  StormAllocHeader —— 8字节标准头部
//---------------------------------------------------------------------------
#pragma pack(push, 1)
struct StormAllocHeader {
    uint16_t Size;      // 总块大小（包含头+用户区+尾部），大块时填0xFFFF
    uint8_t  AlignPad;  // 对齐填充字节数
    uint8_t  Flags;     // 标志位组合（见 StormConst）
    uint16_t HeapHigh;  // 堆标识高16位（Storm内部使用）
    uint16_t Magic;     // 固定魔数 0x6F6D
};
#pragma pack(pop)

static_assert(sizeof(StormAllocHeader) == 8, "StormAllocHeader must be 8 bytes");

//---------------------------------------------------------------------------
//  StormMem —— 内存块操作工具函数
//---------------------------------------------------------------------------
namespace StormMem {

    // 从用户指针获取头部
    inline StormAllocHeader* GetHeader(void* userPtr) noexcept {
        return userPtr ? reinterpret_cast<StormAllocHeader*>(
            static_cast<uint8_t*>(userPtr) - StormConst::HEADER_SIZE
            ) : nullptr;
    }

    // 获取原始分配指针（处理对齐情况）
    inline void* GetRawPtr(void* userPtr) noexcept {
        if (!userPtr) return nullptr;

        auto* hdr = GetHeader(userPtr);
        if (!hdr) return nullptr;

        // 如果是对齐分配，从 userPtr-12 处读取原始指针
        if (hdr->Flags & StormConst::FLAG_ALIGNED) {
            void** originalPtrSlot = reinterpret_cast<void**>(
                static_cast<uint8_t*>(userPtr) - StormConst::ALIGNED_HEADER_SIZE
                );
            return *originalPtrSlot;
        }

        // 普通分配，原始指针就是头部地址
        return hdr;
    }

    // 验证魔数
    inline bool ValidateMagic(void* userPtr) noexcept {
        auto* hdr = GetHeader(userPtr);
        return hdr && hdr->Magic == StormConst::MAGIC_WORD;
    }

    // 验证头部完整性
    inline bool ValidateHeader(void* userPtr) noexcept {
        auto* hdr = GetHeader(userPtr);
        if (!hdr) return false;

        // 检查魔数
        if (hdr->Magic != StormConst::MAGIC_WORD) return false;

        // 检查大小合理性
        if (hdr->Size == 0) return false;

        // 检查标志位合理性
        uint8_t validFlags = StormConst::FLAG_TAIL_SENTINEL |
            StormConst::FLAG_FREED |
            StormConst::FLAG_BIG_BLOCK |
            StormConst::FLAG_ALIGNED;
        if (hdr->Flags & ~validFlags) return false;

        return true;
    }

    // 获取尾部哨兵指针
    inline uint16_t* GetTailSentinel(void* userPtr) noexcept {
        if (!userPtr) return nullptr;

        auto* hdr = GetHeader(userPtr);
        if (!hdr || !(hdr->Flags & StormConst::FLAG_TAIL_SENTINEL)) {
            return nullptr;
        }

        // 尾部哨兵位置：rawPtr + Size - 2
        auto* rawPtr = static_cast<uint8_t*>(GetRawPtr(userPtr));
        return reinterpret_cast<uint16_t*>(rawPtr + hdr->Size - StormConst::TAIL_GUARD_SIZE);
    }

    // 设置尾部哨兵
    inline void SetTailSentinel(void* userPtr) noexcept {
        if (auto* sentinel = GetTailSentinel(userPtr)) {
            *sentinel = StormConst::TAIL_SENTINEL;
        }
    }

    // 检查尾部哨兵完整性
    inline bool CheckTailSentinel(void* userPtr) noexcept {
        auto* sentinel = GetTailSentinel(userPtr);
        if (!sentinel) return true; // 没有哨兵认为检查通过

        return *sentinel == StormConst::TAIL_SENTINEL;
    }

    // 获取用户数据大小
    inline size_t GetUserDataSize(void* userPtr) noexcept {
        auto* hdr = GetHeader(userPtr);
        if (!hdr) return 0;

        size_t totalSize = hdr->Size;
        size_t overhead = StormConst::HEADER_SIZE;

        // 减去对齐填充
        overhead += hdr->AlignPad;

        // 减去尾部结构（链表指针 + 哨兵）
        overhead += StormConst::TOTAL_TAIL_SIZE;

        return totalSize > overhead ? totalSize - overhead : 0;
    }

    // 获取链表指针区域
    inline void* GetLinkArea(void* userPtr) noexcept {
        if (!userPtr) return nullptr;

        auto* hdr = GetHeader(userPtr);
        if (!hdr) return nullptr;

        // 链表区域：rawPtr + Size - 10 （10 = 8字节链表 + 2字节哨兵）
        auto* rawPtr = static_cast<uint8_t*>(GetRawPtr(userPtr));
        return rawPtr + hdr->Size - StormConst::TOTAL_TAIL_SIZE;
    }

    // 计算所需的总分配大小
    inline size_t CalcTotalSize(size_t userSize, size_t alignment = 0, bool withSentinel = true) noexcept {
        size_t totalSize = StormConst::HEADER_SIZE;  // 基础头部

        // 如果需要对齐，可能需要额外的4字节存储原始指针
        if (alignment > 1) {
            totalSize = StormConst::ALIGNED_HEADER_SIZE;

            // 计算对齐填充
            size_t baseAddr = totalSize; // 假设的基地址
            size_t userStart = baseAddr + StormConst::HEADER_SIZE;
            size_t aligned = (userStart + alignment - 1) & ~(alignment - 1);
            totalSize += (aligned - userStart); // 添加对齐填充
        }

        totalSize += userSize;  // 用户数据区
        totalSize += StormConst::TOTAL_TAIL_SIZE;  // 尾部区域（链表+哨兵）

        return totalSize;
    }

    // 设置头部信息
    inline void SetupHeader(void* rawPtr, void* userPtr, size_t userSize,
        size_t totalSize, uint8_t flags, bool withSentinel = true) noexcept {
        if (!rawPtr || !userPtr) return;

        auto* hdr = reinterpret_cast<StormAllocHeader*>(
            static_cast<uint8_t*>(rawPtr) +
            ((flags & StormConst::FLAG_ALIGNED) ? 4 : 0)  // 对齐时头部前移4字节
            );

        // 大块处理
        if (totalSize > StormConst::MAX_SMALL_BLOCK) {
            hdr->Size = StormConst::MAX_SMALL_BLOCK;
            flags |= StormConst::FLAG_BIG_BLOCK;

            // 将真实大小存储在用户指针前12字节处
            if (flags & StormConst::FLAG_ALIGNED) {
                *reinterpret_cast<size_t*>(
                    static_cast<uint8_t*>(userPtr) - StormConst::ALIGNED_HEADER_SIZE - 4
                    ) = totalSize;
            }
        }
        else {
            hdr->Size = static_cast<uint16_t>(totalSize);
        }

        // 计算对齐填充
        hdr->AlignPad = static_cast<uint8_t>(
            static_cast<uint8_t*>(userPtr) - static_cast<uint8_t*>(rawPtr) - StormConst::HEADER_SIZE
            );

        // 设置标志
        if (withSentinel) {
            flags |= StormConst::FLAG_TAIL_SENTINEL;
        }
        hdr->Flags = flags;

        hdr->HeapHigh = 0;  // 简化处理，Storm内部会设置
        hdr->Magic = StormConst::MAGIC_WORD;

        // 如果是对齐分配，存储原始指针
        if (flags & StormConst::FLAG_ALIGNED) {
            *reinterpret_cast<void**>(
                static_cast<uint8_t*>(userPtr) - StormConst::ALIGNED_HEADER_SIZE
                ) = rawPtr;
        }

        // 清零链表区域
        memset(GetLinkArea(userPtr), 0, StormConst::LINK_POINTER_SIZE);

        // 设置尾部哨兵
        if (withSentinel) {
            SetTailSentinel(userPtr);
        }
    }

    // 判断是否为我们管理的内存块
    inline bool IsOurBlock(void* userPtr) noexcept {
        if (!userPtr) return false;

        __try {
            // 基本指针有效性检查
            if (IsBadReadPtr(userPtr, sizeof(void*))) {
                return false;
            }

            auto* hdr = GetHeader(userPtr);
            if (IsBadReadPtr(hdr, sizeof(StormAllocHeader))) {
                return false;
            }

            // 检查魔数和基本标志
            return ValidateHeader(userPtr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

} // namespace StormMem

//---------------------------------------------------------------------------
//  调试和统计相关
//---------------------------------------------------------------------------
namespace StormDebug {

    // 内存块信息结构
    struct BlockInfo {
        void* userPtr;
        void* rawPtr;
        size_t totalSize;
        size_t userSize;
        uint8_t flags;
        bool isValid;
        const char* lastError;
    };

    // 获取内存块详细信息
    inline BlockInfo GetBlockInfo(void* userPtr) noexcept {
        BlockInfo info = {};
        info.userPtr = userPtr;

        if (!userPtr) {
            info.lastError = "空指针";
            return info;
        }

        __try {
            auto* hdr = StormMem::GetHeader(userPtr);
            if (!hdr) {
                info.lastError = "无法获取头部";
                return info;
            }

            info.rawPtr = StormMem::GetRawPtr(userPtr);
            info.totalSize = hdr->Size;
            info.userSize = StormMem::GetUserDataSize(userPtr);
            info.flags = hdr->Flags;
            info.isValid = StormMem::ValidateHeader(userPtr);

            if (info.isValid && (hdr->Flags & StormConst::FLAG_TAIL_SENTINEL)) {
                if (!StormMem::CheckTailSentinel(userPtr)) {
                    info.isValid = false;
                    info.lastError = "尾部哨兵损坏";
                }
            }

            if (info.isValid) {
                info.lastError = "正常";
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            info.lastError = "访问异常";
            info.isValid = false;
        }

        return info;
    }

    // 打印内存块信息（调试用）
    inline void PrintBlockInfo(void* userPtr, const char* context = nullptr) noexcept {
        auto info = GetBlockInfo(userPtr);

        printf("[Storm内存块%s%s] userPtr=%p, rawPtr=%p, total=%zu, user=%zu, flags=0x%02X, 状态=%s\n",
            context ? " " : "", context ? context : "",
            info.userPtr, info.rawPtr, info.totalSize, info.userSize,
            info.flags, info.lastError);
    }

} // namespace StormDebug