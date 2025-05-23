//=== StormCompatible.h ===
#pragma once
#include "pch.h"
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include <memory>
#include <array>

namespace StormCompatible {

    // Storm兼容的块头结构 - 必须与Storm.dll完全一致
#pragma pack(push, 1)
    struct StormBlockHeader {
        DWORD HeapPtr;      // [0] 指向堆结构的指针
        DWORD Size;         // [4] 用户数据大小
        BYTE  AlignPadding; // [8] 对齐填充字节数  
        BYTE  Flags;        // [9] 标志位：0x1=边界检查, 0x2=已释放, 0x4=大块VirtualAlloc, 0x8=特殊标记
        WORD  Magic;        // [10] 魔数，必须是0x6F6D

        // 验证函数
        bool IsValid() const { return Magic == 0x6F6D; }
        bool IsFree() const { return (Flags & 0x2) != 0; }
        bool IsBigBlock() const { return (Flags & 0x4) != 0; }
        bool HasBoundaryCheck() const { return (Flags & 0x1) != 0; }

        // 获取用户数据指针
        void* GetUserData() { return reinterpret_cast<char*>(this) + sizeof(StormBlockHeader); }

        // 从用户指针获取头部
        static StormBlockHeader* FromUserPtr(void* userPtr) {
            if (!userPtr) return nullptr;
            return reinterpret_cast<StormBlockHeader*>(static_cast<char*>(userPtr) - sizeof(StormBlockHeader));
        }

        // 获取边界检查魔数地址
        WORD* GetBoundaryMagic() {
            if (!HasBoundaryCheck()) return nullptr;
            return reinterpret_cast<WORD*>(static_cast<char*>(GetUserData()) + Size - AlignPadding - 2);
        }
    };
#pragma pack(pop)

    // Storm兼容的空闲块结构
#pragma pack(push, 1)
    struct StormFreeBlock {
        WORD  size;         // 包含头部在内的总块大小
        BYTE  alignPadding; // 对齐填充
        BYTE  flags;        // 0x2=free, 0x10=前一个块空闲
        StormFreeBlock* next; // 链表下一个节点

        bool IsFree() const { return (flags & 0x2) != 0; }
        void SetFree(bool free) { if (free) flags |= 0x2; else flags &= ~0x2; }
    };
#pragma pack(pop)

    // 模拟Storm堆结构（只包含必要字段）
    struct SimulatedStormHeap {
        SimulatedStormHeap* next;       // [0] 链表下一个堆
        DWORD heapIndex;                // [1] 堆索引 (0-255)
        DWORD heapId;                   // [2] 堆ID
        DWORD heapSignature;            // [3] 堆签名
        DWORD activeFlag;               // [4] 活跃标志
        DWORD allocCount;               // [5] 分配计数
        DWORD allocSize;                // [6] 分配总大小
        void* memoryStart;              // [7] 内存起始位置
        void* memoryEnd;                // [8] 内存结束位置
        DWORD fragCount;                // [9] 碎片计数
        DWORD commitGranularity;        // [10] 提交粒度
        DWORD commitSize;               // [11] 已提交大小
        DWORD totalSize;                // [12] 总大小
        DWORD bigBlockSize;             // [13] 大块总大小
        DWORD reallocCount;             // [14] 重分配计数
        DWORD freeCount;                // [15] 释放计数
        DWORD reallocSizeCount;         // [16] 重分配大小计数
        void* freeList[9];              // [17-25] 空闲链表 (9个级别)
        DWORD srcLine;                  // [26] 源代码行号
        char name[64];                  // [27+] 名称缓冲区

        // 构造函数
        SimulatedStormHeap(DWORD index, const char* heapName = nullptr);
        ~SimulatedStormHeap();

        // 检查指针是否在堆范围内
        bool ContainsPointer(void* ptr) const {
            return ptr >= memoryStart && ptr < memoryEnd;
        }

        // 获取空闲链表索引
        int GetFreeListIndex(size_t size) const {
            int index = static_cast<int>(size >> 5); // size / 32
            return (index < 9) ? index : 8;
        }
    };

    // Storm兼容的内存分配器
    class StormCompatibleAllocator {
    private:
        static constexpr size_t MAX_HEAPS = 256;
        static constexpr size_t DEFAULT_HEAP_SIZE = 16 * 1024 * 1024; // 16MB
        static constexpr size_t BOUNDARY_MAGIC = 0x12B1; // 4785

        // 堆表和临界区
        std::array<std::unique_ptr<SimulatedStormHeap>, MAX_HEAPS> heapTable_;
        std::array<CRITICAL_SECTION, MAX_HEAPS> criticalSections_;
        std::mutex heapTableMutex_;
        std::atomic<bool> initialized_{ false };

        // 统计信息
        std::atomic<size_t> totalAllocated_{ 0 };
        std::atomic<size_t> totalFreed_{ 0 };
        std::atomic<size_t> allocCount_{ 0 };
        std::atomic<size_t> freeCount_{ 0 };

    public:
        bool EnsureCommitted(SimulatedStormHeap* heap, size_t sizeNeeded);
        StormCompatibleAllocator();
        ~StormCompatibleAllocator();

        // 获取单例
        static StormCompatibleAllocator& GetInstance();

        // 初始化
        bool Initialize();
        void Shutdown();

        // Storm兼容的分配接口
        void* AllocateCompatible(size_t size, const char* name, DWORD srcLine, DWORD flags);
        bool FreeCompatible(void* userPtr);
        void* ReallocateCompatible(void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags);

        // 检查指针是否由我们管理
        bool IsOurPointer(void* ptr);

        // 统计信息
        void GetStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) const;

    private:
        // 堆管理
        SimulatedStormHeap* GetOrCreateHeap(BYTE heapIndex, const char* name);
        BYTE ComputeHeapIndex(const char* name, DWORD srcLine);

        // 内存操作
        void* AllocateFromHeap(SimulatedStormHeap* heap, size_t size, DWORD flags);
        bool FreeToHeap(SimulatedStormHeap* heap, StormBlockHeader* header);

        // 空闲链表管理
        StormFreeBlock* FindFreeBlock(SimulatedStormHeap* heap, size_t requiredSize);
        void AddToFreeList(SimulatedStormHeap* heap, StormFreeBlock* block);
        void RemoveFromFreeList(SimulatedStormHeap* heap, StormFreeBlock* block);

        // 块操作
        void SetupBlockHeader(StormBlockHeader* header, SimulatedStormHeap* heap, size_t userSize, DWORD flags);
        bool ValidateBlockHeader(const StormBlockHeader* header);
        void CoalesceBlocks(SimulatedStormHeap* heap, StormFreeBlock* block);

        // 哈希计算（模拟Storm_502函数）
        uint32_t ComputeStormHash(const char* name, bool caseSensitive, DWORD seed);
    };

} // namespace StormCompatible