//=== StormCompatible.cpp ===
#include "pch.h"
#include "StormCompatible.h"
#include <cstring>
#include <algorithm>
#include "StormOffsets.h"
using namespace StormCompatConfig;

namespace StormCompatible {

    // SimulatedStormHeap 实现
    SimulatedStormHeap::SimulatedStormHeap(DWORD index, const char* heapName)
        : next(nullptr), heapIndex(index), heapId(index), activeFlag(1)
        , allocCount(0), allocSize(0), fragCount(0)
        , commitGranularity(4096), commitSize(0), totalSize(StormCompatConfig::DEFAULT_HEAP_SIZE)
        , bigBlockSize(0), reallocCount(0), freeCount(0), reallocSizeCount(0)
        , srcLine(0)
    {
        // 计算堆签名（模拟Storm的做法）
        heapSignature = (static_cast<DWORD>(reinterpret_cast<uintptr_t>(this) >> 16) << 16) | 0x6F6D;

        // 先 RESERVE 整个虚拟空间
        memoryStart = VirtualAlloc(nullptr, DEFAULT_HEAP_SIZE, MEM_RESERVE, PAGE_READWRITE);
        if (!memoryStart) {
            throw std::runtime_error("Failed to reserve simulated Storm heap memory");
        }
        memoryEnd = static_cast<char*>(memoryStart) + DEFAULT_HEAP_SIZE;

        // 只 COMMIT 4K
        if (!VirtualAlloc(memoryStart, commitGranularity, MEM_COMMIT, PAGE_READWRITE)) {
            VirtualFree(memoryStart, 0, MEM_RELEASE);
            throw std::runtime_error("Failed to commit initial page for Storm heap");
        }
        commitSize = commitGranularity; // 记录已提交

        // 初始化空闲链表
        memset(freeList, 0, sizeof(freeList));

        // 创建初始 4K 空闲块（不溢出16bit）
        StormFreeBlock* initialBlock = static_cast<StormFreeBlock*>(memoryStart);
        initialBlock->size = static_cast<WORD>(commitGranularity); // 4096，不会溢出
        initialBlock->alignPadding = 0;
        initialBlock->flags = 0x2; // 标记为空闲
        initialBlock->next = nullptr;

        // 添加到最大级别的空闲链表
        freeList[8] = initialBlock;

        // 设置名称
        if (heapName) {
            strncpy_s(name, heapName, sizeof(name) - 1);
        }
        else {
            sprintf_s(name, "SimHeap_%u", index);
        }
    }

// ========================================================
//  StormCompatibleAllocator   -- 私有成员
//  修正版：支持按需 Commit  +  大块直连 VirtualAlloc
// ========================================================

/*  辅助：确保堆里至少有 1 个 sizeNeeded 字节的空闲块
 *  若现有 freeList 不够，就按 4 KiB 步长 VirtualAlloc Commit，
 *  并把新页挂成一个空闲块塞进 freeList。
 *  返回 true = 已保证有块可用 / false = 无法再扩容
 */
    bool StormCompatibleAllocator::EnsureCommitted(SimulatedStormHeap* heap, size_t sizeNeeded)
    {
        // ——1. 先判断还能不能再提交
        if (heap->commitSize >= heap->totalSize)          // 已经全部 commit
            return false;
        size_t stillReserved = heap->totalSize - heap->commitSize;
        size_t commitBytes = heap->commitGranularity;
        while (commitBytes < sizeNeeded)                  // 至少满足本次 size
            commitBytes += heap->commitGranularity;
        if (commitBytes > stillReserved)                  // 不要越界
            commitBytes = stillReserved;

        // ——2. 提交物理页
        void* commitBase = static_cast<char*>(heap->memoryStart) + heap->commitSize;
        if (!VirtualAlloc(commitBase, commitBytes, MEM_COMMIT, PAGE_READWRITE))
            return false;

        // ——3. 生成一个新的空闲块并挂到 freeList
        StormFreeBlock* newBlk = static_cast<StormFreeBlock*>(commitBase);
        newBlk->size = static_cast<WORD>(commitBytes);   // ★ 仍保持 WORD；单页最大 64 KiB
        newBlk->alignPadding = 0;
        newBlk->flags = 0x2;                              // 空闲
        newBlk->next = nullptr;
        AddToFreeList(heap, newBlk);

        heap->commitSize += commitBytes;
        return true;
    }


    SimulatedStormHeap::~SimulatedStormHeap() {
        if (memoryStart) {
            VirtualFree(memoryStart, 0, MEM_RELEASE);
        }
    }

    // StormCompatibleAllocator 实现
    StormCompatibleAllocator::StormCompatibleAllocator() {
        // 初始化临界区
        for (size_t i = 0; i < MAX_HEAPS; i++) {
            InitializeCriticalSection(&criticalSections_[i]);
        }
    }

    StormCompatibleAllocator::~StormCompatibleAllocator() {
        Shutdown();

        // 清理临界区
        for (size_t i = 0; i < MAX_HEAPS; i++) {
            DeleteCriticalSection(&criticalSections_[i]);
        }
    }

    StormCompatibleAllocator& StormCompatibleAllocator::GetInstance() {
        static StormCompatibleAllocator instance;
        return instance;
    }

    bool StormCompatibleAllocator::Initialize() {
        if (initialized_.exchange(true)) {
            return true; // 已经初始化
        }

        // 初始化堆表
        for (auto& heap : heapTable_) {
            heap.reset();
        }

        printf("[StormCompatible] 初始化完成\n");
        return true;
    }

    void StormCompatibleAllocator::Shutdown() {
        if (!initialized_.exchange(false)) {
            return; // 未初始化
        }

        std::lock_guard<std::mutex> lock(heapTableMutex_);

        // 清理所有堆
        for (auto& heap : heapTable_) {
            heap.reset();
        }

        printf("[StormCompatible] 关闭完成\n");
    }

    void* StormCompatibleAllocator::AllocateCompatible(size_t size, const char* name, DWORD srcLine, DWORD flags) {
        if (size == 0) return nullptr;
        if (size > 0x7FFFFFFF) return nullptr; // Storm的大小限制

        // 计算堆索引
        BYTE heapIndex = ComputeHeapIndex(name, srcLine);

        // 获取或创建堆
        SimulatedStormHeap* heap = GetOrCreateHeap(heapIndex, name);
        if (!heap) return nullptr;

        // 进入临界区
        EnterCriticalSection(&criticalSections_[heapIndex]);

        void* result = nullptr;
        __try {
            result = AllocateFromHeap(heap, size, flags);
        }
        __finally {
            LeaveCriticalSection(&criticalSections_[heapIndex]);
        }

        if (result) {
            totalAllocated_.fetch_add(size);
            allocCount_.fetch_add(1);
        }

        return result;
    }

    bool StormCompatibleAllocator::FreeCompatible(void* userPtr) {
        if (!userPtr) return true;

        // 获取块头
        StormBlockHeader* header = StormBlockHeader::FromUserPtr(userPtr);
        if (!ValidateBlockHeader(header)) {
            return false; // 不是我们管理的内存
        }

        // 获取堆指针
        SimulatedStormHeap* heap = reinterpret_cast<SimulatedStormHeap*>(header->HeapPtr);

        // 验证堆的有效性
        if (!heap || !heap->ContainsPointer(header)) {
            return false;
        }

        // 计算堆索引
        BYTE heapIndex = static_cast<BYTE>(heap->heapIndex);

        // 进入临界区
        EnterCriticalSection(&criticalSections_[heapIndex]);

        bool result = false;
        __try {
            result = FreeToHeap(heap, header);
        }
        __finally {
            LeaveCriticalSection(&criticalSections_[heapIndex]);
        }

        if (result) {
            totalFreed_.fetch_add(header->Size);
            freeCount_.fetch_add(1);
        }

        return result;
    }

    void* StormCompatibleAllocator::ReallocateCompatible(void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags) {
        if (!oldPtr) {
            return AllocateCompatible(newSize, name, srcLine, flags);
        }

        if (newSize == 0) {
            FreeCompatible(oldPtr);
            return nullptr;
        }

        // 获取旧块头
        StormBlockHeader* oldHeader = StormBlockHeader::FromUserPtr(oldPtr);
        if (!ValidateBlockHeader(oldHeader)) {
            return nullptr; // 不是我们管理的内存
        }

        size_t oldSize = oldHeader->Size;

        // 如果新大小不超过原大小的1.5倍且在同一个级别，就地调整
        if (newSize <= oldSize && newSize >= oldSize / 2) {
            oldHeader->Size = static_cast<DWORD>(newSize);
            return oldPtr;
        }

        // 分配新内存
        void* newPtr = AllocateCompatible(newSize, name, srcLine, flags);
        if (!newPtr) {
            return nullptr;
        }

        // 复制数据
        size_t copySize = (oldSize < newSize) ? oldSize : newSize;
        memcpy(newPtr, oldPtr, copySize);

        // 释放旧内存
        FreeCompatible(oldPtr);

        return newPtr;
    }

    bool StormCompatibleAllocator::IsOurPointer(void* ptr) {
        if (!ptr) return false;

        StormBlockHeader* header = StormBlockHeader::FromUserPtr(ptr);
        return ValidateBlockHeader(header);
    }

    void StormCompatibleAllocator::GetStatistics(size_t& allocated, size_t& freed, size_t& allocCount, size_t& freeCount) const {
        allocated = totalAllocated_.load();
        freed = totalFreed_.load();
        allocCount = allocCount_.load();
        freeCount = freeCount_.load();
    }

    // 私有方法实现
    SimulatedStormHeap* StormCompatibleAllocator::GetOrCreateHeap(BYTE heapIndex, const char* name) {
        // 快速路径：如果堆已存在
        if (heapTable_[heapIndex]) {
            return heapTable_[heapIndex].get();
        }

        // 慢速路径：需要创建新堆
        std::lock_guard<std::mutex> lock(heapTableMutex_);

        // 双重检查
        if (heapTable_[heapIndex]) {
            return heapTable_[heapIndex].get();
        }

        // 创建新堆
        try {
            heapTable_[heapIndex] = std::make_unique<SimulatedStormHeap>(heapIndex, name);
            return heapTable_[heapIndex].get();
        }
        catch (const std::exception& e) {
            printf("[StormCompatible] 创建堆失败: %s\n", e.what());
            return nullptr;
        }
    }

    BYTE StormCompatibleAllocator::ComputeHeapIndex(const char* name, DWORD srcLine) {
        uint32_t hash = ComputeStormHash(name, false, srcLine);
        return static_cast<BYTE>(hash & 0xFF);
    }

    /*  真·分配函数：支持
     *     ① ≤ 0xFE7B：从 freeList 走普通路径（找不到 ⇒ EnsureCommitted ⇒ 再找）
     *     ②  > 0xFE7B：仿 Storm “大块”路径 -- 直接 VirtualAlloc 4 KiB 对齐并打 FLAG_BIG(0x4)
     */
    void* StormCompatibleAllocator::AllocateFromHeap(SimulatedStormHeap* heap,
        size_t userSize,
        DWORD  flags)
    {
        // ——0. Storm 规则：>=0xFE7C 走 big-block
        const size_t BIG_THRESHOLD = 0xFE7C;
        if (userSize >= BIG_THRESHOLD)
        {
            size_t total = userSize + sizeof(StormBlockHeader) + 16;   // enough for align + magic
            total = (total + heap->commitGranularity - 1) & ~(heap->commitGranularity - 1);

            void* bigMem = VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!bigMem) return nullptr;

            StormBlockHeader* h = static_cast<StormBlockHeader*>(bigMem);
            SetupBlockHeader(h, heap, userSize, flags | 0x4);          // 0x4 == BIG
            h->Magic = 0x6F6D;

            heap->bigBlockSize += static_cast<DWORD>(userSize);
            return h->GetUserData();
        }

        // ——1. 普通块：计算含头部/补齐后的 totalSize
        size_t totalSize = sizeof(StormBlockHeader) + userSize;
        if (flags & 0x1) totalSize += 2;               // 边界魔数
        totalSize = (totalSize + 7) & ~static_cast<size_t>(7);   // 8-byte 对齐

        // ——2. 查找空闲块
        StormFreeBlock* block = FindFreeBlock(heap, totalSize);
        if (!block)
        {
            // 试着 commit 新页再找
            if (!EnsureCommitted(heap, totalSize) ||
                !(block = FindFreeBlock(heap, totalSize)))
                return nullptr;                        // 扩容失败
        }

        // ——3. 从 freeList 拿掉
        RemoveFromFreeList(heap, block);

        // ——4. 如果剩余足够大，再拆分出一个新的 free 块
        size_t remainder = block->size - totalSize;
        if (remainder >= sizeof(StormFreeBlock) + 16)
        {
            StormFreeBlock* newFree = reinterpret_cast<StormFreeBlock*>(
                reinterpret_cast<char*>(block) + totalSize);
            newFree->size = static_cast<WORD>(remainder);
            newFree->alignPadding = 0;
            newFree->flags = 0x2;
            newFree->next = nullptr;
            AddToFreeList(heap, newFree);

            block->size = static_cast<WORD>(totalSize);
        }

        // ——5. 写块头
        StormBlockHeader* hdr = reinterpret_cast<StormBlockHeader*>(block);
        SetupBlockHeader(hdr, heap, userSize, flags);

        // ——6. 统计
        heap->allocCount++;
        heap->allocSize += static_cast<DWORD>(userSize);

        if (flags & 0x8)           // Storm 的“清零标志”
            memset(hdr->GetUserData(), 0, userSize);

        return hdr->GetUserData();
    }

    bool StormCompatibleAllocator::FreeToHeap(SimulatedStormHeap* heap, StormBlockHeader* header) {
        // 验证块头
        if (header->IsFree()) {
            return false; // 双重释放
        }

        size_t userSize = header->Size;

        // 转换为空闲块
        StormFreeBlock* freeBlock = reinterpret_cast<StormFreeBlock*>(header);
        freeBlock->size = static_cast<WORD>(sizeof(StormBlockHeader) + userSize);
        freeBlock->alignPadding = header->AlignPadding;
        freeBlock->flags = 0x2; // 空闲标志
        freeBlock->next = nullptr;

        // 处理边界检查
        if (header->HasBoundaryCheck()) {
            freeBlock->size += 2;
        }

        // 8字节对齐
        freeBlock->size = (freeBlock->size + 7) & ~7;

        // 尝试合并相邻块
        CoalesceBlocks(heap, freeBlock);

        // 添加到空闲链表
        AddToFreeList(heap, freeBlock);

        // 更新堆统计
        heap->freeCount++;
        heap->allocSize -= static_cast<DWORD>(userSize);
        heap->allocCount--;

        return true;
    }

    StormFreeBlock* StormCompatibleAllocator::FindFreeBlock(SimulatedStormHeap* heap, size_t requiredSize) {
        // 从合适的级别开始查找
        int startLevel = heap->GetFreeListIndex(requiredSize);

        for (int level = startLevel; level < 9; level++) {
            StormFreeBlock* block = static_cast<StormFreeBlock*>(heap->freeList[level]);

            while (block) {
                if (block->size >= requiredSize) {
                    return block;
                }
                block = block->next;
            }
        }

        return nullptr;
    }

    void StormCompatibleAllocator::AddToFreeList(SimulatedStormHeap* heap, StormFreeBlock* block) {
        int level = heap->GetFreeListIndex(block->size);

        // 插入到链表头部
        block->next = static_cast<StormFreeBlock*>(heap->freeList[level]);
        heap->freeList[level] = block;
    }

    void StormCompatibleAllocator::RemoveFromFreeList(SimulatedStormHeap* heap, StormFreeBlock* targetBlock) {
        int level = heap->GetFreeListIndex(targetBlock->size);

        StormFreeBlock* block = static_cast<StormFreeBlock*>(heap->freeList[level]);
        StormFreeBlock* prev = nullptr;

        while (block) {
            if (block == targetBlock) {
                if (prev) {
                    prev->next = block->next;
                }
                else {
                    heap->freeList[level] = block->next;
                }
                return;
            }
            prev = block;
            block = block->next;
        }
    }

    void StormCompatibleAllocator::SetupBlockHeader(StormBlockHeader* header, SimulatedStormHeap* heap, size_t userSize, DWORD flags) {
        header->HeapPtr = reinterpret_cast<DWORD>(heap);
        header->Size = static_cast<DWORD>(userSize);
        header->AlignPadding = 0;
        header->Flags = static_cast<BYTE>(flags & 0xFF);
        header->Magic = 0x6F6D;

        // 设置边界检查魔数
        if (flags & 0x1) {
            WORD* boundaryMagic = header->GetBoundaryMagic();
            if (boundaryMagic) {
                *boundaryMagic = static_cast<WORD>(BOUNDARY_MAGIC);
            }
        }
    }

    bool StormCompatibleAllocator::ValidateBlockHeader(const StormBlockHeader* header) {
        if (!header) return false;

        __try {
            // 检查魔数
            if (header->Magic != 0x6F6D) return false;

            // 检查大小合理性
            if (header->Size == 0 || header->Size > 0x10000000) return false;

            // 检查堆指针
            SimulatedStormHeap* heap = reinterpret_cast<SimulatedStormHeap*>(header->HeapPtr);
            if (!heap) return false;

            // 检查是否在堆范围内
            if (!heap->ContainsPointer(const_cast<StormBlockHeader*>(header))) return false;

            // 检查边界魔数
            if (header->HasBoundaryCheck()) {
                const WORD* boundaryMagic = const_cast<StormBlockHeader*>(header)->GetBoundaryMagic();
                if (boundaryMagic && *boundaryMagic != BOUNDARY_MAGIC) return false;
            }

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    void StormCompatibleAllocator::CoalesceBlocks(SimulatedStormHeap* heap, StormFreeBlock* block) {
        // 尝试与后续块合并
        char* blockEnd = reinterpret_cast<char*>(block) + block->size;

        if (blockEnd < heap->memoryEnd) {
            StormFreeBlock* nextBlock = reinterpret_cast<StormFreeBlock*>(blockEnd);

            // 检查下一个块是否是空闲的
            if (nextBlock->IsFree() &&
                reinterpret_cast<char*>(nextBlock) + nextBlock->size <= heap->memoryEnd) {

                // 从空闲链表中移除下一个块
                RemoveFromFreeList(heap, nextBlock);

                // 合并
                block->size += nextBlock->size;
            }
        }

        // 注意：向前合并需要更复杂的算法，这里简化处理
    }

    uint32_t StormCompatibleAllocator::ComputeStormHash(const char* name, bool caseSensitive, DWORD seed) {
        // 模拟Storm_502函数的哈希算法
        uint32_t hash = seed ? seed : 2146271213;
        uint32_t hash2 = static_cast<uint32_t>(-286331154);

        if (name) {
            const char* p = name;
            while (*p) {
                uint8_t c = static_cast<uint8_t>(*p);

                if (!caseSensitive) {
                    if (c >= 'a' && c <= 'z') c -= 32; // 转大写
                    if (c == '/') c = '\\'; // 路径分隔符标准化
                }

                // Storm的哈希算法
                hash ^= (hash2 + hash);
                hash2 += c + 32 * hash2 + hash + 3;
                p++;
            }
        }

        if (hash == 0) hash = 1;
        return hash & 0x7FFFFFFF;
    }

} // namespace StormCompatible