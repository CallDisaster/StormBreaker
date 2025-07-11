#include "pch.h"
#include "MemorySafety.h"
#include <cstdio>
#include <cstdarg>
#include <psapi.h>
#include <algorithm>
#include <Log/LogSystem.h>

#pragma comment(lib, "psapi.lib")

// 单例实现
MemorySafety& MemorySafety::GetInstance() noexcept {
    static MemorySafety instance;
    return instance;
}

// 构造函数
MemorySafety::MemorySafety() noexcept
    : m_initialized(false)
    , m_shutdownRequested(false)
    , m_holdQueueHead(nullptr)
    , m_holdQueueTail(nullptr)
    , m_holdQueueCount(0)
    , m_holdTimeMs(500)           // 默认500ms缓冲
    , m_watermarkBytes(1400LL * 1024 * 1024)  // 默认1.4GB水位
    , m_maxCacheBytes(128LL * 1024 * 1024)    // 默认128MB缓存上限
    , m_totalAllocated(0)
    , m_totalFreed(0)
    , m_totalCached(0)
    , m_cacheHits(0)
    , m_cacheMisses(0)
    , m_forcedCleanups(0)
    , m_logFile(INVALID_HANDLE_VALUE)
{
    // 初始化关键段
    InitializeCriticalSection(&m_holdQueueLock);
    InitializeCriticalSection(&m_hashTableLock);
    InitializeCriticalSection(&m_logLock);

    // 清空哈希表
    memset(m_hashTable, 0, sizeof(m_hashTable));

    // 初始化大小分档
    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        SizeClass& sc = m_sizeClasses[i];
        sc.minSize = i * SIZE_CLASS_STEP;
        sc.maxSize = (i + 1) * SIZE_CLASS_STEP - 1;
        sc.alignedSize = (i + 1) * SIZE_CLASS_STEP;
        InitializeCriticalSection(&sc.lock);
        sc.freeList = nullptr;
        sc.freeCount = 0;
        // 大块缓存数量递减：64KB档缓存32个，1MB+档缓存2个
        sc.maxCacheCount = 32 / (i + 1);
        if (sc.maxCacheCount < 2) sc.maxCacheCount = 2;
    }
}

// 析构函数
MemorySafety::~MemorySafety() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }
}

// 初始化
bool MemorySafety::Initialize() noexcept {
    return SafeExecute([this]() -> bool {
        bool expected = false;
        if (!m_initialized.compare_exchange_strong(expected, true)) {
            return true; // 已经初始化
        }

        // 创建日志文件
        m_logFile = CreateFileA(
            "MemorySafety.log",
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        LogMessage("[MemorySafety] 初始化开始");
        LogMessage("[MemorySafety] 配置: 缓冲时间=%ums, 水位=%zuMB, 最大缓存=%zuMB",
            m_holdTimeMs.load(),
            m_watermarkBytes.load() / (1024 * 1024),
            m_maxCacheBytes.load() / (1024 * 1024));

        LogMessage("[MemorySafety] 初始化完成");
        return true;
        }, "Initialize");
}

// 关闭
void MemorySafety::Shutdown() noexcept {
    SafeExecute([this]() -> void {
        bool expected = true;
        if (!m_initialized.compare_exchange_strong(expected, false)) {
            return; // 已经关闭
        }

        m_shutdownRequested.store(true);
        LogMessage("[MemorySafety] 开始关闭");

        // 强制清空所有缓存
        DrainHoldQueue();

        // 释放所有大小分档的缓存
        for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
            SizeClass& sc = m_sizeClasses[i];
            EnterCriticalSection(&sc.lock);

            HoldQueueItem* item = sc.freeList;
            while (item) {
                HoldQueueItem* next = item->next;
                FreeToSystem(item);
                item = next;
            }
            sc.freeList = nullptr;
            sc.freeCount = 0;

            LeaveCriticalSection(&sc.lock);
            DeleteCriticalSection(&sc.lock);
        }

        // 打印统计信息
        PrintStatistics();

        // 关闭日志文件
        if (m_logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(m_logFile);
            m_logFile = INVALID_HANDLE_VALUE;
        }

        // 删除关键段
        DeleteCriticalSection(&m_holdQueueLock);
        DeleteCriticalSection(&m_hashTableLock);
        DeleteCriticalSection(&m_logLock);

        }, "Shutdown");
}

// 分配内存块
void* MemorySafety::AllocateBlock(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecute([this, size, sourceName, sourceLine]() -> void* {
        if (!m_initialized.load() || m_shutdownRequested.load()) {
            return nullptr;
        }

        BlockClass blockClass = GetBlockClass(size);

        // 小块直接返回nullptr，让调用者使用Storm原生分配
        if (blockClass == BlockClass::Small) {
            return nullptr;
        }

        // 先尝试从缓存获取
        void* cached = AllocateFromCache(size, sourceName, sourceLine);
        if (cached) {
            m_cacheHits.fetch_add(1);
            LogMessage("[MemorySafety] 缓存命中: ptr=%p, size=%zu, source=%s:%u",
                cached, size, sourceName ? sourceName : "null", sourceLine);
            return cached;
        }

        // 缓存未命中，从系统分配
        m_cacheMisses.fetch_add(1);
        void* allocated = AllocateFromSystem(size, sourceName, sourceLine);
        if (allocated) {
            LogMessage("[MemorySafety] 系统分配: ptr=%p, size=%zu, source=%s:%u",
                allocated, size, sourceName ? sourceName : "null", sourceLine);
        }

        return allocated;
        }, "AllocateBlock");
}

// 释放内存块
bool MemorySafety::FreeBlock(void* userPtr) noexcept {
    return SafeExecute([this, userPtr]() -> bool {
        if (!userPtr || !m_initialized.load()) {
            return false;
        }

        // 验证是否是我们的块
        if (!IsOurBlock(userPtr)) {
            return false;
        }

        // 从哈希表查找块信息
        HoldQueueItem* item = FindHashEntry(userPtr);
        if (!item) {
            LogMessage("[MemorySafety] 警告: 释放未找到的块 %p", userPtr);
            return false;
        }

        // 从哈希表移除
        RemoveHashEntry(userPtr);

        // 更新统计
        m_totalFreed.fetch_add(item->size);

        LogMessage("[MemorySafety] 释放请求: ptr=%p, size=%zu", userPtr, item->size);

        // 判断是否立即释放还是缓存
        if (m_shutdownRequested.load() || IsMemoryPressureHigh()) {
            // 关闭状态或内存压力高，立即释放
            FreeToSystem(item);
            LogMessage("[MemorySafety] 立即释放: ptr=%p", userPtr);
        }
        else {
            // 正常情况，加入缓冲队列
            EnqueueToHold(item);
            LogMessage("[MemorySafety] 加入缓冲队列: ptr=%p", userPtr);
        }

        return true;
        }, "FreeBlock");
}

// 重新分配内存块
void* MemorySafety::ReallocateBlock(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecute([this, oldPtr, newSize, sourceName, sourceLine]() -> void* {
        if (!oldPtr) {
            return AllocateBlock(newSize, sourceName, sourceLine);
        }

        if (newSize == 0) {
            FreeBlock(oldPtr);
            return nullptr;
        }

        // 检查是否是我们的块
        if (!IsOurBlock(oldPtr)) {
            return nullptr; // 不是我们的块
        }

        size_t oldSize = GetBlockSize(oldPtr);
        if (oldSize == 0) {
            LogMessage("[MemorySafety] 警告: 无法获取旧块大小 %p", oldPtr);
            return nullptr;
        }

        // 如果新大小相近，直接返回原指针
        if (newSize <= oldSize && newSize > oldSize * 3 / 4) {
            LogMessage("[MemorySafety] 重分配优化: ptr=%p, %zu->%zu", oldPtr, oldSize, newSize);
            return oldPtr;
        }

        // 分配新块
        void* newPtr = AllocateBlock(newSize, sourceName, sourceLine);
        if (!newPtr) {
            LogMessage("[MemorySafety] 重分配失败: size=%zu", newSize);
            return nullptr;
        }

        // 复制数据
        size_t copySize = (newSize < oldSize) ? newSize : oldSize;
        __try {
            memcpy(newPtr, oldPtr, copySize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[MemorySafety] 重分配复制异常: old=%p, new=%p, size=%zu",
                oldPtr, newPtr, copySize);
            FreeBlock(newPtr);
            return nullptr;
        }

        // 释放旧块
        FreeBlock(oldPtr);

        LogMessage("[MemorySafety] 重分配成功: %p->%p, %zu->%zu",
            oldPtr, newPtr, oldSize, newSize);
        return newPtr;

        }, "ReallocateBlock");
}

// 检查是否是我们的块
bool MemorySafety::IsOurBlock(void* userPtr) const noexcept {
    return SafeExecute([this, userPtr]() -> bool {
        if (!userPtr || !m_initialized.load()) {
            return false;
        }

        return ValidateStormHeader(userPtr);
        }, "IsOurBlock");
}

// 获取块大小
size_t MemorySafety::GetBlockSize(void* userPtr) const noexcept {
    return SafeExecute([this, userPtr]() -> size_t {
        if (!userPtr || !ValidateStormHeader(userPtr)) {
            return 0;
        }

        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        return header->size;
        }, "GetBlockSize");
}

// 获取块分类
BlockClass MemorySafety::GetBlockClass(size_t size) const noexcept {
    if (size < 64 * 1024) {
        return BlockClass::Small;
    }
    else if (size < 4 * 1024 * 1024) {
        return BlockClass::Large;
    }
    else {
        return BlockClass::Huge;
    }
}

// 检查内存压力
void MemorySafety::CheckMemoryPressure() noexcept {
    SafeExecute([this]() -> void {
        size_t currentVirtual = GetCurrentVirtualMemory();
        size_t watermark = m_watermarkBytes.load();

        if (currentVirtual > watermark) {
            LogMessage("[MemorySafety] 内存压力检测: 当前=%zuMB, 水位=%zuMB",
                currentVirtual / (1024 * 1024), watermark / (1024 * 1024));
            ForceCleanup();
        }
        }, "CheckMemoryPressure");
}

// 强制清理
void MemorySafety::ForceCleanup() noexcept {
    SafeExecute([this]() -> void {
        LogMessage("[MemorySafety] 开始强制清理");

        m_forcedCleanups.fetch_add(1);

        // 清空缓冲队列
        DrainHoldQueue();

        // 清理各大小档的缓存
        for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
            SizeClass& sc = m_sizeClasses[i];
            EnterCriticalSection(&sc.lock);

            size_t cleaned = 0;
            HoldQueueItem* item = sc.freeList;
            while (item && cleaned < sc.freeCount / 2) { // 清理一半
                HoldQueueItem* next = item->next;
                FreeToSystem(item);
                cleaned++;
                item = next;
            }

            sc.freeList = item;
            sc.freeCount -= cleaned;

            LeaveCriticalSection(&sc.lock);

            if (cleaned > 0) {
                LogMessage("[MemorySafety] 清理大小档%zu: 释放%zu个块", i, cleaned);
            }
        }

        LogMessage("[MemorySafety] 强制清理完成");
        }, "ForceCleanup");
}

// 处理缓冲队列（定期调用）
void MemorySafety::ProcessHoldQueue() noexcept {
    SafeExecute([this]() -> void {
        if (!m_initialized.load() || m_shutdownRequested.load()) {
            return;
        }

        DWORD currentTime = GetTickCount();
        DWORD holdTime = m_holdTimeMs.load();
        size_t processed = 0;

        EnterCriticalSection(&m_holdQueueLock);

        HoldQueueItem* current = m_holdQueueHead;
        HoldQueueItem* prev = nullptr;

        while (current) {
            if (currentTime - current->timestamp >= holdTime) {
                // 超时，从队列移除
                if (prev) {
                    prev->next = current->next;
                }
                else {
                    m_holdQueueHead = current->next;
                }

                if (current == m_holdQueueTail) {
                    m_holdQueueTail = prev;
                }

                HoldQueueItem* toProcess = current;
                current = current->next;

                m_holdQueueCount.fetch_sub(1);

                LeaveCriticalSection(&m_holdQueueLock);

                // 尝试放入缓存或直接释放
                FreeToCache(toProcess);
                processed++;

                EnterCriticalSection(&m_holdQueueLock);
            }
            else {
                prev = current;
                current = current->next;
            }
        }

        LeaveCriticalSection(&m_holdQueueLock);

        if (processed > 0) {
            LogMessage("[MemorySafety] 处理缓冲队列: 处理%zu个块", processed);
        }
        }, "ProcessHoldQueue");
}

// 清空缓冲队列
void MemorySafety::DrainHoldQueue() noexcept {
    SafeExecute([this]() -> void {
        LogMessage("[MemorySafety] 开始清空缓冲队列");

        EnterCriticalSection(&m_holdQueueLock);

        size_t drained = 0;
        HoldQueueItem* current = m_holdQueueHead;

        m_holdQueueHead = nullptr;
        m_holdQueueTail = nullptr;
        m_holdQueueCount.store(0);

        LeaveCriticalSection(&m_holdQueueLock);

        // 释放所有项目
        while (current) {
            HoldQueueItem* next = current->next;
            FreeToSystem(current);
            drained++;
            current = next;
        }

        LogMessage("[MemorySafety] 清空缓冲队列完成: 释放%zu个块", drained);
        }, "DrainHoldQueue");
}

// 从系统分配
void* MemorySafety::AllocateFromSystem(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    // 计算实际需要的大小（包含Storm头部和对齐）
    size_t headerSize = sizeof(StormAllocHeader);
    size_t alignedSize = GetAlignedSize(size);
    size_t realSize = headerSize + alignedSize;

    // 如果需要尾部魔数，再加2字节
    bool needTailMagic = (alignedSize >= 1024); // 大块使用尾部校验
    if (needTailMagic) {
        realSize += 2;
    }

    // 页对齐
    realSize = GetAlignedSize(realSize, 4096);

    // VirtualAlloc分配
    void* rawPtr = VirtualAlloc(nullptr, realSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[MemorySafety] VirtualAlloc失败: size=%zu", realSize);
        return nullptr;
    }

    // 计算用户指针
    void* userPtr = static_cast<char*>(rawPtr) + headerSize;

    // 设置Storm兼容头部
    SetupStormHeader(userPtr, size);

    // 创建跟踪项并加入哈希表
    HoldQueueItem* item = CreateHoldItem(rawPtr, userPtr, size, realSize,
        sourceName, sourceLine, GetBlockClass(size));
    if (item) {
        InsertHashEntry(item);
    }

    // 更新统计
    m_totalAllocated.fetch_add(size);

    return userPtr;
}

// 从缓存分配
void* MemorySafety::AllocateFromCache(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    SizeClass* sc = GetSizeClass(size);
    if (!sc) {
        return nullptr;
    }

    EnterCriticalSection(&sc->lock);

    HoldQueueItem* item = sc->freeList;
    if (item && item->size >= size) {
        // 从缓存取出
        sc->freeList = item->next;
        sc->freeCount--;

        LeaveCriticalSection(&sc->lock);

        // 更新项目信息
        item->timestamp = GetTickCount();
        item->threadId = GetCurrentThreadId();

        // 释放旧的源信息并设置新的
        if (item->sourceName) {
            free(const_cast<char*>(item->sourceName));
        }
        item->sourceName = DuplicateString(sourceName);
        item->sourceLine = sourceLine;

        // 重新加入哈希表
        InsertHashEntry(item);

        // 清零用户区域
        memset(item->userPtr, 0, size);

        // 更新统计
        m_totalAllocated.fetch_add(size);
        m_totalCached.fetch_sub(item->size);

        return item->userPtr;
    }

    LeaveCriticalSection(&sc->lock);
    return nullptr;
}

// 释放到系统
void MemorySafety::FreeToSystem(HoldQueueItem* item) noexcept {
    if (!item) return;

    LogMessage("[MemorySafety] 释放到系统: ptr=%p, size=%zu", item->userPtr, item->size);

    // VirtualFree
    if (item->rawPtr) {
        VirtualFree(item->rawPtr, 0, MEM_RELEASE);
    }

    // 销毁跟踪项
    DestroyHoldItem(item);
}

// 释放到缓存
void MemorySafety::FreeToCache(HoldQueueItem* item) noexcept {
    if (!item) return;

    // 检查当前缓存大小
    if (m_totalCached.load() >= m_maxCacheBytes.load()) {
        FreeToSystem(item);
        return;
    }

    SizeClass* sc = GetSizeClass(item->size);
    if (!sc) {
        FreeToSystem(item);
        return;
    }

    EnterCriticalSection(&sc->lock);

    if (sc->freeCount >= sc->maxCacheCount) {
        // 缓存已满，释放到系统
        LeaveCriticalSection(&sc->lock);
        FreeToSystem(item);
        return;
    }

    // 加入缓存
    item->next = sc->freeList;
    sc->freeList = item;
    sc->freeCount++;

    LeaveCriticalSection(&sc->lock);

    // 更新统计
    m_totalCached.fetch_add(item->size);

    LogMessage("[MemorySafety] 释放到缓存: ptr=%p, size=%zu, 档次=%zu",
        item->userPtr, item->size, GetSizeClassIndex(item->size));
}

// 设置Storm兼容头部
void MemorySafety::SetupStormHeader(void* userPtr, size_t size) noexcept {
    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
        static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

    header->size = static_cast<WORD>(size & 0xFFFF);
    header->pad = 0;
    header->flags = 0x4; // 标记为大块VirtualAlloc
    header->heapPtr = STORM_SPECIAL_HEAP; // 我们的特殊标记
    header->frontMagic = STORM_FRONT_MAGIC;

    // 如果需要尾部魔数
    if (size >= 1024) {
        header->flags |= 0x1; // 设置尾部魔数标志
        WORD* tailMagic = reinterpret_cast<WORD*>(static_cast<char*>(userPtr) + size);
        *tailMagic = STORM_TAIL_MAGIC;
    }
}

// 验证Storm头部
bool MemorySafety::ValidateStormHeader(void* userPtr) const noexcept {
    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        // 检查前魔数
        if (header->frontMagic != STORM_FRONT_MAGIC) {
            return false;
        }

        // 检查特殊堆标记
        if (header->heapPtr != STORM_SPECIAL_HEAP) {
            return false;
        }

        // 检查尾部魔数（如果存在）
        if (header->flags & 0x1) {
            WORD* tailMagic = reinterpret_cast<WORD*>(
                static_cast<char*>(userPtr) + header->size);
            if (*tailMagic != STORM_TAIL_MAGIC) {
                return false;
            }
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 获取大小档索引
size_t MemorySafety::GetSizeClassIndex(size_t size) const noexcept {
    size_t index = (size + SIZE_CLASS_STEP - 1) / SIZE_CLASS_STEP - 1;
    if (index >= SIZE_CLASS_COUNT) {
        index = SIZE_CLASS_COUNT - 1;
    }
    return index;
}

// 获取大小档
SizeClass* MemorySafety::GetSizeClass(size_t size) noexcept {
    size_t index = GetSizeClassIndex(size);
    return &m_sizeClasses[index];
}

// 加入缓冲队列
void MemorySafety::EnqueueToHold(HoldQueueItem* item) noexcept {
    if (!item) return;

    item->timestamp = GetTickCount();
    item->next = nullptr;

    EnterCriticalSection(&m_holdQueueLock);

    if (m_holdQueueTail) {
        m_holdQueueTail->next = item;
        m_holdQueueTail = item;
    }
    else {
        m_holdQueueHead = m_holdQueueTail = item;
    }

    m_holdQueueCount.fetch_add(1);

    LeaveCriticalSection(&m_holdQueueLock);
}

// 从缓冲队列取出
HoldQueueItem* MemorySafety::DequeueFromHold() noexcept {
    EnterCriticalSection(&m_holdQueueLock);

    HoldQueueItem* item = m_holdQueueHead;
    if (item) {
        m_holdQueueHead = item->next;
        if (!m_holdQueueHead) {
            m_holdQueueTail = nullptr;
        }
        m_holdQueueCount.fetch_sub(1);
    }

    LeaveCriticalSection(&m_holdQueueLock);

    return item;
}

// 获取当前虚拟内存使用
size_t MemorySafety::GetCurrentVirtualMemory() const noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
        sizeof(pmc))) {
        return pmc.PrivateUsage;
    }
    return 0;
}

// 检查是否内存压力高
bool MemorySafety::IsMemoryPressureHigh() const noexcept {
    size_t current = GetCurrentVirtualMemory();
    size_t watermark = m_watermarkBytes.load();
    return current > watermark;
}

// 创建跟踪项
HoldQueueItem* MemorySafety::CreateHoldItem(void* rawPtr, void* userPtr, size_t size, size_t realSize,
    const char* sourceName, DWORD sourceLine, BlockClass blockClass) noexcept {
    HoldQueueItem* item = static_cast<HoldQueueItem*>(
        VirtualAlloc(nullptr, sizeof(HoldQueueItem), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!item) {
        return nullptr;
    }

    item->rawPtr = rawPtr;
    item->userPtr = userPtr;
    item->size = size;
    item->realSize = realSize;
    item->timestamp = GetTickCount();
    item->threadId = GetCurrentThreadId();
    item->blockClass = blockClass;
    item->sourceName = DuplicateString(sourceName);
    item->sourceLine = sourceLine;
    item->next = nullptr;

    return item;
}

// 销毁跟踪项
void MemorySafety::DestroyHoldItem(HoldQueueItem* item) noexcept {
    if (!item) return;

    if (item->sourceName) {
        free(const_cast<char*>(item->sourceName));
    }

    VirtualFree(item, 0, MEM_RELEASE);
}

// 复制字符串
char* MemorySafety::DuplicateString(const char* str) noexcept {
    if (!str) return nullptr;

    size_t len = strlen(str);
    char* copy = static_cast<char*>(malloc(len + 1));
    if (copy) {
        strcpy_s(copy, len + 1, str);
    }
    return copy;
}

// 哈希计算
size_t MemorySafety::CalculateHash(void* ptr) const noexcept {
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    return (addr >> 4) % HASH_TABLE_SIZE;
}

// 插入哈希表
void MemorySafety::InsertHashEntry(HoldQueueItem* item) noexcept {
    if (!item) return;

    size_t hash = CalculateHash(item->userPtr);

    EnterCriticalSection(&m_hashTableLock);

    item->next = m_hashTable[hash];
    m_hashTable[hash] = item;

    LeaveCriticalSection(&m_hashTableLock);
}

// 查找哈希表项
HoldQueueItem* MemorySafety::FindHashEntry(void* userPtr) const noexcept {
    size_t hash = CalculateHash(userPtr);

    EnterCriticalSection(&m_hashTableLock);

    HoldQueueItem* item = m_hashTable[hash];
    while (item) {
        if (item->userPtr == userPtr) {
            break;
        }
        item = item->next;
    }

    LeaveCriticalSection(&m_hashTableLock);

    return item;
}

// 从哈希表移除
void MemorySafety::RemoveHashEntry(void* userPtr) noexcept {
    size_t hash = CalculateHash(userPtr);

    EnterCriticalSection(&m_hashTableLock);

    HoldQueueItem** current = &m_hashTable[hash];
    while (*current) {
        if ((*current)->userPtr == userPtr) {
            *current = (*current)->next;
            break;
        }
        current = &((*current)->next);
    }

    LeaveCriticalSection(&m_hashTableLock);
}

// 打印统计信息
void MemorySafety::PrintStatistics() const noexcept {
    LogMessage("[MemorySafety] === 统计信息 ===");
    LogMessage("  总分配: %zu bytes", m_totalAllocated.load());
    LogMessage("  总释放: %zu bytes", m_totalFreed.load());
    LogMessage("  当前缓存: %zu bytes", m_totalCached.load());
    LogMessage("  缓存命中: %zu", m_cacheHits.load());
    LogMessage("  缓存未命中: %zu", m_cacheMisses.load());
    LogMessage("  强制清理次数: %zu", m_forcedCleanups.load());
    LogMessage("  缓冲队列大小: %zu", m_holdQueueCount.load());

    // 打印各大小档统计
    for (size_t i = 0; i < SIZE_CLASS_COUNT; ++i) {
        const SizeClass& sc = m_sizeClasses[i];
        if (sc.freeCount > 0) {
            LogMessage("  大小档%zu (%zuKB): %zu个缓存块",
                i, sc.alignedSize / 1024, sc.freeCount);
        }
    }

    size_t currentVM = GetCurrentVirtualMemory();
    LogMessage("  当前虚拟内存: %zu MB", currentVM / (1024 * 1024));
    LogMessage("  内存水位设置: %zu MB", m_watermarkBytes.load() / (1024 * 1024));
    LogMessage("========================");
}

// 获取统计数据
size_t MemorySafety::GetTotalAllocated() const noexcept {
    return m_totalAllocated.load();
}

size_t MemorySafety::GetTotalCached() const noexcept {
    return m_totalCached.load();
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    return m_holdQueueCount.load();
}

// 安全执行包装模板特化
template<typename Func>
auto MemorySafety::SafeExecute(Func&& func, const char* operation) noexcept -> decltype(func()) {
    __try {
        return func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessage("[MemorySafety] 异常在操作 %s: 0x%08X",
            operation, GetExceptionCode());

        // 返回类型的默认值
        using ReturnType = decltype(func());
        if constexpr (std::is_pointer_v<ReturnType>) {
            return nullptr;
        }
        else if constexpr (std::is_same_v<ReturnType, bool>) {
            return false;
        }
        else if constexpr (std::is_arithmetic_v<ReturnType>) {
            return static_cast<ReturnType>(0);
        }
        else {
            return ReturnType{};
        }
    }
}

// 工具函数实现
bool IsValidMemoryRange(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return false;

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            return false;
        }

        return (mbi.State & MEM_COMMIT) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

size_t GetAlignedSize(size_t size, size_t alignment) noexcept {
    return (size + alignment - 1) & ~(alignment - 1);
}

const char* GetBlockClassName(BlockClass blockClass) noexcept {
    switch (blockClass) {
    case BlockClass::Small: return "Small";
    case BlockClass::Large: return "Large";
    case BlockClass::Huge: return "Huge";
    default: return "Unknown";
    }
}