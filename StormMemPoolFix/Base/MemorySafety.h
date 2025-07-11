#pragma once

#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstddef>

// 前向声明避免包含复杂头文件
struct StormBlockInfo;
class HoldQueue;
class SizeClassManager;
class MemoryWatermark;

// Storm内存块头部结构（基于逆向文档）
#pragma pack(push, 1)
struct StormAllocHeader {
    WORD size;          // 块大小
    BYTE pad;           // 对齐填充 = 0
    BYTE flags;         // 标志位
    DWORD heapPtr;      // 堆指针
    WORD frontMagic;    // 前魔数 0x6F6D
    // 用户数据从这里开始
    // 如果 flags & 1，则在用户数据末尾还有 WORD tailMagic = 0x12B1
};
#pragma pack(pop)

// Storm魔数常量
static constexpr WORD STORM_FRONT_MAGIC = 0x6F6D;
static constexpr WORD STORM_TAIL_MAGIC = 0x12B1;
static constexpr DWORD STORM_SPECIAL_HEAP = 0xC0DEFEED; // 我们的特殊标记

// 内存块分类
enum class BlockClass {
    Small,      // < 64KB，使用Storm原生
    Large,      // >= 64KB，使用增强管理  
    Huge        // >= 4MB，特殊处理
};

// 缓冲队列中的块信息
struct HoldQueueItem {
    void* rawPtr;           // 实际VirtualAlloc的地址
    void* userPtr;          // 用户使用的地址
    size_t size;            // 用户请求的大小
    size_t realSize;        // 实际分配的大小
    DWORD timestamp;        // 入队时间
    DWORD threadId;         // 分配线程ID
    BlockClass blockClass;  // 块分类
    const char* sourceName; // 分配来源（拷贝）
    DWORD sourceLine;       // 源代码行
    HoldQueueItem* next;    // 链表指针
};

// 大小分档管理器的档次定义
struct SizeClass {
    size_t minSize;         // 最小尺寸
    size_t maxSize;         // 最大尺寸
    size_t alignedSize;     // 对齐后的标准尺寸
    CRITICAL_SECTION lock; // 该档次的锁
    HoldQueueItem* freeList; // 空闲块链表
    size_t freeCount;       // 空闲块数量
    size_t maxCacheCount;   // 最大缓存数量
};

// 内存安全管理器 - 单例模式
class MemorySafety {
public:
    // 获取单例实例
    static MemorySafety& GetInstance() noexcept;

    // 生命周期管理
    bool Initialize() noexcept;
    void Shutdown() noexcept;

    // 主要内存操作接口
    void* AllocateBlock(size_t size, const char* sourceName, DWORD sourceLine) noexcept;
    bool FreeBlock(void* userPtr) noexcept;
    void* ReallocateBlock(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept;

    // 块验证和查询
    bool IsOurBlock(void* userPtr) const noexcept;
    size_t GetBlockSize(void* userPtr) const noexcept;
    BlockClass GetBlockClass(size_t size) const noexcept;

    // 内存压力管理
    void CheckMemoryPressure() noexcept;
    void ForceCleanup() noexcept;

    // 缓冲队列管理
    void ProcessHoldQueue() noexcept;
    void DrainHoldQueue() noexcept;

    // 统计信息
    void PrintStatistics() const noexcept;
    size_t GetTotalAllocated() const noexcept;
    size_t GetTotalCached() const noexcept;
    size_t GetHoldQueueSize() const noexcept;

    // 配置接口
    void SetHoldTimeMs(DWORD timeMs) noexcept { m_holdTimeMs = timeMs; }
    void SetWatermarkMB(size_t watermarkMB) noexcept { m_watermarkBytes = watermarkMB * 1024 * 1024; }
    void SetMaxCacheSize(size_t maxMB) noexcept { m_maxCacheBytes = maxMB * 1024 * 1024; }

private:
    MemorySafety() noexcept;
    ~MemorySafety() noexcept;

    // 禁止拷贝
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;

    // 内部分配实现
    void* AllocateFromSystem(size_t size, const char* sourceName, DWORD sourceLine) noexcept;
    void* AllocateFromCache(size_t size, const char* sourceName, DWORD sourceLine) noexcept;

    // 内部释放实现  
    void FreeToSystem(HoldQueueItem* item) noexcept;
    void FreeToCache(HoldQueueItem* item) noexcept;

    // Storm兼容性
    void SetupStormHeader(void* userPtr, size_t size) noexcept;
    bool ValidateStormHeader(void* userPtr) const noexcept;

    // 大小分档管理
    size_t GetSizeClassIndex(size_t size) const noexcept;
    SizeClass* GetSizeClass(size_t size) noexcept;

    // 缓冲队列操作
    void EnqueueToHold(HoldQueueItem* item) noexcept;
    HoldQueueItem* DequeueFromHold() noexcept;

    // 内存监控
    size_t GetCurrentVirtualMemory() const noexcept;
    bool IsMemoryPressureHigh() const noexcept;

    // 线程安全的操作包装
    template<typename Func>
    auto SafeExecute(Func&& func, const char* operation) noexcept -> decltype(func());

    // 工具函数
    HoldQueueItem* CreateHoldItem(void* rawPtr, void* userPtr, size_t size, size_t realSize,
        const char* sourceName, DWORD sourceLine, BlockClass blockClass) noexcept;
    void DestroyHoldItem(HoldQueueItem* item) noexcept;
    char* DuplicateString(const char* str) noexcept;

private:
    // 初始化状态
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_shutdownRequested;

    // 缓冲队列
    CRITICAL_SECTION m_holdQueueLock;
    HoldQueueItem* m_holdQueueHead;
    HoldQueueItem* m_holdQueueTail;
    std::atomic<size_t> m_holdQueueCount;

    // 大小分档缓存 (64KB一档，共16档：64KB, 128KB, 192KB, ..., 1MB+)
    static constexpr size_t SIZE_CLASS_COUNT = 16;
    static constexpr size_t SIZE_CLASS_STEP = 64 * 1024;  // 64KB
    SizeClass m_sizeClasses[SIZE_CLASS_COUNT];

    // 块追踪表（简化的哈希表）
    static constexpr size_t HASH_TABLE_SIZE = 4096;
    CRITICAL_SECTION m_hashTableLock;
    HoldQueueItem* m_hashTable[HASH_TABLE_SIZE];

    // 配置参数
    std::atomic<DWORD> m_holdTimeMs;        // 缓冲时间，默认500ms
    std::atomic<size_t> m_watermarkBytes;   // 内存水位，默认1.4GB  
    std::atomic<size_t> m_maxCacheBytes;    // 最大缓存，默认128MB

    // 统计信息
    std::atomic<size_t> m_totalAllocated;
    std::atomic<size_t> m_totalFreed;
    std::atomic<size_t> m_totalCached;
    std::atomic<size_t> m_cacheHits;
    std::atomic<size_t> m_cacheMisses;
    std::atomic<size_t> m_forcedCleanups;

    // 日志文件
    HANDLE m_logFile;
    CRITICAL_SECTION m_logLock;

    // 内部辅助函数声明
    size_t CalculateHash(void* ptr) const noexcept;
    void InsertHashEntry(HoldQueueItem* item) noexcept;
    HoldQueueItem* FindHashEntry(void* userPtr) const noexcept;
    void RemoveHashEntry(void* userPtr) noexcept;
};

// 全局访问宏
#define g_MemorySafety MemorySafety::GetInstance()

// 工具函数
bool IsValidMemoryRange(void* ptr, size_t size) noexcept;
size_t GetAlignedSize(size_t size, size_t alignment = 16) noexcept;
const char* GetBlockClassName(BlockClass blockClass) noexcept;