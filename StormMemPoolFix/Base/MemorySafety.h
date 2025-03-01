#pragma once

#include <Windows.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <string>
#include <cstdint>

// 安全临界区（避免RAII模式）
class SafeCriticalSection {
private:
    CRITICAL_SECTION m_cs;
    bool m_isLocked;

public:
#pragma warning(push)
#pragma warning(disable: 26135) // 禁用RAII相关警告

    SafeCriticalSection() noexcept {
        InitializeCriticalSection(&m_cs);
        m_isLocked = false;
    }

    ~SafeCriticalSection() noexcept {
        if (m_isLocked) {
            LeaveCriticalSection(&m_cs);
        }
        DeleteCriticalSection(&m_cs);
    }

    void Enter() noexcept {
        EnterCriticalSection(&m_cs);
        m_isLocked = true;
    }

    void Leave() noexcept {
        if (m_isLocked) {
            LeaveCriticalSection(&m_cs);
            m_isLocked = false;
        }
    }
#pragma warning(pop)
};

// 内存块跟踪信息
struct MemoryTraceInfo {
    void* rawPointer;      // 原始分配地址
    void* userPointer;     // 用户获得的地址
    size_t size;           // 分配大小
    DWORD timestamp;       // 分配时间
    DWORD threadId;        // 分配线程ID
    char sourceFile[64];   // 分配源文件
    int sourceLine;        // 分配行号
    bool isValid;          // 内存块是否有效
    uint32_t checksum;     // 内存块校验和
};

// 延迟释放队列项目
struct DeferredFreeItem {
    void* pointer;         // 要释放的指针
    DWORD queueTime;       // 入队时间
    size_t size;           // 内存块大小
    bool processed;        // 是否已处理
};

class MemorySafety {
public:
    static MemorySafety& GetInstance() noexcept;

    // 基础管理接口
    bool Initialize() noexcept;
    void Shutdown() noexcept;

    // 内存管理操作
    bool TryRegisterBlock(void* rawPtr, void* userPtr, size_t size,
        const char* sourceFile, int sourceLine) noexcept;
    bool TryUnregisterBlock(void* userPtr) noexcept;
    bool ValidateMemoryBlock(void* ptr) noexcept;
    bool SafeMemoryCopy(void* dest, const void* src, size_t size) noexcept;

    // 延迟释放队列管理
    void EnqueueDeferredFree(void* ptr, size_t size) noexcept;
    void ProcessDeferredFreeQueue() noexcept;

    // 内存安全状态控制
    void EnterUnsafePeriod() noexcept;
    void ExitUnsafePeriod() noexcept;
    bool IsInUnsafePeriod() const noexcept;
    // 统计和验证方法
    void PrintStats() noexcept;
    void ValidateAllBlocks() noexcept;

    // 兼容性接口（转发到 Try* 方法）
    void RegisterMemoryBlock(void* rawPtr, void* userPtr, size_t size,
        const char* sourceFile, int sourceLine) noexcept;
    void UnregisterMemoryBlock(void* userPtr) noexcept;

private:
    MemorySafety() noexcept;
    ~MemorySafety();

    // 内存条目哈希表
    struct MemoryEntry {
        void* userPtr;
        MemoryTraceInfo info;
        MemoryEntry* next;
    };

    enum { HASH_TABLE_SIZE = 4096 };
    MemoryEntry* m_memoryTable[HASH_TABLE_SIZE];
    CRITICAL_SECTION m_tableLock;

    // 延迟释放队列
    struct DeferredFreeItem {
        void* ptr;
        size_t size;
        DeferredFreeItem* next;
    };
    DeferredFreeItem* m_deferredFreeList;
    CRITICAL_SECTION m_queueLock;

    // 影子内存保护
    std::atomic<bool>* m_shadowMap;

    // 原子状态标记
    std::atomic<bool> m_inUnsafePeriod;

    // 日志文件
    HANDLE m_logFile;
    CRITICAL_SECTION m_logLock;

    // 统计信息
    std::atomic<size_t> m_totalAllocations;
    std::atomic<size_t> m_totalFrees;
    std::atomic<size_t> m_totalDeferredFrees;

    // 实用方法
    size_t CalculateHash(void* ptr) const noexcept;
    MemoryEntry* FindEntry(void* userPtr) noexcept;
    void LogMessageImpl(const char* format, ...) noexcept;
    bool ValidatePointerRange(void* ptr, size_t size) noexcept;

    // 禁止复制
    MemorySafety(const MemorySafety&) = delete;
    MemorySafety& operator=(const MemorySafety&) = delete;
};

// 全局访问点
#define g_MemorySafety MemorySafety::GetInstance()

// 安全内存操作宏
#define SAFE_MEMCPY(dest, src, size) g_MemorySafety.SafeMemoryCopy(dest, src, size)

// 辅助函数声明
bool IsValidPointer(void* ptr);
uint32_t QuickChecksum(const void* data, size_t len);