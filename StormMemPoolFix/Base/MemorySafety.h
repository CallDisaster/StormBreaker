#pragma once

#include <Windows.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <Log/LogSystem.h>
#include <Storm/StormHook.h>

// 安全临界区（避免RAII模式）
class SafeCriticalSection {
private:
    CRITICAL_SECTION* cs_;
    bool entered_;
public:
    SafeCriticalSection(CRITICAL_SECTION* cs) noexcept : cs_(cs), entered_(false) {
        if (cs_) {
            __try {
                EnterCriticalSection(cs_);
                entered_ = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                entered_ = false;
                LogMessage("[SafeCS] 进入临界区异常: 0x%08X", GetExceptionCode());
            }
        }
    }
    ~SafeCriticalSection() noexcept {
        if (entered_ && cs_) {
            __try {
                LeaveCriticalSection(cs_);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[SafeCS] 离开临界区异常: 0x%08X", GetExceptionCode());
            }
        }
    }
    bool IsEntered() const noexcept { return entered_; }
};

class SafeMemoryOperations {
public:
    static void* SafeVirtualAlloc(void* lpAddress, size_t dwSize, DWORD flAllocationType, DWORD flProtect) {
        __try {
            return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[SafeMem] VirtualAlloc异常: addr=%p, size=%zu, 异常代码: 0x%08X",
                lpAddress, dwSize, GetExceptionCode());
            return nullptr;
        }
    }

    static BOOL SafeVirtualFree(void* lpAddress, size_t dwSize, DWORD dwFreeType) {
        __try {
            return VirtualFree(lpAddress, dwSize, dwFreeType);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[SafeMem] VirtualFree异常: addr=%p, size=%zu, 异常代码: 0x%08X",
                lpAddress, dwSize, GetExceptionCode());
            return FALSE;
        }
    }

    static void* SafeMemcpy(void* dest, const void* src, size_t count) {
        if (!dest || !src || count == 0) return dest;

        __try {
            if (SafeIsBadWritePtr(dest, count) || SafeIsBadReadPtr(src, count)) {
                LogMessage("[SafeMem] Memcpy参数验证失败: dest=%p, src=%p, count=%zu",
                    dest, src, count);
                return dest;
            }

            return memcpy(dest, src, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[SafeMem] Memcpy异常: dest=%p, src=%p, count=%zu, 异常代码: 0x%08X",
                dest, src, count, GetExceptionCode());
            return dest;
        }
    }

    static void* SafeMemset(void* dest, int value, size_t count) {
        if (!dest || count == 0) return dest;

        __try {
            if (SafeIsBadWritePtr(dest, count)) {
                LogMessage("[SafeMem] Memset参数验证失败: dest=%p, count=%zu", dest, count);
                return dest;
            }

            return memset(dest, value, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogMessage("[SafeMem] Memset异常: dest=%p, value=%d, count=%zu, 异常代码: 0x%08X",
                dest, value, count, GetExceptionCode());
            return dest;
        }
    }
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