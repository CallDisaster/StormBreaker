#include "pch.h"
#include "MemorySafety.h"
#include <cstdio>
#include <cstdarg>
#include <Storm/StormHook.h>

// 单例访问实现
MemorySafety& MemorySafety::GetInstance() noexcept {
    static MemorySafety instance;
    return instance;
}

// 构造函数
MemorySafety::MemorySafety() noexcept
    : m_deferredFreeList(nullptr)
    , m_shadowMap(nullptr)
    , m_inUnsafePeriod(false)
    , m_logFile(INVALID_HANDLE_VALUE)
    , m_totalAllocations(0)
    , m_totalFrees(0)
    , m_totalDeferredFrees(0)
{
    // 初始化内存表
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        m_memoryTable[i] = nullptr;
    }

    // 初始化锁
    InitializeCriticalSection(&m_tableLock);
    InitializeCriticalSection(&m_queueLock);
    InitializeCriticalSection(&m_logLock);

    // 创建或打开日志文件
    m_logFile = CreateFileA(
        "MemorySafety.log",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // 分配影子内存映射 (4MB对应1GB地址空间)
    m_shadowMap = (std::atomic<bool>*)VirtualAlloc(
        NULL,
        1024 * 1024 * sizeof(std::atomic<bool>),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (m_shadowMap) {
        for (size_t i = 0; i < 1024 * 1024; i++) {
            new (&m_shadowMap[i]) std::atomic<bool>(false);
        }
    }

    LogMessageImpl("[MemorySafety] 初始化");
}

// 析构函数
MemorySafety::~MemorySafety() {
    Shutdown();
}

// 初始化
bool MemorySafety::Initialize() noexcept {
    LogMessageImpl("[MemorySafety] 系统启动");
    return true;
}

// 关闭系统
void MemorySafety::Shutdown() noexcept {
    // 处理延迟释放队列
    ProcessDeferredFreeQueue();

    // 释放内存表
    EnterCriticalSection(&m_tableLock);

    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        MemoryEntry* entry = m_memoryTable[i];
        while (entry) {
            MemoryEntry* next = entry->next;
            VirtualFree(entry, 0, MEM_RELEASE);
            entry = next;
        }
        m_memoryTable[i] = nullptr;
    }

    LeaveCriticalSection(&m_tableLock);

    // 释放延迟队列
    EnterCriticalSection(&m_queueLock);

    DeferredFreeItem* item = m_deferredFreeList;
    while (item) {
        DeferredFreeItem* next = item->next;
        VirtualFree(item, 0, MEM_RELEASE);
        item = next;
    }
    m_deferredFreeList = nullptr;

    LeaveCriticalSection(&m_queueLock);

    // 释放影子内存映射
    if (m_shadowMap) {
        VirtualFree(m_shadowMap, 0, MEM_RELEASE);
        m_shadowMap = nullptr;
    }

    // 关闭日志文件
    if (m_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_logFile);
        m_logFile = INVALID_HANDLE_VALUE;
    }

    // 删除锁
    DeleteCriticalSection(&m_tableLock);
    DeleteCriticalSection(&m_queueLock);
    DeleteCriticalSection(&m_logLock);

    LogMessageImpl("[MemorySafety] 系统关闭");
}

// 计算哈希值
size_t MemorySafety::CalculateHash(void* ptr) const noexcept {
    return (reinterpret_cast<uintptr_t>(ptr) >> 4) % HASH_TABLE_SIZE;
}

// 查找内存条目
MemorySafety::MemoryEntry* MemorySafety::FindEntry(void* userPtr) noexcept {
    size_t hash = CalculateHash(userPtr);
    MemoryEntry* entry = m_memoryTable[hash];

    while (entry) {
        if (entry->userPtr == userPtr) {
            return entry;
        }
        entry = entry->next;
    }

    return nullptr;
}

// 注册内存块
bool MemorySafety::TryRegisterBlock(void* rawPtr, void* userPtr, size_t size,
    const char* sourceFile, int sourceLine) noexcept {
    if (!rawPtr || !userPtr) return false;

    __try {
        // 创建新条目
        MemoryEntry* newEntry = (MemoryEntry*)VirtualAlloc(
            NULL,
            sizeof(MemoryEntry),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!newEntry) {
            return false;
        }

        // 填充条目数据
        newEntry->userPtr = userPtr;
        newEntry->info.rawPointer = rawPtr;
        newEntry->info.userPointer = userPtr;
        newEntry->info.size = size;
        newEntry->info.timestamp = GetTickCount();
        newEntry->info.threadId = GetCurrentThreadId();
        newEntry->info.isValid = true;
        newEntry->info.checksum = 0; // 暂不计算校验和

        // 复制源文件信息
        if (sourceFile) {
            strncpy_s(newEntry->info.sourceFile, sourceFile, _countof(newEntry->info.sourceFile) - 1);
        }
        else {
            strcpy_s(newEntry->info.sourceFile, "Unknown");
        }
        newEntry->info.sourceLine = sourceLine;

        // 添加到哈希表
        size_t hash = CalculateHash(userPtr);

        EnterCriticalSection(&m_tableLock);
        newEntry->next = m_memoryTable[hash];
        m_memoryTable[hash] = newEntry;
        LeaveCriticalSection(&m_tableLock);

        // 更新影子内存映射
        if (m_shadowMap) {
            uintptr_t startAddr = reinterpret_cast<uintptr_t>(userPtr);
            uintptr_t endAddr = startAddr + size - 1;

            size_t startPage = (startAddr >> 12);
            size_t endPage = (endAddr >> 12);

            for (size_t page = startPage; page <= endPage && page < (1024 * 1024); page++) {
                m_shadowMap[page].store(true, std::memory_order_relaxed);
            }
        }

        // 更新统计
        m_totalAllocations.fetch_add(1, std::memory_order_relaxed);

        LogMessageImpl("[MemorySafety] 注册块: %p (原始=%p, 大小=%zu, 源=%s:%d)",
            userPtr, rawPtr, size, newEntry->info.sourceFile, sourceLine);

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 注册块异常: %p, 错误=0x%x",
            userPtr, GetExceptionCode());
        return false;
    }
}

// 取消注册内存块
bool MemorySafety::TryUnregisterBlock(void* userPtr) noexcept {
    if (!userPtr) return false;

    __try {
        EnterCriticalSection(&m_tableLock);

        // 查找并删除条目
        size_t hash = CalculateHash(userPtr);
        MemoryEntry* prev = nullptr;
        MemoryEntry* entry = m_memoryTable[hash];

        while (entry) {
            if (entry->userPtr == userPtr) {
                // 从链表移除
                if (prev) {
                    prev->next = entry->next;
                }
                else {
                    m_memoryTable[hash] = entry->next;
                }

                // 更新影子内存映射
                if (m_shadowMap) {
                    uintptr_t startAddr = reinterpret_cast<uintptr_t>(userPtr);
                    uintptr_t endAddr = startAddr + entry->info.size - 1;

                    size_t startPage = (startAddr >> 12);
                    size_t endPage = (endAddr >> 12);

                    for (size_t page = startPage; page <= endPage && page < (1024 * 1024); page++) {
                        m_shadowMap[page].store(false, std::memory_order_relaxed);
                    }
                }

                // 释放条目内存
                MemoryEntry* toFree = entry;

                LeaveCriticalSection(&m_tableLock);

                VirtualFree(toFree, 0, MEM_RELEASE);

                // 更新统计
                m_totalFrees.fetch_add(1, std::memory_order_relaxed);

                LogMessageImpl("[MemorySafety] 取消注册块: %p", userPtr);

                return true;
            }

            prev = entry;
            entry = entry->next;
        }

        LeaveCriticalSection(&m_tableLock);
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LeaveCriticalSection(&m_tableLock);
        LogMessageImpl("[MemorySafety] 取消注册异常: %p, 错误=0x%x",
            userPtr, GetExceptionCode());
        return false;
    }
}

// 验证内存块
bool MemorySafety::ValidateMemoryBlock(void* ptr) noexcept {
    if (!ptr) return false;

    __try {
        // 快速检查：内存是否可访问
        if (!ValidatePointerRange(ptr, 1)) {
            return false;
        }

        // 不安全期跳过详细验证
        if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
            return true;
        }

        // 查找内存条目
        EnterCriticalSection(&m_tableLock);
        MemoryEntry* entry = FindEntry(ptr);
        bool isValid = (entry != nullptr && entry->info.isValid);
        LeaveCriticalSection(&m_tableLock);

        return isValid;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 安全内存复制
bool MemorySafety::SafeMemoryCopy(void* dest, const void* src, size_t size) noexcept {
    if (!dest || !src || size == 0) return false;

    __try {
        // 验证源和目标内存
        if (!ValidatePointerRange(const_cast<void*>(src), size) ||
            !ValidatePointerRange(dest, size)) {
            return false;
        }

        // 分块复制，降低崩溃风险
        const size_t CHUNK_SIZE = 4096;
        const char* srcPtr = static_cast<const char*>(src);
        char* destPtr = static_cast<char*>(dest);

        for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
            size_t bytesToCopy = (offset + CHUNK_SIZE > size) ? (size - offset) : CHUNK_SIZE;

            __try {
                memcpy(destPtr + offset, srcPtr + offset, bytesToCopy);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessageImpl("[MemorySafety] 内存复制异常: offset=%zu, 错误=0x%x",
                    offset, GetExceptionCode());
                return false;
            }
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 内存复制总异常: dest=%p, src=%p, size=%zu, 错误=0x%x",
            dest, src, size, GetExceptionCode());
        return false;
    }
}

// 添加到延迟释放队列
void MemorySafety::EnqueueDeferredFree(void* ptr, size_t size) noexcept {
    if (!ptr) return;

    __try {
        // 创建新队列项
        DeferredFreeItem* newItem = (DeferredFreeItem*)VirtualAlloc(
            NULL,
            sizeof(DeferredFreeItem),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!newItem) {
            LogMessageImpl("[MemorySafety] 延迟释放项创建失败: %p", ptr);
            return;
        }

        newItem->ptr = ptr;
        newItem->size = size;
        newItem->next = nullptr;

        // 添加到队列
        EnterCriticalSection(&m_queueLock);

        if (!m_deferredFreeList) {
            m_deferredFreeList = newItem;
        }
        else {
            DeferredFreeItem* current = m_deferredFreeList;
            while (current->next) {
                current = current->next;
            }
            current->next = newItem;
        }

        LeaveCriticalSection(&m_queueLock);

        // 更新统计
        m_totalDeferredFrees.fetch_add(1, std::memory_order_relaxed);

        LogMessageImpl("[MemorySafety] 延迟释放入队: %p", ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 延迟释放异常: %p, 错误=0x%x",
            ptr, GetExceptionCode());
    }
}

// 处理延迟释放队列
void MemorySafety::ProcessDeferredFreeQueue() noexcept {
    // 如果在不安全期，跳过处理
    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return;
    }

    __try {
        EnterCriticalSection(&m_queueLock);

        DeferredFreeItem* current = m_deferredFreeList;
        DeferredFreeItem* prev = nullptr;
        size_t processedCount = 0;

        while (current) {
            // 尝试释放内存
            __try {
                // 修改：检查是否是mimalloc管理的内存
                if (MemPool::IsFromPool(current->ptr)) {
                    // 使用mimalloc释放
                    MemPool::FreeSafe(current->ptr);
                }
                else {
                    // 使用系统释放
                    VirtualFree(current->ptr, 0, MEM_RELEASE);
                }

                processedCount++;

                // 移除此项
                if (prev) {
                    prev->next = current->next;
                }
                else {
                    m_deferredFreeList = current->next;
                }

                DeferredFreeItem* toFree = current;
                current = current->next;

                VirtualFree(toFree, 0, MEM_RELEASE);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                LogMessage("[MemorySafety] 处理延迟释放异常: %p, 错误=0x%x",
                    current->ptr, GetExceptionCode());

                // 移到下一项
                prev = current;
                current = current->next;
            }
        }

        LeaveCriticalSection(&m_queueLock);

        if (processedCount > 0) {
            LogMessage("[MemorySafety] 处理延迟释放完成: %zu项", processedCount);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LeaveCriticalSection(&m_queueLock);
        LogMessage("[MemorySafety] 处理延迟释放总异常: 错误=0x%x", GetExceptionCode());
    }
}

// 进入不安全期
void MemorySafety::EnterUnsafePeriod() noexcept {
    bool expected = false;
    if (m_inUnsafePeriod.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        LogMessageImpl("[MemorySafety] 进入不安全期");
    }
}

// 退出不安全期
void MemorySafety::ExitUnsafePeriod() noexcept {
    bool expected = true;
    if (m_inUnsafePeriod.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        LogMessageImpl("[MemorySafety] 退出不安全期");
    }
}

// 是否在不安全期
bool MemorySafety::IsInUnsafePeriod() const noexcept {
    return m_inUnsafePeriod.load(std::memory_order_acquire);
}

// 日志实现
void MemorySafety::LogMessageImpl(const char* format, ...) noexcept {
    if (m_logFile == INVALID_HANDLE_VALUE) return;

    __try {
        EnterCriticalSection(&m_logLock);

        // 准备缓冲区
        char buffer[1024];

        // 添加时间戳
        SYSTEMTIME st;
        GetLocalTime(&st);
        int prefixLen = sprintf_s(buffer, sizeof(buffer),
            "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        // 添加消息
        va_list args;
        va_start(args, format);
        int messageLen = vsprintf_s(buffer + prefixLen, sizeof(buffer) - prefixLen, format, args);
        va_end(args);

        if (messageLen > 0) {
            // 添加换行
            strcat_s(buffer, sizeof(buffer), "\r\n");

            // 写入文件
            DWORD bytesWritten;
            WriteFile(
                m_logFile,
                buffer,
                (DWORD)strlen(buffer),
                &bytesWritten,
                NULL
            );
        }

        LeaveCriticalSection(&m_logLock);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 日志写入失败，什么也不做
        LeaveCriticalSection(&m_logLock);
    }
}

// 验证指针范围是否可访问
bool MemorySafety::ValidatePointerRange(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return false;

    __try {
        // 优先检查是否是mimalloc管理的内存
        if (MemPool::IsFromPool(ptr)) {
            // mimalloc管理的内存，直接认为有效
            return true;
        }

        // 原有的VirtualQuery逻辑保持不变
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            return false;
        }

        // 检查内存是否已提交且可读
        if (!(mbi.State & MEM_COMMIT) ||
            (mbi.Protect & PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD)) {
            return false;
        }


        // 如果检查范围较大，仅检查开始和结束位置
        if (size > 4096) {
            char* endPtr = static_cast<char*>(ptr) + size - 1;

            if (!VirtualQuery(endPtr, &mbi, sizeof(mbi))) {
                return false;
            }

            if (!(mbi.State & MEM_COMMIT) ||
                (mbi.Protect & PAGE_NOACCESS) ||
                (mbi.Protect & PAGE_GUARD)) {
                return false;
            }
        }

        // 或者使用影子内存映射
        if (m_shadowMap) {
            uintptr_t startAddr = reinterpret_cast<uintptr_t>(ptr);
            uintptr_t endAddr = startAddr + size - 1;

            size_t startPage = (startAddr >> 12);

            // 仅检查起始页，这是一个快速检查
            if (startPage < (1024 * 1024) && !m_shadowMap[startPage].load(std::memory_order_relaxed)) {
                return false;
            }
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 辅助函数实现
bool IsValidPointer(void* ptr) {
    if (!ptr) return false;

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

// 计算校验和
uint32_t QuickChecksum(const void* data, size_t len) {
    if (!data || len == 0) return 0;

    __try {
        uint32_t sum = 0;
        const uint8_t* bytes = static_cast<const uint8_t*>(data);

        for (size_t i = 0; i < len; i++) {
            sum = ((sum << 7) | (sum >> 25)) + bytes[i];
        }

        return sum;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// 兼容性方法（转发到 Try* 方法）
void MemorySafety::RegisterMemoryBlock(void* rawPtr, void* userPtr, size_t size,
    const char* sourceFile, int sourceLine) noexcept {
    TryRegisterBlock(rawPtr, userPtr, size, sourceFile, sourceLine);
}

void MemorySafety::UnregisterMemoryBlock(void* userPtr) noexcept {
    TryUnregisterBlock(userPtr);
}

// 打印统计信息
void MemorySafety::PrintStats() noexcept {
    __try {
        LogMessageImpl("[MemorySafety] 统计信息:");
        LogMessageImpl("  - 总分配数: %zu", m_totalAllocations.load(std::memory_order_relaxed));
        LogMessageImpl("  - 总释放数: %zu", m_totalFrees.load(std::memory_order_relaxed));
        LogMessageImpl("  - 总延迟释放: %zu", m_totalDeferredFrees.load(std::memory_order_relaxed));

        // 计算当前跟踪块数量
        size_t activeBlocks = 0;
        size_t totalMemory = 0;

        EnterCriticalSection(&m_tableLock);
        for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
            MemoryEntry* entry = m_memoryTable[i];
            while (entry) {
                activeBlocks++;
                totalMemory += entry->info.size;
                entry = entry->next;
            }
        }
        LeaveCriticalSection(&m_tableLock);

        LogMessageImpl("  - 当前跟踪块: %zu", activeBlocks);
        LogMessageImpl("  - 活跃内存: %.2f MB", totalMemory / (1024.0 * 1024.0));

        // 检查延迟释放队列
        size_t queueSize = 0;

        EnterCriticalSection(&m_queueLock);
        DeferredFreeItem* item = m_deferredFreeList;
        while (item) {
            queueSize++;
            item = item->next;
        }
        LeaveCriticalSection(&m_queueLock);

        LogMessageImpl("  - 延迟释放队列: %zu 项", queueSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 统计打印异常: 错误=0x%x", GetExceptionCode());
    }
}

// 验证所有内存块
void MemorySafety::ValidateAllBlocks() noexcept {
    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        LogMessageImpl("[MemorySafety] 不安全期间跳过全块验证");
        return;
    }

    __try {
        size_t validCount = 0;
        size_t invalidCount = 0;

        EnterCriticalSection(&m_tableLock);

        for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
            MemoryEntry* entry = m_memoryTable[i];

            while (entry) {
                __try {
                    bool isValid = ValidatePointerRange(entry->userPtr, entry->info.size);

                    if (isValid) {
                        validCount++;
                    }
                    else {
                        invalidCount++;
                        entry->info.isValid = false;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    invalidCount++;
                }

                entry = entry->next;
            }
        }

        LeaveCriticalSection(&m_tableLock);

        LogMessageImpl("[MemorySafety] 块验证完成: %zu 有效, %zu 无效",
            validCount, invalidCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LeaveCriticalSection(&m_tableLock);
        LogMessageImpl("[MemorySafety] 全块验证异常: 错误=0x%x", GetExceptionCode());
    }
}