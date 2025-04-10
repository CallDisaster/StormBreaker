#include "pch.h"
#include "MemorySafety.h"
#include <cstdio>
#include <cstdarg>
#include "Storm/MemoryPool.h" // 包含 JVM_MemPool 声明
#include <Storm/StormHook.h>
#include "../Base/Logger.h" // 包含日志头文件
#include <exception> // Include for std::exception

// RAII Wrapper for CRITICAL_SECTION
class CriticalSectionLock {
    LPCRITICAL_SECTION m_pcs;
    bool m_locked; // Track lock state
public:
    explicit CriticalSectionLock(LPCRITICAL_SECTION pcs) : m_pcs(pcs), m_locked(false) {
        if (m_pcs) {
            EnterCriticalSection(m_pcs);
            m_locked = true;
        }
    }
    ~CriticalSectionLock() {
        if (m_locked && m_pcs) {
            LeaveCriticalSection(m_pcs);
        }
    }
    // Prevent copying and assignment
    CriticalSectionLock(const CriticalSectionLock&) = delete;
    CriticalSectionLock& operator=(const CriticalSectionLock&) = delete;
};


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

    // 创建或打开日志文件 (保留 SEH 保护 WinAPI)
    __try {
        m_logFile = CreateFileA(
            "MemorySafety.log",
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        m_logFile = INVALID_HANDLE_VALUE;
        OutputDebugStringA("[MemorySafety] Failed to create log file.\n");
    }


    // 分配影子内存映射 (保留 SEH 保护 WinAPI)
    __try {
        m_shadowMap = (std::atomic<bool>*)VirtualAlloc(
            NULL,
            1024 * 1024 * sizeof(std::atomic<bool>),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (m_shadowMap) {
            for (size_t i = 0; i < 1024 * 1024; i++) {
                new (&m_shadowMap[i]) std::atomic<bool>(false); // Placement new doesn't throw C++ exceptions
            }
        }
        else {
            OutputDebugStringA("[MemorySafety] Failed to allocate shadow map.\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        m_shadowMap = nullptr;
        OutputDebugStringA("[MemorySafety] Exception during shadow map allocation.\n");
    }


    LogMessageImpl("[MemorySafety] 初始化"); // LogMessageImpl 内部已移除 SEH
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
    {
        CriticalSectionLock lock(&m_tableLock);
        for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
            MemoryEntry* entry = m_memoryTable[i];
            while (entry) {
                MemoryEntry* next = entry->next;
                VirtualFree(entry, 0, MEM_RELEASE);
                entry = next;
            }
            m_memoryTable[i] = nullptr;
        }
    }

    // 释放延迟队列
    {
        CriticalSectionLock lock(&m_queueLock);
        DeferredFreeItem* item = m_deferredFreeList;
        while (item) {
            DeferredFreeItem* next = item->next;
            VirtualFree(item, 0, MEM_RELEASE);
            item = next;
        }
        m_deferredFreeList = nullptr;
    }

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
}

// 计算哈希值
size_t MemorySafety::CalculateHash(void* ptr) const noexcept {
    return (reinterpret_cast<uintptr_t>(ptr) >> 4) % HASH_TABLE_SIZE;
}

// 查找内存条目
MemorySafety::MemoryEntry* MemorySafety::FindEntry(void* userPtr) noexcept {
    size_t hash = CalculateHash(userPtr);
    CriticalSectionLock lock(&m_tableLock); // Use RAII lock
    MemoryEntry* entry = m_memoryTable[hash];
    while (entry) {
        if (entry->userPtr == userPtr) {
            break;
        }
        entry = entry->next;
    }
    return entry;
}

// 使用SEH方式分配内存条目 - 作为MemorySafety的成员方法
MemorySafety::MemoryEntry* MemorySafety::AllocateMemoryEntrySEH() noexcept {
    MemoryEntry* newEntry = nullptr;
    __try {
        newEntry = (MemoryEntry*)VirtualAlloc(
            NULL,
            sizeof(MemoryEntry),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 创建 MemoryEntry 失败 (Exception: 0x%x)", GetExceptionCode());
        return nullptr;
    }

    if (!newEntry) {
        LogMessageImpl("[MemorySafety] 创建 MemoryEntry 失败 (VirtualAlloc returned NULL)");
    }

    return newEntry;
}

// 注册内存块
bool MemorySafety::TryRegisterBlock(void* rawPtr, void* userPtr, size_t size,
    const char* sourceFile, int sourceLine) noexcept {
    if (!rawPtr || !userPtr) return false;

    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return true;
    }

    // 使用成员方法创建新条目 (避免混用SEH)
    MemoryEntry* newEntry = AllocateMemoryEntrySEH();
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
    newEntry->info.checksum = 0;

    // 复制源文件信息 (使用 C++ try/catch)
    try {
        if (sourceFile) {
            strncpy_s(newEntry->info.sourceFile, sourceFile, _countof(newEntry->info.sourceFile) - 1);
            newEntry->info.sourceFile[_countof(newEntry->info.sourceFile) - 1] = '\0';
        }
        else {
            strcpy_s(newEntry->info.sourceFile, "Unknown");
        }
        newEntry->info.sourceLine = sourceLine;
    }
    catch (const std::exception& e) {
        LogMessageImpl("[MemorySafety] 复制源文件信息时异常: %s", e.what());
        VirtualFree(newEntry, 0, MEM_RELEASE);
        return false;
    }
    catch (...) {
        LogMessageImpl("[MemorySafety] 复制源文件信息时未知异常");
        VirtualFree(newEntry, 0, MEM_RELEASE);
        return false;
    }

    // 添加到哈希表 (使用 RAII lock)
    {
        size_t hash = CalculateHash(userPtr);
        CriticalSectionLock lock(&m_tableLock);
        newEntry->next = m_memoryTable[hash];
        m_memoryTable[hash] = newEntry;
    }

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

    m_totalAllocations.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// 取消注册内存块
bool MemorySafety::TryUnregisterBlock(void* userPtr) noexcept {
    if (!userPtr) return false;

    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return true;
    }

    MemoryEntry* toFree = nullptr;
    bool found = false;
    size_t blockSize = 0;

    { // Use RAII lock
        CriticalSectionLock lock(&m_tableLock);
        // 移除 SEH
        size_t hash = CalculateHash(userPtr);
        MemoryEntry* prev = nullptr;
        MemoryEntry* entry = m_memoryTable[hash];

        while (entry) {
            if (entry->userPtr == userPtr) {
                if (prev) {
                    prev->next = entry->next;
                }
                else {
                    m_memoryTable[hash] = entry->next;
                }
                toFree = entry;
                blockSize = entry->info.size;
                found = true;
                break;
            }
            prev = entry;
            entry = entry->next;
        }
    } // Lock released

    if (found) {
        if (m_shadowMap) {
            uintptr_t startAddr = reinterpret_cast<uintptr_t>(userPtr);
            uintptr_t endAddr = startAddr + blockSize - 1;
            size_t startPage = (startAddr >> 12);
            size_t endPage = (endAddr >> 12);
            for (size_t page = startPage; page <= endPage && page < (1024 * 1024); page++) {
                m_shadowMap[page].store(false, std::memory_order_relaxed);
            }
        }
        VirtualFree(toFree, 0, MEM_RELEASE);
        m_totalFrees.fetch_add(1, std::memory_order_relaxed);
    }

    return found;
}


// 验证内存块
bool MemorySafety::ValidateMemoryBlock(void* ptr) noexcept {
    if (!ptr) return false;

    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return true;
    }

    MemoryEntry* entry = FindEntry(ptr); // Uses RAII lock internally

    if (entry != nullptr && entry->info.isValid) {
        return IsValidPointer(ptr); // Uses SEH for VirtualQuery
    }

    return false;
}

// SEH保护的memcpy函数 - 作为MemorySafety的成员方法
bool MemorySafety::SafeMemcpyWithSEH(void* dest, const void* src, size_t size) noexcept {
    __try {
        memcpy(dest, src, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 内存复制异常: dest=%p, src=%p, size=%zu, 错误=0x%x",
            dest, src, size, GetExceptionCode());
        return false;
    }
}

// 安全内存复制
bool MemorySafety::SafeMemoryCopy(void* dest, const void* src, size_t size) noexcept {
    if (!dest || !src || size == 0) return false;

    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return SafeMemcpyWithSEH(dest, src, size);
    }

    // 先检查指针有效性
    if (IsValidPointer(dest) && IsValidPointer(const_cast<void*>(src))) {
        // 使用成员方法执行SEH保护的memcpy
        return SafeMemcpyWithSEH(dest, src, size);
    }
    else {
        LogMessageImpl("[MemorySafety] SafeMemoryCopy 无效指针: dest=%p, src=%p", dest, src);
        return false;
    }
}

// 使用SEH方式分配DeferredFreeItem - 作为MemorySafety的成员方法
MemorySafety::DeferredFreeItem* MemorySafety::AllocateDeferredFreeItemSEH() noexcept {
    DeferredFreeItem* newItem = nullptr;
    __try {
        newItem = (DeferredFreeItem*)VirtualAlloc(
            NULL,
            sizeof(DeferredFreeItem),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 延迟释放项创建失败 (Exception: 0x%x)", GetExceptionCode());
        return nullptr;
    }

    if (!newItem) {
        LogMessageImpl("[MemorySafety] 延迟释放项创建失败 (VirtualAlloc returned NULL)");
    }

    return newItem;
}

// 添加到延迟释放队列
void MemorySafety::EnqueueDeferredFree(void* ptr, size_t size) noexcept {
    if (!ptr) return;

    // 使用成员方法创建延迟释放项 (避免混用SEH)
    DeferredFreeItem* newItem = AllocateDeferredFreeItemSEH();
    if (!newItem) {
        return;
    }

    newItem->ptr = ptr;
    newItem->size = size;
    newItem->next = nullptr;

    { // Use RAII lock
        CriticalSectionLock lock(&m_queueLock);
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
    } // Lock released

    m_totalDeferredFrees.fetch_add(1, std::memory_order_relaxed);
}

// 检查是否是Storm系统块 (使用SEH) - 作为MemorySafety的成员方法
bool MemorySafety::IsSystemBlockSEH(void* ptr) noexcept {
    bool isSystemBlock = false;
    __try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));
        if (header->Magic == STORM_MAGIC && header->HeapPtr == SPECIAL_MARKER && (header->Flags & 0x4)) {
            isSystemBlock = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 异常时认为不是系统块
    }
    return isSystemBlock;
}

// 处理延迟释放队列
void MemorySafety::ProcessDeferredFreeQueue() noexcept {
    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return;
    }

    DeferredFreeItem* head = nullptr;
    { // Use RAII lock
        CriticalSectionLock lock(&m_queueLock);
        head = m_deferredFreeList;
        m_deferredFreeList = nullptr;
    } // Lock released

    DeferredFreeItem* current = head;
    size_t processedCount = 0;

    while (current) {
        void* ptrToFree = current->ptr;
        bool freed = false;
        DeferredFreeItem* next = current->next;

        try {
            if (MemPool::IsFromPool(ptrToFree)) { // Uses lock internally
                MemPool::FreeSafe(ptrToFree);
                freed = true;
            }
            else if (JVM_MemPool::IsFromPool(ptrToFree)) { // Uses lock internally
                JVM_MemPool::Free(ptrToFree);
                freed = true;
            }
            else {
                // 使用成员方法检查是否是系统块 (避免混用SEH)
                bool isSystemBlock = IsSystemBlockSEH(ptrToFree);

                if (isSystemBlock) {
                    void* rawPtr = static_cast<char*>(ptrToFree) - sizeof(StormAllocHeader);
                    if (VirtualFree(rawPtr, 0, MEM_RELEASE)) {
                        freed = true;
                    }
                    else {
                        LogMessageImpl("[MemorySafety] 处理延迟释放 (System) 失败: %p, Error: %lu", ptrToFree, GetLastError());
                    }
                }
            }
        }
        catch (const std::exception& e) {
            LogMessageImpl("[MemorySafety] 处理延迟释放 C++ 异常: %p, 错误=%s", ptrToFree, e.what());
        }
        catch (...) {
            LogMessageImpl("[MemorySafety] 处理延迟释放未知异常: %p", ptrToFree);
        }

        if (freed) {
            processedCount++;
        }

        VirtualFree(current, 0, MEM_RELEASE);
        current = next;
    }

    // if (processedCount > 0) { // Reduce logging verbosity
    //     LogMessageImpl("[MemorySafety] 处理延迟释放完成: %zu项", processedCount);
    // }
}


// 进入不安全期
void MemorySafety::EnterUnsafePeriod() noexcept {
    bool expected = false;
    if (m_inUnsafePeriod.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        // LogMessageImpl("[MemorySafety] 进入不安全期");
    }
}

// 退出不安全期
void MemorySafety::ExitUnsafePeriod() noexcept {
    bool expected = true;
    if (m_inUnsafePeriod.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        // LogMessageImpl("[MemorySafety] 退出不安全期");
        ProcessDeferredFreeQueue();
    }
}

// 是否在不安全期
bool MemorySafety::IsInUnsafePeriod() const noexcept {
    return m_inUnsafePeriod.load(std::memory_order_acquire);
}

// 日志实现
void MemorySafety::LogMessageImpl(const char* format, ...) noexcept {
    if (m_logFile == INVALID_HANDLE_VALUE) return;

    // 移除 SEH
    CriticalSectionLock lock(&m_logLock); // Use RAII lock
    char buffer[1024];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int prefixLen = sprintf_s(buffer, sizeof(buffer),
        "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, format);
    int messageLen = vsprintf_s(buffer + prefixLen, sizeof(buffer) - prefixLen, format, args);
    va_end(args);

    if (messageLen > 0) {
        strcat_s(buffer, sizeof(buffer), "\r\n");
        DWORD bytesWritten;
        WriteFile(m_logFile, buffer, (DWORD)strlen(buffer), &bytesWritten, NULL);
    }
    // Lock released automatically
}

// 使用SEH方式执行VirtualQuery - 作为MemorySafety的成员方法
bool MemorySafety::DoValidatePointerRangeSEH(void* ptr, size_t size, MEMORY_BASIC_INFORMATION* mbi) noexcept {
    __try {
        if (!VirtualQuery(ptr, mbi, sizeof(*mbi))) {
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// 验证指针范围是否可访问
bool MemorySafety::ValidatePointerRange(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return false;

    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return true;
    }

    // 移除外部 SEH
    if (MemPool::IsFromPool(ptr)) { // Uses lock internally
        return true;
    }
    if (JVM_MemPool::IsFromPool(ptr)) { // Uses lock internally
        return true;
    }

    MEMORY_BASIC_INFORMATION mbi;
    // 使用成员方法执行SEH保护的VirtualQuery (避免混用异常处理)
    if (!DoValidatePointerRangeSEH(ptr, size, &mbi)) {
        return false;
    }

    if (!(mbi.State & MEM_COMMIT) || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
        return false;
    }

    uintptr_t startAddr = reinterpret_cast<uintptr_t>(ptr);
    uintptr_t endAddr = startAddr + size;
    uintptr_t regionEndAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

    if (endAddr > regionEndAddr) {
        char* endPtrCheck = reinterpret_cast<char*>(ptr) + size - 1;
        MEMORY_BASIC_INFORMATION mbi_end;

        // 使用成员方法执行SEH保护的VirtualQuery (避免混用异常处理)
        if (!DoValidatePointerRangeSEH(endPtrCheck, 1, &mbi_end)) {
            return false;
        }

        if (!(mbi_end.State & MEM_COMMIT) || (mbi_end.Protect & PAGE_NOACCESS) || (mbi_end.Protect & PAGE_GUARD)) {
            return false;
        }
    }

    return true;
}

// 使用SEH方式执行VirtualQuery - 单独实现避免混用异常处理
bool DoIsValidPointerSEH(const void* ptr, MEMORY_BASIC_INFORMATION* mbi) {
    __try {
        if (!VirtualQuery(ptr, mbi, sizeof(*mbi))) {
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// 辅助函数实现
bool IsValidPointer(const void* ptr) {
    if (!ptr) return false;

    MEMORY_BASIC_INFORMATION mbi;
    // 使用单独函数执行SEH保护的VirtualQuery (避免混用异常处理)
    if (!DoIsValidPointerSEH(ptr, &mbi)) {
        return false;
    }

    return (mbi.State & MEM_COMMIT) && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

// 使用SEH方式执行校验和计算 - 单独实现避免混用异常处理
uint32_t DoQuickChecksumSEH(const uint8_t* bytes, size_t len) {
    uint32_t sum = 0;
    __try {
        for (size_t i = 0; i < len; i++) {
            sum = ((sum << 7) | (sum >> 25)) + bytes[i];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringA("[MemorySafety] QuickChecksum 异常\n");
        return 0;
    }
    return sum;
}

// 计算校验和
uint32_t QuickChecksum(const void* data, size_t len) {
    if (!data || len == 0) return 0;

    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    // 使用单独函数执行SEH保护的校验和计算 (避免混用异常处理)
    return DoQuickChecksumSEH(bytes, len);
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
    // 移除 SEH
    LogMessageImpl("[MemorySafety] 统计信息:");
    LogMessageImpl("  - 总分配数: %zu", m_totalAllocations.load(std::memory_order_relaxed));
    LogMessageImpl("  - 总释放数: %zu", m_totalFrees.load(std::memory_order_relaxed));
    LogMessageImpl("  - 总延迟释放: %zu", m_totalDeferredFrees.load(std::memory_order_relaxed));

    size_t activeBlocks = 0;
    size_t totalMemory = 0;
    { // Use RAII lock
        CriticalSectionLock lock(&m_tableLock);
        for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
            MemoryEntry* entry = m_memoryTable[i];
            while (entry) {
                if (entry->info.isValid) {
                    activeBlocks++;
                    totalMemory += entry->info.size;
                }
                entry = entry->next;
            }
        }
    } // Lock released

    LogMessageImpl("  - 当前跟踪块: %zu", activeBlocks);
    LogMessageImpl("  - 活跃内存: %.2f MB", totalMemory / (1024.0 * 1024.0));

    size_t queueSize = 0;
    { // Use RAII lock
        CriticalSectionLock lock(&m_queueLock);
        DeferredFreeItem* item = m_deferredFreeList;
        while (item) {
            queueSize++;
            item = item->next;
        }
    } // Lock released
    LogMessageImpl("  - 延迟释放队列: %zu 项", queueSize);
}

// 验证块有效性函数 - 作为MemorySafety的成员方法
bool MemorySafety::ValidateBlockPointerSEH(void* ptr) noexcept {
    bool isValid = false;
    __try {
        // 简单读取验证可访问性
        volatile unsigned char firstByte = *(volatile unsigned char*)ptr;
        isValid = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMessageImpl("[MemorySafety] 验证块地址异常: %p", ptr);
        isValid = false;
    }
    return isValid;
}

// 验证所有内存块
void MemorySafety::ValidateAllBlocks() noexcept {
    if (m_inUnsafePeriod.load(std::memory_order_acquire)) {
        return;
    }

    // 移除 SEH
    size_t validCount = 0;
    size_t invalidCount = 0;
    size_t checkedCount = 0;

    // 收集需要标记为无效的条目
    struct InvalidEntry {
        size_t tableIndex;
        MemoryEntry* entry;
    };
    std::vector<InvalidEntry> invalidEntries;

    try {
        invalidEntries.reserve(100); // 预分配空间避免频繁分配
    }
    catch (...) {
        LogMessageImpl("[MemorySafety] 验证时内存分配失败");
        return;
    }

    // 第一步：扫描所有条目并验证
    {
        CriticalSectionLock lock(&m_tableLock);
        for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
            MemoryEntry* entry = m_memoryTable[i];
            while (entry) {
                checkedCount++;

                if (entry->info.isValid) {
                    // 使用成员方法验证指针有效性(避免混用SEH)
                    bool isValidNow = ValidateBlockPointerSEH(entry->userPtr);

                    if (isValidNow) {
                        validCount++;
                    }
                    else {
                        invalidCount++;
                        try {
                            invalidEntries.push_back({ i, entry });
                        }
                        catch (...) {
                            // 忽略向量操作异常
                        }
                    }
                }
                entry = entry->next;
            }
        }
    }

    // 第二步：标记无效条目
    if (!invalidEntries.empty()) {
        CriticalSectionLock lock(&m_tableLock);
        for (const auto& item : invalidEntries) {
            MemoryEntry* entry = item.entry;
            entry->info.isValid = false;
            LogMessageImpl("[MemorySafety] 验证失败: %p (源: %s:%d)",
                entry->userPtr, entry->info.sourceFile, entry->info.sourceLine);
        }
    }

    LogMessageImpl("[MemorySafety] 块验证完成: 检查 %zu, 有效 %zu, 无效 %zu",
        checkedCount, validCount, invalidCount);
}