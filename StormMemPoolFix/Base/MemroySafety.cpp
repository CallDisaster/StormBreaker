// MemorySafety.cpp - 修复SEH+RAII混用问题的实现
#include "pch.h"
#include "MemorySafety.h"
#include <psapi.h>
#include <algorithm>
#include <cstdarg>

#pragma comment(lib, "psapi.lib")

///////////////////////////////////////////////////////////////////////////////
// 纯C SEH包装函数 - 避免C++对象构造
///////////////////////////////////////////////////////////////////////////////

extern "C" int __stdcall SafeWrapper(void* context, SafeCallbackFn callback) {
    __try {
        return callback(context);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 记录异常代码到全局变量或简单输出
        DWORD exceptionCode = GetExceptionCode();
        char buffer[256];
        wsprintfA(buffer, "[SEH] Exception 0x%08X in SafeWrapper\n", exceptionCode);
        OutputDebugStringA(buffer);
        return 0;
    }
}

///////////////////////////////////////////////////////////////////////////////
// MemorySafety实现
///////////////////////////////////////////////////////////////////////////////

MemorySafety& MemorySafety::GetInstance() noexcept {
    static MemorySafety instance;
    return instance;
}

MemorySafety::MemorySafety() noexcept {
    // 初始化临界区
    InitializeCriticalSection(&m_hashTableCs);
    InitializeCriticalSection(&m_holdQueueCs);
    InitializeCriticalSection(&m_logCs);

    for (int i = 0; i < MemorySafetyConst::SIZE_CLASS_COUNT; ++i) {
        InitializeCriticalSection(&m_cacheCs[i]);
    }
}

MemorySafety::~MemorySafety() noexcept {
    if (m_initialized.load()) {
        Shutdown();
    }

    // 清理临界区
    DeleteCriticalSection(&m_hashTableCs);
    DeleteCriticalSection(&m_holdQueueCs);
    DeleteCriticalSection(&m_logCs);

    for (int i = 0; i < MemorySafetyConst::SIZE_CLASS_COUNT; ++i) {
        DeleteCriticalSection(&m_cacheCs[i]);
    }
}

bool MemorySafety::Initialize() noexcept {
    return SafeExecute([this]() -> bool {
        bool expected = false;
        if (!m_initialized.compare_exchange_strong(expected, true)) {
            return true; // 已初始化
        }

        // 初始化日志文件
        m_logFile = CreateFileA(
            "MemorySafety.log",
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        LogMessage("[MemorySafety] 初始化完成");
        LogMessage("[MemorySafety] 配置 - 缓冲时间:%ums, 内存水位:%zuMB, 最大缓存:%zuMB",
            m_holdTimeMs.load(),
            m_memoryWatermark.load() / (1024 * 1024),
            m_maxCacheSize.load() / (1024 * 1024));

        return true;
        }, "Initialize");
}

void MemorySafety::Shutdown() noexcept {
    SafeExecute([this]() -> void {
        bool expected = true;
        if (!m_initialized.compare_exchange_strong(expected, false)) {
            return; // 已关闭
        }

        m_shutdownRequested.store(true);

        LogMessage("[MemorySafety] 开始关闭");

        // 强制清空Hold队列
        DrainHoldQueue();

        // 清空所有缓存
        for (size_t i = 0; i < MemorySafetyConst::SIZE_CLASS_COUNT; ++i) {
            CleanupSizeClass(i, SIZE_MAX);
        }

        // 释放剩余的哈希表条目
        EnterCriticalSection(&m_hashTableCs);
        for (const auto& pair : m_blockHashTable) {
            VirtualFree(pair.second.rawPtr, 0, MEM_RELEASE);
            LogMessage("[MemorySafety] 清理遗留块: %p", pair.first);
        }
        m_blockHashTable.clear();
        LeaveCriticalSection(&m_hashTableCs);

        LogMessage("[MemorySafety] 关闭完成");

        if (m_logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(m_logFile);
            m_logFile = INVALID_HANDLE_VALUE;
        }
        }, "Shutdown");
}

bool MemorySafety::IsInitialized() const noexcept {
    return m_initialized.load();
}

void* MemorySafety::AllocateBlock(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecute([=]() -> void* {
        if (!m_initialized.load() || m_shutdownRequested.load()) {
            return nullptr;
        }

        stats.totalAllocated.fetch_add(1);
        return InternalAllocate(size, sourceName, sourceLine);
        }, "AllocateBlock");
}

bool MemorySafety::FreeBlock(void* ptr) noexcept {
    return SafeExecute([=]() -> bool {
        if (!ptr || !m_initialized.load()) {
            return false;
        }

        stats.totalFreed.fetch_add(1);
        return InternalFree(ptr);
        }, "FreeBlock");
}

void* MemorySafety::ReallocateBlock(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    return SafeExecute([=]() -> void* {
        if (!m_initialized.load()) {
            return nullptr;
        }

        return InternalReallocate(oldPtr, newSize, sourceName, sourceLine);
        }, "ReallocateBlock");
}

bool MemorySafety::IsOurBlock(void* ptr) const noexcept {
    return SafeExecute([=]() -> bool {
        if (!ptr || !m_initialized.load()) {
            return false;
        }

        EnterCriticalSection(&m_hashTableCs);
        bool found = m_blockHashTable.find(ptr) != m_blockHashTable.end();
        LeaveCriticalSection(&m_hashTableCs);

        return found;
        }, "IsOurBlock");
}

size_t MemorySafety::GetBlockSize(void* ptr) const noexcept {
    return SafeExecute([=]() -> size_t {
        if (!ptr || !m_initialized.load()) {
            return 0;
        }

        BlockInfo info;
        if (FindInHashTable(ptr, &info)) {
            return info.userSize;
        }

        return 0;
        }, "GetBlockSize");
}

void* MemorySafety::InternalAllocate(size_t size, const char* sourceName, DWORD sourceLine) noexcept {
    // 先尝试从缓存获取
    size_t sizeClass = GetSizeClass(size);
    size_t alignedSize = AlignSize(size + MemorySafetyConst::STANDARD_HEADER_SIZE + MemorySafetyConst::TAIL_MAGIC_SIZE, 16);

    void* rawPtr = TryGetFromCache(sizeClass, alignedSize);
    if (rawPtr) {
        stats.cacheHits.fetch_add(1);

        // 重新设置头部信息
        void* userPtr = static_cast<char*>(rawPtr) + MemorySafetyConst::STANDARD_HEADER_SIZE;
        SetupStormHeader(userPtr, size, alignedSize);

        // 更新哈希表
        BlockInfo info = {
            rawPtr, alignedSize, size,
            MemorySafetyUtils::GetTickCount(),
            sourceName, sourceLine
        };
        AddToHashTable(userPtr, info);

        return userPtr;
    }

    stats.cacheMisses.fetch_add(1);

    // 创建新块
    return CreateBlock(size, sourceName, sourceLine);
}

bool MemorySafety::InternalFree(void* ptr) noexcept {
    // 验证指针
    if (!ValidateStormHeader(ptr)) {
        LogError("[MemorySafety] 无效指针或损坏的头部: %p", ptr);
        return false;
    }

    // 从哈希表移除
    BlockInfo info;
    if (!RemoveFromHashTable(ptr, &info)) {
        LogError("[MemorySafety] 指针不在哈希表中: %p", ptr);
        return false;
    }

    // 添加到Hold队列而不是立即释放
    AddToHoldQueue(info.rawPtr, info.totalSize);

    return true;
}

void* MemorySafety::InternalReallocate(void* oldPtr, size_t newSize, const char* sourceName, DWORD sourceLine) noexcept {
    if (!oldPtr) {
        return InternalAllocate(newSize, sourceName, sourceLine);
    }

    if (newSize == 0) {
        InternalFree(oldPtr);
        return nullptr;
    }

    // 获取旧块信息
    BlockInfo oldInfo;
    if (!FindInHashTable(oldPtr, &oldInfo)) {
        return nullptr;
    }

    // 如果新大小足够小，就地重用
    size_t newAlignedSize = AlignSize(newSize + MemorySafetyConst::STANDARD_HEADER_SIZE + MemorySafetyConst::TAIL_MAGIC_SIZE, 16);
    if (newAlignedSize <= oldInfo.totalSize) {
        // 更新头部信息
        SetupStormHeader(oldPtr, newSize, oldInfo.totalSize);

        // 更新哈希表中的用户大小
        EnterCriticalSection(&m_hashTableCs);
        auto it = m_blockHashTable.find(oldPtr);
        if (it != m_blockHashTable.end()) {
            it->second.userSize = newSize;
        }
        LeaveCriticalSection(&m_hashTableCs);

        return oldPtr;
    }

    // 分配新块
    void* newPtr = InternalAllocate(newSize, sourceName, sourceLine);
    if (newPtr) {
        // 复制数据
        size_t copySize = min(oldInfo.userSize, newSize);
        memcpy(newPtr, oldPtr, copySize);

        // 释放旧块
        InternalFree(oldPtr);
    }

    return newPtr;
}

void* MemorySafety::CreateBlock(size_t userSize, const char* sourceName, DWORD sourceLine) noexcept {
    // 计算总大小：头部 + 用户数据 + 尾魔数
    size_t totalSize = AlignSize(userSize + MemorySafetyConst::STANDARD_HEADER_SIZE + MemorySafetyConst::TAIL_MAGIC_SIZE, 16);

    // VirtualAlloc分配
    void* rawPtr = VirtualAlloc(nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogError("[MemorySafety] VirtualAlloc失败: 大小=%zu", totalSize);
        return nullptr;
    }

    // 计算用户指针
    void* userPtr = static_cast<char*>(rawPtr) + MemorySafetyConst::STANDARD_HEADER_SIZE;

    // 设置Storm兼容头部
    SetupStormHeader(userPtr, userSize, totalSize);

    // 添加到哈希表
    BlockInfo info = {
        rawPtr, totalSize, userSize,
        MemorySafetyUtils::GetTickCount(),
        sourceName, sourceLine
    };
    AddToHashTable(userPtr, info);

    return userPtr;
}

bool MemorySafety::DestroyBlock(void* rawPtr) noexcept {
    if (!rawPtr) return false;

    BOOL result = VirtualFree(rawPtr, 0, MEM_RELEASE);
    if (!result) {
        LogError("[MemorySafety] VirtualFree失败: %p, 错误=%u", rawPtr, GetLastError());
        return false;
    }

    return true;
}

void MemorySafety::SetupStormHeader(void* userPtr, size_t userSize, size_t totalSize) noexcept {
    if (!userPtr) return;

    // 获取头部指针
    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
        static_cast<char*>(userPtr) - MemorySafetyConst::STANDARD_HEADER_SIZE
        );

    // 设置头部字段
    header->HeapPtr = MemorySafetyConst::STORM_SPECIAL_HEAP;
    header->Size = static_cast<DWORD>(min(totalSize, 0xFFFFFFFFUL)); // 32位大小
    header->AlignPadding = 0;
    header->Flags = 0x1; // 启用尾魔数
    header->Magic = MemorySafetyConst::STORM_FRONT_MAGIC;

    // 设置尾魔数
    WORD* tailMagic = reinterpret_cast<WORD*>(
        static_cast<char*>(userPtr) + userSize
        );
    *tailMagic = MemorySafetyConst::STORM_TAIL_MAGIC;
}

bool MemorySafety::ValidateStormHeader(void* userPtr) const noexcept {
    if (!userPtr) return false;

    // 检查头部魔数
    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
        static_cast<char*>(userPtr) - MemorySafetyConst::STANDARD_HEADER_SIZE
        );

    if (header->Magic != MemorySafetyConst::STORM_FRONT_MAGIC) {
        return false;
    }

    if (header->HeapPtr != MemorySafetyConst::STORM_SPECIAL_HEAP) {
        return false;
    }

    return true;
}

size_t MemorySafety::GetSizeClass(size_t size) const noexcept {
    // 64KB为单位分档
    size_t sizeClass = size >> MemorySafetyConst::SIZE_CLASS_SHIFT;
    return min(sizeClass, MemorySafetyConst::SIZE_CLASS_COUNT - 1);
}

void* MemorySafety::TryGetFromCache(size_t sizeClass, size_t minSize) noexcept {
    EnterCriticalSection(&m_cacheCs[sizeClass]);

    auto& cache = m_sizeClassCaches[sizeClass];
    void* result = nullptr;

    // 查找足够大的块
    for (auto it = cache.freeBlocks.begin(); it != cache.freeBlocks.end(); ++it) {
        if (it->totalSize >= minSize) {
            result = it->rawPtr;
            cache.totalCached -= it->totalSize;
            cache.freeBlocks.erase(it);
            break;
        }
    }

    LeaveCriticalSection(&m_cacheCs[sizeClass]);
    return result;
}

void MemorySafety::AddToCache(size_t sizeClass, void* rawPtr, size_t totalSize) noexcept {
    EnterCriticalSection(&m_cacheCs[sizeClass]);

    auto& cache = m_sizeClassCaches[sizeClass];

    // 检查缓存是否已满
    if (cache.freeBlocks.size() >= MemorySafetyConst::MAX_CACHE_PER_CLASS) {
        // 释放最老的块
        if (!cache.freeBlocks.empty()) {
            auto& oldest = cache.freeBlocks[0];
            DestroyBlock(oldest.rawPtr);
            cache.totalCached -= oldest.totalSize;
            cache.freeBlocks.erase(cache.freeBlocks.begin());
        }
    }

    // 添加到缓存
    cache.freeBlocks.push_back({ rawPtr, totalSize, MemorySafetyUtils::GetTickCount() });
    cache.totalCached += totalSize;

    LeaveCriticalSection(&m_cacheCs[sizeClass]);
}

void MemorySafety::CleanupSizeClass(size_t sizeClass, size_t maxRemove) noexcept {
    if (sizeClass >= MemorySafetyConst::SIZE_CLASS_COUNT) return;

    EnterCriticalSection(&m_cacheCs[sizeClass]);

    auto& cache = m_sizeClassCaches[sizeClass];
    size_t removed = 0;

    while (!cache.freeBlocks.empty() && removed < maxRemove) {
        auto& entry = cache.freeBlocks.back();
        DestroyBlock(entry.rawPtr);
        cache.totalCached -= entry.totalSize;
        cache.freeBlocks.pop_back();
        removed++;
    }

    LeaveCriticalSection(&m_cacheCs[sizeClass]);
}

void MemorySafety::AddToHoldQueue(void* rawPtr, size_t totalSize) noexcept {
    EnterCriticalSection(&m_holdQueueCs);

    m_holdQueue.push_back({ rawPtr, totalSize, MemorySafetyUtils::GetTickCount() });
    stats.holdQueueSize.store(m_holdQueue.size());

    LeaveCriticalSection(&m_holdQueueCs);
}

void MemorySafety::ProcessHoldQueue() noexcept {
    SafeExecute([this]() -> void {
        ProcessExpiredEntries();

        // 检查内存压力
        if (ShouldTriggerCleanup()) {
            ForceCleanup();
        }
        }, "ProcessHoldQueue");
}

void MemorySafety::ProcessExpiredEntries() noexcept {
    DWORD currentTime = MemorySafetyUtils::GetTickCount();
    DWORD holdTime = m_holdTimeMs.load();

    EnterCriticalSection(&m_holdQueueCs);

    auto it = m_holdQueue.begin();
    while (it != m_holdQueue.end()) {
        DWORD entryAge = currentTime - it->queueTime;

        if (entryAge >= holdTime) {
            // 过期，尝试加入缓存或释放
            size_t sizeClass = GetSizeClass(it->totalSize);

            // 先尝试加入缓存
            bool addedToCache = false;
            EnterCriticalSection(&m_cacheCs[sizeClass]);

            auto& cache = m_sizeClassCaches[sizeClass];
            if (cache.freeBlocks.size() < MemorySafetyConst::MAX_CACHE_PER_CLASS &&
                cache.totalCached + it->totalSize <= m_maxCacheSize.load()) {

                cache.freeBlocks.push_back({ it->rawPtr, it->totalSize, currentTime });
                cache.totalCached += it->totalSize;
                addedToCache = true;
            }

            LeaveCriticalSection(&m_cacheCs[sizeClass]);

            if (!addedToCache) {
                // 直接释放
                DestroyBlock(it->rawPtr);
            }

            it = m_holdQueue.erase(it);
        }
        else {
            ++it;
        }
    }

    stats.holdQueueSize.store(m_holdQueue.size());
    LeaveCriticalSection(&m_holdQueueCs);
}

void MemorySafety::DrainHoldQueue() noexcept {
    SafeExecute([this]() -> void {
        EnterCriticalSection(&m_holdQueueCs);

        for (const auto& entry : m_holdQueue) {
            DestroyBlock(entry.rawPtr);
        }

        m_holdQueue.clear();
        stats.holdQueueSize.store(0);

        LeaveCriticalSection(&m_holdQueueCs);

        LogMessage("[MemorySafety] Hold队列已清空");
        }, "DrainHoldQueue");
}

size_t MemorySafety::GetHoldQueueSize() const noexcept {
    return stats.holdQueueSize.load();
}

void MemorySafety::ForceCleanup() noexcept {
    SafeExecute([this]() -> void {
        LogMessage("[MemorySafety] 开始强制清理");

        // 清空Hold队列
        DrainHoldQueue();

        // 清理所有缓存的一半
        for (size_t i = 0; i < MemorySafetyConst::SIZE_CLASS_COUNT; ++i) {
            EnterCriticalSection(&m_cacheCs[i]);
            size_t removeCount = m_sizeClassCaches[i].freeBlocks.size() / 2;
            LeaveCriticalSection(&m_cacheCs[i]);

            if (removeCount > 0) {
                CleanupSizeClass(i, removeCount);
            }
        }

        m_lastCleanupTime.store(MemorySafetyUtils::GetTickCount());
        stats.forceCleanups.fetch_add(1);

        LogMessage("[MemorySafety] 强制清理完成");
        }, "ForceCleanup");
}

bool MemorySafety::IsMemoryUnderPressure() const noexcept {
    size_t vmUsage = GetProcessVirtualMemoryUsage();
    return vmUsage > m_memoryWatermark.load();
}

size_t MemorySafety::GetTotalCached() const noexcept {
    size_t total = 0;

    for (size_t i = 0; i < MemorySafetyConst::SIZE_CLASS_COUNT; ++i) {
        EnterCriticalSection(&m_cacheCs[i]);
        total += m_sizeClassCaches[i].totalCached;
        LeaveCriticalSection(&m_cacheCs[i]);
    }

    return total;
}

bool MemorySafety::ShouldTriggerCleanup() const noexcept {
    DWORD currentTime = MemorySafetyUtils::GetTickCount();
    DWORD lastCleanup = m_lastCleanupTime.load();

    if (currentTime - lastCleanup < MemorySafetyConst::MIN_CLEANUP_INTERVAL_MS) {
        return false;
    }

    return IsMemoryUnderPressure() || GetTotalCached() > m_maxCacheSize.load();
}

void MemorySafety::AddToHashTable(void* userPtr, const BlockInfo& info) noexcept {
    EnterCriticalSection(&m_hashTableCs);
    m_blockHashTable[userPtr] = info;
    LeaveCriticalSection(&m_hashTableCs);
}

bool MemorySafety::RemoveFromHashTable(void* userPtr, BlockInfo* outInfo) noexcept {
    EnterCriticalSection(&m_hashTableCs);

    auto it = m_blockHashTable.find(userPtr);
    if (it == m_blockHashTable.end()) {
        LeaveCriticalSection(&m_hashTableCs);
        return false;
    }

    if (outInfo) {
        *outInfo = it->second;
    }

    m_blockHashTable.erase(it);
    LeaveCriticalSection(&m_hashTableCs);

    return true;
}

bool MemorySafety::FindInHashTable(void* userPtr, BlockInfo* outInfo) const noexcept {
    EnterCriticalSection(&m_hashTableCs);

    auto it = m_blockHashTable.find(userPtr);
    if (it == m_blockHashTable.end()) {
        LeaveCriticalSection(&m_hashTableCs);
        return false;
    }

    if (outInfo) {
        *outInfo = it->second;
    }

    LeaveCriticalSection(&m_hashTableCs);
    return true;
}

size_t MemorySafety::GetProcessVirtualMemoryUsage() const noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc = { sizeof(pmc) };
    if (GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        return pmc.PrivateUsage;
    }
    return 0;
}

void MemorySafety::SetHoldTimeMs(DWORD timeMs) noexcept {
    m_holdTimeMs.store(timeMs);
    LogMessage("[MemorySafety] 缓冲时间设置为 %u ms", timeMs);
}

void MemorySafety::SetWatermarkMB(size_t watermarkMB) noexcept {
    m_memoryWatermark.store(watermarkMB * 1024 * 1024);
    LogMessage("[MemorySafety] 内存水位设置为 %zu MB", watermarkMB);
}

void MemorySafety::SetMaxCacheSize(size_t maxCacheMB) noexcept {
    m_maxCacheSize.store(maxCacheMB * 1024 * 1024);
    LogMessage("[MemorySafety] 最大缓存设置为 %zu MB", maxCacheMB);
}

void MemorySafety::LogMessage(const char* format, ...) const noexcept {
    EnterCriticalSection(&m_logCs);

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // 控制台输出
    printf("%s\n", buffer);

    // 文件输出
    if (m_logFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        char timeBuffer[64];
        sprintf_s(timeBuffer, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

        DWORD written;
        WriteFile(m_logFile, timeBuffer, static_cast<DWORD>(strlen(timeBuffer)), &written, nullptr);
        WriteFile(m_logFile, buffer, static_cast<DWORD>(strlen(buffer)), &written, nullptr);
        WriteFile(m_logFile, "\r\n", 2, &written, nullptr);
        FlushFileBuffers(m_logFile);
    }

    LeaveCriticalSection(&m_logCs);
}

void MemorySafety::LogError(const char* format, ...) const noexcept {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    LogMessage("[ERROR] %s", buffer);
}

///////////////////////////////////////////////////////////////////////////////
// 工具函数实现
///////////////////////////////////////////////////////////////////////////////

namespace MemorySafetyUtils {
    DWORD GetTickCount() noexcept {
        return ::GetTickCount64() & 0xFFFFFFFF; // 防止64位回绕问题
    }

    bool HasTimeElapsed(DWORD startTime, DWORD intervalMs) noexcept {
        DWORD currentTime = GetTickCount();
        return (currentTime - startTime) >= intervalMs;
    }

    size_t AlignSize(size_t size, size_t alignment) noexcept {
        return (size + alignment - 1) & ~(alignment - 1);
    }

    size_t GetPageAlignedSize(size_t size) noexcept {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return AlignSize(size, si.dwPageSize);
    }

    bool IsValidPointer(void* ptr) noexcept {
        if (!ptr) return false;

        __try {
            volatile char test = *static_cast<char*>(ptr);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

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
}