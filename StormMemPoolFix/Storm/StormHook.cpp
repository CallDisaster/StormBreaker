// ======================== StormHook.cpp 完整修复版本 ========================
#include "pch.h"
#include "StormHook.h"
#include "MemoryPool.h"
#include "Base/Logger.h"
#include "Base/MemorySafety.h"
#include <detours.h>
#include <shared_mutex>
#include <vector>
#include <algorithm>
#include <memory>
#include <cstdint>
#include <unordered_map>

// ======================== 全局变量定义 ========================
Storm_MemAlloc_t       g_origStormAlloc = nullptr;
Storm_MemFree_t        g_origStormFree = nullptr;
Storm_MemReAlloc_t     g_origStormReAlloc = nullptr;
StormHeap_CleanupAll_t g_origCleanupAll = nullptr;
ResetMemoryManager_t   g_origResetMemoryManager = nullptr;

// ======================== 内部状态管理 ========================
namespace {
    // 线程安全的自管块表
    std::shared_mutex g_managedBlocksMutex;
    std::unordered_map<void*, ManagedBlockInfo> g_managedBlocks;

    // 全局状态标志
    std::atomic<bool> g_initialized(false);
    std::atomic<bool> g_inUnsafePeriod(false);
    std::atomic<bool> g_inCleanupAll(false);
    std::atomic<bool> g_inReset(false);

    // 统计信息
    std::atomic<size_t> g_totalAllocatedBlocks(0);
    std::atomic<size_t> g_totalAllocatedBytes(0);
    std::atomic<size_t> g_totalFreedBlocks(0);
    std::atomic<size_t> g_totalFreedBytes(0);

    // 大块分配阈值（64KB）
    std::atomic<size_t> g_largeBlockThreshold{ 128 * 1024 }; // 默认 128 KiB，更安全

    // 线程局部状态（避免递归）
    thread_local bool tls_inHook = false;

    // 真实StormHeap探测
    std::atomic<void*> g_defaultStormHeap{ nullptr };
}

// ======================== SEH包装的辅助函数 ========================
namespace SEH_Helpers {
    DWORD g_lastExceptionCode = 0;

    // SEH包装的内存复制（避免C++对象）
    BOOL SafeMemCopy_SEH(void* dst, const void* src, size_t size) {
        if (!dst || !src || size == 0) return FALSE;

        __try {
            memcpy(dst, src, size);
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return FALSE;
        }
    }

    // SEH包装的头部验证
    BOOL ValidateHeader_SEH(const void* userPtr) {
        if (!userPtr) return FALSE;

        __try {
            const uint8_t* ptr = static_cast<const uint8_t*>(userPtr);
            const StormAllocHeader* header = reinterpret_cast<const StormAllocHeader*>(ptr - sizeof(StormAllocHeader));

            // 验证魔数
            if (header->magic != STORM_FRONT_MAGIC) return FALSE;

            // 验证HeapPtr不为空（防止野指针）
            if (!header->heapPtr) return FALSE;

            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return FALSE;
        }
    }

    // SEH包装的原始Storm调用
    void* CallOrigStormAlloc_SEH(int ecx, int edx, size_t size, const char* name, DWORD srcLine, DWORD flags) {
        __try {
            return g_origStormAlloc ? g_origStormAlloc(ecx, edx, size, name, srcLine, flags) : nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return nullptr;
        }
    }

    int CallOrigStormFree_SEH(void* ptr, const char* name, int argList, DWORD flags) {
        __try {
            return g_origStormFree ? g_origStormFree(ptr, name, argList, flags) : 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return 1;
        }
    }

    void* CallOrigStormReAlloc_SEH(int ecx, int edx, void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags) {
        __try {
            return g_origStormReAlloc ? g_origStormReAlloc(ecx, edx, oldPtr, newSize, name, srcLine, flags) : nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return nullptr;
        }
    }

    // === 新增：SEH保护的StormHeap探测函数 ===
    BOOL CaptureHeapFromUserPtr_SEH(const void* userPtr, void** outHeap) {
        if (!userPtr || !outHeap) return FALSE;
        __try {
            const uint8_t* p = (const uint8_t*)userPtr;
            const StormAllocHeader* h = (const StormAllocHeader*)(p - sizeof(StormAllocHeader));
            if (h->magic != STORM_FRONT_MAGIC || !h->heapPtr) return FALSE;
            *outHeap = h->heapPtr;
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return FALSE;
        }
    }

    void* ProbeAlloc32_SEH() {
        __try {
            return g_origStormAlloc ? g_origStormAlloc(0, 0, 32, "probe", 0, 0) : nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
            return nullptr;
        }
    }

    void ProbeFree_SEH(void* p) {
        __try {
            if (g_origStormFree && p) g_origStormFree(p, "probe", 0, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_lastExceptionCode = GetExceptionCode();
        }
    }

    // 获取最后异常代码的函数，用于外部日志记录
    DWORD GetLastExceptionCode() {
        return g_lastExceptionCode;
    }

    // 清除异常代码
    void ClearLastExceptionCode() {
        g_lastExceptionCode = 0;
    }
}

// ======================== 内部实现函数 ========================
namespace StormHook_Internal {

    // 对齐辅助函数
    static inline uint8_t* AlignUp(uint8_t* ptr, size_t alignment) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
        addr = (addr + (alignment - 1)) & ~(uintptr_t)(alignment - 1);
        return reinterpret_cast<uint8_t*>(addr);
    }

    static BOOL __stdcall UpdateHeaderHeapPtr_SEH(void* userPtr, void* newHeap) {
        __try {
            uint8_t* p = (uint8_t*)userPtr;
            StormAllocHeader* h = (StormAllocHeader*)(p - sizeof(StormAllocHeader));
            if (h->magic != STORM_FRONT_MAGIC) return FALSE;
            h->heapPtr = newHeap;
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    // === 新增：StormHeap探测函数 ===
    bool ProbeDefaultStormHeapPointer() {
        if (g_defaultStormHeap.load(std::memory_order_acquire)) return true;
        if (!g_origStormAlloc || !g_origStormFree) return false;

        void* tmp = SEH_Helpers::ProbeAlloc32_SEH();
        if (!tmp) return false;

        void* heap = nullptr;
        if (SEH_Helpers::CaptureHeapFromUserPtr_SEH(tmp, &heap) && heap) {
            void* expected = nullptr;
            g_defaultStormHeap.compare_exchange_strong(expected, heap, std::memory_order_acq_rel);
        }

        SEH_Helpers::ProbeFree_SEH(tmp);
        return g_defaultStormHeap.load(std::memory_order_acquire) != nullptr;
    }

    void* GetDefaultStormHeap() {
        return g_defaultStormHeap.load(std::memory_order_acquire);
    }

    void TryCaptureDefaultHeapFromAllocResult(void* userPtr) {
        if (GetDefaultStormHeap() || !userPtr) return;

        void* heap = nullptr;
        if (SEH_Helpers::CaptureHeapFromUserPtr_SEH(userPtr, &heap) && heap) {
            void* expected = nullptr;
            g_defaultStormHeap.compare_exchange_strong(expected, heap, std::memory_order_acq_rel);
        }
    }

    bool RegisterManagedBlock(void* userPtr, const ManagedBlockInfo& info) {
        if (!userPtr) return false;

        std::unique_lock<std::shared_mutex> lock(g_managedBlocksMutex);

        // 检查是否已存在
        if (g_managedBlocks.find(userPtr) != g_managedBlocks.end()) {
            Logger::GetInstance().LogWarning("尝试注册已存在的管理块: %p", userPtr);
            return false;
        }

        g_managedBlocks[userPtr] = info;
        g_totalAllocatedBlocks.fetch_add(1, std::memory_order_relaxed);
        g_totalAllocatedBytes.fetch_add(info.originalSize, std::memory_order_relaxed);

        return true;
    }

    void FixHeadersAfterReset(void* newHeap) {
        if (!newHeap) return;

        std::vector<void*> snapshot;
        {
            std::shared_lock<std::shared_mutex> lock(g_managedBlocksMutex);
            snapshot.reserve(g_managedBlocks.size());
            for (const auto& kv : g_managedBlocks) snapshot.push_back(kv.first);
        }

        size_t ok = 0, fail = 0;
        for (void* up : snapshot) {
            if (UpdateHeaderHeapPtr_SEH(up, newHeap)) ++ok; else ++fail;
        }
        Logger::GetInstance().LogInfo("Reset后已修复heapPtr: 成功=%zu, 失败=%zu", ok, fail);
    }

    bool UnregisterManagedBlock(void* userPtr) {
        if (!userPtr) return false;

        std::unique_lock<std::shared_mutex> lock(g_managedBlocksMutex);

        auto it = g_managedBlocks.find(userPtr);
        if (it == g_managedBlocks.end()) {
            return false;
        }

        g_totalFreedBlocks.fetch_add(1, std::memory_order_relaxed);
        g_totalFreedBytes.fetch_add(it->second.originalSize, std::memory_order_relaxed);

        g_managedBlocks.erase(it);
        return true;
    }

    bool GetManagedBlockInfo(void* userPtr, ManagedBlockInfo& info) {
        if (!userPtr) return false;

        std::shared_lock<std::shared_mutex> lock(g_managedBlocksMutex);

        auto it = g_managedBlocks.find(userPtr);
        if (it == g_managedBlocks.end()) {
            return false;
        }

        info = it->second;
        return true;
    }

    // === 修改：使用真实StormHeap指针 ===
    void SetupStormCompatibleHeader(void* userPtr, size_t size) {
        if (!userPtr) return;

        uint8_t* ptr = static_cast<uint8_t*>(userPtr);
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(ptr - sizeof(StormAllocHeader));

        header->size = static_cast<uint16_t>(size & 0xFFFF);
        // padding 已在 AllocateMemory 里设置
        header->flags = 0; // 关键：不设置大页标记(0x4)

        // 关键：写入"真实"的 StormHeap*，而不是函数地址或模块句柄
        void* realHeap = GetDefaultStormHeap();
        header->heapPtr = realHeap;   // 由探测流程保证非空
        header->magic = STORM_FRONT_MAGIC;

        Logger::GetInstance().LogDebug("设置Storm兼容头: ptr=%p, size=%zu, heapPtr=%p",
            userPtr, size, header->heapPtr);
    }

    bool ValidateStormHeader(void* userPtr) {
        return SEH_Helpers::ValidateHeader_SEH(userPtr) == TRUE;
    }

    size_t GetBlockSizeFromHeader(void* userPtr) {
        if (!ValidateStormHeader(userPtr)) {
            return 0;
        }

        const uint8_t* ptr = static_cast<const uint8_t*>(userPtr);
        const StormAllocHeader* header = reinterpret_cast<const StormAllocHeader*>(ptr - sizeof(StormAllocHeader));

        return header->size;
    }

    size_t GetBlockSizeFromManagedTable(void* userPtr) {
        ManagedBlockInfo info;
        if (GetManagedBlockInfo(userPtr, info)) {
            return info.originalSize;
        }
        return 0;
    }

    void EnterUnsafePeriod() {
        g_inUnsafePeriod.store(true, std::memory_order_release);
        Logger::GetInstance().LogDebug("进入不安全期");
    }

    void ExitUnsafePeriod() {
        g_inUnsafePeriod.store(false, std::memory_order_release);
        Logger::GetInstance().LogDebug("退出不安全期");
    }
}

// ======================== 公共接口实现 ========================
namespace StormHook {

    bool Initialize() {
        if (g_initialized.exchange(true, std::memory_order_acq_rel)) {
            return true; // 已初始化
        }

        Logger::GetInstance().LogInfo("初始化StormHook系统...");

        // 初始化内存池
        if (!MemoryPool::Initialize()) {
            Logger::GetInstance().LogError("内存池初始化失败");
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        // 初始化内存安全系统
        if (!MemorySafety::GetInstance().Initialize()) {
            Logger::GetInstance().LogError("内存安全系统初始化失败");
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        // === 新增：主动探测默认StormHeap* ===
        StormHook_Internal::ProbeDefaultStormHeapPointer();

        Logger::GetInstance().LogInfo("StormHook系统初始化完成");
        return true;
    }

    void Shutdown() {
        if (!g_initialized.exchange(false, std::memory_order_acq_rel)) {
            return; // 未初始化
        }

        Logger::GetInstance().LogInfo("关闭StormHook系统...");

        // 清理所有管理的块
        FlushManagedBlocks();

        // 关闭内存安全系统
        MemorySafety::GetInstance().Shutdown();

        // 关闭内存池
        MemoryPool::Shutdown();

        Logger::GetInstance().LogInfo("StormHook系统已关闭");
    }

    bool IsOurBlock(void* userPtr) {
        if (!userPtr || !g_initialized.load(std::memory_order_acquire)) {
            return false;
        }

        // 快速检查：是否在我们的管理表中
        std::shared_lock<std::shared_mutex> lock(g_managedBlocksMutex);
        return g_managedBlocks.find(userPtr) != g_managedBlocks.end();
    }

    bool IsInUnsafePeriod() {
        return g_inUnsafePeriod.load(std::memory_order_acquire) ||
            g_inCleanupAll.load(std::memory_order_acquire) ||
            g_inReset.load(std::memory_order_acquire);
    }

    void SetLargeBlockThreshold(size_t bytes) {
        if (bytes < 64 * 1024) bytes = 64 * 1024; // 最低不小于 64 KiB
        g_largeBlockThreshold.store(bytes, std::memory_order_release);
        Logger::GetInstance().LogInfo("大块拦截阈值已设置为: %zu KiB", bytes / 1024);
    }

    size_t GetLargeBlockThreshold() {
        return g_largeBlockThreshold.load(std::memory_order_acquire);
    }

    // === 修改：未获得真实StormHeap则不拦截 ===
    void* AllocateMemory(size_t size, const char* name, DWORD srcLine) {
        if (!g_initialized.load(std::memory_order_acquire) || tls_inHook) {
            return nullptr;
        }

        // 修改：使用可调阈值
        if (size < g_largeBlockThreshold.load(std::memory_order_acquire)) {
            return nullptr;
        }

        // 在不安全期间直接回退到原生分配
        if (IsInUnsafePeriod()) {
            return nullptr;
        }

        // 未探测到真实StormHeap则回退
        if (!StormHook_Internal::GetDefaultStormHeap()) {
            return nullptr;
        }

        tls_inHook = true;

        // 计算总需要的大小：头部 + 用户数据 + 对齐余量
        const size_t headerSize = sizeof(StormAllocHeader);
        const size_t alignment = 16;
        const size_t totalNeeded = size + headerSize + (alignment - 1);

        // 从TLSF分配原始内存（不使用AllocateAligned，我们自己处理对齐）
        void* rawPtr = MemoryPool::Allocate(totalNeeded);
        if (!rawPtr) {
            Logger::GetInstance().LogError("TLSF分配失败: size=%zu", totalNeeded);
            tls_inHook = false;
            return nullptr;
        }

        // 计算对齐后的用户指针位置
        uint8_t* rawBytes = static_cast<uint8_t*>(rawPtr);
        uint8_t* userPtr = StormHook_Internal::AlignUp(rawBytes + headerSize, alignment);

        // 验证有足够空间放置头部
        const size_t actualHeaderOffset = static_cast<size_t>(userPtr - rawBytes);
        if (actualHeaderOffset < headerSize) {
            Logger::GetInstance().LogError("对齐计算错误: headerOffset=%zu < headerSize=%zu",
                actualHeaderOffset, headerSize);
            MemoryPool::Free(rawPtr);
            tls_inHook = false;
            return nullptr;
        }

        // 设置头部中的padding字段（记录额外的偏移量）
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(userPtr - headerSize);
        header->padding = static_cast<uint8_t>(actualHeaderOffset - headerSize);

        // 设置Storm兼容头部（现在使用真实StormHeap指针）
        StormHook_Internal::SetupStormCompatibleHeader(userPtr, size);

        // 注册到管理表
        ManagedBlockInfo info;
        info.magic = STORMBREAKER_MAGIC;
        info.originalSize = size;
        info.rawPtr = rawPtr;
        info.timestamp = GetTickCount();

        if (!StormHook_Internal::RegisterManagedBlock(userPtr, info)) {
            Logger::GetInstance().LogError("注册管理块失败: ptr=%p", userPtr);
            MemoryPool::Free(rawPtr);
            tls_inHook = false;
            return nullptr;
        }

        // 注册到内存安全系统（在非不安全期间）
        if (!IsInUnsafePeriod()) {
            MemorySafety::GetInstance().RegisterMemoryBlock(rawPtr, userPtr, size, name, srcLine);
        }

        // 减少频繁的Debug日志输出，只在大块分配时记录
        if (size >= 1024 * 1024) {  // 只记录1MB以上的大块分配
            Logger::GetInstance().LogInfo("分配大块: user=%p, size=%zu MB", userPtr, size / (1024 * 1024));
        }

        tls_inHook = false;
        return userPtr;
    }

    bool FreeMemory(void* ptr) {
        if (!ptr || !g_initialized.load(std::memory_order_acquire) || tls_inHook) {
            return false;
        }

        tls_inHook = true;

        // 获取管理块信息
        ManagedBlockInfo info;
        if (!StormHook_Internal::GetManagedBlockInfo(ptr, info)) {
            tls_inHook = false;
            return false; // 不是我们管理的块
        }

        // 从管理表中移除（一定要先移，避免地址复用撞车）
        if (!StormHook_Internal::UnregisterManagedBlock(ptr)) {
            Logger::GetInstance().LogError("移除管理块失败: ptr=%p", ptr);
        }

        // 关键改动：无论是否处于不安全期，都尽力把 MemorySafety 的登记移除，避免"重复注册"
        MemorySafety::GetInstance().TryUnregisterBlock(ptr);

        // 释放 TLSF 内存
        MemoryPool::Free(info.rawPtr);

        if (info.originalSize >= 1024 * 1024) {
            Logger::GetInstance().LogInfo("释放大块: ptr=%p, size=%zu MB",
                ptr, info.originalSize / (1024 * 1024));
        }

        tls_inHook = false;
        return true;
    }

    void* ReallocMemory(void* oldPtr, size_t newSize, const char* name, DWORD srcLine) {
        if (!g_initialized.load(std::memory_order_acquire) || tls_inHook) {
            return nullptr;
        }

        // 处理边界情况
        if (!oldPtr) {
            return AllocateMemory(newSize, name, srcLine);
        }

        if (newSize == 0) {
            FreeMemory(oldPtr);
            return nullptr;
        }

        tls_inHook = true;

        // 获取旧块信息
        ManagedBlockInfo oldInfo;
        if (!StormHook_Internal::GetManagedBlockInfo(oldPtr, oldInfo)) {
            tls_inHook = false;
            return nullptr; // 不是我们管理的块
        }

        // 如果新大小不需要大块处理，返回失败让调用者处理
        if (newSize < GetLargeBlockThreshold()) {
            tls_inHook = false;
            return nullptr;
        }

        // 分配新块（会自动处理对齐）
        void* newPtr = AllocateMemory(newSize, name, srcLine);
        if (!newPtr) {
            Logger::GetInstance().LogError("重分配新块失败: size=%zu", newSize);
            tls_inHook = false;
            return nullptr;
        }

        // 复制数据（取较小的大小）
        size_t copySize = (oldInfo.originalSize < newSize) ? oldInfo.originalSize : newSize;
        if (!SEH_Helpers::SafeMemCopy_SEH(newPtr, oldPtr, copySize)) {
            Logger::GetInstance().LogError("重分配数据复制失败");
            FreeMemory(newPtr);
            tls_inHook = false;
            return nullptr;
        }

        // 释放旧块
        FreeMemory(oldPtr);

        Logger::GetInstance().LogDebug("成功重分配: old=%p->new=%p, oldSize=%zu->newSize=%zu",
            oldPtr, newPtr, oldInfo.originalSize, newSize);

        tls_inHook = false;
        return newPtr;
    }

    void FlushManagedBlocks() {
        Logger::GetInstance().LogInfo("清理所有管理块...");

        std::vector<void*> blocksToFree;

        {
            std::shared_lock<std::shared_mutex> lock(g_managedBlocksMutex);
            blocksToFree.reserve(g_managedBlocks.size());

            for (const auto& pair : g_managedBlocks) {
                blocksToFree.push_back(pair.first);
            }
        }

        for (void* ptr : blocksToFree) {
            FreeMemory(ptr);
        }

        Logger::GetInstance().LogInfo("清理完成，共清理%zu个块", blocksToFree.size());
    }

    void ProcessDeferredFree() {
        MemorySafety::GetInstance().ProcessDeferredFreeQueue();
    }

    size_t GetManagedBlockCount() {
        return g_totalAllocatedBlocks.load(std::memory_order_relaxed) -
            g_totalFreedBlocks.load(std::memory_order_relaxed);
    }

    size_t GetTotalManagedSize() {
        return g_totalAllocatedBytes.load(std::memory_order_relaxed) -
            g_totalFreedBytes.load(std::memory_order_relaxed);
    }

    void PrepareForReset() {
        Logger::GetInstance().LogDebug("准备Reset，进入不安全期...");
        g_inReset.store(true, std::memory_order_release);

        // 我们自己的不安全期
        StormHook_Internal::EnterUnsafePeriod();
        // 让 MemorySafety 也进入不安全期
        MemorySafety::GetInstance().EnterUnsafePeriod();

        // 为避免 Reset 过程后半段才去 free，尽量在 Reset 前清空延迟队列
        MemorySafety::GetInstance().FlushDeferredFreeQueue();

        // 清理 TLSF 空闲页
        MemoryPool::TrimFreePages();
    }

    void PostReset() {
        Logger::GetInstance().LogDebug("Reset完成，开始收尾...");

        // Reset 后，Storm 会重建 StormHeap，先重探一次默认 StormHeap*
        (void)StormHook_Internal::ProbeDefaultStormHeapPointer();
        void* newHeap = StormHook_Internal::GetDefaultStormHeap();

        // 用新的 StormHeap* 修我们头里的 heapPtr，避免后续校验/回收踩旧堆
        StormHook_Internal::FixHeadersAfterReset(newHeap);

        // 先退出 MemorySafety 的不安全期，再处理可能积压的延迟释放
        MemorySafety::GetInstance().ExitUnsafePeriod();
        MemorySafety::GetInstance().ProcessDeferredFreeQueue();

        // 退出我们的不安全期
        StormHook_Internal::ExitUnsafePeriod();
        g_inReset.store(false, std::memory_order_release);

        Logger::GetInstance().LogInfo("ResetMemoryManager完成");
    }

    // 新增：验证指针是否正确对齐
    bool IsPointerAligned(void* ptr, size_t alignment) {
        if (!ptr) return false;
        return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
    }

    // 新增：验证我们分配的内存是否正确对齐
    bool ValidateBlockAlignment(void* userPtr) {
        if (!userPtr || !IsOurBlock(userPtr)) {
            return false;
        }

        // 检查用户指针是否16字节对齐
        if (!IsPointerAligned(userPtr, 16)) {
            Logger::GetInstance().LogError("用户指针未正确16字节对齐: %p", userPtr);
            return false;
        }

        // 验证头部位置
        const uint8_t* ptr = static_cast<const uint8_t*>(userPtr);
        const StormAllocHeader* header = reinterpret_cast<const StormAllocHeader*>(ptr - sizeof(StormAllocHeader));

        // 检查魔数
        if (header->magic != STORM_FRONT_MAGIC) {
            Logger::GetInstance().LogError("头部魔数不正确: %p, magic=0x%04X", userPtr, header->magic);
            return false;
        }

        // 检查HeapPtr是否有效
        if (!header->heapPtr) {
            Logger::GetInstance().LogError("头部heapPtr为空: %p", userPtr);
            return false;
        }

        return true;
    }
}

// ======================== Hook函数实现 ========================

void* __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
    const char* name, DWORD srcLine, DWORD flags) {
    // 尝试用我们的系统分配
    void* ptr = StormHook::AllocateMemory(size, name, srcLine);
    if (ptr) {
        return ptr;
    }

    // 回退到原始Storm分配
    void* result = SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, size, name, srcLine, flags);

    // === 新增：顺手被动抓一次StormHeap ===
    StormHook_Internal::TryCaptureDefaultHeapFromAllocResult(result);

    // 检查是否有异常发生
    DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
    if (exceptCode != 0) {
        Logger::GetInstance().LogError("Storm原始分配函数异常: size=%zu, code=0x%08X", size, exceptCode);
        SEH_Helpers::ClearLastExceptionCode();
    }

    return result;
}

int __stdcall Hooked_Storm_MemFree(void* ptr, const char* name, int argList, DWORD flags) {
    if (!ptr) {
        return 1; // NULL指针认为成功
    }

    // 尝试用我们的系统释放
    if (StormHook::FreeMemory(ptr)) {
        return 1; // 成功
    }

    // 回退到原始Storm释放
    int result = SEH_Helpers::CallOrigStormFree_SEH(ptr, name, argList, flags);

    // 检查是否有异常发生
    DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
    if (exceptCode != 0) {
        Logger::GetInstance().LogError("Storm原始释放函数异常: ptr=%p, code=0x%08X", ptr, exceptCode);
        SEH_Helpers::ClearLastExceptionCode();
    }

    return result;
}

void* __fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void* oldPtr, size_t newSize,
    const char* name, DWORD srcLine, DWORD flags) {
    // 尝试用我们的系统重分配
    void* ptr = StormHook::ReallocMemory(oldPtr, newSize, name, srcLine);
    if (ptr) {
        return ptr;
    }

    // 如果oldPtr是我们管理的但新大小不需要大块处理，需要手动迁移
    if (oldPtr && StormHook::IsOurBlock(oldPtr) && newSize > 0) {
        // 使用Storm分配新内存
        void* newPtr = SEH_Helpers::CallOrigStormAlloc_SEH(ecx, edx, newSize, name, srcLine, flags);

        if (newPtr) {
            // 复制数据
            size_t oldSize = StormHook_Internal::GetBlockSizeFromManagedTable(oldPtr);
            size_t copySize = (oldSize < newSize) ? oldSize : newSize;

            if (SEH_Helpers::SafeMemCopy_SEH(newPtr, oldPtr, copySize)) {
                // 释放旧块
                StormHook::FreeMemory(oldPtr);
                return newPtr;
            }
            else {
                // 复制失败，释放新分配的内存
                SEH_Helpers::CallOrigStormFree_SEH(newPtr, name, 0, 0);
            }
        }

        return nullptr;
    }

    // 回退到原始Storm重分配
    void* result = SEH_Helpers::CallOrigStormReAlloc_SEH(ecx, edx, oldPtr, newSize, name, srcLine, flags);

    // 检查是否有异常发生
    DWORD exceptCode = SEH_Helpers::GetLastExceptionCode();
    if (exceptCode != 0) {
        Logger::GetInstance().LogError("Storm原始重分配函数异常: ptr=%p, size=%zu, code=0x%08X",
            oldPtr, newSize, exceptCode);
        SEH_Helpers::ClearLastExceptionCode();
    }

    return result;
}

void __stdcall Hooked_StormHeap_CleanupAll() {
    // 防止递归调用
    if (g_inCleanupAll.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    // 使用静态变量控制日志频率，避免刷屏
    static std::atomic<DWORD> lastLogTime{ 0 };
    static std::atomic<size_t> callCount{ 0 };

    DWORD currentTime = GetTickCount();
    size_t currentCount = callCount.fetch_add(1, std::memory_order_relaxed);

    // 只有在超过1秒间隔或者是错误时才记录日志
    bool shouldLog = (currentTime - lastLogTime.load(std::memory_order_relaxed) > 1000) || (currentCount % 100 == 0);

    if (shouldLog) {
        lastLogTime.store(currentTime, std::memory_order_relaxed);
        Logger::GetInstance().LogDebug("CleanupAll调用 (第%zu次)", currentCount);
    }

    StormHook_Internal::EnterUnsafePeriod();

    // 安全执行原始CleanupAll
    __try {
        if (g_origCleanupAll) {
            g_origCleanupAll();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError("CleanupAll执行异常: 0x%08X (调用次数: %zu)", GetExceptionCode(), currentCount);
    }

    // 处理延迟释放
    StormHook::ProcessDeferredFree();

    StormHook_Internal::ExitUnsafePeriod();
    g_inCleanupAll.store(false, std::memory_order_release);
}

int __fastcall Hooked_ResetMemoryManager(void* thiz, int edx, int a2, void (*pump)(void)) {
    Logger::GetInstance().LogInfo("开始ResetMemoryManager...");

    // Reset前准备
    StormHook::PrepareForReset();

    int result = 0;

    // 安全执行原始Reset
    __try {
        if (g_origResetMemoryManager) {
            result = g_origResetMemoryManager(thiz, edx, a2, pump);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::GetInstance().LogError("ResetMemoryManager执行异常: 0x%08X", GetExceptionCode());
    }

    // Reset后清理
    StormHook::PostReset();

    Logger::GetInstance().LogInfo("ResetMemoryManager完成");
    return result;
}