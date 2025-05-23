#include "pch.h"
//// #include "StormHook.h" // Moved lower
//#include <Windows.h>
//#include <cstdio>
//#include <map>
//#include <mutex>
//#include <detours.h>
//#include <cstring>
//#include <iostream>
//#include <intrin.h>
//#include <unordered_set>
//#include <unordered_map>
//#include "StormOffsets.h"
//#include "StormHook.h" // Include after StormOffsets.h
//#include "MemoryPool.h"
//#include <shared_mutex>
//
//// 当块被 free 后, Storm 通常把头4字节改成 size(WORD) + AlignPadding(BYTE) + Flags(BYTE=2) + pNext
//#pragma pack(push,1)
//struct StormFreeBlock
//{
//    WORD  size;         // 包含头部在内的“整块大小”，= (sizeof(StormFreeBlock) + 用户区 + 可能余的边界)
//    BYTE  AlignPadding; // 对齐
//    BYTE  Flags;        // 0x2=free
//    StormFreeBlock* pNext; // 后面链接
//};
//#pragma pack(pop)
//
//enum class BlockState {
//    Normal,      // 正常状态
//    Reset,       // 已MEM_RESET
//    Decommitted, // 已MEM_DECOMMIT (仅用于特殊情况)
//    Invalid      // 无效状态
//};
//
//struct BlockStateInfoEx {
//    std::atomic<BlockState> state{ BlockState::Normal };
//    std::atomic<size_t> size{ 0 };
//    std::atomic<DWORD> timestamp{ 0 };
//    std::atomic<uint32_t> version{ 0 };  // 版本号，用于CAS操作
//    char operation[64];  // 固定大小避免动态分配
//    std::mutex opMutex;  // 保护operation字段
//
//    BlockStateInfoEx() {
//        operation[0] = '\0';
//    }
//
//    // 设置操作描述（线程安全）
//    void SetOperation(const char* op) {
//        std::lock_guard<std::mutex> lock(opMutex);
//        strncpy_s(operation, op, _countof(operation) - 1);
//    }
//
//    // 获取操作描述（线程安全）
//    std::string GetOperation() const {
//        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(opMutex));
//        return std::string(operation);
//    }
//};
//
//// ============== 全局数据 ==============
//static std::unordered_map<void*, size_t> g_DecommittedBlocks;
//static std::mutex g_DecommitLock;
//
//// Define static variables for hook statistics, limiting scope to this file
//std::atomic<size_t> g_freedByAllocHook{ 0 };
//std::atomic<size_t> g_freedByFreeHook{ 0 };
//static size_t g_peakMemoryUsed = 0;
//
//static std::unordered_map<void*, size_t> g_ResetBlocks;
//static std::mutex g_ResetLock;  // 改名对应的锁
//
//
//// StormOffsets 里定义的全局:
//extern uintptr_t gStormDllBase;
//inline size_t StormFix_GetCurrentUsage()
//{
//    if (Storm_g_TotalAllocatedMemory)
//        return Storm_g_TotalAllocatedMemory;
//    return 0;
//}
//
//class BlockReferenceCounter {
//private:
//    struct RefCountInfo {
//        std::atomic<int> refCount{ 0 };
//        size_t blockSize{ 0 };
//        DWORD lastAccessTime{ 0 };
//        bool isHotBlock{ false };  // 热点块标记
//    };
//
//    mutable std::shared_mutex m_mutex;
//    std::unordered_map<void*, RefCountInfo> m_refCounts;
//
//    // 配置参数
//    static constexpr size_t MIN_RESET_SIZE = 1024 * 1024;      // 1MB - 只对大块使用RESET
//    static constexpr size_t MIN_DECOMMIT_SIZE = 16 * 1024 * 1024; // 16MB - 更大的块才考虑DECOMMIT
//    static constexpr DWORD HOT_BLOCK_THRESHOLD = 5000;         // 5秒内访问过的认为是热块
//
//public:
//    // 增加引用
//    void AddRef(void* block) {
//        std::unique_lock<std::shared_mutex> lock(m_mutex);
//        auto& info = m_refCounts[block];
//        info.refCount++;
//        info.lastAccessTime = GetTickCount();
//    }
//
//    // 减少引用
//    int Release(void* block) {
//        std::unique_lock<std::shared_mutex> lock(m_mutex);
//        auto it = m_refCounts.find(block);
//        if (it != m_refCounts.end()) {
//            int newCount = --it->second.refCount;
//            if (newCount <= 0) {
//                m_refCounts.erase(it);
//                return 0;
//            }
//            return newCount;
//        }
//        return 0;
//    }
//
//    // 获取引用计数
//    int GetRefCount(void* block) const {
//        std::shared_lock<std::shared_mutex> lock(m_mutex);
//        auto it = m_refCounts.find(block);
//        return (it != m_refCounts.end()) ? it->second.refCount.load() : 0;
//    }
//
//    // 设置块信息
//    void SetBlockInfo(void* block, size_t size) {
//        std::unique_lock<std::shared_mutex> lock(m_mutex);
//        auto& info = m_refCounts[block];
//        info.blockSize = size;
//        info.lastAccessTime = GetTickCount();
//    }
//
//    // 检查是否是热点块
//    bool IsHotBlock(void* block) const {
//        std::shared_lock<std::shared_mutex> lock(m_mutex);
//        auto it = m_refCounts.find(block);
//        if (it != m_refCounts.end()) {
//            DWORD currentTime = GetTickCount();
//            return (currentTime - it->second.lastAccessTime) < HOT_BLOCK_THRESHOLD;
//        }
//        return false;
//    }
//
//    // 获取内存优化策略
//    enum class OptimizationStrategy {
//        None,       // 不优化
//        Reset,      // 使用MEM_RESET
//        Decommit    // 使用MEM_DECOMMIT（极少使用）
//    };
//
//    OptimizationStrategy GetOptimizationStrategy(void* block, size_t blockSize) {
//        // 检查引用计数
//        if (GetRefCount(block) > 0) {
//            return OptimizationStrategy::None;
//        }
//
//        // 检查是否是热点块
//        if (IsHotBlock(block)) {
//            return OptimizationStrategy::None;
//        }
//
//        // 根据大小决定策略
//        if (blockSize >= MIN_DECOMMIT_SIZE) {
//            // 超大块且长时间未使用，可以考虑DECOMMIT
//            std::shared_lock<std::shared_mutex> lock(m_mutex);
//            auto it = m_refCounts.find(block);
//            if (it != m_refCounts.end()) {
//                DWORD idleTime = GetTickCount() - it->second.lastAccessTime;
//                if (idleTime > 60000) {  // 1分钟未使用
//                    return OptimizationStrategy::Decommit;
//                }
//            }
//        }
//
//        if (blockSize >= MIN_RESET_SIZE) {
//            return OptimizationStrategy::Reset;
//        }
//
//        return OptimizationStrategy::None;
//    }
//};
//
//// 全局引用计数器
//static BlockReferenceCounter g_blockRefCounter;
//
//class AtomicBlockStateManager {
//private:
//    mutable std::shared_mutex m_mapMutex;
//    std::unordered_map<void*, std::unique_ptr<BlockStateInfoEx>> m_states;
//
//public:
//    // 原子性状态转换
//    bool TransitionState(void* ptr, BlockState expectedState, BlockState newState,
//        size_t size, const char* operation) {
//        std::unique_lock<std::shared_mutex> lock(m_mapMutex);
//
//        // 获取或创建状态信息
//        auto& stateInfo = m_states[ptr];
//        if (!stateInfo) {
//            stateInfo = std::make_unique<BlockStateInfoEx>();
//        }
//
//        // 尝试原子性状态转换
//        BlockState currentState = stateInfo->state.load(std::memory_order_acquire);
//        if (currentState != expectedState) {
//            LogMessage("[StateTransition] 状态不匹配: ptr=%p, 期望=%d, 实际=%d",
//                ptr, expectedState, currentState);
//            return false;
//        }
//
//        // 执行状态转换
//        uint32_t oldVersion = stateInfo->version.load(std::memory_order_relaxed);
//
//        stateInfo->state.store(newState, std::memory_order_release);
//        stateInfo->size.store(size, std::memory_order_relaxed);
//        stateInfo->timestamp.store(GetTickCount(), std::memory_order_relaxed);
//        stateInfo->SetOperation(operation);
//        stateInfo->version.store(oldVersion + 1, std::memory_order_release);
//
//        LogMessage("[StateTransition] 成功: ptr=%p, %d -> %d, 版本=%u, 操作=%s",
//            ptr, expectedState, newState, oldVersion + 1, operation);
//
//        return true;
//    }
//
//    // 获取当前状态（带版本号）
//    struct StateSnapshot {
//        BlockState state;
//        size_t size;
//        DWORD timestamp;
//        uint32_t version;
//        std::string operation;
//        bool valid;
//    };
//
//    StateSnapshot GetState(void* ptr) const {
//        std::shared_lock<std::shared_mutex> lock(m_mapMutex);
//
//        auto it = m_states.find(ptr);
//        if (it == m_states.end() || !it->second) {
//            return { BlockState::Normal, 0, 0, 0, "", false };
//        }
//
//        const auto& info = *it->second;
//
//        // 原子性读取所有字段
//        uint32_t version1 = info.version.load(std::memory_order_acquire);
//        StateSnapshot snapshot;
//        snapshot.state = info.state.load(std::memory_order_relaxed);
//        snapshot.size = info.size.load(std::memory_order_relaxed);
//        snapshot.timestamp = info.timestamp.load(std::memory_order_relaxed);
//        snapshot.operation = info.GetOperation();
//        uint32_t version2 = info.version.load(std::memory_order_acquire);
//
//        // 确保读取期间没有发生修改
//        snapshot.valid = (version1 == version2);
//        snapshot.version = version1;
//
//        return snapshot;
//    }
//
//    // 条件更新（CAS操作）
//    bool ConditionalUpdate(void* ptr, uint32_t expectedVersion, BlockState newState,
//        size_t size, const char* operation) {
//        std::unique_lock<std::shared_mutex> lock(m_mapMutex);
//
//        auto it = m_states.find(ptr);
//        if (it == m_states.end() || !it->second) {
//            return false;
//        }
//
//        auto& info = *it->second;
//        uint32_t currentVersion = info.version.load(std::memory_order_acquire);
//
//        if (currentVersion != expectedVersion) {
//            return false;  // 版本不匹配，其他线程已修改
//        }
//
//        // 执行更新
//        info.state.store(newState, std::memory_order_release);
//        info.size.store(size, std::memory_order_relaxed);
//        info.timestamp.store(GetTickCount(), std::memory_order_relaxed);
//        info.SetOperation(operation);
//        info.version.store(currentVersion + 1, std::memory_order_release);
//
//        return true;
//    }
//
//    // 清理过期状态
//    void CleanupExpiredStates(DWORD expirationMs = 300000) {  // 默认5分钟
//        std::unique_lock<std::shared_mutex> lock(m_mapMutex);
//
//        DWORD currentTime = GetTickCount();
//        auto it = m_states.begin();
//
//        while (it != m_states.end()) {
//            if (it->second) {
//                DWORD timestamp = it->second->timestamp.load(std::memory_order_relaxed);
//                if (currentTime - timestamp > expirationMs) {
//                    it = m_states.erase(it);
//                    continue;
//                }
//            }
//            ++it;
//        }
//    }
//
//    // 获取统计信息
//    void GetStatistics(size_t& totalBlocks, size_t& resetBlocks, size_t& decommittedBlocks) const {
//        std::shared_lock<std::shared_mutex> lock(m_mapMutex);
//
//        totalBlocks = m_states.size();
//        resetBlocks = 0;
//        decommittedBlocks = 0;
//
//        for (const auto& pair : m_states) {
//            if (pair.second) {
//                BlockState state = pair.second->state.load(std::memory_order_relaxed);
//                if (state == BlockState::Reset) resetBlocks++;
//                else if (state == BlockState::Decommitted) decommittedBlocks++;
//            }
//        }
//    }
//};
//
//// 全局状态管理器
//static AtomicBlockStateManager g_atomicStateManager;
//
//// ============== StormFreeList / 触发合并等 ==============
//#define FREE_LIST_SLOT_BASE 17
//#define FREE_LIST_SLOT_COUNT 9
//
//// ============== 原函数指针声明 ==============
//typedef DWORD* (__fastcall* StormHeap_Create_t)(char*, int, int, size_t, int, SIZE_T, SIZE_T);
//typedef unsigned __int16* (__fastcall* StormHeap_AllocPage_t)(char*, unsigned int, LPVOID);
//typedef DWORD* (__fastcall* StormHeap_RebuildFreeList_t)(DWORD*);
//typedef char* (__fastcall* StormHeap_CombineFreeBlocks_t)(int, unsigned __int16*, int*, char*);
//typedef int(__fastcall* StormHeap_CommitPages_t)(DWORD*, int);
//typedef char(__fastcall* StormHeap_InternalFree_t)(DWORD*, unsigned __int16*);
//typedef int(__fastcall* StormHeap_ComputeIndex_t)(int*, int);
//typedef void* (__fastcall* StormHeap_Alloc_t)(DWORD*, int, int, size_t);
//typedef char* (__fastcall* StormHeap_ReallocImpl_t)(DWORD*, DWORD*, char*, unsigned __int16*, size_t, char);
//typedef int(__fastcall* sub_1502AE30_t)(DWORD*, unsigned __int16*, int, unsigned int);
//typedef int(__fastcall* sub_1502B680_t)(DWORD*, unsigned __int16*, int, unsigned int);
//typedef void(__fastcall* sub_1502B4F0_t)(DWORD*, DWORD*, unsigned __int16*);
//typedef void(__fastcall* sub_15035850_t)();
//
//// 全局原函数指针
//static StormHeap_Create_t           s_origStormHeap_Create = nullptr;
//static StormHeap_AllocPage_t        s_origStormHeap_AllocPage = nullptr;
//static StormHeap_RebuildFreeList_t  s_origStormHeap_RebuildFreeList = nullptr;
//static StormHeap_CombineFreeBlocks_t s_origStormHeap_CombineFreeBlocks = nullptr;
//static StormHeap_CommitPages_t      s_origStormHeap_CommitPages = nullptr;
//static StormHeap_InternalFree_t     s_origStormHeap_InternalFree = nullptr;
//static StormHeap_ComputeIndex_t     s_origStormHeap_ComputeIndex = nullptr;
//static StormHeap_Alloc_t            s_origStormHeap_Alloc = nullptr;
//static StormHeap_ReallocImpl_t      s_origStormHeap_ReallocImpl = nullptr;
//static sub_1502AE30_t               s_origSub_1502AE30 = nullptr;
//static sub_1502B680_t               s_origSub_1502B680 = nullptr;
//static sub_1502B4F0_t               s_origSub_1502B4F0 = nullptr;
//static sub_15035850_t               s_origSub_15035850 = nullptr;
//
// // 安全的状态查询
//BlockState SafeGetBlockState(void* ptr) {
//    auto snapshot = g_atomicStateManager.GetState(ptr);
//    return snapshot.valid ? snapshot.state : BlockState::Normal;
//}
//
//// 安全的状态设置（保持兼容性）
//void SetBlockState(void* ptr, BlockState state, size_t size, const std::string& operation) {
//    // 尝试从任意状态转换到新状态
//    auto currentSnapshot = g_atomicStateManager.GetState(ptr);
//    if (currentSnapshot.valid) {
//        g_atomicStateManager.TransitionState(ptr, currentSnapshot.state, state, size, operation.c_str());
//    }
//    else {
//        // 如果不存在，从Normal状态开始
//        g_atomicStateManager.TransitionState(ptr, BlockState::Normal, state, size, operation.c_str());
//    }
//}
//
//static bool StormBlockIsFree(const void* pBlock)
//{
//    const StormFreeBlock* fb = reinterpret_cast<const StormFreeBlock*>(pBlock);
//    return (fb->Flags & 0x2) != 0; // 2 => free
//}
//
//static size_t StormBlockGetTotalSize(const void* pBlock)
//{
//    // 如果是 free
//    const StormFreeBlock* fb = reinterpret_cast<const StormFreeBlock*>(pBlock);
//    if ((fb->Flags & 0x2) != 0)
//    {
//        // => StormFreeBlock
//        //  fb->size 包含了全部长度
//        return fb->size;
//    }
//    else
//    {
//        // => StormAllocHeader
//        const StormAllocHeader* ah = reinterpret_cast<const StormAllocHeader*>(pBlock);
//        size_t total = ah->Size + sizeof(StormAllocHeader) + ah->AlignPadding;
//        // 如果 (ah->Flags & 0x1) => boundaryMagic, 可能还会多 2字节
//        // 不同版本Storm 里 boundaryMagic 不一定; 这里先演示不加
//        // if (ah->Flags & 0x1) total += 2; 
//        return total;
//    }
//}
//
//// ============== 触发“紧凑合并”逻辑 (不变) ==============
//static void CheckAndTriggerHeapCompact(char* heapBase)
//{
//    DWORD* heap = (DWORD*)heapBase;
//    static int compactCounter = 0;
//    // 大约超过 90% 时计数+1
//    if ((heap[7] - heap[8]) > 0.9 * heap[7])
//    {
//        compactCounter++;
//        if (compactCounter >= 3)
//        {
//            size_t usageBefore = StormFix_GetCurrentUsage();
//            s_origStormHeap_RebuildFreeList(heap);
//            size_t usageAfter = StormFix_GetCurrentUsage();
//            if (usageBefore > usageAfter)
//            {
//                g_freedByAllocHook += (usageBefore - usageAfter);
//            }
//            compactCounter = 0;
//        }
//    }
//    else
//    {
//        compactCounter = 0;
//    }
//}
//
//// 原始函数安全调用
//inline unsigned __int16* SafeStormHeap_AllocPage(char* heapBase, unsigned int requestedSize, LPVOID lpAddress) {
//    unsigned __int16* pResult = nullptr;
//    __try {
//        pResult = s_origStormHeap_AllocPage(heapBase, requestedSize, lpAddress);
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER) {
//        pResult = nullptr;
//    }
//    return pResult;
//}
//
//// 安全 VirtualAlloc
//inline LPVOID SafeVirtualAlloc(LPVOID addr, size_t size) {
//    LPVOID re = nullptr;
//    __try {
//        re = VirtualAlloc(addr, size, MEM_COMMIT, PAGE_READWRITE);
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER) {
//        re = nullptr;
//    }
//    return re;
//}
//
//
//unsigned __int16* __fastcall StormHeap_AllocPageHook(char* heapBase, unsigned int requestedSize, LPVOID lpAddress) {
//    // 参数验证
//    if (!SafeValidatePointer(heapBase, sizeof(DWORD) * 32)) {
//        LogMessage("[AllocPage] 无效的堆基址: %p", heapBase);
//        return nullptr;
//    }
//
//    CheckAndTriggerHeapCompact(heapBase);
//
//    // 【危险区1：原函数调用】（只允许C指针）
//    unsigned __int16* pResult = SafeStormHeap_AllocPage(heapBase, requestedSize, lpAddress);
//    if (!pResult) {
//        LogMessage("[AllocPage] 分配失败: 大小=%u", requestedSize);
//        return nullptr;
//    }
//
//    // 【危险区2：计算块基址】（也无C++对象）
//    if (!SafeValidatePointer(pResult, requestedSize)) {
//        LogMessage("[AllocPage] 返回的指针无效: %p", pResult);
//        return nullptr;
//    }
//    char* blockBase = (char*)pResult - sizeof(StormAllocHeader);
//    if (!SafeValidatePointer(blockBase, sizeof(StormAllocHeader))) {
//        LogMessage("[AllocPage] 计算的块基址无效: %p", blockBase);
//        return pResult;
//    }
//
//    // 【安全区：所有C++对象和状态查询、日志等】
//    auto stateSnapshot = g_atomicStateManager.GetState(blockBase);
//
//    if (stateSnapshot.valid && stateSnapshot.state == BlockState::Reset) {
//        if (g_atomicStateManager.TransitionState(blockBase, BlockState::Reset, BlockState::Normal, 0, "AllocPage_Reuse")) {
//            LogMessage("[AllocPage] MEM_RESET块被重用: %p", blockBase);
//        }
//        else {
//            LogMessage("[AllocPage] 状态转换失败（并发修改）: %p", blockBase);
//        }
//    }
//    else if (stateSnapshot.valid && stateSnapshot.state == BlockState::Decommitted) {
//        LogMessage("[AllocPage] 重新提交DECOMMIT块: %p, 大小: %zu", blockBase, stateSnapshot.size);
//
//        // 【危险区3：VirtualAlloc】（无C++对象）
//        LPVOID re = SafeVirtualAlloc(blockBase, stateSnapshot.size);
//        if (re) {
//            if (g_atomicStateManager.ConditionalUpdate(blockBase, stateSnapshot.version, BlockState::Normal, 0, "AllocPage_Recommit")) {
//                LogMessage("[AllocPage] 重新提交成功: %p", blockBase);
//            }
//            else {
//                LogMessage("[AllocPage] 状态更新失败（版本不匹配）: %p", blockBase);
//            }
//        }
//        else {
//            DWORD error = GetLastError();
//            LogMessage("[AllocPage] 重新提交失败: ptr=%p, size=%zu, 错误=%d", blockBase, stateSnapshot.size, error);
//            return nullptr;
//        }
//    }
//
//    return pResult;
//}
//
//
//// ============== Hook: StormHeap_InternalFree ==============
//char __fastcall StormHeap_InternalFreeHook(DWORD* heap, unsigned __int16* blockHeader) {
//    // 获取原始用户指针和大小
//    void* userPtr = (void*)((char*)blockHeader + sizeof(StormAllocHeader));
//    size_t size = 0;
//
//    // 检查小块池拦截
//    try {
//        StormAllocHeader* hdr = reinterpret_cast<StormAllocHeader*>(blockHeader);
//        size = hdr->Size;
//
//        if (size > 0 && SmallBlockPool::ShouldIntercept(size)) {
//            if (SmallBlockPool::Free(userPtr, size)) {
//                LogMessage("[SmallBlock] 小块池释放成功: %p, 大小: %zu", userPtr, size);
//                return 2;  // 成功码
//            }
//        }
//    }
//    catch (...) {
//        LogMessage("[InternalFree] 小块检查异常: %p", blockHeader);
//    }
//
//    size_t usageBefore = StormFix_GetCurrentUsage();
//
//    // 调用原始Storm释放函数
//    char ret = s_origStormHeap_InternalFree(heap, blockHeader);
//
//    size_t usageMid = StormFix_GetCurrentUsage();
//    size_t freedByOrig = (usageBefore > usageMid) ? (usageBefore - usageMid) : 0;
//
//    // Storm内部整理逻辑
//    if (heap[5] == 0) {
//        size_t usageBeforeReset = StormFix_GetCurrentUsage();
//        heap[8] = heap[7];
//        for (int i = 0; i < FREE_LIST_SLOT_COUNT; i++)
//            heap[FREE_LIST_SLOT_BASE + i] = 0;
//        size_t usageAfterReset = StormFix_GetCurrentUsage();
//        g_freedByFreeHook += (usageBeforeReset > usageAfterReset) ?
//            (usageBeforeReset - usageAfterReset) : 0;
//    }
//    else {
//        size_t usageBeforeRebuild = StormFix_GetCurrentUsage();
//        s_origStormHeap_RebuildFreeList(heap);
//        size_t usageAfterRebuild = StormFix_GetCurrentUsage();
//        g_freedByFreeHook += (usageBeforeRebuild > usageAfterRebuild) ?
//            (usageBeforeRebuild - usageAfterRebuild) : 0;
//    }
//    g_freedByFreeHook += freedByOrig;
//
//    // 修复: 安全的内存优化处理
//    bool isFree = StormBlockIsFree(blockHeader);
//    if (isFree) {
//        size_t blockSize = StormBlockGetTotalSize(blockHeader);
//        if (blockSize > 0) {
//            SYSTEM_INFO si;
//            GetSystemInfo(&si);
//            size_t pageSize = si.dwPageSize;
//            uintptr_t addr = (uintptr_t)blockHeader;
//
//            // 检查页对齐和大小要求
//            bool isPageAligned = (addr % pageSize) == 0;
//            bool isSizeAligned = (blockSize % pageSize) == 0;
//
//            if (isPageAligned && isSizeAligned) {
//                // 获取优化策略
//                auto strategy = g_blockRefCounter.GetOptimizationStrategy(blockHeader, blockSize);
//
//                switch (strategy) {
//                case BlockReferenceCounter::OptimizationStrategy::Reset: {
//                    LogMessage("[InternalFree] 使用MEM_RESET优化大块: %p, 大小: %zu KB",
//                        blockHeader, blockSize / 1024);
//
//                    // 保护性检查：确保块确实是空闲的
//                    if (StormBlockIsFree(blockHeader)) {
//                        BOOL bOK = VirtualFree(blockHeader, blockSize, MEM_RESET);
//                        if (bOK) {
//                            SetBlockState(blockHeader, BlockState::Reset, blockSize, "InternalFree_Reset");
//
//                            // 统计
//                            static std::atomic<size_t> s_totalReset{ 0 };
//                            static std::atomic<size_t> s_resetCount{ 0 };
//                            s_totalReset += blockSize;
//                            s_resetCount++;
//
//                            if (s_resetCount.load() % 100 == 0) {  // 每100次记录一次
//                                LogMessage("[优化统计] MEM_RESET: 次数=%zu, 累计=%zu MB",
//                                    s_resetCount.load(), s_totalReset.load() / (1024 * 1024));
//                            }
//                        }
//                        else {
//                            DWORD error = GetLastError();
//                            LogMessage("[InternalFree] MEM_RESET失败: ptr=%p, size=%zu, 错误=%d",
//                                blockHeader, blockSize, error);
//                        }
//                    }
//                    break;
//                }
//
//                case BlockReferenceCounter::OptimizationStrategy::Decommit: {
//                    LogMessage("[InternalFree] 使用MEM_DECOMMIT优化超大块: %p, 大小: %zu MB",
//                        blockHeader, blockSize / (1024 * 1024));
//
//                    BOOL bOK = VirtualFree(blockHeader, blockSize, MEM_DECOMMIT);
//                    if (bOK) {
//                        SetBlockState(blockHeader, BlockState::Decommitted, blockSize, "InternalFree_Decommit");
//                    }
//                    else {
//                        DWORD error = GetLastError();
//                        LogMessage("[InternalFree] MEM_DECOMMIT失败: ptr=%p, size=%zu, 错误=%d",
//                            blockHeader, blockSize, error);
//                    }
//                    break;
//                }
//
//                case BlockReferenceCounter::OptimizationStrategy::None:
//                default:
//                    // 不进行内存优化
//                    break;
//                }
//            }
//        }
//    }
//
//    return ret;
//}
//
//// ============== Hook: StormHeap_Alloc (可选) ==============
//void* __fastcall StormHeap_AllocHook(DWORD* pHeap, int a2, int flags, size_t size) {
//    // 检查小块池拦截
//    if (SmallBlockPool::ShouldIntercept(size)) {
//        void* ptr = SmallBlockPool::Allocate(size);
//        if (ptr) {
//            LogMessage("[SmallBlock] 小块池分配: %p, 大小: %zu", ptr, size);
//            return ptr;
//        }
//        // 小块池分配失败，继续Storm分配
//    }
//
//    // 调用原始Storm分配
//    void* pUserPtr = s_origStormHeap_Alloc(pHeap, a2, flags, size);
//    if (!pUserPtr) {
//        return nullptr;
//    }
//
//    // 检查是否使用了优化过的内存
//    char* blockBase = (char*)pUserPtr - sizeof(StormAllocHeader);
//    g_blockRefCounter.SetBlockInfo(blockBase, size);
//    g_blockRefCounter.AddRef(blockBase);
//
//    // 使用新系统查询状态
//    auto stateSnapshot = g_atomicStateManager.GetState(blockBase);
//
//    if (stateSnapshot.valid && stateSnapshot.state == BlockState::Reset) {
//        LogMessage("[StormAlloc] 重用MEM_RESET块: %p, 大小: %zu", pUserPtr, size);
//        // 原子性状态切换（兼容并发）
//        g_atomicStateManager.TransitionState(blockBase, BlockState::Reset, BlockState::Normal, 0, "StormAlloc_Reuse");
//    }
//    else if (stateSnapshot.valid && stateSnapshot.state == BlockState::Decommitted) {
//        // 理论上AllocPage已处理此状态，此处是容错
//        LogMessage("[StormAlloc] 警告: 使用了未恢复的DECOMMIT块: %p", pUserPtr);
//
//        // 再次尝试提交
//        LPVOID re = VirtualAlloc(blockBase, stateSnapshot.size, MEM_COMMIT, PAGE_READWRITE);
//        if (re) {
//            // 条件更新，要求版本号一致防止竞态
//            bool ok = g_atomicStateManager.ConditionalUpdate(
//                blockBase, stateSnapshot.version, BlockState::Normal, 0, "StormAlloc_Emergency");
//            if (ok) {
//                LogMessage("[StormAlloc] 紧急恢复成功: %p", blockBase);
//            }
//            else {
//                LogMessage("[StormAlloc] 紧急恢复失败（版本不匹配）: %p", blockBase);
//                return nullptr;
//            }
//        }
//        else {
//            LogMessage("[StormAlloc] 紧急恢复失败: %p", blockBase);
//            return nullptr;
//        }
//    }
//
//    return pUserPtr;
//}
//
////char* __fastcall Hook_StormHeap_CombineFreeBlocks(int a1, unsigned __int16* blockHeader, int* a3, char* a4) {
////    // 先执行原始函数
////    char* result = s_origStormHeap_CombineFreeBlocks(a1, blockHeader, a3, a4);
////
////    // 检查堆状态和碎片化程度
////    DWORD* heap = (DWORD*)a1;
////    if (heap && heap[7] > 0 && heap[8] > 0) {
////        // 计算碎片化率：已分配内存中的空闲比例
////        float fragRatio = (float)heap[8] / (float)heap[7];
////
////        // 超过75%碎片化率时，强制整理
////        if (fragRatio > 0.75f) {
////            s_origStormHeap_RebuildFreeList(heap);
////            LogMessage("[优化] 检测到高碎片化率(%.1f%%)，执行强制内存整理", fragRatio * 100.0f);
////        }
////    }
////
////    return result;
////}
//
////DWORD* __fastcall Hooked_StormHeap_RebuildFreeList(DWORD* heap) {
////    // 调用原始函数
////    DWORD* result = s_origStormHeap_RebuildFreeList(heap);
////
////    // 检查内存使用量，主动回收未使用的内存池
////    static DWORD lastCleanupTime = 0;
////    DWORD currentTime = GetTickCount();
////
////    if (currentTime - lastCleanupTime > 30000) { // 每30秒
////        lastCleanupTime = currentTime;
////        MemPool::CheckAndFreeUnusedPools();
////    }
////
////    return result;
////}
//
//// ============== 其他 Hook (保留空壳) ==============
//
//static int __fastcall Hooked_StormHeap_ComputeIndex(int* a1, int a2) { return 1; }
//static char* __fastcall Hooked_StormHeap_ReallocImpl(
//    DWORD* a1, DWORD* a2, char* Src, unsigned __int16* a4, size_t newSize, char flags)
//{
//    return nullptr;
//}
//static int __fastcall Hooked_sub_1502AE30(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4) { return 1; }
//static int __fastcall Hooked_sub_1502B680(DWORD* a1, unsigned __int16* a2, int a3, unsigned int a4) { return 0; }
//static void __fastcall Hooked_sub_1502B4F0(DWORD* a1, DWORD* a2, unsigned __int16* a3) {}
//static void __fastcall Hooked_sub_15035850() {}
//
//// ============== 主 Hook 安装函数 ==============
//bool HookAllStormHeapFunctions()
//{
//    // 1) 获取Storm函数地址
//    s_origStormHeap_Create = (StormHeap_Create_t)(gStormDllBase + 0x2A350);
//    s_origStormHeap_AllocPage = (StormHeap_AllocPage_t)(gStormDllBase + 0x2A510);
//    s_origStormHeap_RebuildFreeList = (StormHeap_RebuildFreeList_t)(gStormDllBase + 0x2A920);
//    s_origStormHeap_CombineFreeBlocks = (StormHeap_CombineFreeBlocks_t)(gStormDllBase + 0x2B790);
//    s_origStormHeap_CommitPages = (StormHeap_CommitPages_t)(gStormDllBase + 0x2ADE0);
//    s_origStormHeap_InternalFree = (StormHeap_InternalFree_t)(gStormDllBase + 0x2ABF0);
//    s_origStormHeap_ComputeIndex = (StormHeap_ComputeIndex_t)(gStormDllBase + 0x2AD60);
//    s_origStormHeap_Alloc = (StormHeap_Alloc_t)(gStormDllBase + 0x2B3B0);
//    s_origStormHeap_ReallocImpl = (StormHeap_ReallocImpl_t)(gStormDllBase + 0x2B560);
//    s_origSub_1502AE30 = (sub_1502AE30_t)(gStormDllBase + 0x2AE30);
//    s_origSub_1502B680 = (sub_1502B680_t)(gStormDllBase + 0x2B680);
//    s_origSub_1502B4F0 = (sub_1502B4F0_t)(gStormDllBase + 0x2B4F0);
//    s_origSub_15035850 = (sub_15035850_t)(gStormDllBase + 0x35850);
//
//    // 2) Detour
//    DetourTransactionBegin();
//    DetourUpdateThread(GetCurrentThread());
//
//    DetourAttach(&(PVOID&)s_origStormHeap_AllocPage, StormHeap_AllocPageHook);
//    DetourAttach(&(PVOID&)s_origStormHeap_InternalFree, StormHeap_InternalFreeHook);
//    DetourAttach(&(PVOID&)s_origStormHeap_Alloc, StormHeap_AllocHook);
//
//    // 如果你想 Hook 更多:
//    // DetourAttach(&(PVOID&)s_origStormHeap_RebuildFreeList,  Hooked_StormHeap_RebuildFreeList);
//    //DetourAttach(&(PVOID&)s_origStormHeap_CombineFreeBlocks, Hook_StormHeap_CombineFreeBlocks);
//    // ...
//
//    LONG error = DetourTransactionCommit();
//    if (error != NO_ERROR)
//    {
//        printf("[HookAllStormHeapFunctions] Detour commit error = %d\n", error);
//        return false;
//    }
//
//    printf("[HookAllStormHeapFunctions] success.\n");
//    return true;
//}
//
//void CleanupBlockStates() {
//    // 统计状态
//    size_t totalBlocks = 0, resetBlocks = 0, decommittedBlocks = 0;
//    g_atomicStateManager.GetStatistics(totalBlocks, resetBlocks, decommittedBlocks);
//
//    LogMessage("[清理] 块状态统计: MEM_RESET=%zu, MEM_DECOMMIT=%zu, 总计=%zu",
//        resetBlocks, decommittedBlocks, totalBlocks);
//
//    // 清理所有过期块（这里可自定义过期时间，默认5分钟）
//    g_atomicStateManager.CleanupExpiredStates();
//}
//
//void CleanupMemoryOptimization() {
//    LogMessage("[清理] 清理内存优化状态...");
//
//    // 清理块状态
//    CleanupBlockStates();
//
//    // 这里不需要清理引用计数，因为它会随着对象析构自动清理
//}