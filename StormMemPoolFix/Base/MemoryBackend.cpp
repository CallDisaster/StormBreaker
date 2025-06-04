// MemoryBackend.cpp 修正版
#include "pch.h"
#include "MemoryBackend.h"
#include "Storm/MemoryPool.h" // 现有TLSF实现 (使用命名空间为 MemPool)
#include "MiMemPool.h"        // mimalloc实现
#include "Base/Logger.h"
#include "Storm/StormHook.h"
#include "MemorySafetyUtils.h"

// 静态变量
namespace {
    // 内部状态
    std::atomic<bool> g_initialized{ false };
    std::atomic<bool> g_inShutdown{ false };
}

// 实现统一内存池接口
namespace MemoryPool {
    void Initialize() {
        // 防止重复初始化
        if (g_initialized.exchange(true)) {
            return;
        }

        LogMessage("[MemPool] 初始化后端: %s",
            MemoryConfig::Get().backend == MemBackendType::Mimalloc ? "mimalloc" :
            MemoryConfig::Get().backend == MemBackendType::TLSF ? "TLSF" : "System");

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            MiMemPool::Initialize();
            break;
        case MemBackendType::TLSF:
            // 使用现有的TLSF实现
            MemPool::Initialize(128 * 1024 * 1024);
            break;
        case MemBackendType::System:
            // 系统后端不需要特殊初始化
            break;
        }
    }

    void Shutdown() {
        // 防止重复关闭
        if (g_inShutdown.exchange(true)) {
            return;
        }

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            MiMemPool::Shutdown();
            break;
        case MemBackendType::TLSF:
            MemPool::Shutdown();
            break;
        case MemBackendType::System:
            // 系统后端不需要特殊关闭
            break;
        }

        g_initialized.store(false);
        g_inShutdown.store(false);
    }

    void* AllocateSafe(size_t size) {
        // 确保已初始化
        if (!g_initialized.load()) {
            Initialize();
        }

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::AllocateSafe(size);
        case MemBackendType::TLSF:
            return MemPool::AllocateSafe(size);
        case MemBackendType::System:
        {
            // 使用系统分配 - 添加花括号创建作用域
            void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader) + 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!sysPtr) return nullptr;

            void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
            SetupCompatibleHeader(userPtr, size);
            return userPtr;
        }
        default:
            return nullptr;
        }
    }

    void* Allocate(size_t size) {
        // 确保已初始化
        if (!g_initialized.load()) {
            Initialize();
        }

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::Allocate(size);
        case MemBackendType::TLSF:
            return MemPool::Allocate(size);
        case MemBackendType::System:
            return AllocateSafe(size); // 对系统而言，安全和非安全相同
        default:
            return nullptr;
        }
    }

    void FreeSafe(void* ptr) {
        if (!ptr) return;

        // 已经关闭时不释放
        if (g_inShutdown.load()) {
            return;
        }

        // 根据后端类型选择释放方法
        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            MiMemPool::FreeSafe(ptr);
            break;
        case MemBackendType::TLSF:
            MemPool::FreeSafe(ptr);
            break;
        case MemBackendType::System:
            // 获取原始指针并使用VirtualFree
            if (!IsBadReadPtr(ptr, sizeof(void*))) {
                try {
                    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                        static_cast<char*>(ptr) - sizeof(StormAllocHeader));

                    if (!IsBadReadPtr(header, sizeof(StormAllocHeader)) &&
                        header->Magic == STORM_MAGIC) {
                        void* basePtr = static_cast<char*>(ptr) - sizeof(StormAllocHeader);
                        VirtualFree(basePtr, 0, MEM_RELEASE);
                    }
                }
                catch (...) {
                    LogMessage("[MemPool] System后端释放异常: %p", ptr);
                }
            }
            break;
        }
    }

    void Free(void* ptr) {
        if (!ptr) return;

        // 已经关闭时不释放
        if (g_inShutdown.load()) {
            return;
        }

        // 对于Free，简单调用安全版本
        FreeSafe(ptr);
    }

    void* ReallocSafe(void* oldPtr, size_t newSize) {
        // 处理空指针和零大小的特殊情况
        if (!oldPtr) return AllocateSafe(newSize);
        if (newSize == 0) {
            FreeSafe(oldPtr);
            return nullptr;
        }

        // 已经关闭时不重新分配
        if (g_inShutdown.load()) {
            return nullptr;
        }

        // 确保已初始化
        if (!g_initialized.load()) {
            Initialize();
        }

        // 根据后端类型选择重分配方法
        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::ReallocSafe(oldPtr, newSize);
        case MemBackendType::TLSF:
            return MemPool::ReallocSafe(oldPtr, newSize);
        case MemBackendType::System:
            // 系统版本：分配+复制+释放
            void* newPtr = AllocateSafe(newSize);
            if (!newPtr) return nullptr;

            // 尝试获取旧块大小
            size_t oldSize = 0;
            try {
                StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                    static_cast<char*>(oldPtr) - sizeof(StormAllocHeader));

                if (!IsBadReadPtr(header, sizeof(StormAllocHeader)) &&
                    header->Magic == STORM_MAGIC) {
                    oldSize = header->Size;
                }
            }
            catch (...) {
                oldSize = 0;
            }

            // 复制数据
            if (oldSize > 0) {
                // 使用安全复制
                size_t copySize = min(oldSize, newSize);
                try {
                    memcpy(newPtr, oldPtr, copySize);
                }
                catch (...) {
                    LogMessage("[MemPool] System后端复制异常");
                }
            }

            // 释放旧块
            FreeSafe(oldPtr);

            return newPtr;
        default:
            return nullptr;
        }
    }

    void* Realloc(void* oldPtr, size_t newSize) {
        // 简单调用安全版本
        return ReallocSafe(oldPtr, newSize);
    }

    void* AllocateJassVM(size_t size) {
        // 确保已初始化
        if (!g_initialized.load()) {
            Initialize();
        }

        // 如果配置了专用JassVM池
        if (MemoryConfig::Get().useSpecialJassVMPool) {
            switch (MemoryConfig::Get().backend) {
            case MemBackendType::Mimalloc:
                return MiMemPool::AllocateJassVM(size);
            case MemBackendType::TLSF:
                // 如果TLSF实现支持JassVM专用分配
                return JVM_MemPool::Allocate(size);
            default:
                break;
            }
        }

        // 退回到常规分配
        return Allocate(size);
    }

    void* AllocateJassVMSafe(size_t size) {
        // 与AllocateJassVM类似，但使用安全版本
        if (!g_initialized.load()) {
            Initialize();
        }

        if (MemoryConfig::Get().useSpecialJassVMPool) {
            switch (MemoryConfig::Get().backend) {
            case MemBackendType::Mimalloc:
                return MiMemPool::AllocateJassVM(size);
            case MemBackendType::TLSF:
                return JVM_MemPool::Allocate(size);
            default:
                break;
            }
        }

        return AllocateSafe(size);
    }

    bool IsFromPool(void* ptr) {
        if (!ptr) return false;

        // 根据后端类型选择检查方法
        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::IsFromPool(ptr);
        case MemBackendType::TLSF:
            return MemPool::IsFromPool(ptr);
        case MemBackendType::System:
            // 系统后端检查Storm头部
            if (!IsBadReadPtr(ptr, sizeof(void*))) {
                try {
                    StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
                        static_cast<char*>(ptr) - sizeof(StormAllocHeader));

                    return (!IsBadReadPtr(header, sizeof(StormAllocHeader)) &&
                        header->Magic == STORM_MAGIC);
                }
                catch (...) {
                    return false;
                }
            }
            return false;
        default:
            return false;
        }
    }

    size_t GetUsedSize() {
        if (!g_initialized.load()) return 0;

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::GetUsedSize();
        case MemBackendType::TLSF:
            return MemPool::GetUsedSize();
        case MemBackendType::System:
            // 系统后端没有准确统计
            return 0;
        default:
            return 0;
        }
    }

    size_t GetTotalSize() {
        if (!g_initialized.load()) return 0;

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            return MiMemPool::GetTotalSize();
        case MemBackendType::TLSF:
            return MemPool::GetTotalSize();
        case MemBackendType::System:
            // 系统后端没有准确统计
            return 0;
        default:
            return 0;
        }
    }

    void PrintStats() {
        if (!g_initialized.load()) {
            LogMessage("[MemPool] 未初始化，无统计信息");
            return;
        }

        LogMessage("[MemPool] === 内存统计信息 ===");
        LogMessage("[MemPool] 后端类型: %s",
            MemoryConfig::Get().backend == MemBackendType::Mimalloc ? "mimalloc" :
            MemoryConfig::Get().backend == MemBackendType::TLSF ? "TLSF" : "System");

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            MiMemPool::PrintStats();
            break;
        case MemBackendType::TLSF:
            MemPool::PrintStats();
            break;
        case MemBackendType::System:
            LogMessage("[MemPool] System后端没有详细统计信息");
            break;
        }

        // 获取进程整体内存使用情况
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            LogMessage("[MemPool] 进程内存: 工作集=%zu MB, 分页文件=%zu MB",
                pmc.WorkingSetSize / (1024 * 1024),
                pmc.PagefileUsage / (1024 * 1024));
        }

        LogMessage("[MemPool] =====================");
    }

    void CollectUnused() {
        if (!g_initialized.load()) return;

        switch (MemoryConfig::Get().backend) {
        case MemBackendType::Mimalloc:
            MiMemPool::CollectUnused();
            break;
        case MemBackendType::TLSF:
            break;
        default:
            break;
        }
    }
}