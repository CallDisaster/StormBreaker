#include "pch.h"
#include "StormHeap.h"
#include "StormCompatible.h"

// C接口实现
extern "C" {

    void* StormCompat_Allocate(size_t size, const char* name, DWORD srcLine, DWORD flags) {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        return allocator.AllocateCompatible(size, name, srcLine, flags);
    }

    int StormCompat_Free(void* ptr) {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        return allocator.FreeCompatible(ptr) ? 1 : 0;
    }

    void* StormCompat_Reallocate(void* oldPtr, size_t newSize, const char* name, DWORD srcLine, DWORD flags) {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        return allocator.ReallocateCompatible(oldPtr, newSize, name, srcLine, flags);
    }

    bool StormCompat_IsOurPointer(void* ptr) {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        return allocator.IsOurPointer(ptr);
    }

    void StormCompat_GetStatistics(size_t* allocated, size_t* freed, size_t* allocCount, size_t* freeCount) {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        allocator.GetStatistics(*allocated, *freed, *allocCount, *freeCount);
    }

    bool StormCompat_Initialize() {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        return allocator.Initialize();
    }

    void StormCompat_Shutdown() {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();
        allocator.Shutdown();
    }

    void StormCompat_PrintStats() {
        StormCompatible::StormCompatibleAllocator& allocator =
            StormCompatible::StormCompatibleAllocator::GetInstance();

        size_t allocated, freed, allocCount, freeCount;
        allocator.GetStatistics(allocated, freed, allocCount, freeCount);

        printf("[StormCompat] === 兼容分配器统计 ===\n");
        printf("[StormCompat] 总分配: %zu 次, %zu MB\n", allocCount, allocated / (1024 * 1024));
        printf("[StormCompat] 总释放: %zu 次, %zu MB\n", freeCount, freed / (1024 * 1024));
        printf("[StormCompat] 当前使用: %zu MB\n", (allocated - freed) / (1024 * 1024));

        if (allocCount > freeCount) {
            printf("[StormCompat] 可能泄漏: %zu 个块, %zu MB\n",
                allocCount - freeCount, (allocated - freed) / (1024 * 1024));
        }
    }

} // extern "C"