#pragma once

#include "MemoryPool.h"

#include <cstdint>
#include <memory>

#if !defined(_WIN32) || defined(_WIN64)
#error StormBreaker memory backends support Win32/x86 only.
#endif

static_assert(sizeof(size_t) == 4,
    "StormBreaker memory backends require 32-bit size_t.");

namespace MemoryPool {
namespace Internal {

using BackendBlockVisitor = bool (*)(
    void* pointer, size_t usableSize, void* context);
using BackendFreeValidator = bool (*)(
    void* pointer, size_t usableSize, void* context);

struct BackendStats {
    uint64_t reservedBytes;
    uint64_t committedBytes;
    uint64_t peakReservedBytes;
    uint64_t peakCommittedBytes;
    uint64_t growthCount;
    uint64_t trimCount;
    uint64_t lockWaitCount;
    uint64_t lockWaitNanoseconds;
    uint64_t maxLockWaitNanoseconds;
    LatencyHistogramStats lockWaitLatency;
};

class MemoryBackend {
public:
    virtual ~MemoryBackend() = default;

    virtual BackendKind GetKind() const = 0;
    virtual const char* GetName() const = 0;

    virtual bool Initialize(const Config& config) = 0;
    virtual void Shutdown() = 0;

    // Allocation and free return the usable size while the backend lock is
    // already held. This avoids a second ownership/size lookup on every SMem
    // operation, which is especially costly for TLSF.
    virtual void* Allocate(size_t size, size_t* usableSize) = 0;
    virtual void* AllocateAligned(
        size_t size, size_t alignment, size_t* usableSize) = 0;
    virtual void* Reallocate(
        void* ptr, size_t newSize, size_t* usableSize) = 0;
    // Returns ptr on success and nullptr on failure. A failure must leave the
    // original allocation and its contents unchanged.
    // Validates the exact allocation, captures its old usable size, and tries
    // the resize under one backend lock. oldUsableSize remains zero when ptr
    // is not an exact live allocation; a nonzero old size with nullptr return
    // is a normal in-place miss.
    virtual void* ReallocateInPlace(
        void* ptr, size_t newSize, size_t* oldUsableSize,
        size_t* newUsableSize) = 0;
    virtual size_t Free(void* ptr) = 0;
    // Validates and inspects an exact live block under the same ownership
    // gate used for the eventual free. Returning false leaves it allocated.
    virtual size_t FreeConditional(
        void* ptr, BackendFreeValidator validator, void* context) = 0;
    virtual MemoryPool::BatchFreeResult FreeBatch(
        const MemoryPool::BatchFreeEntry* entries, size_t count) {
        MemoryPool::BatchFreeResult result{};
        if (!entries && count != 0) {
            return result;
        }
        for (; result.freedCount < count; ++result.freedCount) {
            const size_t usable = Free(entries[result.freedCount].pointer);
            if (usable == 0) {
                break;
            }
            result.usableBytes += usable;
        }
        return result;
    }

    virtual bool IsFromBackend(void* ptr) const = 0;
    virtual bool QueryAllocation(void* ptr, size_t* usableSize) const = 0;
    virtual size_t GetBlockSize(void* ptr) const = 0;
    // Visits exact live allocation starts under a backend snapshot gate. The
    // visitor may inspect/copy metadata but must not re-enter or free blocks.
    virtual bool VisitAllocatedBlocks(
        BackendBlockVisitor visitor, void* context) const = 0;

    virtual bool Extend(size_t additionalSize) = 0;
    virtual void Trim() = 0;
    virtual void Compact() = 0;

    virtual void SetThreadSafety(bool enabled) = 0;
    virtual BackendStats GetStats() const = 0;
    virtual void ResetStats() = 0;

    virtual void* GetNativeHandle() const = 0;
    virtual size_t GetPoolCount() const = 0;
    virtual void DumpPoolInfo() const = 0;
    virtual bool Validate() const = 0;
};

std::unique_ptr<MemoryBackend> CreateTlsfBackend();
std::unique_ptr<MemoryBackend> CreateTlsfShardedBackend();
std::unique_ptr<MemoryBackend> CreateMimallocBackend();

} // namespace Internal
} // namespace MemoryPool
