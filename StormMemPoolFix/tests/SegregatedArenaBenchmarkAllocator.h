#pragma once

#include <cstdint>

namespace StormBreaker::Benchmark {

// Benchmark-only bounded size-class allocator. It is intentionally isolated
// from the production backend surface until it passes the 32-bit VA, latency,
// cross-thread, and long-run retention gates.
class SegregatedArenaAllocator final {
public:
  SegregatedArenaAllocator() noexcept = default;
  ~SegregatedArenaAllocator() noexcept;

  SegregatedArenaAllocator(const SegregatedArenaAllocator&) = delete;
  SegregatedArenaAllocator& operator=(const SegregatedArenaAllocator&) = delete;

  bool Initialize(bool cacheEmptySpans = true,
                  uint32_t spanSizeKiB = 64u,
                  bool remoteFree = false,
                  bool lazySpanInitialization = false,
                  uint32_t remoteBatchSize = 0u) noexcept;
  bool Shutdown() noexcept;

  void* Allocate(uint32_t size, bool zeroMemory) noexcept;
  bool Free(void* pointer) noexcept;
  void* Reallocate(void* pointer, uint32_t newSize,
                   bool zeroGrowth) noexcept;

private:
  struct State;
  State* state_ = nullptr;
};

} // namespace StormBreaker::Benchmark
