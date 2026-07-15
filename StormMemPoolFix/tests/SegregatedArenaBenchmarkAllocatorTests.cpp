#include "pch.h"

#include "SegregatedArenaBenchmarkAllocator.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

using StormBreaker::Benchmark::SegregatedArenaAllocator;

constexpr std::array<uint32_t, 40> kPayloadClasses{
    16u,    32u,    48u,    64u,    80u,    96u,    112u,   128u,
    160u,   192u,   224u,   256u,   320u,   384u,   448u,   512u,
    640u,   768u,   896u,   1024u,  1280u,  1536u,  1792u,  2048u,
    2560u,  3072u,  3584u,  4096u,  5120u,  6144u,  7168u,  8192u,
    10240u, 12288u, 14336u, 16384u, 20480u, 24576u, 28672u, 32768u};

bool Check(bool condition, const char* expression, int line) noexcept {
  if (!condition) {
    std::fprintf(stderr, "FAILED line %d: %s\n", line, expression);
  }
  return condition;
}

#define CHECK(expression)                                                       \
  do {                                                                          \
    if (!Check(!!(expression), #expression, __LINE__)) {                         \
      return false;                                                             \
    }                                                                           \
  } while (false)

struct Block {
  void* pointer = nullptr;
  uint32_t size = 0;
  uint8_t pattern = 0;
};

bool IsAligned16(const void* pointer) noexcept {
  return (reinterpret_cast<uintptr_t>(pointer) & 0x0Fu) == 0;
}

void FillBlock(const Block& block) noexcept {
  if (block.size != 0) {
    std::memset(block.pointer, block.pattern, block.size);
  }
}

bool VerifyBlock(const Block& block) noexcept {
  const auto* bytes = static_cast<const uint8_t*>(block.pointer);
  for (uint32_t index = 0; index < block.size; ++index) {
    if (bytes[index] != block.pattern) {
      return false;
    }
  }
  return true;
}

void FillSentinels(void* pointer, uint32_t size, uint8_t pattern) noexcept {
  if (size == 0) {
    return;
  }
  auto* bytes = static_cast<uint8_t*>(pointer);
  const uint32_t prefix = (std::min)(size, 16u);
  std::memset(bytes, pattern, prefix);
  if (size > prefix) {
    const uint32_t suffix = (std::min)(size - prefix, 16u);
    std::memset(bytes + size - suffix, pattern, suffix);
  }
}

bool VerifySentinels(const void* pointer, uint32_t size,
                     uint8_t pattern) noexcept {
  if (size == 0) {
    return true;
  }
  const auto* bytes = static_cast<const uint8_t*>(pointer);
  const uint32_t prefix = (std::min)(size, 16u);
  for (uint32_t index = 0; index < prefix; ++index) {
    if (bytes[index] != pattern) {
      return false;
    }
  }
  if (size > prefix) {
    const uint32_t suffix = (std::min)(size - prefix, 16u);
    for (uint32_t index = size - suffix; index < size; ++index) {
      if (bytes[index] != pattern) {
        return false;
      }
    }
  }
  return true;
}

bool IsZeroed(const void* pointer, uint32_t size) noexcept {
  const auto* bytes = static_cast<const uint8_t*>(pointer);
  for (uint32_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}

bool TestEverySizeClassBoundary() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize());

  std::vector<Block> blocks;
  blocks.reserve(kPayloadClasses.size() * 3u + 1u);
  uint32_t sequence = 0;
  for (const uint32_t boundary : kPayloadClasses) {
    const std::array<uint32_t, 3> sizes{boundary - 1u, boundary,
                                        boundary + 1u};
    for (const uint32_t size : sizes) {
      Block block{};
      block.pointer = allocator.Allocate(size, false);
      block.size = size;
      block.pattern = static_cast<uint8_t>(0x31u + (sequence++ % 0xB0u));
      CHECK(block.pointer != nullptr);
      CHECK(IsAligned16(block.pointer));
      FillBlock(block);
      blocks.push_back(block);
    }
  }

  Block zero{};
  zero.pointer = allocator.Allocate(0, false);
  CHECK(zero.pointer != nullptr);
  CHECK(IsAligned16(zero.pointer));
  blocks.push_back(zero);

  for (const Block& block : blocks) {
    CHECK(VerifyBlock(block));
  }
  for (auto iterator = blocks.rbegin(); iterator != blocks.rend(); ++iterator) {
    CHECK(allocator.Free(iterator->pointer));
  }
  CHECK(allocator.Free(nullptr));
  CHECK(allocator.Shutdown());
  return true;
}

bool TestReallocateRoutes() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize());

  void* sameClass = allocator.Allocate(17, false);
  CHECK(sameClass != nullptr);
  std::memset(sameClass, 0x41, 17);
  void* sameClassGrown = allocator.Reallocate(sameClass, 24, false);
  CHECK(sameClassGrown == sameClass);
  CHECK(VerifySentinels(sameClassGrown, 17, 0x41));

  void* sameClassShrunk = allocator.Reallocate(sameClassGrown, 1, false);
  CHECK(sameClassShrunk == sameClassGrown);
  CHECK(static_cast<uint8_t*>(sameClassShrunk)[0] == 0x41);
  CHECK(allocator.Free(sameClassShrunk));

  void* crossClass = allocator.Allocate(16, false);
  CHECK(crossClass != nullptr);
  std::memset(crossClass, 0x52, 16);
  void* crossClassGrown = allocator.Reallocate(crossClass, 17, false);
  CHECK(crossClassGrown != nullptr);
  CHECK(crossClassGrown != crossClass);
  CHECK(VerifySentinels(crossClassGrown, 16, 0x52));
  CHECK(allocator.Free(crossClassGrown));

  void* smallBlock = allocator.Allocate(32768, false);
  CHECK(smallBlock != nullptr);
  std::memset(smallBlock, 0x63, 32768);
  void* largeBlock = allocator.Reallocate(smallBlock, 32769, false);
  CHECK(largeBlock != nullptr);
  CHECK(largeBlock != smallBlock);
  CHECK(VerifySentinels(largeBlock, 32768, 0x63));

  void* smallAgain = allocator.Reallocate(largeBlock, 32768, false);
  CHECK(smallAgain != nullptr);
  CHECK(smallAgain != largeBlock);
  CHECK(VerifySentinels(smallAgain, 32768, 0x63));
  CHECK(allocator.Free(smallAgain));

  void* freedByZero = allocator.Allocate(128, false);
  CHECK(freedByZero != nullptr);
  CHECK(allocator.Reallocate(freedByZero, 0, false) == nullptr);

  void* allocatedByRealloc = allocator.Reallocate(nullptr, 32769, true);
  CHECK(allocatedByRealloc != nullptr);
  CHECK(IsZeroed(allocatedByRealloc, 32769));
  CHECK(allocator.Free(allocatedByRealloc));

  CHECK(allocator.Shutdown());
  return true;
}

bool TestZeroMemoryAndZeroGrowth() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize());

  constexpr std::array<uint32_t, 11> kZeroSizes{
      0u,   1u,    16u,    17u,   255u,  256u,
      257u, 4096u, 32768u, 32769u, 65536u};
  for (const uint32_t size : kZeroSizes) {
    void* pointer = allocator.Allocate(size, true);
    CHECK(pointer != nullptr);
    CHECK(IsZeroed(pointer, size));
    CHECK(allocator.Free(pointer));
  }

  void* inPlace = allocator.Allocate(17, false);
  CHECK(inPlace != nullptr);
  std::memset(inPlace, 0x74, 17);
  void* inPlaceGrown = allocator.Reallocate(inPlace, 23, true);
  CHECK(inPlaceGrown == inPlace);
  CHECK(VerifySentinels(inPlaceGrown, 17, 0x74));
  CHECK(IsZeroed(static_cast<uint8_t*>(inPlaceGrown) + 17, 6));

  void* inPlaceShrunk = allocator.Reallocate(inPlaceGrown, 17, false);
  CHECK(inPlaceShrunk == inPlaceGrown);
  std::memset(static_cast<uint8_t*>(inPlaceShrunk) + 17, 0x85, 6);
  void* regrown = allocator.Reallocate(inPlaceShrunk, 23, true);
  CHECK(regrown == inPlaceShrunk);
  CHECK(IsZeroed(static_cast<uint8_t*>(regrown) + 17, 6));
  CHECK(allocator.Free(regrown));

  void* crossClass = allocator.Allocate(32, false);
  CHECK(crossClass != nullptr);
  std::memset(crossClass, 0x96, 32);
  void* crossClassGrown = allocator.Reallocate(crossClass, 33, true);
  CHECK(crossClassGrown != nullptr);
  CHECK(crossClassGrown != crossClass);
  CHECK(VerifySentinels(crossClassGrown, 32, 0x96));
  CHECK(static_cast<uint8_t*>(crossClassGrown)[32] == 0);
  CHECK(allocator.Free(crossClassGrown));

  void* routeChange = allocator.Allocate(32768, false);
  CHECK(routeChange != nullptr);
  std::memset(routeChange, 0xA7, 32768);
  void* routeChangeGrown = allocator.Reallocate(routeChange, 32769, true);
  CHECK(routeChangeGrown != nullptr);
  CHECK(routeChangeGrown != routeChange);
  CHECK(VerifySentinels(routeChangeGrown, 32768, 0xA7));
  CHECK(static_cast<uint8_t*>(routeChangeGrown)[32768] == 0);

  void* largeGrown = allocator.Reallocate(routeChangeGrown, 65537, true);
  CHECK(largeGrown != nullptr);
  CHECK(VerifySentinels(largeGrown, 32768, 0xA7));
  CHECK(IsZeroed(static_cast<uint8_t*>(largeGrown) + 32769,
                 65537u - 32769u));
  CHECK(allocator.Free(largeGrown));

  CHECK(allocator.Shutdown());
  return true;
}

bool ExerciseSpanRecycling(bool cacheEmptySpans, bool remoteFree,
                           uint32_t rounds) {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize(cacheEmptySpans, 64u, remoteFree));

  struct Batch {
    uint32_t size;
    uint32_t count;
  };
  constexpr std::array<Batch, 4> kBatches{{
      {16u, 16384u},
      {256u, 4096u},
      {4096u, 512u},
      {32768u, 96u},
  }};

  std::vector<Block> blocks;
  blocks.reserve(16384u);
  for (uint32_t round = 0; round < rounds; ++round) {
    for (const Batch batch : kBatches) {
      blocks.clear();
      blocks.reserve(batch.count);
      for (uint32_t index = 0; index < batch.count; ++index) {
        Block block{};
        block.pointer = allocator.Allocate(batch.size, false);
        block.size = batch.size;
        block.pattern = static_cast<uint8_t>(
            1u + ((round * 37u + index * 13u + batch.size) % 251u));
        CHECK(block.pointer != nullptr);
        FillSentinels(block.pointer, block.size, block.pattern);
        blocks.push_back(block);
      }

      for (const Block& block : blocks) {
        CHECK(VerifySentinels(block.pointer, block.size, block.pattern));
      }

      // Odd/even reverse order empties spans in a repeatable non-LIFO pattern.
      for (size_t index = blocks.size(); index-- > 0;) {
        if ((index & 1u) != 0) {
          CHECK(allocator.Free(blocks[index].pointer));
        }
      }
      for (size_t index = blocks.size(); index-- > 0;) {
        if ((index & 1u) == 0) {
          CHECK(allocator.Free(blocks[index].pointer));
        }
      }
    }
  }

  CHECK(allocator.Shutdown());
  return true;
}

bool TestSpanRecycleAndCache() {
  CHECK(ExerciseSpanRecycling(true, false, 5));
  CHECK(ExerciseSpanRecycling(false, false, 2));
  CHECK(ExerciseSpanRecycling(true, true, 5));
  CHECK(ExerciseSpanRecycling(false, true, 2));
  return true;
}

bool TestLazySpanInitialization() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize(true, 64u, false, true));

  std::vector<Block> blocks;
  blocks.reserve(12000u);
  for (uint32_t index = 0; index < 12000u; ++index) {
    const uint32_t size = kPayloadClasses[index % kPayloadClasses.size()];
    Block block{};
    block.pointer = allocator.Allocate(size, false);
    block.size = size;
    block.pattern = static_cast<uint8_t>(1u + (index % 251u));
    CHECK(block.pointer != nullptr);
    CHECK(IsAligned16(block.pointer));
    FillSentinels(block.pointer, block.size, block.pattern);
    blocks.push_back(block);
  }

  for (size_t index = 0; index < blocks.size(); index += 2u) {
    CHECK(VerifySentinels(blocks[index].pointer, blocks[index].size,
                          blocks[index].pattern));
    CHECK(allocator.Free(blocks[index].pointer));
  }
  for (size_t index = 1; index < blocks.size(); index += 2u) {
    CHECK(VerifySentinels(blocks[index].pointer, blocks[index].size,
                          blocks[index].pattern));
    CHECK(allocator.Free(blocks[index].pointer));
  }

  CHECK(allocator.Shutdown());
  return true;
}

bool ExerciseFourThreadCrossThreadFree(uint32_t remoteBatchSize) {
  constexpr uint32_t kThreadCount = 4;
  constexpr uint32_t kBlocksPerThread = 768;
  constexpr uint32_t kRounds = 8;
  constexpr std::array<uint32_t, 24> kSizes{
      0u,    1u,     15u,    16u,    17u,    24u,
      25u,   63u,    64u,    65u,    255u,   256u,
      257u,  1024u,  1025u,  4096u,  4097u,  8192u,
      8193u, 16384u, 16385u, 32768u, 32769u, 65537u};

  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize(true, 64u, true, false, remoteBatchSize));

  std::array<std::vector<Block>, kThreadCount> produced;
  for (auto& blocks : produced) {
    blocks.reserve(kBlocksPerThread);
  }
  std::barrier phaseComplete(static_cast<std::ptrdiff_t>(kThreadCount));
  std::atomic<bool> success{true};
  std::array<std::thread, kThreadCount> threads;

  for (uint32_t threadIndex = 0; threadIndex < kThreadCount; ++threadIndex) {
    threads[threadIndex] = std::thread([&, threadIndex] {
      auto& ownBlocks = produced[threadIndex];
      for (uint32_t round = 0; round < kRounds; ++round) {
        ownBlocks.clear();
        for (uint32_t index = 0; index < kBlocksPerThread; ++index) {
          const uint32_t size = kSizes[(index * 17u + threadIndex * 7u +
                                        round * 11u) %
                                       kSizes.size()];
          Block block{};
          block.pointer = allocator.Allocate(size, false);
          block.size = size;
          block.pattern = static_cast<uint8_t>(
              1u + ((round * 43u + threadIndex * 61u + index * 29u) %
                    251u));
          if (!block.pointer) {
            success.store(false, std::memory_order_relaxed);
            break;
          }
          FillSentinels(block.pointer, block.size, block.pattern);
          ownBlocks.push_back(block);
        }

        phaseComplete.arrive_and_wait();

        const uint32_t producer =
            (threadIndex + kThreadCount - 1u) % kThreadCount;
        for (const Block& block : produced[producer]) {
          if (!VerifySentinels(block.pointer, block.size, block.pattern) ||
              !allocator.Free(block.pointer)) {
            success.store(false, std::memory_order_relaxed);
          }
        }
        phaseComplete.arrive_and_wait();
      }
    });
  }

  for (std::thread& thread : threads) {
    thread.join();
  }
  CHECK(success.load(std::memory_order_relaxed));
  CHECK(allocator.Shutdown());
  return true;
}

bool TestFourThreadCrossThreadFree() {
  constexpr std::array<uint32_t, 5> kBatchSizes{0u, 1u, 4u, 16u, 64u};
  for (const uint32_t batchSize : kBatchSizes) {
    CHECK(ExerciseFourThreadCrossThreadFree(batchSize));
  }
  return true;
}

bool TestSubthresholdBatchFlushesAtThreadExit() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Initialize(true, 64u, true, false, 64u));

  constexpr uint32_t kBlockCount = 7u;
  std::array<void*, kBlockCount> blocks{};
  for (uint32_t index = 0; index < kBlockCount; ++index) {
    blocks[index] = allocator.Allocate(64u, false);
    CHECK(blocks[index] != nullptr);
    std::memset(blocks[index], static_cast<int>(0x40u + index), 64u);
  }

  std::atomic<bool> success{true};
  std::thread consumer([&] {
    for (uint32_t index = 0; index < kBlockCount; ++index) {
      const auto* bytes = static_cast<const uint8_t*>(blocks[index]);
      if (bytes[0] != static_cast<uint8_t>(0x40u + index) ||
          !allocator.Free(blocks[index])) {
        success.store(false, std::memory_order_relaxed);
      }
    }
  });
  consumer.join();

  CHECK(success.load(std::memory_order_relaxed));
  CHECK(allocator.Shutdown());
  return true;
}

bool TestShutdownContract() {
  SegregatedArenaAllocator allocator;
  CHECK(allocator.Shutdown());
  CHECK(allocator.Initialize());
  CHECK(allocator.Initialize());

  void* survivor = allocator.Allocate(32769, false);
  CHECK(survivor != nullptr);
  std::memset(survivor, 0xB8, 32769);
  CHECK(!allocator.Shutdown());
  CHECK(VerifySentinels(survivor, 32769, 0xB8));

  void* afterRejectedShutdown = allocator.Allocate(64, true);
  CHECK(afterRejectedShutdown != nullptr);
  CHECK(IsZeroed(afterRejectedShutdown, 64));
  CHECK(allocator.Free(afterRejectedShutdown));
  CHECK(allocator.Free(survivor));
  CHECK(allocator.Shutdown());
  CHECK(allocator.Allocate(16, false) == nullptr);

  CHECK(allocator.Initialize(false));
  void* finalBlock = allocator.Allocate(32768, false);
  CHECK(finalBlock != nullptr);
  CHECK(allocator.Free(finalBlock));
  CHECK(allocator.Shutdown());
  return true;
}

struct TestCase {
  const char* name;
  bool (*function)();
};

} // namespace

int main() {
  constexpr std::array<TestCase, 8> kTests{{
      {"all size-class boundaries", TestEverySizeClassBoundary},
      {"realloc routes", TestReallocateRoutes},
      {"zero memory and growth", TestZeroMemoryAndZeroGrowth},
      {"span recycle and cache", TestSpanRecycleAndCache},
      {"lazy span initialization", TestLazySpanInitialization},
      {"four-thread cross-thread free", TestFourThreadCrossThreadFree},
      {"subthreshold batch thread-exit flush",
       TestSubthresholdBatchFlushesAtThreadExit},
      {"shutdown contract", TestShutdownContract},
  }};

  const auto suiteStart = std::chrono::steady_clock::now();
  for (const TestCase& test : kTests) {
    const auto testStart = std::chrono::steady_clock::now();
    std::printf("[ RUN      ] %s\n", test.name);
    if (!test.function()) {
      std::fprintf(stderr, "[  FAILED  ] %s\n", test.name);
      return 1;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - testStart);
    std::printf("[       OK ] %s (%lld ms)\n", test.name,
                static_cast<long long>(elapsed.count()));
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - suiteStart);
  std::printf("[  PASSED  ] %zu tests (%lld ms)\n", kTests.size(),
              static_cast<long long>(elapsed.count()));
  return 0;
}
