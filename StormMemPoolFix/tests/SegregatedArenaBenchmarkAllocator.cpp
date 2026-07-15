#include "pch.h"
#include "SegregatedArenaBenchmarkAllocator.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>

namespace StormBreaker::Benchmark {
namespace {

constexpr uint32_t kChunkSize = 64u * 1024u * 1024u;
constexpr uint32_t kMinimumSpanSize = 16u * 1024u;
constexpr uint32_t kMaximumSpanSize = 64u * 1024u;
constexpr uint32_t kMaxChunks = 8u;
constexpr uint32_t kMaxPages =
    (kChunkSize / kMinimumSpanSize) * kMaxChunks;
constexpr uint32_t kEmptySpansPerClass = 2u;
constexpr uint32_t kSpanMagic = 0x53424153u;
constexpr uint32_t kBlockMagic = 0x5342424Cu;
constexpr uint32_t kLargeClass = UINT32_MAX;
constexpr uint32_t kRemoteBatchSlotCount = 16u;

// The 16-byte header makes 24/40/56-byte payload classes physically
// identical to 32/48/64 after alignment. Keeping those classes only split
// locality across extra locks and spans without saving memory.
constexpr std::array<uint32_t, 40> kPayloadClasses{
    16u,    32u,    48u,    64u,    80u,    96u,    112u,   128u,
    160u,   192u,   224u,   256u,   320u,   384u,   448u,   512u,
    640u,   768u,   896u,   1024u,  1280u,  1536u,  1792u,  2048u,
    2560u,  3072u,  3584u,  4096u,  5120u,  6144u,  7168u,  8192u,
    10240u, 12288u, 14336u, 16384u, 20480u, 24576u, 28672u, 32768u};

uint32_t Mix32(uint32_t value) noexcept {
  value ^= value >> 16;
  value *= 0x7FEB352Du;
  value ^= value >> 15;
  value *= 0x846CA68Bu;
  value ^= value >> 16;
  return value;
}

constexpr uint32_t Align16(uint32_t value) noexcept {
  return (value + 15u) & ~15u;
}

uint32_t FindClass(uint32_t size) noexcept {
  if (size <= 16u) {
    return 0u;
  }
  if (size <= 128u) {
    return ((size + 15u) >> 4u) - 1u;
  }
  if (size <= 256u) {
    return 8u + ((size - 129u) >> 5u);
  }
  if (size <= 512u) {
    return 12u + ((size - 257u) >> 6u);
  }
  if (size <= 1024u) {
    return 16u + ((size - 513u) >> 7u);
  }
  if (size <= 2048u) {
    return 20u + ((size - 1025u) >> 8u);
  }
  if (size <= 4096u) {
    return 24u + ((size - 2049u) >> 9u);
  }
  if (size <= 8192u) {
    return 28u + ((size - 4097u) >> 10u);
  }
  if (size <= 16384u) {
    return 32u + ((size - 8193u) >> 11u);
  }
  if (size <= 32768u) {
    return 36u + ((size - 16385u) >> 12u);
  }
  return kLargeClass;
}

struct FreeNode {
  FreeNode* next;
};

struct alignas(16) BlockHeader {
  uint32_t magic;
  uint32_t requestedSize;
  uint32_t classIndex;
  uint32_t cookie;
};

static_assert(sizeof(BlockHeader) == 16);

struct alignas(64) SpanHeader {
  uint32_t magic;
  uint32_t classIndex;
  uint32_t blockSize;
  uint32_t capacity;
  volatile LONG liveBlocks;
  uint32_t inAvailableList;
  uint32_t countedEmpty;
  uint32_t nextUnused;
  uint32_t ownerThreadId;
  FreeNode* freeList;
  void* volatile remoteFreeList;
  SpanHeader* previousAvailable;
  SpanHeader* nextAvailable;
  uint8_t padding[64u - 13u * sizeof(uint32_t)];
};

static_assert(sizeof(void*) == sizeof(uint32_t));
static_assert(sizeof(SpanHeader) == 64);

struct ClassState {
  SRWLOCK lock = SRWLOCK_INIT;
  SpanHeader* available = nullptr;
  uint32_t emptySpans = 0;
  volatile LONG liveBlocks = 0;
};

uint32_t HeaderCookie(const BlockHeader* header, uint32_t requestedSize,
                      uint32_t classIndex, uint32_t secret) noexcept {
  return Mix32(static_cast<uint32_t>(
                   reinterpret_cast<uintptr_t>(header)) ^
               requestedSize ^ (classIndex * 0x9E3779B9u) ^ secret);
}

SpanHeader* SpanFor(const BlockHeader* header, uint32_t spanSize) noexcept {
  const uintptr_t address = reinterpret_cast<uintptr_t>(header);
  return reinterpret_cast<SpanHeader*>(address & ~(spanSize - 1u));
}

void AddAvailable(ClassState& state, SpanHeader* span) noexcept {
  span->previousAvailable = nullptr;
  span->nextAvailable = state.available;
  if (state.available) {
    state.available->previousAvailable = span;
  }
  state.available = span;
  span->inAvailableList = 1;
}

void RemoveAvailable(ClassState& state, SpanHeader* span) noexcept {
  if (!span->inAvailableList) {
    return;
  }
  if (span->previousAvailable) {
    span->previousAvailable->nextAvailable = span->nextAvailable;
  } else {
    state.available = span->nextAvailable;
  }
  if (span->nextAvailable) {
    span->nextAvailable->previousAvailable = span->previousAvailable;
  }
  span->previousAvailable = nullptr;
  span->nextAvailable = nullptr;
  span->inAvailableList = 0;
}

LONG LoadLiveBlocks(const SpanHeader* span) noexcept {
  return InterlockedCompareExchange(
      const_cast<volatile LONG*>(&span->liveBlocks), 0, 0);
}

FreeNode* TakeRemoteFreeList(SpanHeader* span) noexcept {
  return static_cast<FreeNode*>(InterlockedExchangePointer(
      &span->remoteFreeList, nullptr));
}

bool HasRemoteFreeBlocks(SpanHeader* span) noexcept {
  return InterlockedCompareExchangePointer(
             &span->remoteFreeList, nullptr, nullptr) != nullptr;
}

void DrainRemoteFreeList(SpanHeader* span) noexcept {
  FreeNode* remote = TakeRemoteFreeList(span);
  while (remote) {
    FreeNode* next = remote->next;
    remote->next = span->freeList;
    span->freeList = remote;
    remote = next;
  }
}

void PushRemoteFree(SpanHeader* span, FreeNode* node) noexcept {
  void* observed = InterlockedCompareExchangePointer(
      &span->remoteFreeList, nullptr, nullptr);
  do {
    node->next = static_cast<FreeNode*>(observed);
  } while ((observed = InterlockedCompareExchangePointer(
                &span->remoteFreeList, node, observed)) != node->next);
}

void PushRemoteBatch(SpanHeader* span, FreeNode* head,
                     FreeNode* tail) noexcept {
  void* observed = InterlockedCompareExchangePointer(
      &span->remoteFreeList, nullptr, nullptr);
  do {
    tail->next = static_cast<FreeNode*>(observed);
  } while ((observed = InterlockedCompareExchangePointer(
                &span->remoteFreeList, head, observed)) != tail->next);
}

bool HasLocalCapacity(const SpanHeader* span) noexcept {
  return span->freeList != nullptr || span->nextUnused < span->capacity;
}

using RemoteBatchFlushFunction = void (*)(
    void* owner, SpanHeader* span, FreeNode* head, FreeNode* tail,
    uint32_t count) noexcept;

struct RemoteBatchSlot {
  void* owner = nullptr;
  SpanHeader* span = nullptr;
  FreeNode* head = nullptr;
  FreeNode* tail = nullptr;
  uint32_t count = 0;
  RemoteBatchFlushFunction flush = nullptr;
};

class ThreadRemoteBatchCache final {
public:
  ~ThreadRemoteBatchCache() noexcept {
    FlushAll();
  }

  bool Enqueue(void* owner, SpanHeader* span, FreeNode* node,
               uint32_t batchSize,
               RemoteBatchFlushFunction flush) noexcept {
    if (!owner || !span || !node || batchSize < 2u || !flush) {
      return false;
    }

    const uintptr_t spanKey = reinterpret_cast<uintptr_t>(span) >> 16u;
    const uint32_t set = static_cast<uint32_t>(
        (spanKey * 0x9E3779B1u) & ((kRemoteBatchSlotCount / 2u) - 1u));
    RemoteBatchSlot* const first = &slots_[set * 2u];
    RemoteBatchSlot* const second = first + 1;
    RemoteBatchSlot* selected = nullptr;
    RemoteBatchSlot* empty = nullptr;
    for (RemoteBatchSlot* slot : {first, second}) {
      if (slot->owner == owner && slot->span == span) {
        selected = slot;
        break;
      }
      if (!empty && !slot->owner) {
        empty = slot;
      }
    }
    if (!selected) {
      selected = empty ? empty
                       : (first->count >= second->count ? first : second);
      FlushSlot(*selected);
      selected->owner = owner;
      selected->span = span;
      selected->flush = flush;
    }

    node->next = selected->head;
    selected->head = node;
    if (selected->count == 0) {
      selected->tail = node;
    }
    ++selected->count;
    if (selected->count >= batchSize) {
      FlushSlot(*selected);
    }
    return true;
  }

  void FlushOwner(void* owner) noexcept {
    for (RemoteBatchSlot& slot : slots_) {
      if (slot.owner == owner) {
        FlushSlot(slot);
      }
    }
  }

private:
  static void FlushSlot(RemoteBatchSlot& slot) noexcept {
    if (!slot.owner) {
      return;
    }
    const RemoteBatchFlushFunction flush = slot.flush;
    void* const owner = slot.owner;
    SpanHeader* const span = slot.span;
    FreeNode* const head = slot.head;
    FreeNode* const tail = slot.tail;
    const uint32_t count = slot.count;
    slot = {};
    flush(owner, span, head, tail, count);
  }

  void FlushAll() noexcept {
    for (RemoteBatchSlot& slot : slots_) {
      FlushSlot(slot);
    }
  }

  std::array<RemoteBatchSlot, kRemoteBatchSlotCount> slots_{};
};

thread_local ThreadRemoteBatchCache tls_remoteBatches;

} // namespace

struct SegregatedArenaAllocator::State {
  SRWLOCK arenaLock = SRWLOCK_INIT;
  HANDLE largeHeap = nullptr;
  void* chunks[kMaxChunks]{};
  uint32_t usedPages[kMaxChunks]{};
  void* recycledPages[kMaxPages]{};
  SpanHeader* activeSpans[kMaxPages]{};
  uint32_t recycledCount = 0;
  uint32_t chunkCount = 0;
  uint32_t spanSize = kMaximumSpanSize;
  uint32_t pagesPerChunk = kChunkSize / kMaximumSpanSize;
  uint32_t secret = 0xA110CA7Eu;
  uint32_t emptySpanLimit = kEmptySpansPerClass;
  bool remoteFreeEnabled = false;
  bool lazySpanInitialization = false;
  uint32_t remoteBatchSize = 0;
  std::atomic<bool> corrupted{false};
  std::atomic<uint32_t> largeLiveBlocks{0};
  ClassState classes[kPayloadClasses.size()]{};

  uint32_t SpanSlot(const void* span) const noexcept {
    const uintptr_t address = reinterpret_cast<uintptr_t>(span);
    for (uint32_t chunk = 0; chunk < chunkCount; ++chunk) {
      const uintptr_t begin = reinterpret_cast<uintptr_t>(chunks[chunk]);
      if (address >= begin && address < begin + kChunkSize) {
        const uint32_t minimumPage = static_cast<uint32_t>(
            (address - begin) / kMinimumSpanSize);
        return chunk * (kChunkSize / kMinimumSpanSize) + minimumPage;
      }
    }
    return UINT32_MAX;
  }

  bool RegisterSpan(SpanHeader* span) noexcept {
    AcquireSRWLockExclusive(&arenaLock);
    const uint32_t slot = SpanSlot(span);
    const bool valid = slot < kMaxPages && activeSpans[slot] == nullptr;
    if (valid) {
      activeSpans[slot] = span;
    }
    ReleaseSRWLockExclusive(&arenaLock);
    return valid;
  }

  void UnregisterSpan(SpanHeader* span) noexcept {
    AcquireSRWLockExclusive(&arenaLock);
    const uint32_t slot = SpanSlot(span);
    if (slot < kMaxPages && activeSpans[slot] == span) {
      activeSpans[slot] = nullptr;
    }
    ReleaseSRWLockExclusive(&arenaLock);
  }

  void* AcquirePage() noexcept {
    AcquireSRWLockExclusive(&arenaLock);
    void* page = nullptr;
    if (recycledCount != 0) {
      page = recycledPages[--recycledCount];
    } else {
      uint32_t chunk = chunkCount;
      if (chunk == 0 || usedPages[chunk - 1u] == pagesPerChunk) {
        if (chunk == kMaxChunks) {
          ReleaseSRWLockExclusive(&arenaLock);
          return nullptr;
        }
        void* base = VirtualAlloc(nullptr, kChunkSize, MEM_RESERVE,
                                  PAGE_READWRITE);
        if (!base) {
          ReleaseSRWLockExclusive(&arenaLock);
          return nullptr;
        }
        chunks[chunk] = base;
        usedPages[chunk] = 0;
        ++chunkCount;
        ++chunk;
      }
      const uint32_t active = chunk - 1u;
      page = static_cast<uint8_t*>(chunks[active]) +
             usedPages[active]++ * spanSize;
    }

    if (!VirtualAlloc(page, spanSize, MEM_COMMIT, PAGE_READWRITE)) {
      recycledPages[recycledCount++] = page;
      page = nullptr;
    }
    ReleaseSRWLockExclusive(&arenaLock);
    return page;
  }

  void RecyclePage(void* page) noexcept {
    VirtualFree(page, spanSize, MEM_DECOMMIT);
    AcquireSRWLockExclusive(&arenaLock);
    if (recycledCount < kMaxPages) {
      recycledPages[recycledCount++] = page;
    }
    ReleaseSRWLockExclusive(&arenaLock);
  }

  SpanHeader* CreateSpan(uint32_t classIndex) noexcept {
    void* page = AcquirePage();
    if (!page) {
      return nullptr;
    }
    auto* span = static_cast<SpanHeader*>(page);
    const uint32_t blockSize =
        Align16(sizeof(BlockHeader) + kPayloadClasses[classIndex]);
    const uint32_t capacity = (spanSize - sizeof(SpanHeader)) / blockSize;
    if (capacity == 0) {
      RecyclePage(page);
      return nullptr;
    }
    span->magic = kSpanMagic;
    span->classIndex = classIndex;
    span->blockSize = blockSize;
    span->capacity = capacity;
    span->liveBlocks = 0;
    span->inAvailableList = 0;
    span->countedEmpty = 0;
    span->nextUnused = 0;
    span->ownerThreadId = GetCurrentThreadId();
    span->freeList = nullptr;
    span->remoteFreeList = nullptr;
    span->previousAvailable = nullptr;
    span->nextAvailable = nullptr;
    if (!lazySpanInitialization) {
      auto* cursor = static_cast<uint8_t*>(page) + sizeof(SpanHeader);
      for (uint32_t index = 0; index < capacity; ++index) {
        auto* node = reinterpret_cast<FreeNode*>(cursor + index * blockSize);
        node->next = span->freeList;
        span->freeList = node;
      }
      span->nextUnused = capacity;
    }
    if (remoteFreeEnabled && !RegisterSpan(span)) {
      RecyclePage(page);
      return nullptr;
    }
    return span;
  }

  void* AllocateSmall(uint32_t size, uint32_t classIndex,
                      bool zeroMemory) noexcept {
    ClassState& state = classes[classIndex];
    AcquireSRWLockExclusive(&state.lock);
    SpanHeader* span = state.available;
    while (span && remoteFreeEnabled) {
      DrainRemoteFreeList(span);
      if (HasLocalCapacity(span)) {
        break;
      }
      SpanHeader* next = span->nextAvailable;
      if (LoadLiveBlocks(span) == static_cast<LONG>(span->capacity) &&
          !HasRemoteFreeBlocks(span)) {
        RemoveAvailable(state, span);
      }
      span = next;
    }
    if (!span) {
      ReleaseSRWLockExclusive(&state.lock);
      span = CreateSpan(classIndex);
      if (!span) {
        return nullptr;
      }
      AcquireSRWLockExclusive(&state.lock);
      AddAvailable(state, span);
      span->countedEmpty = 1;
      ++state.emptySpans;
    }

    if (remoteFreeEnabled) {
      DrainRemoteFreeList(span);
    }
    FreeNode* node = span->freeList;
    if (node) {
      span->freeList = node->next;
    } else if (span->nextUnused < span->capacity) {
      auto* cursor = reinterpret_cast<uint8_t*>(span) + sizeof(SpanHeader);
      node = reinterpret_cast<FreeNode*>(
          cursor + span->nextUnused++ * span->blockSize);
    } else {
      ReleaseSRWLockExclusive(&state.lock);
      return nullptr;
    }
    const LONG previousLive = remoteFreeEnabled
                                  ? InterlockedIncrement(&span->liveBlocks) - 1
                                  : span->liveBlocks++;
    if (previousLive == 0 && span->countedEmpty) {
      --state.emptySpans;
      span->countedEmpty = 0;
      span->ownerThreadId = GetCurrentThreadId();
    }
    if (!remoteFreeEnabled) {
      ++state.liveBlocks;
    }
    if (!HasLocalCapacity(span) &&
        (!remoteFreeEnabled ||
         (LoadLiveBlocks(span) == static_cast<LONG>(span->capacity) &&
          !HasRemoteFreeBlocks(span)))) {
      RemoveAvailable(state, span);
    }
    ReleaseSRWLockExclusive(&state.lock);

    auto* header = reinterpret_cast<BlockHeader*>(node);
    header->magic = kBlockMagic;
    header->requestedSize = size;
    header->classIndex = classIndex;
    header->cookie = HeaderCookie(header, size, classIndex, secret);
    void* user = header + 1;
    if (zeroMemory && size != 0) {
      std::memset(user, 0, size);
    }
    return user;
  }

  void* AllocateLarge(uint32_t size, bool zeroMemory) noexcept {
    if (size > UINT32_MAX - sizeof(BlockHeader)) {
      return nullptr;
    }
    auto* header = static_cast<BlockHeader*>(HeapAlloc(
        largeHeap, 0, sizeof(BlockHeader) + (size == 0 ? 1u : size)));
    if (!header) {
      return nullptr;
    }
    header->magic = kBlockMagic;
    header->requestedSize = size;
    header->classIndex = kLargeClass;
    header->cookie = HeaderCookie(header, size, kLargeClass, secret);
    void* user = header + 1;
    if (zeroMemory && size != 0) {
      std::memset(user, 0, size);
    }
    largeLiveBlocks.fetch_add(1u, std::memory_order_relaxed);
    return user;
  }

  bool Decode(void* pointer, BlockHeader** outHeader) const noexcept {
    if (!pointer || !outHeader) {
      return false;
    }
    auto* header = static_cast<BlockHeader*>(pointer) - 1;
    if (header->magic != kBlockMagic ||
        (header->classIndex != kLargeClass &&
         header->classIndex >= kPayloadClasses.size()) ||
        header->cookie != HeaderCookie(header, header->requestedSize,
                                       header->classIndex, secret)) {
      return false;
    }
    *outHeader = header;
    return true;
  }

  bool FreeSmallLocked(BlockHeader* header, SpanHeader* span,
                       ClassState& state) noexcept {
    if (span->liveBlocks == 0) {
      return false;
    }
    const bool wasFull = !HasLocalCapacity(span);
    auto* node = reinterpret_cast<FreeNode*>(header);
    node->next = span->freeList;
    span->freeList = node;
    --span->liveBlocks;
    --state.liveBlocks;
    if (wasFull) {
      AddAvailable(state, span);
    }
    if (span->liveBlocks == 0) {
      if (state.emptySpans < emptySpanLimit) {
        span->countedEmpty = 1;
        ++state.emptySpans;
      } else {
        RemoveAvailable(state, span);
        span->magic = 0;
        return true;
      }
    }
    return false;
  }

  bool FreeSmallRemote(BlockHeader* header, SpanHeader* span,
                       ClassState& state) noexcept {
    auto* node = reinterpret_cast<FreeNode*>(header);
    PushRemoteFree(span, node);
    const LONG remaining = InterlockedDecrement(&span->liveBlocks);
    if (remaining < 0) {
      return false;
    }
    const bool transitionFromFull =
        remaining + 1 == static_cast<LONG>(span->capacity);
    const bool transitionToEmpty = remaining == 0;
    if (!transitionFromFull && !transitionToEmpty) {
      return false;
    }

    bool recycle = false;
    AcquireSRWLockExclusive(&state.lock);
    DrainRemoteFreeList(span);
    if (span->freeList && !span->inAvailableList) {
      AddAvailable(state, span);
    }
    if (LoadLiveBlocks(span) == 0 && !span->countedEmpty) {
      if (state.emptySpans < emptySpanLimit) {
        span->countedEmpty = 1;
        ++state.emptySpans;
      } else {
        RemoveAvailable(state, span);
        span->magic = 0;
        recycle = true;
      }
    }
    ReleaseSRWLockExclusive(&state.lock);
    return recycle;
  }

  bool FreeSmallOwnerLocked(BlockHeader* header, SpanHeader* span,
                            ClassState& state) noexcept {
    if (LoadLiveBlocks(span) <= 0) {
      return false;
    }
    DrainRemoteFreeList(span);
    const bool wasFull = !HasLocalCapacity(span);
    auto* node = reinterpret_cast<FreeNode*>(header);
    node->next = span->freeList;
    span->freeList = node;
    const LONG remaining = InterlockedDecrement(&span->liveBlocks);
    if (remaining < 0) {
      corrupted.store(true, std::memory_order_release);
      return false;
    }
    if (wasFull && !span->inAvailableList) {
      AddAvailable(state, span);
    }
    if (remaining == 0 && !span->countedEmpty) {
      if (state.emptySpans < emptySpanLimit) {
        span->countedEmpty = 1;
        ++state.emptySpans;
      } else {
        RemoveAvailable(state, span);
        span->magic = 0;
        return true;
      }
    }
    return false;
  }

  void FlushRemoteBatch(SpanHeader* span, FreeNode* head,
                        FreeNode* tail, uint32_t count) noexcept {
    if (!span || !head || !tail || count == 0 ||
        span->magic != kSpanMagic ||
        span->classIndex >= kPayloadClasses.size()) {
      corrupted.store(true, std::memory_order_release);
      return;
    }

    PushRemoteBatch(span, head, tail);
    const LONG previous = InterlockedExchangeAdd(
        &span->liveBlocks, -static_cast<LONG>(count));
    if (previous < static_cast<LONG>(count)) {
      corrupted.store(true, std::memory_order_release);
      return;
    }
    const LONG remaining = previous - static_cast<LONG>(count);
    if (previous != static_cast<LONG>(span->capacity) && remaining != 0) {
      return;
    }

    ClassState& state = classes[span->classIndex];
    bool recycle = false;
    AcquireSRWLockExclusive(&state.lock);
    DrainRemoteFreeList(span);
    if (HasLocalCapacity(span) && !span->inAvailableList) {
      AddAvailable(state, span);
    }
    if (LoadLiveBlocks(span) == 0 && !span->countedEmpty) {
      if (state.emptySpans < emptySpanLimit) {
        span->countedEmpty = 1;
        ++state.emptySpans;
      } else {
        RemoveAvailable(state, span);
        span->magic = 0;
        recycle = true;
      }
    }
    ReleaseSRWLockExclusive(&state.lock);
    if (recycle) {
      UnregisterSpan(span);
      RecyclePage(span);
    }
  }

  static void FlushRemoteBatchThunk(
      void* owner, SpanHeader* span, FreeNode* head, FreeNode* tail,
      uint32_t count) noexcept {
    static_cast<State*>(owner)->FlushRemoteBatch(
        span, head, tail, count);
  }

  bool FreeSmall(BlockHeader* header) noexcept {
    SpanHeader* span = SpanFor(header, spanSize);
    const uint32_t classIndex = header->classIndex;
    if (span->magic != kSpanMagic || span->classIndex != classIndex) {
      return false;
    }
    ClassState& state = classes[classIndex];
    bool recycle = false;
    if (remoteFreeEnabled) {
      if (remoteBatchSize != 0 &&
          span->ownerThreadId == GetCurrentThreadId()) {
        AcquireSRWLockExclusive(&state.lock);
        recycle = FreeSmallOwnerLocked(header, span, state);
        ReleaseSRWLockExclusive(&state.lock);
      } else if (remoteBatchSize > 1u) {
        return tls_remoteBatches.Enqueue(
            this, span, reinterpret_cast<FreeNode*>(header),
            remoteBatchSize, &State::FlushRemoteBatchThunk);
      } else {
        recycle = FreeSmallRemote(header, span, state);
      }
    } else {
      AcquireSRWLockExclusive(&state.lock);
      recycle = FreeSmallLocked(header, span, state);
      ReleaseSRWLockExclusive(&state.lock);
    }
    if (recycle) {
      if (remoteFreeEnabled) {
        UnregisterSpan(span);
      }
      RecyclePage(span);
    }
    return true;
  }

  uint32_t FindUsableClass(uint32_t size) const noexcept {
    const uint32_t classIndex = FindClass(size);
    if (classIndex == kLargeClass) {
      return classIndex;
    }
    const uint32_t blockSize =
        Align16(sizeof(BlockHeader) + kPayloadClasses[classIndex]);
    return blockSize <= spanSize - sizeof(SpanHeader)
               ? classIndex
               : kLargeClass;
  }
};

SegregatedArenaAllocator::~SegregatedArenaAllocator() noexcept {
  Shutdown();
}

bool SegregatedArenaAllocator::Initialize(bool cacheEmptySpans,
                                           uint32_t spanSizeKiB,
                                           bool remoteFree,
                                           bool lazySpanInitialization,
                                           uint32_t remoteBatchSize) noexcept {
  if (state_) {
    return true;
  }
  if (spanSizeKiB != 16u && spanSizeKiB != 32u && spanSizeKiB != 64u) {
    return false;
  }
  if ((!remoteFree && remoteBatchSize != 0u) ||
      (remoteBatchSize != 0u && remoteBatchSize != 1u &&
       remoteBatchSize != 4u && remoteBatchSize != 8u &&
       remoteBatchSize != 16u && remoteBatchSize != 32u &&
       remoteBatchSize != 64u)) {
    return false;
  }
  State* state = static_cast<State*>(VirtualAlloc(
      nullptr, sizeof(State), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!state) {
    return false;
  }
  new (state) State{};
  LARGE_INTEGER counter{};
  QueryPerformanceCounter(&counter);
  state->secret = Mix32(counter.LowPart ^ counter.HighPart ^
                        GetCurrentThreadId() ^
                        static_cast<uint32_t>(
                            reinterpret_cast<uintptr_t>(state)));
  state->emptySpanLimit = cacheEmptySpans ? kEmptySpansPerClass : 0u;
  state->remoteFreeEnabled = remoteFree;
  state->lazySpanInitialization = lazySpanInitialization;
  state->remoteBatchSize = remoteBatchSize;
  state->spanSize = spanSizeKiB * 1024u;
  state->pagesPerChunk = kChunkSize / state->spanSize;
  state->largeHeap = HeapCreate(0, 0, 0);
  if (!state->largeHeap) {
    state->~State();
    VirtualFree(state, 0, MEM_RELEASE);
    return false;
  }
  ULONG compatibility = 2;
  if (!HeapSetInformation(state->largeHeap, HeapCompatibilityInformation,
                          &compatibility, sizeof(compatibility))) {
    HeapDestroy(state->largeHeap);
    state->~State();
    VirtualFree(state, 0, MEM_RELEASE);
    return false;
  }
  state_ = state;
  return true;
}

bool SegregatedArenaAllocator::Shutdown() noexcept {
  if (!state_) {
    return true;
  }
  State* state = state_;
  tls_remoteBatches.FlushOwner(state);
  if (state->corrupted.load(std::memory_order_acquire)) {
    return false;
  }
  if (state->largeLiveBlocks.load(std::memory_order_acquire) != 0) {
    return false;
  }
  if (state->remoteFreeEnabled) {
    for (SpanHeader* span : state->activeSpans) {
      if (span && LoadLiveBlocks(span) != 0) {
        return false;
      }
    }
  } else {
    for (ClassState& classState : state->classes) {
      AcquireSRWLockShared(&classState.lock);
      const bool hasLiveBlocks = classState.liveBlocks != 0;
      ReleaseSRWLockShared(&classState.lock);
      if (hasLiveBlocks) {
        return false;
      }
    }
  }
  bool success = true;
  if (state->largeHeap) {
    success = HeapDestroy(state->largeHeap) != FALSE;
    state->largeHeap = nullptr;
  }
  for (uint32_t index = 0; index < state->chunkCount; ++index) {
    if (state->chunks[index] &&
        !VirtualFree(state->chunks[index], 0, MEM_RELEASE)) {
      success = false;
    }
  }
  state->~State();
  VirtualFree(state, 0, MEM_RELEASE);
  state_ = nullptr;
  return success;
}

void* SegregatedArenaAllocator::Allocate(uint32_t size,
                                         bool zeroMemory) noexcept {
  if (!state_) {
    return nullptr;
  }
  const uint32_t classIndex = state_->FindUsableClass(size);
  if (classIndex == kLargeClass) {
    return state_->AllocateLarge(size, zeroMemory);
  }
  void* pointer = state_->AllocateSmall(size, classIndex, zeroMemory);
  // Keep the arena's 512 MiB reservation bound on Win32. Once its span budget
  // is exhausted, preserve allocator semantics through the private LFH route
  // instead of turning bounded VA usage into allocation failures.
  return pointer ? pointer : state_->AllocateLarge(size, zeroMemory);
}

bool SegregatedArenaAllocator::Free(void* pointer) noexcept {
  if (!pointer) {
    return true;
  }
  if (!state_) {
    return false;
  }
  BlockHeader* header = nullptr;
  if (!state_->Decode(pointer, &header)) {
    return false;
  }
  if (header->classIndex != kLargeClass) {
    return state_->FreeSmall(header);
  }
  header->magic = 0;
  if (!HeapFree(state_->largeHeap, 0, header)) {
    return false;
  }
  state_->largeLiveBlocks.fetch_sub(1u, std::memory_order_relaxed);
  return true;
}

void* SegregatedArenaAllocator::Reallocate(void* pointer, uint32_t newSize,
                                           bool zeroGrowth) noexcept {
  if (!pointer) {
    return Allocate(newSize, zeroGrowth);
  }
  if (newSize == 0) {
    Free(pointer);
    return nullptr;
  }
  if (!state_) {
    return nullptr;
  }
  BlockHeader* header = nullptr;
  if (!state_->Decode(pointer, &header)) {
    return nullptr;
  }
  const uint32_t oldSize = header->requestedSize;
  if (header->classIndex != kLargeClass &&
      newSize <= kPayloadClasses[header->classIndex]) {
    if (zeroGrowth && newSize > oldSize) {
      std::memset(static_cast<uint8_t*>(pointer) + oldSize, 0,
                  newSize - oldSize);
    }
    header->requestedSize = newSize;
    header->cookie = HeaderCookie(header, newSize, header->classIndex,
                                  state_->secret);
    return pointer;
  }
  if (header->classIndex == kLargeClass &&
      state_->FindUsableClass(newSize) == kLargeClass) {
    auto* replacement = static_cast<BlockHeader*>(HeapReAlloc(
        state_->largeHeap, 0, header, sizeof(BlockHeader) + newSize));
    if (!replacement) {
      return nullptr;
    }
    void* user = replacement + 1;
    if (zeroGrowth && newSize > oldSize) {
      std::memset(static_cast<uint8_t*>(user) + oldSize, 0,
                  newSize - oldSize);
    }
    replacement->requestedSize = newSize;
    replacement->cookie = HeaderCookie(replacement, newSize, kLargeClass,
                                        state_->secret);
    return user;
  }

  void* replacement = Allocate(newSize, false);
  if (!replacement) {
    return nullptr;
  }
  std::memcpy(replacement, pointer, (std::min)(oldSize, newSize));
  if (zeroGrowth && newSize > oldSize) {
    std::memset(static_cast<uint8_t*>(replacement) + oldSize, 0,
                newSize - oldSize);
  }
  if (!Free(pointer)) {
    Free(replacement);
    return nullptr;
  }
  return replacement;
}

} // namespace StormBreaker::Benchmark
