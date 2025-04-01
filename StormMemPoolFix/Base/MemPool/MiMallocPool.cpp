// MiMallocPool.cpp
#include "MiMallocPool.h"
#include "Base/Logger.h"
#include "../../Storm/StormHook.h"
#include <Windows.h>
#include <Base/MemorySafety.h>

MiMallocPool::MiMallocPool() {
    // ���캯������ʵ�ʳ�ʼ�����ȴ�Initialize����
}

MiMallocPool::~MiMallocPool() {
    // ȷ��Shutdown������
    Shutdown();
}

bool MiMallocPool::Initialize(size_t initialSize) {
    if (m_mainHeap) {
        LogMessage("[MiMallocPool] �ѳ�ʼ��");
        return true;
    }

    // 1. ���ü����ύ�ڴ� - �������ڼ��������ڴ�ռ��
    mi_option_set(mi_option_arena_eager_commit, 0);

    // 2. �����ڴ�黹�ӳ� - ��δʹ���ڴ����黹ϵͳ
    mi_option_set(mi_option_purge_delay, 10);

    // 3. ���ý�С��Ԥ���ռ� - ����������ڴ���ߣ���ܹؼ�
    mi_option_set(mi_option_arena_reserve, 16 * 1024);

    // �ӳ��ύ - ����ܻ�����ڴ����ģʽ
    mi_option_set(mi_option_eager_commit_delay, 8);

    mi_option_set(mi_option_reset_decommits, 1);

    // ������Ҫmimalloc��
    m_mainHeap = mi_heap_new();
    if (!m_mainHeap) {
        LogMessage("[MiMallocPool] �޷�����mimalloc����");
        return false;
    }

    // ������ȫ����ר�ö�
    m_safeHeap = mi_heap_new();
    if (!m_safeHeap) {
        LogMessage("[MiMallocPool] �޷�����mimalloc��ȫ��");
        mi_heap_delete(m_mainHeap);
        m_mainHeap = nullptr;
        return false;
    }

    // ���ó�ʼ�ش�С
    m_totalPoolSize.store(initialSize);

    LogMessage("[MiMallocPool] mimalloc��ʼ����ɣ�Ԥ����С: %zu �ֽ�", initialSize);
    return true;
}

void MiMallocPool::Shutdown() {
    if (m_disableMemoryReleasing.load()) {
        LogMessage("[MiMallocPool] ���������ڴ�飬�������������");
        m_mainHeap = nullptr;
        m_safeHeap = nullptr;
        return;
    }

    if (m_mainHeap) {
        mi_heap_destroy(m_mainHeap);
        m_mainHeap = nullptr;
    }

    if (m_safeHeap) {
        mi_heap_destroy(m_safeHeap);
        m_safeHeap = nullptr;
    }

    LogMessage("[MiMallocPool] mimalloc�ر����");
}

void* MiMallocPool::Allocate(size_t size) {
    if (!m_mainHeap) {
        // ����ʼ��
        Initialize(64 * 1024 * 1024);  // Ĭ��64MB
        if (!m_mainHeap) return nullptr;
    }

    size_t lockIndex = get_shard_index(nullptr, size);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    void* ptr = mi_heap_malloc(m_mainHeap, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    return ptr;
}

void MiMallocPool::Free(void* ptr) {
    if (!m_mainHeap || !ptr) return;

    // �����ͷ����ÿ�
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] �����ͷ����ÿ�: %p���Ѻ���", ptr);
        return;
    }

    // ʹ�û���ָ���ַ�ķ�Ƭ��
    size_t lockIndex = get_shard_index(ptr);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    // �ȼ���Ƿ���mimalloc������ڴ�
    bool isMainHeapPtr = mi_heap_check_owned(m_mainHeap, ptr);
    bool isSafeHeapPtr = m_safeHeap && mi_heap_check_owned(m_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // �������mimalloc������ڴ棬��¼��־������
        return;
    }

    // ���ڰ�ȫ�ػ�ȡ��С
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // ����������ѡ���ͷŷ�ʽ
    if (isMainHeapPtr) {
        mi_free(ptr);
    }
    else if (isSafeHeapPtr) {
        mi_free(ptr);  // mimalloc���Զ���ָ��·�ɵ���ȷ�Ķ�
    }
}

void* MiMallocPool::Realloc(void* oldPtr, size_t newSize) {
    if (!m_mainHeap) return nullptr;
    if (!oldPtr) return Allocate(newSize);
    if (newSize == 0) {
        Free(oldPtr);
        return nullptr;
    }

    size_t oldLockIndex = get_shard_index(oldPtr);
    size_t newLockIndex = get_shard_index(nullptr, newSize);

    // ����������Ƭ
    if (oldLockIndex != newLockIndex) {
        // ��˳����������������
        if (oldLockIndex < newLockIndex) {
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);

            size_t oldSize = mi_usable_size(oldPtr);
            void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

            if (newPtr) {
                if (oldSize > 0) {
                    m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
                m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
            }

            return newPtr;
        }
        else {
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);

            size_t oldSize = mi_usable_size(oldPtr);
            void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

            if (newPtr) {
                if (oldSize > 0) {
                    m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
                }
                m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
            }

            return newPtr;
        }
    }
    else {
        std::lock_guard<std::mutex> lock(m_poolMutexes[oldLockIndex]);

        size_t oldSize = mi_usable_size(oldPtr);
        void* newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }

        return newPtr;
    }
}

void* MiMallocPool::AllocateSafe(size_t size) {
    if (!m_mainHeap) {
        // ����ʼ��
        Initialize(64 * 1024 * 1024);  // Ĭ��64MB
        if (!m_mainHeap) return nullptr;
    }

    // ע�⣺������Ӧ���Ѿ���������Ӧ�ķ�Ƭ��

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // �ڲ���ȫ��ֱ����ϵͳ����
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sysPtr) {
            LogMessage("[MiMallocPool] ����ȫ�ڼ�ϵͳ�ڴ����ʧ��: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[MiMallocPool] ����ȫ�ڼ�ʹ��ϵͳ�ڴ�: %p, ��С: %zu", userPtr, size);
        return sysPtr;
    }

    if (!m_safeHeap) {
        if (!m_mainHeap) {
            Initialize(64 * 1024 * 1024);
        }
        if (!m_safeHeap) return nullptr;
    }

    void* ptr = mi_heap_malloc(m_safeHeap, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);
    }

    return ptr;
}

void MiMallocPool::FreeSafe(void* ptr) {
    if (!ptr) return;

    // ע�⣺������Ӧ���Ѿ���������Ӧ�ķ�Ƭ��

    // �����ͷ����ÿ�
    if (IsPermanentBlock(ptr)) {
        LogMessage("[MiMallocPool] �����ͷ����ÿ�: %p���Ѻ���", ptr);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // ����ȫ�ڴ���: ��ָ������ӳ��ͷŶ���
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        return;
    }

    // ����Ƿ���mimalloc������ڴ�
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(m_mainHeap, ptr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(m_safeHeap, ptr);

    if (!isMainHeapPtr && !isSafeHeapPtr) {
        // �������mimalloc������ڴ棬��¼��־������
        return;
    }

    // ��ȡ��С������ͳ��
    size_t size = mi_usable_size(ptr);
    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // ����������ѡ���ͷŷ�ʽ
    if (isMainHeapPtr) {
        mi_free(ptr);
    }
    else if (isSafeHeapPtr) {
        mi_free(ptr);  // mimalloc���Զ���ָ��·�ɵ���ȷ�Ķ�
    }
}

void* MiMallocPool::ReallocSafe(void* oldPtr, size_t newSize) {
    if (!m_mainHeap) return nullptr;
    if (!oldPtr) return AllocateSafe(newSize);
    if (newSize == 0) {
        FreeSafe(oldPtr);
        return nullptr;
    }

    // ע�⣺������Ӧ���Ѿ���������Ӧ�ķ�Ƭ��

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // ����ȫ�ڴ���: ����+����+�ӳ��ͷ�
        void* newPtr = AllocateSafe(newSize);
        if (!newPtr) return nullptr;

        // ���԰�ȫ����
        size_t oldSize = mi_usable_size(oldPtr);
        if (oldSize > 0) {
            size_t copySize = min(oldSize, newSize);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                LogMessage("[MiMallocPool] ����ȫ�ڼ临������ʧ��");
                return nullptr;
            }
        }
        else {
            // ����޷���ȡ��С��ֻ������������
            try {
                memcpy(newPtr, oldPtr, min(64, newSize));
            }
            catch (...) {
                LogMessage("[MiMallocPool] ����ȫ�ڼ临������ʧ��");
                return nullptr;
            }
        }

        // ��oldPtr�����ӳ��ͷŶ��У����ͷţ�ֻ��¼��
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);

        return newPtr;
    }

    // ֱ��ʹ��mimalloc��realloc����
    void* newPtr = nullptr;

    // ����Ƿ���mimalloc������ڴ�
    bool isMainHeapPtr = g_mainHeap && mi_heap_check_owned(m_mainHeap, oldPtr);
    bool isSafeHeapPtr = g_safeHeap && mi_heap_check_owned(m_safeHeap, oldPtr);

    if (isMainHeapPtr) {
        size_t oldSize = mi_usable_size(oldPtr);
        newPtr = mi_heap_realloc(m_mainHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }
    }
    else if (isSafeHeapPtr) {
        size_t oldSize = mi_usable_size(oldPtr);
        newPtr = mi_heap_realloc(m_safeHeap, oldPtr, newSize);

        if (newPtr) {
            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
            m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
        }
    }
    else {
        // �������ǹ�����ڴ棬�������ڴ沢����
        newPtr = AllocateSafe(newSize);
        if (newPtr && oldPtr) {
            // ���Կ���һЩ���ݣ������ǲ�֪��ԭ���С��ֻ�ܱ��ع���
            try {
                memcpy(newPtr, oldPtr, min(newSize, (size_t)64));
            }
            catch (...) {}
        }
    }

    return newPtr;
}

size_t MiMallocPool::GetUsedSize() {
    return m_usedSize.load(std::memory_order_relaxed);
}

size_t MiMallocPool::GetTotalSize() {
    // ȷ���ܴ�Сʼ�մ������ô�С
    size_t currentUsed = GetUsedSize();
    size_t calculatedTotal = m_totalPoolSize.load(std::memory_order_relaxed);

    // ���ʹ���������˼�¼������
    if (currentUsed > calculatedTotal) {
        // �����ܴ�СΪ��ǰʹ������150%
        size_t newTotal = currentUsed * 3 / 2;
        m_totalPoolSize.store(newTotal, std::memory_order_relaxed);
        return newTotal;
    }

    return calculatedTotal;
}

bool MiMallocPool::IsFromPool(void* ptr) {
    if (!ptr) return false;

    __try {
        // ����Ƿ�Ϊmimalloc������ڴ�
        if (m_mainHeap && mi_heap_check_owned(m_mainHeap, ptr)) {
            return true;
        }

        if (m_safeHeap && mi_heap_check_owned(m_safeHeap, ptr)) {
            return true;
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // ����ָ������쳣
        return false;
    }
}

size_t MiMallocPool::GetBlockSize(void* ptr) {
    if (!ptr) return 0;

    __try {
        // ���Ի�ȡStormHeader��Ϣ
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }
    }
    catch (...) {
        // ͷ������ʧ��
    }

    // ����Ƿ�Ϊmimalloc������ڴ�
    bool isMainHeapPtr = false;
    bool isSafeHeapPtr = false;

    try {
        if (m_mainHeap) {
            isMainHeapPtr = mi_heap_check_owned(m_mainHeap, ptr);
        }
    }
    catch (...) {}

    try {
        if (m_safeHeap) {
            isSafeHeapPtr = mi_heap_check_owned(m_safeHeap, ptr);
        }
    }
    catch (...) {}

    if (isMainHeapPtr || isSafeHeapPtr) {
        // ʹ��mimalloc��ȡ���С
        try {
            return mi_usable_size(ptr);
        }
        catch (...) {}
    }

    // ��������ǣ�����0��ʾδ֪��С
    return 0;
}

void MiMallocPool::PrintStats() {
    if (!m_mainHeap) {
        LogMessage("[MiMallocPool] mimallocδ��ʼ��");
        return;
    }

    LogMessage("[MiMallocPool] === mimalloc�ڴ��ͳ�� ===");
    LogMessage("[MiMallocPool] �����ڴ�: %zu KB", m_usedSize.load() / 1024);

    // �ռ�mimalloc��ͳ����Ϣ (mimalloc����Ҳ��ͳ�ƹ���)
    // ��ӡmimalloc�Լ���ͳ����Ϣ
    mi_stats_print(NULL);

    LogMessage("[MiMallocPool] mimallocͳ�����");
}

void MiMallocPool::CheckAndFreeUnusedPools() {
    // ǿ��mimalloc�ռ��ɻ��յ��ڴ�
    if (m_mainHeap) {
        mi_heap_collect(m_mainHeap, true);
    }

    if (m_safeHeap) {
        mi_heap_collect(m_safeHeap, true);
    }
}

void MiMallocPool::DisableMemoryReleasing() {
    m_disableMemoryReleasing.store(true);
    LogMessage("[MiMallocPool] �ѽ����ڴ��ͷţ������ڴ潫���������̽���");
}

void MiMallocPool::HeapCollect() {
    if (m_mainHeap) {
        mi_heap_collect(m_mainHeap, true);
    }
}

void* MiMallocPool::CreateStabilizingBlock(size_t size, const char* purpose) {
    // ʹ��ϵͳ����ȷ���ȶ���
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[MiMallocPool] �޷������ȶ�����: %zu", size);
        return nullptr;
    }

    void* userPtr = static_cast<char*>(rawPtr) + sizeof(StormAllocHeader);

    // ȷ����ȷ����ͷ��
    try {
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(rawPtr);
        header->HeapPtr = SPECIAL_MARKER;  // �����ǣ���ʾ���ǹ���Ŀ�
        header->Size = static_cast<DWORD>(size);
        header->AlignPadding = 0;
        header->Flags = 0x4;  // ���Ϊ���VirtualAlloc
        header->Magic = STORM_MAGIC;
    }
    catch (...) {
        LogMessage("[MiMallocPool] �����ȶ�����ͷ��ʧ��: %p", rawPtr);
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return nullptr;
    }

    LogMessage("[MiMallocPool] �����ȶ�����: %p (��С: %zu, ��;: %s)",
        userPtr, size, purpose ? purpose : "δ֪");

    return userPtr;
}

bool MiMallocPool::ValidatePointer(void* ptr) {
    if (!ptr) return false;

    __try {
        // ���Զ�ȡָ��ĵ�һ���ֽڣ���֤�ɶ�
        volatile char test = *static_cast<char*>(ptr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void MiMallocPool::Preheat() {
    LogMessage("[MiMallocPool] ��ʼԤ���ڴ��...");

    // ���ݳ��������С����Ԥ��
    const std::pair<size_t, int> commonSizes[] = {
        {4, 50},      // 4�ֽڣ�Ԥ��50��
        {16, 30},     // 16�ֽڣ�Ԥ��30��
        {32, 20},     // 32�ֽڣ�Ԥ��20��
        {72, 15},     // 72�ֽڣ�Ԥ��15��
        {108, 15},    // 108�ֽڣ�Ԥ��15��
        {128, 10},    // 128�ֽڣ�Ԥ��10��
        {192, 10},    // 192�ֽڣ�Ԥ��10��
        {256, 10},    // 256�ֽڣ�Ԥ��10��
        {512, 5},     // 512�ֽڣ�Ԥ��5��
        {1024, 5},    // 1KB��Ԥ��5��
        {4096, 3},    // 4KB��Ԥ��3��
        {16384, 2},   // 16KB��Ԥ��2��
        {65536, 1},   // 64KB��Ԥ��1��
        {262144, 1},  // 256KB��Ԥ��1��
    };

    std::vector<void*> preheatedBlocks;

    for (const auto& [size, count] : commonSizes) {
        for (int i = 0; i < count; i++) {
            void* ptr = mi_heap_malloc(m_mainHeap, size);
            if (ptr) preheatedBlocks.push_back(ptr);
        }
    }

    LogMessage("[MiMallocPool] Ԥ�ȷ����� %zu ���ڴ��", preheatedBlocks.size());

    // �ͷ�һ��Ԥ�ȵĿ飬����һ���ڻ�����
    for (size_t i = 0; i < preheatedBlocks.size() / 2; i++) {
        mi_free(preheatedBlocks[i]);
    }

    LogMessage("[MiMallocPool] �ڴ��Ԥ����ɣ��ͷ��� %zu ���ڴ��", preheatedBlocks.size() / 2);
}

void MiMallocPool::DisableActualFree() {
    DisableMemoryReleasing();  // ������ʵ�ֵĺ���
}

size_t MiMallocPool::get_shard_index(void* ptr, size_t size) {
    size_t hash;
    if (ptr) {
        // FNV-1a��ϣ�ļ򻯰�
        hash = (reinterpret_cast<uintptr_t>(ptr) * 2654435761) >> 16;
    }
    else {
        // ���ڲ�ͬ��С�ķ���ʹ�ø���ѧ�ķֲ�
        if (size <= 128) {
            hash = size / 16;
        }
        else if (size <= 4096) {
            hash = 8 + (size - 128) / 64;
        }
        else if (size <= 65536) {
            hash = 70 + (size / 1024);
        }
        else {
            hash = 134 + (size / 16384);
        }
    }
    return hash % LOCK_SHARDS;
}