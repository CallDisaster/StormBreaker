// TLSFPool.cpp
#include "TLSFPool.h"
#include "Base/Logger.h"
#include "StormHook.h"
#include <Windows.h>
#include <Storm/StormHook.h>
#include <Base/MemorySafety.h>

TLSFPool::TLSFPool() {
    // ���캯������ʵ�ʳ�ʼ�����ȴ�Initialize����
}

TLSFPool::~TLSFPool() {
    // ȷ��Shutdown������
    Shutdown();
}

bool TLSFPool::Initialize(size_t initialSize) {
    if (m_tlsfPool) {
        LogMessage("[TLSFPool] �ѳ�ʼ��");
        return true;
    }

    // �����ڴ�ؿռ�
    m_poolMemory = VirtualAlloc(NULL, initialSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!m_poolMemory) {
        LogMessage("[TLSFPool] �޷����������ڴ�: %zu �ֽ�", initialSize);
        return false;
    }

    // ����TLSF��
    m_tlsfPool = tlsf_create(m_poolMemory);
    if (!m_tlsfPool) {
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
        LogMessage("[TLSFPool] �޷�����TLSF����");
        return false;
    }

    // ������ڴ��
    void* pool = tlsf_add_pool(m_tlsfPool,
        static_cast<char*>(m_poolMemory) + tlsf_size(),
        initialSize - tlsf_size());
    if (!pool) {
        tlsf_destroy(m_tlsfPool);
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
        m_tlsfPool = nullptr;
        LogMessage("[TLSFPool] �޷�������ڴ��");
        return false;
    }

    // ������ȫ��
    size_t safePoolSize = initialSize / 10; // 10%�Ĵ�С
    m_safePoolMemory = VirtualAlloc(NULL, safePoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (m_safePoolMemory) {
        m_safeTlsfPool = tlsf_create(m_safePoolMemory);
        if (m_safeTlsfPool) {
            void* safePool = tlsf_add_pool(m_safeTlsfPool,
                static_cast<char*>(m_safePoolMemory) + tlsf_size(),
                safePoolSize - tlsf_size());
            if (!safePool) {
                tlsf_destroy(m_safeTlsfPool);
                VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
                m_safePoolMemory = nullptr;
                m_safeTlsfPool = nullptr;
                LogMessage("[TLSFPool] �޷���Ӱ�ȫ�ڴ�أ�����ʹ������");
            }
        }
        else {
            VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
            m_safePoolMemory = nullptr;
            LogMessage("[TLSFPool] �޷�����TLSF��ȫ�أ�����ʹ������");
        }
    }

    // ���óش�С
    m_totalPoolSize.store(initialSize);

    LogMessage("[TLSFPool] TLSF��ʼ����ɣ�Ԥ����С: %zu �ֽ�", initialSize);
    return true;
}

void TLSFPool::Shutdown() {
    if (m_disableMemoryReleasing.load()) {
        LogMessage("[TLSFPool] ���������ڴ�飬�������������");
        m_tlsfPool = nullptr;
        m_poolMemory = nullptr;
        m_safeTlsfPool = nullptr;
        m_safePoolMemory = nullptr;
        return;
    }

    // ����ȫ��׷�ٱ�
    {
        std::lock_guard<std::mutex> lock(m_trackingMutex);
        m_allocatedBlocks.clear();
    }

    // ����TLSF��
    if (m_safeTlsfPool) {
        tlsf_destroy(m_safeTlsfPool);
        m_safeTlsfPool = nullptr;
    }

    if (m_safePoolMemory) {
        VirtualFree(m_safePoolMemory, 0, MEM_RELEASE);
        m_safePoolMemory = nullptr;
    }

    if (m_tlsfPool) {
        tlsf_destroy(m_tlsfPool);
        m_tlsfPool = nullptr;
    }

    if (m_poolMemory) {
        VirtualFree(m_poolMemory, 0, MEM_RELEASE);
        m_poolMemory = nullptr;
    }

    LogMessage("[TLSFPool] TLSF�ر����");
}

void* TLSFPool::Allocate(size_t size) {
    if (!m_tlsfPool) {
        // ����ʼ��
        Initialize(64 * 1024 * 1024);  // Ĭ��64MB
        if (!m_tlsfPool) return nullptr;
    }

    size_t lockIndex = get_shard_index(nullptr, size);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    void* ptr = tlsf_malloc(m_tlsfPool, size);
    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);

        // ��¼����
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        m_allocatedBlocks[ptr] = size;
    }

    return ptr;
}

void TLSFPool::Free(void* ptr) {
    if (!m_tlsfPool || !ptr) return;

    // �����ͷ����ÿ�
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] �����ͷ����ÿ�: %p���Ѻ���", ptr);
        return;
    }

    size_t lockIndex = get_shard_index(ptr);
    std::lock_guard<std::mutex> lock(m_poolMutexes[lockIndex]);

    // ���Ҽ�¼�Ŀ��С
    size_t size = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(ptr);
        if (it != m_allocatedBlocks.end()) {
            size = it->second;
            m_allocatedBlocks.erase(it);
        }
    }

    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // �ͷ��ڴ�
    tlsf_free(m_tlsfPool, ptr);
}

void* TLSFPool::Realloc(void* oldPtr, size_t newSize) {
    if (!m_tlsfPool) return nullptr;
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
            return ReallocInternal(oldPtr, newSize);
        }
        else {
            std::lock_guard<std::mutex> lock2(m_poolMutexes[newLockIndex]);
            std::lock_guard<std::mutex> lock1(m_poolMutexes[oldLockIndex]);
            return ReallocInternal(oldPtr, newSize);
        }
    }
    else {
        std::lock_guard<std::mutex> lock(m_poolMutexes[oldLockIndex]);
        return ReallocInternal(oldPtr, newSize);
    }
}

void* TLSFPool::AllocateSafe(size_t size) {
    if (!m_tlsfPool) {
        // ����ʼ��
        Initialize(64 * 1024 * 1024);
        if (!m_tlsfPool) return nullptr;
    }

    // ע�⣺������Ӧ���Ѿ���������Ӧ�ķ�Ƭ��

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // ����ȫ��ʹ��ϵͳ����
        void* sysPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sysPtr) {
            LogMessage("[TLSFPool] ����ȫ�ڼ�ϵͳ�ڴ����ʧ��: %zu", size);
            return nullptr;
        }

        void* userPtr = static_cast<char*>(sysPtr) + sizeof(StormAllocHeader);
        SetupCompatibleHeader(userPtr, size - sizeof(StormAllocHeader));
        LogMessage("[TLSFPool] ����ȫ�ڼ�ʹ��ϵͳ�ڴ�: %p, ��С: %zu", userPtr, size);
        return sysPtr;
    }

    // ����ʹ�ð�ȫ��
    void* ptr = nullptr;
    if (m_safeTlsfPool) {
        ptr = tlsf_malloc(m_safeTlsfPool, size);
    }

    // ��ȫ�ط���ʧ�ܣ����˵�����
    if (!ptr && m_tlsfPool) {
        ptr = tlsf_malloc(m_tlsfPool, size);
    }

    if (ptr) {
        m_usedSize.fetch_add(size, std::memory_order_relaxed);

        // ��¼����
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        m_allocatedBlocks[ptr] = size;
    }

    return ptr;
}

void TLSFPool::FreeSafe(void* ptr) {
    if (!ptr) return;

    // ע�⣺������Ӧ���Ѿ���������Ӧ�ķ�Ƭ��

    // �����ͷ����ÿ�
    if (IsPermanentBlock(ptr)) {
        LogMessage("[TLSFPool] �����ͷ����ÿ�: %p���Ѻ���", ptr);
        return;
    }

    if (g_cleanAllInProgress || g_insideUnsafePeriod.load()) {
        // ����ȫ�ڴ���: ��ָ������ӳ��ͷŶ���
        g_MemorySafety.EnqueueDeferredFree(ptr, GetBlockSize(ptr));
        return;
    }

    // ��ȡ���С������ͳ��
    size_t size = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(ptr);
        if (it != m_allocatedBlocks.end()) {
            size = it->second;
            m_allocatedBlocks.erase(it);
        }
    }

    if (size > 0) {
        m_usedSize.fetch_sub(size, std::memory_order_relaxed);
    }

    // �ж��Ƿ����԰�ȫ��
    bool isSafePoolPtr = m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool));
    bool isMainPoolPtr = m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool));

    // ����������ѡ���ͷŷ�ʽ
    if (isSafePoolPtr) {
        tlsf_free(m_safeTlsfPool, ptr);
    }
    else if (isMainPoolPtr) {
        tlsf_free(m_tlsfPool, ptr);
    }
    else {
        // δ֪��Դ��ʹ��VirtualFree
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void* TLSFPool::ReallocSafe(void* oldPtr, size_t newSize) {
    if (!m_tlsfPool) return nullptr;
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

        // ���Ի�ȡ�ɿ��С
        size_t oldSize = GetBlockSize(oldPtr);

        // ���Ը�������
        size_t copySize = oldSize > 0 ? min(oldSize, newSize) : min(newSize, (size_t)64);
        try {
            memcpy(newPtr, oldPtr, copySize);
        }
        catch (...) {
            LogMessage("[TLSFPool] ����ȫ�ڼ临������ʧ��");
            FreeSafe(newPtr);
            return nullptr;
        }

        // ���ͷž�ָ�룬���Ƿ����ӳٶ���
        g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        return newPtr;
    }

    // �ж��Ƿ����԰�ȫ��
    bool isSafePoolPtr = m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool));
    bool isMainPoolPtr = m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool));

    // ��ȡ�ɿ��С
    size_t oldSize = 0;
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        auto it = m_allocatedBlocks.find(oldPtr);
        if (it != m_allocatedBlocks.end()) {
            oldSize = it->second;
        }
    }

    void* newPtr = nullptr;

    // ������Դ��ѡ���ط��䷽ʽ
    if (isSafePoolPtr) {
        newPtr = tlsf_realloc(m_safeTlsfPool, oldPtr, newSize);
    }
    else if (isMainPoolPtr) {
        newPtr = tlsf_realloc(m_tlsfPool, oldPtr, newSize);
    }
    else {
        // δ֪��Դ���������ڴ沢����
        newPtr = AllocateSafe(newSize);
        if (newPtr && oldPtr) {
            size_t copySize = oldSize > 0 ? min(oldSize, newSize) : min(newSize, (size_t)64);
            try {
                memcpy(newPtr, oldPtr, copySize);
            }
            catch (...) {
                FreeSafe(newPtr);
                return nullptr;
            }

            // ����ָ������ӳ��ͷŶ���
            g_MemorySafety.EnqueueDeferredFree(oldPtr, oldSize);
        }
    }

    if (newPtr) {
        // ����ͳ�ƺ͸�����Ϣ
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);

        // ���ָ��仯���Ƴ��ɼ�¼
        if (newPtr != oldPtr) {
            auto it = m_allocatedBlocks.find(oldPtr);
            if (it != m_allocatedBlocks.end()) {
                m_allocatedBlocks.erase(it);
            }

            if (oldSize > 0) {
                m_usedSize.fetch_sub(oldSize, std::memory_order_relaxed);
            }
        }

        // ����¼�¼
        m_allocatedBlocks[newPtr] = newSize;
        m_usedSize.fetch_add(newSize, std::memory_order_relaxed);
    }

    return newPtr;
}

size_t TLSFPool::GetUsedSize() {
    return m_usedSize.load(std::memory_order_relaxed);
}

size_t TLSFPool::GetTotalSize() {
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

bool TLSFPool::IsFromPool(void* ptr) {
    if (!ptr) return false;

    __try {
        // ����Ƿ�ΪTLSF������ڴ�
        if (m_tlsfPool && tlsf_check_pool(tlsf_get_pool(m_tlsfPool))) {
            return true;
        }

        if (m_safeTlsfPool && tlsf_check_pool(tlsf_get_pool(m_safeTlsfPool))) {
            return true;
        }

        // ���ȫ�ָ��ٱ�
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        return m_allocatedBlocks.find(ptr) != m_allocatedBlocks.end();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // ����ָ������쳣
        return false;
    }
}

size_t TLSFPool::GetBlockSize(void* ptr) {
    if (!ptr) return 0;

    // ���ԴӸ��ٱ��ȡ��С
    std::lock_guard<std::mutex> trackLock(m_trackingMutex);
    auto it = m_allocatedBlocks.find(ptr);
    if (it != m_allocatedBlocks.end()) {
        return it->second;
    }

    // ���Դ�TLSF��ȡ��С
    return tlsf_block_size(ptr);
}

void TLSFPool::PrintStats() {
    if (!m_tlsfPool) {
        LogMessage("[TLSFPool] TLSFδ��ʼ��");
        return;
    }

    LogMessage("[TLSFPool] === TLSF�ڴ��ͳ�� ===");
    LogMessage("[TLSFPool] �����ڴ�: %zu KB", m_usedSize.load() / 1024);
    LogMessage("[TLSFPool] ���ڴ�: %zu KB", m_totalPoolSize.load() / 1024);

    // ���Сͳ��
    {
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        LogMessage("[TLSFPool] ���ٿ�����: %zu", m_allocatedBlocks.size());
    }

    LogMessage("[TLSFPool] TLSFͳ�����");
}

void TLSFPool::CheckAndFreeUnusedPools() {
    // TLSFû���Զ��ػ��ջ��ƣ�����ֻ����־��¼
    LogMessage("[TLSFPool] CheckAndFreeUnusedPools - TLSFû���Զ��ػ��ջ���");
}

void TLSFPool::DisableMemoryReleasing() {
    m_disableMemoryReleasing.store(true);
    LogMessage("[TLSFPool] �ѽ����ڴ��ͷţ������ڴ潫���������̽���");
}

void TLSFPool::HeapCollect() {
    // TLSFû���������ջ��ƣ���������ֶ�������Ƭ
    LogMessage("[TLSFPool] HeapCollect - TLSFû���Զ��������ջ���");
}

void* TLSFPool::CreateStabilizingBlock(size_t size, const char* purpose) {
    // ʹ��ϵͳ����ȷ���ȶ���
    void* rawPtr = VirtualAlloc(NULL, size + sizeof(StormAllocHeader),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawPtr) {
        LogMessage("[TLSFPool] �޷������ȶ�����: %zu", size);
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
        LogMessage("[TLSFPool] �����ȶ�����ͷ��ʧ��: %p", rawPtr);
        VirtualFree(rawPtr, 0, MEM_RELEASE);
        return nullptr;
    }

    LogMessage("[TLSFPool] �����ȶ�����: %p (��С: %zu, ��;: %s)",
        userPtr, size, purpose ? purpose : "δ֪");

    return userPtr;
}

bool TLSFPool::ValidatePointer(void* ptr) {
    if (!ptr) return false;

    __try {
        // ���Զ�ȡָ��ĵ�һ���ֽڣ���֤�ɶ�
        volatile char test = *static_cast<char*>(ptr);

        // ���ȫ�ָ��ٱ�
        std::lock_guard<std::mutex> trackLock(m_trackingMutex);
        return m_allocatedBlocks.find(ptr) != m_allocatedBlocks.end();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void TLSFPool::Preheat() {
    if (!m_tlsfPool) {
        Initialize(64 * 1024 * 1024);  // Ĭ��64MB
        if (!m_tlsfPool) return;
    }

    LogMessage("[TLSFPool] ��ʼԤ���ڴ��...");

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
            void* ptr = tlsf_malloc(m_tlsfPool, size);
            if (ptr) {
                preheatedBlocks.push_back(ptr);

                // ��¼����
                std::lock_guard<std::mutex> trackLock(m_trackingMutex);
                m_allocatedBlocks[ptr] = size;
                m_usedSize.fetch_add(size, std::memory_order_relaxed);
            }
        }
    }

    LogMessage("[TLSFPool] Ԥ�ȷ����� %zu ���ڴ��", preheatedBlocks.size());

    // �ͷ�һ��Ԥ�ȵĿ飬����һ���ڻ�����
    for (size_t i = 0; i < preheatedBlocks.size() / 2; i++) {
        Free(preheatedBlocks[i]);
    }

    LogMessage("[TLSFPool] �ڴ��Ԥ����ɣ��ͷ��� %zu ���ڴ��", preheatedBlocks.size() / 2);
}

void TLSFPool::DisableActualFree() {
    DisableMemoryReleasing();  // ������ʵ�ֵĺ���
}

size_t TLSFPool::get_shard_index(void* ptr, size_t size) {
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