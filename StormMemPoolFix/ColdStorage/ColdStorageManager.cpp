// ColdStorageManager.cpp 修改版 - 包含冷存储代理占位符支持

#include "pch.h"
#include "ColdStorageManager.h"
#include "../Base/Logger.h"
#include <processthreadsapi.h>
#include <synchapi.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <stdexcept>
#include <system_error>
#include <unordered_map>
#include <Storm/StormHook.h>

namespace ColdStorage {

    // 存储代理映射 (代理指针 -> BlockID)
    static std::unordered_map<void*, BlockID> g_proxyToBlockMap;
    static std::mutex g_proxyMapMutex;

    // --- 单例实现 ---
    ColdStorageManager& ColdStorageManager::GetInstance() {
        static ColdStorageManager instance;
        return instance;
    }

    // --- 构造函数 ---
    ColdStorageManager::ColdStorageManager() {
        // 成员变量已通过类内初始化器初始化
    }

    // --- 析构函数 ---
    ColdStorageManager::~ColdStorageManager() {
        Shutdown(); // 确保在对象销毁时清理资源
    }

    // --- 工具方法 - 检查指针是否为冷存储代理 ---
    bool ColdStorageManager::IsProxyPointer(void* ptr) {
        if (!ptr) return false;

        __try {
            ColdStorageProxy* proxy = static_cast<ColdStorageProxy*>(ptr);
            return (proxy->magic == COLD_PROXY_MAGIC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // --- 工具方法 - 从代理获取BlockID ---
    BlockID ColdStorageManager::GetBlockIdFromProxy(void* proxyPtr) {
        if (!proxyPtr) return INVALID_BLOCK_ID;

        __try {
            ColdStorageProxy* proxy = static_cast<ColdStorageProxy*>(proxyPtr);
            if (proxy->magic == COLD_PROXY_MAGIC) {
                return proxy->blockId;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 异常处理
        }

        // 尝试从映射获取
        std::lock_guard<std::mutex> lock(g_proxyMapMutex);
        auto it = g_proxyToBlockMap.find(proxyPtr);
        if (it != g_proxyToBlockMap.end()) {
            return it->second;
        }

        return INVALID_BLOCK_ID;
    }

    // --- 工具方法 - 释放代理内存 ---
    void ColdStorageManager::FreeProxyMemory(void* proxyPtr) {
        if (!proxyPtr) return;

        // 从映射中移除
        {
            std::lock_guard<std::mutex> lock(g_proxyMapMutex);
            g_proxyToBlockMap.erase(proxyPtr);
        }

        // 释放内存
        VirtualFree(proxyPtr, 0, MEM_RELEASE);
    }

    // --- 初始化 ---
    bool ColdStorageManager::Initialize(const std::wstring& storageProcessPath) {
        // 初始化代码保持不变
        if (m_initialized.load()) {
            LogMessage("[ColdStorage] 管理器已初始化");
            return true;
        }

        std::lock_guard<std::mutex> lock(m_apiMutex);

        LogMessage("[ColdStorage] 开始初始化...");

        bool success = false;
        HANDLE hMapFile = NULL;
        HANDLE hCmdSem = NULL;
        HANDLE hRespSem = NULL;
        HANDLE hMutex = NULL;
        HANDLE hReadyEvent = NULL;
        SharedMemHeader* pHeader = nullptr;

        try {
            // 1. 创建或打开共享内存互斥体
            hMutex = CreateMutexW(NULL, FALSE, SHARED_MEM_MUTEX_NAME);
            if (!hMutex) {
                throw std::system_error(GetLastError(), std::system_category(), "创建互斥体失败");
            }
            bool alreadyExists = (GetLastError() == ERROR_ALREADY_EXISTS);

            // 2. 创建或打开共享内存文件映射
            hMapFile = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                NULL,
                PAGE_READWRITE,
                0,
                SHARED_MEM_SIZE,
                SHARED_MEM_NAME);
            if (!hMapFile) {
                throw std::system_error(GetLastError(), std::system_category(), "创建文件映射失败");
            }

            // 3. 映射共享内存到进程地址空间
            pHeader = (SharedMemHeader*)MapViewOfFile(
                hMapFile,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                SHARED_MEM_SIZE);
            if (!pHeader) {
                throw std::system_error(GetLastError(), std::system_category(), "映射视图失败");
            }

            // 4. 创建或打开信号量
            hCmdSem = CreateSemaphoreW(NULL, 0, CMD_QUEUE_CAPACITY, CMD_QUEUE_SEM_NAME);
            if (!hCmdSem) {
                throw std::system_error(GetLastError(), std::system_category(), "创建命令信号量失败");
            }
            hRespSem = CreateSemaphoreW(NULL, 0, 1, RESP_SEM_NAME);
            if (!hRespSem) {
                throw std::system_error(GetLastError(), std::system_category(), "创建响应信号量失败");
            }

            // 5. 创建或打开存储进程就绪事件
            hReadyEvent = CreateEventW(NULL, TRUE, FALSE, STORAGE_PROCESS_READY_EVENT_NAME);
            if (!hReadyEvent) {
                throw std::system_error(GetLastError(), std::system_category(), "创建就绪事件失败");
            }

            // 6. 初始化共享内存头部
            if (!alreadyExists) {
                if (WaitForSingleObject(hMutex, INFINITE) == WAIT_OBJECT_0) {
                    pHeader->writeIndex = 0;
                    pHeader->readIndex = 0;
                    ReleaseMutex(hMutex);
                }
                else {
                    throw std::runtime_error("获取共享内存互斥锁失败");
                }
                LogMessage("[ColdStorage] 共享内存已初始化");
            }

            // 7. 启动存储进程
            if (!LaunchStorageProcess(storageProcessPath)) {
                LogMessage("[ColdStorage] 警告：无法启动存储进程，管理器将在无存储后端模式下运行");
            }
            else {
                LogMessage("[ColdStorage] 等待存储进程就绪...");
                DWORD waitResult = WaitForSingleObject(hReadyEvent, 10000); // 等待10秒
                if (waitResult == WAIT_OBJECT_0) {
                    m_storageProcessReady.store(true);
                    LogMessage("[ColdStorage] 存储进程已就绪");
                }
                else {
                    LogMessage("[ColdStorage] 警告：等待存储进程就绪超时或失败 (错误码: %d)", GetLastError());
                }
            }

            // 8. 保存句柄和指针
            m_hSharedMemFile = hMapFile;
            m_pSharedMemHeader = pHeader;
            m_pDataBuffer = reinterpret_cast<unsigned char*>(pHeader) + DATA_BUFFER_OFFSET;
            m_hCmdQueueSem = hCmdSem;
            m_hRespSem = hRespSem;
            m_hMutex = hMutex;
            m_hReadyEvent = hReadyEvent;

            m_initialized.store(true);
            success = true;
            LogMessage("[ColdStorage] 初始化成功");

        }
        catch (const std::system_error& e) {
            LogMessage("[ColdStorage] 初始化系统错误: %s (代码: %d)", e.what(), e.code().value());
        }
        catch (const std::runtime_error& e) {
            LogMessage("[ColdStorage] 初始化运行时错误: %s", e.what());
        }
        catch (...) {
            LogMessage("[ColdStorage] 初始化发生未知错误");
        }

        // 清理（如果初始化失败）
        if (!success) {
            if (pHeader) UnmapViewOfFile(pHeader);
            if (hMapFile) CloseHandle(hMapFile);
            if (hCmdSem) CloseHandle(hCmdSem);
            if (hRespSem) CloseHandle(hRespSem);
            if (hMutex) CloseHandle(hMutex);
            if (hReadyEvent) CloseHandle(hReadyEvent);
            if (m_hStorageProcess) {
                TerminateProcess(m_hStorageProcess, 1);
                CloseHandle(m_hStorageProcess);
                m_hStorageProcess = NULL;
            }
            m_pSharedMemHeader = nullptr;
            m_pDataBuffer = nullptr;
        }

        return success;
    }

    // --- 关闭 ---
    void ColdStorageManager::Shutdown() {
        if (!m_initialized.exchange(false)) {
            return;
        }

        LogMessage("[ColdStorage] 开始关闭...");
        std::lock_guard<std::mutex> lock(m_apiMutex);

        // 1. 通知存储进程关闭
        if (m_storageProcessReady.load() && m_hStorageProcess) {
            LogMessage("[ColdStorage] 发送关闭命令到存储进程...");
            Command shutdownCmd = {};
            shutdownCmd.type = CommandType::SHUTDOWN;
            if (SendCommandInternal(shutdownCmd)) {
                LogMessage("[ColdStorage] 等待存储进程退出...");
                WaitForSingleObject(m_hStorageProcess, 5000);
            }
            else {
                LogMessage("[ColdStorage] 警告：发送关闭命令失败");
            }
        }

        // 2. 强制终止存储进程（如果仍在运行）
        if (m_hStorageProcess) {
            DWORD exitCode;
            if (GetExitCodeProcess(m_hStorageProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                LogMessage("[ColdStorage] 强制终止存储进程...");
                TerminateProcess(m_hStorageProcess, 0);
            }
            CloseHandle(m_hStorageProcess);
            m_hStorageProcess = NULL;
        }

        // 3. 清理共享内存和同步对象
        if (m_pSharedMemHeader) {
            UnmapViewOfFile(m_pSharedMemHeader);
            m_pSharedMemHeader = nullptr;
            m_pDataBuffer = nullptr;
        }
        if (m_hSharedMemFile) {
            CloseHandle(m_hSharedMemFile);
            m_hSharedMemFile = NULL;
        }
        if (m_hCmdQueueSem) {
            CloseHandle(m_hCmdQueueSem);
            m_hCmdQueueSem = NULL;
        }
        if (m_hRespSem) {
            CloseHandle(m_hRespSem);
            m_hRespSem = NULL;
        }
        if (m_hMutex) {
            CloseHandle(m_hMutex);
            m_hMutex = NULL;
        }
        if (m_hReadyEvent) {
            CloseHandle(m_hReadyEvent);
            m_hReadyEvent = NULL;
        }

        // 4. 清理代理映射和内存
        {
            std::lock_guard<std::mutex> mapLock(g_proxyMapMutex);
            for (auto const& [proxyPtr, blockId] : g_proxyToBlockMap) {
                __try {
                    VirtualFree(proxyPtr, 0, MEM_RELEASE);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // 忽略异常
                }
            }
            g_proxyToBlockMap.clear();
        }

        m_storageProcessReady.store(false);
        LogMessage("[ColdStorage] 关闭完成");
    }

    // --- 检查存储进程状态 ---
    bool ColdStorageManager::IsStorageProcessReady() const {
        return m_initialized.load() && m_storageProcessReady.load();
    }

    // --- 启动存储进程 ---
    bool ColdStorageManager::LaunchStorageProcess(const std::wstring& path) {
        LogMessage("[ColdStorage] 尝试启动存储进程: %ls", path.c_str());

        // 获取当前工作目录作为基础路径
        wchar_t currentDir[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, currentDir);

        // 构建完整路径
        std::wstring fullPath = path;
        if (path.find(L'\\') == std::wstring::npos && path.find(L'/') == std::wstring::npos) {
            fullPath = std::wstring(currentDir) + L"\\" + path;
        }

        LogMessage("[ColdStorage] 使用完整路径: %ls", fullPath.c_str());

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};

        DWORD creationFlags = 0;  // 使用默认标志

        if (!CreateProcessW(
            fullPath.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            &si,
            &pi)) {

            DWORD error = GetLastError();
            LogMessage("[ColdStorage] CreateProcessW 失败，错误码: %d", error);
            return false;
        }

        m_hStorageProcess = pi.hProcess;
        CloseHandle(pi.hThread);

        LogMessage("[ColdStorage] 存储进程已启动 (PID: %d)", pi.dwProcessId);
        return true;
    }

    // --- 生成BlockID ---
    BlockID ColdStorageManager::GenerateNewBlockID() {
        return m_nextBlockId.fetch_add(1);
    }

    // --- 发送命令 (内部实现) ---
    bool ColdStorageManager::SendCommandInternal(const Command& cmd, const void* dataPtr, size_t dataSize) {
        // 内部实现代码保持不变
        if (!m_initialized.load() || !m_storageProcessReady.load()) {
            LogMessage("[ColdStorage] 错误：管理器未初始化或存储进程未就绪，无法发送命令");
            return false;
        }

        // 1. 获取共享内存互斥锁
        if (WaitForSingleObject(m_hMutex, 5000) != WAIT_OBJECT_0) {
            LogMessage("[ColdStorage] 错误：获取共享内存互斥锁超时");
            return false;
        }

        bool success = false;
        size_t dataOffset = 0;

        try {
            // 2. 检查命令队列是否有空间
            uint32_t currentWriteIndex = m_pSharedMemHeader->writeIndex;
            uint32_t nextWriteIndex = (currentWriteIndex + 1) % CMD_QUEUE_CAPACITY;

            if (nextWriteIndex == m_pSharedMemHeader->readIndex) {
                LogMessage("[ColdStorage] 错误：命令队列已满");
                throw std::runtime_error("Command queue full");
            }

            // 3. 如果需要传输数据，检查数据缓冲区空间并复制数据
            if (dataPtr && dataSize > 0) {
                if (dataSize > DATA_BUFFER_SIZE) {
                    LogMessage("[ColdStorage] 错误：数据大小 (%zu) 超过缓冲区限制 (%zu)", dataSize, DATA_BUFFER_SIZE);
                    throw std::runtime_error("Data size exceeds buffer limit");
                }
                memcpy(m_pDataBuffer, dataPtr, dataSize);
                dataOffset = 0;
            }

            // 4. 构造最终要发送的命令
            Command finalCmd = cmd;
            if (dataPtr && dataSize > 0) {
                finalCmd.dataOffset = dataOffset;
                finalCmd.size = dataSize;
            }

            // 5. 将命令写入队列
            m_pSharedMemHeader->commandQueue[currentWriteIndex] = finalCmd;

            // 6. 更新写索引
            m_pSharedMemHeader->writeIndex = nextWriteIndex;

            // 7. 释放命令队列信号量，通知存储进程有新命令
            if (!ReleaseSemaphore(m_hCmdQueueSem, 1, NULL)) {
                LogMessage("[ColdStorage] 错误：释放命令信号量失败，错误码: %d", GetLastError());
                throw std::runtime_error("Failed to release command semaphore");
            }

            success = true;

        }
        catch (const std::exception& e) {
            LogMessage("[ColdStorage] 发送命令时发生异常: %s", e.what());
            success = false;
        }
        catch (...) {
            LogMessage("[ColdStorage] 发送命令时发生未知异常");
            success = false;
        }

        // 8. 释放共享内存互斥锁
        ReleaseMutex(m_hMutex);

        return success;
    }

    // --- 等待响应 (内部实现) ---
    std::pair<bool, ErrorCode> ColdStorageManager::WaitForResponse(CommandType expectedType, DWORD timeoutMs,
        Command* outCmd,
        void* outDataBuffer,
        size_t* outDataSize) {
        // 内部实现代码保持不变
        if (!m_initialized.load() || !m_storageProcessReady.load()) {
            return { false, ErrorCode::INTERNAL_ERROR };
        }

        // 1. 等待响应信号量
        DWORD waitResult = WaitForSingleObject(m_hRespSem, timeoutMs);
        if (waitResult != WAIT_OBJECT_0) {
            LogMessage("[ColdStorage] 等待响应%s (错误码: %d)",
                (waitResult == WAIT_TIMEOUT ? "超时" : "失败"), GetLastError());
            return { false, ErrorCode::SHARED_MEM_ERROR };
        }

        // 2. 获取共享内存互斥锁
        if (WaitForSingleObject(m_hMutex, 5000) != WAIT_OBJECT_0) {
            LogMessage("[ColdStorage] 错误：获取共享内存互斥锁以读取响应时超时");
            return { false, ErrorCode::SHARED_MEM_ERROR };
        }

        std::pair<bool, ErrorCode> result = { false, ErrorCode::INTERNAL_ERROR };

        try {
            // 3. 从命令队列读取响应
            uint32_t responseIndex = (m_pSharedMemHeader->writeIndex + CMD_QUEUE_CAPACITY - 1) % CMD_QUEUE_CAPACITY;
            const Command& responseCmd = m_pSharedMemHeader->commandQueue[responseIndex];

            // 4. 检查响应类型和错误码
            if (responseCmd.type == CommandType::ERROR_RESP) {
                LogMessage("[ColdStorage] 收到错误响应: %u", static_cast<uint32_t>(responseCmd.errorCode));
                result = { false, responseCmd.errorCode };
            }
            else if (responseCmd.type == expectedType) {
                result = { true, ErrorCode::NONE };
                if (outCmd) {
                    *outCmd = responseCmd;
                }

                // 如果是数据响应，并且需要复制数据
                if (expectedType == CommandType::DATA_RESP && outDataBuffer && outDataSize) {
                    if (responseCmd.size <= *outDataSize) {
                        memcpy(outDataBuffer, m_pDataBuffer + responseCmd.dataOffset, responseCmd.size);
                        *outDataSize = responseCmd.size;
                    }
                    else {
                        LogMessage("[ColdStorage] 错误：接收数据缓冲区不足 (需要 %zu, 提供 %zu)",
                            responseCmd.size, *outDataSize);
                        result = { false, ErrorCode::SHARED_MEM_ERROR };
                    }
                }
            }
            else {
                LogMessage("[ColdStorage] 错误：收到意外的响应类型 (期望 %u, 收到 %u)",
                    static_cast<uint32_t>(expectedType), static_cast<uint32_t>(responseCmd.type));
                result = { false, ErrorCode::INTERNAL_ERROR };
            }

        }
        catch (const std::exception& e) {
            LogMessage("[ColdStorage] 处理响应时发生异常: %s", e.what());
            result = { false, ErrorCode::INTERNAL_ERROR };
        }
        catch (...) {
            LogMessage("[ColdStorage] 处理响应时发生未知异常");
            result = { false, ErrorCode::INTERNAL_ERROR };
        }

        // 5. 释放共享内存互斥锁
        ReleaseMutex(m_hMutex);

        return result;
    }

    // --- 修改: StoreBlock 方法 ---
    BlockID ColdStorageManager::StoreBlock(const void* ptr, size_t size) {
        if (!ptr || size == 0) return INVALID_BLOCK_ID;
        if (!IsStorageProcessReady()) return INVALID_BLOCK_ID;

        std::lock_guard<std::mutex> lock(m_apiMutex);

        BlockID newId = GenerateNewBlockID();
        Command cmd = {};
        cmd.type = CommandType::STORE;
        cmd.blockId = newId;
        cmd.size = size;

        LogMessage("[ColdStorage] 请求存储块: ID=%llu, 大小=%zu", newId, size);

        if (SendCommandInternal(cmd, ptr, size)) {
            // 等待ACK响应
            auto [success, errorCode] = WaitForResponse(CommandType::ACK);
            if (success) {
                LogMessage("[ColdStorage] 存储块成功: ID=%llu", newId);

                // 创建占位符内存 - 使用真实内存而非标记
                void* proxyPtr = VirtualAlloc(NULL, sizeof(ColdStorageProxy),
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (!proxyPtr) {
                    LogMessage("[ColdStorage] 无法分配占位符内存，释放块: ID=%llu", newId);
                    FreeBlock(newId);
                    return INVALID_BLOCK_ID;
                }

                // 设置占位符数据
                ColdStorageProxy* proxy = static_cast<ColdStorageProxy*>(proxyPtr);
                proxy->blockId = newId;
                proxy->magic = COLD_PROXY_MAGIC;
                proxy->originalSize = size;

                // 记录映射关系
                {
                    std::lock_guard<std::mutex> mapLock(g_proxyMapMutex);
                    g_proxyToBlockMap[proxyPtr] = newId;
                }

                LogMessage("[ColdStorage] 创建占位符: %p -> BlockID=%llu", proxyPtr, newId);
                return newId;
            }
            else {
                LogMessage("[ColdStorage] 存储块失败: ID=%llu, 错误码=%u", newId, static_cast<uint32_t>(errorCode));
                return INVALID_BLOCK_ID;
            }
        }
        else {
            LogMessage("[ColdStorage] 发送存储命令失败: ID=%llu", newId);
            return INVALID_BLOCK_ID;
        }
    }

    // --- 修改: RetrieveBlock 方法 ---
    std::optional<size_t> ColdStorageManager::RetrieveBlock(BlockID blockId, void* buffer, size_t bufferSize) {
        if (blockId == INVALID_BLOCK_ID || !buffer || bufferSize == 0) return std::nullopt;
        if (!IsStorageProcessReady()) return std::nullopt;

        std::lock_guard<std::mutex> lock(m_apiMutex);

        Command cmd = {};
        cmd.type = CommandType::RETRIEVE;
        cmd.blockId = blockId;

        LogMessage("[ColdStorage] 请求取回块: ID=%llu", blockId);

        if (SendCommandInternal(cmd)) {
            Command responseCmd;
            size_t receivedSize = bufferSize;
            auto [success, errorCode] = WaitForResponse(CommandType::DATA_RESP, 5000, &responseCmd, buffer, &receivedSize);

            if (success) {
                LogMessage("[ColdStorage] 取回块成功: ID=%llu, 大小=%zu", blockId, receivedSize);
                return receivedSize;
            }
            else {
                LogMessage("[ColdStorage] 取回块失败: ID=%llu, 错误码=%u", blockId, static_cast<uint32_t>(errorCode));
                return std::nullopt;
            }
        }
        else {
            LogMessage("[ColdStorage] 发送取回命令失败: ID=%llu", blockId);
            return std::nullopt;
        }
    }

    // --- 修改: FreeBlock 方法 ---
    bool ColdStorageManager::FreeBlock(BlockID blockId) {
        if (blockId == INVALID_BLOCK_ID) return false;
        if (!IsStorageProcessReady()) return false;

        std::lock_guard<std::mutex> lock(m_apiMutex);

        Command cmd = {};
        cmd.type = CommandType::FREE;
        cmd.blockId = blockId;

        LogMessage("[ColdStorage] 请求释放块: ID=%llu", blockId);

        if (SendCommandInternal(cmd)) {
            auto [success, errorCode] = WaitForResponse(CommandType::ACK);
            if (!success) {
                LogMessage("[ColdStorage] 释放块失败: ID=%llu, 错误码=%u", blockId, static_cast<uint32_t>(errorCode));
            }
            return success;
        }
        else {
            LogMessage("[ColdStorage] 发送释放命令失败: ID=%llu", blockId);
            return false;
        }
    }

    // --- Ping存储进程 ---
    bool ColdStorageManager::PingStorageProcess() {
        if (!IsStorageProcessReady()) return false;

        std::lock_guard<std::mutex> lock(m_apiMutex);

        Command cmd = {};
        cmd.type = CommandType::PING;

        if (SendCommandInternal(cmd)) {
            auto [success, errorCode] = WaitForResponse(CommandType::ACK, 1000);
            return success;
        }
        return false;
    }

} // namespace ColdStorage