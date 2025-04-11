#include "pch.h"
#include "ColdStorageManager.h"
#include "../Base/Logger.h" // 引入项目日志系统
#include <processthreadsapi.h> // For CreateProcess
#include <synchapi.h> // For WaitForSingleObject, ReleaseSemaphore, etc.
#include <handleapi.h> // For CloseHandle
#include <memoryapi.h> // For MapViewOfFile, UnmapViewOfFile
#include <stdexcept>   // For std::runtime_error
#include <system_error> // For std::system_error

namespace ColdStorage {

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

// --- 初始化 ---
bool ColdStorageManager::Initialize(const std::wstring& storageProcessPath) {
    if (m_initialized.load()) {
        LogSystem::GetInstance().Log("[ColdStorage] 管理器已初始化");
        return true;
    }

    std::lock_guard<std::mutex> lock(m_apiMutex); // 保护初始化过程

    LogSystem::GetInstance().Log("[ColdStorage] 开始初始化...");

    bool success = false;
    HANDLE hMapFile = NULL;
    HANDLE hCmdSem = NULL;
    HANDLE hRespSem = NULL;
    HANDLE hMutex = NULL;
    HANDLE hReadyEvent = NULL;
    SharedMemHeader* pHeader = nullptr;

    try {
        // 1. 创建或打开共享内存互斥体 (确保原子性创建)
        hMutex = CreateMutexW(NULL, FALSE, SHARED_MEM_MUTEX_NAME);
        if (!hMutex) {
            throw std::system_error(GetLastError(), std::system_category(), "创建互斥体失败");
        }
        // 检查是否是第一个创建者
        bool alreadyExists = (GetLastError() == ERROR_ALREADY_EXISTS);

        // 2. 创建或打开共享内存文件映射
        hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,    // 使用页面文件
            NULL,                    // 默认安全属性
            PAGE_READWRITE,          // 读写权限
            0,                       // 高位大小
            SHARED_MEM_SIZE,         // 低位大小
            SHARED_MEM_NAME);
        if (!hMapFile) {
            throw std::system_error(GetLastError(), std::system_category(), "创建文件映射失败");
        }

        // 3. 映射共享内存到进程地址空间
        pHeader = (SharedMemHeader*)MapViewOfFile(
            hMapFile,                // 文件映射句柄
            FILE_MAP_ALL_ACCESS,     // 读写权限
            0,                       // 文件偏移高位
            0,                       // 文件偏移低位
            SHARED_MEM_SIZE);
        if (!pHeader) {
            throw std::system_error(GetLastError(), std::system_category(), "映射视图失败");
        }

        // 4. 创建或打开信号量
        // 命令队列信号量：初始计数为0，最大为CMD_QUEUE_CAPACITY
        hCmdSem = CreateSemaphoreW(NULL, 0, CMD_QUEUE_CAPACITY, CMD_QUEUE_SEM_NAME);
        if (!hCmdSem) {
            throw std::system_error(GetLastError(), std::system_category(), "创建命令信号量失败");
        }
        // 响应信号量：初始计数为0，最大为1 (因为一次只处理一个响应)
        hRespSem = CreateSemaphoreW(NULL, 0, 1, RESP_SEM_NAME);
        if (!hRespSem) {
            throw std::system_error(GetLastError(), std::system_category(), "创建响应信号量失败");
        }

        // 5. 创建或打开存储进程就绪事件 (手动重置)
        hReadyEvent = CreateEventW(NULL, TRUE, FALSE, STORAGE_PROCESS_READY_EVENT_NAME);
        if (!hReadyEvent) {
            throw std::system_error(GetLastError(), std::system_category(), "创建就绪事件失败");
        }

        // 6. 如果是第一个创建者，初始化共享内存头部
        if (!alreadyExists) {
             if (WaitForSingleObject(hMutex, INFINITE) == WAIT_OBJECT_0) {
                pHeader->writeIndex = 0;
                pHeader->readIndex = 0;
                // 可以选择性地清零命令队列和数据区
                // memset(pHeader->commandQueue, 0, sizeof(Command) * CMD_QUEUE_CAPACITY);
                // memset((unsigned char*)pHeader + DATA_BUFFER_OFFSET, 0, DATA_BUFFER_SIZE);
                ReleaseMutex(hMutex);
             } else {
                 throw std::runtime_error("获取共享内存互斥锁失败");
             }
            LogSystem::GetInstance().Log("[ColdStorage] 共享内存已初始化");
        }

        // 7. 启动存储进程
        if (!LaunchStorageProcess(storageProcessPath)) {
             LogSystem::GetInstance().Log("[ColdStorage] 警告：无法启动存储进程，管理器将在无存储后端模式下运行");
             // 这里可以选择是否抛出异常，取决于是否允许无后端运行
             // throw std::runtime_error("启动存储进程失败");
        } else {
            // 等待存储进程就绪信号 (带超时)
            LogSystem::GetInstance().Log("[ColdStorage] 等待存储进程就绪...");
            DWORD waitResult = WaitForSingleObject(hReadyEvent, 10000); // 等待10秒
            if (waitResult == WAIT_OBJECT_0) {
                m_storageProcessReady.store(true);
                LogSystem::GetInstance().Log("[ColdStorage] 存储进程已就绪");
            } else {
                 LogSystem::GetInstance().Log("[ColdStorage] 警告：等待存储进程就绪超时或失败 (错误码: %d)", GetLastError());
                 // 可以选择关闭已启动的进程或继续运行
            }
        }


        // 8. 保存句柄和指针
        m_hSharedMemFile = hMapFile;
        m_pSharedMemHeader = pHeader;
        m_pDataBuffer = reinterpret_cast<unsigned char*>(pHeader) + DATA_BUFFER_OFFSET;
        m_hCmdQueueSem = hCmdSem;
        m_hRespSem = hRespSem;
        m_hMutex = hMutex;
        m_hReadyEvent = hReadyEvent; // 保存就绪事件句柄

        m_initialized.store(true);
        success = true;
        LogSystem::GetInstance().Log("[ColdStorage] 初始化成功");

    } catch (const std::system_error& e) {
        LogSystem::GetInstance().Log("[ColdStorage] 初始化系统错误: %s (代码: %d)", e.what(), e.code().value());
    } catch (const std::runtime_error& e) {
        LogSystem::GetInstance().Log("[ColdStorage] 初始化运行时错误: %s", e.what());
    } catch (...) {
        LogSystem::GetInstance().Log("[ColdStorage] 初始化发生未知错误");
    }

    // 清理（如果初始化失败）
    if (!success) {
        if (pHeader) UnmapViewOfFile(pHeader);
        if (hMapFile) CloseHandle(hMapFile);
        if (hCmdSem) CloseHandle(hCmdSem);
        if (hRespSem) CloseHandle(hRespSem);
        if (hMutex) CloseHandle(hMutex);
        if (hReadyEvent) CloseHandle(hReadyEvent);
        if (m_hStorageProcess) { // 如果进程已启动但后续失败
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
        return; // 防止重复关闭
    }

    LogSystem::GetInstance().Log("[ColdStorage] 开始关闭...");
    std::lock_guard<std::mutex> lock(m_apiMutex); // 保护关闭过程

    // 1. 通知存储进程关闭 (如果它已就绪)
    if (m_storageProcessReady.load() && m_hStorageProcess) {
        LogSystem::GetInstance().Log("[ColdStorage] 发送关闭命令到存储进程...");
        Command shutdownCmd = {};
        shutdownCmd.type = CommandType::SHUTDOWN;
        if (SendCommandInternal(shutdownCmd)) {
            // 等待存储进程退出 (带超时)
            LogSystem::GetInstance().Log("[ColdStorage] 等待存储进程退出...");
            WaitForSingleObject(m_hStorageProcess, 5000); // 等待5秒
        } else {
             LogSystem::GetInstance().Log("[ColdStorage] 警告：发送关闭命令失败");
        }
    }

    // 2. 强制终止存储进程（如果仍在运行）
    if (m_hStorageProcess) {
        DWORD exitCode;
        if (GetExitCodeProcess(m_hStorageProcess, &exitCode) && exitCode == STILL_ACTIVE) {
            LogSystem::GetInstance().Log("[ColdStorage] 强制终止存储进程...");
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


    m_storageProcessReady.store(false);
    LogSystem::GetInstance().Log("[ColdStorage] 关闭完成");
}

// --- 检查存储进程状态 ---
bool ColdStorageManager::IsStorageProcessReady() const {
    return m_initialized.load() && m_storageProcessReady.load();
}

// --- 启动存储进程 ---
bool ColdStorageManager::LaunchStorageProcess(const std::wstring& path) {
    LogSystem::GetInstance().Log("[ColdStorage] 尝试启动存储进程: %ls", path.c_str());

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // CREATE_NO_WINDOW: 不创建控制台窗口
    // DETACHED_PROCESS: 在单独的控制台会话中运行（可选）
    if (!CreateProcessW(
        path.c_str(),   // 可执行文件路径
        NULL,           // 命令行参数 (无)
        NULL,           // 进程安全属性
        NULL,           // 线程安全属性
        FALSE,          // 不继承句柄
        CREATE_NO_WINDOW, // 创建标志
        NULL,           // 环境变量
        NULL,           // 当前目录
        &si,            // STARTUPINFO
        &pi             // PROCESS_INFORMATION
    )) {
        LogSystem::GetInstance().Log("[ColdStorage] CreateProcessW 失败，错误码: %d", GetLastError());
        return false;
    }

    // 保存进程句柄，关闭线程句柄
    m_hStorageProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    LogSystem::GetInstance().Log("[ColdStorage] 存储进程已启动 (PID: %d)", pi.dwProcessId);
    return true;
}

// --- 生成BlockID ---
BlockID ColdStorageManager::GenerateNewBlockID() {
    // 使用原子操作保证唯一性
    return m_nextBlockId.fetch_add(1);
}


// --- 发送命令 (内部实现) ---
bool ColdStorageManager::SendCommandInternal(const Command& cmd, const void* dataPtr, size_t dataSize) {
    if (!m_initialized.load() || !m_storageProcessReady.load()) {
        LogSystem::GetInstance().Log("[ColdStorage] 错误：管理器未初始化或存储进程未就绪，无法发送命令");
        return false;
    }

    // 1. 获取共享内存互斥锁
    if (WaitForSingleObject(m_hMutex, 5000) != WAIT_OBJECT_0) { // 5秒超时
        LogSystem::GetInstance().Log("[ColdStorage] 错误：获取共享内存互斥锁超时");
        return false;
    }

    bool success = false;
    size_t dataOffset = 0; // 数据在共享内存中的偏移

    try {
        // 2. 检查命令队列是否有空间
        uint32_t currentWriteIndex = m_pSharedMemHeader->writeIndex;
        uint32_t nextWriteIndex = (currentWriteIndex + 1) % CMD_QUEUE_CAPACITY;

        if (nextWriteIndex == m_pSharedMemHeader->readIndex) {
            // 队列已满
            LogSystem::GetInstance().Log("[ColdStorage] 错误：命令队列已满");
            throw std::runtime_error("Command queue full");
        }

        // 3. 如果需要传输数据，检查数据缓冲区空间并复制数据
        if (dataPtr && dataSize > 0) {
            if (dataSize > DATA_BUFFER_SIZE) {
                LogSystem::GetInstance().Log("[ColdStorage] 错误：数据大小 (%zu) 超过缓冲区限制 (%zu)", dataSize, DATA_BUFFER_SIZE);
                throw std::runtime_error("Data size exceeds buffer limit");
            }
            // 简单策略：直接覆盖数据区 (实际应用中可能需要更复杂的缓冲区管理)
            memcpy(m_pDataBuffer, dataPtr, dataSize);
            dataOffset = 0; // 假设数据总是从缓冲区开始位置写入
        }

        // 4. 构造最终要发送的命令 (包含数据偏移)
        Command finalCmd = cmd;
        if (dataPtr && dataSize > 0) {
            finalCmd.dataOffset = dataOffset;
            finalCmd.size = dataSize; // 确保命令中包含正确的大小
        }

        // 5. 将命令写入队列
        m_pSharedMemHeader->commandQueue[currentWriteIndex] = finalCmd;

        // 6. 更新写索引 (内存屏障确保写入完成)
        // 使用原子操作或确保编译器不会重排序 volatile 访问
        // 在MSVC中，volatile通常足够；更严格可以用 std::atomic_thread_fence
        // std::atomic_thread_fence(std::memory_order_release);
        m_pSharedMemHeader->writeIndex = nextWriteIndex;

        // 7. 释放命令队列信号量，通知存储进程有新命令
        if (!ReleaseSemaphore(m_hCmdQueueSem, 1, NULL)) {
             LogSystem::GetInstance().Log("[ColdStorage] 错误：释放命令信号量失败，错误码: %d", GetLastError());
             // 回滚写索引？可能比较复杂，暂时只记录错误
             throw std::runtime_error("Failed to release command semaphore");
        }

        success = true;

    } catch (const std::exception& e) {
         LogSystem::GetInstance().Log("[ColdStorage] 发送命令时发生异常: %s", e.what());
         success = false;
    } catch (...) {
         LogSystem::GetInstance().Log("[ColdStorage] 发送命令时发生未知异常");
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
    if (!m_initialized.load() || !m_storageProcessReady.load()) {
        return {false, ErrorCode::INTERNAL_ERROR}; // 管理器或进程未就绪
    }

    // 1. 等待响应信号量
    DWORD waitResult = WaitForSingleObject(m_hRespSem, timeoutMs);
    if (waitResult != WAIT_OBJECT_0) {
        LogSystem::GetInstance().Log("[ColdStorage] 等待响应%s (错误码: %d)",
            (waitResult == WAIT_TIMEOUT ? "超时" : "失败"), GetLastError());
        return {false, ErrorCode::SHARED_MEM_ERROR};
    }

    // 2. 获取共享内存互斥锁
    if (WaitForSingleObject(m_hMutex, 5000) != WAIT_OBJECT_0) {
        LogSystem::GetInstance().Log("[ColdStorage] 错误：获取共享内存互斥锁以读取响应时超时");
        // 尝试释放响应信号量，避免死锁？(谨慎操作)
        // ReleaseSemaphore(m_hRespSem, 1, NULL);
        return {false, ErrorCode::SHARED_MEM_ERROR};
    }

    std::pair<bool, ErrorCode> result = {false, ErrorCode::INTERNAL_ERROR};

    try {
        // 3. 从命令队列读取响应 (假设响应也通过命令队列返回，或者有单独的响应槽)
        // 这里简化处理：假设响应直接覆盖了发送的命令槽或有特定响应槽
        // 实际应用可能需要更复杂的响应机制

        // 假设响应在 writeIndex 的前一个位置 (由存储进程写入)
        // 注意：这只是一个简化的假设，实际协议需要明确定义
        uint32_t responseIndex = (m_pSharedMemHeader->writeIndex + CMD_QUEUE_CAPACITY - 1) % CMD_QUEUE_CAPACITY;
        const Command& responseCmd = m_pSharedMemHeader->commandQueue[responseIndex];

        // 4. 检查响应类型和错误码
        if (responseCmd.type == CommandType::ERROR_RESP) {
            LogSystem::GetInstance().Log("[ColdStorage] 收到错误响应: %u", static_cast<uint32_t>(responseCmd.errorCode));
            result = {false, responseCmd.errorCode};
        } else if (responseCmd.type == expectedType) {
            // 响应类型匹配
            result = {true, ErrorCode::NONE};
            if (outCmd) {
                *outCmd = responseCmd; // 复制响应命令
            }

            // 如果是数据响应，并且需要复制数据
            if (expectedType == CommandType::DATA_RESP && outDataBuffer && outDataSize) {
                if (responseCmd.size <= *outDataSize) { // 检查缓冲区大小
                    memcpy(outDataBuffer, m_pDataBuffer + responseCmd.dataOffset, responseCmd.size);
                    *outDataSize = responseCmd.size; // 返回实际复制的大小
                } else {
                    LogSystem::GetInstance().Log("[ColdStorage] 错误：接收数据缓冲区不足 (需要 %zu, 提供 %zu)",
                                                 responseCmd.size, *outDataSize);
                    result = {false, ErrorCode::SHARED_MEM_ERROR};
                }
            }
        } else {
            LogSystem::GetInstance().Log("[ColdStorage] 错误：收到意外的响应类型 (期望 %u, 收到 %u)",
                                         static_cast<uint32_t>(expectedType), static_cast<uint32_t>(responseCmd.type));
            result = {false, ErrorCode::INTERNAL_ERROR};
        }

    } catch (const std::exception& e) {
         LogSystem::GetInstance().Log("[ColdStorage] 处理响应时发生异常: %s", e.what());
         result = {false, ErrorCode::INTERNAL_ERROR};
    } catch (...) {
         LogSystem::GetInstance().Log("[ColdStorage] 处理响应时发生未知异常");
         result = {false, ErrorCode::INTERNAL_ERROR};
    }

    // 5. 释放共享内存互斥锁
    ReleaseMutex(m_hMutex);

    return result;
}


// --- 公共 API 实现 ---

BlockID ColdStorageManager::StoreBlock(const void* ptr, size_t size) {
    if (!ptr || size == 0) return INVALID_BLOCK_ID;
    if (!IsStorageProcessReady()) return INVALID_BLOCK_ID;

    std::lock_guard<std::mutex> lock(m_apiMutex); // 保护API调用

    BlockID newId = GenerateNewBlockID();
    Command cmd = {};
    cmd.type = CommandType::STORE;
    cmd.blockId = newId;
    cmd.size = size; // size 会在 SendCommandInternal 中被覆盖，但先设置

    LogSystem::GetInstance().Log("[ColdStorage] 请求存储块: ID=%llu, 大小=%zu", newId, size);

    if (SendCommandInternal(cmd, ptr, size)) {
        // 等待ACK响应
        auto [success, errorCode] = WaitForResponse(CommandType::ACK);
        if (success) {
            LogSystem::GetInstance().Log("[ColdStorage] 存储块成功: ID=%llu", newId);
            return newId;
        } else {
            LogSystem::GetInstance().Log("[ColdStorage] 存储块失败: ID=%llu, 错误码=%u", newId, static_cast<uint32_t>(errorCode));
            return INVALID_BLOCK_ID;
        }
    } else {
        LogSystem::GetInstance().Log("[ColdStorage] 发送存储命令失败: ID=%llu", newId);
        return INVALID_BLOCK_ID;
    }
}

std::optional<size_t> ColdStorageManager::RetrieveBlock(BlockID blockId, void* buffer, size_t bufferSize) {
    if (blockId == INVALID_BLOCK_ID || !buffer || bufferSize == 0) return std::nullopt;
    if (!IsStorageProcessReady()) return std::nullopt;

    std::lock_guard<std::mutex> lock(m_apiMutex);

    Command cmd = {};
    cmd.type = CommandType::RETRIEVE;
    cmd.blockId = blockId;
    // size 和 dataOffset 由存储进程在响应中设置

    LogSystem::GetInstance().Log("[ColdStorage] 请求取回块: ID=%llu", blockId);

    if (SendCommandInternal(cmd)) {
        Command responseCmd;
        size_t receivedSize = bufferSize; // 传入缓冲区大小
        auto [success, errorCode] = WaitForResponse(CommandType::DATA_RESP, 5000, &responseCmd, buffer, &receivedSize);

        if (success) {
            LogSystem::GetInstance().Log("[ColdStorage] 取回块成功: ID=%llu, 大小=%zu", blockId, receivedSize);
            return receivedSize;
        } else {
             LogSystem::GetInstance().Log("[ColdStorage] 取回块失败: ID=%llu, 错误码=%u", blockId, static_cast<uint32_t>(errorCode));
            return std::nullopt;
        }
    } else {
        LogSystem::GetInstance().Log("[ColdStorage] 发送取回命令失败: ID=%llu", blockId);
        return std::nullopt;
    }
}

bool ColdStorageManager::FreeBlock(BlockID blockId) {
    if (blockId == INVALID_BLOCK_ID) return false;
    if (!IsStorageProcessReady()) return false;

    std::lock_guard<std::mutex> lock(m_apiMutex);

    Command cmd = {};
    cmd.type = CommandType::FREE;
    cmd.blockId = blockId;

    LogSystem::GetInstance().Log("[ColdStorage] 请求释放块: ID=%llu", blockId);

    if (SendCommandInternal(cmd)) {
        auto [success, errorCode] = WaitForResponse(CommandType::ACK);
         if (!success) {
             LogSystem::GetInstance().Log("[ColdStorage] 释放块失败: ID=%llu, 错误码=%u", blockId, static_cast<uint32_t>(errorCode));
         }
        return success;
    } else {
        LogSystem::GetInstance().Log("[ColdStorage] 发送释放命令失败: ID=%llu", blockId);
        return false;
    }
}

bool ColdStorageManager::PingStorageProcess() {
     if (!IsStorageProcessReady()) return false;

    std::lock_guard<std::mutex> lock(m_apiMutex);

    Command cmd = {};
    cmd.type = CommandType::PING;

    if (SendCommandInternal(cmd)) {
        auto [success, errorCode] = WaitForResponse(CommandType::ACK, 1000); // 1秒超时
        return success;
    }
    return false;
}


} // namespace ColdStorage
