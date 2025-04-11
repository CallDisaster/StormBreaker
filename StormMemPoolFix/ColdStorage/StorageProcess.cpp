#include "pch.h"
#include "Common.h"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <memory> // For std::unique_ptr
#include <system_error> // For std::system_error
#include <cstdlib> // For malloc, free
#include <cstdio> // For vsnprintf, printf
#include <cstdarg> // For va_list, va_start, va_end

// --- 全局变量 (存储进程内部) ---
namespace {
    std::atomic<bool> g_shouldExit{ false };
    HANDLE g_hSharedMemFile = NULL;
    ColdStorage::SharedMemHeader* g_pSharedMemHeader = nullptr;
    unsigned char* g_pDataBuffer = nullptr;
    HANDLE g_hCmdQueueSem = NULL;
    HANDLE g_hRespSem = NULL;
    HANDLE g_hMutex = NULL;
    HANDLE g_hReadyEvent = NULL;

    // 用于存储冷数据块的简单内存管理器
    struct StoredBlock {
        void* ptr;
        size_t size;
    };
    std::unordered_map<ColdStorage::BlockID, StoredBlock> g_storedBlocks;
    std::mutex g_storedBlocksMutex; // 保护 g_storedBlocks 的访问

    // 简单的日志函数 (输出到控制台)
    void LogStorage(const char* format, ...) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        printf("[StorageProcess] %s\n", buffer);
        // 实际项目中可以写入文件
        fflush(stdout); // 确保立即输出
    }
}

// --- 辅助函数 ---

// 发送响应到主进程
bool SendResponse(const ColdStorage::Command& response, const void* dataPtr = nullptr, size_t dataSize = 0) {
    if (!g_pSharedMemHeader) return false;

    // 1. 获取共享内存互斥锁
    if (WaitForSingleObject(g_hMutex, 5000) != WAIT_OBJECT_0) {
        LogStorage("错误：获取共享内存互斥锁以发送响应时超时");
        return false;
    }

    bool success = false;
    size_t dataOffset = 0;

    try {
        // 2. 如果需要传输数据，复制到数据缓冲区
        if (dataPtr && dataSize > 0) {
            if (dataSize > ColdStorage::DATA_BUFFER_SIZE) {
                LogStorage("错误：响应数据大小 (%zu) 超过缓冲区限制 (%zu)", dataSize, ColdStorage::DATA_BUFFER_SIZE);
                throw std::runtime_error("Response data size exceeds buffer limit");
            }
            memcpy(g_pDataBuffer, dataPtr, dataSize);
            dataOffset = 0; // 假设总是从头开始写
        }

        // 3. 构造最终响应命令
        ColdStorage::Command finalResponse = response;
        if (dataPtr && dataSize > 0) {
            finalResponse.dataOffset = dataOffset;
            finalResponse.size = dataSize;
        }

        // 4. 将响应写入命令队列的下一个写位置 (由主进程读取)
        // 注意：这里的协议假设响应覆盖了命令槽，实际可能需要更复杂的机制
        // 或者存储进程直接修改命令队列中的命令状态并设置错误码
        // 这里简化为直接写入 writeIndex 的前一个位置
         uint32_t responseIndex = (g_pSharedMemHeader->writeIndex + ColdStorage::CMD_QUEUE_CAPACITY - 1) % ColdStorage::CMD_QUEUE_CAPACITY;
         g_pSharedMemHeader->commandQueue[responseIndex] = finalResponse;


        // 5. 释放响应信号量，通知主进程有响应
        if (!ReleaseSemaphore(g_hRespSem, 1, NULL)) {
            LogStorage("错误：释放响应信号量失败，错误码: %d", GetLastError());
            throw std::runtime_error("Failed to release response semaphore");
        }

        success = true;

    } catch (const std::exception& e) {
        LogStorage("发送响应时发生异常: %s", e.what());
        success = false;
    } catch (...) {
        LogStorage("发送响应时发生未知异常");
        success = false;
    }

    // 6. 释放共享内存互斥锁
    ReleaseMutex(g_hMutex);
    return success;
}

// 发送错误响应
bool SendErrorResponse(ColdStorage::BlockID blockId, ColdStorage::ErrorCode errorCode) {
    ColdStorage::Command response = {};
    response.type = ColdStorage::CommandType::ERROR_RESP;
    response.blockId = blockId;
    response.errorCode = errorCode;
    return SendResponse(response);
}

// 发送确认响应
bool SendAckResponse(ColdStorage::BlockID blockId) {
    ColdStorage::Command response = {};
    response.type = ColdStorage::CommandType::ACK;
    response.blockId = blockId;
    response.errorCode = ColdStorage::ErrorCode::NONE;
    return SendResponse(response);
}

// 发送数据响应
bool SendDataResponse(ColdStorage::BlockID blockId, const void* data, size_t size) {
     ColdStorage::Command response = {};
    response.type = ColdStorage::CommandType::DATA_RESP;
    response.blockId = blockId;
    response.size = size; // 大小由 SendResponse 内部根据 dataSize 设置
    response.errorCode = ColdStorage::ErrorCode::NONE;
    return SendResponse(response, data, size);
}


// --- 命令处理函数 ---

void HandleStoreCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 STORE 命令: ID=%llu, 大小=%zu, 数据偏移=%zu", cmd.blockId, cmd.size, cmd.dataOffset);

    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID || cmd.size == 0) {
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 1. 分配内存来存储数据 (使用标准 malloc/free)
    void* storedPtr = malloc(cmd.size);
    if (!storedPtr) {
        LogStorage("错误：为块 %llu 分配内存失败 (大小 %zu)", cmd.blockId, cmd.size);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_NO_SPACE);
        return;
    }

    // 2. 从共享内存复制数据
    bool copySuccess = false;
    if (WaitForSingleObject(g_hMutex, 5000) == WAIT_OBJECT_0) {
        try {
            // 确保数据偏移和大小在共享内存数据缓冲区范围内
             if (cmd.dataOffset + cmd.size <= ColdStorage::DATA_BUFFER_SIZE) {
                memcpy(storedPtr, g_pDataBuffer + cmd.dataOffset, cmd.size);
                copySuccess = true;
             } else {
                 LogStorage("错误：无效的数据偏移或大小 (块 %llu, 偏移 %zu, 大小 %zu)", cmd.blockId, cmd.dataOffset, cmd.size);
             }
        } catch (...) {
            LogStorage("错误：从共享内存复制数据时异常 (块 %llu)", cmd.blockId);
        }
        ReleaseMutex(g_hMutex);
    } else {
        LogStorage("错误：获取共享内存锁以复制数据时超时 (块 %llu)", cmd.blockId);
    }

    if (!copySuccess) {
        free(storedPtr);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_COPY_ERROR);
        return;
    }

    // 3. 将块信息存入 map
    {
        std::lock_guard<std::mutex> lock(g_storedBlocksMutex);
        // 如果ID已存在，先释放旧内存
        auto it = g_storedBlocks.find(cmd.blockId);
        if (it != g_storedBlocks.end()) {
            LogStorage("警告：覆盖已存在的块 %llu", cmd.blockId);
            if (it->second.ptr) {
                free(it->second.ptr);
            }
        }
        g_storedBlocks[cmd.blockId] = {storedPtr, cmd.size};
    }

    // 4. 发送 ACK 响应
    SendAckResponse(cmd.blockId);
    LogStorage("块 %llu 存储成功", cmd.blockId);
}

void HandleRetrieveCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 RETRIEVE 命令: ID=%llu", cmd.blockId);

    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID) {
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    void* dataPtr = nullptr;
    size_t dataSize = 0;

    // 1. 查找块
    {
        std::lock_guard<std::mutex> lock(g_storedBlocksMutex);
        auto it = g_storedBlocks.find(cmd.blockId);
        if (it == g_storedBlocks.end()) {
            LogStorage("错误：未找到要取回的块 %llu", cmd.blockId);
            SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::RETRIEVE_FAILED_NOT_FOUND);
            return;
        }
        dataPtr = it->second.ptr;
        dataSize = it->second.size;
    }

    // 2. 发送数据响应 (SendResponse 内部会处理数据复制到共享内存)
    if (SendDataResponse(cmd.blockId, dataPtr, dataSize)) {
        LogStorage("块 %llu 取回数据发送成功", cmd.blockId);
    } else {
        LogStorage("错误：发送块 %llu 的数据响应失败", cmd.blockId);
        // SendDataResponse 内部已发送错误，这里不再重复发送
    }
}

void HandleFreeCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 FREE 命令: ID=%llu", cmd.blockId);

    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID) {
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 1. 查找并移除块
    bool found = false;
    void* ptrToFree = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_storedBlocksMutex);
        auto it = g_storedBlocks.find(cmd.blockId);
        if (it != g_storedBlocks.end()) {
            found = true;
            ptrToFree = it->second.ptr;
            g_storedBlocks.erase(it);
        }
    }

    // 2. 释放内存
    if (found) {
        if (ptrToFree) {
            free(ptrToFree);
        }
        SendAckResponse(cmd.blockId);
        LogStorage("块 %llu 释放成功", cmd.blockId);
    } else {
        LogStorage("错误：未找到要释放的块 %llu", cmd.blockId);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::FREE_FAILED_NOT_FOUND);
    }
}

// --- 主函数 ---
int main() {
    LogStorage("存储进程启动");

    // 1. 打开现有的共享内存和同步对象
    try {
        g_hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_MUTEX_NAME);
        if (!g_hMutex) throw std::system_error(GetLastError(), std::system_category(), "打开互斥体失败");

        g_hSharedMemFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_NAME);
        if (!g_hSharedMemFile) throw std::system_error(GetLastError(), std::system_category(), "打开文件映射失败");

        g_pSharedMemHeader = (ColdStorage::SharedMemHeader*)MapViewOfFile(g_hSharedMemFile, FILE_MAP_ALL_ACCESS, 0, 0, ColdStorage::SHARED_MEM_SIZE);
        if (!g_pSharedMemHeader) throw std::system_error(GetLastError(), std::system_category(), "映射视图失败");
        g_pDataBuffer = reinterpret_cast<unsigned char*>(g_pSharedMemHeader) + ColdStorage::DATA_BUFFER_OFFSET;

        g_hCmdQueueSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::CMD_QUEUE_SEM_NAME);
        if (!g_hCmdQueueSem) throw std::system_error(GetLastError(), std::system_category(), "打开命令信号量失败");

        g_hRespSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::RESP_SEM_NAME);
        if (!g_hRespSem) throw std::system_error(GetLastError(), std::system_category(), "打开响应信号量失败");

        g_hReadyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, ColdStorage::STORAGE_PROCESS_READY_EVENT_NAME);
        if (!g_hReadyEvent) throw std::system_error(GetLastError(), std::system_category(), "打开就绪事件失败");

    } catch (const std::system_error& e) {
        LogStorage("初始化共享资源失败: %s (代码: %d)", e.what(), e.code().value());
        // 清理已打开的句柄
        if (g_hMutex) CloseHandle(g_hMutex);
        if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
        if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
        if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
        if (g_hRespSem) CloseHandle(g_hRespSem);
        if (g_hReadyEvent) CloseHandle(g_hReadyEvent);
        return 1;
    }

    LogStorage("共享资源连接成功");

    // 2. 发出就绪信号
    SetEvent(g_hReadyEvent);
    LogStorage("已发送就绪信号");

    // 3. 命令处理循环
    LogStorage("开始监听命令...");
    while (!g_shouldExit.load()) {
        // 等待命令信号量
        DWORD waitResult = WaitForSingleObject(g_hCmdQueueSem, 1000); // 等待1秒

        if (waitResult == WAIT_OBJECT_0) {
            // 有新命令到达
            ColdStorage::Command cmd;
            bool cmdRead = false;

            // 获取互斥锁读取命令
            if (WaitForSingleObject(g_hMutex, 5000) == WAIT_OBJECT_0) {
                try {
                    uint32_t currentReadIndex = g_pSharedMemHeader->readIndex;
                    if (currentReadIndex != g_pSharedMemHeader->writeIndex) {
                        // 队列非空，读取命令
                        cmd = g_pSharedMemHeader->commandQueue[currentReadIndex];
                        // 更新读索引
                        g_pSharedMemHeader->readIndex = (currentReadIndex + 1) % ColdStorage::CMD_QUEUE_CAPACITY;
                        cmdRead = true;
                    }
                } catch (...) {
                     LogStorage("读取命令时发生异常");
                }
                ReleaseMutex(g_hMutex);
            } else {
                 LogStorage("错误：获取共享内存锁以读取命令时超时");
            }

            // 处理读取到的命令
            if (cmdRead) {
                switch (cmd.type) {
                    case ColdStorage::CommandType::PING:
                        LogStorage("收到 PING 命令");
                        SendAckResponse(ColdStorage::INVALID_BLOCK_ID);
                        break;
                    case ColdStorage::CommandType::STORE:
                        HandleStoreCommand(cmd);
                        break;
                    case ColdStorage::CommandType::RETRIEVE:
                        HandleRetrieveCommand(cmd);
                        break;
                    case ColdStorage::CommandType::FREE:
                        HandleFreeCommand(cmd);
                        break;
                    case ColdStorage::CommandType::SHUTDOWN:
                        LogStorage("收到 SHUTDOWN 命令，准备退出...");
                        g_shouldExit.store(true);
                        SendAckResponse(ColdStorage::INVALID_BLOCK_ID); // 确认收到关闭命令
                        break;
                    default:
                        LogStorage("收到未知命令类型: %u", static_cast<uint32_t>(cmd.type));
                        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::UNKNOWN_COMMAND);
                        break;
                }
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            // 超时，继续循环或执行其他维护任务
        } else {
            // 等待失败，可能需要退出
            LogStorage("等待命令信号量失败，错误码: %d，退出...", GetLastError());
            g_shouldExit.store(true);
        }
    }

    // 4. 清理资源
    LogStorage("开始清理资源...");
    {
        std::lock_guard<std::mutex> lock(g_storedBlocksMutex);
        for (auto const& [id, val] : g_storedBlocks) {
            if (val.ptr) {
                free(val.ptr);
            }
        }
        g_storedBlocks.clear();
        LogStorage("已释放所有存储的块");
    }

    if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
    if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
    if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
    if (g_hRespSem) CloseHandle(g_hRespSem);
    if (g_hMutex) CloseHandle(g_hMutex);
    if (g_hReadyEvent) CloseHandle(g_hReadyEvent); // 关闭就绪事件句柄

    LogStorage("存储进程正常退出");
    return 0;
}
