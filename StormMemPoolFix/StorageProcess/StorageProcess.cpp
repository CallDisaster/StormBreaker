// #include "pch.h" // 移除 pch.h 引用
#include "../ColdStorage/Common.h" // 添加 Common.h 引用
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

// 带 SEH 保护的 malloc
void* SafeMallocWithSEH(size_t size, ColdStorage::BlockID blockId) {
    void* ptr = nullptr;
    __try {
        ptr = malloc(size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogStorage("块 %llu: malloc 发生 SEH 异常: 0x%X", blockId, GetExceptionCode());
        ptr = nullptr;
    }
    return ptr;
}

// 带 SEH 保护的从共享内存复制
bool SafeCopyFromSharedMemWithSEH(void* dest, size_t sourceOffset, size_t size, ColdStorage::BlockID blockId) {
    bool copySuccess = false;
    LogStorage("块 %llu: 尝试从共享内存复制数据 (目标=%p, 源偏移=%zu, 大小=%zu)...", blockId, dest, sourceOffset, size);
    if (WaitForSingleObject(g_hMutex, 5000) == WAIT_OBJECT_0) {
        __try {
            // 确保数据偏移和大小在共享内存数据缓冲区范围内
            if (sourceOffset + size <= ColdStorage::DATA_BUFFER_SIZE) {
                LogStorage("块 %llu: 执行 memcpy...", blockId);
                memcpy(dest, g_pDataBuffer + sourceOffset, size);
                copySuccess = true;
                LogStorage("块 %llu: memcpy 完成", blockId);
            } else {
                LogStorage("错误：无效的数据偏移或大小 (块 %llu, 偏移 %zu, 大小 %zu, 缓冲区 %zu)", blockId, sourceOffset, size, ColdStorage::DATA_BUFFER_SIZE);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LogStorage("错误：从共享内存复制数据时发生 SEH 异常 (块 %llu): 0x%X", blockId, GetExceptionCode());
            copySuccess = false; // 确保标记为失败
        }
        ReleaseMutex(g_hMutex);
    } else {
        LogStorage("错误：获取共享内存锁以复制数据时超时 (块 %llu)", blockId);
    }
    return copySuccess;
}


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
            // 移除 SEH 保护，依赖 main 的顶层 SEH
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

    // 1. 分配数据存储空间（带SEH保护）
    void* storedPtr = nullptr;
    __try {
        storedPtr = malloc(cmd.size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogStorage("块 %llu: malloc 发生异常: 0x%X", cmd.blockId, GetExceptionCode());
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_NO_SPACE);
        return;
    }
    if (!storedPtr) {
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_NO_SPACE);
        return;
    }

    // 2. 数据复制（带SEH保护）
    bool copyOk = false;
    if (WaitForSingleObject(g_hMutex, 5000) == WAIT_OBJECT_0) {
        __try {
            if (cmd.dataOffset + cmd.size <= ColdStorage::DATA_BUFFER_SIZE) {
                memcpy(storedPtr, g_pDataBuffer + cmd.dataOffset, cmd.size);
                copyOk = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LogStorage("块 %llu: memcpy 发生异常 0x%X", cmd.blockId, GetExceptionCode());
        }
        ReleaseMutex(g_hMutex);
    }
    if (!copyOk) {
        __try { free(storedPtr); }
        __except (EXCEPTION_EXECUTE_HANDLER) {} // 防御野指针free
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_COPY_ERROR);
        return;
    }

    // 3. map写入（用手动锁 + SEH保护 free，不在try块内放C++对象!）
    bool mapOk = false;
    g_storedBlocksMutex.lock(); // 不要用 lock_guard，这里是POD对象就没事
    __try {
        auto it = g_storedBlocks.find(cmd.blockId);
        if (it != g_storedBlocks.end()) {
            __try { if (it->second.ptr) free(it->second.ptr); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        g_storedBlocks[cmd.blockId] = { storedPtr, cmd.size };
        mapOk = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 出现std::bad_alloc等，也不崩进程
        LogStorage("存储map发生SEH异常，BlockID=%llu", cmd.blockId);
    }
    g_storedBlocksMutex.unlock();

    if (!mapOk) {
        __try { free(storedPtr); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INTERNAL_ERROR);
        return;
    }

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
        // 使用 lock_guard，因为此函数不使用 SEH
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
    g_storedBlocksMutex.lock(); // 手动加锁
    auto it = g_storedBlocks.find(cmd.blockId);
    if (it != g_storedBlocks.end()) {
        found = true;
        ptrToFree = it->second.ptr;
        g_storedBlocks.erase(it);
    }
    g_storedBlocksMutex.unlock(); // 手动解锁

    // 2. 释放内存
    if (found) {
        if (ptrToFree) {
            // 添加 SEH 保护 free
            __try { free(ptrToFree); }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                 LogStorage("错误：释放块 %llu (地址 %p) 时发生 SEH 异常: 0x%X", cmd.blockId, ptrToFree, GetExceptionCode());
                 // 即使释放失败，也尝试发送错误响应
                 SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INTERNAL_ERROR);
                 return; // 提前返回，避免发送错误的 ACK
            }
        }
        SendAckResponse(cmd.blockId);
        LogStorage("块 %llu 释放成功", cmd.blockId);
    } else {
        LogStorage("错误：未找到要释放的块 %llu", cmd.blockId);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::FREE_FAILED_NOT_FOUND);
    }
}

// --- 命令处理循环函数 ---
void CommandProcessingLoop() {
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
                // 这里不再需要 try...catch，因为顶层 main 有 SEH
                uint32_t currentReadIndex = g_pSharedMemHeader->readIndex;
                if (currentReadIndex != g_pSharedMemHeader->writeIndex) {
                    // 队列非空，读取命令
                    cmd = g_pSharedMemHeader->commandQueue[currentReadIndex];
                    // 更新读索引
                    g_pSharedMemHeader->readIndex = (currentReadIndex + 1) % ColdStorage::CMD_QUEUE_CAPACITY;
                    cmdRead = true;
                }
                ReleaseMutex(g_hMutex);
            } else {
                 LogStorage("错误：获取共享内存锁以读取命令时超时");
                 // 考虑是否需要更健壮的处理，例如尝试重新获取或退出
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
    } // 结束 while 循环
}

// --- 清理资源函数 ---
void CleanupResources() {
    LogStorage("开始清理资源...");
    // 清理存储的块
    g_storedBlocksMutex.lock(); // 手动加锁
    __try { // SEH 保护 map 迭代和 free
        for (auto const& [id, val] : g_storedBlocks) {
            if (val.ptr) {
                // 添加 SEH 保护 free
                 __try { free(val.ptr); }
                 __except(EXCEPTION_EXECUTE_HANDLER) {
                      LogStorage("错误：清理时释放块 %llu (地址 %p) 时发生 SEH 异常: 0x%X", id, val.ptr, GetExceptionCode());
                 }
            }
        }
        g_storedBlocks.clear();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
         LogStorage("错误：清理 g_storedBlocks 时发生 SEH 异常: 0x%X", GetExceptionCode());
    }
    g_storedBlocksMutex.unlock(); // 手动解锁
    LogStorage("已释放所有存储的块");


    // 清理 Windows 句柄
    if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
    if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
    if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
    if (g_hRespSem) CloseHandle(g_hRespSem);
    if (g_hMutex) CloseHandle(g_hMutex);
    if (g_hReadyEvent) CloseHandle(g_hReadyEvent); // 关闭就绪事件句柄

    g_pSharedMemHeader = nullptr;
    g_pDataBuffer = nullptr;
    g_hSharedMemFile = NULL;
    g_hCmdQueueSem = NULL;
    g_hRespSem = NULL;
    g_hMutex = NULL;
    g_hReadyEvent = NULL;

    LogStorage("Windows 句柄已清理");
}


// --- 主函数 ---
int main() {
    LogStorage("存储进程启动");
    int exitCode = 0; // 用于返回码

    // 添加顶层 SEH 保护
    __try {
        // 1. 打开现有的共享内存和同步对象
        g_hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_MUTEX_NAME);
        if (!g_hMutex) {
             LogStorage("初始化失败: 打开互斥体失败 (代码: %d)", GetLastError());
             return 1;
        }

        g_hSharedMemFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_NAME);
        if (!g_hSharedMemFile) {
             LogStorage("初始化失败: 打开文件映射失败 (代码: %d)", GetLastError());
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        g_pSharedMemHeader = (ColdStorage::SharedMemHeader*)MapViewOfFile(g_hSharedMemFile, FILE_MAP_ALL_ACCESS, 0, 0, ColdStorage::SHARED_MEM_SIZE);
        if (!g_pSharedMemHeader) {
             LogStorage("初始化失败: 映射视图失败 (代码: %d)", GetLastError());
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }
        g_pDataBuffer = reinterpret_cast<unsigned char*>(g_pSharedMemHeader) + ColdStorage::DATA_BUFFER_OFFSET;

        g_hCmdQueueSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::CMD_QUEUE_SEM_NAME);
        if (!g_hCmdQueueSem) {
             LogStorage("初始化失败: 打开命令信号量失败 (代码: %d)", GetLastError());
             if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        g_hRespSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::RESP_SEM_NAME);
        if (!g_hRespSem) {
             LogStorage("初始化失败: 打开响应信号量失败 (代码: %d)", GetLastError());
             if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
             if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        LogStorage("共享资源连接成功");

        // 2. 发出就绪信号
        SetEvent(g_hReadyEvent);
        LogStorage("已发送就绪信号");

        // 3. 调用命令处理循环
        CommandProcessingLoop();

    // 4. 清理资源 (移到 SEH 块外部，确保总是执行)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogStorage("!!! 存储进程 main 函数发生严重 SEH 异常: 0x%X !!!", GetExceptionCode());
        exitCode = 1; // 设置错误返回码
        // 尝试进行最基本的清理
        if (g_hMutex) ReleaseMutex(g_hMutex); // 尝试释放可能持有的锁
    }

    __try {
        // 1. 打开现有的共享内存和同步对象
        g_hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_MUTEX_NAME);
        if (!g_hMutex) {
             LogStorage("初始化失败: 打开互斥体失败 (代码: %d)", GetLastError());
             return 1;
        }

        g_hSharedMemFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_NAME);
        if (!g_hSharedMemFile) {
             LogStorage("初始化失败: 打开文件映射失败 (代码: %d)", GetLastError());
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        g_pSharedMemHeader = (ColdStorage::SharedMemHeader*)MapViewOfFile(g_hSharedMemFile, FILE_MAP_ALL_ACCESS, 0, 0, ColdStorage::SHARED_MEM_SIZE);
        if (!g_pSharedMemHeader) {
             LogStorage("初始化失败: 映射视图失败 (代码: %d)", GetLastError());
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }
        g_pDataBuffer = reinterpret_cast<unsigned char*>(g_pSharedMemHeader) + ColdStorage::DATA_BUFFER_OFFSET;

        g_hCmdQueueSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::CMD_QUEUE_SEM_NAME);
        if (!g_hCmdQueueSem) {
             LogStorage("初始化失败: 打开命令信号量失败 (代码: %d)", GetLastError());
             if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        g_hRespSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::RESP_SEM_NAME);
        if (!g_hRespSem) {
             LogStorage("初始化失败: 打开响应信号量失败 (代码: %d)", GetLastError());
             if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
             if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        g_hReadyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, ColdStorage::STORAGE_PROCESS_READY_EVENT_NAME);
        if (!g_hReadyEvent) {
             LogStorage("初始化失败: 打开就绪事件失败 (代码: %d)", GetLastError());
             if (g_hRespSem) CloseHandle(g_hRespSem);
             if (g_hCmdQueueSem) CloseHandle(g_hCmdQueueSem);
             if (g_pSharedMemHeader) UnmapViewOfFile(g_pSharedMemHeader);
             if (g_hSharedMemFile) CloseHandle(g_hSharedMemFile);
             if (g_hMutex) CloseHandle(g_hMutex);
             return 1;
        }

        LogStorage("共享资源连接成功");

        // 2. 发出就绪信号
        SetEvent(g_hReadyEvent);
        LogStorage("已发送就绪信号");

        // 3. 调用命令处理循环
        CommandProcessingLoop();

    // 4. 清理资源 (移到 SEH 块外部，确保总是执行)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogStorage("!!! 存储进程 main 函数发生严重 SEH 异常: 0x%X !!!", GetExceptionCode());
        exitCode = 1; // 设置错误返回码
        // 尝试进行最基本的清理
        if (g_hMutex) ReleaseMutex(g_hMutex); // 尝试释放可能持有的锁
    }

    // 清理资源
    CleanupResources();

    LogStorage("存储进程退出，返回码: %d", exitCode);
    return exitCode;
}
