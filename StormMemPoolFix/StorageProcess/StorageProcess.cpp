// StorageProcess.cpp
#include "../ColdStorage/Common.h" // 添加 Common.h 引用
#include <Windows.h>
#include <iostream>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdlib> // For malloc, free
#include <cstdio> // For vsnprintf, printf
#include <cstdarg> // For va_list, va_start, va_end

// --- 全局变量 (存储进程内部) ---
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

    // 简单的块存储结构 - 替代unordered_map
    struct StoredBlock {
        void* ptr;        // 内存指针
        size_t size;      // 块大小
        bool inUse;       // 是否使用中
    };
    
    // 改为动态分配
    const size_t MAX_BLOCKS = 1000;  // 减小到1000个块
    StoredBlock* g_blockStore = nullptr;  // 改为指针
    CRITICAL_SECTION g_blockStoreLock;  // 使用Windows临界区替代std::mutex

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

    // 初始化块存储 - 改为使用Windows API
    bool InitBlockStore() {
        // 初始化临界区
        InitializeCriticalSection(&g_blockStoreLock);
        
        // 动态分配块存储数组
        g_blockStore = (StoredBlock*)malloc(sizeof(StoredBlock) * MAX_BLOCKS);
        if (!g_blockStore) {
            LogStorage("错误: 无法分配块存储数组");
            return false;
        }
        
        // 初始化所有块
        for (size_t i = 0; i < MAX_BLOCKS; i++) {
            g_blockStore[i].ptr = nullptr;
            g_blockStore[i].size = 0;
            g_blockStore[i].inUse = false;
        }
        
        LogStorage("块存储初始化成功: %zu 块", MAX_BLOCKS);
        return true;
    }
    
    // 添加资源释放函数
    void DestroyBlockStore() {
        if (g_blockStore) {
            // 先清理已分配的内存块
            EnterCriticalSection(&g_blockStoreLock);
            for (size_t i = 0; i < MAX_BLOCKS; i++) {
                if (g_blockStore[i].inUse && g_blockStore[i].ptr) {
                    free(g_blockStore[i].ptr);
                }
            }
            
            // 释放存储数组
            free(g_blockStore);
            g_blockStore = nullptr;
            LeaveCriticalSection(&g_blockStoreLock);
        }
        
        // 删除临界区
        DeleteCriticalSection(&g_blockStoreLock);
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

        // 4. 将响应写入命令队列
        uint32_t responseIndex = (g_pSharedMemHeader->writeIndex + ColdStorage::CMD_QUEUE_CAPACITY - 1) % ColdStorage::CMD_QUEUE_CAPACITY;
        g_pSharedMemHeader->commandQueue[responseIndex] = finalResponse;

        // 5. 释放响应信号量，通知主进程有响应
        if (!ReleaseSemaphore(g_hRespSem, 1, NULL)) {
            LogStorage("错误：释放响应信号量失败，错误码: %d", GetLastError());
            throw std::runtime_error("Failed to release response semaphore");
        }

        success = true;

    }
    catch (const std::exception& e) {
        LogStorage("发送响应时发生异常: %s", e.what());
        success = false;
    }
    catch (...) {
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
    response.size = size;
    response.errorCode = ColdStorage::ErrorCode::NONE;
    return SendResponse(response, data, size);
}

// --- 命令处理函数 ---

void HandleStoreCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 STORE 命令: ID=%llu, 大小=%zu, 数据偏移=%zu", cmd.blockId, cmd.size, cmd.dataOffset);

    // 验证参数
    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID || cmd.size == 0) {
        LogStorage("无效的BlockID或大小为0，发送错误响应");
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 确保BlockID在有效范围内
    if (cmd.blockId >= MAX_BLOCKS) {
        LogStorage("错误：BlockID超出最大范围: %llu >= %zu", cmd.blockId, MAX_BLOCKS);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 验证数据偏移量是否在有效范围内
    if (cmd.dataOffset >= ColdStorage::DATA_BUFFER_SIZE) {
        LogStorage("错误：数据偏移量超出缓冲区范围：%zu >= %zu",
            cmd.dataOffset, ColdStorage::DATA_BUFFER_SIZE);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_COPY_ERROR);
        return;
    }

    // 验证缓冲区大小是否足够
    if (cmd.dataOffset + cmd.size > ColdStorage::DATA_BUFFER_SIZE) {
        LogStorage("错误：数据大小超出缓冲区剩余空间：%zu + %zu > %zu",
            cmd.dataOffset, cmd.size, ColdStorage::DATA_BUFFER_SIZE);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_COPY_ERROR);
        return;
    }

    // 1. 分配内存
    LogStorage("块 %llu: 分配存储空间: %zu 字节", cmd.blockId, cmd.size);
    void* storedPtr = nullptr;
    __try {
        storedPtr = malloc(cmd.size);
        if (!storedPtr) {
            LogStorage("块 %llu: malloc返回空指针", cmd.blockId);
            SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_NO_SPACE);
            return;
        }
        LogStorage("块 %llu: 内存分配成功: %p", cmd.blockId, storedPtr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("块 %llu: malloc 发生异常: 0x%X", cmd.blockId, exCode);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_NO_SPACE);
        return;
    }

    // 2. 数据复制
    LogStorage("块 %llu: 正在复制数据...", cmd.blockId);
    bool copyOk = false;

    if (WaitForSingleObject(g_hMutex, 5000) != WAIT_OBJECT_0) {
        LogStorage("块 %llu: 无法获取互斥锁进行数据复制", cmd.blockId);
        free(storedPtr);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::SHARED_MEM_ERROR);
        return;
    }

    __try {
        LogStorage("块 %llu: 开始内存复制: 源=%p, 目标=%p, 大小=%zu",
            cmd.blockId, (g_pDataBuffer + cmd.dataOffset), storedPtr, cmd.size);

        // 逐字节复制提高安全性
        unsigned char* src = g_pDataBuffer + cmd.dataOffset;
        unsigned char* dst = (unsigned char*)storedPtr;
        for (size_t i = 0; i < cmd.size; i++) {
            dst[i] = src[i];
        }

        copyOk = true;
        LogStorage("块 %llu: 数据复制成功", cmd.blockId);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("块 %llu: 数据复制异常: 0x%X", cmd.blockId, exCode);
    }

    ReleaseMutex(g_hMutex);

    if (!copyOk) {
        LogStorage("块 %llu: 数据复制失败，正在释放已分配内存", cmd.blockId);
        free(storedPtr);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::STORE_FAILED_COPY_ERROR);
        return;
    }

    // 3. 存储块
    LogStorage("块 %llu: 正在写入存储映射...", cmd.blockId);
    bool mapOk = false;

    EnterCriticalSection(&g_blockStoreLock);
    __try {
        // 如果该块已经存在，先释放旧内存
        if (g_blockStore[cmd.blockId].inUse && g_blockStore[cmd.blockId].ptr) {
            LogStorage("块 %llu: 替换现有块", cmd.blockId);
            free(g_blockStore[cmd.blockId].ptr);
        }

        // 更新存储
        g_blockStore[cmd.blockId].ptr = storedPtr;
        g_blockStore[cmd.blockId].size = cmd.size;
        g_blockStore[cmd.blockId].inUse = true;

        mapOk = true;
        LogStorage("块 %llu: 存储映射更新成功", cmd.blockId);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("块 %llu: 存储映射写入异常: 0x%X", cmd.blockId, exCode);
    }
    LeaveCriticalSection(&g_blockStoreLock);

    if (!mapOk) {
        LogStorage("块 %llu: 存储映射写入失败", cmd.blockId);
        free(storedPtr);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INTERNAL_ERROR);
        return;
    }

    // 4. 发送成功响应
    LogStorage("块 %llu: 存储成功，发送确认响应", cmd.blockId);
    if (!SendAckResponse(cmd.blockId)) {
        LogStorage("块 %llu: 发送确认响应失败", cmd.blockId);
    }
    LogStorage("块 %llu 存储处理完成", cmd.blockId);
}

void HandleRetrieveCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 RETRIEVE 命令: ID=%llu", cmd.blockId);

    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID) {
        LogStorage("无效的BlockID，发送错误响应");
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 检查BlockID是否在有效范围内
    if (cmd.blockId >= MAX_BLOCKS) {
        LogStorage("错误：BlockID超出范围: %llu >= %zu", cmd.blockId, MAX_BLOCKS);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    void* dataPtr = nullptr;
    size_t dataSize = 0;

    // 从块存储获取数据
    EnterCriticalSection(&g_blockStoreLock);
    __try {
        if (g_blockStore[cmd.blockId].inUse) {
            dataPtr = g_blockStore[cmd.blockId].ptr;
            dataSize = g_blockStore[cmd.blockId].size;
            LogStorage("块 %llu: 查找成功，大小=%zu", cmd.blockId, dataSize);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("块 %llu: 获取存储信息异常: 0x%X", cmd.blockId, exCode);
    }
    LeaveCriticalSection(&g_blockStoreLock);

    if (!dataPtr) {
        LogStorage("错误：未找到要取回的块 %llu", cmd.blockId);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::RETRIEVE_FAILED_NOT_FOUND);
        return;
    }

    // 发送数据响应
    LogStorage("块 %llu: 正在发送数据响应...", cmd.blockId);
    if (SendDataResponse(cmd.blockId, dataPtr, dataSize)) {
        LogStorage("块 %llu 取回数据发送成功", cmd.blockId);
    }
    else {
        LogStorage("错误：发送块 %llu 的数据响应失败", cmd.blockId);
    }
}

void HandleFreeCommand(const ColdStorage::Command& cmd) {
    LogStorage("处理 FREE 命令: ID=%llu", cmd.blockId);

    if (cmd.blockId == ColdStorage::INVALID_BLOCK_ID) {
        LogStorage("无效的BlockID，发送错误响应");
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 检查BlockID是否在有效范围内
    if (cmd.blockId >= MAX_BLOCKS) {
        LogStorage("错误：BlockID超出范围: %llu >= %zu", cmd.blockId, MAX_BLOCKS);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INVALID_BLOCK_ID);
        return;
    }

    // 查找并释放块
    bool found = false;
    void* ptrToFree = nullptr;

    EnterCriticalSection(&g_blockStoreLock);
    __try {
        if (g_blockStore[cmd.blockId].inUse) {
            found = true;
            ptrToFree = g_blockStore[cmd.blockId].ptr;

            // 清除存储条目
            g_blockStore[cmd.blockId].ptr = nullptr;
            g_blockStore[cmd.blockId].size = 0;
            g_blockStore[cmd.blockId].inUse = false;

            LogStorage("块 %llu: 已从存储映射中移除", cmd.blockId);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("块 %llu: 移除块异常: 0x%X", cmd.blockId, exCode);
    }
    LeaveCriticalSection(&g_blockStoreLock);

    // 释放内存
    if (found && ptrToFree) {
        __try {
            free(ptrToFree);
            LogStorage("块 %llu: 内存已释放", cmd.blockId);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD exCode = GetExceptionCode();
            LogStorage("错误：释放块 %llu (地址 %p) 时发生 SEH 异常: 0x%X",
                cmd.blockId, ptrToFree, exCode);
            SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INTERNAL_ERROR);
            return;
        }

        SendAckResponse(cmd.blockId);
        LogStorage("块 %llu 释放成功", cmd.blockId);
    }
    else {
        LogStorage("错误：未找到要释放的块 %llu", cmd.blockId);
        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::FREE_FAILED_NOT_FOUND);
    }
}

// --- 命令处理循环函数 ---
void CommandProcessingLoop() {
    LogStorage("开始监听命令...");

    // 添加外层异常处理
    __try {
        while (!g_shouldExit.load()) {
            // 等待命令信号量
            DWORD waitResult = WaitForSingleObject(g_hCmdQueueSem, 1000); // 等待1秒

            if (waitResult == WAIT_OBJECT_0) {
                // 有新命令到达
                ColdStorage::Command cmd = {};
                bool cmdRead = false;

                // 获取互斥锁读取命令
                if (WaitForSingleObject(g_hMutex, 5000) == WAIT_OBJECT_0) {
                    __try {
                        uint32_t currentReadIndex = g_pSharedMemHeader->readIndex;
                        if (currentReadIndex != g_pSharedMemHeader->writeIndex) {
                            // 队列非空，读取命令
                            cmd = g_pSharedMemHeader->commandQueue[currentReadIndex];
                            // 更新读索引
                            g_pSharedMemHeader->readIndex = (currentReadIndex + 1) % ColdStorage::CMD_QUEUE_CAPACITY;
                            cmdRead = true;
                            LogStorage("读取命令: 类型=%u, ID=%llu",
                                static_cast<unsigned>(cmd.type), cmd.blockId);
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        DWORD exCode = GetExceptionCode();
                        LogStorage("读取命令时发生异常: 0x%X", exCode);
                    }
                    ReleaseMutex(g_hMutex);
                }
                else {
                    LogStorage("错误：获取共享内存锁以读取命令时超时");
                }

                // 处理读取到的命令 - 为每个命令类型添加独立的异常处理
                if (cmdRead) {
                    __try {
                        LogStorage("开始处理命令: 类型=%u, ID=%llu",
                            static_cast<unsigned>(cmd.type), cmd.blockId);

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
                            SendAckResponse(ColdStorage::INVALID_BLOCK_ID);
                            break;
                        default:
                            LogStorage("收到未知命令类型: %u", static_cast<uint32_t>(cmd.type));
                            SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::UNKNOWN_COMMAND);
                            break;
                        }

                        LogStorage("命令处理完成: 类型=%u, ID=%llu",
                            static_cast<unsigned>(cmd.type), cmd.blockId);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        DWORD exCode = GetExceptionCode();
                        LogStorage("处理命令时发生严重异常: 类型=%u, ID=%llu, 错误=0x%X",
                            static_cast<unsigned>(cmd.type), cmd.blockId, exCode);

                        // 尝试发送错误响应
                        SendErrorResponse(cmd.blockId, ColdStorage::ErrorCode::INTERNAL_ERROR);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("命令处理循环发生崩溃性异常: 0x%X", exCode);
    }

    LogStorage("命令监听循环已退出");
}

// --- 清理资源函数 ---
void CleanupResources() {
    LogStorage("开始清理资源...");

    // 清理块存储
    LogStorage("正在清理存储块...");
    EnterCriticalSection(&g_blockStoreLock);
    __try {
        for (size_t i = 0; i < MAX_BLOCKS; i++) {
            if (g_blockStore[i].inUse && g_blockStore[i].ptr) {
                __try {
                    free(g_blockStore[i].ptr);
                    g_blockStore[i].ptr = nullptr;
                    g_blockStore[i].size = 0;
                    g_blockStore[i].inUse = false;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DWORD exCode = GetExceptionCode();
                    LogStorage("错误：释放块 %zu 时异常: 0x%X", i, exCode);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("错误：清理存储块时发生异常: 0x%X", exCode);
    }
    LeaveCriticalSection(&g_blockStoreLock);
    LogStorage("存储块清理完成");

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

    LogStorage("所有资源已清理");
}

// --- 主函数 ---
int main() {
    LogStorage("存储进程启动");
    int exitCode = 0; // 用于返回码

    // 初始化块存储
    LogStorage("初始化块存储器...");
    InitBlockStore();

    // 顶层异常处理
    __try {
        // 1. 初始化步骤 - 按顺序执行所有句柄初始化
        LogStorage("正在初始化共享内存和同步对象...");

        // 1.1 初始化互斥体
        LogStorage("正在打开互斥体...");
        g_hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_MUTEX_NAME);
        if (!g_hMutex) {
            LogStorage("初始化失败: 打开互斥体失败 (代码: %d)", GetLastError());
            return 1;
        }
        LogStorage("互斥体初始化成功");

        // 1.2 初始化共享内存
        LogStorage("正在打开共享内存文件映射...");
        g_hSharedMemFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ColdStorage::SHARED_MEM_NAME);
        if (!g_hSharedMemFile) {
            LogStorage("初始化失败: 打开文件映射失败 (代码: %d)", GetLastError());
            CloseHandle(g_hMutex);
            return 1;
        }
        LogStorage("共享内存文件映射打开成功");

        LogStorage("正在映射共享内存视图...");
        g_pSharedMemHeader = (ColdStorage::SharedMemHeader*)MapViewOfFile(g_hSharedMemFile, FILE_MAP_ALL_ACCESS, 0, 0, ColdStorage::SHARED_MEM_SIZE);
        if (!g_pSharedMemHeader) {
            LogStorage("初始化失败: 映射视图失败 (代码: %d)", GetLastError());
            CloseHandle(g_hSharedMemFile);
            CloseHandle(g_hMutex);
            return 1;
        }
        g_pDataBuffer = reinterpret_cast<unsigned char*>(g_pSharedMemHeader) + ColdStorage::DATA_BUFFER_OFFSET;
        LogStorage("共享内存视图映射成功");

        // 1.3 初始化命令信号量
        LogStorage("正在打开命令信号量...");
        g_hCmdQueueSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::CMD_QUEUE_SEM_NAME);
        if (!g_hCmdQueueSem) {
            LogStorage("初始化失败: 打开命令信号量失败 (代码: %d)", GetLastError());
            UnmapViewOfFile(g_pSharedMemHeader);
            CloseHandle(g_hSharedMemFile);
            CloseHandle(g_hMutex);
            return 1;
        }
        LogStorage("命令信号量打开成功");

        // 1.4 初始化响应信号量
        LogStorage("正在打开响应信号量...");
        g_hRespSem = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, ColdStorage::RESP_SEM_NAME);
        if (!g_hRespSem) {
            LogStorage("初始化失败: 打开响应信号量失败 (代码: %d)", GetLastError());
            CloseHandle(g_hCmdQueueSem);
            UnmapViewOfFile(g_pSharedMemHeader);
            CloseHandle(g_hSharedMemFile);
            CloseHandle(g_hMutex);
            return 1;
        }
        LogStorage("响应信号量打开成功");

        // 1.5 初始化就绪事件
        LogStorage("正在打开就绪事件...");
        g_hReadyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, ColdStorage::STORAGE_PROCESS_READY_EVENT_NAME);
        if (!g_hReadyEvent) {
            LogStorage("初始化失败: 打开就绪事件失败 (代码: %d)", GetLastError());
            CloseHandle(g_hRespSem);
            CloseHandle(g_hCmdQueueSem);
            UnmapViewOfFile(g_pSharedMemHeader);
            CloseHandle(g_hSharedMemFile);
            CloseHandle(g_hMutex);
            return 1;
        }
        LogStorage("就绪事件打开成功");

        LogStorage("所有共享资源连接成功");

        // 2. 发出就绪信号 - 所有句柄都已成功初始化后才执行
        LogStorage("正在发送就绪信号...");
        if (!SetEvent(g_hReadyEvent)) {
            LogStorage("警告: 发送就绪信号失败 (代码: %d)", GetLastError());
        }
        else {
            LogStorage("就绪信号已成功发送");
        }

        // 3. 调用命令处理循环
        CommandProcessingLoop();

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        LogStorage("!!! 存储进程 main 函数发生严重 SEH 异常: 0x%X !!!", exCode);
        exitCode = 1; // 设置错误返回码
        // 尝试进行最基本的清理
        if (g_hMutex) ReleaseMutex(g_hMutex); // 尝试释放可能持有的锁
    }

    // 清理资源
    CleanupResources();

    LogStorage("存储进程退出，返回码: %d", exitCode);
    return exitCode;
}