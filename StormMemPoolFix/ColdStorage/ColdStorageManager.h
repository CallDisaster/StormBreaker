#pragma once

#include "Common.h"
#include <Windows.h>
#include <string>
#include <mutex>
#include <atomic>
#include <vector>
#include <optional> // 用于可选返回值

namespace ColdStorage {

// 主进程中的冷存储管理器
class ColdStorageManager {
public:
    // 获取单例实例
    static ColdStorageManager& GetInstance();

    // 初始化：创建/打开共享内存、信号量、互斥体，尝试启动存储进程
    bool Initialize(const std::wstring& storageProcessPath);

    // 关闭：通知存储进程关闭，释放资源
    void Shutdown();

    // 检查存储进程是否就绪
    bool IsStorageProcessReady() const;

    // 请求存储内存块
    // ptr: 指向要存储的数据的指针
    // size: 数据大小
    // 返回: 成功则返回分配的BlockID，失败则返回INVALID_BLOCK_ID
    BlockID StoreBlock(const void* ptr, size_t size);

    // 请求取回内存块
    // blockId: 要取回的块ID
    // buffer: 用于接收数据的缓冲区
    // bufferSize: 缓冲区大小
    // 返回: 成功则返回实际读取的大小，失败则返回std::nullopt
    std::optional<size_t> RetrieveBlock(BlockID blockId, void* buffer, size_t bufferSize);

    // 请求释放内存块
    // blockId: 要释放的块ID
    // 返回: 操作是否成功发送并得到确认
    bool FreeBlock(BlockID blockId);

    // Ping存储进程，检查连通性
    bool PingStorageProcess();

private:
    // 私有构造/析构，确保单例
    ColdStorageManager();
    ~ColdStorageManager();

    // 禁止复制和赋值
    ColdStorageManager(const ColdStorageManager&) = delete;
    ColdStorageManager& operator=(const ColdStorageManager&) = delete;

    // 启动存储进程
    bool LaunchStorageProcess(const std::wstring& path);

    // 发送命令到共享内存队列 (内部函数，处理同步和队列管理)
    // cmd: 要发送的命令
    // dataPtr: (可选) 指向要同时写入数据区的数据
    // dataSize: (可选) 数据大小
    // 返回: 操作是否成功
    bool SendCommandInternal(const Command& cmd, const void* dataPtr = nullptr, size_t dataSize = 0);

    // 等待并获取响应 (内部函数)
    // expectedType: 期望的响应类型
    // timeoutMs: 超时时间 (毫秒)
    // outCmd: (可选) 用于接收响应命令结构体
    // outDataBuffer: (可选) 用于接收响应数据的缓冲区 (DATA_RESP时)
    // outDataSize: (可选) 接收到的数据大小
    // 返回: 操作是否成功及错误码
    std::pair<bool, ErrorCode> WaitForResponse(CommandType expectedType, DWORD timeoutMs = 5000,
                                               Command* outCmd = nullptr,
                                               void* outDataBuffer = nullptr,
                                               size_t* outDataSize = nullptr);

    // 生成唯一的BlockID
    BlockID GenerateNewBlockID();

    // --- 成员变量 ---
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_storageProcessReady{ false };
    HANDLE m_hSharedMemFile = NULL;     // 共享内存文件句柄
    SharedMemHeader* m_pSharedMemHeader = nullptr; // 指向共享内存头部的指针
    unsigned char* m_pDataBuffer = nullptr;      // 指向共享内存数据缓冲区的指针
    HANDLE m_hCmdQueueSem = NULL;       // 命令队列信号量 (通知存储进程有新命令)
    HANDLE m_hRespSem = NULL;           // 响应信号量 (存储进程通知主进程有响应)
    HANDLE m_hMutex = NULL;             // 共享内存互斥体 (保护共享内存访问)
    HANDLE m_hStorageProcess = NULL;    // 存储进程句柄
    HANDLE m_hReadyEvent = NULL;        // 存储进程就绪事件

    std::mutex m_apiMutex;              // 保护对外的API调用，防止并发问题
    std::atomic<uint64_t> m_nextBlockId{ 1 }; // 用于生成BlockID
};

} // namespace ColdStorage
