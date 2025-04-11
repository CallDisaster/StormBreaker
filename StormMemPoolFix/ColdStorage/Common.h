#pragma once

#include <Windows.h>
#include <cstdint>

namespace ColdStorage {

// --- 常量定义 ---

// Common.h 中的命名空间对象调整

// 共享内存名称 (确保唯一性)
    constexpr const wchar_t* SHARED_MEM_NAME = L"Global\\StormColdStorageSharedMem_v1";
    // 命令队列信号量名称
    constexpr const wchar_t* CMD_QUEUE_SEM_NAME = L"Global\\StormColdStorageCmdSem_v1";
    // 响应信号量名称
    constexpr const wchar_t* RESP_SEM_NAME = L"Global\\StormColdStorageRespSem_v1";
    // 共享内存互斥体名称
    constexpr const wchar_t* SHARED_MEM_MUTEX_NAME = L"Global\\StormColdStorageMutex_v1";
    // 存储进程启动事件名称
    constexpr const wchar_t* STORAGE_PROCESS_READY_EVENT_NAME = L"Global\\StormColdStorageReadyEvent_v1";


// 共享内存大小 (例如 64MB，可调整)
constexpr size_t SHARED_MEM_SIZE = 64 * 1024 * 1024;
// 命令队列大小 (能容纳多少个命令)
constexpr size_t CMD_QUEUE_CAPACITY = 1024;
// 数据缓冲区大小 (共享内存中用于传输数据的区域)
constexpr size_t DATA_BUFFER_OFFSET = sizeof(uint32_t) * 2; // read/write index for queue
// const size_t DATA_BUFFER_SIZE = SHARED_MEM_SIZE - (CMD_QUEUE_CAPACITY * sizeof(Command) + DATA_BUFFER_OFFSET); // Moved definition after Command struct


// --- 枚举与结构体 ---

// 命令类型
enum class CommandType : uint32_t {
    PING = 0,       // 心跳检测
    STORE = 1,      // 请求存储内存块
    RETRIEVE = 2,   // 请求取回内存块
    FREE = 3,       // 请求释放内存块
    SHUTDOWN = 4,   // 通知存储进程关闭
    ACK = 100,      // 确认响应
    ERROR_RESP = 101, // 错误响应
    DATA_RESP = 102   // 数据响应 (用于RETRIEVE)
};

// 错误码
enum class ErrorCode : uint32_t {
    NONE = 0,
    UNKNOWN_COMMAND = 1,
    STORE_FAILED_NO_SPACE = 2,
    STORE_FAILED_COPY_ERROR = 3,
    RETRIEVE_FAILED_NOT_FOUND = 4,
    RETRIEVE_FAILED_COPY_ERROR = 5,
    FREE_FAILED_NOT_FOUND = 6,
    INVALID_BLOCK_ID = 7,
    SHARED_MEM_ERROR = 8,
    INTERNAL_ERROR = 99
};

// 内存块唯一ID类型
using BlockID = uint64_t;
constexpr BlockID INVALID_BLOCK_ID = 0;

// 命令结构体 (在共享内存命令队列中使用)
#pragma pack(push, 1)
struct Command {
    CommandType type;       // 命令类型
    BlockID blockId;        // 操作的内存块ID
    size_t size;            // 内存块大小 (STORE/RETRIEVE时有效)
    size_t dataOffset;      // 数据在共享内存数据区的偏移 (STORE/RETRIEVE时有效)
    ErrorCode errorCode;    // 错误码 (响应时有效)
    // 可根据需要添加其他字段，如校验和等
};
#pragma pack(pop)

// 数据缓冲区大小 (共享内存中用于传输数据的区域) - 定义移到此处
const size_t DATA_BUFFER_SIZE = SHARED_MEM_SIZE - (CMD_QUEUE_CAPACITY * sizeof(Command) + DATA_BUFFER_OFFSET);

// 共享内存头部结构 (用于管理命令队列)
struct SharedMemHeader {
    volatile uint32_t writeIndex; // 主进程写入命令的位置
    volatile uint32_t readIndex;  // 存储进程读取命令的位置
    Command commandQueue[CMD_QUEUE_CAPACITY]; // 命令循环队列
    // 后续是数据缓冲区
};


} // namespace ColdStorage
