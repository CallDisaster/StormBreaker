// ======================== StormHook.h 修复版本 ========================
#pragma once
#include "pch.h"
#include <Windows.h>
#include <atomic>
#include <stdint.h>
#include <unordered_map>

// 前向声明Logger，避免包含问题
class Logger;

// ======================== Storm 兼容小块头（16字节防伪识别头）
// ========================
#pragma pack(push, 1)

struct StormAllocHeader {
  uint32_t magic;         // StormBreaker 自有块标识
  uint32_t requestedSize; // 用户请求大小
  uint32_t sizeCookie;    // requestedSize ^ kStormBreakerCookie
  uint16_t headerSize;    // 头大小
  uint16_t rejectTag;     // 故意不写 0x6F6D，令原生 Storm 快速拒绝
};
#pragma pack(pop)

static_assert(sizeof(StormAllocHeader) == 16,
              "StormAllocHeader must be exactly 16 bytes");

// ======================== 统一标识常量 ========================
constexpr uint32_t STORMBREAKER_MAGIC = 0x53425431u; // 'SBT1'
constexpr uint32_t kStormBreakerCookie = 0x9E3779B9u;
constexpr uint16_t kStormBreakerRejectTag = 0x4253u; // 'SB'
constexpr uint16_t STORM_FRONT_MAGIC = 0x6F6D;       // Storm前置魔数

// ======================== 全局状态管理 ========================
namespace StormHook {
// 初始化和清理
bool Initialize();
void Shutdown();

// 状态查询
bool IsOurBlock(void *userPtr);
bool IsInUnsafePeriod();

// 内存管理
void *AllocateMemory(size_t size, const char *name = nullptr,
                     DWORD srcLine = 0);
bool FreeMemory(void *ptr);
void *ReallocMemory(void *oldPtr, size_t newSize, const char *name = nullptr,
                    DWORD srcLine = 0);

// 清理和维护
void FlushManagedBlocks();
void ProcessDeferredFree();

// 统计信息
size_t GetManagedBlockCount();
size_t GetTotalManagedSize();

// Reset协同
void PrepareForReset();
void PostReset();

// 对齐验证
bool IsPointerAligned(void *ptr, size_t alignment);
bool ValidateBlockAlignment(void *userPtr);

// 大块阈值管理
void SetLargeBlockThreshold(size_t bytes);
size_t GetLargeBlockThreshold();
} // namespace StormHook

// ======================== Hook函数声明 ========================
extern "C" {
// Storm内存分配Hook
void *__fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size,
                                       const char *name, DWORD srcLine,
                                       DWORD flags);
int __stdcall Hooked_Storm_MemFree(void *ptr, const char *name, int argList,
                                   DWORD flags);
int __stdcall Hooked_Storm_MemGetSize(void *ptr, const char *name, int argList);
void *__fastcall Hooked_Storm_MemReAlloc(int ecx, int edx, void *oldPtr,
                                         size_t newSize, const char *name,
                                         DWORD srcLine, DWORD flags);

// Storm清理Hook
void __stdcall Hooked_StormHeap_CleanupAll();

// Reset协同Hook（可选）
int __stdcall Hooked_ResetMemoryManager();
}

// ======================== 原始函数指针类型 ========================
typedef void *(__fastcall *Storm_MemAlloc_t)(int ecx, int edx, size_t size,
                                             const char *name, DWORD srcLine,
                                             DWORD flags);
typedef int(__stdcall *Storm_MemFree_t)(void *ptr, const char *name,
                                        int argList, DWORD flags);
typedef void *(__fastcall *Storm_MemReAlloc_t)(int ecx, int edx, void *oldPtr,
                                               size_t newSize, const char *name,
                                               DWORD srcLine, DWORD flags);
typedef int(__stdcall *Storm_MemGetSize_t)(void *ptr, const char *name,
                                           int argList);
typedef void(__stdcall *StormHeap_CleanupAll_t)();
typedef int(__stdcall *ResetMemoryManager_t)();

// ======================== 原始函数指针（外部定义） ========================
extern Storm_MemAlloc_t g_origStormAlloc;
extern Storm_MemFree_t g_origStormFree;
extern Storm_MemReAlloc_t g_origStormReAlloc;
extern Storm_MemGetSize_t g_origStormGetSize;
extern StormHeap_CleanupAll_t g_origCleanupAll;
extern ResetMemoryManager_t g_origResetMemoryManager;

// ======================== 内部状态（不暴露实现细节） ========================
namespace StormHook_Internal {
// 头部操作
void SetupStormTlsfHeader(void *userPtr, size_t size);
bool QueryManagedBlock(void *userPtr, StormAllocHeader **outOriginalHeader,
                       size_t *outOriginalSize);
void PoisonManagedHeader(StormAllocHeader *hdr);

// 状态管理
void EnterUnsafePeriod();
void ExitUnsafePeriod();
} // namespace StormHook_Internal
