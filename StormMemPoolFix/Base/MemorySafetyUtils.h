// MemorySafetyUtils.h
#pragma once
#include "pch.h"
#include <Windows.h>
#include "Base/Logger.h"
#include "Storm/StormHook.h"

// 内存安全辅助工具类
class MemorySafetyUtils {
public:
    // 验证指针是否有效
    static bool IsValidPointer(void* ptr, size_t size = 1) {
        if (!ptr) return false;

        // 先检查指针地址是否有效
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            return false;
        }

        // 检查内存状态和保护
        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD)) {
            return false;
        }

        // 如果请求检查整个区域
        if (size > 1) {
            // 检查范围末尾是否有效
            char* endPtr = static_cast<char*>(ptr) + size - 1;
            if (endPtr < static_cast<char*>(ptr)) { // 溢出检查
                return false;
            }

            // 检查结束地址是否越界
            if (endPtr >= static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize) {
                // 跨区域，需要再次检查
                return VirtualQuery(endPtr, &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & PAGE_NOACCESS) &&
                    !(mbi.Protect & PAGE_GUARD);
            }
        }

        return true;
    }

    // 安全内存复制
    static bool SafeMemoryCopy(void* dest, const void* src, size_t size) {
        if (!dest || !src || size == 0) return false;

        // 验证源和目标内存
        if (!IsValidPointer(const_cast<void*>(src), size) ||
            !IsValidPointer(dest, size)) {
            return false;
        }

        // 这里不使用__try机制，而是使用更直接的方法
        // 分块复制
        const size_t CHUNK_SIZE = 4096;
        const char* srcPtr = static_cast<const char*>(src);
        char* destPtr = static_cast<char*>(dest);

        for (size_t offset = 0; offset < size; offset += CHUNK_SIZE) {
            size_t bytesToCopy = (offset + CHUNK_SIZE > size) ?
                (size - offset) : CHUNK_SIZE;

            if (IsBadReadPtr(srcPtr + offset, bytesToCopy) ||
                IsBadWritePtr(destPtr + offset, bytesToCopy)) {
                LogMessage("[安全] 内存复制错误: dest=%p, src=%p, offset=%zu",
                    dest, src, offset);
                return false;
            }

            memcpy(destPtr + offset, srcPtr + offset, bytesToCopy);
        }

        return true;
    }

    // 检查Storm内存块有效性
    static bool IsValidStormBlock(void* userPtr) {
        if (!userPtr) return false;

        // 检查指针是否可读
        if (IsBadReadPtr(userPtr, sizeof(void*))) {
            return false;
        }

        // 尝试读取头部
        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(userPtr) - sizeof(StormAllocHeader));

        // 检查头部是否可读
        if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
            return false;
        }

        // 验证基本魔数
        if (header->Magic != STORM_MAGIC) {
            return false;
        }

        // 如果特殊标记
        if (header->HeapPtr == SPECIAL_MARKER) {
            return true;
        }

        // 验证Storm块一致性
        if (header->Size == 0 ||
            header->Size > 0x1000000 || // 16MB是一个合理的上限
            (header->Flags & 0x2)) { // 标记为已释放
            return false;
        }

        // 检查用户区是否可访问
        return !IsBadReadPtr(userPtr, header->Size);
    }

    // 尝试获取块大小
    static size_t GetBlockSize(void* ptr) {
        if (!ptr) return 0;

        // 检查指针是否可读
        if (IsBadReadPtr(ptr, sizeof(void*))) {
            return 0;
        }

        StormAllocHeader* header = reinterpret_cast<StormAllocHeader*>(
            static_cast<char*>(ptr) - sizeof(StormAllocHeader));

        // 检查头部是否可读
        if (IsBadReadPtr(header, sizeof(StormAllocHeader))) {
            return 0;
        }

        if (header->Magic == STORM_MAGIC) {
            return header->Size;
        }

        return 0;
    }
};