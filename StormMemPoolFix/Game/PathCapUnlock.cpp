#include "pch.h"
#include "PathCapUnlock.h"
#include <windows.h>
#include <psapi.h>
#include <cstring>
#include <atomic>
#include <vector>
#include <Base/Logger.h>

// ------- 你当前环境下验证过的相对偏移（相对于 game.dll 基址） -------
// 说明：在你这套 1.27a 构建中，表地址 = game.dll + 0x00BC5FFC
// 如果后面要适配别的版本，可以在这里开一个表做版本映射或做 sig-scan
static constexpr uintptr_t kPathTableRva = 0x00BC5FFC;

// 表结构参数（来自你的 JASS 反推）
static constexpr size_t kEntryCount = 64;
static constexpr size_t kStride = 0x1C; // 28 bytes

// 运行期状态
namespace {
    std::atomic<bool>   g_installed{ false };
    uintptr_t           g_tableAddr = 0;                // 实际 VA
    float               g_backup[kEntryCount] = { 0.0f }; // 备份首字段（float）
}

// RAII 的页面保护修改器
class ProtectGuard {
public:
    ProtectGuard(void* addr, size_t size, DWORD newProt)
        : m_addr(addr), m_size(size), m_applied(false), m_oldProt(0) {
        if (VirtualProtect(m_addr, m_size, newProt, &m_oldProt)) {
            m_applied = true;
        }
    }
    ~ProtectGuard() {
        if (m_applied) {
            DWORD tmp;
            VirtualProtect(m_addr, m_size, m_oldProt, &tmp);
        }
    }
private:
    void* m_addr;
    size_t m_size;
    bool   m_applied;
    DWORD  m_oldProt;
};

// 取 game.dll 基址
static HMODULE GetGameModule() {
    HMODULE h = GetModuleHandleA("game.dll");
    if (!h) h = GetModuleHandleA("Game.dll"); // 兼容大小写/不同发行包
    return h;
}

// （可选）做一点点“哨兵校验”，避免误写：检查第 0、1、2、3 项的结构形态
static bool LightProbeValidate(uintptr_t tableBase) {
    // 只验证“看起来像结构”的形态：第0字段是float；+8的DWORD经常是0或1；步长一致。
    // 放松校验，避免不同版本结构细节不一导致误判。
    for (size_t i = 0; i < 4; ++i) {
        uintptr_t e = tableBase + i * kStride;
        float     f = *reinterpret_cast<float*>(e);
        // 合理值域：0.25 ~ 4.0，避免 NaN/inf/乱指针
        if (!(f > 0.0f && f < 10.0f)) return false;

        // +8 的 dword 很多版本是标志位（0/1 都可能），不强校验，仅确认可读
        volatile uint32_t probe = *reinterpret_cast<uint32_t*>(e + 8);
        (void)probe;
    }
    return true;
}

bool InstallPathCapUnlock(float newValue) {
    if (g_installed.load(std::memory_order_acquire))
        return true;

    HMODULE hGame = GetGameModule();
    if (!hGame) {
        Logger::GetInstance().LogError("[PathCap] 未找到 game.dll 模块");
        return false;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(hGame);
    uintptr_t table = base + kPathTableRva;

    // 基础“能读”检查
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(table), &mbi, sizeof(mbi))) {
        Logger::GetInstance().LogError("[PathCap] VirtualQuery 失败");
        return false;
    }
    if (!(mbi.State == MEM_COMMIT)) {
        Logger::GetInstance().LogError("[PathCap] 目标页不是 MEM_COMMIT");
        return false;
    }

    // 轻量校验形态，最大限度避免误写
    if (!LightProbeValidate(table)) {
        Logger::GetInstance().LogWarning("[PathCap] 轻量校验未通过，可能是不同版本/偏移变化；已放弃写入（建议改用签名扫描）");
        return false;
    }

    // 备份 + 写入
    size_t totalBytes = kStride * kEntryCount;
    ProtectGuard guard(reinterpret_cast<void*>(table), totalBytes, PAGE_READWRITE);

    float* p0 = reinterpret_cast<float*>(table);
    for (size_t i = 0; i < kEntryCount; ++i) {
        uintptr_t e = table + i * kStride;
        float* fp = reinterpret_cast<float*>(e); // 首字段 float
        g_backup[i] = *fp;
        *fp = newValue;
    }

    g_tableAddr = table;
    g_installed.store(true, std::memory_order_release);

    Logger::GetInstance().LogInfo("[PathCap] 写入完成: table=%p, count=%zu, stride=0x%zX, value=%.3f",
        reinterpret_cast<void*>(g_tableAddr), kEntryCount, kStride, newValue);

    // 读回几项做日志确认
    float f0 = *reinterpret_cast<float*>(g_tableAddr + 0 * kStride);
    float f1 = *reinterpret_cast<float*>(g_tableAddr + 1 * kStride);
    Logger::GetInstance().LogInfo("[PathCap] 验证: entry0=%.3f, entry1=%.3f", f0, f1);
    return true;
}

void UninstallPathCapUnlock() {
    if (!g_installed.load(std::memory_order_acquire) || g_tableAddr == 0)
        return;

    size_t totalBytes = kStride * kEntryCount;
    ProtectGuard guard(reinterpret_cast<void*>(g_tableAddr), totalBytes, PAGE_READWRITE);

    for (size_t i = 0; i < kEntryCount; ++i) {
        uintptr_t e = g_tableAddr + i * kStride;
        float* fp = reinterpret_cast<float*>(e);
        *fp = g_backup[i];
    }

    Logger::GetInstance().LogInfo("[PathCap] 已还原寻路容量表");
    g_tableAddr = 0;
    g_installed.store(false, std::memory_order_release);
}
