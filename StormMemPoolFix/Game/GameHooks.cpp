#include "pch.h"
#include "GameHooks.h"

#include <Base/Logger.h>
#include <detours.h>
#include <atomic>
#include <float.h>
#include <unknwn.h> // IUnknown

// 来自 IDA 的信息：
// int __fastcall sub_6F0EC530(HMODULE *a1, IDirect3D9 **a2)
// 主要逻辑：
//   *a1 = 0;
//   *a2 = 0;
//   HMODULE h = LoadLibraryA("d3d9.dll");
//   *a1 = h;
//   if (h && Direct3DCreate9 && 创建成功) {
//       sub_6F155290(); // clearfp + control87(0x9001F, 0xFFFFF)
//       return 1;
//   } else {
//       sub_6F0EC7D0(a1, a2); // 释放 *a2->Release + FreeLibrary(*a1)
//       sub_6F155290();
//       return 0;
//   }

namespace {
    // Game.dll 基址 + 0x0EC530 = sub_6F0EC530
    constexpr uintptr_t kGameD3DInitRva = 0x00EC530;

    // SDK 版本（原始代码中直接使用 32）
    constexpr UINT kD3DSdkVersion = 32u;

    using Game_CreateD3D_t = int(__fastcall*)(HMODULE* a1, IDirect3D9** a2);
    using Direct3DCreate9Ex_t = HRESULT(WINAPI*)(UINT, void**);

    Game_CreateD3D_t g_origGameCreateD3D = nullptr;
    std::atomic<bool> g_d3dHookInstalled{ false };

    // 模拟 sub_6F155290：清理浮点异常并设置控制字（使用安全版本）
    void SetFloatControlWord() {
        _clearfp();
        unsigned int current = 0;
        _controlfp_s(&current, 0x9001F, 0xFFFFF);
    }

    // 模拟 sub_6F0EC7D0：释放设备并卸载 d3d9.dll
    void CleanupD3D(HMODULE* phModule, IDirect3D9** ppD3D) {
        if (ppD3D && *ppD3D) {
            IUnknown* unk = reinterpret_cast<IUnknown*>(*ppD3D);
            unk->Release();
            *ppD3D = nullptr;
        }

        if (phModule && *phModule) {
            FreeLibrary(*phModule);
            *phModule = nullptr;
        }
    }

    int __fastcall Hooked_Game_CreateD3D(HMODULE* a1, IDirect3D9** a2) {
        Logger::GetInstance().LogInfo("[GameHooks] sub_6F0EC530 被调用，尝试使用 Direct3DCreate9Ex...");

        if (!a1 || !a2) {
            Logger::GetInstance().LogWarning("[GameHooks] 参数为空，直接转发到原始函数");
            return g_origGameCreateD3D ? g_origGameCreateD3D(a1, a2) : 0;
        }

        *a1 = nullptr;
        *a2 = nullptr;

        HMODULE hD3D9 = LoadLibraryA("d3d9.dll");
        *a1 = hD3D9;

        if (hD3D9) {
            auto pCreateEx = reinterpret_cast<Direct3DCreate9Ex_t>(
                GetProcAddress(hD3D9, "Direct3DCreate9Ex"));

            if (pCreateEx) {
                void* pD3DEx = nullptr;
                HRESULT hr = pCreateEx(kD3DSdkVersion, &pD3DEx);

                if (SUCCEEDED(hr) && pD3DEx) {
                    *a2 = reinterpret_cast<IDirect3D9*>(pD3DEx);

                    Logger::GetInstance().LogInfo(
                        "[GameHooks] Direct3DCreate9Ex 成功，已返回 IDirect3D9Ex 实例（向下转型为 IDirect3D9*）");

                    SetFloatControlWord();
                    return 1;
                }
                else {
                    Logger::GetInstance().LogWarning(
                        "[GameHooks] Direct3DCreate9Ex 失败，hr=0x%08X，回退到原始实现", hr);

                    if (pD3DEx) {
                        IUnknown* unk = reinterpret_cast<IUnknown*>(pD3DEx);
                        unk->Release();
                    }

                    CleanupD3D(a1, a2);
                }
            }
            else {
                Logger::GetInstance().LogInfo(
                    "[GameHooks] 未找到 Direct3DCreate9Ex，回退到原始实现");
            }
        }
        else {
            Logger::GetInstance().LogError(
                "[GameHooks] LoadLibraryA(\"d3d9.dll\") 失败，错误码=%lu，回退到原始实现", GetLastError());
        }

        // 走到这里说明 Ex 路径不可用或失败，回退到 Game.dll 原始实现
        if (g_origGameCreateD3D) {
            Logger::GetInstance().LogInfo("[GameHooks] 调用原始 sub_6F0EC530");
            return g_origGameCreateD3D(a1, a2);
        }

        // 理论上不会走到这里（DetourAttach 成功后 g_origGameCreateD3D 一定非空）
        Logger::GetInstance().LogError("[GameHooks] g_origGameCreateD3D 为空，只能模拟失败路径");
        CleanupD3D(a1, a2);
        SetFloatControlWord();
        return 0;
    }
} // namespace

namespace GameHooks {

bool Install(HMODULE hGame) {
    if (g_d3dHookInstalled.load(std::memory_order_acquire)) {
        return true;
    }

    if (!hGame) {
        Logger::GetInstance().LogWarning("[GameHooks] Install 调用时未找到 Game.dll 模块");
        return false;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(hGame);
    auto target = reinterpret_cast<Game_CreateD3D_t>(base + kGameD3DInitRva);

    g_origGameCreateD3D = target;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&reinterpret_cast<PVOID&>(g_origGameCreateD3D), Hooked_Game_CreateD3D);

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        Logger::GetInstance().LogError("[GameHooks] 安装 D3D9Ex Hook 失败，Detours 返回: %ld", result);
        g_origGameCreateD3D = nullptr;
        return false;
    }

    g_d3dHookInstalled.store(true, std::memory_order_release);
    Logger::GetInstance().LogInfo("[GameHooks] 已在 Game.dll+0x%X 安装 D3D9Ex Hook",
        static_cast<unsigned>(kGameD3DInitRva));

    return true;
}

void Uninstall() {
    if (!g_d3dHookInstalled.load(std::memory_order_acquire)) {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_origGameCreateD3D) {
        DetourDetach(&reinterpret_cast<PVOID&>(g_origGameCreateD3D), Hooked_Game_CreateD3D);
    }

    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        Logger::GetInstance().LogWarning("[GameHooks] 卸载 D3D9Ex Hook 失败，Detours 返回: %ld", result);
    }
    else {
        Logger::GetInstance().LogInfo("[GameHooks] D3D9Ex Hook 已卸载");
    }

    g_origGameCreateD3D = nullptr;
    g_d3dHookInstalled.store(false, std::memory_order_release);
}

} // namespace GameHooks
