// Hooks.h
#pragma once
#include "Core.h" // 需要 Core 里的东西
#include <vector>
#include <utility>
#include <cstdint>

// --- Typedefs for hooked functions ---
typedef HRESULT(WINAPI* EndScene_t)(IDirect3DDevice9* pDevice);
// 为 RenderUI 定义函数指针类型 (根据你的偏移列表猜测参数)
typedef void(__fastcall* RenderUI_t)(void* pGameUI, int unknown);
// ... 其他你需要 Hook 的函数的 Typedef ...

// --- Original function pointers ---
extern EndScene_t oEndScene;
extern RenderUI_t oRenderUI;
// ... 其他原始函数指针 ...

// --- Hook 安装与卸载 ---
namespace Hooks {
    bool Initialize(); // 初始化 Hook 库 (Detours/MinHook)
    void Shutdown();   // 关闭 Hook 库

    // 安装初始的 Hook (例如 RenderUI, 用于获取设备指针)
    bool InstallInitialHooks();

    // 安装 EndScene Hook (在获取到设备指针后调用)
    bool InstallEndSceneHook();

    // 安装其他你需要的游戏逻辑 Hook
    bool InstallGameHooks(const std::vector<std::pair<uintptr_t*, uintptr_t>>& hooks); // 示例：传入地址对进行安装
}

// --- Proxy function declarations ---
HRESULT WINAPI Hooked_EndScene(IDirect3DDevice9* pDevice);
void __fastcall Hooked_RenderUI(void* pGameUI, int unknown);
// ... 其他 Hook 代理函数的声明 ...