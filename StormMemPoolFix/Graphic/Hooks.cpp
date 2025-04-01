// Hooks.cpp (使用 Detours 重写)
#include "pch.h" 
#include "Hooks.h"
#include <windows.h>
#include <detours.h>      // 包含 Detours 头文件
#include "GameOffsets.h"   

// --- Original function pointers definition ---
// Detours 要求原始函数指针在 Attach 时被赋值
EndScene_t oEndScene = nullptr;
RenderUI_t oRenderUI = nullptr;
// ... 其他原始函数指针定义 ...

// --- Hook 安装与卸载 实现 (使用 Detours) ---
namespace Hooks {

    bool Initialize() {
        LogInfo("Initializing Detours Hook library...");
        // Detours 通常不需要全局初始化函数，初始化通过事务完成
        return true;
    }

    void Shutdown() {
        LogInfo("Shutting down Detours Hook library...");
        // 在 DLL_PROCESS_DETACH 中进行卸载事务
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        LogInfo("Detaching hooks...");
        // 卸载所有已安装的 Hook
        //if (oEndScene) DetourDetach(&(PVOID&)oEndScene, Hooked_EndScene);
        //if (oRenderUI) DetourDetach(&(PVOID&)oRenderUI, Hooked_RenderUI);
        // ... 卸载其他 Hook ...

        if (DetourTransactionCommit() == NO_ERROR) {
            LogInfo("Hooks successfully detached.");
        }
        else {
            LogError("Failed to commit detour transaction for detaching hooks.");
        }
    }

    bool InstallInitialHooks() {
        LogInfo("Installing initial hooks (RenderUI) using Detours...");
        if (!address_RenderUI) { LogError("InstallInitialHooks failed: address_RenderUI is not set!"); return false; }

        // oRenderUI 必须在 Attach 之前指向原始函数地址
        oRenderUI = (RenderUI_t)address_RenderUI;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        LogInfo("开始HookRenderUI");
        // 附加 Hook
        //LONG error = DetourAttach(&(PVOID&)oRenderUI, Hooked_RenderUI);
        //if (error != NO_ERROR) {
        //    LogError("DetourAttach failed for RenderUI (0x%p), Error: %ld", (void*)address_RenderUI, error);
        //    DetourTransactionAbort();
        //    return false;
        //}

        //// 提交事务
        //if (DetourTransactionCommit() != NO_ERROR) {
        //    LogError("Failed to commit detour transaction for RenderUI hook.");
        //    // 尝试回滚 Detach (虽然可能意义不大)
        //    DetourTransactionBegin();
        //    DetourUpdateThread(GetCurrentThread());
        //    DetourDetach(&(PVOID&)oRenderUI, Hooked_RenderUI); // 尝试撤销
        //    DetourTransactionCommit();
        //    oRenderUI = nullptr; // 重置指针
        //    return false;
        //}

        LogInfo("Hook for RenderUI (0x%p) installed via Detours.", (void*)address_RenderUI);
        return true;
    }

    bool InstallEndSceneHook() {
        if (!g_pD3DDevice) { LogError("Cannot install EndScene hook: D3D Device is NULL!"); return false; }
        static bool endSceneHooked = false;
        if (endSceneHooked) return true;

        LogInfo("Installing EndScene hook using Detours...");

        // 获取 EndScene 地址 (VTable index 42)
        void** pVTable = *(void***)g_pD3DDevice;
        if (IsBadReadPtr(pVTable, sizeof(void*) * 43)) { /* Log Error */ return false; }
        uintptr_t address_EndScene = (uintptr_t)pVTable[42];
        if (IsBadCodePtr((FARPROC)address_EndScene)) { /* Log Error */ return false; }

        // oEndScene 必须在 Attach 之前指向原始函数地址
        oEndScene = (EndScene_t)address_EndScene;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        LONG error = DetourAttach(&(PVOID&)oEndScene, Hooked_EndScene);
        if (error != NO_ERROR) {
            LogError("DetourAttach failed for EndScene (0x%p), Error: %ld", (void*)address_EndScene, error);
            DetourTransactionAbort();
            oEndScene = nullptr; // 重置指针
            return false;
        }

        if (DetourTransactionCommit() != NO_ERROR) {
            LogError("Failed to commit detour transaction for EndScene hook.");
            // 尝试回滚 Detach
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)oEndScene, Hooked_EndScene);
            DetourTransactionCommit();
            oEndScene = nullptr;
            return false;
        }

        LogInfo("Hook for EndScene (0x%p) installed via Detours.", (void*)address_EndScene);
        endSceneHooked = true;
        return true;
    }

} // namespace Hooks


// --- Proxy function implementations ---
// Hooked_RenderUI 和 Hooked_EndScene 的内部逻辑保持不变，因为它们不依赖 Hook 库本身

// RenderUI 的 Hook 函数
void __fastcall Hooked_RenderUI(void* pGameUI, int unknown) {
    static bool deviceReady = false;

    if (!deviceReady) {
        if (!g_pD3DDevice) {
            if (Core_GrabDevicePointer()) {
                if (Core_CreateDebugFont()) {
                    if (Hooks::InstallEndSceneHook()) { // 这里调用上面的 Detours 版本
                        deviceReady = true;
                        LogInfo("Device pointer obtained and dependent hooks installed.");
                    }
                    else { LogError("Failed to install EndScene hook after getting device."); }
                }
                else { LogError("Failed to create debug font after getting device."); }
            }
        }
        else {
            if (Core_CreateDebugFont() && Hooks::InstallEndSceneHook()) {
                deviceReady = true;
            }
        }
    }

    // !! 调用原始函数 (Detours 会修改 oRenderUI 指向一个 Trampoline) !!
    if (oRenderUI) {
        oRenderUI(pGameUI, unknown); // 直接调用 oRenderUI 即可调用原始函数
    }
    else { LogError("Original RenderUI function pointer is NULL or detour failed!"); }

    // 在这里绘制 ImGui 等 UI
    // ...
}

// EndScene 的 Hook 函数
HRESULT WINAPI Hooked_EndScene(IDirect3DDevice9* pDevice) {
    // 内部逻辑不变
    if (g_pD3DDevice && g_pDebugFont) {
        if (pDevice != g_pD3DDevice) { /* Log Warning */ }

        RECT textRect;
        D3DVIEWPORT9 viewport;
        g_pD3DDevice->GetViewport(&viewport);
        SetRect(&textRect, 10, 10, viewport.Width - 10, viewport.Height - 10);

        g_pDebugFont->DrawTextW(NULL, L"Hello World D3D9 ASI! (插件运行中)", -1, &textRect,
            DT_LEFT | DT_TOP | DT_NOCLIP, D3DCOLOR_ARGB(255, 0, 255, 0));

        // 其他渲染逻辑...
    }

    // 调用原始 EndScene
    if (oEndScene) {
        // 直接调用 oEndScene 即可调用原始函数
        return oEndScene(pDevice);
    }
    else {
        LogError("Original EndScene function pointer is NULL or detour failed!");
        return D3DERR_INVALIDCALL;
    }
}