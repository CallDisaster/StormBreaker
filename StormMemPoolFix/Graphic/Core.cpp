// Core.cpp
#include "pch.h"
#include "Core.h"
#include <cstdio>   // ��Ҫ vsnprintf
#include <cstdarg>  // ��Ҫ va_list
#include <iostream>
#include "GameOffsets.h"

// --- ȫ�ֱ������� ---
HMODULE g_hSelf = nullptr;
uintptr_t g_GameBase = 0;
IDirect3DDevice9* g_pD3DDevice = nullptr;
uintptr_t g_absGxDeviceAddress = 0;
ID3DXFont* g_pDebugFont = nullptr;

// !! �Ƴ�����̨��ص� FILE* ָ�� !!

// --- ������������ȫ�ͷ� COM ���� ---
template<typename T>
void SafeRelease(T*& pInterface) {
    if (pInterface) {
        pInterface->Release();
        pInterface = nullptr;
    }
}

// --- ��־����ʵ�� (ʹ�� OutputDebugStringA) ---
#define LOG_HELPER_DBGVIEW(levelPrefix, format) \
    char buffer[2048]; \
    char logBuffer[2100]; \
    va_list args; \
    va_start(args, format); \
    vsnprintf(buffer, sizeof(buffer), format, args); \
    va_end(args); \
    buffer[sizeof(buffer) - 1] = '\0'; \
    sprintf_s(logBuffer, sizeof(logBuffer), "[ASI Plugin]%s %s\n", levelPrefix, buffer); \
    OutputDebugStringA(logBuffer);

void LogInfo(const char* format, ...) { LOG_HELPER_DBGVIEW("[INFO]", format); }
void LogError(const char* format, ...) { LOG_HELPER_DBGVIEW("[ERROR]", format); }
void LogWarning(const char* format, ...) { LOG_HELPER_DBGVIEW("[WARN]", format); }

// --- �򵥵���Ϣ��ʾ (��ѡ) ---
void ShowMessage(const std::wstring& msg, bool isError = true) {
    // ����ѡ��ֻ��¼��־��������Ȼ��ʾ MessageBox
    if (isError) LogError("MsgBox: %S", msg.c_str());
    else LogInfo("MsgBox: %S", msg.c_str());
    MessageBoxW(nullptr, msg.c_str(), L"ASI Plugin",
        MB_OK | (isError ? MB_ICONERROR : MB_ICONINFORMATION) | MB_TOPMOST);
}

// --- ���ĳ�ʼ�� ---
bool Core_Init(HMODULE hModule) {
    g_hSelf = hModule;
    std::cout << "Hello World!" << std::endl;
    g_GameBase = (uintptr_t)GetModuleHandleW(L"Game.dll");
    if (g_GameBase == 0) {
        LogError("Failed to get Game.dll base address!");
        // ShowMessage(L"Failed to get Game.dll base address!", true); // ��ѡ����Ϣ��
        return false;
    }
    LogInfo("Game.dll base address: 0x%p", (void*)g_GameBase);
    std::cout << "Game.dll base address: 0x%p" << (void*)g_GameBase << std::endl;

    g_pD3DDevice = nullptr;
    g_pDebugFont = nullptr;

    LogInfo("Core initialized (logging via OutputDebugString).");
    return true;
}

// --- �������� ---
void Core_Shutdown() {
    LogInfo("Core Shutting down...");
    SafeRelease(g_pDebugFont); // ʹ�� SafeRelease
    // !! �Ƴ� Core_CleanupConsole() !!
}

// --- �豸��ȡ�����崴�� (���ֲ���) ---
bool Core_GrabDevicePointer() {
    if (g_pD3DDevice) { return true; }
    if (g_absGxDeviceAddress == 0) { LogError("gxDevice absolute address is not set!"); return false; }

    try {
        IDirect3DDevice9** ppDevice = (IDirect3DDevice9**)g_absGxDeviceAddress;
        if (!IsBadReadPtr(ppDevice, sizeof(IDirect3DDevice9*))) {
            g_pD3DDevice = *ppDevice;
            if (g_pD3DDevice && !IsBadReadPtr(g_pD3DDevice, sizeof(void*))) {
                void** pVTable = *(void***)g_pD3DDevice;
                if (!IsBadReadPtr(pVTable, sizeof(void*) * 43)) {
                    LogInfo("Successfully obtained D3D9 Device pointer: 0x%p via gxDevice offset.", g_pD3DDevice);
                    return true;
                }
                else { /* LogError VTable invalid */ g_pD3DDevice = nullptr; return false; }
            }
            else { /* LogWarning Pointer NULL or invalid */ g_pD3DDevice = nullptr; return false; }
        }
        else { /* LogError Failed to read memory */ return false; }
    }
    catch (...) { /* LogError Exception */ g_pD3DDevice = nullptr; return false; }
}

bool Core_CreateDebugFont() {
    if (!g_pD3DDevice) { LogError("Cannot create debug font: D3D Device is NULL."); return false; }
    if (g_pDebugFont) { return true; }

    LogInfo("Creating debug font (Arial 18pt Bold)...");
    D3DXFONT_DESCW fontDesc = {};
    fontDesc.Height = 18;
    fontDesc.Weight = FW_BOLD;
    fontDesc.MipLevels = 1;
    fontDesc.CharSet = DEFAULT_CHARSET;
    fontDesc.Quality = ANTIALIASED_QUALITY;
    wcscpy_s(fontDesc.FaceName, L"Arial");

    HRESULT hr = D3DXCreateFontIndirectW(g_pD3DDevice, &fontDesc, &g_pDebugFont);
    if (FAILED(hr)) {
        LogError("D3DXCreateFontIndirectW failed! HRESULT: 0x%X", hr);
        g_pDebugFont = nullptr;
        return false;
    }
    LogInfo("Debug font created successfully.");
    return true;
}