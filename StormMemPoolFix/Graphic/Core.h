// Core.h
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>     
#include <d3dx9.h>    // 仍然需要 D3DX9 (为了字体)
#include <cstdint>    
#include <string>

// --- 全局变量 ---
extern HMODULE g_hSelf;
extern uintptr_t g_GameBase;
extern IDirect3DDevice9* g_pD3DDevice;
extern uintptr_t g_absGxDeviceAddress;
extern ID3DXFont* g_pDebugFont;        // 字体指针保留

// --- 基础功能函数 ---
bool Core_Init(HMODULE hModule);       // 初始化核心 (获取地址)
void Core_Shutdown();                  // 清理核心 (释放字体)
bool Core_GrabDevicePointer();         // 尝试获取设备指针
bool Core_CreateDebugFont();           // 创建 D3DX 字体
// !! 移除控制台函数 !!
// void Core_SetupConsole();           
// void Core_CleanupConsole();
void LogInfo(const char* format, ...); // 日志函数 (使用 OutputDebugStringA)
void LogError(const char* format, ...);
void LogWarning(const char* format, ...);
// !! 移除 ws2s，因为 Log 函数使用 char*，MessageBoxW 使用 WCHAR* !!
// std::string ws2s(const std::wstring& wstr); 

// 简单的消息提示 (可选，可保留或移除)
void ShowMessage(const std::wstring& msg, bool isError);