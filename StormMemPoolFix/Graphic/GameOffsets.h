// GameOffsets.h
#pragma once
#include "pch.h"
#include <cstdint>

// 游戏版本号
constexpr uint32_t GAME_BUILD_127A = 52240;	//1.27a

// --- 全局地址变量声明 (使用 extern) ---
// 让其他文件可以通过包含此头文件来访问这些地址

extern uintptr_t address_GameBase; // Game.dll 基地址

// Input/Window
extern uintptr_t address_MouseEvent;
extern uintptr_t address_WndProc;

// Misc/Network Delays
extern uintptr_t address_localDelay;
extern uintptr_t address_lanDelay;
extern uintptr_t address_netDelay;

// Rendering/Matrix
extern uintptr_t address_MatrixPerspectiveFov;
extern uintptr_t address_MatrixLookAt;
extern uintptr_t address_RenderWorldObjects;
extern uintptr_t address_RenderTranslucent;
extern uintptr_t address_RenderOpaque;
extern uintptr_t address_RenderWorld;
extern uintptr_t address_RenderCineFilter;
extern uintptr_t address_RenderUI;
extern uintptr_t address_InitSceneView;

// UI Frames
extern uintptr_t address_BuildHPBars;
extern uintptr_t address_BuildMainMenu;
extern uintptr_t address_GetGameUI;
extern uintptr_t address_SetFramePoint;
extern uintptr_t address_SetFramePoint2;
extern uintptr_t address_SetFrameWidth;
extern uintptr_t address_SetFrameHeight;
extern uintptr_t address_SetFrameText;

// Game Data Access
extern uintptr_t address_GetTerrain;
extern uintptr_t address_gxDevice; // !! 指向设备指针的全局变量地址 !!
extern uintptr_t address_dwSceneSettings1; // 场景设置
extern uintptr_t address_MiscDataGetColor; // 获取颜色

// JASS Natives
extern uintptr_t address_InitJassNatives;
extern uintptr_t address_BindJassNative;

// Fog of War
extern uintptr_t address_ApplyFogOfWarEx;

// 其他未找到或未使用的
// extern uintptr_t address_LockFPS;
// extern uintptr_t address_LockTextureSizeCmp;
// extern uintptr_t address_LockTextureSizeMov;


// --- 初始化函数声明 ---
// 根据传入的游戏版本号，填充上面的地址变量
// 需要在 GameOffsets.cpp 中实现
void InitGameOffsets(uint32_t gameBuildVersion);