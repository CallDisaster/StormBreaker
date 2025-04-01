// GameOffsets.cpp
#include "pch.h"
#include "GameOffsets.h"
#include "Core.h" // 需要 Core.h 来访问 g_GameBase

// --- 全局地址变量定义 ---
// 在这里定义变量，它们将在链接时分配内存

uintptr_t address_GameBase = 0;

// Input/Window
uintptr_t address_MouseEvent = 0;
uintptr_t address_WndProc = 0;

// Misc/Network Delays
uintptr_t address_localDelay = 0;
uintptr_t address_lanDelay = 0;
uintptr_t address_netDelay = 0;

// Rendering/Matrix
uintptr_t address_MatrixPerspectiveFov = 0;
uintptr_t address_MatrixLookAt = 0;
uintptr_t address_RenderWorldObjects = 0;
uintptr_t address_RenderTranslucent = 0;
uintptr_t address_RenderOpaque = 0;
uintptr_t address_RenderWorld = 0;
uintptr_t address_RenderCineFilter = 0;
uintptr_t address_RenderUI = 0;
uintptr_t address_BuildHPBars = 0;
uintptr_t address_BuildMainMenu = 0;
uintptr_t address_InitSceneView = 0;

// UI Frames
uintptr_t address_GetGameUI = 0;
uintptr_t address_SetFramePoint = 0;
uintptr_t address_SetFramePoint2 = 0;
uintptr_t address_SetFrameWidth = 0;
uintptr_t address_SetFrameHeight = 0;
uintptr_t address_SetFrameText = 0;

// Game Data Access
uintptr_t address_GetTerrain = 0;
uintptr_t address_gxDevice = 0; // !! 关键偏移量 !!
uintptr_t address_dwSceneSettings1 = 0;
uintptr_t address_MiscDataGetColor = 0;

// JASS Natives
uintptr_t address_InitJassNatives = 0;
uintptr_t address_BindJassNative = 0;

// Fog of War
uintptr_t address_ApplyFogOfWarEx = 0;

// 其他
// uintptr_t address_LockFPS = 0;
// ...

// --- 初始化函数实现 ---
void InitGameOffsets(uint32_t gameBuildVersion)
{
	// 确保 g_GameBase 已经被 Core_Init 设置
	if (g_GameBase == 0) {
		LogError("InitGameOffsets called before g_GameBase was set!");
		// 可以在这里尝试获取，或者直接返回错误
		g_GameBase = (uintptr_t)GetModuleHandleW(L"Game.dll");
		if (g_GameBase == 0) return; // 获取失败则无法继续
	}

	LogInfo("Initializing game offsets for build version: %u", gameBuildVersion);

	// --- 根据版本号填充地址 ---
	if (gameBuildVersion == GAME_BUILD_127A) // 52240
	{
		LogInfo("Detected Game Build 1.27a (52240). Applying offsets...");

		// 使用你找到的 1.27a 偏移量 (基于 Game.dll 基址)
		address_MouseEvent = g_GameBase + 0x364C40;
		address_WndProc = g_GameBase + 0x0EC940;

		address_localDelay = g_GameBase + 0x845EE1;
		address_lanDelay = g_GameBase + 0x84AE21;
		address_netDelay = g_GameBase + 0x8476B1;

		address_MatrixPerspectiveFov = g_GameBase + 0x0D31D0; // 确认使用这个
		address_MatrixLookAt = g_GameBase + 0x0D2AD0;
		address_RenderWorldObjects = g_GameBase + 0x395620;
		address_RenderTranslucent = g_GameBase + 0x50B3A0;
		address_RenderOpaque = g_GameBase + 0x50B1A0;
		address_RenderWorld = g_GameBase + 0x395900;
		address_RenderCineFilter = g_GameBase + 0x3ACCF0;
		address_RenderUI = g_GameBase + 0x0B7C90; // !! 用于初始 Hook !!
		address_BuildHPBars = g_GameBase + 0x379A30;
		address_BuildMainMenu = g_GameBase + 0x2BE270;
		address_InitSceneView = g_GameBase + 0x190210;

		address_GetGameUI = g_GameBase + 0x34F3A0;
		address_SetFramePoint = g_GameBase + 0x0BD8A0;
		address_SetFramePoint2 = g_GameBase + 0x0B0830;
		address_SetFrameWidth = g_GameBase + 0x0BD960;
		address_SetFrameHeight = g_GameBase + 0x0BD7C0;
		address_SetFrameText = g_GameBase + 0x0AA130;

		address_GetTerrain = g_GameBase + 0x771060;
		address_gxDevice = g_GameBase + 0xBE4238; // !! 核心: 指向设备指针的地址 !!
		address_InitJassNatives = g_GameBase + 0x1E9A50;
		address_BindJassNative = g_GameBase + 0x7E3710;

		address_ApplyFogOfWarEx = g_GameBase + 0x71F040;
		address_dwSceneSettings1 = g_GameBase + 0xB66D58;
		address_MiscDataGetColor = g_GameBase + 0x701D50;

		LogInfo("Offsets for 1.27a applied.");
	}
	else
	{
		LogError("Unsupported game build version: %u", gameBuildVersion);
		// 可以选择抛出异常或设置所有地址为 0
	}
}