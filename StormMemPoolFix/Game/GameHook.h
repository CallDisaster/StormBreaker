#pragma once
#include "pch.h"
#include <Windows.h>
#include "GameDllReverse/AIL.h"

// Miles Sound System 函数在War3中的地址（移到GameHook.cpp中初始化）
#define AIL_OPEN_STREAM_ADDR              (gGameDllBase + 0x11CA)
#define AIL_CLOSE_STREAM_ADDR             (gGameDllBase + 0x11D0)
#define AIL_ALLOCATE_SAMPLE_HANDLE_ADDR   (gGameDllBase + 0x111C)
#define AIL_RELEASE_SAMPLE_HANDLE_ADDR    (gGameDllBase + 0x1122)
#define AIL_STREAM_STATUS_ADDR            (gGameDllBase + 0x11FA)
#define AIL_SET_STREAM_LOOP_COUNT_ADDR    (gGameDllBase + 0x11F4)

// 游戏内相关函数的地址 - 确保在初始化时使用gGameDllBase
#define PLAY_THEMATIC_MUSIC_ADDR              (gGameDllBase + 0x1F1E30)
#define PLAY_THEMATIC_MUSIC_EX_ADDR           (gGameDllBase + 0x1F1E50)
#define END_THEMATIC_MUSIC_ADDR               (gGameDllBase + 0x1E0130)
#define SET_THEMATIC_MUSIC_PLAY_POSITION_ADDR (gGameDllBase + 0x1F7050)

// Hook函数声明
int __fastcall hkPlayThematicMusic(void* thisptr, void* edx, const char* file);
int __fastcall hkPlayThematicMusicEx(void* thisptr, void* edx, const char* file, int32_t frommsecs);
void __fastcall hkEndThematicMusic(void* thisptr, void* edx);
int __fastcall hkSetThematicMusicPlayPosition(void* thisptr, void* edx, int32_t millisecs);

// 初始化与清理
bool InitializeGameHook();
void ShutdownGameHook();