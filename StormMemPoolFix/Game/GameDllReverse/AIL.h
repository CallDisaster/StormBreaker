#pragma once
#include "pch.h"
#include <Windows.h>

// 确保只定义一次
extern uintptr_t gGameDllBase;

// Miles Sound System 类型定义
typedef void* HSTREAM;
typedef void* HSAMPLE;
typedef void* HDIGDRIVER;

// Miles Sound System 函数指针类型
typedef HSTREAM(*AIL_open_stream_sample_handle_t)(HSAMPLE S);
typedef void (*AIL_close_stream_t)(HSTREAM stream);
typedef void (*AIL_release_sample_handle_t)(HSAMPLE S);
typedef int (*AIL_stream_status_t)(HSTREAM stream);
typedef HSAMPLE(*AIL_allocate_sample_handle_t)(HDIGDRIVER dig);
typedef void (*AIL_set_stream_loop_count_t)(HSTREAM stream, int32_t count);

// 游戏内相关函数的函数指针类型
typedef int(__fastcall* PlayThematicMusic_t)(void* thisptr, void* edx, const char* file);
typedef int(__fastcall* PlayThematicMusicEx_t)(void* thisptr, void* edx, const char* file, int32_t frommsecs);
typedef void(__fastcall* EndThematicMusic_t)(void* thisptr, void* edx);
typedef int(__fastcall* SetThematicMusicPlayPosition_t)(void* thisptr, void* edx, int32_t millisecs);

// 全局变量声明
extern AIL_open_stream_sample_handle_t AIL_open_stream_sample_handle;
extern AIL_close_stream_t AIL_close_stream;
extern AIL_release_sample_handle_t AIL_release_sample_handle;
extern AIL_stream_status_t AIL_stream_status;
extern AIL_set_stream_loop_count_t AIL_set_stream_loop_count;

// 原始函数指针
extern PlayThematicMusic_t oPlayThematicMusic;
extern PlayThematicMusicEx_t oPlayThematicMusicEx;
extern EndThematicMusic_t oEndThematicMusic;
extern SetThematicMusicPlayPosition_t oSetThematicMusicPlayPosition;

// 当前音频流与样本句柄
extern HSTREAM gCurrentStream;
extern HSAMPLE gCurrentSample;

// 音频状态相关常量
#define SMP_DONE      1   // Sample/stream 已播放结束
#define SMP_PLAYING   2   // Sample/stream 正在播放
#define SMP_STOPPED   3   // Sample/stream 已停止
#define SMP_PAUSED    4   // Sample/stream 已暂停

// 函数声明（前向声明）
HSAMPLE GetCurrentSampleFromManager(void* soundManager);
void CleanupCurrentAudioStream();