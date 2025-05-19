#include "pch.h"
#include "AIL.h"
// 全局变量定义
AIL_open_stream_sample_handle_t AIL_open_stream_sample_handle = nullptr;
AIL_close_stream_t AIL_close_stream = nullptr;
AIL_release_sample_handle_t AIL_release_sample_handle = nullptr;
AIL_stream_status_t AIL_stream_status = nullptr;
AIL_set_stream_loop_count_t AIL_set_stream_loop_count = nullptr;

// 原始函数指针
PlayThematicMusic_t oPlayThematicMusic = nullptr;
PlayThematicMusicEx_t oPlayThematicMusicEx = nullptr;
EndThematicMusic_t oEndThematicMusic = nullptr;
SetThematicMusicPlayPosition_t oSetThematicMusicPlayPosition = nullptr;

// 当前音频流与样本句柄
HSTREAM gCurrentStream = nullptr;
HSAMPLE gCurrentSample = nullptr;