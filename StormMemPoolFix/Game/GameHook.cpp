#include "pch.h"
#include "GameHook.h"
#include "detours.h"
#include <cstdio>

// 游戏DLL基址
uintptr_t gGameDllBase = 0;

// 工具函数: 从管理器对象获取当前样本句柄
HSAMPLE GetCurrentSampleFromManager(void* soundManager) {
    if (!soundManager) return nullptr;

    // 从CSoundManager对象中获取当前样本句柄
    // 根据反编译代码，样本句柄存储于偏移0x234处
    return *reinterpret_cast<HSAMPLE*>(
        reinterpret_cast<uintptr_t>(soundManager) + 0x234);
}

// 工具函数: 清理当前音频流
void CleanupCurrentAudioStream() {
    // 关闭当前流（如果存在）
    if (gCurrentStream) {
        AIL_close_stream(gCurrentStream);
        gCurrentStream = nullptr;
    }

    // 释放当前样本句柄（如果存在）
    if (gCurrentSample) {
        AIL_release_sample_handle(gCurrentSample);
        gCurrentSample = nullptr;
    }
}

// Hook函数: 播放主题音乐
int __fastcall hkPlayThematicMusic(void* thisptr, void* edx, const char* file) {
    // 清理现有的音频资源，防止内存泄漏
    CleanupCurrentAudioStream();

    // 调用原始函数播放新音乐
    int result = oPlayThematicMusic(thisptr, edx, file);

    // 记录新的样本句柄
    HSAMPLE newSample = GetCurrentSampleFromManager(thisptr);
    if (newSample) {
        gCurrentSample = newSample;
        gCurrentStream = AIL_open_stream_sample_handle(newSample);
    }

    return result;
}

// Hook函数: 带淡入的播放主题音乐
int __fastcall hkPlayThematicMusicEx(void* thisptr, void* edx, const char* file, int32_t frommsecs) {
    // 清理现有的音频资源，防止内存泄漏
    CleanupCurrentAudioStream();

    // 调用原始函数播放新音乐
    int result = oPlayThematicMusicEx(thisptr, edx, file, frommsecs);

    // 记录新的样本句柄
    HSAMPLE newSample = GetCurrentSampleFromManager(thisptr);
    if (newSample) {
        gCurrentSample = newSample;
        gCurrentStream = AIL_open_stream_sample_handle(newSample);
    }

    return result;
}

// Hook函数: 结束主题音乐
void __fastcall hkEndThematicMusic(void* thisptr, void* edx) {
    // 调用原始函数停止音乐
    oEndThematicMusic(thisptr, edx);

    // 确保资源被正确清理
    CleanupCurrentAudioStream();
}

// Hook函数: 设置主题音乐播放位置
int __fastcall hkSetThematicMusicPlayPosition(void* thisptr, void* edx, int32_t millisecs) {
    // 这个函数不需要特殊清理，仅调用原始函数即可
    return oSetThematicMusicPlayPosition(thisptr, edx, millisecs);
}

// 初始化游戏Hook
bool InitializeGameHook() {
    // 获取game.dll基址
    gGameDllBase = (uintptr_t)GetModuleHandleA("game.dll");
    if (!gGameDllBase) {
        return false;
    }

    // 初始化Miles Sound System函数指针
    AIL_open_stream_sample_handle = reinterpret_cast<AIL_open_stream_sample_handle_t>(AIL_OPEN_STREAM_ADDR);
    AIL_close_stream = reinterpret_cast<AIL_close_stream_t>(AIL_CLOSE_STREAM_ADDR);
    AIL_release_sample_handle = reinterpret_cast<AIL_release_sample_handle_t>(AIL_RELEASE_SAMPLE_HANDLE_ADDR);
    AIL_stream_status = reinterpret_cast<AIL_stream_status_t>(AIL_STREAM_STATUS_ADDR);
    AIL_set_stream_loop_count = reinterpret_cast<AIL_set_stream_loop_count_t>(AIL_SET_STREAM_LOOP_COUNT_ADDR);

    // 验证函数指针
    if (!AIL_open_stream_sample_handle || !AIL_close_stream || !AIL_release_sample_handle ||
        !AIL_stream_status || !AIL_set_stream_loop_count) {
        // 记录错误 - Miles Sound System函数指针无效
        return false;
    }

    // 使用Detours挂钩ThematicMusic相关函数
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 挂钩PlayThematicMusic
    oPlayThematicMusic = reinterpret_cast<PlayThematicMusic_t>(PLAY_THEMATIC_MUSIC_ADDR);
    DetourAttach(&(PVOID&)oPlayThematicMusic, hkPlayThematicMusic);

    // 挂钩PlayThematicMusicEx
    oPlayThematicMusicEx = reinterpret_cast<PlayThematicMusicEx_t>(PLAY_THEMATIC_MUSIC_EX_ADDR);
    DetourAttach(&(PVOID&)oPlayThematicMusicEx, hkPlayThematicMusicEx);

    // 挂钩EndThematicMusic
    oEndThematicMusic = reinterpret_cast<EndThematicMusic_t>(END_THEMATIC_MUSIC_ADDR);
    DetourAttach(&(PVOID&)oEndThematicMusic, hkEndThematicMusic);

    // 挂钩SetThematicMusicPlayPosition
    oSetThematicMusicPlayPosition = reinterpret_cast<SetThematicMusicPlayPosition_t>(SET_THEMATIC_MUSIC_PLAY_POSITION_ADDR);
    DetourAttach(&(PVOID&)oSetThematicMusicPlayPosition, hkSetThematicMusicPlayPosition);

    // 提交事务
    LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        // 记录错误 - Detours挂钩失败
        return false;
    }

    // 初始化成功
    return true;
}

// 清理游戏音频Hook
void ShutdownGameHook() {
    // 移除所有挂钩
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (oPlayThematicMusic)
        DetourDetach(&(PVOID&)oPlayThematicMusic, hkPlayThematicMusic);

    if (oPlayThematicMusicEx)
        DetourDetach(&(PVOID&)oPlayThematicMusicEx, hkPlayThematicMusicEx);

    if (oEndThematicMusic)
        DetourDetach(&(PVOID&)oEndThematicMusic, hkEndThematicMusic);

    if (oSetThematicMusicPlayPosition)
        DetourDetach(&(PVOID&)oSetThematicMusicPlayPosition, hkSetThematicMusicPlayPosition);

    DetourTransactionCommit();

    // 清理当前音频流
    CleanupCurrentAudioStream();
}