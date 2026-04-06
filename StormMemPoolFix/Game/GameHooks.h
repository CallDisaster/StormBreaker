#pragma once

#include "pch.h"

// 前向声明，避免直接依赖 d3d9 头文件
struct IDirect3D9;

// Warcraft III Game.dll 相关 Hook
namespace GameHooks {
    // 安装 Game.dll 内部与 D3D9 初始化相关的 Hook
    // hGame: Game.dll 模块句柄（GetModuleHandleA("Game.dll")）
    bool Install(HMODULE hGame);

    // 卸载所有在 Game.dll 上安装的 Hook
    void Uninstall();
}

