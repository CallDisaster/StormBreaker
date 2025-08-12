#pragma once
#include "pch.h"
#include <cstdint>

// 写入/还原寻路容量（单位寻路上限“解锁”）
bool InstallPathCapUnlock(float newValue = 2.0f); // 默认 2.0
void UninstallPathCapUnlock();
