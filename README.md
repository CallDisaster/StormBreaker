# StormBreaker

StormBreaker 是一个面向 `Warcraft III 1.27a` 的 `Storm.dll` 内存兼容与优化插件。项目通过 Hook `SMemAlloc / SMemFree / SMemReAlloc / SMemGetSize` 等接口，将 `64 KiB` 以上的大块分配转移到 `TLSF` 内存池，同时保留 Storm 原生的小块分配路径，并在 `ResetMemoryManager` 和 `SMemHeapCleanupAll` 场景下提供兼容处理、日志与监控能力。

它的目标不是重写整个 Storm 内存系统，而是在尽量保持原有行为的前提下，降低旧版 Storm 内存统计持续增长带来的稳定性风险。

## 设计目标

- 保留 Storm 原生小块分配行为，避免直接重写内部堆结构。
- 仅拦截大块分配，减少对 `Storm_g_TotalAllocatedMemory` 的持续压力。
- 在释放、重分配和取大小等调用上保持兼容行为。
- 在 `ResetMemoryManager` 和 `SMemHeapCleanupAll` 场景下尽量安全退让。
- 提供日志、监控与基础内存安全检查能力，便于排查问题。

## About

如果你需要一条适合仓库首页、项目介绍或 GitHub About 的短文案，可以直接使用下面这版：

> 面向 Warcraft III 1.27a 的 Storm.dll 内存兼容与优化插件：通过 Hook 与 TLSF 接管大块分配路径，保留原生小块行为，并改善旧版 Storm 的内存边界稳定性。

## 当前实现

### 大块拦截策略

- 默认仅拦截 `>= 64 KiB` 的分配请求。
- 小于阈值的请求直接回退到原始 Storm 分配器。
- 大块请求进入 TLSF 内存池，默认配置如下：
  - 初始池大小：`64 MiB`
  - 扩展粒度：`16 MiB`
  - 最大池大小：`1 GiB`
  - 对齐：`16` 字节

### Storm 兼容层

当前兼容方案已经更新为“私有识别头 + Hook 兼容分流”，而不是早期的“伪造真实 Storm 堆头”方案。

- 每个托管块在用户指针前写入一个 `16` 字节的私有头：
  - `magic`
  - `requestedSize`
  - `sizeCookie`
  - `headerSize`
  - `rejectTag`
- `SMemFree` 和 `SMemReAlloc` 会先判断是否为 StormBreaker 托管块。
- `SMemGetSize` 对托管块直接返回记录的请求大小，对非托管块回退到原始 Storm 实现。
- 这种设计避免继续依赖真实 `StormHeap*` 指针，也降低了 Reset 后修复头部指针的复杂度。

### 安全期处理

- `SMemHeapCleanupAll` 与 `ResetMemoryManager` 被 Hook 后，会进入“不安全期”。
- 不安全期内，大块分配会回退到原始 Storm 分配路径。
- 进入 Reset 前会：
  - 通知 `MemorySafety` 进入不安全期
  - 刷新延迟释放队列
  - 尝试回收完全空闲的 TLSF 扩展池
- Reset 完成后再退出不安全期并恢复常规处理。

### 内存池与监控

- TLSF 支持扩展池注册和完全空闲池回收。
- `MemorySafety` 负责跟踪托管块、延迟释放、验证、泄漏检测与损坏检测。
- `MemoryMonitor` 会周期性输出：
  - 进程 `PrivateBytes / WorkingSet`
  - TLSF 使用情况
  - Storm 内部统计
  - StormBreaker 当前托管块数量和托管字节数

### 其他功能

- 初始化完成后会尝试安装寻路容量补丁 `PathCapUnlock`。
- 寻路容量写入失败不会阻止主内存系统继续工作。

## 代码结构

```text
Document/
  StormBreaker_Overview.md      设计背景与实现说明
  401(不包含报错函数).txt      Storm 分配路径分析资料
  Free(不含报错函数).txt       Storm 释放路径分析资料
  ReAlloc.txt                  Storm 重分配路径分析资料

StormMemPoolFix/
  dllmain.cpp                  DLL 入口、异步初始化、Hook 安装
  Storm/
    StormHook.cpp/.h           Storm Hook 与兼容分流
    MemoryPool.cpp/.h          TLSF 内存池封装
    StormOffsets.cpp/.h        Storm.dll 偏移与全局状态读取
    tlsf.c/.h                  TLSF 实现
  Base/
    Logger.cpp/.h              日志系统
    MemroySafety.cpp
    MemorySafety.h             内存跟踪、延迟释放、监控
  Game/
    PathCapUnlock.cpp/.h       寻路容量补丁
  Build/
    StormBreaker.asi           默认输出产物
```

## 构建说明

### 推荐方式

当前有效的主构建入口是 Visual Studio 工程：

- 工程文件：`StormMemPoolFix/StormMemPoolFix.vcxproj`
- 推荐配置：`Release | Win32`
- 输出文件：`StormMemPoolFix/Build/StormBreaker.asi`

如果使用解决方案文件：

- 解决方案文件：`StormBreaker.sln`
- 平台名使用 `x86`，它映射到工程内的 `Win32`

示例：

```powershell
msbuild StormMemPoolFix\StormMemPoolFix.vcxproj /t:Build /p:Configuration=Release /p:Platform=Win32
```

```powershell
msbuild StormBreaker.sln /t:Build /p:Configuration=Release /p:Platform=x86
```

### 依赖

仓库内已包含项目使用到的主要依赖：

- Microsoft Detours
- TLSF
- spdlog
- nlohmann/json
- mimalloc

其中，当前主内存拦截路径使用的是 `TLSF`；`mimalloc` 目前不是 StormBreaker 大块接管逻辑的核心分配器。

## 部署与运行

### 适用环境

- 游戏版本：`Warcraft III 1.27a`
- 架构：`x86`
- 目标模块：`Storm.dll`

### 加载方式

- 可以通过注入器或宿主加载器加载 `StormBreaker.dll / StormBreaker.asi`
- 插件在 `DllMain` 中只创建工作线程，真正初始化在 Loader Lock 之外执行
- 只要 `Storm.dll` 已经映射，插件就可以在运行中途加载

### 建议的注入时机

- 越早越好，最好在资源高峰加载前完成 Hook 安装
- 插件接管之前已经发生的大块分配，仍然会计入 Storm 原始统计

### 日志与控制台

- 初始化时会自动创建控制台窗口
- 日志默认写入：

```text
.\StormBreaker\StormMemory.log
```

## 实现边界与限制

- 当前偏移表按现有 `Storm.dll / game.dll` 版本维护，若目标版本变化，需要更新：
  - `StormMemPoolFix/Storm/StormOffsets.cpp`
  - `StormMemPoolFix/Game/PathCapUnlock.cpp`
- 小块分配仍由原始 Storm 管理，这是一项有意保留的兼容策略。
- 兼容层依赖 Hook 覆盖面；它不是一个脱离 Storm Hook 独立运行的通用内存管理器。
- 仓库中的 `StormMemPoolFix/CMakeLists.txt` 不是本插件的主构建入口，不建议将其作为 StormBreaker 的实际构建脚本。

## 当前状态

根据当前仓库代码检查，主线实现具备以下状态：

- `SMemAlloc / SMemFree / SMemReAlloc / SMemGetSize` Hook 已实现
- `SMemHeapCleanupAll` 与 `ResetMemoryManager` 协同逻辑已实现
- `64 KiB` 大块阈值与 `16` 字节对齐策略已落实
- `Release | Win32` 工程构建已验证通过

## 许可证

本项目采用 `MIT License`。详见 [LICENSE.txt](LICENSE.txt)。
