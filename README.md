# StormBreaker 1.3.0

StormBreaker 是面向 Warcraft III 1.27a x86 的内存优化 ASI。1.3.0 的正式方案不再全面接管 Storm 小块池，而是采用经过实机验证的组合：

- `>= 0xFE7C` 的大块由 TLSF 管理，减缓 Win32 低地址空间碎片化。
- 小块继续使用 Storm 原生 arena，保持游戏最敏感路径的速度与 ABI 兼容性。
- 默认启用 `search` 修复，补上 Storm 分箱搜索在特定非空桶状态下漏掉高位可用块的问题。

完整接管、hybrid 和 mimalloc 后端仍保留在实验分支，不属于 1.3.0 正式包。

## 支持版本

安装 Hook 前会校验 PE32/x86、文件 SHA-256、导出 RVA 和 relocation-safe 函数前导字节。未知版本不会部分安装 Hook，而是保持原生 Storm 运行。

| 模块 | Warcraft III 1.27a 已验证 SHA-256 |
|---|---|
| `Storm.dll` | `F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB` |
| `Game.dll` | `E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A` |
| `WorldEdit.exe` | `5F645DB7C436ED2DE0C52712D98ACAF75E518847E6234D4CC1E5C5BEE2D76DFC` |

Warcraft III 要求 `Storm.dll + Game.dll` 匹配；World Editor 要求 `Storm.dll + WorldEdit.exe` 匹配。

## 安装

1. 将 `StormBreaker.asi` 放入 Warcraft III 根目录。
2. 启动游戏。Warcraft III 自带的 ASI loader 会加载插件，不需要本地 `d3d9.dll`。
3. 控制台出现 `StormBreaker v1.3.0`、`HOOKS=YES`、`BACKEND=tlsf`、`native small repair=search` 即表示加载成功。

默认每 60 秒刷新一次控制面板，并写入 `StormBreaker/StormMemory.log`。

## 使用的算法

### 大块：TLSF

Storm 的四个公共内存入口 ordinal `401/403/404/405` 被原子安装 Hook。尺寸达到 `0xFE7C` 的分配进入 TLSF：

- 两级隔离适配（Two-Level Segregated Fit），查找与合并具有有界常数时间。
- 16 字节受保护路由头实现 O(1) 所有权识别，不使用热路径哈希表。
- 初始池 64 MiB，按需求扩展，统一 requested-live 上限 1 GiB。
- 支持真正的原地 realloc、池回收、统计和低地址策略。
- Release ASI 永久 pin；进程退出时不拆除仍可能被 Storm 调用的 Hook。

### 小块：Storm 原生池 + Search 修复

Storm 原生小块 arena 使用 8 字节对齐和 9 个 free bin。其快速路径存在一个已逆向确认的缺口：目标 bin 非空但其中没有足够大的块时，原实现可能不再检查更高 bin。

`search` 修复只在这个状态出现时检查高位 bin，把合适的块提升到目标 bin 后仍交回原生分配函数处理。常见路径只做固定条件判断；不分配辅助内存、不引入 STL 容器、不增加新锁，也不改变 Storm 块头。

### 安全与诊断

- 目标 DLL 版本和 Hook 前导字节双重校验。
- `realloc(ptr, 0)`、跨域 realloc、OOM fallback 和计数修正具有明确结果语义。
- Hook attach/detach 事务检查；Release 生命周期永久 pin。
- 可选 metrics、延迟直方图、LeakProfiler 和内存安全跟踪默认关闭，避免正式热路径开销。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---:|---|
| `STORMBREAKER_NATIVE_SMALL_REPAIR` | `search` | `off` 回退原生行为；`coalesce` 仅用于诊断 |
| `STORMBREAKER_CONTROL_PANEL_INTERVAL_SECONDS` | `60` | 控制面板刷新间隔 |
| `STORMBREAKER_DISABLE_CONTROL_PANEL` | `0` | 设为 `1` 关闭控制面板线程 |
| `STORMBREAKER_DISABLE_DEBUG_CONSOLE` | `0` | 设为 `1` 关闭调试控制台 |
| `STORMBREAKER_MEMORY_MONITOR` | `0` | 设为 `1` 开启内存监控线程 |
| `STORMBREAKER_TELEMETRY` | `0` | 设为 `1` 开启详细指标与延迟统计 |
| `STORMBREAKER_PROFILER` | `off` | `off`、`sampled` 或 `full` |
| `STORMBREAKER_MEMORY_SAFETY` | `0` | 设为 `1` 开启完整块跟踪 |

生产构建锁定 TLSF 后端，`STORMBREAKER_MEMORY_BACKEND` 不会切换正式 ASI。

## 验证结果

一次同场景配对观察中，`search` 修复处理了 2,527,085 次原生小块入口，其中 51,276 次成功提升高位 bin，`invalidSkips=0`。相对未启用修复的同一构建：

| 指标 | 变化 |
|---|---:|
| Private bytes | -9.25 MiB |
| Virtual size | -13.24 MiB |
| 低 2 GiB 空闲空间 | +13.23 MiB |
| 最大连续空闲区 | 持平（138.05 MiB） |
| 空闲区域数量 | 287 → 282 |

这些数据用于证明修复方向有效，不等同于跨机器统计基准。项目当前的实机测试记录为原版约 30 秒、插件约 25 秒；具体地图、磁盘缓存和运行环境会影响加载时间。

## 构建与测试

```powershell
msbuild StormBreaker.sln /t:StormMemPoolFix /p:Configuration=Release /p:Platform=x86
cmake -S StormMemPoolFix -B build-release-tests -A Win32 -DSTORMBREAKER_BUILD_TESTS=ON
cmake --build build-release-tests --config Release --target StormBreakerTests
./build-release-tests/Release/StormBreakerTests.exe
python -m unittest tools.tests.test_storm_small_allocator_model -v
python tools/package_release.py
```

## 文档

- [1.3.0 发布说明](Document/Release_1.3.0.md)
- [Storm 原生小块池研究](Document/Storm_Native_Small_Pool.md)
- [Storm 内存 API 逆向研究](Document/Storm_Memory_Research.md)
- [分配器离线基准](Document/StormBreaker_Allocator_Benchmark.md)

## License

[MIT License](LICENSE.txt)
