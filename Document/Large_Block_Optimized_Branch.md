# 大块接管优化分支

## 分支边界

- `codex/full-takeover-experiment`：保存完整 Storm 导出 API 接管实验，基线提交为 `c0c426f`。
- `codex/large-block-optimized`：当前生产候选，只接管 Storm ordinals `401/403/404/405`，只托管 `size >= 0xFE7C` 的请求，后端编译期锁定为单池 TLSF。

这里的“仅接管大块”不是把全接管框架的阈值设为 `large`。生产 ASI 不初始化 heap registry，也不链接 `StormTakeover.cpp` 和 `StormHeapRegistry.cpp`。Storm 的 `406/481-490/496`、小块 arena、heap ID 和枚举行为全部保持原生。

## Hook 热路径

- 安装前仍校验 PE32/x86、Storm SHA-256、全部目标 ordinal 的 RVA 和 relocation-safe 前导字节；不匹配时不安装任何 Hook。
- profiler、遥测和关闭流程均未启用时，小块 `SMemAlloc` 只做阈值判断，然后直接调用 Detours trampoline。
- `SMemFree/SMemGetSize/SMemReAlloc` 用 64 KiB 粒度、固定 65,536 项的无锁页目录先判断地址是否可能属于 TLSF。确定不属于时不探测 StormBreaker 头，也不进入 heap registry。
- 已释放指针会先写入固定近期释放表，再允许后端归还最后一个扩展池，消除并发 double-free 落回原生 Storm 的窗口。
- Release ASI 永久 pin 到进程退出；进程退出阶段不拆 Hook、不销毁仍可能被 Storm 使用的 TLSF。

## 迁移到旧架构的 TLSF 改进

1. 扩容按 TLSF 真实二级 size class 计算，不再为接近 16 MiB 边界的请求创建“字节数够、类别却不可选”的无效池。
2. 超过常规粒度的请求使用 64 KiB 对齐紧配池；失败重试会回滚新池，并在 OOM 冷路径清除不匹配的空池。
3. `tlsf_pool_is_empty` 利用完全合并后的单自由块不变量做 O(1) 空池判断。
4. 默认 `warm-empty-pools=0`：最后一个块释放后立即归还扩展池，主池固定保留 64 MiB。显式内存压力仍会完整 Trim。
5. 保留一个 warm 扩展池的实验旋钮只存在于逻辑基准。7 组标准 map-load 配对中位数为 `+1.04%`，并稳定多保留 16 MiB，因此未晋级生产默认。
6. 每个主池和扩展池的完整范围必须低于 `0x80000000`。Windows 在 LAA x86 进程中返回高地址时，该范围会被立即释放并拒绝，避免 Game/Storm 的有符号 32 位地址判断把合法指针视为负值。
7. 后端集合发布后不可变，Release 热路径不再为生命周期增加引用计数；TLSF 内部仍保留必要的并发锁。

## 离线验证结果

本阶段没有启动 Warcraft III 或 WorldEdit，只运行独立 x86 mock、单元测试和压力测试。

| 项目 | 结果 |
| --- | --- |
| 单元/并发/压力测试 | 全部通过 |
| 原生 Storm mock 对四 Hook，小块 churn，7 组 standard | wall 中位差 `+1.56%` |
| 同一小块 churn 的 sampled p99 | 两者均为 `400 ns` |
| warm pool `1` 对即时回收 `0`，7 组 standard map-load | wall 中位差 `+1.04%`，常驻多 `16 MiB`，拒绝 |
| full 实验 ASI 文件大小 | `720,384` bytes |
| 当前大块 ASI 文件大小 | `243,200` bytes |

map-load mock 的“原生”端使用现代 Windows process heap，并不是 Storm 1.27a 的逐次大块 `VirtualAlloc` 路径，因此它不能预测真实进图收益。它只用于检查相同事件序列、失败数、池回收、p99 和框架固定开销。真实的 21 秒/24.5 秒结果仍需使用同一地图、同一 War3 根目录复测。

## 构建与人工测试

```powershell
cmake -S StormMemPoolFix -B build-large -A Win32 `
  -DSTORMBREAKER_BUILD_TESTS=ON
cmake --build build-large --config Release --target `
  StormBreakerTests StormBreaker
```

产物为 `StormMemPoolFix/Build/StormBreaker.asi`，当前 Release SHA-256 为
`F331092D7BC8B5B555CA24A8D8B9EEA02BE91454232710092375872046BF4671`。
控制台启动后应立即显示：

```text
READY=YES HOOKS=YES BACKEND=tlsf
takeover=large-four-hook, threshold=0xFE7C
```

随后默认每 60 秒刷新。这个分支的 `STORMBREAKER_TAKEOVER_MODE` 和 `STORMBREAKER_MEMORY_BACKEND` 不参与生产选择；要继续验证 full/hybrid，请切换到 `codex/full-takeover-experiment`。
