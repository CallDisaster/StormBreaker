# StormBreaker 1.3.0 发布说明

发布日期：2026-07-15

## 发布定位

1.3.0 是 StormBreaker 内存路线完成逆向、全接管实验和实机筛选后的稳定版本。正式方案选择“大块接管、小块原生修复”，优先保证 Warcraft III 1.27a 的速度、低地址空间利用率与兼容性。

本版本只发布 `StormBreaker.asi` 一份生产二进制：

- 大块后端：TLSF。
- 接管阈值：`0xFE7C`。
- Hook：Storm ordinal `401/403/404/405`。
- 小块策略：Storm 原生 arena + `search` 修复。
- 生命周期：Release 永久 pin，进程退出不拆 Hook。

## 算法说明

### TLSF 大块池

TLSF 用两级位图定位适配区间，分配、释放和相邻块合并均为有界常数时间。StormBreaker 在其外层增加 16 字节受保护路由头、1 GiB requested-live 预算、原地 realloc、分段扩展和池回收。

这个后端只处理 Storm 原本会走独立大块路径的请求，避免将上百万次小块操作导入新的同步、元数据和路由成本。

### Storm 小块 Search 修复

逆向确认 Storm 小块 arena 使用 9 个 free bin。原算法在“目标 bin 非空，但 bin 内所有块都小于请求”时，可能让这个 bin 遮蔽高位 bin 中实际可用的块，进而继续 bump/扩容。

修复只在该缺口状态搜索高位 bin，并把适配块链接到目标 bin。后续切分、块头写入和调试标记仍全部由原生 Storm 完成。因此它保留了原生小块池的紧凑 8 字节头和成熟热路径，同时减少不必要的 arena 增长。

### 未晋级算法

全尺寸 TLSF、mimalloc-only 和 hybrid 均完成过实现与实验，但没有进入 1.3.0：

- 全尺寸 TLSF 在真实地图上出现显著加载时间回退。
- mimalloc 的通用并发与安全设计无法抵消 Storm 单线程密集小块调用的路由成本。
- hybrid 的双后端路由、头部和生命周期成本增加了内存占用，且曾出现兼容性问题。

相关实现保留在实验分支，便于后续继续研究，不影响正式版本。

## 兼容性锁定

| 模块 | SHA-256 |
|---|---|
| `Storm.dll` | `F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB` |
| `Game.dll` | `E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A` |
| `WorldEdit.exe` | `5F645DB7C436ED2DE0C52712D98ACAF75E518847E6234D4CC1E5C5BEE2D76DFC` |

校验失败时不会安装部分 Hook。

## 观测数据

同一场景启用 `search` 后记录到：

- 原生小块入口：2,527,085 次。
- 高位 bin 提升：51,276 次。
- 无效 arena 跳过：0 次。
- Private bytes：降低 9.25 MiB。
- Virtual size：降低 13.24 MiB。
- 低 2 GiB 空闲：增加 13.23 MiB。
- 最大连续空闲区：保持 138.05 MiB。
- 空闲区域数：287 降至 282。

分配模型中的综合策略相对未修复 Storm 模型，reserved 中位数降低约 5.44%，committed 中位数降低约 4.56%，arena 数中位数降低约 2.61%。模型用于比较算法趋势，实机数据才是发布决策依据。

最终用户侧加载测试记录为原版约 30 秒、1.3.0 候选版约 25 秒。由于地图脚本、磁盘缓存和后台负载差异，该数字不作为所有机器上的固定承诺。

## 安装与回退

正式产物：

| 文件 | 字节数 | SHA-256 |
|---|---:|---|
| `StormBreaker.asi` | 246,784 | `E9E5623B0CD872F8F56CB159257A5AFC7588B2EDE5286CD0FC7194D1B7A40055` |

将 `StormBreaker.asi` 放入 Warcraft III 根目录。控制台必须显示：

```text
StormBreaker v1.3.0
HOOKS=YES
BACKEND=tlsf
native small repair=search
```

只回退小块修复：设置 `STORMBREAKER_NATIVE_SMALL_REPAIR=off`。

完全回退：退出游戏后移除 `StormBreaker.asi`。插件在进程内被永久 pin，运行中不支持安全卸载。

## 已知限制

- 仅支持锁定的 Warcraft III 1.27a x86 文件，其他补丁版本会拒绝 Hook。
- 32 位进程仍受低 2 GiB 地址布局约束；插件只能降低增长和碎片，不能消除游戏自身泄漏。
- `coalesce` 模式可能增加长尾停顿，仅用于诊断。
- profiler、完整内存安全跟踪和详细遥测会产生额外开销，正式运行默认关闭。
