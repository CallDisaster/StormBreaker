# StormBreaker

StormBreaker 是面向 Warcraft III 1.27a x86 的 Storm 内存 API 兼容与优化插件。

当前 `codex/large-block-optimized` 分支是编译期锁定的 `large/tlsf` 版本：只安装 ordinals `401/403/404/405`，只托管 `>= 0xFE7C` 的请求，并从生产链接中移除了全接管 registry。完整导出接管保存在 `codex/full-takeover-experiment`。分支结构、TLSF 改进和本轮基准详见 [大块接管优化分支](Document/Large_Block_Optimized_Branch.md)。

## 版本门禁

安装任何内存 Hook 前会同时校验 PE32/x86、SHA-256、导出 RVA 和 relocation-safe 函数前导字节。未知版本会保持原生 Storm 完整运行，不进行部分安装。

| 模块 | 已验证 SHA-256 |
| --- | --- |
| `Storm.dll` | `F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB` |
| `Game.dll` | `E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A` |
| `WorldEdit.exe` | `5F645DB7C436ED2DE0C52712D98ACAF75E518847E6234D4CC1E5C5BEE2D76DFC` |

War3 运行时要求匹配 `Storm.dll + Game.dll`；WorldEdit 运行时要求匹配 `Storm.dll + WorldEdit.exe`。

## 当前实现

### 接管边界

当前生产 ASI 只安装 `401/403/404/405` 核心 Hook，不初始化或链接全接管 heap registry。这样不会改变 Game 可观察的 `406/482/496` 行为，也不会让原生小块经过 full takeover 的 heap-ID 路径。下列完整导出能力属于实验分支和离线测试目标。

- `401/403/404/405`：通用 alloc/free/size/realloc，按每个指针的受保护头与后端所有权在托管和原生域之间分流。
- `406`：在全导出档返回原生存量与托管 requested-live 的统一 32 位计数，并同步三个可选输出参数；不再暴露后端头部和 size-class 舍入差异。
- `481/482`：枚举托管块、原生堆、托管逻辑堆和唯一后端汇总记录；原生游标顺序保持不变。
- `483/484`：保持 Storm 的调用点 heap ID 算法，并为托管指针返回解码后的 heap ID。
- `485-490`：支持显式 heap 的创建、分配、销毁、释放、重分配和取大小。
- `496`：镜像 Debug Memory、Protect Memory、fill pattern 和 Realloc Shuffle 状态，同时转发原函数。

项目不 Hook Storm 内部 `StormHeap_*`，也不存在可用的 `ResetMemoryManager` 导出。历史兼容 helper 仍在源码中供旧路径单元测试使用，但正式安装事务只覆盖上述导出 API。

### 块头与 heap registry

- 小于 `0xFE7C` 的托管块使用 8 字节头，保持 Storm 普通小块相同的固定头开销。
- 大块使用 16 字节头，记录 requested size、heap ID、route 和校验信息。
- 进程密钥由 `BCryptGenRandom` 生成；校验绑定用户指针、大小、heap ID 和 route。
- 后端精确验证分配起点；损坏指针或 65,536 项近期释放表命中时拒绝操作，绝不落入原生 Storm。
- 固定 16,384 项 heap registry 记录 active/destroying/tombstone、来源、存活/峰值统计与在途引用，不在热路径扩容 STL 容器。
- registry 条目保持 64 字节对齐并压缩为 2 MiB 固定存储；caller-derived heap ID 使用进程级 16,384 项、8 路组相联的只增缓存。命中无锁且跨线程共享，每次查找最多检查 8 项，缓存饱和只旁路到原生 483，不会退化为整表扫描。
- 显式托管 heap 保留一个原生零尺寸 sentinel，使 Protect/OOM 兼容委托和持久块销毁行为仍有有效原生 shell。

### ReAlloc 与 Storm flags

- 零尺寸分配返回可释放的非空块；托管零尺寸 realloc 保持 Storm 语义，不按 CRT `free` 处理。
- `0x08` 清零新块或增长尾部。
- `0x10` 禁止移动；无法原地增长时返回空且旧块保持有效。
- Realloc Shuffle 强制移动。
- Storm 原生大块 realloc 总是移动；托管大块现在同样采用分配、复制、释放，仅小块允许原地扩缩。
- Debug Memory 提供尾哨兵和填充值；fill pattern 使用 Storm 的 `0xEE/0xDD` 约定。
- Protect Memory 委托原生 Storm 并记录 degraded reason。
- mimalloc 使用 `mi_expand`，TLSF 支持真实原地 realloc；允许移动时才进行跨 route 分配、复制和释放。
- 原生大块只有在确认旧块已经释放后才修正 Storm 的泄漏式计数。

### 后端与生命周期

- `tlsf`：默认后端，初始 64 MiB、常规 16 MiB 扩展粒度，支持池遍历、空扩展池回收与原地 realloc。扩容按 TLSF 的真实二级尺寸桶上界计算；超过常规粒度的大对象改用 64 KiB 紧配池，并只在分配失败的冷路径回收不匹配的空池。生产默认使用 Windows system 布局；`clustered` 高地址布局只保留为离线诊断选项，因为真实 Warcraft III 测试出现了无响应/崩溃。
- `mimalloc`：专用 first-class heap，只调用显式 `mi_` API，不覆盖 CRT、全局 malloc 或 new/delete。
- `hybrid`：小块走 mimalloc，`> 0xFE7B` 的大块走 TLSF。large 模式不会产生 mimalloc 路由，因此延迟初始化该 heap，避免额外保留约 128 MiB VA。
- mimalloc 默认关闭分配线程上的定时自动 purge；空页仍可在 heap 内复用，显式内存压力/Trim 会临时启用强制 purge。这样不会用每秒一次的 Windows decommit 换取游戏长帧。
- 所有后端共用 1 GiB requested-live 预算。
- Hook 安装/卸载会将进程线程加入同一 Detours 事务；失败则整体回滚或保留 trampoline、Hook 与后端。
- Release 模块永久 pin 到进程退出。进程退出的 `DLL_PROCESS_DETACH` 不拆 Hook、不销毁仍可能被 Storm 使用的池。

## 配置

```text
STORMBREAKER_TAKEOVER_MODE=large|32k|8k|2k|256|full
STORMBREAKER_MEMORY_BACKEND=tlsf|mimalloc|hybrid|tlsf-sharded
STORMBREAKER_TLSF_ADDRESS_POLICY=clustered|system
STORMBREAKER_PROFILER=off|sampled|full
STORMBREAKER_TELEMETRY=0|1
STORMBREAKER_ARTIFACT_DIR=<directory>
STORMBREAKER_MIMALLOC_PURGE_DELAY_MS=-1..3600000
STORMBREAKER_MIMALLOC_ARENA_RESERVE_MIB=0|8|16|32|64|128
STORMBREAKER_MIMALLOC_PAGE_FULL_RETAIN=-1..8
STORMBREAKER_MIMALLOC_PAGE_MAX_CANDIDATES=1..16
```

当前分支的生产值编译期锁定为 `large/tlsf/system/profiler-off/telemetry-off`；`STORMBREAKER_TAKEOVER_MODE` 和 `STORMBREAKER_MEMORY_BACKEND` 不会改写生产选择。所有 TLSF 地址范围还必须完整低于 `0x80000000`。`tlsf-sharded`、mimalloc、hybrid 和 full takeover 只在实验分支或离线测试目标中使用。
`STORMBREAKER_MIMALLOC_PURGE_DELAY_MS` 默认为 `-1`（关闭自动 purge）；非负值用于诊断上游 mimalloc 的延迟策略。
其余 mimalloc 参数只用于离线诊断：arena 的 `0` 表示上游 x86 默认 128 MiB，满页保留与候选页搜索默认分别为 `2/4`。当前没有任何组合通过相对 TLSF 的 3% 内存门槛。

可选诊断开关：

- `STORMBREAKER_MEMORY_SAFETY=1`：启用旧兼容层的完整块追踪和周期验证。
- `STORMBREAKER_VERBOSE_LOG=1`：启用高频调试日志，会影响分配性能。
- `STORMBREAKER_MEMORY_MONITOR=1`：启用旧版周期内存监控。
- `STORMBREAKER_DISABLE_DEBUG_CONSOLE=1`：不创建控制台。
- `STORMBREAKER_DISABLE_CONTROL_PANEL=1`：关闭控制面板心跳，基准测试会设置它。
- `STORMBREAKER_STATUS_INTERVAL_SEC=5..3600`：心跳周期，默认 60 秒。

Hook 成功后控制面板立即输出一次 `READY=YES HOOKS=YES`，随后每 60 秒刷新并 flush 到 `./StormBreaker/StormMemory.log`。
日志轮转保留 `.1-.5`，支持覆盖最老备份；共享/重命名失败会退避 60 秒，避免每条日志重复关闭和重开文件。
full 模式下 ordinal 482 的 native/managed heap 快照只在一轮枚举开始时构建一次；控制面板的 `heap enumeration calls/snapshot rebuilds` 可验证整轮游标没有重复全表扫描。
控制面板同时输出 `callerCache=hits/misses/bypasses/saturated entries=N`。`bypasses` 表示动态或非核心映像 caller 不能安全长期缓存，`saturated` 表示目标组已满，`entries` 是当前精确占用量；事件计数在线程内按 4,096 次批量汇总，供诊断趋势使用。无论命中率如何，查找成本都被限制为最多 8 个槽位。

`callerHash=direct-verified` 表示启动时已用 8 组探针对比 Storm ordinal 483，随后直接执行完全一致的 31 位调用点哈希；验证失败会保留原 trampoline。近期释放表使用单乘法 Fibonacci 索引，在不改变 65,536 项容量和跨线程 double-free 拒绝语义的前提下，减少分配/释放热路径指令并改善连续对齐地址的槽位覆盖。`heapIdHint=hits/misses` 仅用于实验诊断，生产容量为 0。

## Profiler 与遥测

LeakProfiler 使用预分配的 65,536 项 MPSC ring；Hook 热路径不做文件 I/O、符号化或 STL 扩容。输出 `SBLP` 二进制流，每秒 checkpoint，可在尾部截断后恢复：

```powershell
python tools\analyze_leak_profile.py <leak_profile.sblp> --output report.json
```

`sampled` 完整记录托管块，对原生小块按指针哈希 1/256 采样；`full` 仅用于短时诊断。Reset 只作为启发式 epoch marker，Cleanup 只作为 marker；单次进程报告 survivor，连续跨两个以上 epoch 增长才标记 leak candidate。

`STORMBREAKER_TELEMETRY=1` 每秒写 `metrics_<pid>.jsonl`，包含实际 backend/mode、Hook 状态、requested/usable/reserved/committed、fallback/degraded 原因、延迟直方图和 profiler 丢失状态。控制面板的 `last` 字段还会显示最近一次降级请求的精确 `size`，用于区分真实预算耗尽与后端扩容问题。

## 构建

Visual Studio 入口：

```powershell
msbuild StormBreaker.sln /t:Build /p:Configuration=Release /p:Platform=x86
```

CMake 可同时生成诊断变体和 x86 测试：

```powershell
cmake -S StormMemPoolFix -B build-stormbreaker -A Win32 `
  -DSTORMBREAKER_BUILD_TESTS=ON -DSTORMBREAKER_BUILD_VARIANTS=ON
cmake --build build-stormbreaker --config Release --target `
  StormBreakerTests StormBreaker StormBreakerTLSF StormBreakerMimalloc StormBreakerHybrid
```

输出位于 `StormMemPoolFix/Build/`：

- `StormBreaker.asi`：当前分支的四 Hook、大块专用、后端锁定 TLSF 产物。
- `StormBreaker-TLSF.asi`：后端锁定 TLSF。
- `StormBreaker-mimalloc.asi`：后端锁定 mimalloc。
- `StormBreaker-hybrid.asi`：后端锁定 hybrid。

四份产物构建并验证完成后，用下列命令重新生成发布清单。脚本会先校验所有 ASI 均为 x86 且开启 LAA，再原子更新尺寸与 SHA-256；任一产物不合格时保留旧清单：

```powershell
python tools/write_stormbreaker_variant_manifest.py
```

当前生产构建同时锁定后端与 takeover 边界；环境变量不能把它切换为 full。

## 测试

```powershell
ctest --test-dir build-stormbreaker -C Release --output-on-failure
python -m unittest tools.test_analyze_leak_profile `
  tools.test_stormbreaker_benchmark `
  tools.tests.test_stormbreaker_benchmark_extended -v
```

StormBreaker 自有 runner 位于 `tools/stormbreaker_benchmark.py`。它只调用 AutoTest 的启动/停止能力，不修改 AutoTest；每轮强制 isolated desktop，拒绝运行目录中的真实 `d3d9.dll`，并验证系统 d3d9、Storm、Game、ASI 路径与 SHA。固定五组为 `off`、`large-tlsf`、`full-tlsf`、`full-mimalloc`、`full-hybrid`。

直接崩溃烟测使用 `tools/stormbreaker_crash_smoke.py`。当前非隔离目标为 `E:\Work\Warcraft III`；runner 只终止路径校验后的本轮自有 PID，部署前后备份/恢复 ASI，并在系统 Commit 余量或进程 Commit 触及保护线时将轮次标为 guard-stop，而不是误报为崩溃。

`full/hybrid` 只有在以下真实工作负载门槛全部通过后才能晋级：地图 ready 回退不超过 5%，Private/Commit/Virtual 的配对 95% CI 上界不超过 `large/tlsf` 3%，Hook p99 不恶化超过 10%，Virtual 增长斜率下降至少 20%，最大连续空闲区提升至少 10%，且超过 10 ms 的分配停顿下降至少 20%。

## 代码结构

```text
StormMemPoolFix/Storm/StormTakeover.*       全导出 Hook 与兼容分流
StormMemPoolFix/Storm/StormVersionProfile.* 版本、SHA、RVA 与前导字节门禁
StormMemPoolFix/Storm/StormHeapRegistry.*   固定容量逻辑 heap registry
StormMemPoolFix/Storm/MemoryPool.*          后端路由、预算、统计与生命周期
StormMemPoolFix/Storm/*Backend.cpp          TLSF/mimalloc 实现
StormMemPoolFix/Base/LeakProfiler.*         MPSC ring 与 SBLP writer
StormMemPoolFix/Base/Telemetry.*            metrics JSONL
StormMemPoolFix/tests/                      x86 单元/压力/mock Storm 测试
tools/                                      runner、离线解析器与 IDA 注释脚本
Document/Storm_Memory_Research.md           已验证逆向结论与实现边界
```

## 限制

- 全接管能减少 Storm 每调用点 arena 导致的 32 位虚拟地址碎片，但不等于一定降低 working set 或缩短首次进图时间。
- 官方 Game/WorldEdit 已静态审计；动态 Warden 或第三方插件仍可能形成未知调用边界，因此每个指针都必须保持 mixed-domain 路由。
- 全导出档的 406 托管部分报告 requested-live；large 档直接保留 Storm 原生 406。Game 会用它计算资源差值和默认纹理 key，因此仍需真实渲染工作负载验证。
- registry 容量固定为 16,384。表满后用 32 KiB、四哈希 membership filter 对确定不存在的 ID 做 O(1) 拒绝；已存在 ID 仍精确查找。耗尽会明确记录并退化到原生 heap，不会静默伪装成已接管。
- 当前没有运行真实 War3/WorldEdit 晋级基准；默认值不会自动切换到 `full/hybrid`。

## 许可证

本项目采用 MIT License，详见 `LICENSE.txt`。
