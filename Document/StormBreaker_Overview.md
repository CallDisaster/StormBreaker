# StormBreaker 项目说明（写给后来者）

本文件概述了暴雪 **Storm.dll** 内存池的行为、它在魔兽争霸 III 旧版本中的缺陷，以及 StormBreaker 目前的优化思路与项目现状。希望阅读后可以快速理解我们已经做过的工作、为什么这么做、以及后续仍可能扩展的方向。

---

## 1. Storm 内存池到底发生了什么？

### 1.1 分配入口与 2GB 限制

游戏及其插件调用 `SMemAlloc / SMemFree / SMemReAlloc` 时，最终都会进入 `StormHeap_Alloc` 等内部函数。每次分配，Storm 都会把字节数累加到 **`g_TotalAllocatedMemory`**（偏移 `0x1505738C` 一带），一旦累计值超过 `0x7FFFFFFF`：

```
if (Storm_g_TotalAllocatedMemory > 0x7FFFFFFF) {
    Storm_AllocErrorHandler(...);
    ExitProcess(1);
}
```

这就是旧版魔兽“内存涨到 2G 必崩”的根源。

### 1.2 大块与小块的差异

- **小块（< ~64 KiB）**：落在 Storm 自己管理的堆里。根据调用源计算堆索引，进入对应的 `CRITICAL_SECTION`，在链表里找空闲块。开销不算小，但问题主要是性能。
- **大块（≥ ~64 KiB）**：Storm 直接 `VirtualAlloc` 一整段，并更新 `g_TotalAllocatedMemory`。释放时虽然会回收，但计数已经涨上去，会迅速逼近 2GB 限制。

### 1.3 其它相关接口

Storm 自身提供了 `SMemGetSize`、`SMemHeapCleanupAll`、`ResetMemoryManager` 等维护/调试接口。Hook 这些函数时必须保持兼容，否则会破坏内部状态，引发后续崩溃。

---

## 2. StormBreaker 的解决思路

### 2.1 核心策略：劫持大块，伪装兼容

项目通过 Detours Hook 接管 Storm 的分配函数。逻辑如下：

1. **判断大块**：当前阈值设为 64 KiB，与 Storm 内部判定一致。若小于阈值，直接回退到原始 Storm 分配。
2. **大块走 TLSF**：我们维护一个 TLSF 内存池（64 MB 初始，可按 16 MB 扩展至 1 GB）。所有大块请求都在这个池里完成，并保证 16 字节对齐。
3. **伪造 Storm 头部**：在用户指针前写入与 Storm 一致的 10 字节头部，包含魔数、padding、真实 `StormHeap*`，使 `SMemFree/SMemGetSize` 等接口能顺利通过校验。
4. **登记块信息**：`ManagedBlockInfo` 保留原始指针、大小、时间戳等，方便重算、释放、监控。
5. **Reset/Cleanup 协同**：Hook `ResetMemoryManager` / `SMemHeapCleanupAll`。Reset 后重新捕获默认 `StormHeap*` 并修复头部里的指针。

> 关键目标是让 Storm 的 `g_TotalAllocatedMemory` 保持在较低水平（通常 400–600 MB），而大块占用转移到我们可控的 TLSF 池。这样即使游戏总内存增长，Storm 原生的 2GB 限制也不再被触发。

### 2.2 安全与监控

* `MemorySafety`：跟踪所有托管块，支持延迟释放、泄漏检测、损坏检测。
* `TrimFreePages`：若某个 TLSF 扩展池完全空闲，会 `tlsf_remove_pool + VirtualFree` 回收给系统。
* 监控线程定期打印 OS 口径内存（提交量、常驻集）、Storm 累计、TLSF 使用、延迟释放队列等，让调试和验证一目了然。

---

## 3. 当前代码状态（关键点）

| 功能 | 状态 | 说明 |
|------|------|------|
| 自动初始化 | ✅ | DLL 注入后自动完成日志初始化、Hook 安装、监控启动。 |
| Hook 覆盖面 | ✅ | `SMemAlloc/Free/ReAlloc/GetSize`、`SMemHeapCleanupAll`、`ResetMemoryManager`（若有导出/偏移）。 |
| 大块拦截阈值 | ✅ | 默认 64 KiB，确保所有会触发 Storm 大块路径的请求都进入 TLSF。 |
| 兼容层 | ✅ | `SMemGetSize` 会优先从管理表返回真实大小，再兜底调用 Storm 原函数。 |
| TLSF 扩展回收 | ✅ | 完整实现 `TrimFreePages`，空闲的扩展池返回操作系统。 |
| 监控数据对比 | ✅ | 无论日志还是定期报告，都能看到 “Storm 累计 vs TLSF 占用” 的差值。 |

实际测试结果：Storm 的全局计数长期稳定在 500 MB 左右；TLSF 扩展在高负载时约 1.2–1.5 GB，可随释放回落。游戏再也不会因为 Storm 累计到 2 GB 而崩溃。

---

## 4. 仍可扩展的方向（非必须）

1. **更多 Storm API 兼容**  
   若地图或调试工具会使用 `SMemHeapSize`、`SMemDumpState` 等函数，可参照 `SMemGetSize` 的做法增加 Hook。

2. **策略/配置动态化**  
   阈值、扩展粒度、监控间隔都可外部化到配置文件，甚至根据实时数据自适应调整。

3. **更细的告警机制**  
   对 Storm 累计、TLSF 剩余、延迟释放队列等设置警戒线，一旦出现异常趋势立刻告警。

4. **多版本支持**  
   若要兼容其他版本的 Storm.dll，需要维护偏移表或做自动探测。

5. **脚本级排查**  
   Storm 小块路径仍由原生管理，若要解决小块泄漏问题，应排查地图脚本/插件，而不是重写 Storm 的小块分配器（难度巨大且收益有限）。

---

## 5. 其它常见疑问

### 5.1 为什么不重写小块分配？

Storm 小块路径与内部数据结构紧耦合：堆哈希表、临界区、调试填充、统计接口、错误码等都依赖原实现。全面替换等同于把 Storm 的内存管理器重新写一遍，工程量巨大、风险极高，而小块并不是导致崩溃的主要因素，所以没必要走这条路。

### 5.2 现在还能再压榨多少？

我们的主要目标（延缓 Storm 内存池触顶）已经完成。如果继续优化，也只是锦上添花（更好的监控、配置化、兼容更多 API）；除非发现新的瓶颈，否则没有必要大规模改动。

### 5.3 StormBreaker vs 原生的性能差异？

大块分配改走 TLSF，避免频繁 `VirtualAlloc/VirtualFree`，在高压场景下性能更稳定；小块仍由 Storm 原生管理，因此整体行为和兼容性保持不变。

---

## 6. 如何继续维护？

1. **注入方式**：保持原有流程，把 StormBreaker.dll 注入到游戏进程即可。无需额外初始化步骤。
2. **看日志**：`StormBreaker/StormMemory.log` 会输出 Storm/TLSF 的实时状态。重点关注 Storm 累计是否稳定、TLSF 是否可回收。
3. **出现异常时**：先看日志有没有 `ResetMemoryManager` / `SMemGetSize` 相关的错误，确认 Hook 是否成功安装；检查 `StormOffsets` 是否对应当前 Storm.dll 版本。
4. **需要新功能**：按上面“扩展方向”循序渐进，小改动先在 Playground 测试，再合并。

---

## 7. 项目目录（与本说明相关部分）

```
Document/
  └── StormBreaker_Overview.md    # 本文档
StormMemPoolFix/
  ├── Storm/
  │   ├── StormHook.cpp/.h        # Hook 主逻辑（拦截/兼容）
  │   ├── MemoryPool.cpp/.h       # TLSF 管理器
  │   └── StormOffsets.cpp/.h     # Storm 全局变量偏移
  ├── Base/
  │   ├── MemroySafety.cpp/.h     # 块跟踪、监控、延迟释放
  │   └── Logger.*                # 日志系统
  └── dllmain.cpp                 # DLL 入口、初始化与装钩
```

---

## 8. 最后

StormBreaker 目前能稳定地把 Storm 原生 2GB 限制变成“一个不会再涨的数字”，这是项目的最核心价值。后续若有新的需求，可以在此基础上继续迭代，但请优先保持兼容性和稳定性。如果你刚接手并准备扩展功能，建议按以下顺序开展：

1. 跑一次高负载地图，确认 Storm/TLSF 状态正常。  
2. 熟悉 `StormHook` 和 `MemoryPool` 的主要流程。  
3. 了解 `MemorySafety` 的延迟释放、监控机制。  
4. 再酌情考虑是否要扩展 Hook、配置或监控功能。

### 注入时机补充说明

只要 Storm.dll 已经映射，我们的 DLL 可以在“中途”加载（例如 RB 作者在地图载入阶段调用 `LoadLibrary`）；`DllMain` 会自动完成初始化和装钩，后续的大块分配都会进入 TLSF。需要注意的是：在我们接管之前已经分配的大块仍然计入 Storm 原始统计，无法补救，所以建议尽量在资源爆发式加载之前注入。另外，装钩瞬间最好处于 Storm 内存接口空闲的时间点（加载流程的同步阶段），避免与原始 `SMemAlloc/Free` 发生竞态。

祝维护顺利，有问题欢迎在日志或注释中继续记录你的发现。*** End Patch
