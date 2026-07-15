# Changelog

## [1.3.0] - 2026-07-15

### Added

- 增加 Storm 原生小块池 `search` 修复，并作为正式构建默认策略。
- 增加小块修复的调用、提升、重建、无效 arena 和 bypass 计数。
- 增加独立 LeakProfiler、SBLP 二进制事件流、metrics JSONL 和离线解析器。
- 增加 TLSF、mimalloc、hybrid、分片 TLSF 的离线基准与压力测试框架。
- 增加 PE 版本资源、可复现发布打包脚本和发布校验信息。

### Changed

- 正式架构调整为“大块 TLSF + 小块 Storm 原生池修复”，不再以全尺寸接管作为默认目标。
- 大块阈值固定为 `0xFE7C`，正式构建锁定 TLSF 后端。
- TLSF 初始池为 64 MiB，并使用按需求扩展、原地 realloc、池回收和低地址策略。
- 正式控制面板默认 60 秒刷新，并显示版本、Hook、后端和小块修复状态。
- 详细遥测、内存监控和 profiler 默认关闭，降低发布热路径开销。

### Fixed

- 修复 Storm 目标 bin 非空但无合适块时可能漏查高位 bin 的分箱搜索缺口。
- 修复 `realloc(ptr, 0)` 释放后再次落入原生 Storm 的问题。
- 修复原生 realloc 失败时错误扣减旧块计数的问题。
- 修复跨线程异常状态、计数更新、并发遍历和 shutdown 顺序问题。
- Hook 安装与卸载改为检查完整 Detours 事务；失败时保持 trampoline 和后端有效。
- Release ASI 永久 pin，进程退出不主动拆 Hook 或销毁仍可能被 Storm 使用的池。
- 修复 TLSF 32 位边界自测、原地 realloc 和扩容路径中的若干正确性与性能问题。

### Compatibility

- 仅支持已锁定 SHA-256 的 Warcraft III 1.27a Win32/x86 模块。
- full takeover、mimalloc-only 和 hybrid 作为实验实现保留，不包含在 1.3.0 正式包中。
- `STORMBREAKER_NATIVE_SMALL_REPAIR=off` 可恢复原生小块行为；`coalesce` 仅建议诊断使用。
