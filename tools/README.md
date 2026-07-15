# StormBreaker benchmark runner

`stormbreaker_benchmark.py` runs one warmup block and ten measured blocks by
default. Every block contains `off`, `tlsf`, and `mimalloc` exactly once in a
seeded rotating order.

```powershell
python tools/stormbreaker_benchmark.py
```

Important overrides:

```powershell
python tools/stormbreaker_benchmark.py `
  --war3-root E:\Work\War3_AutoTestSandbox `
  --map "E:\Work\War3_AutoTestSandbox\(4)生与死v1.28读档bug修复.w3x" `
  --asi StormMemPoolFix\Build\StormBreaker.asi `
  --measured-blocks 10 `
  --memory-gate-pct 3 `
  --speed-gate-pct 5
```

The runner uses AutoTest's `launch_war3_instance` contract. Every round gets a
unique instance root, isolated desktop, Job Object, session ID, and artifact
directory; it never switches to the interactive desktop and stops only its own
session. The ASI process contract is
`STORMBREAKER_MEMORY_BACKEND=tlsf|mimalloc`, `STORMBREAKER_TELEMETRY=1`, plus
`STORMBREAKER_ARTIFACT_DIR=<per-round artifact directory>`. An enabled round
must emit `metrics_<pid>.jsonl` with a status containing `hooksInstalled: true`
and the requested `backend`. Missing or mismatched metrics fail the round.

Results are written under `stormbreaker_benchmark_results/<run-id>/`. Each
round has `samples.jsonl`, `modules.json`, HUD readiness features, ready/final
screenshots, metrics JSONL, and `round.json`. `summary.json` contains
median/p95 aggregates, within-block paired deltas, seeded bootstrap 95% CIs,
and fail-closed validation gates. `evaluation.recommendedBackend` remains
`tlsf` unless mimalloc passes the paired TLSF comparison: Private/Commit/Virtual
95% CI upper bounds <=3%, allocator p99 does not regress, and either load time
improves >=5% or allocation p99 improves >=10%. Exit code `0` means the
benchmark dataset is complete and valid even when TLSF remains recommended;
`1` means coverage was incomplete, and `2` means a fatal preflight or
restoration error.

Run the no-game unit suite with:

```powershell
python -m unittest discover -s tools -p "test_*.py" -v
```
