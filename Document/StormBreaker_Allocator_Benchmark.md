# StormBreaker allocator logic benchmark

## Purpose

This benchmark isolates allocator and takeover algorithms from Warcraft III.
It never launches War3, WorldEdit, AutoTest, an isolated desktop, or an ASI
loader. The same deterministic operation trace is executed against production
paths and deliberately isolated allocator candidates:

- `winheap`: direct Windows process-heap control, used only as a lower-overhead
  reference and not presented as native Storm performance.
- `pool`: the selected `MemoryPool` backend without the Storm API adapter.
- `takeover/tlsf`: full StormBreaker takeover with the TLSF backend.
- `takeover/mimalloc`: full takeover with the dedicated mimalloc first-class
  heap.
- `takeover/hybrid`: full takeover with mimalloc below `0xFE7C` and TLSF at or
  above it.
- `takeover/tlsf-sharded`: diagnostic four-shard TLSF with a shared 1 GiB
  reservation budget and a fixed 64 KiB address-to-shard directory.
- `private-heap`, `rpmalloc`, `rpmalloc-threaded`, `segregated-arena` and
  `segregated-hybrid`: diagnostic candidates. They are never selected by a
  production environment variable merely because the benchmark can run them.

Additional allocator candidates must implement the same `MemoryBackend`
contract and run the unchanged traces before they can enter production code.

## Reproducibility contract

- Target: Release Win32/x86, profiler off, telemetry off, takeover `full`.
- PRNG: fixed PCG32 implementation and an explicit 64-bit seed.
- A measured repetition runs in a fresh process. One unreported warm-up process
  precedes seven measured processes for every engine/scenario pair.
- The runner rotates engine order with a fixed seed to reduce thermal and
  background-load bias.
- The benchmark pre-reserves its live-pointer table before the timed region.
- Per-operation latency is sampled at a fixed interval rather than timing every
  operation. Wall time always covers the complete operation stream and drain.
- Every run drains all live blocks, validates requested-live bytes return to
  zero, and emits one machine-readable JSON object. A failed invariant makes
  the run invalid instead of silently contributing a slow or fast sample.

## Canonical traces

### `map-load`

Models the observed full-takeover load shape: many small allocations, thousands
of caller-derived heaps, a rising live set, intermittent frees and reallocs,
then a complete drain.

- `standard`: 6,600,000 operations, target 1,300,000 live blocks, 4,096 caller
  sites. The size distribution targets roughly 300-400 requested bytes per live
  block while retaining rare 8 KiB to 1 MiB requests.
- `quick`: one tenth of the standard operations and live target, with the same
  distribution and caller count.
- Separate static and dynamic caller-name variants exercise cacheable and
  deliberately uncacheable ordinal-483 inputs.

### `small-churn`

Repeated 8-512 byte allocate/free traffic with a bounded 32,768-block working
set. This isolates size-class reuse, ownership lookup and registry accounting.

### `realloc`

A stable small-object working set receives in-place growth, shrink, same-size,
zero-size and cross-route realloc requests. Payload prefixes are sampled for
copy correctness.

### `editor-burst`

Repeated bursts of 64 KiB to 4 MiB allocations followed by shuffled frees. It
reports operation stalls above 1 ms and 10 ms in addition to percentiles.

### `cross-thread`

Four producer threads allocate independent blocks, then ownership rotates and
another thread frees each block. This measures first-class-heap behavior,
cross-thread free and shared accounting contention.

### `heap-enumeration` and `heap-destroy`

These takeover-only traces validate the complexity of ordinals 481 and 487.
Enumeration mixes native and managed records and requires one managed snapshot
per cursor chain. Destroy builds one live-block snapshot and frees from that
snapshot. Snapshot counters are hard invariants, not advisory metrics, so an
accidental O(N squared) implementation fails the run.

### `caller-hash`

This takeover-only microtrace executes 2,000,000 (`quick`) or 20,000,000
verified ordinal-483 hashes over short, medium and long source names. It keeps
the output checksum identical between candidates and separates caller-hash
instruction cost from allocator, registry and OS scheduling work.

## Reported metrics

- complete wall time and operations per second;
- sampled allocation/free/realloc p50, p95 and p99 latency;
- operations exceeding 1 ms and 10 ms;
- peak live block count and requested bytes;
- process Working Set, Private, Commit and occupied Virtual bytes before the
  timed region, at peak live, and after drain;
- StormBreaker backend counters, caller-cache counters and registry occupancy;
- a deterministic checksum over successful operations and sampled payloads.

The Python runner reports median, p95, paired differences and bootstrap 95%
confidence intervals while retaining every raw JSON record.

## Acceptance gates

An algorithm change is retained only when all correctness checks pass and at
least one canonical hot scenario shows either:

- median wall-time/throughput improvement of at least 3%; or
- sampled p99 improvement of at least 10%.

It must not regress any other canonical scenario by more than 3%, and the upper
bound of the paired 95% confidence interval for Private, Commit and Virtual
growth must remain within 3% of the current accepted baseline.

An additional allocator backend has a higher gate: it must improve at least two
of `map-load`, `small-churn`, `editor-burst` or `cross-thread`, including one
improvement of at least 10%, without violating the same memory and correctness
limits. A backend that only wins a synthetic micro-case remains diagnostic.

## Benchmark phases

1. Record the current TLSF, mimalloc and hybrid implementation as baseline 0.
2. Optimize caller resolution, heap-slot lookup, ownership classification and
   accounting one change at a time, preserving raw A/B output.
3. Evaluate additional allocator candidates behind `MemoryBackend`; do not
   replace the default based on upstream claims or a single throughput number.
4. Build the final ASIs only after the logic benchmark and stress tests pass.
5. Warcraft III testing remains a separate final validation performed when the
   game workspace is available.

## Commands

The canonical production-path matrix is:

```powershell
python tools\stormbreaker_allocator_benchmark.py `
  --profile standard --engines winheap takeover `
  --backends tlsf mimalloc hybrid --repetitions 7 `
  --seed 20260713 --output-dir stormbreaker_benchmark_results\production-path-standard-v1
```

A single algorithm factor is interleaved in fresh processes. Any non-factor
options are fixed explicitly so the result cannot silently compare two
different configurations:

```powershell
python tools\stormbreaker_allocator_factor_benchmark.py `
  --engine takeover --backend tlsf --profile standard `
  --scenarios map-load realloc --factor-option tlsf-range-index `
  --values off on --reference-value off --repetitions 9 `
  --fixed-option --pool-initial-mib=4
```

Both runners retain `raw.jsonl` beside `summary.json`. Published conclusions
must name the result directory and may not be reconstructed from console text.

## Accepted algorithm baseline (2026-07-13)

`production-path-standard-v1` is the first post-correctness standard baseline.
All rows below are medians from seven measured fresh processes; times are logic
benchmark times, not Warcraft III map-ready times.

| scenario | WinHeap | takeover/TLSF | takeover/mimalloc | takeover/hybrid |
| --- | ---: | ---: | ---: | ---: |
| map-load | 2578.7 ms | 4591.3 ms | 4106.0 ms | 4161.5 ms |
| realloc | 4810.2 ms | 6131.1 ms | 4728.6 ms | 4308.8 ms |
| editor-burst | 22.6 ms | 6.2 ms | 8.3 ms | 5.6 ms |
| cross-thread | 371.0 ms | 1099.2 ms | 425.9 ms | 459.2 ms |

Relative to takeover/TLSF, mimalloc improved map-load by 11.5% (paired 95%
CI -17.1% to -5.9%) but increased peak Private by 16.8% and peak Virtual by
33.9%. Hybrid improved map-load by 4.6% (CI -12.7% to -0.7%) while increasing
the same memory metrics by 15.1% and 28.7%. Neither passes the 3% memory gate,
so TLSF remains the accepted default and the faster routes remain diagnostic.

The accepted TLSF range index is recorded in
`factor-takeover-tlsf-range-index-v1`. With a forced 4 MiB initial pool, binary
range lookup reduced map-load by 11.58% (CI -15.72% to -3.06%) and realloc by
9.64% (CI -17.87% to -7.88%), with unchanged peak Private and Virtual. This
replaces a linear scan of every grown pool for ownership and exact-block checks.

The caller thread cache factor tested capacities 0, 64, 256 and 1024. After
switching the implementation to commit exactly the selected capacity, the final
standard 256-versus-1024 map-load comparison was statistically inconclusive:
-1.32% paired median, 95% CI -5.40% to +9.40%. Production uses 256 to reduce
each participating thread's committed cache from approximately 16 KiB to 4 KiB
and releases it at thread exit; no throughput claim is attached to this
footprint change.

## Candidate disposition

`allocator-candidates-threaded-standard-v2` compared four diagnostic allocators
over the unchanged standard traces:

- `rpmalloc-threaded` improved map-load by 35.9%, realloc by 42.4%, editor burst
  by 83.1% and cross-thread by 48.2% versus WinHeap. It retained about 358 MiB
  after map-load and about 1165 MiB after cross-thread drain, and it lacks the
  exact global block visitation required by ordinals 481/487. It is not a
  production candidate without a bounded live-block index and effective purge.
- `segregated-arena` improved map-load by 35.2% and realloc by 42.6%, but
  regressed cross-thread by 22.5% and increased occupied Virtual space. Its
  private-heap overflow route fixes class-fragmentation OOM but not remote-free
  contention.
- `segregated-hybrid` showed similar map/realloc speed and an 80.4% editor-burst
  gain, but regressed cross-thread by 24.5% and retained substantially more
  memory than the arena-only candidate.

No additional allocator passes both the speed and 3% memory gates. A new
candidate must pass these offline gates before any Warcraft III run.

## Rejected algorithm experiments (2026-07-13)

### Four-shard TLSF

`takeover-tlsf-sharded-standard-v1` is the seven-repetition standard result.
The implementation uses four independent TLSF controls, one aggregate
reservation CAS and a 65,536-entry x86 address directory, so valid free/query
operations reach exactly one shard. This removed the original four-lock owner
probe but did not make sharding a general improvement.

| scenario | wall change vs TLSF | paired 95% CI | peak Private | peak Virtual |
| --- | ---: | ---: | ---: | ---: |
| map-load | +11.26% | +7.98% to +19.64% | +8.80% | +8.48% |
| caller-locality | +4.93% | +0.95% to +13.27% | +8.80% | +8.48% |
| realloc | +2.57% | -0.06% to +13.10% | -12.70% | -10.39% |
| cross-thread | -6.19% | -6.91% to -2.59% | -0.38% | -0.37% |

Cross-thread wall time improved, but p99 did not, and map-shaped workloads paid
for 137 shard-local extensions instead of 31 aggregate extensions. Per-shard
fragmentation raised the map working set above the 3% gate. A 1 MiB growth
variant reduced that memory penalty but introduced repeatable caller-locality
regressions. `tlsf-sharded` remains an explicit diagnostic backend; production
continues to default to single TLSF.

### Segregated remote-free queue

`factor-segregated-remote-free-quick-v2` compared the same 40 size classes and
span layout with either the original per-class SRW lock or a lock-free
per-span remote-free chain. The chain only enters the class lock when a span
changes from full to available or becomes empty. It nevertheless regressed
cross-thread wall time by 3.41% (CI +3.03% to +9.82%) and map-load by 4.89%
(CI +1.20% to +12.55%) without reducing memory. Cache-line exchange on each
block cost more than the short SRW critical section, so this path remains
benchmark-only.

### Bounded mimalloc arenas

`factor-mimalloc-arena-reserve-standard-v2` tested the upstream x86 128 MiB
arena reservation against 8 and 16 MiB. The 8 MiB setting reduced map-load
peak Virtual by 7.79%, realloc by 29.34% and cross-thread by 9.63%. Paired wall
changes were +1.31%, -8.94% and +1.19% respectively, with every 95% interval
crossing zero. Private/Commit changed by less than 1%, and the long realloc
trace eventually reserved the same total VA after drain. Smaller arenas are
therefore a useful x86 diagnostic knob, but they do not erase mimalloc's
Private/Commit gap against TLSF.

Quick factors for `page_full_retain=0..8` and
`page_max_candidates=1..16` changed peak memory by less than 0.2%. They were
stopped before a standard run. No mimalloc parameter combination is promoted.

### Bounded rpmalloc caches

The original `rpmalloc-threaded` result was rechecked with runtime-selectable
global and thread span cache limits. Disabling the global cache reduced
map-load Private after drain by 32.5% and realloc by 72.4%, but regressed
realloc by about 9% and small-churn by about 13% in the first quick factor.
With the global cache disabled, a 64-span thread limit reduced map-load drain
Private by another 40.0%; realloc drain Private/Virtual fell 37.9%/21.2% while
its wall median regressed 4.45%.

The cross-thread trace did not release retained memory at any cache limit.
rpmalloc orphans a heap when its owner thread exits; later frees from another
thread remain on the orphan heap's deferred lists until that heap is adopted
and collected. Forcing a process-wide orphan walk is not concurrency-safe, and
rpmalloc still lacks exact live-block visitation for Storm ordinals 481/487.
The candidate is rejected before a standard promotion run, but the raw quick
factors are retained in `factor-rpmalloc-global-cache-quick-v1`,
`factor-rpmalloc-cache-multiplier-quick-v1` and
`factor-rpmalloc-thread-cache-limit-quick-v1`.

The accepted production algorithm changes from this phase are therefore the
TLSF range index and bounded caller caches. All allocator replacements remain
diagnostic until a candidate passes speed, memory, exact visitation and
cross-thread reclamation together.

## Address-space and lifecycle algorithms (2026-07-14)

This phase remained offline and sequential. No Warcraft III or WorldEdit
process was launched. Every factor used a fresh x86 process, and the runner was
checked after each matrix for orphan benchmark children.

### Accepted: full-table membership filter

The fixed 16,384-entry heap registry previously became an unbounded CPU trap
at 100% load: every new ID scanned all 16,384 cache-line entries. A 32 KiB,
four-hash, insert-only membership filter now provides a no-false-negative
check once the table is full. Existing IDs retain exact lookup semantics;
definitely absent IDs fail in O(1), and only Bloom false positives scan.

`factor-registry-membership-filter-quick-v1` measured nine paired runs. The
1,024-overflow saturation trace improved wall time by 99.48% (95% CI -99.65%
to -99.35%), p99 by 99.84%, and collision probes by 92.98%. Private and Virtual
were unchanged in the A/B because both test variants allocate the same filter.
`factor-registry-membership-filter-normal-quick-v1` found no normal map-load or
caller-locality regression. Production enables the filter permanently.

### Accepted: clustered TLSF virtual-address placement

The benchmark memory snapshot now reports the largest contiguous free region
and free-region count in addition to Private, Commit and occupied Virtual.
TLSF uses one `MEM_TOP_DOWN` placement for the main pool, then attempts exact
64 KiB-aligned reservations immediately below the lowest existing TLSF pool.
Only a blocked exact address falls back to a system top-down search. This
clusters growth without pre-reserving the whole 1 GiB budget.

In `factor-tlsf-top-down-clustered-map-standard-v1`, with a 16 MiB main pool
and 34 growth pools, five paired standard map runs increased the largest free
region by 39.41% (95% CI +37.85% to +40.33%) and reduced free-region count by
2.08%. Wall median was -0.49%, p99 0%, and Private/Virtual changed by less than
0.01%. The offline result initially promoted `clustered`, but a subsequent real
Warcraft III run made large/TLSF unresponsive and large/hybrid exit while both
shared the TLSF route. Production therefore defaults back to `system`;
`STORMBREAKER_TLSF_ADDRESS_POLICY=clustered` remains diagnostic-only. A failed
clustered main allocation still automatically falls back to system placement.

### Accepted: constant-time empty-pool trim

`tlsf_pool_is_empty` checks the same invariant required by
`tlsf_remove_pool`: one coalesced free block followed by the zero-size
sentinel. It replaces a full block walk in TLSF Trim, main-pool decommit checks,
and sharded rollback. There is no alloc/free hot-path accounting.

`factor-tlsf-constant-time-empty-check-standard-v1` retained one block per 32
allocations across a 524,288-block fragmented trace. Old Trim median/p95 was
2520.1/3496.3 microseconds; the new path was 2.0/2.94 microseconds, a paired
99.92% median reduction (95% CI -99.95% to -99.88%). Ordinal 487 now invokes
TLSF-only Trim after a successful explicit-heap destroy. It does not purge
mimalloc or decommit the main TLSF pool.

### Rejected or diagnostic-only

- `factor-tlsf-main-pool-decommit-trim-cycle-quick-v1`: decommitting an empty
  64 MiB main pool reduced idle Private/Commit by 83.86%, but repeated
  drain/recommit increased wall time by 15.20% (CI +3.51% to +16.86%) and made
  sampled p99 about 23.6 times larger. The mechanism remains test-only and is
  not triggered by heap destroy.
- `factor-tlsf-clustered-initial-pool-map-editor-standard-v1`: a 32 MiB main
  pool reduced light-load footprint, but map wall regressed 6.08% (CI +0.27%
  to +14.43%) and editor-burst 12.14%. Production retains 64 MiB. The 16 MiB
  candidate was rejected earlier for editor p99.
- BatchIt-style remote-free batches, lazy segregated spans, detailed-counter
  batching, and allocator-stat suppression all failed their quick gates. The
  implementations remain benchmark-only where useful; production defaults did
  not change.

## Caller and ownership hot-path pass (2026-07-14)

Fresh-process factor runs added `--direct-caller-hash`,
`--direct-hash-byte-table`, `--heap-id-slot-hint`,
`--registry-predicted-slot`, `--registry-hazard-pinning` and
`--recent-free-hash` controls.

Accepted:

- Storm's exact ordinal-483 algorithm is executed directly only after eight
  startup probes match the native trampoline. A 256-entry byte-delta table
  replaces two nibble-table loads and one subtraction per source-name byte.
  The 20-million-operation hash trace had a paired wall median of -12.17%; its
  95% CI crossed zero because host frequency changed during the run, while the
  checksum and p99 remained identical.
- The 65,536-entry recently-freed table now uses Fibonacci indexing. Nine quick
  map pairs improved sampled p99 by 19.72% (95% CI -42.86% to -8.70%) with
  unchanged memory. Three standard realloc pairs improved wall time by 4.31%
  (CI -19.53% to -4.27%); five standard map confirmation pairs were neutral.
  On 65,536 sequential aligned addresses it retained 58,048 unique slots versus
  41,274 for Mix32, so the cheaper index also reduced representative collisions.

Rejected or test-only:

- A per-thread heap-ID-to-registry-slot cache consumed up to 12 KiB per thread
  at 1,024 entries and did not produce stable wall or p99 gains.
- Predicting the registry's initial open-addressing slot made caller-locality
  wall time about 5% worse because displaced heaps paid an extra failed acquire.
- Hazard publication reduced quick cross-thread p99 from about 32.1 to 28.0
  microseconds, but regressed map wall/p99 by about 4.4%/10%. Production keeps
  generation reference pinning; the hazard implementation remains test-only.

## TLSF size-class-aware growth (2026-07-14)

A direct large/TLSF Warcraft III run repeatedly reported two
`backend-out-of-memory` fallbacks while requested-live was only 123-142 MiB
and the backend had reserved 352-384 MiB of its 1 GiB budget. A new atomic
control-panel field identified the exact request as 16,658,432 bytes.

This request exposes a TLSF boundary condition. The allocation fits in 16 MiB
arithmetically, but `mapping_search` rounds it upward to the next one of 32
second-level classes. The previous growth calculation added only fixed 64 KiB
slack, created a 16 MiB pool, and retried against a free block whose class was
still below the requested class. Each retry left another empty 16 MiB pool and
fell back to native Storm.

`tlsf_allocation_pool_size` now mirrors TLSF's request alignment, memalign gap,
class rounding and pool overhead. If that minimum exceeds the normal growth
granularity, the extension is rounded to the Windows 64 KiB allocation
granularity instead of the next 16 MiB multiple. Empty mismatched growth pools
are reclaimed only after an allocation has already failed, and a newly added
pool is rolled back if its retry still fails. The successful allocation/free
hot path performs no new scan.

The production-sized boundary is locked into the C++ suite. The final exact-ASI
67-second direct-root run completed with zero failure, fallback, degradation or
hung samples. Both it and the diagnostic run had exactly 123 MiB requested at
the 60-second heartbeat; reserved fell from 384 MiB to 204 MiB, a 180 MiB or
46.9% reduction, while two native fallbacks became zero. Quick fresh-process
map-load and realloc traces also completed with zero allocator failures and
zero >10 ms samples. Their artifacts are
`tlsf-class-growth-fix-hotpath-20260714` and
`tlsf-class-growth-fix-trim-20260714`.
