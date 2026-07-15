# Storm Native Small Pool Model and Repair

Last updated: 2026-07-15

## Verification scope

These facts were verified in the Warcraft III 1.27a `Storm.dll` IDB with image
base `0x15000000`. The supported file is still locked by SHA-256 in
`StormVersionProfile`; unknown binaries must not receive the internal hook.

The IDA annotation source is
`tools/ida/apply_storm_memory_annotations.py`. It declares the native arena and
block types, names the verified internal routines, and records the defects at
the relevant instructions. Re-running it is idempotent.

## Exact native structures

The normal small-block header is eight bytes:

| Offset | Type | Meaning |
| --- | --- | --- |
| `+0` | `uint16` | total block bytes, including header and padding |
| `+2` | `uint8` | alignment padding |
| `+3` | `uint8` | allocated/free, debug, external and lifetime flags |
| `+4` | `uint32` | arena signature while live; next pointer while free |

The arena fields used by allocation and free are:

| Offset | Field |
| --- | --- |
| `0` | next arena in bucket |
| `4` | 31-bit logical heap ID |
| `8` | low-byte bucket index |
| `12` | block signature: arena high 16 bits plus `0x6F6D` |
| `16` | current-arena flag |
| `20` | live allocation count |
| `24` | requested live bytes |
| `28` | first block address |
| `32` | bump pointer/end of block stream |
| `36` | adjacent-free hint |
| `40` | commit granularity |
| `44` | committed bytes |
| `48` | reserved bytes |
| `52` | external requested bytes |
| `56` | allocation calls |
| `60` | free calls |
| `68..100` | nine free-list heads |
| `104` | source line |
| `108` | variable-length source name |

The first arena reserves 64 KiB and commits 4 KiB. Its block stream begins at
`align8(112 + source_name_length)`. Later arenas double the previous reserve up
to 256 MiB; their initial commit and commit granularity are one eighth of the
reserve.

## Size and bin mathematics

For a normal request `s`:

```text
B(s) = align8(s + 8)
H(s) = B(s) - s = 8 + ((-s) mod 8)
```

Thus live-block internal overhead is 8 through 15 bytes. If request residues
modulo eight are uniform, the exact mean is 11.5 bytes. A one-byte request uses
16 bytes, so its overhead/request ratio is 1500% and total/request ratio is
1600%.

Debug mode reserves a two-byte tail canary:

```text
Bdebug(s) = align8(s + 10)
Hdebug(s) = 10 .. 17 bytes, mean 13.5 bytes
```

The free-list index is:

```text
bin(total) = min(total >> 5, 8)
```

Bins 0 through 7 each cover one 32-byte interval. Bin 8 combines every block
from 256 bytes through the maximum 16-bit block size. This very broad final bin
is intentionally cheap but can require a long linear scan.

## Allocation and free algorithm

`StormHeap_AllocPage` computes the aligned total, then:

1. If `adjacentFreeHint >= 4` and the exact target bin is empty, rebuild all
   free lists and coalesce adjacent free blocks.
2. Choose the first non-empty bin at or above the target bin.
3. Search only that bin with an approximate best-fit rule. The early-stop
   tolerance begins at 16 bytes and rises by four after each improvement.
4. Split a selected block when the remainder is at least 16 bytes. Otherwise
   absorb the remainder as alignment padding.
5. If no block was selected, allocate at the bump pointer, commit more pages,
   or create a geometrically larger arena.

Freeing the tail rewinds the bump pointer immediately. Other blocks are pushed
onto a size bin. Adjacent blocks are not coalesced immediately; only a hint is
updated. `StormHeap_RebuildFreeList` later scans the physical block stream,
merges adjacent free blocks while the combined 16-bit size remains valid, and
reconstructs all nine lists.

## Confirmed defects

### Higher-bin masking

If the target bin is non-empty but every block in it is smaller than the
request, unsigned subtraction rejects those blocks. Storm does not continue to
a higher bin. It grows the bump region or arena even when a higher-bin block
fits exactly.

A deterministic example is:

```text
free bin 1: total 32
free bin 2: total 64
request:    total 56
```

The native search examines only bin 1 and misses bin 2. This is a correctness
defect in the fit search, not a statistical allocator tradeoff.

### Deferred coalescing blind spot

Rebuild is considered only when the exact target bin is empty and the hint is
at least four. A non-empty target bin containing only undersized blocks can
therefore suppress both higher-bin search and coalescing. Bin 8 is especially
affected because it represents almost the entire small-allocation range.

### Shrink hint omission

`StormHeap_ShrinkInPlace` can create a free remainder of at least 16 bytes but
does not set the following block's previous-free hint. The physical scan can
still recover the space, but the heuristic may postpone that scan.

### Global counter drift

Allocation adds requested bytes to `g_TotalAllocatedMemory`; normal small free
subtracts total block bytes. Each completed small allocation lifetime therefore
drifts the counter downward by 8 to 15 bytes in normal mode. The external large
path has the opposite error because free subtracts only its small placeholder.

## Fragmentation limits

Internal fragmentation has the exact per-live-block bound above. For live
requests `s_i`, normal-mode block storage is:

```text
sum(s_i) + 8N <= live block bytes <= sum(s_i) + 15N
```

There is no non-trivial external-fragmentation bound under arbitrary object
lifetimes. One live byte can pin an arena after all other blocks are freed:

| Pinned arena | Requested utilization | Reserved waste |
| --- | ---: | ---: |
| 64 KiB initial arena | `1 / 65,536 = 0.0015259%` | `99.9984741%` |
| 256 MiB maximum arena | `1 / 268,435,456 = 0.0000003725%` | `99.9999996275%` |

Therefore the mathematical supremum of reserved and committed fragmentation is
100%. Per-caller heap isolation makes this achievable across many heaps because
free space cannot be shared between caller IDs.

Before reaching the 256 MiB cap, geometric reserve growth has a useful ideal
bound: the sum of all arenas is less than twice the newest arena. Arbitrary
lifetimes remove that bound once old arenas remain pinned, and additional
256 MiB arenas then grow the sum linearly.

For the 497 caller IDs observed in the full-takeover telemetry, one initial
native arena per caller alone represents 31.0625 MiB reserved and 1.9414 MiB
committed before payload. This is not automatically waste, but it defines the
floor created by lifetime partitioning.

## Executable model and results

`tools/storm_small_allocator_model.py` reproduces:

- exact normal/debug size formulas and nine bins;
- native single-bin approximate best-fit;
- deferred rebuild/coalescing and 16-bit merge limit;
- bump-tail rewind;
- geometric reserve/commit growth;
- per-caller arena chains and deferred empty-arena cleanup.

The model provides three policies: exact native `storm`, minimal
`search-fixed`, and `coalesce-fixed`. Unit tests include the deterministic
higher-bin trap.

An eight-seed synthetic small-allocation trace was run with 100,000 operations
and 497 caller IDs per seed. These numbers predict algorithm direction, not
Warcraft map load time:

| Policy vs native | Reserved median | Committed median | Arena count median | Search steps median | Free-block bytes median |
| --- | ---: | ---: | ---: | ---: | ---: |
| search-fixed | -5.435% | -4.555% | -2.611% | +11.247% | -26.145% |
| coalesce-fixed | -5.395% | -4.769% | -2.554% | +9.090% | -26.785% |

Across the eight seeds, `coalesce-fixed` reserved improvement ranged from
3.777% to 7.877%, and committed improvement from 3.418% to 5.299%.

Run the model and tests with:

```powershell
python tools/storm_small_allocator_model.py --scenario small-churn --operations 100000 --callers 497
python -m unittest tools.tests.test_storm_small_allocator_model -v
```

## Experimental native repair

`StormNativeSmallRepair` keeps Storm's allocator, headers, caller heaps,
locking, realloc, enumeration and cleanup intact. It detours only verified
internal `StormHeap_AllocPage` and runs while Storm already holds the bucket
critical section.

The `search` mode promotes one fitting higher-bin block to the target-list head
only when a non-empty target bin masks it. Original Storm immediately consumes
and splits that block. The `coalesce` mode additionally calls Storm's own
rebuild routine after a true global miss with `adjacentFreeHint >= 4`, then
retries promotion. An O(1) head check bypasses the repair scan whenever native
Storm can already satisfy the request. Neither path allocates memory or takes
another lock.

Configuration is deliberately opt-in:

```text
STORMBREAKER_NATIVE_SMALL_REPAIR=off       (default)
STORMBREAKER_NATIVE_SMALL_REPAIR=search
STORMBREAKER_NATIVE_SMALL_REPAIR=coalesce
```

The internal RVA, function prologues, arena bounds, free flags, alignment and
list walk length are validated. Suspicious state is left untouched and counted
as an invalid skip. The 60-second control panel reports calls, promotions,
rebuilds, bypasses and invalid skips.

This is the preferred next experiment over full small-block replacement. It
targets a measured Storm defect while retaining the native allocator's very
low metadata and ABI cost. The stable large-only behavior remains unchanged
when the option is absent.
