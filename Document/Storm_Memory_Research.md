# Storm / Game Memory Research

Last updated: 2026-07-13

## Scope

This document records the allocator ABI and lifecycle facts verified against the
Warcraft III 1.27a `Storm.dll` used by `E:\Work\War3_AutoTestSandbox`. It also
records the implementation boundary and the remaining runtime promotion tests
before enabling small-block takeover by default.

The intended design is an API-level replacement behind the exported `SMem*`
entry points. Direct replacement of `g_HeapHashTable`, Storm heap structures, or
Storm block headers is not proposed.

## Storm.dll verified facts

### Public memory entry points

The target Storm image base in the IDB is `0x15000000`.

| Ordinal | Address | IDA name | Meaning |
| --- | --- | --- | --- |
| 401 | `0x1502B830` | `Storm_MemAlloc` | `SMemAlloc` |
| 403 | `0x1502BE40` | `Storm_MemFree` | `SMemFree` |
| 404 | `0x1502C000` | `Storm_404` | `SMemGetSize` |
| 405 | `0x1502C8B0` | `Storm_MemReAlloc` | `SMemReAlloc` |
| 406 | `0x1502BF10` | `Storm_406` | global memory counter query |
| 481 | `0x1502BB20` | `Storm_481` | `SMemFindNextBlock` |
| 482 | `0x1502BD10` | `Storm_482` | `SMemFindNextHeap2` |
| 483 | `0x1502BF40` | `Storm_483` | `SMemGetHeapByCaller` |
| 484 | `0x1502BF90` | `Storm_484` | `SMemGetHeapByPtr` |
| 485 | `0x1502C0A0` | `Storm_485` | `SMemHeapAlloc` |
| 486 | `0x1502C180` | `Storm_486` | `SMemHeapCreate` |
| 487 | `0x1502C300` | `Storm_487` | `SMemHeapDestroy` |
| 488 | `0x1502C3A0` | `Storm_488` | `SMemHeapFree` |
| 489 | `0x1502C5E0` | `Storm_489` | `SMemHeapReAlloc` |
| 490 | `0x1502C6D0` | `Storm_490` | `SMemHeapSize` |
| 496 | `0x1502C980` | `Storm_496` | memory debug option setter |

The DLL exports these primarily by ordinal. StormBreaker currently falls back to
known RVAs when named `GetProcAddress` lookups fail.

### Important internal functions

| Address | Name | Purpose |
| --- | --- | --- |
| `0x1502A350` | `StormHeap_Create` | reserve/commit and initialize one heap arena |
| `0x1502A510` | `StormHeap_AllocPage` | allocate a small block or external large block |
| `0x1502A830` | `Storm_CheckMemPointer` | validate `0x6F6D`, state and tail canary |
| `0x1502A920` | `StormHeap_RebuildFreeList` | scan arena and rebuild/coalesce free lists |
| `0x1502AA70` | unnamed destroy helper | report/release live blocks and destroy an arena |
| `0x1502AB50` | `StormHeap_CleanupAll` | release eligible empty heap arenas |
| `0x1502ABF0` | `StormHeap_InternalFree` | free/coalesce a block or release external VA |
| `0x1502AD60` | `StormHeap_ComputeIndex` | derive logical heap ID from caller metadata |
| `0x1502ADE0` | `StormHeap_CommitPages` | commit more pages inside a reserved arena |
| `0x1502AE30` | unnamed grow helper | attempt in-place small-block growth |
| `0x1502B3B0` | `StormHeap_Alloc` | allocation wrapper, fill/zero and accounting |
| `0x1502B4F0` | unnamed free wrapper | size/accounting, poison and internal free |
| `0x1502B560` | `StormHeap_ReallocImpl` | in-place resize or allocate/copy/free |
| `0x1502B680` | unnamed shrink helper | shrink/split a small block in place |
| `0x1502B790` | `StormHeap_CombineFreeBlocks` | split/coalesce free ranges |
| `0x1502B920` | memory shutdown | disable manager and destroy all Storm heaps |

### Heap topology

`Storm_MemAlloc` computes a 31-bit logical heap ID from `name + srcLine`.
The low eight bits select one of 256 hash buckets and one of 256 critical
sections. The full logical ID is used to search a linked list inside that
bucket. Consequently there can be far more than 256 heap arenas.

A newly created arena normally uses:

- reserved size: `0x10000` (64 KiB)
- initially committed size: `0x1000` (4 KiB)
- commit granularity: `0x1000` (4 KiB)
- base address aligned to Windows allocation granularity

When an arena cannot satisfy a request, Storm can create another arena for the
same logical heap. Its reserve/commit values grow from the previous arena. This
per-caller arena model gives lifetime locality but can consume and fragment a
large amount of the 32-bit virtual address space.

### Small-block layout

Normal small blocks are eight-byte aligned and use an eight-byte header. Debug
memory mode adds a two-byte tail canary and effectively uses ten bytes of
overhead before alignment.

Conceptual normal header:

```text
block + 0  uint16 total_block_size
block + 2  uint8  alignment_padding
block + 3  uint8  state_and_option_flags
block + 4  uint16 heap_base_high16
block + 6  uint16 magic = 0x6F6D
block + 8  user data
```

`Storm_CheckMemPointer` requires `*(uint16_t *)(user - 2) == 0x6F6D`.
It checks bit `0x02` for an already-freed block. In debug memory mode it also
checks a `0x12B1` tail canary.

The heap pointer is reconstructed from the stored high 16 bits. This is why a
private StormBreaker block must never be passed to an original Storm free,
realloc, size or heap-query routine.

### Large-block boundary and layout

`StormHeap_AllocPage` switches to an external `VirtualAlloc` path when:

```text
requested_size > 0xFE7B
```

StormBreaker therefore begins interception at `0xFE7C` (`65148`). In the
external path the user allocation has a separate 16-byte prefix. Important
fields observed by Storm include:

- requested size at `user - 16`
- pointer to the owning Storm placeholder block at `user - 12`
- flags around `user - 5`
- the `0x6F6D` marker at `user - 2`

The placeholder block remains inside the Storm heap while the user payload is a
separate virtual allocation.

### Allocation flags and options

Verified semantics that a replacement must preserve:

- allocation/reallocation flag `0x08`: zero the new allocation, or zero only
  the grown tail during realloc
- realloc flag `0x10`: do not move; if in-place growth fails, return null while
  keeping the old block valid
- allocation flag `0x04000000`: stored as Storm header bit `0x40`; affects
  shutdown leak reporting
- allocation flag `0x08000000`: stored as Storm header bit `0x80`; affects
  persistent/shutdown handling
- `Debug Memory`: adds a tail canary
- `Protect Memory`: forces the external virtual-allocation path
- `Realloc Shuffle`: disables the normal in-place realloc attempt
- fill-pattern mode: fills new memory with `0xEE` and freed small blocks with
  `0xDD`

The full-export takeover passes these flags through its managed allocation and
reallocation paths. The older `StormHook` helper remains only as a legacy test
surface and is not attached by the production Detours transaction.

### Realloc behavior

For a valid native block Storm first tries an in-place shrink or growth. If that
fails and flag `0x10` is clear, it allocates a new block, copies
`min(old_size, new_size)`, frees the old block, and zero/fills the grown tail as
requested.

Mixed native/managed blocks are unavoidable because Storm initializes before
the ASI and allocations may also occur on explicitly native fallback paths.
Ownership must therefore be decided from each pointer, never from the current
threshold or global mode.

### Accounting defect

`StormHeap_Alloc` adds the requested size to `g_TotalAllocatedMemory`.
The free wrapper subtracts the Storm block's stored total size. For external
large allocations this stored value belongs to the small placeholder rather
than the real payload, causing the counter to retain most of the released large
allocation. StormBreaker's native-large counter correction addresses this
specific mismatch.

Ordinal 406 returns this global counter. A full takeover must either hook the
query to report combined native plus managed live bytes or explicitly accept
that the in-game value no longer describes total Storm allocations.

### Cleanup and shutdown

`StormHeap_CleanupAll` scans all 256 buckets and releases eligible empty arenas.
It is normally triggered after a Storm allocation when an earlier free marked a
heap as empty. If all new allocations are intercepted, that implicit next
allocation may never occur. A takeover should invoke original cleanup after
native frees or at a rate-limited maintenance point so pre-hook native arenas do
not remain reserved indefinitely.

The full memory shutdown at `0x1502B920` sets the initialized flag to false,
walks every bucket, handles live native blocks, frees all Storm arenas, and
deletes the 256 critical sections. It is called from Storm's shutdown chain at
`0x15039B20`.

StormBreaker must remain pinned and must not destroy a backend while managed
blocks can still be freed. Process-exit memory is left to the OS.

### Internal bypass paths

Storm also exposes explicit heap APIs 485/488/489 which call
`StormHeap_Alloc`, the internal free wrapper, and `StormHeap_ReallocImpl`
directly. These bypass the main 401/403/405 entry points.

Import-table audit of the sandbox binaries found:

- `War3.exe`: imports 401/403/405, not 485/488/489
- `Game.dll`: imports 401/403/405 plus memory statistics/configuration APIs
  406/482/496, not 485/488/489
- `WorldEdit.exe`: imports 401/403/405/406, not 485/488/489

No non-allocator Storm function was found comparing the `0x6F6D` or `0x12B1`
markers. A disassembly scan of the target `Game.dll` also found no direct use of
those constants. This gives high confidence for the official binaries, but
third-party plugins may still call explicit heap APIs and require compatibility
policy.

## Implemented staged small-block takeover

### Safety prerequisites and closure

1. Verified allocation and realloc flags are preserved.
2. Zero-size allocation and realloc behavior is covered by mock Storm tests.
3. Ownership routing is pointer-based across native, TLSF and mimalloc domains.
4. Header/backend validation prevents managed pointers reaching original Storm.
5. Release pins the ASI; process-exit detach leaves Hook and backends alive.
6. Native-to-managed, managed-to-native and cross-route realloc are tested.
7. Native frees preserve Storm cleanup behavior; no internal cleanup function is
   detoured.
8. Ordinal 406 combines native and managed requested-live; ordinal 482 emits native,
   managed logical heap and one backend aggregate record without double-counting.

### Compact small header

Large managed blocks retain a 16-byte header. Small managed blocks use an
eight-byte protected header so fixed overhead matches normal Storm:

```text
uint32 pointer_bound_cookie
uint16 requested_size
uint8  encoded_heap_and_route
uint8  state_and_storm_flags
```

The cookie must incorporate the user pointer, a process secret and the requested
size to minimize false ownership matches when probing native pointers. Large
blocks retain the existing 16-byte header.

### Rollout modes

`0xFE7C` remains the production default. Runtime modes lower the minimum managed
size in stages:

```text
large -> 32768 -> 8192 -> 2048 -> 256 -> full including size zero
```

Every stage supports native blocks allocated before hook installation and during
deliberate fallback. Free and realloc routing is based on the protected block
header plus exact backend ownership.

### Backend direction

The current map-load result shows TLSF is the better fit for Storm's large
bursts, while the current test never exercises mimalloc's small-object path. The
leading candidate is therefore:

- small blocks below `0xFE7C`: mimalloc
- large blocks at or above `0xFE7C`: TLSF

A route field in the private header allows correct cross-thread free and realloc.
A single-backend full-mimalloc build is also useful as a lower-complexity control
variant. Sharded TLSF should remain conditional on measured lock contention.

### Expected benefit and risk

The strongest expected benefit is reduced 32-bit virtual-address fragmentation:
many per-caller 64 KiB Storm reservations are replaced by shared allocator
arenas. It may also improve cross-caller reuse and delay address-space exhaustion.

This does not guarantee lower working set or faster allocation. Storm's small
allocator has only eight/ten bytes of fixed overhead, 256 locks, per-caller
lifetime locality and cheap free lists. A naive 16-byte-header, single-lock TLSF
replacement can consume more memory and run slower. Peak Private, Commit,
Virtual, allocation latency and map/editor workflows must all be measured.

## Game.dll verified facts

### Target identity and API surface

The focused IDA pass used `E:\Work\War3\Game.dll`, image base
`0x6F000000`. Its SHA-256 is:

```text
E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A
```

This is byte-identical to the `Game.dll` in
`E:\Work\War3_AutoTestSandbox`, so the results apply to the planned tests.

The core Game image imports these Storm memory entry points:

| Ordinal | IAT | Import thunk | Static call xrefs |
| --- | --- | --- | ---: |
| 401 | `0x6F94E678` | `0x6F120628` | 2615 |
| 403 | `0x6F94E5C8` | `0x6F1205CE` | 9058 |
| 405 | `0x6F94E67C` | `0x6F12062E` | 881 |
| 406 | `0x6F94E5A8` | `0x6F81918A` | 1 wrapper caller |
| 482 | `0x6F94E5FC` | `0x6F819184` | 2 calls in one function |
| 496 | `0x6F94E6AC` | `0x6F120676` | 1 caller |

It does not import 404, 481, 483-490, or the explicit heap allocation APIs
485/488/489. The official Game core therefore allocates exclusively through
401/403/405. A scan also found no direct use of the Storm block markers
`0x6F6D` or `0x12B1`.

### Allocation and reallocation flags

The normal 401 call sequence pushes `flags`, `line`, `file`, then `size`.
Direct sites use flag 0 or 8, while many generated container wrappers pass a
dynamic flag and frequently OR in 8. A replacement must therefore preserve
zero-fill semantics rather than treating flags as diagnostic metadata.

The normal 405 sequence adds the old pointer as the fifth argument. A static
pass over all 881 call sites found the dominant immediate modes to be 0 and
`0x10`, plus at least one flag-8 path and one propagated dynamic path. The
`0x10` no-move contract is consequently common Game behavior: returning a
moved pointer when it is set would be a real correctness bug. Typical vector
growth code deliberately tries realloc with `0x10`, then falls back to 401 plus
copy when it returns null.

Static recovery of every dynamic flag value is not reliable enough to be a
validation oracle. The takeover build should add a flag histogram to the
existing telemetry before progressing below each size threshold.

### Ordinal 406 is resource accounting and a texture-key seed

`sub_6F7039A0` is only:

```text
return Storm_406(0, 0, 0);
```

Texture/resource loading function `sub_6F6FE6D0` samples it before and after
loading a BLP/TGA and adds the delta to `dword_6FBED9EC`. Tiny getter/reset
stubs expose that accumulator. It also derives a default texture lookup key
from the pre-load counter (`counter & 0xFFFFFFCE | 0x0E`) when the caller does
not supply one. No branch compares ordinal 406 with a memory limit, and there
is no OOM decision on this call chain, but the returned value is not merely a
cosmetic statistic.

After full takeover, leaving 406 native-only would both omit managed allocations
from Game's resource-memory accounting and make the default texture-key seed
nearly static. Hooking 406 is therefore a prerequisite, not an optional display
improvement. The full-export implementation reports native-adjusted plus managed
requested-live with 32-bit wrap-compatible arithmetic and copies the same value
to all three optional outputs, matching Storm's output behavior. The production
`large` stage leaves ordinal 406 native because Game observes the counter delta;
backend-specific usable bytes must never leak into this texture/resource key.

### Ordinal 482 is a diagnostic heap display

`sub_6F3B18E0` runs at most every two seconds when a diagnostic/UI state bit is
enabled. It enumerates Storm heaps with ordinal 482, sums two fields, and
formats:

```text
mem (MB): %5.2f/%5.2f
```

It does not control allocation, cache eviction, or map flow. The implementation
preserves the original native heap cursor order, merges managed logical heaps,
and emits one reserved/committed backend aggregate record so HUD totals do not
double-count per-heap live bytes.

### Ordinal 496 is called during process-level Game shutdown

The function takes `(value_bits, mask_bits)`. For each set mask bit it copies
the corresponding value bit into one Storm global. The verified mapping is:

| Bit | Storm global | Meaning |
| ---: | --- | --- |
| 1 | `0x1505536C` | Debug Memory |
| 2 | `0x15057388` | memory error/assert reporting behavior |
| 4 | `0x15056F74` | Protect Memory |
| 8 | `0x15056F70` | allocation/free fill patterns (`0xEE`/`0xDD`) |

The only Game call is `Storm_496(0, 8)` inside `sub_6F027660`, the large
Game-application shutdown chain. It clears the fill-pattern mode after several
subsystem teardown calls and before the remaining global objects are freed. It
does not clean heaps and is not a map-reset callback. A managed replacement
should preserve this option for managed blocks if enabled, but must not destroy
or reset its backend in response to the call.

### There is no Storm `ResetMemoryManager` map-reset API

The IDB name `ResetMemoryManager_05E710` at `0x6F05E710` is misleading. Its
entire behavior is:

1. `SetEvent(dword_6FBB895C)`
2. enter/drain `MainLoop_6F05F710(1)`
3. clear `dword_6FBB8978`

It neither references Storm nor resets an allocator. `GameMain` calls its jump
stub after `GameApplication_Init` returns, then executes `sub_6F027660` for
process-level application shutdown. Storm.dll has no corresponding export.

The production installation transaction does not resolve or Hook
`ResetMemoryManager`. A disabled legacy source block remains only as historical
reference. Hooking `0x6F05E710` would only hook engine-loop shutdown and would
not provide map-level reclamation.

### Map cleanup is explicit object-graph teardown

The JASS VM path demonstrates the actual lifecycle model. `JassVm_FinalCleanup`
at `0x6F7DD070` walks frames, script objects, handles, strings, hash tables and
arrays, issuing many ordinary ordinal-403 frees. `FreeJassVm` invokes that deep
cleanup. There is no global Storm allocator reset at map unload.

This rules out blindly freeing all allocations at a guessed map boundary.
Objects can cross UI/map epochs, and the allocator must continue to route each
free by pointer ownership. Reset/unload markers remain useful for leak analysis,
but only repeated cross-epoch survivors may be classified as candidates.

### Dynamic Warden module is the compatibility boundary

Normal Game `GetProcAddress` sites do not resolve SMem names. However,
`sub_6F885910` is the Warden client module loader. It decompresses executable
code, loads a module-selected list of DLLs, and resolves imported functions by
either name or ordinal before applying executable page protection. Its payload
is supplied dynamically, so a server-provided Warden module could in principle
import Storm APIs not present in Game.dll's static table.

This does not block takeover of the official 401/403/405 path, but it prevents
claiming that static imports describe every possible process caller. The
implemented policy is mixed-domain compatibility with all exported heap APIs
404 and 481-490 detoured. Unknown native pointers continue through the verified
trampoline; managed, corrupted and recently released pointers never fall
through to native Storm.

### Remaining runtime promotion validation

- Capture runtime flag and size histograms for 401/405 during map load, editor
  load, map unload and return-to-menu.
- Mark the exact outer map-load/unload epochs around JASS, terrain and UI
  teardown without treating them as allocator reset points.
- Verify at runtime whether Warden or third-party modules call 404/481-490 and
  preserve their mixed-domain behavior.
- Confirm at least eight-byte returned-pointer alignment for every backend.

## Benefits of full small-block takeover

The primary benefit is 32-bit address-space longevity, not a guaranteed faster
first map load. Storm partitions small allocations by caller-derived logical
heap. Each arena reserves at least 64 KiB, and one caller can accumulate
multiple arenas. A shared backend can reuse free space across call sites and
therefore reduce reservation count, holes, and stranded capacity.

Concrete expected benefits are:

1. Lower virtual-address fragmentation and a later 32-bit VA exhaustion point.
2. Cross-caller reuse instead of free space being trapped in a logical Storm
   heap whose original call site no longer allocates.
3. Unified requested-live, usable, committed and reserved accounting for nearly
   all Game allocations.
4. Complete ownership data for survivor/leak profiling and allocation-domain
   analysis across map epochs.
5. A hybrid fast path: mimalloc size classes and cross-thread free for small
   objects, with TLSF retained for large burst allocations.
6. Better control over backend scavenging and memory-pressure policy than the
   implicit "cleanup on a later Storm allocation" behavior.
7. Consistent OOM telemetry and failure policy instead of opaque per-heap arena
   growth.

The costs are equally concrete. Native Storm small blocks already use only an
eight-byte header, distribute contention over 256 locks, and preserve useful
per-caller lifetime locality. A global backend with a 16-byte private header can
increase tiny-object memory, commit retention, and hot-path latency even while
Virtual Size improves. Full takeover is worthwhile only if the compact header,
flag semantics, mixed ownership, and staged measurements all pass.

## Full exported-heap ABI closure

The final Storm pass used SHA-256
`F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB`.
The confirmed takeover surface and external ABI are:

| Ordinal | Export | Confirmed arguments |
| ---: | --- | --- |
| 401 | SMemAlloc | two unused fastcall registers; size, file, line, flags on stack |
| 403 | SMemFree | pointer, file, line, flags |
| 404 | SMemGetSize | pointer, file, line |
| 405 | SMemReAlloc | two unused fastcall registers; pointer, size, file, line, flags |
| 406 | SMemGetAllocated | three optional output pointers |
| 481 | SMemFindNextBlock | heap ID, previous user pointer, next pointer, 28-byte info |
| 482 | SMemFindNextHeap | current heap ID, next ID, 296-byte info |
| 483/484 | heap lookup | file+line / user pointer |
| 485-490 | explicit heap API | alloc, create, destroy, free, realloc and size |
| 496 | SMemSetOption | value bits, mask bits |

Ordinal 486 takes `(baseAddress, initialSize, flags, sourceFile, sourceLine)`.
The base address must be null, the initial size is page-rounded with a 4 KiB
minimum, and the flags parameter is ignored. Explicit heap IDs begin at
`0x80000001`; ordinal 483 always returns a nonzero 31-bit ID, so the domains are
disjoint. Ordinals 485/488/489/490 use `(heapId, flags, ...)`, and the native
implementation ignores the flags parameter for free and size.

### Enumeration structures

The 28-byte ordinal-481 record contains, in order: structure size, block user
pointer, allocated flag, pointer-valid flag, requested bytes, allocator overhead
and a reserved DWORD. A null previous pointer starts enumeration. A non-null
previous user pointer resumes after that native block.

The 296-byte ordinal-482 record contains heap ID at offset 4, source name at 8,
source line at 268, committed bytes at 276, reserved bytes at 280,
`0x7FFFFFFF` at 284, live allocation count at 288 and requested bytes at 292.
Game's debug overlay sums offsets 276 and 292.

### Corrected lifetime and zero-size semantics

Storm zero-size allocation returns a non-null valid block whose reported size
is zero. A normal small `SMemReAlloc(ptr, 0)` shrinks in place and returns the
same pointer. A large or Realloc-Shuffle block instead allocates another valid
zero-request block and frees the old block. With flag `0x10`, a move is forbidden
and failure leaves the old block unchanged. StormBreaker must reproduce this;
treating zero-size realloc as C `free` is incompatible.

Heap destroy also has persistence semantics. It frees ordinary live blocks,
logs unsuppressed survivors, but preserves allocations made with flag
`0x08000000`; an arena and its logical heap remain active while any such block
exists. Flag `0x04000000` suppresses the leak warning but does not preserve the
block. A managed registry therefore returns to active state after destroy when
persistent survivors remain, and becomes a tombstone only when none remain.

The reproducible, SHA-guarded IDA annotations live in
`tools/ida/apply_storm_memory_annotations.py`.

## Implementation closure (2026-07-13)

The production Detours transaction validates the complete export profile. The
`large` stage installs `401/403/404/405`; lower-threshold stages install
`401/403/404/405/406/481-490/496` atomically. The verified WorldEdit host SHA-256 is
`5F645DB7C436ED2DE0C52712D98ACAF75E518847E6234D4CC1E5C5BEE2D76DFC`.

The following implementation points are complete and covered by x86 tests:

- eight-byte small and sixteen-byte large protected headers;
- exact TLSF/mimalloc allocation-start validation and recent-free rejection;
- fixed-capacity heap registry, explicit native sentinel and persistent destroy;
- all Storm option flags, zero-size behavior, mixed-domain and cross-route
  realloc;
- small-block TLSF/mimalloc in-place realloc, Storm-compatible moving large
  realloc, hybrid routing and the shared 1 GiB requested-live budget;
- 481/482 enumeration, 406 optional outputs and native large-counter repair;
- hook/backend close gates, Release pinning and process-exit OS reclamation;
- SBLP v1/v2 truncation recovery and isolated five-variant benchmark contracts.

This closure is an implementation milestone, not a promotion result. Until the
isolated War3 and WorldEdit workloads satisfy the approved confidence-interval,
address-space and stall thresholds, the runtime defaults remain `large/tlsf`.

### Runtime regression finding

The first manual 2026-07-13 hybrid/mimalloc trials were both actually
`mode=large`, not full small-block takeover. Their log showed three abnormal
startup gaps totaling about 332 ms. The active log was 142,662,137 bytes while
all backup slots already existed: `MoveFileA` could not replace them, rotation
ignored every failure, and each subsequent log line repeated close, four failed
moves, reopen and size query. Rotation now replaces the oldest backup, uses
delete-sharing and backs off for 60 seconds on failure.

The same pass restored large-stage compatibility: only core 401/403/404/405 are
detoured, native small allocation bypasses registry/statistics when diagnostics
are off, large realloc always moves, and a hybrid-large build does not initialize
an unreachable mimalloc route. Full exported takeover remains available only in
the lower-threshold stages pending isolated interaction validation.

### Full-takeover periodic-stall finding

The first confirmed `mode=full backend=hybrid scope=all` manual run on
2026-07-13 entered the map successfully with no rejected pointers or allocator
failures. After 60 seconds it held 1,316,768 managed blocks and 414 MiB of
requested-live memory. The user observed a regular roughly one-second hitch.

Two periodic main-thread costs existed in the implementation:

1. Vendored mimalloc v3.3.2 defaults `mi_option_purge_delay` to 1000 ms. When a
   page becomes empty, the allocation/free thread that next observes the
   expiry can walk purge ranges and issue Windows decommit calls. StormBreaker
   now defaults this option to `-1`; empty pages remain reusable inside the
   dedicated heap, while explicit memory-pressure collection temporarily
   enables a forced purge.
2. Game's diagnostic ordinal-482 loop advances one heap cursor per call. The
   adapter previously recollected every native heap and copied all 16,384
   registry slots on every cursor step, then linearly searched managed heaps.
   A complete display pass was therefore quadratic in heap count. It now
   builds one weakly-consistent snapshot at cursor zero, sorts lookup indexes,
   and reuses that snapshot for the complete cursor chain. Native order remains
   unchanged and managed-only IDs are returned in ascending order.

The control panel exposes ordinal-482 calls and snapshot rebuilds so a normal
enumeration should show many calls but one rebuild. This change still requires
an in-game full-mode retest before full takeover can be promoted.

### Full-takeover load-time regression finding

After the periodic-stall fixes, a manual full/hybrid run still increased the
same map's ready time from the earlier roughly 21 seconds to roughly 32 seconds.
The user confirmed that this load regression predated the purge and ordinal-482
fixes, so it is a separate hot-path problem. The corresponding 60-second sample
held 1,313,458 managed blocks, 412 MiB requested-live, 672 MiB reserved and
597 MiB committed, with zero allocation failures/rejected pointers,
`degraded=2`, and ordinal-482 calls/rebuilds of `6116/5`.

At that scale, even a few microseconds of fixed work per successful allocation
accumulate into seconds. The x86 review found repeated route selection,
lifecycle TLS bookkeeping, two unconditional recently-freed-table CAS
operations, several 64-bit diagnostic `cmpxchg8b` counters, per-allocation peak
CAS updates, and a second mimalloc metadata lookup for usable size. These have
been removed or moved off the net-growth path without relaxing the 1 GiB live
budget, registry destroy guard, pointer checks, or requested-live accounting.

IDA confirms that ordinal 483 reaches `StormHeap_ComputeIndex` at `0x1502AD60`.
It returns a nonzero 31-bit ID derived from source file and line; native Storm
only keeps a one-entry caller cache. Registry slot hints remain epoch-validated
and identity-checked; a stale or conflicting hint falls back to normal probing
rather than spinning.

The first process-wide caller cache used 4,096-entry open addressing. Runtime
evidence disproved its sizing and complexity assumptions: the 2026-07-13 full
hybrid run reached `callerCache=372736/6624677` after 60 seconds and map-ready
took 68.72 seconds. Once the table filled, one miss could inspect all 4,096
entries before the native call and again while holding the publication lock.
The per-miss 64-bit diagnostic increment and repeated module queries added more
hot-path contention. This was the direct cause of the 68.72-second regression.

The replacement is a 16,384-entry, eight-way set-associative append-only cache.
Every lookup and publication examines at most eight entries; a full set records
`saturated` and immediately keeps the native result. Dynamic or non-core-image
caller names record `bypass` and are never retained past their valid lifetime.
Core module ranges are captured once, obvious non-core dynamic callers bypass
the cache before probing, and hit/miss/bypass/saturation counters are
accumulated per thread in batches of 4,096. Exact cache occupancy is reported as
`entries`. A Win32 regression test now
forces 32,768 unique immutable callers plus dynamic-name bypasses. This proves
the bounded saturation behavior in the mock environment; map-ready performance
still requires a new manual run.

Heap destruction was tightened in the same pass. Ordinals 481/488/490 now hold
the heap generation guard across managed and native operations. Ordinal 487
only commits a tombstone when native destroy succeeds and ordinal 481 reports
no allocated survivor, including zero-request persistent blocks; otherwise it
restores Active/Native state. A failed sentinel free restores registry
ownership.

The control heartbeat reports
`callerCache=hits/misses/bypasses/saturated entries=N`. Full/hybrid remains a
diagnostic candidate rather than the default until the bounded replacement is
measured in the actual map-load workflow.

### Offline algorithm baseline and linear-time heap operations

Warcraft III was intentionally not used while the map-development workspace was
occupied. A deterministic Win32/x86 allocator harness now replays map-load,
caller-locality, small-churn, realloc, editor-burst and cross-thread traces in a
fresh process per sample. It also has takeover-only heap-enumeration and
heap-destroy traces. The runner preserves raw samples and computes paired,
seeded bootstrap confidence intervals; the complete contract is documented in
`Document/StormBreaker_Allocator_Benchmark.md`.

Ordinal 481 had the same cursor-chain hazard previously fixed for 482. Managed
blocks were recollected for every returned block, turning a chain into O(N
squared). It now enumerates native records first, creates one managed snapshot
when the chain crosses into managed records, and reuses that snapshot until the
chain ends. Ordinal 487 likewise builds one managed snapshot before freeing a
heap instead of rescanning all managed blocks after every free. Runtime counters
distinguish calls, snapshot builds and snapshot block counts. Standard tests
enumerated 250,000 blocks in about 122 ms and destroyed 500,000 blocks in about
99 ms with exactly one snapshot each.

TLSF ownership lookup also degraded with pool growth. Extra pools are now kept
sorted by base address; ownership and exact allocation-start validation use one
binary range lookup followed by one TLSF check. The old linear path exists only
under `STORMBREAKER_TESTING` for a controlled factor. Standard A/B results with
a forced 4 MiB initial pool improved map-load by 11.58% (95% CI -15.72% to
-3.06%) and realloc by 9.64% (CI -17.87% to -7.88%) without changing Private or
Virtual usage, so the index is permanently enabled in production.

The caller resolver retains the bounded 16,384-entry shared set-associative
table. Its optional direct-mapped thread cache now defaults to 256 entries,
commits only the selected capacity, and releases the allocation when the thread
exits. A 1024-entry cache did not show a repeatable throughput advantage; the
smaller default is a working-set and lifetime correction rather than a claimed
map-load speedup.

The first multi-allocator standard matrix rejects both attractive shortcuts.
Per-thread rpmalloc is much faster on every tested trace but retains hundreds of
MiB after drain and cannot provide Storm's exact process-wide enumeration or
heap destroy without an additional live-block index. The fixed-class segregated
arena drains cleanly and is fast on map/realloc, but regresses cross-thread free
and consumes more Virtual address space. mimalloc and the current hybrid are
faster than TLSF on the production map-load trace but exceed the 3% Private and
Virtual gates. These remain diagnostic implementations.

### Allocator candidate closure

The follow-up candidate work used only the deterministic x86 logic harness; it
did not launch Warcraft III or WorldEdit.

Four-shard TLSF now has a fixed 64 KiB x86 address directory, aggregate 1 GiB
reservation accounting, exact cross-shard free/query, and all-shard snapshot
validation. The standard matrix still rejected it: cross-thread wall time
improved 6.19%, while map-load regressed 11.26% and its peak Private/Virtual
rose 8.80%/8.48%. Shard-local fragmentation and 137 extensions versus 31 for
single TLSF dominate the synthetic map shape. The backend remains selectable
as `tlsf-sharded` for diagnostics only.

The benchmark-only segregated allocator also tested a per-span lock-free
remote-free queue. It made cross-thread 3.41% slower and map-load 4.89% slower
without saving memory, showing that per-block cache-line exchange costs more
than the existing short per-class SRW section for this workload.

mimalloc's x86 default reserves arenas in 128 MiB increments. Reducing the
diagnostic arena size to 8 MiB lowered peak Virtual by 7.79% on map-load,
29.34% on realloc and 9.63% on cross-thread, with no statistically reliable
wall regression. Private/Commit moved by less than 1%, and long realloc traffic
eventually accumulated the same total reservation. Varying full-page retention
and candidate-page search depth changed memory by less than 0.2%. This improves
VA granularity but cannot promote mimalloc over TLSF.

rpmalloc's high post-drain retention was not left as an unexplained upstream
property. Benchmark extensions varied its global cache multiplier and its
per-thread one-span cache limit. Global-cache-off plus a 64-span thread limit
substantially reduced single-thread drain Private, but the cross-thread trace
was unaffected. When an allocating thread exits with live blocks, rpmalloc
orphans that heap; later remote frees remain deferred until the heap is adopted
and collected. A forced global orphan traversal would require new locking and
would still not provide the exact block visitation required by ordinals
481/487, so this route is not production-safe.

The resulting decision is conservative: single TLSF remains the default.
Future allocator work must begin with exact visitation and orphan-safe remote
reclamation, then pass the existing standard traces before any in-game test.

### 2026 allocator literature pass and project-specific results

The literature pass did not justify replacing TLSF wholesale. Mimalloc's
page-local sharded free lists and temporal cadence are already represented by
the pinned mimalloc 3.3.2 candidate, but that candidate fails this project's
x86 Private/Virtual gate. snmalloc and BatchIt target producer-consumer remote
free traffic with batched message passing; the corresponding bounded
remote-free experiments did not improve StormBreaker's mostly short,
single-owner critical sections. Mesh requires page aliasing and remapping,
which is incompatible with Storm's naked-pointer ABI and 32-bit address-space
risk. The 2026 reassessment of custom allocation reinforces the measured
result: generic size-class replacement often has little application-level
benefit, while explicit region/lifetime boundaries remain useful.

Primary sources reviewed:

- [Mimalloc: Free List Sharding in Action](https://www.microsoft.com/en-us/research/publication/mimalloc-free-list-sharding-in-action/)
- [snmalloc: A Message Passing Allocator](https://www.microsoft.com/en-us/research/uploads/prod/2020/04/snmalloc.pdf)
- [BatchIt: Optimizing Message-Passing Allocators for Producer-Consumer Workloads](https://www.ietfng.org/nwf/_downloads/0226ee0c2f26bc4cc8a1a7cd52d3809a/2024-ismm-batchit.pdf)
- [Mesh: Compacting Memory Management for C/C++ Applications](https://arxiv.org/abs/1902.04738)
- [Reconsidering "Reconsidering Custom Memory Allocation"](https://arxiv.org/abs/2605.17119)

The successful adaptations therefore operate around TLSF rather than replacing
it:

1. A 32 KiB insert-only Bloom membership filter prevents the fixed heap
   registry from degenerating into 16,384 probes per unknown ID after
   saturation. Nine paired runs reduced saturation wall time by 99.48% without
   changing lookup correctness.
2. Clustered high-address placement separates StormBreaker growth from normal
   bottom-up process allocation. Five standard map pairs improved the largest
   contiguous free region by 39.41% with neutral p99 and memory totals.
3. TLSF's coalescing invariant makes empty-pool detection O(1). On the standard
   fragmented trim trace this reduced 2.520 ms to 2.0 microseconds. Ordinal 487
   now uses this explicit heap-lifetime boundary to return empty TLSF growth
   pools immediately.

Frequent main-pool decommit was rejected despite an 83.86% idle Commit saving:
repeated recommit raised wall time 15.20% and sampled p99 roughly 23.6x. A
32 MiB default main pool was also rejected by standard map/editor timing. The
production baseline remains 64 MiB single TLSF, with system placement,
constant-time trim, the binary range index, and saturation-safe registry
lookup. Real Warcraft III and WorldEdit validation remains the final promotion
gate; it was intentionally not run in this phase.

### Real-game invalidation of clustered placement (2026-07-14)

The first real-game validation after the offline address-space pass invalidated
clustered placement as a production default. Large/TLSF became unresponsive and
large/hybrid exited before its first 60-second heartbeat. In large mode hybrid
does not initialize or route to mimalloc, so the two failures share the same
TLSF allocation path. Full/mimalloc entered the map but required about 48
seconds versus 24 seconds native and the earlier 21-second large/TLSF build.
Production now defaults to the original Windows system placement. Clustered
placement remains opt-in so its offline fragmentation result is preserved
without exposing normal players to high-address compatibility risk.

### Direct-root validation and takeover hot-path closure (2026-07-14)

Non-isolated validation moved to `E:\Work\Warcraft III` at the user's request.
The runner validates the exact Storm/Game hashes, system SysWOW64 d3d9, loaded
ASI path/hash and owned War3 PID before it can stop a process. Large/TLSF and
large/hybrid both completed 100-second direct-root smoke runs with no crash or
hang after restoring the TLSF system-placement default. A later diagnostic run
was stopped by the 2 GiB system-Commit headroom guard at roughly 15 seconds;
that result is guard-stopped, not a game failure.

Real logs exposed millions of caller-cache bypasses in large mode. The source
was `SMemReAlloc(nullptr, small)`: unlike `SMemAlloc`, it performed ordinal 483
and registry work before eventually delegating to native Storm. It now uses the
same below-threshold fast bypass, and a regression test proves that the native
483 mock is not called.

Storm ordinal 483 ultimately hashes through ordinal 502 and the 16-DWORD table
at Storm RVA `0x43F18`. StormBreaker now implements that unsigned-wraparound
algorithm directly, including null names, high bytes, the 31-bit mask and the
zero-to-one mapping. Installation compares eight direct results with the
unhooked native ordinal before the Detours transaction. Only an exact match
publishes `callerHash=direct-verified`; otherwise all calls retain the native
trampoline. A 1 KiB byte-delta table removes one table load and subtraction per
name byte without changing any fixed vector.

Three registry shortcuts were measured and rejected. A thread-local heap-ID
slot cache increased hit rate but not application throughput, direct prediction
of the initial open-addressing slot penalized displaced heaps, and hazard-style
generation publication improved cross-thread tails while regressing the
single-thread map path. Production therefore retains the epoch-validated caller
slot hint only for immutable module strings and the existing operation reference
guard required by ordinal 487.

The recent-free table remained a measurable cost because allocation clears one
possible stale entry and free both queries and publishes an entry. Its index is
now the high 16 bits of a 32-bit Fibonacci multiply over `pointer >> 3`, replacing
three xor stages and two multiplies in Mix32. Capacity, exact pointer comparison
and cross-thread rejection are unchanged. Representative 65,536-address tests
improved unique-slot coverage by more than 10,000 entries; quick map p99 improved
19.72% with a confidence interval excluding zero, standard realloc wall improved
4.31%, and standard map confirmation remained statistically neutral.

### TLSF false-OOM boundary and adaptive growth (2026-07-14)

The current locked-TLSF build passed two direct, non-isolated 67-70 second runs
from `E:\Work\Warcraft III`, but the first two runs exposed exactly two managed
fallbacks at the 60-second heartbeat. The diagnostic artifact
`warcraftiii-large-tlsf-fallback-size-20260714` records the last request as
16,658,432 bytes on ordinal 401. This was not requested-budget exhaustion:
requested-live was 123 MiB and reserved was 384 MiB.

TLSF's 32 second-level classes round that near-16-MiB request above the class of
a free block inside a 16 MiB pool. The old backend calculated growth from raw
bytes plus 64 KiB, so it repeatedly added a pool that could contain the bytes
but could never be selected by `mapping_search`. This explained both stable
native fallback and the accumulation of empty growth pools.

The backend now asks TLSF for a conservative class-aware fresh-pool size,
including base alignment, memalign gap, class rounding and sentinel overhead.
Large extensions use 64 KiB tight sizing rather than a full additional 16 MiB
step. On the already-failed growth path it also removes empty non-fitting pools;
if the retry after adding a pool still fails, that new pool is rolled back.
Normal successful allocation and free paths are unchanged.

The final exact-binary artifact `warcraftiii-large-tlsf-final-exact-20260714`
loaded ASI SHA-256
`CC1B6B9E6E704668FB224BA2476D10CBE40123CA162E10AA6FE18E217D659E37`
and survived the full observation with valid Storm/Game/system-d3d9/ASI
modules, no hung sample, no guard stop and registry restoration. Its heartbeat
reported `fallback=0` and `degraded=0`. Both this run and the diagnostic run
had exactly 123 MiB requested; reserved fell from 384 MiB to 204 MiB, a
180 MiB (46.9%) reduction, while two native fallbacks became zero. Observed
process Commit peak fell from about 1090 MiB to 867 MiB, but that process-level
number is workload-state sensitive and is not treated as statistically
significant. These runs validate crash behavior and allocator health, not
map-ready timing.
