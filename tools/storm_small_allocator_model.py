"""Executable model of the Warcraft III 1.27a Storm small-block allocator.

The model mirrors the verified Storm.dll rules that affect fragmentation:

* one arena chain per caller-derived heap id;
* 8-byte alignment and an 8-byte normal block header;
* nine free-list bins selected by min(total_size >> 5, 8);
* native first-nonempty-bin search and deferred coalescing;
* 64 KiB initial reserve, 4 KiB initial commit, geometric arena growth.

It intentionally models allocator policy, not pointer contents or Win32 calls.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from typing import Iterable


SMALL_REQUEST_LIMIT = 0xFE7B
INITIAL_RESERVE = 0x10000
INITIAL_COMMIT = 0x1000
MAX_GEOMETRIC_RESERVE = 0x10000000
MIN_SPLIT = 0x10
FREE_FLAG = 0x02
PREVIOUS_FREE_FLAG = 0x10
DEBUG_FLAG = 0x01


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def block_layout(requested: int, debug: bool = False) -> tuple[int, int]:
    if requested < 0 or requested > SMALL_REQUEST_LIMIT:
        raise ValueError("request is outside Storm's native small-block path")
    fixed = 10 if debug else 8
    unaligned = requested + fixed
    padding = (-unaligned) & 7
    return unaligned + padding, padding


def bin_index(total_size: int) -> int:
    return min(total_size >> 5, 8)


def arena_header_size(source_name_length: int) -> int:
    if source_name_length < 0:
        raise ValueError("source name length cannot be negative")
    return align_up(112 + source_name_length, 8)


@dataclass(eq=False)
class Block:
    start: int
    total: int
    requested: int
    padding: int
    flags: int = 0
    allocated: bool = True

    @property
    def end(self) -> int:
        return self.start + self.total

    @property
    def previous_free(self) -> bool:
        return bool(self.flags & PREVIOUS_FREE_FLAG)

    def set_previous_free(self, enabled: bool) -> None:
        if enabled:
            self.flags |= PREVIOUS_FREE_FLAG
        else:
            self.flags &= ~PREVIOUS_FREE_FLAG


@dataclass
class Arena:
    reserve: int
    committed: int
    commit_granularity: int
    data_start: int
    bump: int = 0
    blocks: list[Block] = field(default_factory=list)
    bins: list[list[Block]] = field(
        default_factory=lambda: [[] for _ in range(9)]
    )
    adjacent_free_hint: int = 0
    live_count: int = 0
    requested_live: int = 0

    def __post_init__(self) -> None:
        self.bump = self.data_start

    def insert_free(self, block: Block) -> None:
        self.bins[bin_index(block.total)].insert(0, block)

    def remove_free(self, block: Block) -> None:
        self.bins[bin_index(block.total)].remove(block)

    def next_block(self, block: Block) -> Block | None:
        index = self.blocks.index(block) + 1
        return self.blocks[index] if index < len(self.blocks) else None

    def rebuild_free_lists(self) -> None:
        merged: list[Block] = []
        for block in self.blocks:
            if (
                not block.allocated
                and merged
                and not merged[-1].allocated
                and merged[-1].end == block.start
                and merged[-1].total + block.total <= 0xFFFF
            ):
                merged[-1].total += block.total
                continue
            merged.append(block)
        self.blocks = merged
        self.bins = [[] for _ in range(9)]
        for block in self.blocks:
            if not block.allocated:
                self.bins[bin_index(block.total)].append(block)
        self.adjacent_free_hint = 0

    def ensure_committed(self, end: int) -> bool:
        if end > self.reserve:
            return False
        if end > self.committed:
            self.committed = min(
                self.reserve, align_up(end, self.commit_granularity)
            )
        return True


@dataclass(frozen=True)
class Allocation:
    handle: int
    heap_id: int
    arena: Arena
    block: Block


class StormSmallAllocator:
    """Policy model with native and two minimally corrected search modes."""

    VALID_POLICIES = {"storm", "search-fixed", "coalesce-fixed"}

    def __init__(self, policy: str = "storm", source_name_length: int = 24):
        if policy not in self.VALID_POLICIES:
            raise ValueError(f"unknown policy: {policy}")
        self.policy = policy
        self.source_name_length = source_name_length
        self.heaps: dict[int, list[Arena]] = {}
        self.allocations: dict[int, Allocation] = {}
        self.next_handle = 1
        self.search_steps = 0
        self.rebuilds = 0
        self.higher_bin_misses = 0
        self.cleanup_pending: Arena | None = None
        self.cleanup_runs = 0

    def _cleanup_empty_arenas(self) -> None:
        for heap_id in list(self.heaps):
            retained = [
                arena for arena in self.heaps[heap_id] if arena.live_count != 0
            ]
            if retained:
                self.heaps[heap_id] = retained
            else:
                del self.heaps[heap_id]
        self.cleanup_pending = None
        self.cleanup_runs += 1

    def _new_arena(self, previous: Arena | None) -> Arena:
        if previous is None:
            reserve = INITIAL_RESERVE
            committed = INITIAL_COMMIT
            granularity = INITIAL_COMMIT
        else:
            reserve = previous.reserve
            if reserve < MAX_GEOMETRIC_RESERVE:
                reserve *= 2
            committed = reserve >> 3
            granularity = reserve >> 3
        header = arena_header_size(self.source_name_length)
        if header > committed:
            committed = align_up(header, granularity)
        return Arena(reserve, committed, granularity, header)

    @staticmethod
    def _candidate_from_bin(blocks: Iterable[Block], needed: int) -> Block | None:
        best: Block | None = None
        best_remainder = 0x7FFFFFFF
        tolerance = 16
        for block in blocks:
            remainder = (
                block.total - needed
                if block.total >= needed
                else (1 << 32) + block.total - needed
            )
            if remainder < best_remainder:
                best = block
                best_remainder = remainder
                if remainder < tolerance:
                    break
                tolerance += 4
        return best

    def _find_candidate(self, arena: Arena, needed: int) -> Block | None:
        target = bin_index(needed)
        if arena.adjacent_free_hint >= 4 and not arena.bins[target]:
            arena.rebuild_free_lists()
            self.rebuilds += 1

        first = next((i for i in range(target, 9) if arena.bins[i]), None)
        if first is None:
            return None

        self.search_steps += len(arena.bins[first])
        candidate = self._candidate_from_bin(arena.bins[first], needed)
        if self.policy == "storm":
            if candidate is None and any(
                block.total >= needed
                for index in range(first + 1, 9)
                for block in arena.bins[index]
            ):
                self.higher_bin_misses += 1
            return candidate

        # Minimal correction: preserve Storm's normal first-bin behavior and
        # only pay for higher-bin walks after that bin contains no fitting block.
        if candidate is None:
            for index in range(first + 1, 9):
                if not arena.bins[index]:
                    continue
                self.search_steps += len(arena.bins[index])
                candidate = self._candidate_from_bin(arena.bins[index], needed)
                if candidate is not None:
                    break
        if (
            candidate is None
            and self.policy == "coalesce-fixed"
            and arena.adjacent_free_hint >= 4
        ):
            arena.rebuild_free_lists()
            self.rebuilds += 1
            for index in range(target, 9):
                if not arena.bins[index]:
                    continue
                self.search_steps += len(arena.bins[index])
                candidate = self._candidate_from_bin(arena.bins[index], needed)
                if candidate is not None:
                    break
        return candidate

    def _allocate_from_free(
        self, arena: Arena, block: Block, requested: int, needed: int,
        padding: int, debug: bool,
    ) -> Block:
        arena.remove_free(block)
        next_block = arena.next_block(block)
        if block.previous_free or (
            next_block is not None and not next_block.allocated
        ):
            arena.adjacent_free_hint = max(0, arena.adjacent_free_hint - 1)

        old_total = block.total
        old_end = block.end
        remainder = old_total - needed
        prior_flag = block.flags & PREVIOUS_FREE_FLAG
        block.allocated = True
        block.requested = requested
        block.padding = padding
        block.flags = prior_flag | (DEBUG_FLAG if debug else 0)

        if old_end == arena.bump:
            block.total = needed
            arena.bump = block.end
        elif remainder < MIN_SPLIT:
            block.total = old_total
            block.padding += remainder
            if next_block is not None:
                next_block.set_previous_free(False)
        else:
            block.total = needed
            remainder_block = Block(
                start=block.end,
                total=remainder,
                requested=0,
                padding=0,
                flags=FREE_FLAG,
                allocated=False,
            )
            index = arena.blocks.index(block)
            arena.blocks.insert(index + 1, remainder_block)
            arena.insert_free(remainder_block)
            after = arena.next_block(remainder_block)
            if after is not None:
                after.set_previous_free(True)
        return block

    def allocate(self, heap_id: int, requested: int, debug: bool = False) -> int:
        needed, padding = block_layout(requested, debug)
        arenas = self.heaps.setdefault(heap_id, [])
        if not arenas:
            arenas.insert(0, self._new_arena(None))
        arena = arenas[0]
        allocation_entry_arena = arena

        candidate = self._find_candidate(arena, needed)
        if candidate is not None:
            block = self._allocate_from_free(
                arena, candidate, requested, needed, padding, debug
            )
        else:
            if arena.bump + needed > arena.reserve:
                arena = self._new_arena(arena)
                arenas.insert(0, arena)
            if not arena.ensure_committed(arena.bump + needed):
                raise MemoryError("Storm arena cannot commit the requested block")
            block = Block(
                start=arena.bump,
                total=needed,
                requested=requested,
                padding=padding,
                flags=DEBUG_FLAG if debug else 0,
            )
            arena.blocks.append(block)
            arena.bump += needed

        arena.live_count += 1
        arena.requested_live += requested
        handle = self.next_handle
        self.next_handle += 1
        self.allocations[handle] = Allocation(handle, heap_id, arena, block)
        if (
            self.cleanup_pending is not None
            and allocation_entry_arena is not self.cleanup_pending
        ):
            self._cleanup_empty_arenas()
        return handle

    def free(self, handle: int) -> None:
        allocation = self.allocations.pop(handle)
        arena = allocation.arena
        block = allocation.block
        if not block.allocated:
            raise ValueError("double free")
        arena.live_count -= 1
        arena.requested_live -= block.requested

        if block.end == arena.bump:
            arena.bump = block.start
            arena.blocks.remove(block)
        else:
            next_block = arena.next_block(block)
            was_previous_free = block.previous_free
            block.allocated = False
            block.requested = 0
            block.padding = 0
            block.flags = (PREVIOUS_FREE_FLAG if was_previous_free else 0) | FREE_FLAG
            arena.insert_free(block)
            if next_block is not None:
                next_was_free = not next_block.allocated
                next_block.set_previous_free(True)
            else:
                next_was_free = False
            if was_previous_free or next_was_free:
                arena.adjacent_free_hint += 1

        if arena.live_count == 0:
            arena.blocks.clear()
            arena.bins = [[] for _ in range(9)]
            arena.bump = arena.data_start
            arena.adjacent_free_hint = 0
            if allocation.heap_id < 0x80000000:
                self.cleanup_pending = arena

    def stats(self) -> dict[str, int | float | str]:
        arenas = [arena for chain in self.heaps.values() for arena in chain]
        live_blocks = [
            block for arena in arenas for block in arena.blocks if block.allocated
        ]
        free_blocks = [
            block for arena in arenas for block in arena.blocks if not block.allocated
        ]
        requested = sum(arena.requested_live for arena in arenas)
        reserved = sum(arena.reserve for arena in arenas)
        committed = sum(arena.committed for arena in arenas)
        live_block_bytes = sum(block.total for block in live_blocks)
        free_bytes = sum(block.total for block in free_blocks)
        return {
            "policy": self.policy,
            "heapCount": len(self.heaps),
            "arenaCount": len(arenas),
            "liveBlocks": len(live_blocks),
            "requestedLiveBytes": requested,
            "liveBlockBytes": live_block_bytes,
            "internalFragmentBytes": live_block_bytes - requested,
            "freeBlockBytes": free_bytes,
            "reservedBytes": reserved,
            "committedBytes": committed,
            "reserveUtilization": requested / reserved if reserved else 1.0,
            "commitUtilization": requested / committed if committed else 1.0,
            "searchSteps": self.search_steps,
            "rebuilds": self.rebuilds,
            "cleanupRuns": self.cleanup_runs,
            "higherBinMisses": self.higher_bin_misses,
        }


def run_bin_trap(policy: str) -> dict[str, int | float | str]:
    allocator = StormSmallAllocator(policy)
    small = allocator.allocate(1, 24)   # total 32, bin 1
    large = allocator.allocate(1, 56)   # total 64, bin 2
    allocator.allocate(1, 8)            # live tail prevents bump rewind
    allocator.free(large)
    allocator.free(small)
    allocator.allocate(1, 48)           # total 56, should reuse bin 2
    return allocator.stats()


def run_small_churn(
    policy: str, operations: int, callers: int, seed: int
) -> dict[str, int | float | str]:
    rng = random.Random(seed)
    allocator = StormSmallAllocator(policy)
    live: list[int] = []
    for _ in range(operations):
        if live and rng.random() < 0.44:
            index = rng.randrange(len(live))
            allocator.free(live.pop(index))
            continue
        roll = rng.random()
        if roll < 0.45:
            size = rng.randint(1, 32)
        elif roll < 0.75:
            size = rng.randint(33, 128)
        elif roll < 0.94:
            size = rng.randint(129, 1024)
        else:
            size = rng.randint(1025, SMALL_REQUEST_LIMIT)
        live.append(allocator.allocate(rng.randrange(callers), size))
    return allocator.stats()


def theoretical_summary() -> dict[str, float | int | str]:
    normal_overheads = [block_layout(size)[0] - size for size in range(8)]
    debug_overheads = [block_layout(size, True)[0] - size for size in range(8)]
    return {
        "normalHeaderBytes": 8,
        "normalAbsoluteOverheadMin": min(normal_overheads),
        "normalAbsoluteOverheadMax": max(normal_overheads),
        "normalUniformResidueMean": sum(normal_overheads) / 8,
        "debugAbsoluteOverheadMin": min(debug_overheads),
        "debugAbsoluteOverheadMax": max(debug_overheads),
        "debugUniformResidueMean": sum(debug_overheads) / 8,
        "oneByteInitialArenaRequestedUtilization": 1 / INITIAL_RESERVE,
        "externalFragmentationSupremum": 1.0,
        "externalFragmentationBound": (
            "No non-trivial bound under arbitrary lifetimes; one live block can pin an arena."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenario", choices=("theory", "bin-trap", "small-churn"),
        default="small-churn"
    )
    parser.add_argument("--operations", type=int, default=200_000)
    parser.add_argument("--callers", type=int, default=497)
    parser.add_argument("--seed", type=int, default=0x127A)
    args = parser.parse_args()

    if args.operations <= 0 or args.callers <= 0:
        parser.error("operations and callers must be positive")
    if args.scenario == "theory":
        output: object = theoretical_summary()
    else:
        runner = run_bin_trap if args.scenario == "bin-trap" else None
        output = []
        for policy in ("storm", "search-fixed", "coalesce-fixed"):
            if runner:
                output.append(runner(policy))
            else:
                output.append(
                    run_small_churn(policy, args.operations, args.callers, args.seed)
                )
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
