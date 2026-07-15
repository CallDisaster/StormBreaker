from __future__ import annotations

import unittest

from tools.storm_small_allocator_model import (
    INITIAL_RESERVE,
    StormSmallAllocator,
    arena_header_size,
    bin_index,
    block_layout,
    run_bin_trap,
    theoretical_summary,
)


class LayoutTests(unittest.TestCase):
    def test_normal_layout_matches_storm_alignment(self) -> None:
        self.assertEqual(block_layout(0), (8, 0))
        self.assertEqual(block_layout(1), (16, 7))
        self.assertEqual(block_layout(8), (16, 0))
        self.assertEqual(block_layout(0xFE7B), (0xFE88, 5))

    def test_debug_layout_adds_tail_canary(self) -> None:
        self.assertEqual(block_layout(0, True), (16, 6))
        self.assertEqual(block_layout(6, True), (16, 0))

    def test_bins_and_dynamic_arena_header(self) -> None:
        self.assertEqual([bin_index(size) for size in (8, 32, 64, 248, 256)],
                         [0, 1, 2, 7, 8])
        self.assertEqual(arena_header_size(0), 112)
        self.assertEqual(arena_header_size(5), 120)


class NativePolicyTests(unittest.TestCase):
    def test_native_first_nonempty_bin_misses_higher_fit(self) -> None:
        native = run_bin_trap("storm")
        fixed = run_bin_trap("search-fixed")
        self.assertEqual(native["higherBinMisses"], 1)
        self.assertEqual(fixed["higherBinMisses"], 0)
        self.assertGreater(native["freeBlockBytes"], fixed["freeBlockBytes"])

    def test_free_tail_rewinds_bump_pointer(self) -> None:
        allocator = StormSmallAllocator()
        first = allocator.allocate(7, 32)
        second = allocator.allocate(7, 64)
        arena = allocator.heaps[7][0]
        before = arena.bump
        allocator.free(second)
        self.assertLess(arena.bump, before)
        allocator.free(first)
        self.assertEqual(arena.bump, arena.data_start)

    def test_geometric_arena_growth_matches_storm(self) -> None:
        allocator = StormSmallAllocator()
        live = []
        while len(allocator.heaps.get(1, [])) < 2:
            live.append(allocator.allocate(1, 0x4000))
        arenas = allocator.heaps[1]
        self.assertEqual(arenas[1].reserve, INITIAL_RESERVE)
        self.assertEqual(arenas[0].reserve, INITIAL_RESERVE * 2)

    def test_internal_fragmentation_bound(self) -> None:
        theory = theoretical_summary()
        self.assertEqual(theory["normalAbsoluteOverheadMin"], 8)
        self.assertEqual(theory["normalAbsoluteOverheadMax"], 15)
        self.assertEqual(theory["normalUniformResidueMean"], 11.5)


if __name__ == "__main__":
    unittest.main()
