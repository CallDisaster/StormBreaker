from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import stormbreaker_benchmark as bench


def make_config(root: Path) -> bench.BenchmarkConfig:
    return bench.BenchmarkConfig(
        war3_root=root / "war3",
        map_path=root / "war3" / "map.w3x",
        asi_path=root / "build" / "StormBreaker.asi",
        autotest_dir=root / "AutoTest",
        output_dir=root / "out",
    )


def healthy_metrics_row(variant: str, stalls: int = 3) -> dict[str, object]:
    selected = bench.variant_config(variant)
    backend = str(selected["backend"])
    takeover = str(selected["takeoverMode"])
    return {
        "hooksInstalled": True,
        "memoryBackend": backend,
        "takeoverMode": takeover,
        "backend": {
            "name": backend,
            "fallbackAllocations": 0,
            "failures": 0,
        },
        "takeover": {
            "mode": takeover,
            "managedFallbackCalls": 0,
            "nativeFallbackCalls": 0,
            "degradedCalls": 0,
            "registryInsertFailures": 0,
        },
        "pool": {"failureCount": 0},
        "latency": {
            "p99Nanoseconds": 1000,
            "allocateP99Nanoseconds": 900,
            "over10msCount": stalls,
        },
        "profiler": {
            "dropped": 0,
            "writeErrors": 0,
            "incomplete": False,
        },
    }


def measured_rounds(
    *,
    hybrid_memory: float = 102.0,
    hybrid_slope: float = 0.7,
    hybrid_free: float = 115.0,
    hybrid_stalls: float = 7.0,
) -> list[dict[str, object]]:
    values = {
        "off": (95.0, 19.0, 900.0, 1.2, 90.0, 12.0),
        "large-tlsf": (100.0, 20.0, 1000.0, 1.0, 100.0, 10.0),
        "full-tlsf": (101.0, 20.0, 1020.0, 0.9, 105.0, 9.0),
        "full-mimalloc": (101.0, 20.2, 1010.0, 0.8, 108.0, 8.0),
        "full-hybrid": (
            hybrid_memory,
            20.5,
            1050.0,
            hybrid_slope,
            hybrid_free,
            hybrid_stalls,
        ),
    }
    rows: list[dict[str, object]] = []
    for block in range(bench.DEFAULT_MEASURED_CYCLES):
        for variant in bench.VARIANTS:
            memory, ready, p99, slope, free_region, stalls = values[variant]
            rows.append(
                {
                    "phase": "measured",
                    "block": block,
                    "variant": variant,
                    "ok": True,
                    "metrics": {
                        "readyElapsedSec": ready,
                        "measurementPeakWorkingSetMB": memory,
                        "measurementPeakCommitMB": memory,
                        "measurementPeakPrivateMB": memory,
                        "measurementPeakVirtualMB": memory * 2.0,
                        "measurementEndLargestFreeRegionMB": free_region,
                        "measurementEndFreeRegionCount": 100.0,
                        "measurementVirtualGrowthSlopeMBPerSec": slope,
                        "measurementPeakHandleCount": 200.0,
                        "measurementPeakStormAllocatedMB": 50.0,
                        "allocatorP99Nanoseconds": p99,
                        "allocateP99Nanoseconds": p99,
                        "allocatorStallOver10msCount": stalls,
                    },
                }
            )
    return rows


class ScheduleAndScenarioTests(unittest.TestCase):
    def test_five_variant_schedule_is_complete_rotating_and_deterministic(self) -> None:
        first = bench.generate_schedule(1, 10, seed=17)
        second = bench.generate_schedule(1, 10, seed=17)
        self.assertEqual(first, second)
        self.assertEqual(55, len(first))
        width = len(bench.VARIANTS)
        blocks = [first[offset : offset + width] for offset in range(0, len(first), width)]
        for block in blocks:
            self.assertEqual(set(bench.VARIANTS), {row.variant for row in block})
            self.assertEqual(list(range(width)), [row.order for row in block])
        for previous, current in zip(blocks, blocks[1:]):
            self.assertEqual(
                [row.variant for row in previous[1:] + previous[:1]],
                [row.variant for row in current],
            )

    def test_scenario_manifest_represents_ten_fresh_process_cycles(self) -> None:
        schedule = bench.generate_schedule(1, 10, seed=9)
        manifest = bench.build_scenario_manifest(schedule, 10)
        self.assertTrue(manifest["complete"])
        self.assertEqual("fresh-isolated-process-per-cycle", manifest["cycleModel"])
        self.assertEqual(50, manifest["totalMeasuredRounds"])
        for rows in manifest["cyclesByVariant"].values():
            self.assertEqual(list(range(1, 11)), [row["cycle"] for row in rows])


class LaunchAndTelemetryTests(unittest.TestCase):
    def test_variant_environment_and_isolation_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = make_config(Path(temporary))
            kwargs = bench.build_launch_kwargs(
                config,
                "full-hybrid",
                config.output_dir / "round",
                run_id="run",
                session_id="session",
                artifact_root=config.output_dir / "autotest",
            )
            env = json.loads(kwargs["env_overrides_json"])
            self.assertEqual("hybrid", env["STORMBREAKER_MEMORY_BACKEND"])
            self.assertEqual("full", env["STORMBREAKER_TAKEOVER_MODE"])
            self.assertTrue(kwargs["use_isolated_desktop"])
            launch = {
                "windowed": True,
                "envOverrides": env,
                "desktop": {"ok": True, "name": "desk", "handle": 123},
            }
            self.assertTrue(
                bench.validate_isolation_contract(kwargs, launch, "desk")["ok"]
            )
            launch["desktop"] = {"ok": True, "name": "desk", "handle": 0}
            self.assertFalse(
                bench.validate_isolation_contract(kwargs, launch, "desk")["ok"]
            )

            off_kwargs = bench.build_launch_kwargs(
                config,
                "off",
                config.output_dir / "off",
                run_id="run",
                session_id="off",
                artifact_root=config.output_dir / "autotest",
            )
            off_env = json.loads(off_kwargs["env_overrides_json"])
            self.assertNotIn("STORMBREAKER_MEMORY_BACKEND", off_env)
            self.assertNotIn("STORMBREAKER_TAKEOVER_MODE", off_env)

    def test_metrics_fail_closed_on_missing_or_dirty_takeover_state(self) -> None:
        valid = healthy_metrics_row("full-hybrid")
        validation = bench.validate_metrics_rows([valid], "full-hybrid")
        self.assertTrue(validation["ok"], validation["errors"])
        self.assertEqual(3.0, bench.summarize_metrics_rows([valid])["allocatorStallOver10msCount"])

        missing = dict(valid)
        missing.pop("takeoverMode")
        missing.pop("takeover")
        self.assertFalse(bench.validate_metrics_rows([missing], "full-hybrid")["ok"])

        missing_stalls = json.loads(json.dumps(valid))
        missing_stalls["latency"].pop("over10msCount")
        self.assertFalse(
            bench.validate_metrics_rows([missing_stalls], "full-hybrid")["ok"]
        )

        dirty = healthy_metrics_row("full-hybrid")
        dirty["takeover"]["degradedCalls"] = 1  # type: ignore[index]
        self.assertFalse(bench.validate_metrics_rows([dirty], "full-hybrid")["ok"])
        self.assertTrue(bench.validate_metrics_rows([], "off")["ok"])


class AddressSpaceStatisticsTests(unittest.TestCase):
    def test_pe_identity_requires_x86_large_address_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "War3.exe"
            data = bytearray(256)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<H", data, 0x84, bench.IMAGE_FILE_MACHINE_I386)
            struct.pack_into(
                "<H", data, 0x80 + 22, bench.IMAGE_FILE_LARGE_ADDRESS_AWARE
            )
            struct.pack_into("<H", data, 0x80 + 24, bench.PE32_MAGIC)
            image.write_bytes(data)
            identity = bench.read_pe_identity(image)
            self.assertTrue(identity["isWin32X86"])
            self.assertTrue(identity["largeAddressAware"])

    def test_virtual_free_regions_merge_and_clip(self) -> None:
        regions = [
            {"baseAddress": 0, "regionSize": 100, "state": bench.MEM_FREE},
            {"baseAddress": 100, "regionSize": 50, "state": bench.MEM_FREE},
            {"baseAddress": 150, "regionSize": 50, "state": 0x1000},
            {"baseAddress": 200, "regionSize": 200, "state": bench.MEM_FREE},
        ]
        result = bench.summarize_virtual_regions(regions, address_limit=300)
        self.assertEqual(2, result["freeRegionCount"])
        self.assertEqual(150, result["largestFreeRegionBytes"])
        self.assertEqual(250, result["totalFreeAddressSpaceBytes"])

    def test_linear_growth_slope_and_round_summary(self) -> None:
        self.assertEqual(2.0, bench.linear_regression_slope([(0, 1), (1, 3), (2, 5)]))
        samples = [
            {
                "elapsedSec": second,
                "workingSetMB": 10 + second,
                "commitMB": 20 + second,
                "privateMB": 15 + second,
                "virtualMB": 100 + 2 * second,
                "handleCount": 20,
                "largestFreeRegionMB": 500 - second,
                "freeRegionCount": 10 + second,
            }
            for second in range(5)
        ]
        result = bench._collect_round_metrics(samples, 1.0)
        self.assertEqual(2.0, result["measurementVirtualGrowthSlopeMBPerSec"])
        self.assertEqual(496.0, result["measurementEndLargestFreeRegionMB"])
        self.assertEqual(14.0, result["measurementEndFreeRegionCount"])


class ReportGateTests(unittest.TestCase):
    def test_full_hybrid_passes_all_approved_gates(self) -> None:
        result = bench.evaluate_results(
            measured_rounds(),
            measured_blocks=10,
            bootstrap_iterations=250,
            seed=4,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["fullHybridPromoted"])
        self.assertEqual("full-hybrid", result["recommendedVariant"])
        for name in (
            "memory",
            "hookP99",
            "loadTime",
            "longTermAddressSpace",
            "allocatorStalls",
        ):
            self.assertTrue(result["gates"][name]["pass"], name)

    def test_memory_or_address_regression_blocks_promotion_but_not_validity(self) -> None:
        result = bench.evaluate_results(
            measured_rounds(hybrid_memory=104.0, hybrid_free=105.0),
            measured_blocks=10,
            bootstrap_iterations=200,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["fullHybridPromoted"])
        self.assertEqual("large-tlsf", result["recommendedVariant"])
        self.assertFalse(result["gates"]["memory"]["pass"])
        self.assertFalse(result["gates"]["longTermAddressSpace"]["pass"])

    def test_missing_cycle_invalidates_report(self) -> None:
        rows = measured_rounds()
        rows.pop()
        result = bench.evaluate_results(
            rows,
            measured_blocks=10,
            bootstrap_iterations=100,
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["gates"]["coverage"]["pass"])

    def test_zero_stall_baseline_is_treated_as_already_optimal(self) -> None:
        rows = measured_rounds()
        for row in rows:
            if row["variant"] in ("large-tlsf", "full-hybrid"):
                row["metrics"]["allocatorStallOver10msCount"] = 0.0
        result = bench.evaluate_results(
            rows,
            measured_blocks=10,
            bootstrap_iterations=100,
        )
        stall = result["gates"]["allocatorStalls"]
        self.assertTrue(stall["pass"])
        self.assertTrue(stall["rows"][0]["alreadyZero"])

    def test_non_growing_virtual_baseline_is_already_stable(self) -> None:
        rows = measured_rounds()
        for row in rows:
            if row["variant"] == "large-tlsf":
                row["metrics"]["measurementVirtualGrowthSlopeMBPerSec"] = 0.0
            elif row["variant"] == "full-hybrid":
                row["metrics"]["measurementVirtualGrowthSlopeMBPerSec"] = -0.01
        result = bench.evaluate_results(
            rows,
            measured_blocks=10,
            bootstrap_iterations=100,
        )
        address = result["gates"]["longTermAddressSpace"]
        self.assertTrue(address["pass"])
        self.assertTrue(address["rows"][0]["alreadyStable"])


class AsiAndModuleValidationTests(unittest.TestCase):
    def test_asi_deployment_restores_both_loader_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "war3"
            nested = root / "StormBreaker"
            nested.mkdir(parents=True)
            source = base / "current.asi"
            source.write_bytes(b"current")
            root_asi = root / "StormBreaker.asi"
            nested_asi = nested / "StormBreaker.asi"
            root_asi.write_bytes(b"root-old")
            nested_asi.write_bytes(b"nested-old")
            transaction = bench.AsiRoundFiles(
                root, source, "full-hybrid", base / "artifacts"
            )
            with transaction:
                self.assertEqual(b"current", root_asi.read_bytes())
                self.assertFalse(nested_asi.exists())
                self.assertEqual(bench.file_sha256(source), transaction.deployed_sha256)
            self.assertEqual(b"root-old", root_asi.read_bytes())
            self.assertEqual(b"nested-old", nested_asi.read_bytes())

    def test_module_gate_checks_asi_and_storm_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "war3"
            root.mkdir()
            d3d9 = base / "Windows" / "SysWOW64" / "d3d9.dll"
            d3d9.parent.mkdir(parents=True)
            d3d9.write_bytes(b"system")
            storm = root / "Storm.dll"
            storm.write_bytes(b"storm")
            game = root / "Game.dll"
            game.write_bytes(b"game")
            asi = root / "StormBreaker.asi"
            asi.write_bytes(b"asi")
            modules = [
                {"name": "d3d9.dll", "path": str(d3d9)},
                {"name": "Storm.dll", "path": str(storm)},
                {"name": "Game.dll", "path": str(game)},
                {"name": "StormBreaker.asi", "path": str(asi)},
            ]
            result = bench.validate_modules(
                modules,
                variant="full-tlsf",
                runtime_root=root,
                deployed_asi_sha256=bench.file_sha256(asi),
                expected_d3d9_path=d3d9,
                expected_storm_sha256=bench.file_sha256(storm),
                expected_game_sha256=bench.file_sha256(game),
            )
            self.assertTrue(result["ok"], result["errors"])
            result = bench.validate_modules(
                modules,
                variant="full-tlsf",
                runtime_root=root,
                deployed_asi_sha256="0" * 64,
                expected_d3d9_path=d3d9,
                expected_storm_sha256=bench.file_sha256(storm),
                expected_game_sha256=bench.file_sha256(game),
            )
            self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
