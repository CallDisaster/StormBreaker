from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import stormbreaker_benchmark as bench


class ScheduleTests(unittest.TestCase):
    def test_schedule_is_deterministic_complete_and_rotating(self) -> None:
        first = bench.generate_schedule(1, 10, seed=12345)
        second = bench.generate_schedule(1, 10, seed=12345)
        self.assertEqual(first, second)
        width = len(bench.VARIANTS)
        self.assertEqual(width * 11, len(first))

        blocks: list[list[str]] = []
        for offset in range(0, len(first), width):
            block = first[offset : offset + width]
            self.assertEqual(set(bench.VARIANTS), {row.variant for row in block})
            self.assertEqual(list(range(width)), [row.order for row in block])
            blocks.append([row.variant for row in block])

        self.assertEqual("warmup", first[0].phase)
        self.assertTrue(all(row.phase == "measured" for row in first[width:]))
        for previous, current in zip(blocks, blocks[1:]):
            self.assertEqual(previous[1:] + previous[:1], current)

    def test_uint32_counter_extends_only_a_real_wrap(self) -> None:
        extender = bench.UInt32WrapExtender()
        sequence = [0xFFFFFFF0, 0xFFFFFFFE, 3, 9]
        extended = [extender.update(value) for value in sequence]
        self.assertEqual([0xFFFFFFF0, 0xFFFFFFFE, 0x100000003, 0x100000009], extended)

        small_drop = bench.UInt32WrapExtender()
        self.assertEqual(100, small_drop.update(100))
        self.assertEqual(90, small_drop.update(90))


class StatisticsTests(unittest.TestCase):
    def test_bootstrap_ci_is_seeded_and_constant_safe(self) -> None:
        constant = bench.bootstrap_ci([2.5] * 8, iterations=200, seed=7)
        self.assertEqual(2.5, constant["low"])
        self.assertEqual(2.5, constant["high"])

        first = bench.bootstrap_ci([1, 2, 3, 4, 5], iterations=500, seed=99)
        second = bench.bootstrap_ci([1, 2, 3, 4, 5], iterations=500, seed=99)
        self.assertEqual(first, second)
        self.assertLessEqual(first["low"], 3.0)
        self.assertGreaterEqual(first["high"], 3.0)

    def test_percentile_and_describe_report_median_and_p95(self) -> None:
        summary = bench.describe([1, 2, 3, 4, 5])
        self.assertEqual(3.0, summary["median"])
        self.assertAlmostEqual(4.8, summary["p95"])


def make_measured_rounds(
    *,
    hybrid_memory: float = 102.0,
    hybrid_slope: float = 0.7,
    hybrid_free: float = 115.0,
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
            7.0,
        ),
    }
    rows: list[dict[str, object]] = []
    for block in range(10):
        for variant in bench.VARIANTS:
            memory, ready, allocator_p99, slope, free_region, stalls = values[variant]
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
                        "measurementPeakVirtualMB": memory * 2,
                        "measurementEndLargestFreeRegionMB": free_region,
                        "measurementEndFreeRegionCount": 100.0,
                        "measurementVirtualGrowthSlopeMBPerSec": slope,
                        "measurementPeakHandleCount": 200,
                        "measurementPeakStormAllocatedMB": 50,
                        "allocatorP99Nanoseconds": allocator_p99,
                        "allocateP99Nanoseconds": allocator_p99,
                        "allocatorStallOver10msCount": stalls,
                    },
                }
            )
    return rows


class GateTests(unittest.TestCase):
    def test_memory_and_speed_gates_pass_within_thresholds(self) -> None:
        result = bench.evaluate_results(
            make_measured_rounds(),
            measured_blocks=10,
            memory_gate_pct=3.0,
            speed_gate_pct=5.0,
            bootstrap_iterations=200,
            seed=5,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["gates"]["memory"]["pass"])
        self.assertTrue(result["gates"]["hookP99"]["pass"])
        self.assertTrue(result["gates"]["loadTime"]["pass"])
        self.assertTrue(result["gates"]["longTermAddressSpace"]["pass"])
        self.assertTrue(result["gates"]["allocatorStalls"]["pass"])
        self.assertTrue(result["fullHybridPromoted"])
        self.assertEqual(result["recommendedVariant"], "full-hybrid")
        self.assertEqual(
            2.0,
            result["paired"]["full-hybrid_vs_large-tlsf"]["measurementPeakPrivateMB"]
            ["deltaPct"]["median"],
        )

    def test_memory_gate_rejects_more_than_three_percent(self) -> None:
        result = bench.evaluate_results(
            make_measured_rounds(hybrid_memory=106.0),
            measured_blocks=10,
            bootstrap_iterations=200,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["fullHybridPromoted"])
        self.assertEqual(result["recommendedVariant"], "large-tlsf")
        failed = result["gates"]["memory"]["rows"]
        self.assertTrue(failed)
        self.assertTrue(all(not row["pass"] for row in failed))

    def test_speed_gate_and_missing_round_are_hard_failures(self) -> None:
        rows = make_measured_rounds()
        rows.pop()
        result = bench.evaluate_results(
            rows,
            measured_blocks=10,
            bootstrap_iterations=200,
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["gates"]["coverage"]["pass"])
        self.assertFalse(result["fullHybridPromoted"])


class AsiRoundFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "war3"
        self.root.mkdir()
        (self.root / "StormBreaker").mkdir()
        self.source = self.base / "build.asi"
        self.source.write_bytes(b"current-build")
        self.root_asi = self.root / "StormBreaker.asi"
        self.nested_asi = self.root / "StormBreaker" / "StormBreaker.asi"
        self.root_asi.write_bytes(b"original-root")
        self.nested_asi.write_bytes(b"original-nested")
        self.artifacts = self.base / "artifacts"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_originals_restored(self) -> None:
        self.assertEqual(b"original-root", self.root_asi.read_bytes())
        self.assertEqual(b"original-nested", self.nested_asi.read_bytes())

    def test_off_disables_both_locations_then_restores(self) -> None:
        transaction = bench.AsiRoundFiles(self.root, self.source, "off", self.artifacts)
        with transaction:
            self.assertFalse(self.root_asi.exists())
            self.assertFalse(self.nested_asi.exists())
        self.assert_originals_restored()
        self.assertTrue(transaction.restore_result["ok"])

    def test_on_deploys_only_current_build_to_root_then_restores(self) -> None:
        for variant in ("large-tlsf", "full-mimalloc"):
            with self.subTest(variant=variant):
                transaction = bench.AsiRoundFiles(
                    self.root, self.source, variant, self.artifacts
                )
                with transaction:
                    self.assertEqual(b"current-build", self.root_asi.read_bytes())
                    self.assertFalse(self.nested_asi.exists())
                    self.assertEqual(
                        bench.file_sha256(self.source), transaction.deployed_sha256
                    )
                self.assert_originals_restored()

    def test_restore_runs_on_exception_and_preserves_absence(self) -> None:
        self.root_asi.unlink()
        self.nested_asi.unlink()
        with self.assertRaisesRegex(RuntimeError, "planned"):
            with bench.AsiRoundFiles(self.root, self.source, "large-tlsf", self.artifacts):
                self.assertTrue(self.root_asi.exists())
                raise RuntimeError("planned")
        self.assertFalse(self.root_asi.exists())
        self.assertFalse(self.nested_asi.exists())


class ModuleValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "war3"
        self.root.mkdir()
        self.asi = self.root / "StormBreaker.asi"
        self.asi.write_bytes(b"asi-build")
        self.expected_hash = bench.file_sha256(self.asi)
        self.system_d3d9 = self.base / "Windows" / "SysWOW64" / "d3d9.dll"
        self.system_d3d9.parent.mkdir(parents=True)
        self.system_d3d9.write_bytes(b"system-d3d9")
        self.storm = self.root / "Storm.dll"
        self.storm.write_bytes(b"storm")
        self.game = self.root / "Game.dll"
        self.game.write_bytes(b"game")
        self.modules = [
            {"name": "War3.exe", "path": str(self.root / "War3.exe")},
            {"name": "d3d9.dll", "path": str(self.system_d3d9)},
            {"name": "Storm.dll", "path": str(self.storm)},
            {"name": "Game.dll", "path": str(self.game)},
            {"name": "StormBreaker.asi", "path": str(self.asi)},
        ]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def validate(self, variant: str, modules: list[dict[str, str]] | None = None, sha: str | None = None):
        return bench.validate_modules(
            modules if modules is not None else self.modules,
            variant=variant,
            runtime_root=self.root,
            deployed_asi_sha256=self.expected_hash if sha is None else sha,
            expected_d3d9_path=self.system_d3d9,
            expected_storm_sha256=bench.file_sha256(self.storm),
            expected_game_sha256=bench.file_sha256(self.game),
        )

    def test_on_requires_system_d3d9_root_asi_matching_sha_and_storm(self) -> None:
        self.assertTrue(self.validate("large-tlsf")["ok"])

        wrong_d3d9 = [dict(row) for row in self.modules]
        wrong_d3d9[1]["path"] = str(self.root / "d3d9.dll")
        self.assertFalse(self.validate("large-tlsf", wrong_d3d9)["ok"])

        self.assertFalse(self.validate("large-tlsf", sha="0" * 64)["ok"])
        no_storm = [row for row in self.modules if row["name"] != "Storm.dll"]
        self.assertFalse(self.validate("large-tlsf", no_storm)["ok"])
        no_game = [row for row in self.modules if row["name"] != "Game.dll"]
        self.assertFalse(self.validate("large-tlsf", no_game)["ok"])

    def test_off_rejects_any_stormbreaker_module(self) -> None:
        self.assertFalse(self.validate("off")["ok"])
        without_asi = [row for row in self.modules if row["name"] != "StormBreaker.asi"]
        self.assertTrue(self.validate("off", without_asi)["ok"])

    def test_on_rejects_nested_or_duplicate_asi(self) -> None:
        nested = self.root / "StormBreaker" / "StormBreaker.asi"
        nested.parent.mkdir()
        nested.write_bytes(b"asi-build")
        nested_modules = [dict(row) for row in self.modules]
        nested_modules[-1]["path"] = str(nested)
        self.assertFalse(self.validate("full-mimalloc", nested_modules)["ok"])

        duplicate = self.modules + [{"name": "StormBreaker.asi", "path": str(self.asi)}]
        self.assertFalse(self.validate("large-tlsf", duplicate)["ok"])


class MetricsAndLaunchContractTests(unittest.TestCase):
    def test_metrics_require_expected_backend_and_installed_hooks(self) -> None:
        valid = [self.healthy_metrics("large-tlsf")]
        self.assertTrue(bench.validate_metrics_rows(valid, "large-tlsf")["ok"])
        self.assertFalse(bench.validate_metrics_rows(valid, "full-mimalloc")["ok"])
        self.assertFalse(
            bench.validate_metrics_rows(
                [{**valid[0], "hooksInstalled": False}], "large-tlsf"
            )["ok"]
        )
        self.assertTrue(bench.validate_metrics_rows([], "off")["ok"])
        self.assertFalse(bench.validate_metrics_rows(valid, "off")["ok"])

    @staticmethod
    def healthy_metrics(variant: str) -> dict[str, object]:
        selected = bench.variant_config(variant)
        backend = str(selected["backend"])
        takeover = str(selected["takeoverMode"])
        return {
            "hooksInstalled": True,
            "memoryBackend": backend,
            "takeoverMode": takeover,
            "backend": {"name": backend, "fallbackAllocations": 0, "failures": 0},
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
                "over10msCount": 0,
            },
            "profiler": {"dropped": 0, "writeErrors": 0, "incomplete": False},
        }

    def test_launch_contract_requires_multi_instance_isolated_desktop(self) -> None:
        config = bench.BenchmarkConfig(
            war3_root=Path(r"E:\sandbox"),
            map_path=Path(r"E:\sandbox\map.w3x"),
            asi_path=Path(r"E:\build\StormBreaker.asi"),
            autotest_dir=Path(r"E:\AutoTest"),
            output_dir=Path(r"E:\out"),
        )
        kwargs = bench.build_launch_kwargs(
            config,
            "full-mimalloc",
            Path(r"E:\out\round"),
            run_id="sb_run",
            session_id="r001-full-mimalloc",
            artifact_root=Path(r"E:\out\autotest"),
        )
        self.assertTrue(kwargs["windowed"])
        self.assertTrue(kwargs["use_isolated_desktop"])
        self.assertFalse(kwargs["deploy_d3d9_before_launch"])
        self.assertTrue(kwargs["reuse_existing_root"])
        self.assertEqual(r"E:\sandbox", kwargs["sandbox_root"])
        self.assertEqual("sb_run", kwargs["run_id"])
        self.assertEqual("r001-full-mimalloc", kwargs["session_id"])
        self.assertNotIn("auto_perf_record", kwargs)
        self.assertNotIn("baseline_width", kwargs)
        env = json.loads(kwargs["env_overrides_json"])
        self.assertEqual("mimalloc", env["STORMBREAKER_MEMORY_BACKEND"])
        self.assertEqual("full", env["STORMBREAKER_TAKEOVER_MODE"])
        self.assertEqual("1", env["STORMBREAKER_TELEMETRY"])
        self.assertEqual("1", env["STORMBREAKER_DISABLE_CONTROL_PANEL"])
        self.assertEqual("0", env["STORMBREAKER_MEMORY_MONITOR"])
        self.assertEqual(str(Path(r"E:\out\round").resolve()), env["STORMBREAKER_ARTIFACT_DIR"])


if __name__ == "__main__":
    unittest.main()
