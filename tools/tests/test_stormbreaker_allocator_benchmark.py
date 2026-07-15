from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import stormbreaker_allocator_benchmark as bench


PROFILE = "quick"
SEED = 12345


def make_result(
    spec: bench.RoundSpec,
    *,
    wall_time_ms: float = 100.0,
    checksum: str | int = "0x2a",
    valid: bool = True,
) -> dict[str, object]:
    return {
        "valid": valid,
        "engine": spec.engine,
        "backend": spec.backend,
        "scenario": spec.scenario,
        "profile": PROFILE,
        "seed": spec.seed,
        "checksum": checksum,
        "metrics": {
            "wallTimeMs": wall_time_ms,
            "operationsPerSecond": 1_000_000.0 / wall_time_ms,
            "latency": {"p99Nanoseconds": wall_time_ms * 10.0},
        },
    }


def make_complete_records(
    *,
    backends: tuple[str, ...] = ("tlsf", "mimalloc"),
    repetitions: int = 3,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    schedule = bench.generate_schedule(
        ("map-load",), backends, repetitions=repetitions, seed=SEED
    )
    for spec in schedule:
        base = 100.0 + 10.0 * (max(spec.repetition, 1) - 2)
        if spec.engine == "winheap":
            wall_time = base
        elif spec.backend == "tlsf":
            wall_time = base * 0.8
        else:
            wall_time = base * 0.7
        records.append(
            bench.make_record(
                spec,
                PROFILE,
                make_result(spec, wall_time_ms=wall_time),
            )
        )
    return records


class ScheduleTests(unittest.TestCase):
    def test_schedule_is_complete_deterministic_and_cyclically_rotated(self) -> None:
        scenarios = ("map-load", "cross-thread")
        backends = ("tlsf", "mimalloc", "hybrid")
        first = bench.generate_schedule(scenarios, backends, repetitions=3, seed=SEED)
        second = bench.generate_schedule(scenarios, backends, repetitions=3, seed=SEED)
        self.assertEqual(first, second)

        width = 1 + len(backends)
        blocks_per_scenario = 1 + 3
        self.assertEqual(len(scenarios) * blocks_per_scenario * width, len(first))
        expected_configs = {"winheap", "takeover/tlsf", "takeover/mimalloc", "takeover/hybrid"}

        for scenario in scenarios:
            rows = [row for row in first if row.scenario == scenario]
            blocks = [rows[offset : offset + width] for offset in range(0, len(rows), width)]
            self.assertEqual("warmup", blocks[0][0].phase)
            self.assertTrue(all(row.phase == "warmup" for row in blocks[0]))
            self.assertTrue(
                all(row.phase == "measured" for block in blocks[1:] for row in block)
            )
            self.assertEqual(
                [0, 1, 2, 3], [block[0].repetition for block in blocks]
            )
            for block in blocks:
                self.assertEqual(list(range(width)), [row.order for row in block])
                self.assertEqual({row.configuration.key for row in block}, expected_configs)
                self.assertEqual({SEED}, {row.seed for row in block})
            for previous, current in zip(blocks, blocks[1:]):
                previous_keys = [row.configuration.key for row in previous]
                current_keys = [row.configuration.key for row in current]
                self.assertEqual(previous_keys[1:] + previous_keys[:1], current_keys)

    def test_backend_subset_selects_a_stable_control_and_reference(self) -> None:
        configurations = bench.build_configurations(("mimalloc", "hybrid"))
        self.assertEqual(bench.EngineConfig("winheap", "mimalloc"), configurations[0])
        self.assertEqual("mimalloc", bench.reference_backend(("mimalloc", "hybrid")))
        sharded = bench.build_configurations(
            ("tlsf-sharded",), engines=("takeover",)
        )
        self.assertEqual((bench.EngineConfig("takeover", "tlsf-sharded"),), sharded)
        self.assertEqual("tlsf-sharded", bench.reference_backend(("tlsf-sharded",)))

    def test_expanded_engines_include_direct_and_per_backend_candidates(self) -> None:
        configurations = bench.build_configurations(
            ("tlsf", "mimalloc"), bench.ENGINES
        )
        self.assertEqual(
            {
                "native-storm",
                "winheap",
                "private-heap",
                "rpmalloc",
                "rpmalloc-threaded",
                "segregated-arena",
                "segregated-hybrid",
                "legacy-large/tlsf",
                "pool/tlsf",
                "pool/mimalloc",
                "takeover/tlsf",
                "takeover/mimalloc",
            },
            {configuration.key for configuration in configurations},
        )
        schedule = bench.generate_schedule(
            ("map-load",), ("tlsf",), repetitions=2, seed=SEED,
            engines=("rpmalloc", "pool"),
        )
        self.assertEqual(6, len(schedule))
        self.assertEqual(
            {"rpmalloc", "pool/tlsf"},
            {row.configuration.key for row in schedule},
        )


class JsonParsingTests(unittest.TestCase):
    def test_final_non_empty_stdout_line_is_the_json_result(self) -> None:
        parsed = bench.parse_last_json_line(
            'initializing\nprogress 100%\n{"valid":true,"checksum":"abc"}\n\n'
        )
        self.assertEqual({"valid": True, "checksum": "abc"}, parsed)

    def test_malformed_final_line_fails_even_if_an_earlier_line_is_json(self) -> None:
        with self.assertRaisesRegex(bench.BenchmarkFailure, "final non-empty line"):
            bench.parse_last_json_line('{"valid":true}\nnot-json\n')

    def test_non_object_duplicate_keys_and_non_finite_numbers_are_rejected(self) -> None:
        for stdout in (
            "[1, 2, 3]\n",
            '{"valid":true,"valid":false}\n',
            '{"valid":true,"metric":NaN}\n',
        ):
            with self.subTest(stdout=stdout):
                with self.assertRaises(bench.BenchmarkFailure):
                    bench.parse_last_json_line(stdout)


class FailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = bench.RoundSpec(
            scenario="map-load",
            phase="measured",
            repetition=1,
            order=0,
            engine="takeover",
            backend="tlsf",
            seed=SEED,
        )

    def test_invalid_identity_missing_checksum_and_missing_metrics_are_rejected(self) -> None:
        invalid = make_result(self.spec, valid=False)
        with self.assertRaisesRegex(bench.BenchmarkFailure, "valid=true"):
            bench.validate_result(invalid, self.spec, PROFILE)

        wrong_backend = make_result(self.spec)
        wrong_backend["backend"] = "mimalloc"
        with self.assertRaisesRegex(bench.BenchmarkFailure, "backend mismatch"):
            bench.validate_result(wrong_backend, self.spec, PROFILE)

        missing_checksum = make_result(self.spec)
        del missing_checksum["checksum"]
        with self.assertRaisesRegex(bench.BenchmarkFailure, "no checksum"):
            bench.validate_result(missing_checksum, self.spec, PROFILE)

        missing_metrics = make_result(self.spec)
        del missing_metrics["metrics"]
        with self.assertRaisesRegex(bench.BenchmarkFailure, "no numeric metrics"):
            bench.validate_result(missing_metrics, self.spec, PROFILE)

    def test_nonzero_process_exit_is_a_hard_failure(self) -> None:
        def failed_process(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 9, stdout="{}\n", stderr="allocator failed")

        with self.assertRaisesRegex(bench.BenchmarkFailure, "exited with code 9"):
            bench.execute_round(
                Path("StormBreakerAllocatorBenchmark.exe"),
                self.spec,
                PROFILE,
                process_runner=failed_process,
            )

    def test_real_flat_json_shape_and_winheap_backend_label_are_accepted(self) -> None:
        spec = bench.RoundSpec(
            scenario="small-churn",
            phase="measured",
            repetition=1,
            order=0,
            engine="winheap",
            backend="tlsf",
            seed=SEED,
        )
        result = {
            "schema": 1,
            "valid": True,
            "engine": "winheap",
            "backend": "winheap",
            "scenario": "small-churn",
            "profile": PROFILE,
            "seed": SEED,
            "trace_operations": 500_000,
            "wall_ns": 25_000_000,
            "ops_per_sec": 20_000_000.0,
            "checksum": 42,
            "latency": {"p95_ns": 250, "p99_ns": 400},
        }
        self.assertEqual("42", bench.validate_result(result, spec, PROFILE))
        metrics = bench.extract_metrics(result)
        self.assertEqual(25_000_000.0, metrics["wall_ns"])
        self.assertEqual(250.0, metrics["latency.p95_ns"])

    def test_command_contract_and_valid_process_result(self) -> None:
        observed: dict[str, object] = {}

        def successful_process(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            observed["command"] = command
            observed["kwargs"] = kwargs
            stdout = "diagnostic\n" + json.dumps(make_result(self.spec)) + "\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        result = bench.execute_round(
            Path("C:/bench/StormBreakerAllocatorBenchmark.exe"),
            self.spec,
            PROFILE,
            process_runner=successful_process,
        )
        self.assertTrue(result["valid"])
        self.assertEqual(
            [
                "C:\\bench\\StormBreakerAllocatorBenchmark.exe",
                "--engine",
                "takeover",
                "--backend",
                "tlsf",
                "--scenario",
                "map-load",
                "--profile",
                "quick",
                "--seed",
                str(SEED),
            ],
            observed["command"],
        )
        kwargs = observed["kwargs"]
        self.assertIsInstance(kwargs, dict)
        self.assertFalse(kwargs["check"])
        self.assertTrue(kwargs["text"])

    def test_checksum_mismatch_across_configs_fails(self) -> None:
        winheap = bench.RoundSpec(
            scenario="map-load",
            phase="warmup",
            repetition=0,
            order=0,
            engine="winheap",
            backend="tlsf",
            seed=SEED,
        )
        records = [
            bench.make_record(winheap, PROFILE, make_result(winheap, checksum="0x2a")),
            bench.make_record(self.spec, PROFILE, make_result(self.spec, checksum="0x2b")),
        ]
        with self.assertRaisesRegex(bench.BenchmarkFailure, "checksum mismatch"):
            bench.validate_checksums(records)

    def test_runner_removes_stale_summary_and_writes_failure_without_running_exe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "StormBreakerAllocatorBenchmark.exe"
            executable.write_bytes(b"not executed")
            output_dir = root / "results"
            output_dir.mkdir()
            (output_dir / "summary.json").write_text("stale", encoding="utf-8")
            calls = 0

            def fake_process(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                values = {
                    command[index]: command[index + 1]
                    for index in range(1, len(command), 2)
                }
                spec = bench.RoundSpec(
                    scenario=values["--scenario"],
                    phase="warmup",
                    repetition=0,
                    order=0,
                    engine=values["--engine"],
                    backend=values["--backend"],
                    seed=int(values["--seed"]),
                )
                result = make_result(spec, valid=calls == 1)
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(result) + "\n", stderr=""
                )

            config = bench.RunnerConfig(
                executable=executable,
                output_dir=output_dir,
                profile=PROFILE,
                scenarios=("map-load",),
                backends=("tlsf",),
                repetitions=1,
                seed=SEED,
            )
            with self.assertRaisesRegex(bench.BenchmarkFailure, "valid=true"):
                bench.run_benchmark(config, process_runner=fake_process)

            self.assertEqual(2, calls)
            self.assertFalse((output_dir / "summary.json").exists())
            failure = json.loads((output_dir / "failure.json").read_text(encoding="utf-8"))
            self.assertFalse(failure["valid"])
            self.assertEqual(1, failure["completedRuns"])
            raw_lines = (output_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(1, len(raw_lines))


class StatisticsTests(unittest.TestCase):
    def test_percentile_and_bootstrap_are_deterministic(self) -> None:
        self.assertAlmostEqual(4.8, bench.percentile([1, 2, 3, 4, 5], 0.95))
        first = bench.bootstrap_ci([1, 2, 3, 4, 5], iterations=300, seed=99)
        second = bench.bootstrap_ci([1, 2, 3, 4, 5], iterations=300, seed=99)
        self.assertEqual(first, second)
        constant = bench.bootstrap_ci([2.5] * 7, iterations=100, seed=7)
        self.assertEqual(2.5, constant["low"])
        self.assertEqual(2.5, constant["high"])

    def test_summary_reports_absolute_and_paired_relative_statistics(self) -> None:
        records = make_complete_records()
        summary = bench.summarize_results(
            records,
            scenarios=("map-load",),
            backends=("tlsf", "mimalloc"),
            repetitions=3,
            profile=PROFILE,
            seed=SEED,
            bootstrap_iterations=300,
        )
        self.assertTrue(summary["valid"])
        self.assertEqual(12, summary["runCount"])
        scenario = summary["scenarios"]["map-load"]
        winheap_wall = scenario["configurations"]["winheap"]["metrics"]["wallTimeMs"]
        self.assertEqual(100.0, winheap_wall["median"])
        self.assertEqual(109.0, winheap_wall["p95"])
        self.assertLessEqual(winheap_wall["bootstrap95Median"]["low"], 100.0)
        self.assertGreaterEqual(winheap_wall["bootstrap95Median"]["high"], 100.0)

        tlsf_relative = scenario["relativeToWinheap"]["takeover/tlsf"]["metrics"]["wallTimeMs"]
        self.assertEqual(0.8, tlsf_relative["ratio"]["median"])
        self.assertEqual(-20.0, tlsf_relative["percentChange"]["median"])
        self.assertEqual(
            -20.0, tlsf_relative["bootstrap95MedianPercentChange"]["low"]
        )

        backend_comparisons = scenario["relativeToBackend"]
        self.assertEqual("takeover/tlsf", backend_comparisons["reference"])
        mimalloc_relative = backend_comparisons["comparisons"]["takeover/mimalloc"]
        wall_relative = mimalloc_relative["metrics"]["wallTimeMs"]
        self.assertEqual(0.875, wall_relative["ratio"]["median"])
        self.assertEqual(-12.5, wall_relative["percentChange"]["median"])

    def test_coverage_gap_fails_before_summary_publication(self) -> None:
        records = make_complete_records()
        records.pop()
        with self.assertRaisesRegex(bench.BenchmarkFailure, "coverage"):
            bench.summarize_results(
                records,
                scenarios=("map-load",),
                backends=("tlsf", "mimalloc"),
                repetitions=3,
                profile=PROFILE,
                seed=SEED,
                bootstrap_iterations=50,
            )


class CliTests(unittest.TestCase):
    def test_cli_accepts_trim_cycle_for_takeover_only(self) -> None:
        config = bench.parse_args(
            [
                "--executable",
                "C:/bench/StormBreakerAllocatorBenchmark.exe",
                "--scenarios",
                "trim-cycle",
                "--engines",
                "takeover",
                "--backends",
                "tlsf",
            ]
        )
        self.assertEqual(("trim-cycle",), config.scenarios)
        self.assertEqual(("takeover",), config.engines)

    def test_cli_accepts_required_options_and_comma_separated_filters(self) -> None:
        config = bench.parse_args(
            [
                "--executable",
                "C:/bench/StormBreakerAllocatorBenchmark.exe",
                "--output-dir",
                "C:/bench/results",
                "--profile",
                "standard",
                "--scenarios",
                "map-load,realloc",
                "--backends",
                "mimalloc,hybrid",
                "--repetitions",
                "9",
                "--seed",
                "0x2a",
            ]
        )
        self.assertEqual("standard", config.profile)
        self.assertEqual(("map-load", "realloc"), config.scenarios)
        self.assertEqual(("mimalloc", "hybrid"), config.backends)
        self.assertEqual(9, config.repetitions)
        self.assertEqual(42, config.seed)


if __name__ == "__main__":
    unittest.main()
