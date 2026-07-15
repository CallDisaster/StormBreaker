from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import stormbreaker_allocator_benchmark as base
import stormbreaker_allocator_factor_benchmark as factor


SEED = 0x12345


def make_config(
    root: Path | None = None,
    *,
    values: tuple[str, ...] = ("4", "16", "64"),
    reference: str = "64",
    repetitions: int = 3,
    fixed_options: tuple[tuple[str, str], ...] = (),
) -> factor.RunnerConfig:
    root = root or Path("C:/bench")
    return factor.RunnerConfig(
        factor_option="--pool-initial-mib",
        factor_values=values,
        fixed_options=fixed_options,
        executable=root / "StormBreakerAllocatorBenchmark.exe",
        output_dir=root / "results",
        engine="takeover",
        backend="hybrid",
        profile="quick",
        scenarios=("map-load",),
        reference_value=reference,
        repetitions=repetitions,
        seed=SEED,
        bootstrap_iterations=200,
        timeout_seconds=12.5,
    )


def make_result(
    config: factor.RunnerConfig,
    spec: factor.FactorRoundSpec,
    *,
    wall_ns: float = 100.0,
    checksum: str | int = "0x2a",
    valid: bool = True,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": 1,
        "valid": valid,
        "engine": config.engine,
        "backend": (
            config.engine if config.engine in base.DIRECT_ENGINES else config.backend
        ),
        "scenario": spec.scenario,
        "profile": config.profile,
        "seed": spec.seed,
        "checksum": checksum,
        "metrics": {
            "wall_ns": wall_ns,
            "ops_per_sec": 1_000_000.0 / wall_ns,
            "latency": {"p99_ns": wall_ns * 2.0},
        },
    }
    result[factor.factor_field_name(config.factor_option)] = (
        factor.canonical_factor_echo(spec.factor_value)
    )
    return result


def make_records(config: factor.RunnerConfig) -> list[dict[str, object]]:
    multipliers = {
        value: (8 + index) / 10
        for index, value in enumerate(config.factor_values)
    }
    records: list[dict[str, object]] = []
    schedule = factor.generate_schedule(
        config.scenarios, config.factor_values, config.repetitions, config.seed
    )
    for spec in schedule:
        repetition = max(spec.repetition, 1)
        base_wall = 80.0 + repetition * 10.0
        result = make_result(
            config,
            spec,
            wall_ns=base_wall * multipliers[spec.factor_value],
        )
        records.append(factor.make_record(config, spec, result))
    return records


def command_values(command: list[str]) -> dict[str, str]:
    return {
        command[index]: command[index + 1]
        for index in range(1, len(command), 2)
    }


class ScheduleTests(unittest.TestCase):
    def test_schedule_is_complete_deterministic_and_cyclically_rotated(self) -> None:
        scenarios = ("map-load", "cross-thread")
        values = ("off", "on", "debug")
        first = factor.generate_schedule(scenarios, values, 4, SEED)
        second = factor.generate_schedule(scenarios, values, 4, SEED)
        self.assertEqual(first, second)
        self.assertEqual(len(scenarios) * len(values) * 5, len(first))

        for scenario in scenarios:
            rows = [row for row in first if row.scenario == scenario]
            blocks = [
                rows[offset : offset + len(values)]
                for offset in range(0, len(rows), len(values))
            ]
            self.assertEqual([0, 1, 2, 3, 4], [block[0].repetition for block in blocks])
            self.assertTrue(all(row.phase == "warmup" for row in blocks[0]))
            self.assertTrue(
                all(row.phase == "measured" for block in blocks[1:] for row in block)
            )
            for block in blocks:
                self.assertEqual(set(values), {row.factor_value for row in block})
                self.assertEqual(list(range(3)), [row.order for row in block])
            for previous, current in zip(blocks, blocks[1:]):
                previous_values = [row.factor_value for row in previous]
                current_values = [row.factor_value for row in current]
                self.assertEqual(previous_values[1:] + previous_values[:1], current_values)

    def test_factor_values_require_distinct_typed_echoes(self) -> None:
        for values in (("4",), ("4", "4"), ("on", "true"), ("16", "0x10")):
            with self.subTest(values=values):
                with self.assertRaises(base.BenchmarkFailure):
                    factor.generate_schedule(("map-load",), values, 1, SEED)


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = make_config()
        self.spec = factor.FactorRoundSpec(
            scenario="map-load",
            phase="measured",
            repetition=1,
            order=0,
            factor_value="16",
            seed=SEED,
        )

    def test_command_contains_sorted_fixed_options_and_exactly_one_factor(self) -> None:
        config = replace(
            self.config,
            factor_option="--tlsf-range-index",
            factor_values=("off", "on"),
            fixed_options=(
                ("--pool-initial-mib", "4"),
                ("--caller-mode", "static"),
            ),
        )
        spec = replace(self.spec, factor_value="on")
        command = factor.build_command(config.executable, config, spec)
        values = command_values(command)
        self.assertEqual("takeover", values["--engine"])
        self.assertEqual("hybrid", values["--backend"])
        self.assertEqual("map-load", values["--scenario"])
        self.assertEqual("quick", values["--profile"])
        self.assertEqual(str(SEED), values["--seed"])
        self.assertEqual("static", values["--caller-mode"])
        self.assertEqual("4", values["--pool-initial-mib"])
        self.assertEqual("on", values["--tlsf-range-index"])
        self.assertEqual(8, len(values))
        self.assertEqual(
            [
                str(config.executable),
                "--engine",
                "takeover",
                "--backend",
                "hybrid",
                "--scenario",
                "map-load",
                "--profile",
                "quick",
                "--seed",
                str(SEED),
                "--caller-mode",
                "static",
                "--pool-initial-mib",
                "4",
                "--tlsf-range-index",
                "on",
            ],
            command,
        )

    def test_fixed_option_conflicts_duplicates_and_malformed_pairs_fail_closed(
        self,
    ) -> None:
        for option in ("--engine", "--backend", "--scenario", "--profile", "--seed"):
            with self.subTest(option=option):
                config = replace(self.config, fixed_options=((option, "blocked"),))
                with self.assertRaisesRegex(
                    base.BenchmarkFailure, "fixed benchmark identity"
                ):
                    factor.build_command(config.executable, config, self.spec)

        factor_conflict = replace(
            self.config, fixed_options=(("--pool-initial-mib", "4"),)
        )
        with self.assertRaisesRegex(base.BenchmarkFailure, "factor option"):
            factor.build_command(
                factor_conflict.executable, factor_conflict, self.spec
            )

        duplicate = replace(
            self.config,
            fixed_options=(
                ("--caller-mode", "static"),
                ("--caller-mode", "dynamic"),
            ),
        )
        with self.assertRaisesRegex(base.BenchmarkFailure, "duplicate fixed option"):
            factor.build_command(duplicate.executable, duplicate, self.spec)

        malformed_config = replace(
            self.config, fixed_options=(("--caller-mode=dynamic", "static"),)
        )
        with self.assertRaisesRegex(base.BenchmarkFailure, "long CLI option"):
            factor.build_command(
                malformed_config.executable, malformed_config, self.spec
            )

        for value, message in (
            ("pool-initial-mib=4", "long CLI option"),
            ("-p=4", "long CLI option"),
            ("--pool-initial-mib=", "non-empty"),
            ("--pool-initial-mib", "--NAME=VALUE"),
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(base.BenchmarkFailure, message):
                    factor.parse_fixed_option(value)

    def test_required_identity_fields_are_not_optional(self) -> None:
        for key in ("engine", "backend", "scenario", "profile", "seed"):
            result = make_result(self.config, self.spec)
            del result[key]
            with self.subTest(key=key):
                with self.assertRaisesRegex(base.BenchmarkFailure, "identity field"):
                    factor.validate_result(result, self.config, self.spec)

    def test_identity_and_factor_mismatches_fail_closed(self) -> None:
        wrong_profile = make_result(self.config, self.spec)
        wrong_profile["profile"] = "standard"
        with self.assertRaisesRegex(base.BenchmarkFailure, "profile mismatch"):
            factor.validate_result(wrong_profile, self.config, self.spec)

        missing_echo = make_result(self.config, self.spec)
        del missing_echo["pool_initial_mib"]
        with self.assertRaisesRegex(base.BenchmarkFailure, "missing factor echo"):
            factor.validate_result(missing_echo, self.config, self.spec)

        wrong_echo = make_result(self.config, self.spec)
        wrong_echo["pool_initial_mib"] = 64
        with self.assertRaisesRegex(base.BenchmarkFailure, "factor echo mismatch"):
            factor.validate_result(wrong_echo, self.config, self.spec)

        numeric_bool_confusion = make_result(self.config, self.spec)
        numeric_bool_confusion["pool_initial_mib"] = True
        with self.assertRaisesRegex(base.BenchmarkFailure, "factor echo mismatch"):
            factor.validate_result(numeric_bool_confusion, self.config, self.spec)

    def test_checksum_and_real_metrics_are_required(self) -> None:
        missing_checksum = make_result(self.config, self.spec)
        del missing_checksum["checksum"]
        with self.assertRaisesRegex(base.BenchmarkFailure, "no checksum"):
            factor.validate_result(missing_checksum, self.config, self.spec)

        missing_metrics = make_result(self.config, self.spec)
        del missing_metrics["metrics"]
        with self.assertRaisesRegex(base.BenchmarkFailure, "no numeric metrics"):
            factor.validate_result(missing_metrics, self.config, self.spec)

    def test_boolean_and_string_factor_echoes_are_typed(self) -> None:
        bool_config = factor.RunnerConfig(
            factor_option="span-cache",
            factor_values=("off", "on"),
            reference_value="on",
        )
        bool_spec = factor.FactorRoundSpec(
            "map-load", "measured", 1, 0, "off", SEED
        )
        result = make_result(self.config, self.spec)
        result.update({"span_cache": False})
        result.pop("pool_initial_mib")
        result["seed"] = SEED
        self.assertEqual("42", factor.validate_result(result, bool_config, bool_spec))

        self.assertEqual("caller_mode", factor.factor_field_name("caller-mode"))
        self.assertEqual("static", factor.canonical_factor_echo("static"))

    def test_control_options_and_malformed_options_are_rejected(self) -> None:
        for option in ("seed", "--engine", "-pool-initial-mib", "Pool-Initial-MiB"):
            with self.subTest(option=option):
                with self.assertRaises(base.BenchmarkFailure):
                    factor.normalize_factor_option(option)

        empty_reference = replace(make_config(), reference_value="")
        with self.assertRaisesRegex(base.BenchmarkFailure, "reference value"):
            factor.summarize_results([], empty_reference)

    def test_nonzero_exit_timeout_and_malformed_json_are_hard_failures(self) -> None:
        def failed(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 7, stdout="{}\n", stderr="failed")

        with self.assertRaisesRegex(base.BenchmarkFailure, "exited with code 7"):
            factor.execute_round(self.config, self.spec, process_runner=failed)

        def timed_out(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired("benchmark", 1.0)

        with self.assertRaisesRegex(base.BenchmarkFailure, "timed out"):
            factor.execute_round(self.config, self.spec, process_runner=timed_out)

        def malformed(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, stdout="{}\nnot-json\n", stderr="")

        with self.assertRaisesRegex(base.BenchmarkFailure, "final non-empty line"):
            factor.execute_round(self.config, self.spec, process_runner=malformed)


class SummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = make_config()
        self.records = make_records(self.config)

    def test_summary_has_absolute_and_paired_reference_statistics(self) -> None:
        summary = factor.summarize_results(self.records, self.config)
        self.assertTrue(summary["valid"])
        self.assertEqual("--pool-initial-mib", summary["factor"]["option"])
        self.assertEqual("pool_initial_mib", summary["factor"]["field"])
        self.assertEqual("64", summary["factor"]["reference"])
        self.assertEqual(12, summary["runCount"])
        self.assertEqual(9, summary["measuredRunCount"])

        scenario = summary["scenarios"]["map-load"]
        reference_wall = scenario["values"]["64"]["metrics"]["wall_ns"]
        self.assertEqual(100.0, reference_wall["median"])
        self.assertEqual(109.0, reference_wall["p95"])
        self.assertIn("bootstrap95Median", reference_wall)
        self.assertIn("bootstrap95P95", reference_wall)

        relative = scenario["relativeToReference"]["comparisons"]["4"]
        wall_relative = relative["metrics"]["wall_ns"]
        self.assertEqual(-20.0, wall_relative["percentChange"]["median"])
        self.assertEqual(0.8, wall_relative["ratio"]["median"])
        self.assertEqual(
            -20.0, wall_relative["bootstrap95MedianPercentChange"]["low"]
        )

    def test_factor_echo_is_not_reported_as_a_performance_metric(self) -> None:
        summary = factor.summarize_results(self.records, self.config)
        metrics = summary["scenarios"]["map-load"]["values"]["4"]["metrics"]
        self.assertNotIn("pool_initial_mib", metrics)

    def test_summary_records_fixed_options_and_excludes_their_echoes(self) -> None:
        config = replace(
            self.config,
            factor_option="--tlsf-range-index",
            factor_values=("off", "on"),
            reference_value="off",
            fixed_options=(
                ("--pool-initial-mib", "4"),
                ("--caller-mode", "static"),
            ),
        )
        records = make_records(config)
        for record in records:
            result = record["result"]
            self.assertIsInstance(result, dict)
            result["pool_initial_mib"] = 4
            result["caller_mode"] = "static"

        summary = factor.summarize_results(records, config)
        self.assertEqual(
            [
                {"option": "--caller-mode", "value": "static"},
                {"option": "--pool-initial-mib", "value": "4"},
            ],
            summary["fixedOptions"],
        )
        metrics = summary["scenarios"]["map-load"]["values"]["off"]["metrics"]
        self.assertNotIn("pool_initial_mib", metrics)

    def test_coverage_checksum_and_metric_drift_are_rejected(self) -> None:
        missing = list(self.records)
        missing.pop()
        with self.assertRaisesRegex(base.BenchmarkFailure, "coverage"):
            factor.summarize_results(missing, self.config)

        checksum_drift = [dict(record) for record in self.records]
        checksum_drift[-1] = dict(checksum_drift[-1])
        checksum_drift[-1]["checksum"] = "0x2b"
        checksum_drift[-1]["result"] = dict(checksum_drift[-1]["result"])
        checksum_drift[-1]["result"]["checksum"] = "0x2b"
        with self.assertRaisesRegex(base.BenchmarkFailure, "checksum mismatch"):
            factor.summarize_results(checksum_drift, self.config)

        metric_drift = [dict(record) for record in self.records]
        target = next(
            index
            for index, record in enumerate(metric_drift)
            if record["phase"] == "measured" and record["factorValue"] == "4"
        )
        metric_drift[target] = dict(metric_drift[target])
        metric_drift[target]["result"] = dict(metric_drift[target]["result"])
        metric_drift[target]["result"]["metrics"] = dict(
            metric_drift[target]["result"]["metrics"]
        )
        metric_drift[target]["result"]["metrics"]["new_metric"] = 1
        with self.assertRaisesRegex(base.BenchmarkFailure, "metric set changed"):
            factor.summarize_results(metric_drift, self.config)


class RunnerTests(unittest.TestCase):
    def test_runner_uses_one_fresh_call_per_round_and_writes_raw_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "StormBreakerAllocatorBenchmark.exe"
            executable.write_bytes(b"not executed")
            config = make_config(
                root,
                values=("4", "64"),
                reference="64",
                repetitions=2,
                fixed_options=(("--tlsf-range-index", "on"),),
            )
            commands: list[list[str]] = []

            def successful(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                values = command_values(command)
                self.assertEqual("on", values["--tlsf-range-index"])
                spec = factor.FactorRoundSpec(
                    scenario=values["--scenario"],
                    phase="measured",
                    repetition=1,
                    order=0,
                    factor_value=values["--pool-initial-mib"],
                    seed=int(values["--seed"]),
                )
                result = make_result(
                    config,
                    spec,
                    wall_ns=80.0 if spec.factor_value == "4" else 100.0,
                )
                self.assertEqual(12.5, kwargs["timeout"])
                return subprocess.CompletedProcess(
                    command, 0, stdout="diagnostic\n" + json.dumps(result) + "\n", stderr=""
                )

            summary = factor.run_benchmark(config, process_runner=successful)
            self.assertEqual(6, len(commands))
            self.assertTrue(
                all(
                    command_values(command)["--tlsf-range-index"] == "on"
                    for command in commands
                )
            )
            self.assertEqual(6, summary["runCount"])
            self.assertEqual(
                6,
                len((config.output_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()),
            )
            self.assertTrue((config.output_dir / "summary.json").is_file())
            self.assertFalse((config.output_dir / "failure.json").exists())

    def test_runner_removes_stale_summary_and_records_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "StormBreakerAllocatorBenchmark.exe"
            executable.write_bytes(b"not executed")
            config = make_config(
                root, values=("4", "64"), reference="64", repetitions=1
            )
            config.output_dir.mkdir()
            (config.output_dir / "summary.json").write_text("stale", encoding="utf-8")
            calls = 0

            def wrong_second_echo(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                values = command_values(command)
                spec = factor.FactorRoundSpec(
                    values["--scenario"],
                    "measured",
                    1,
                    0,
                    values["--pool-initial-mib"],
                    int(values["--seed"]),
                )
                result = make_result(config, spec)
                if calls == 2:
                    result["pool_initial_mib"] = 999
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(result) + "\n", stderr=""
                )

            with self.assertRaisesRegex(base.BenchmarkFailure, "factor echo mismatch"):
                factor.run_benchmark(config, process_runner=wrong_second_echo)

            self.assertEqual(2, calls)
            self.assertFalse((config.output_dir / "summary.json").exists())
            failure = json.loads(
                (config.output_dir / "failure.json").read_text(encoding="utf-8")
            )
            self.assertFalse(failure["valid"])
            self.assertEqual(1, failure["completedRuns"])
            self.assertEqual(
                1,
                len((config.output_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()),
            )


class CliTests(unittest.TestCase):
    def test_cli_parses_fixed_identity_factor_values_and_reference(self) -> None:
        config = factor.parse_args(
            [
                "--executable",
                "C:/bench/StormBreakerAllocatorBenchmark.exe",
                "--output-dir",
                "C:/bench/factors",
                "--engine",
                "pool",
                "--backend",
                "tlsf",
                "--profile",
                "standard",
                "--scenarios",
                "map-load,realloc",
                "--factor-option",
                "tlsf-range-index",
                "--fixed-option",
                "--pool-initial-mib=4",
                "--fixed-option=--caller-mode=static",
                "--values",
                "off,on",
                "--reference-value",
                "on",
                "--repetitions",
                "9",
                "--seed",
                "0x2a",
                "--bootstrap-iterations",
                "300",
                "--timeout-seconds",
                "30",
            ]
        )
        self.assertEqual("pool", config.engine)
        self.assertEqual("tlsf", config.backend)
        self.assertEqual("standard", config.profile)
        self.assertEqual(("map-load", "realloc"), config.scenarios)
        self.assertEqual("--tlsf-range-index", config.factor_option)
        self.assertEqual(("off", "on"), config.factor_values)
        self.assertEqual("on", config.reference_value)
        self.assertEqual(
            (
                ("--caller-mode", "static"),
                ("--pool-initial-mib", "4"),
            ),
            config.fixed_options,
        )
        self.assertEqual(9, config.repetitions)
        self.assertEqual(42, config.seed)
        self.assertEqual(300, config.bootstrap_iterations)
        self.assertEqual(30.0, config.timeout_seconds)


if __name__ == "__main__":
    unittest.main()
