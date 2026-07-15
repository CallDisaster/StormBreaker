from __future__ import annotations

"""Interleaved single-factor runner for the StormBreaker allocator benchmark."""

import argparse
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
import math
from pathlib import Path
import random
import re
import subprocess
import sys
from typing import Any

import stormbreaker_allocator_benchmark as benchmark


DEFAULT_OUTPUT_DIR = (
    benchmark.REPO_ROOT / "stormbreaker_allocator_factor_benchmark_results"
)
DEFAULT_TIMEOUT_SECONDS = 600.0
SUMMARY_SCHEMA = "stormbreaker.allocator-factor-benchmark.summary.v1"
_CONTROL_OPTIONS = {
    "--engine",
    "--backend",
    "--scenario",
    "--profile",
    "--seed",
}


@dataclass(frozen=True)
class FactorRoundSpec:
    scenario: str
    phase: str
    repetition: int
    order: int
    factor_value: str
    seed: int

    @property
    def identity(self) -> tuple[str, str, int, int, str, int]:
        return (
            self.scenario,
            self.phase,
            self.repetition,
            self.order,
            self.factor_value,
            self.seed,
        )


@dataclass(frozen=True)
class RunnerConfig:
    factor_option: str
    factor_values: tuple[str, ...]
    executable: Path = benchmark.DEFAULT_EXECUTABLE
    output_dir: Path = DEFAULT_OUTPUT_DIR
    engine: str = "takeover"
    backend: str = "hybrid"
    profile: str = benchmark.DEFAULT_PROFILE
    scenarios: tuple[str, ...] = benchmark.DEFAULT_SCENARIOS
    reference_value: str | None = None
    repetitions: int = benchmark.DEFAULT_REPETITIONS
    seed: int = benchmark.DEFAULT_SEED
    bootstrap_iterations: int = benchmark.DEFAULT_BOOTSTRAP_ITERATIONS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    fixed_options: tuple[tuple[str, str], ...] = ()


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


def normalize_factor_option(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise benchmark.BenchmarkFailure("factor option must not be empty")
    option = value if value.startswith("--") else f"--{value}"
    if not re.fullmatch(r"--[a-z0-9][a-z0-9-]*", option):
        raise benchmark.BenchmarkFailure(
            "factor option must be one lowercase long CLI option"
        )
    if option in _CONTROL_OPTIONS:
        raise benchmark.BenchmarkFailure(
            f"factor option {option} conflicts with fixed benchmark identity"
        )
    return option


def _validate_fixed_option_parts(option: str, value: str) -> tuple[str, str]:
    if not re.fullmatch(r"--[a-z0-9][a-z0-9-]*", option):
        raise benchmark.BenchmarkFailure(
            "fixed option name must be one lowercase long CLI option"
        )
    if (
        not value
        or value != value.strip()
        or any(character in value for character in ("\0", "\r", "\n"))
    ):
        raise benchmark.BenchmarkFailure(
            "fixed option value must be non-empty and have no surrounding "
            "whitespace or control lines"
        )
    return option, value


def parse_fixed_option(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise benchmark.BenchmarkFailure("fixed option must use --NAME=VALUE")
    option, separator, option_value = value.partition("=")
    if not separator:
        raise benchmark.BenchmarkFailure("fixed option must use --NAME=VALUE")
    return _validate_fixed_option_parts(option, option_value)


def normalize_fixed_options(
    fixed_options: Sequence[tuple[str, str]], factor_option: str
) -> tuple[tuple[str, str], ...]:
    factor = normalize_factor_option(factor_option)
    if not isinstance(fixed_options, Sequence) or isinstance(
        fixed_options, (str, bytes)
    ):
        raise benchmark.BenchmarkFailure(
            "fixed options must contain --NAME/VALUE pairs"
        )
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in fixed_options:
        if (
            not isinstance(entry, Sequence)
            or isinstance(entry, (str, bytes))
            or len(entry) != 2
        ):
            raise benchmark.BenchmarkFailure(
                "fixed options must contain --NAME/VALUE pairs"
            )
        option_name, raw_value = entry
        if not isinstance(option_name, str) or not isinstance(raw_value, str):
            raise benchmark.BenchmarkFailure(
                "fixed option names and values must be strings"
            )
        option, option_value = _validate_fixed_option_parts(
            option_name, raw_value
        )
        if option in _CONTROL_OPTIONS:
            raise benchmark.BenchmarkFailure(
                f"fixed option {option} conflicts with fixed benchmark identity"
            )
        if option == factor:
            raise benchmark.BenchmarkFailure(
                f"fixed option {option} conflicts with factor option"
            )
        if option in seen:
            raise benchmark.BenchmarkFailure(f"duplicate fixed option: {option}")
        seen.add(option)
        normalized.append((option, option_value))
    return tuple(sorted(normalized, key=lambda item: item[0]))


def factor_field_name(option: str) -> str:
    return normalize_factor_option(option)[2:].replace("-", "_")


def canonical_factor_echo(value: str) -> bool | int | str:
    """Translate one CLI spelling to the type emitted by the C++ benchmark."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise benchmark.BenchmarkFailure(
            "factor values must be non-empty strings without surrounding whitespace"
        )
    if any(character in value for character in ("\0", "\r", "\n")):
        raise benchmark.BenchmarkFailure("factor values must not contain control lines")
    folded = value.casefold()
    if folded in ("on", "true"):
        return True
    if folded in ("off", "false"):
        return False
    if re.fullmatch(r"[+-]?[0-9]+", value):
        return int(value, 10)
    if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    return value


def _typed_identity(value: Any) -> tuple[str, Any]:
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, str):
        return ("str", value)
    return (type(value).__name__, value)


def _validate_factor_values(values: Sequence[str]) -> tuple[str, ...]:
    selected = tuple(values)
    if len(selected) < 2:
        raise benchmark.BenchmarkFailure("at least two factor values are required")
    echoes = [canonical_factor_echo(value) for value in selected]
    identities = [_typed_identity(value) for value in echoes]
    if len(set(selected)) != len(selected):
        raise benchmark.BenchmarkFailure("factor values must not contain duplicates")
    if len(set(identities)) != len(identities):
        raise benchmark.BenchmarkFailure(
            "factor values must have distinct echoed values"
        )
    return selected


def _reference_value(config: RunnerConfig) -> str:
    reference = (
        config.factor_values[0]
        if config.reference_value is None
        else config.reference_value
    )
    if reference not in config.factor_values:
        raise benchmark.BenchmarkFailure(
            f"reference value {reference!r} is not one of the factor values"
        )
    return reference


def _validate_config(config: RunnerConfig, *, require_executable: bool) -> None:
    normalize_factor_option(config.factor_option)
    normalize_fixed_options(config.fixed_options, config.factor_option)
    _validate_factor_values(config.factor_values)
    _reference_value(config)
    try:
        benchmark._validate_selection(config.scenarios, benchmark.SCENARIOS, "scenarios")
        benchmark._validate_selection((config.engine,), benchmark.ENGINES, "engines")
        benchmark._validate_selection((config.backend,), benchmark.BACKENDS, "backends")
    except ValueError as exc:
        raise benchmark.BenchmarkFailure(str(exc)) from exc
    if config.profile not in benchmark.PROFILES:
        raise benchmark.BenchmarkFailure(f"unknown profile: {config.profile}")
    if any(
        scenario in benchmark.TAKEOVER_SCENARIOS
        for scenario in config.scenarios
    ) and config.engine != "takeover":
        raise benchmark.BenchmarkFailure(
            "heap enumeration/destroy scenarios require engine=takeover"
        )
    if config.repetitions <= 0:
        raise benchmark.BenchmarkFailure("repetitions must be positive")
    if not 0 <= config.seed <= 0xFFFFFFFFFFFFFFFF:
        raise benchmark.BenchmarkFailure("seed must be an unsigned 64-bit integer")
    if config.bootstrap_iterations <= 0:
        raise benchmark.BenchmarkFailure("bootstrap iterations must be positive")
    if not math.isfinite(config.timeout_seconds) or config.timeout_seconds <= 0.0:
        raise benchmark.BenchmarkFailure("timeout seconds must be finite and positive")
    if require_executable:
        if config.executable.suffix.casefold() != ".exe":
            raise benchmark.BenchmarkFailure(
                "benchmark executable must have an .exe suffix"
            )
        if not config.executable.is_file():
            raise benchmark.BenchmarkFailure(
                f"benchmark executable not found: {config.executable}"
            )


def generate_schedule(
    scenarios: Sequence[str],
    factor_values: Sequence[str],
    repetitions: int,
    seed: int,
) -> list[FactorRoundSpec]:
    """Create complete blocks with one warmup and cyclic value rotation."""
    try:
        selected_scenarios = benchmark._validate_selection(
            scenarios, benchmark.SCENARIOS, "scenarios"
        )
    except ValueError as exc:
        raise benchmark.BenchmarkFailure(str(exc)) from exc
    selected_values = _validate_factor_values(factor_values)
    if repetitions <= 0:
        raise benchmark.BenchmarkFailure("repetitions must be positive")
    if not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        raise benchmark.BenchmarkFailure("seed must be an unsigned 64-bit integer")

    rng = random.Random(seed)
    schedule: list[FactorRoundSpec] = []
    for scenario in selected_scenarios:
        base = list(selected_values)
        rng.shuffle(base)
        initial_rotation = rng.randrange(len(base))
        block_index = 0
        for phase, block_count in (("warmup", 1), ("measured", repetitions)):
            for repetition in range(block_count):
                rotation = (initial_rotation + block_index) % len(base)
                ordered = base[rotation:] + base[:rotation]
                reported_repetition = 0 if phase == "warmup" else repetition + 1
                schedule.extend(
                    FactorRoundSpec(
                        scenario=scenario,
                        phase=phase,
                        repetition=reported_repetition,
                        order=order,
                        factor_value=value,
                        seed=seed,
                    )
                    for order, value in enumerate(ordered)
                )
                block_index += 1
    return schedule


def build_command(
    executable: Path, config: RunnerConfig, spec: FactorRoundSpec
) -> list[str]:
    command = [
        str(executable),
        "--engine",
        config.engine,
        "--backend",
        config.backend,
        "--scenario",
        spec.scenario,
        "--profile",
        config.profile,
        "--seed",
        str(spec.seed),
    ]
    for option, value in normalize_fixed_options(
        config.fixed_options, config.factor_option
    ):
        command.extend((option, value))
    command.extend(
        (
            normalize_factor_option(config.factor_option),
            spec.factor_value,
        )
    )
    return command


def _reported_backend(config: RunnerConfig) -> str:
    return config.engine if config.engine in benchmark.DIRECT_ENGINES else config.backend


def _require_identity(
    result: Mapping[str, Any], config: RunnerConfig, spec: FactorRoundSpec
) -> None:
    expected: dict[str, Any] = {
        "engine": config.engine,
        "backend": _reported_backend(config),
        "scenario": spec.scenario,
        "profile": config.profile,
        "seed": spec.seed,
    }
    for key, expected_value in expected.items():
        if key not in result:
            raise benchmark.BenchmarkFailure(
                f"benchmark result is missing identity field {key}"
            )
        actual = result[key]
        if key == "seed":
            matches = (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and actual == expected_value
            )
        else:
            matches = isinstance(actual, str) and actual == expected_value
        if not matches:
            raise benchmark.BenchmarkFailure(
                f"benchmark result {key} mismatch: expected {expected_value!r}, "
                f"got {actual!r}"
            )


def _require_factor_echo(
    result: Mapping[str, Any], config: RunnerConfig, spec: FactorRoundSpec
) -> bool | int | str:
    field = factor_field_name(config.factor_option)
    if field not in result:
        raise benchmark.BenchmarkFailure(
            f"benchmark result is missing factor echo field {field}"
        )
    expected = canonical_factor_echo(spec.factor_value)
    actual = result[field]
    if _typed_identity(actual) != _typed_identity(expected):
        raise benchmark.BenchmarkFailure(
            f"benchmark factor echo mismatch for {field}: expected {expected!r}, "
            f"got {actual!r}"
        )
    return expected


def extract_metrics(
    result: Mapping[str, Any],
    factor_option: str,
    fixed_options: Sequence[tuple[str, str]] = (),
) -> dict[str, float]:
    """Use the base metric parser after removing benchmark configuration echoes."""
    fields = {factor_field_name(factor_option)}
    fields.update(
        factor_field_name(option)
        for option, _value in normalize_fixed_options(
            fixed_options, factor_option
        )
    )
    filtered = dict(result)
    for field in fields:
        filtered.pop(field, None)
    return benchmark.extract_metrics(filtered)


def validate_result(
    result: Mapping[str, Any], config: RunnerConfig, spec: FactorRoundSpec
) -> str:
    base_spec = benchmark.RoundSpec(
        scenario=spec.scenario,
        phase=spec.phase,
        repetition=spec.repetition,
        order=spec.order,
        engine=config.engine,
        backend=config.backend,
        seed=spec.seed,
    )
    checksum = benchmark.validate_result(result, base_spec, config.profile)
    _require_identity(result, config, spec)
    _require_factor_echo(result, config, spec)
    extract_metrics(result, config.factor_option, config.fixed_options)
    return checksum


def execute_round(
    config: RunnerConfig,
    spec: FactorRoundSpec,
    *,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    """Launch one fresh benchmark process and validate its final JSON line."""
    command = build_command(config.executable, config, spec)
    runner = process_runner or subprocess.run
    try:
        completed = runner(
            command,
            cwd=str(config.executable.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=config.timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise benchmark.BenchmarkFailure(
            f"benchmark process timed out after {config.timeout_seconds:g} seconds"
        ) from exc
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise benchmark.BenchmarkFailure(
            f"benchmark process failed to start or produce UTF-8 output: {exc}"
        ) from exc
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        detail = f": {stderr[-2000:]}" if stderr else ""
        raise benchmark.BenchmarkFailure(
            f"benchmark process exited with code {completed.returncode}{detail}"
        )
    result = benchmark.parse_last_json_line(completed.stdout or "")
    validate_result(result, config, spec)
    return result


def make_record(
    config: RunnerConfig,
    spec: FactorRoundSpec,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    checksum = validate_result(result, config, spec)
    field = factor_field_name(config.factor_option)
    return {
        "scenario": spec.scenario,
        "phase": spec.phase,
        "repetition": spec.repetition,
        "order": spec.order,
        "engine": config.engine,
        "backend": config.backend,
        "profile": config.profile,
        "seed": spec.seed,
        "factorOption": normalize_factor_option(config.factor_option),
        "factorField": field,
        "factorValue": spec.factor_value,
        "factorEcho": result[field],
        "checksum": checksum,
        "result": dict(result),
    }


def _record_identity(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("scenario"),
        record.get("phase"),
        record.get("repetition"),
        record.get("order"),
        record.get("factorValue"),
        record.get("seed"),
    )


def _validate_coverage(
    records: Sequence[Mapping[str, Any]], config: RunnerConfig
) -> None:
    schedule = generate_schedule(
        config.scenarios, config.factor_values, config.repetitions, config.seed
    )
    expected = Counter(spec.identity for spec in schedule)
    actual = Counter(_record_identity(record) for record in records)
    if actual != expected:
        missing = list((expected - actual).elements())
        unexpected = list((actual - expected).elements())
        raise benchmark.BenchmarkFailure(
            "factor benchmark coverage is incomplete or duplicated: "
            f"missing={missing[:3]!r}, unexpected={unexpected[:3]!r}"
        )

    option = normalize_factor_option(config.factor_option)
    field = factor_field_name(option)
    by_identity = {spec.identity: spec for spec in schedule}
    for record in records:
        fixed_identity = {
            "engine": config.engine,
            "backend": config.backend,
            "profile": config.profile,
            "factorOption": option,
            "factorField": field,
        }
        for key, expected_value in fixed_identity.items():
            if record.get(key) != expected_value:
                raise benchmark.BenchmarkFailure(f"raw record {key} mismatch")
        spec = by_identity[_record_identity(record)]
        result = record.get("result")
        if not isinstance(result, Mapping):
            raise benchmark.BenchmarkFailure("raw record result must be an object")
        checksum = validate_result(result, config, spec)
        if checksum != benchmark.normalize_checksum(record.get("checksum")):
            raise benchmark.BenchmarkFailure(
                "raw record checksum disagrees with its result"
            )
        if _typed_identity(record.get("factorEcho")) != _typed_identity(
            result[field]
        ):
            raise benchmark.BenchmarkFailure(
                "raw record factor echo disagrees with its result"
            )
    benchmark.validate_checksums(records)


def _metrics_by_repetition(
    records: Sequence[Mapping[str, Any]],
    factor_option: str,
    fixed_options: Sequence[tuple[str, str]],
) -> dict[int, dict[str, float]]:
    by_repetition: dict[int, dict[str, float]] = {}
    metric_names: set[str] | None = None
    for record in sorted(records, key=lambda row: int(row["repetition"])):
        repetition = int(record["repetition"])
        if repetition in by_repetition:
            raise benchmark.BenchmarkFailure(
                f"duplicate measured repetition {repetition}"
            )
        result = record.get("result")
        if not isinstance(result, Mapping):
            raise benchmark.BenchmarkFailure("raw record result must be an object")
        metrics = extract_metrics(result, factor_option, fixed_options)
        current_names = set(metrics)
        if metric_names is None:
            metric_names = current_names
        elif current_names != metric_names:
            raise benchmark.BenchmarkFailure(
                "numeric metric set changed between repetitions"
            )
        by_repetition[repetition] = metrics
    return by_repetition


def _records_without_factor_metric(
    records: Sequence[Mapping[str, Any]],
    factor_option: str,
    fixed_options: Sequence[tuple[str, str]],
) -> list[dict[str, Any]]:
    fields = {factor_field_name(factor_option)}
    fields.update(
        factor_field_name(option)
        for option, _value in normalize_fixed_options(
            fixed_options, factor_option
        )
    )
    sanitized: list[dict[str, Any]] = []
    for record in records:
        copied = dict(record)
        result = copied.get("result")
        if not isinstance(result, Mapping):
            raise benchmark.BenchmarkFailure("raw record result must be an object")
        copied_result = dict(result)
        for field in fields:
            copied_result.pop(field, None)
        copied["result"] = copied_result
        sanitized.append(copied)
    return sanitized


def summarize_results(
    records: Sequence[Mapping[str, Any]], config: RunnerConfig
) -> dict[str, Any]:
    _validate_config(config, require_executable=False)
    _validate_coverage(records, config)
    reference = _reference_value(config)
    option = normalize_factor_option(config.factor_option)
    fixed_options = normalize_fixed_options(config.fixed_options, option)
    field = factor_field_name(option)
    scenario_summaries: dict[str, Any] = {}

    for scenario in config.scenarios:
        measured = [
            record
            for record in records
            if record["scenario"] == scenario and record["phase"] == "measured"
        ]
        by_value = {
            value: [record for record in measured if record["factorValue"] == value]
            for value in config.factor_values
        }
        metrics_by_value: dict[str, dict[int, dict[str, float]]] = {}
        expected_metric_names: set[str] | None = None
        value_summaries: dict[str, Any] = {}

        for value in config.factor_values:
            value_records = by_value[value]
            repetitions = _metrics_by_repetition(
                value_records, option, fixed_options
            )
            if sorted(repetitions) != list(range(1, config.repetitions + 1)):
                raise benchmark.BenchmarkFailure(
                    f"measured repetitions are incomplete for {scenario}/{value}"
                )
            metric_names = set(next(iter(repetitions.values())))
            if expected_metric_names is None:
                expected_metric_names = metric_names
            elif metric_names != expected_metric_names:
                raise benchmark.BenchmarkFailure(
                    f"numeric metric set differs between factor values in {scenario}"
                )
            metrics_by_value[value] = repetitions
            metric_summaries = {
                metric: benchmark._metric_summary(
                    [repetitions[index][metric] for index in sorted(repetitions)],
                    bootstrap_iterations=config.bootstrap_iterations,
                    seed=benchmark._stable_seed(
                        config.seed, scenario, option, value, metric
                    ),
                )
                for metric in sorted(metric_names)
            }
            value_summaries[value] = {
                "factorValue": value,
                "factorEcho": canonical_factor_echo(value),
                "samples": config.repetitions,
                "checksum": benchmark.normalize_checksum(value_records[0]["checksum"]),
                "metrics": metric_summaries,
            }

        comparisons: dict[str, Any] = {}
        baseline_records = _records_without_factor_metric(
            by_value[reference], option, fixed_options
        )
        for value in config.factor_values:
            candidate_records = _records_without_factor_metric(
                by_value[value], option, fixed_options
            )
            comparisons[value] = benchmark._comparison_summary(
                baseline_records,
                candidate_records,
                baseline_key=reference,
                candidate_key=value,
                bootstrap_iterations=config.bootstrap_iterations,
                seed=benchmark._stable_seed(
                    config.seed, scenario, option, reference, value
                ),
            )

        scenario_summaries[scenario] = {
            "values": value_summaries,
            "relativeToReference": {
                "reference": reference,
                "comparisons": comparisons,
            },
        }

    return {
        "schema": SUMMARY_SCHEMA,
        "valid": True,
        "engine": config.engine,
        "backend": config.backend,
        "profile": config.profile,
        "seed": config.seed,
        "warmupRepetitions": 1,
        "measuredRepetitions": config.repetitions,
        "scenarios": scenario_summaries,
        "factor": {
            "option": option,
            "field": field,
            "values": list(config.factor_values),
            "reference": reference,
        },
        "fixedOptions": [
            {"option": fixed_option, "value": value}
            for fixed_option, value in fixed_options
        ],
        "runCount": len(records),
        "measuredRunCount": sum(
            1 for record in records if record["phase"] == "measured"
        ),
        "execution": {
            "processModel": "fresh process per value/scenario/repetition",
            "rotation": "fixed-seed cyclic",
            "timeoutSeconds": config.timeout_seconds,
        },
        "bootstrap": {
            "method": "seeded percentile bootstrap",
            "confidence": 0.95,
            "iterations": config.bootstrap_iterations,
        },
        "rawJsonl": "raw.jsonl",
    }


def run_benchmark(
    config: RunnerConfig, *, process_runner: ProcessRunner | None = None
) -> dict[str, Any]:
    """Run all factor values and publish a summary only after full validation."""
    try:
        config.output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise benchmark.BenchmarkFailure(
            f"cannot create benchmark output directory: {exc}"
        ) from exc

    raw_path = config.output_dir / "raw.jsonl"
    summary_path = config.output_dir / "summary.json"
    failure_path = config.output_dir / "failure.json"
    try:
        # A stale success artifact must disappear before any fallible setup work.
        summary_path.unlink(missing_ok=True)
        raw_path.unlink(missing_ok=True)
        failure_path.unlink(missing_ok=True)
    except OSError as exc:
        raise benchmark.BenchmarkFailure(
            f"cannot clear stale benchmark output: {exc}"
        ) from exc
    records: list[dict[str, Any]] = []
    schedule: list[FactorRoundSpec] = []

    try:
        _validate_config(config, require_executable=True)
        schedule = generate_schedule(
            config.scenarios,
            config.factor_values,
            config.repetitions,
            config.seed,
        )
        with raw_path.open("w", encoding="utf-8", newline="\n") as stream:
            for spec in schedule:
                result = execute_round(config, spec, process_runner=process_runner)
                record = make_record(config, spec, result)
                stream.write(
                    json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
                )
                stream.flush()
                records.append(record)
                benchmark.validate_checksums(records)

        summary = summarize_results(records, config)
        benchmark._write_json_atomic(summary_path, summary)
        return summary
    except Exception as exc:
        summary_path.unlink(missing_ok=True)
        failure = {
            "schema": SUMMARY_SCHEMA,
            "valid": False,
            "error": str(exc),
            "completedRuns": len(records),
            "expectedRuns": len(schedule),
            "rawJsonl": raw_path.name,
        }
        try:
            benchmark._write_json_atomic(failure_path, failure)
        except OSError:
            pass
        if isinstance(exc, benchmark.BenchmarkFailure):
            raise
        raise benchmark.BenchmarkFailure(f"factor benchmark runner failed: {exc}") from exc


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0.0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return parsed


def _flatten_values(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for value in values
        for item in value.split(",")
        if item.strip()
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one StormBreaker allocator benchmark factor in interleaved fresh "
            "processes. Pass a long option as NAME or --factor-option=--NAME."
        )
    )
    parser.add_argument("--executable", type=Path, default=benchmark.DEFAULT_EXECUTABLE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--engine", choices=benchmark.ENGINES, default="takeover")
    parser.add_argument("--backend", choices=benchmark.BACKENDS, default="hybrid")
    parser.add_argument(
        "--profile", choices=benchmark.PROFILES, default=benchmark.DEFAULT_PROFILE
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(benchmark.DEFAULT_SCENARIOS),
        metavar="SCENARIO",
        help="space- or comma-separated fixed scenarios",
    )
    parser.add_argument(
        "--factor-option",
        required=True,
        metavar="OPTION",
        help="one benchmark CLI option, for example pool-initial-mib",
    )
    parser.add_argument(
        "--fixed-option",
        action="append",
        default=[],
        metavar="--NAME=VALUE",
        help=(
            "fixed benchmark long option; repeat as needed, for example "
            "--fixed-option --pool-initial-mib=4"
        ),
    )
    parser.add_argument(
        "--values",
        nargs="+",
        required=True,
        metavar="VALUE",
        help="two or more space- or comma-separated factor values",
    )
    parser.add_argument("--reference-value", metavar="VALUE")
    parser.add_argument(
        "--repetitions",
        type=benchmark._positive_integer,
        default=benchmark.DEFAULT_REPETITIONS,
    )
    parser.add_argument("--seed", type=benchmark._uint64, default=benchmark.DEFAULT_SEED)
    parser.add_argument(
        "--bootstrap-iterations",
        type=benchmark._positive_integer,
        default=benchmark.DEFAULT_BOOTSTRAP_ITERATIONS,
    )
    parser.add_argument(
        "--timeout-seconds", type=_positive_float, default=DEFAULT_TIMEOUT_SECONDS
    )
    return parser


def _prepare_cli_args(argv: Sequence[str] | None) -> list[str]:
    source = list(sys.argv[1:] if argv is None else argv)
    prepared: list[str] = []
    index = 0
    while index < len(source):
        argument = source[index]
        if argument == "--fixed-option" and index + 1 < len(source):
            prepared.append(f"--fixed-option={source[index + 1]}")
            index += 2
            continue
        prepared.append(argument)
        index += 1
    return prepared


def parse_args(argv: Sequence[str] | None = None) -> RunnerConfig:
    parser = build_parser()
    args = parser.parse_args(_prepare_cli_args(argv))
    try:
        scenarios = benchmark._split_cli_selection(
            args.scenarios, benchmark.SCENARIOS, "scenarios"
        )
        option = normalize_factor_option(args.factor_option)
        fixed_options = normalize_fixed_options(
            tuple(parse_fixed_option(value) for value in args.fixed_option),
            option,
        )
        values = _validate_factor_values(_flatten_values(args.values))
        reference = args.reference_value or values[0]
        if reference not in values:
            raise benchmark.BenchmarkFailure(
                f"reference value {reference!r} is not one of the factor values"
            )
    except (argparse.ArgumentTypeError, benchmark.BenchmarkFailure) as exc:
        parser.error(str(exc))
    return RunnerConfig(
        factor_option=option,
        factor_values=values,
        fixed_options=fixed_options,
        executable=args.executable.resolve(),
        output_dir=args.output_dir.resolve(),
        engine=args.engine,
        backend=args.backend,
        profile=args.profile,
        scenarios=scenarios,
        reference_value=reference,
        repetitions=args.repetitions,
        seed=args.seed,
        bootstrap_iterations=args.bootstrap_iterations,
        timeout_seconds=args.timeout_seconds,
    )


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_args(argv)
    try:
        run_benchmark(config)
    except benchmark.BenchmarkFailure as exc:
        print(f"factor benchmark failed closed: {exc}", file=sys.stderr)
        return 1
    print(f"raw JSONL: {config.output_dir / 'raw.jsonl'}")
    print(f"summary JSON: {config.output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
