from __future__ import annotations

"""Independent-process runner for the StormBreaker allocator logic benchmark."""

import argparse
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
from typing import Any


TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DEFAULT_EXECUTABLE = (
    REPO_ROOT
    / "autotest_results"
    / "cmake_full_takeover"
    / "Release"
    / "StormBreakerAllocatorBenchmark.exe"
)
DEFAULT_OUTPUT_DIR = REPO_ROOT / "stormbreaker_allocator_benchmark_results"

DIRECT_ENGINES = (
    "native-storm",
    "winheap",
    "private-heap",
    "rpmalloc",
    "rpmalloc-threaded",
    "segregated-arena",
    "segregated-hybrid",
)
ENGINES = (*DIRECT_ENGINES, "legacy-large", "pool", "takeover")
DEFAULT_ENGINES = ("winheap", "takeover")
DEFAULT_BACKENDS = ("tlsf", "mimalloc", "hybrid")
BACKENDS = (*DEFAULT_BACKENDS, "tlsf-sharded")
DEFAULT_SCENARIOS = (
    "map-load",
    "caller-locality",
    "small-churn",
    "realloc",
    "editor-burst",
    "cross-thread",
)
TAKEOVER_SCENARIOS = (
    "trim-cycle",
    "trim-fragmented",
    "registry-saturation",
    "heap-enumeration",
    "heap-destroy",
    "caller-hash",
)
SCENARIOS = (*DEFAULT_SCENARIOS, *TAKEOVER_SCENARIOS)
PROFILES = ("quick", "standard")
DEFAULT_PROFILE = "quick"
DEFAULT_REPETITIONS = 7
DEFAULT_SEED = 0xC0FFEE
DEFAULT_BOOTSTRAP_ITERATIONS = 5_000
SUMMARY_SCHEMA = "stormbreaker.allocator-benchmark.summary.v1"


class BenchmarkFailure(RuntimeError):
    """A process, correctness, coverage, or result validation failed."""


@dataclass(frozen=True)
class EngineConfig:
    engine: str
    backend: str

    @property
    def key(self) -> str:
        if self.engine in DIRECT_ENGINES:
            return self.engine
        return f"{self.engine}/{self.backend}"


@dataclass(frozen=True)
class RoundSpec:
    scenario: str
    phase: str
    repetition: int
    order: int
    engine: str
    backend: str
    seed: int

    @property
    def configuration(self) -> EngineConfig:
        return EngineConfig(self.engine, self.backend)

    @property
    def identity(self) -> tuple[str, str, int, int, str, str, int]:
        return (
            self.scenario,
            self.phase,
            self.repetition,
            self.order,
            self.engine,
            self.backend,
            self.seed,
        )


@dataclass(frozen=True)
class RunnerConfig:
    executable: Path = DEFAULT_EXECUTABLE
    output_dir: Path = DEFAULT_OUTPUT_DIR
    profile: str = DEFAULT_PROFILE
    scenarios: tuple[str, ...] = DEFAULT_SCENARIOS
    backends: tuple[str, ...] = DEFAULT_BACKENDS
    engines: tuple[str, ...] = DEFAULT_ENGINES
    repetitions: int = DEFAULT_REPETITIONS
    seed: int = DEFAULT_SEED


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


def _validate_selection(
    values: Sequence[str], allowed: Sequence[str], label: str
) -> tuple[str, ...]:
    selected = tuple(values)
    if not selected:
        raise ValueError(f"{label} must not be empty")
    unknown = [value for value in selected if value not in allowed]
    if unknown:
        raise ValueError(f"unknown {label}: {', '.join(unknown)}")
    if len(set(selected)) != len(selected):
        raise ValueError(f"{label} must not contain duplicates")
    return selected


def reference_backend(backends: Sequence[str]) -> str:
    selected = _validate_selection(backends, BACKENDS, "backends")
    return "tlsf" if "tlsf" in selected else selected[0]


def build_configurations(
    backends: Sequence[str] = DEFAULT_BACKENDS,
    engines: Sequence[str] = DEFAULT_ENGINES,
) -> tuple[EngineConfig, ...]:
    """Expand direct engines once and routed engines once per backend."""
    selected = _validate_selection(backends, BACKENDS, "backends")
    selected_engines = _validate_selection(engines, ENGINES, "engines")
    control_backend = reference_backend(selected)
    configurations: list[EngineConfig] = []
    for engine in selected_engines:
        if engine in ("pool", "takeover"):
            configurations.extend(
                EngineConfig(engine, backend) for backend in selected
            )
        else:
            configurations.append(EngineConfig(engine, control_backend))
    return tuple(configurations)


def generate_schedule(
    scenarios: Sequence[str] = DEFAULT_SCENARIOS,
    backends: Sequence[str] = DEFAULT_BACKENDS,
    repetitions: int = DEFAULT_REPETITIONS,
    seed: int = DEFAULT_SEED,
    *,
    engines: Sequence[str] = DEFAULT_ENGINES,
) -> list[RoundSpec]:
    """Generate complete blocks with a seeded start and cyclic engine rotation."""
    selected_scenarios = _validate_selection(scenarios, SCENARIOS, "scenarios")
    configurations = build_configurations(backends, engines)
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    if not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seed must be an unsigned 64-bit integer")

    rng = random.Random(seed)
    schedule: list[RoundSpec] = []
    for scenario in selected_scenarios:
        base = list(configurations)
        rng.shuffle(base)
        initial_rotation = rng.randrange(len(base))
        block = 0
        for phase, phase_repetitions in (("warmup", 1), ("measured", repetitions)):
            for repetition in range(phase_repetitions):
                rotation = (initial_rotation + block) % len(base)
                ordered = base[rotation:] + base[:rotation]
                reported_repetition = 0 if phase == "warmup" else repetition + 1
                schedule.extend(
                    RoundSpec(
                        scenario=scenario,
                        phase=phase,
                        repetition=reported_repetition,
                        order=order,
                        engine=configuration.engine,
                        backend=configuration.backend,
                        seed=seed,
                    )
                    for order, configuration in enumerate(ordered)
                )
                block += 1
    return schedule


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def parse_last_json_line(stdout: str) -> dict[str, Any]:
    """Parse exactly the final non-empty stdout line as a strict JSON object."""
    if not isinstance(stdout, str):
        raise BenchmarkFailure("benchmark stdout is not text")
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise BenchmarkFailure("benchmark stdout has no non-empty line")
    last_line = lines[-1].lstrip("\ufeff")
    try:
        parsed = json.loads(
            last_line,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise BenchmarkFailure(
            "benchmark stdout final non-empty line is not strict JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise BenchmarkFailure("benchmark JSON result must be an object")
    return parsed


def _assert_finite_numbers(value: Any, path: str = "result") -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise BenchmarkFailure(f"non-finite number at {path}")
    if isinstance(value, Mapping):
        for key, child in value.items():
            _assert_finite_numbers(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_finite_numbers(child, f"{path}[{index}]")


def normalize_checksum(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        raise BenchmarkFailure("benchmark checksum is missing or invalid")
    if isinstance(value, int):
        if value < 0:
            raise BenchmarkFailure("benchmark checksum must not be negative")
        return str(value)
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkFailure("benchmark checksum must be a non-empty string or integer")

    checksum = value.strip()
    try:
        if checksum.lower().startswith("0x"):
            return str(int(checksum, 16))
        if checksum.isdecimal():
            return str(int(checksum, 10))
    except ValueError as exc:
        raise BenchmarkFailure("benchmark checksum is malformed") from exc
    return checksum.casefold()


def _result_checksum(result: Mapping[str, Any]) -> str:
    values: list[Any] = []
    if "checksum" in result:
        values.append(result["checksum"])
    correctness = result.get("correctness")
    if isinstance(correctness, Mapping) and "checksum" in correctness:
        values.append(correctness["checksum"])
    if not values:
        raise BenchmarkFailure("benchmark result has no checksum")
    normalized = [normalize_checksum(value) for value in values]
    if len(set(normalized)) != 1:
        raise BenchmarkFailure("benchmark result contains conflicting checksums")
    return normalized[0]


_ROOT_METADATA = {
    "backend",
    "checksum",
    "correctness",
    "engine",
    "profile",
    "scenario",
    "schema",
    "schemaVersion",
    "seed",
    "valid",
}


def _flatten_numeric(
    value: Any, prefix: str, destination: dict[str, float]
) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float)):
        converted = float(value)
        if not math.isfinite(converted):
            raise BenchmarkFailure(f"non-finite metric: {prefix}")
        if prefix in destination and destination[prefix] != converted:
            raise BenchmarkFailure(f"conflicting metric values for {prefix}")
        destination[prefix] = converted
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten_numeric(child, child_prefix, destination)


def extract_metrics(result: Mapping[str, Any]) -> dict[str, float]:
    """Flatten numeric metrics while excluding identity and correctness metadata."""
    metrics: dict[str, float] = {}
    nested_metrics = result.get("metrics")
    if nested_metrics is not None:
        if not isinstance(nested_metrics, Mapping):
            raise BenchmarkFailure("benchmark metrics must be an object")
        _flatten_numeric(nested_metrics, "", metrics)

    for key, value in result.items():
        if key in _ROOT_METADATA or key == "metrics":
            continue
        _flatten_numeric(value, key, metrics)
    if not metrics:
        raise BenchmarkFailure("benchmark result has no numeric metrics")
    return metrics


def _identity_matches(key: str, actual: Any, expected: Any) -> bool:
    if key == "seed":
        return not isinstance(actual, bool) and isinstance(actual, int) and actual == expected
    return isinstance(actual, str) and actual == expected


def validate_result(
    result: Mapping[str, Any], spec: RoundSpec, profile: str
) -> str:
    """Validate one successful process result and return its canonical checksum."""
    if result.get("valid") is not True:
        raise BenchmarkFailure("benchmark result is missing valid=true")
    _assert_finite_numbers(result)

    expected_identity: dict[str, Any] = {
        "engine": spec.engine,
        "scenario": spec.scenario,
        "profile": profile,
        "seed": spec.seed,
    }
    for key, expected in expected_identity.items():
        if key in result and not _identity_matches(key, result[key], expected):
            raise BenchmarkFailure(
                f"benchmark result {key} mismatch: expected {expected!r}, "
                f"got {result[key]!r}"
            )

    if "backend" in result:
        reported_backend = result["backend"]
        accepted = {spec.backend}
        if spec.engine in DIRECT_ENGINES:
            accepted.update((spec.engine, "none"))
        if not isinstance(reported_backend, str) or reported_backend not in accepted:
            raise BenchmarkFailure(
                f"benchmark result backend mismatch: expected one of "
                f"{sorted(accepted)!r}, got {reported_backend!r}"
            )

    checksum = _result_checksum(result)
    extract_metrics(result)
    return checksum


def build_command(executable: Path, spec: RoundSpec, profile: str) -> list[str]:
    return [
        str(executable),
        "--engine",
        spec.engine,
        "--backend",
        spec.backend,
        "--scenario",
        spec.scenario,
        "--profile",
        profile,
        "--seed",
        str(spec.seed),
    ]


def execute_round(
    executable: Path,
    spec: RoundSpec,
    profile: str,
    *,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    """Run one fresh process and return its validated final JSON object."""
    command = build_command(executable, spec, profile)
    runner = process_runner or subprocess.run
    try:
        completed = runner(
            command,
            cwd=str(executable.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise BenchmarkFailure(
            f"benchmark process failed to start or produce UTF-8 output: {exc}"
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        detail = f": {stderr[-2000:]}" if stderr else ""
        raise BenchmarkFailure(
            f"benchmark process exited with code {completed.returncode}{detail}"
        )
    result = parse_last_json_line(completed.stdout or "")
    validate_result(result, spec, profile)
    return result


def make_record(
    spec: RoundSpec, profile: str, result: Mapping[str, Any]
) -> dict[str, Any]:
    checksum = validate_result(result, spec, profile)
    return {
        "scenario": spec.scenario,
        "phase": spec.phase,
        "repetition": spec.repetition,
        "order": spec.order,
        "engine": spec.engine,
        "backend": spec.backend,
        "profile": profile,
        "seed": spec.seed,
        "checksum": checksum,
        "result": dict(result),
    }


def _record_identity(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("scenario"),
        record.get("phase"),
        record.get("repetition"),
        record.get("order"),
        record.get("engine"),
        record.get("backend"),
        record.get("seed"),
    )


def validate_checksums(records: Iterable[Mapping[str, Any]]) -> None:
    """Require one deterministic checksum per profile/scenario/seed trace."""
    expected: dict[tuple[Any, Any, Any], str] = {}
    for record in records:
        key = (record.get("profile"), record.get("scenario"), record.get("seed"))
        checksum = normalize_checksum(record.get("checksum"))
        previous = expected.setdefault(key, checksum)
        if checksum != previous:
            raise BenchmarkFailure(
                "checksum mismatch for "
                f"profile={key[0]!r}, scenario={key[1]!r}, seed={key[2]!r}: "
                f"expected {previous}, got {checksum}"
            )


def percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be in [0, 1]")
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _rounded(value: float) -> float:
    return round(float(value), 6)


def describe(values: Sequence[float]) -> dict[str, Any]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    if not finite:
        return {"n": 0, "median": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(finite),
        "median": _rounded(statistics.median(finite)),
        "p95": _rounded(percentile(finite, 0.95)),
        "min": _rounded(min(finite)),
        "max": _rounded(max(finite)),
    }


def bootstrap_ci(
    values: Sequence[float],
    *,
    statistic: Callable[[Sequence[float]], float] = statistics.median,
    confidence: float = 0.95,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    if not finite:
        return {
            "n": 0,
            "confidence": confidence,
            "iterations": iterations,
            "low": None,
            "high": None,
        }
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if iterations <= 0:
        raise ValueError("iterations must be positive")

    if len(finite) == 1 or all(value == finite[0] for value in finite):
        point = _rounded(statistic(finite))
        return {
            "n": len(finite),
            "confidence": confidence,
            "iterations": iterations,
            "low": point,
            "high": point,
        }

    rng = random.Random(seed)
    count = len(finite)
    estimates = [
        float(statistic([finite[rng.randrange(count)] for _ in range(count)]))
        for _ in range(iterations)
    ]
    alpha = (1.0 - confidence) / 2.0
    return {
        "n": count,
        "confidence": confidence,
        "iterations": iterations,
        "low": _rounded(percentile(estimates, alpha)),
        "high": _rounded(percentile(estimates, 1.0 - alpha)),
    }


def _stable_seed(seed: int, *labels: str) -> int:
    material = ":".join((str(seed), *labels)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "little")


def _metric_summary(
    values: Sequence[float], *, bootstrap_iterations: int, seed: int
) -> dict[str, Any]:
    summary = describe(values)
    summary["bootstrap95Median"] = bootstrap_ci(
        values,
        iterations=bootstrap_iterations,
        seed=_stable_seed(seed, "median"),
    )
    summary["bootstrap95P95"] = bootstrap_ci(
        values,
        statistic=lambda sample: percentile(sample, 0.95),
        iterations=bootstrap_iterations,
        seed=_stable_seed(seed, "p95"),
    )
    return summary


def _configuration_key(record: Mapping[str, Any]) -> str:
    engine = record.get("engine")
    backend = record.get("backend")
    if engine in DIRECT_ENGINES:
        return str(engine)
    return f"{engine}/{backend}"


def _metrics_by_repetition(
    records: Sequence[Mapping[str, Any]],
) -> dict[int, dict[str, float]]:
    by_repetition: dict[int, dict[str, float]] = {}
    metric_names: set[str] | None = None
    for record in sorted(records, key=lambda row: int(row["repetition"])):
        repetition = int(record["repetition"])
        if repetition in by_repetition:
            raise BenchmarkFailure(f"duplicate measured repetition {repetition}")
        result = record.get("result")
        if not isinstance(result, Mapping):
            raise BenchmarkFailure("raw record result must be an object")
        metrics = extract_metrics(result)
        current_names = set(metrics)
        if metric_names is None:
            metric_names = current_names
        elif current_names != metric_names:
            raise BenchmarkFailure("numeric metric set changed between repetitions")
        by_repetition[repetition] = metrics
    return by_repetition


def _comparison_summary(
    baseline_records: Sequence[Mapping[str, Any]],
    candidate_records: Sequence[Mapping[str, Any]],
    *,
    baseline_key: str,
    candidate_key: str,
    bootstrap_iterations: int,
    seed: int,
) -> dict[str, Any]:
    baseline = _metrics_by_repetition(baseline_records)
    candidate = _metrics_by_repetition(candidate_records)
    if set(baseline) != set(candidate):
        raise BenchmarkFailure(
            f"paired repetitions differ between {baseline_key} and {candidate_key}"
        )
    common_metrics = set.intersection(
        *(set(metrics) for metrics in (*baseline.values(), *candidate.values()))
    )
    if not common_metrics:
        raise BenchmarkFailure(
            f"no comparable numeric metrics for {baseline_key} and {candidate_key}"
        )

    metrics_summary: dict[str, Any] = {}
    for metric in sorted(common_metrics):
        ratios: list[float] = []
        percentages: list[float] = []
        zero_baseline_pairs = 0
        for repetition in sorted(baseline):
            old = baseline[repetition][metric]
            new = candidate[repetition][metric]
            if old == 0.0:
                zero_baseline_pairs += 1
                if new == 0.0:
                    ratios.append(1.0)
                    percentages.append(0.0)
                continue
            ratios.append(new / old)
            percentages.append(100.0 * (new - old) / old)
        metrics_summary[metric] = {
            "pairedSamples": len(baseline),
            "zeroBaselinePairs": zero_baseline_pairs,
            "ratio": describe(ratios),
            "percentChange": describe(percentages),
            "bootstrap95MedianPercentChange": bootstrap_ci(
                percentages,
                iterations=bootstrap_iterations,
                seed=_stable_seed(
                    seed, baseline_key, candidate_key, metric, "relative"
                ),
            ),
        }
    return {
        "baseline": baseline_key,
        "candidate": candidate_key,
        "metrics": metrics_summary,
    }


def _validate_coverage(
    records: Sequence[Mapping[str, Any]],
    schedule: Sequence[RoundSpec],
    profile: str,
) -> None:
    expected = Counter(spec.identity for spec in schedule)
    actual = Counter(_record_identity(record) for record in records)
    if actual != expected:
        missing = list((expected - actual).elements())
        unexpected = list((actual - expected).elements())
        raise BenchmarkFailure(
            "benchmark coverage is incomplete or duplicated: "
            f"missing={missing[:3]!r}, unexpected={unexpected[:3]!r}"
        )
    for record in records:
        if record.get("profile") != profile:
            raise BenchmarkFailure("raw record profile mismatch")
        result = record.get("result")
        if not isinstance(result, Mapping):
            raise BenchmarkFailure("raw record result must be an object")
        spec = RoundSpec(
            scenario=str(record["scenario"]),
            phase=str(record["phase"]),
            repetition=int(record["repetition"]),
            order=int(record["order"]),
            engine=str(record["engine"]),
            backend=str(record["backend"]),
            seed=int(record["seed"]),
        )
        checksum = validate_result(result, spec, profile)
        if checksum != normalize_checksum(record.get("checksum")):
            raise BenchmarkFailure("raw record checksum disagrees with its result")
    validate_checksums(records)


def summarize_results(
    records: Sequence[Mapping[str, Any]],
    *,
    scenarios: Sequence[str],
    backends: Sequence[str],
    repetitions: int,
    profile: str,
    seed: int,
    engines: Sequence[str] = DEFAULT_ENGINES,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
) -> dict[str, Any]:
    selected_scenarios = _validate_selection(scenarios, SCENARIOS, "scenarios")
    selected_backends = _validate_selection(backends, BACKENDS, "backends")
    selected_engines = _validate_selection(engines, ENGINES, "engines")
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    schedule = generate_schedule(
        selected_scenarios, selected_backends, repetitions, seed,
        engines=selected_engines,
    )
    _validate_coverage(records, schedule, profile)

    configurations = build_configurations(selected_backends, selected_engines)
    reference_key = f"takeover/{reference_backend(selected_backends)}"
    pool_reference_key = f"pool/{reference_backend(selected_backends)}"
    scenario_summaries: dict[str, Any] = {}
    for scenario in selected_scenarios:
        measured = [
            record
            for record in records
            if record["scenario"] == scenario and record["phase"] == "measured"
        ]
        by_configuration = {
            configuration.key: [
                record
                for record in measured
                if _configuration_key(record) == configuration.key
            ]
            for configuration in configurations
        }

        configuration_summaries: dict[str, Any] = {}
        for configuration in configurations:
            config_records = by_configuration[configuration.key]
            metrics_by_repetition = _metrics_by_repetition(config_records)
            if sorted(metrics_by_repetition) != list(range(1, repetitions + 1)):
                raise BenchmarkFailure(
                    f"measured repetitions are incomplete for {scenario}/"
                    f"{configuration.key}"
                )
            metric_names = sorted(next(iter(metrics_by_repetition.values())))
            metric_summaries = {
                metric: _metric_summary(
                    [
                        metrics_by_repetition[repetition][metric]
                        for repetition in sorted(metrics_by_repetition)
                    ],
                    bootstrap_iterations=bootstrap_iterations,
                    seed=_stable_seed(seed, scenario, configuration.key, metric),
                )
                for metric in metric_names
            }
            configuration_summaries[configuration.key] = {
                "engine": configuration.engine,
                "backendArgument": configuration.backend,
                "samples": repetitions,
                "checksum": normalize_checksum(config_records[0]["checksum"]),
                "metrics": metric_summaries,
            }

        relative_to_winheap = {}
        if "winheap" in by_configuration:
            relative_to_winheap = {
                configuration.key: _comparison_summary(
                    by_configuration["winheap"],
                    by_configuration[configuration.key],
                    baseline_key="winheap",
                    candidate_key=configuration.key,
                    bootstrap_iterations=bootstrap_iterations,
                    seed=_stable_seed(seed, scenario, "winheap"),
                )
                for configuration in configurations
                if configuration.key != "winheap"
            }
        relative_to_backend = {}
        if reference_key in by_configuration:
            relative_to_backend = {
                configuration.key: _comparison_summary(
                    by_configuration[reference_key],
                    by_configuration[configuration.key],
                    baseline_key=reference_key,
                    candidate_key=configuration.key,
                    bootstrap_iterations=bootstrap_iterations,
                    seed=_stable_seed(seed, scenario, reference_key),
                )
                for configuration in configurations
                if configuration.engine == "takeover"
            }
        relative_to_pool_backend = {}
        if pool_reference_key in by_configuration:
            relative_to_pool_backend = {
                configuration.key: _comparison_summary(
                    by_configuration[pool_reference_key],
                    by_configuration[configuration.key],
                    baseline_key=pool_reference_key,
                    candidate_key=configuration.key,
                    bootstrap_iterations=bootstrap_iterations,
                    seed=_stable_seed(seed, scenario, pool_reference_key),
                )
                for configuration in configurations
                if configuration.engine == "pool"
            }
        scenario_summaries[scenario] = {
            "configurations": configuration_summaries,
            "relativeToWinheap": relative_to_winheap,
            "relativeToBackend": {
                "reference": reference_key,
                "comparisons": relative_to_backend,
            },
            "relativeToPoolBackend": {
                "reference": pool_reference_key,
                "comparisons": relative_to_pool_backend,
            },
        }

    return {
        "schema": SUMMARY_SCHEMA,
        "valid": True,
        "profile": profile,
        "seed": seed,
        "warmupRepetitions": 1,
        "measuredRepetitions": repetitions,
        "backends": list(selected_backends),
        "engines": list(selected_engines),
        "referenceBackend": reference_backend(selected_backends),
        "runCount": len(records),
        "measuredRunCount": sum(
            1 for record in records if record["phase"] == "measured"
        ),
        "bootstrap": {
            "method": "seeded percentile bootstrap",
            "confidence": 0.95,
            "iterations": bootstrap_iterations,
        },
        "rawJsonl": "raw.jsonl",
        "scenarios": scenario_summaries,
    }


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def _validate_runner_config(config: RunnerConfig) -> None:
    _validate_selection(config.scenarios, SCENARIOS, "scenarios")
    _validate_selection(config.backends, BACKENDS, "backends")
    _validate_selection(config.engines, ENGINES, "engines")
    if any(scenario in TAKEOVER_SCENARIOS for scenario in config.scenarios) and (
        tuple(config.engines) != ("takeover",)
    ):
        raise BenchmarkFailure(
            "trim/enumeration/destroy scenarios require engines=takeover"
        )
    if config.profile not in PROFILES:
        raise BenchmarkFailure(f"unknown profile: {config.profile}")
    if config.repetitions <= 0:
        raise BenchmarkFailure("repetitions must be positive")
    if not 0 <= config.seed <= 0xFFFFFFFFFFFFFFFF:
        raise BenchmarkFailure("seed must be an unsigned 64-bit integer")
    if config.executable.suffix.casefold() != ".exe":
        raise BenchmarkFailure("benchmark executable must have an .exe suffix")
    if not config.executable.is_file():
        raise BenchmarkFailure(f"benchmark executable not found: {config.executable}")


def run_benchmark(
    config: RunnerConfig, *, process_runner: ProcessRunner | None = None
) -> dict[str, Any]:
    """Run every process, retain raw JSONL, and publish only a valid summary."""
    _validate_runner_config(config)
    schedule = generate_schedule(
        config.scenarios, config.backends, config.repetitions, config.seed,
        engines=config.engines,
    )
    config.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = config.output_dir / "raw.jsonl"
    summary_path = config.output_dir / "summary.json"
    failure_path = config.output_dir / "failure.json"
    summary_path.unlink(missing_ok=True)
    failure_path.unlink(missing_ok=True)

    records: list[dict[str, Any]] = []
    try:
        with raw_path.open("w", encoding="utf-8", newline="\n") as stream:
            for spec in schedule:
                result = execute_round(
                    config.executable,
                    spec,
                    config.profile,
                    process_runner=process_runner,
                )
                record = make_record(spec, config.profile, result)
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
                records.append(record)
                # Check after persistence so a mismatching result remains available.
                validate_checksums(records)

        summary = summarize_results(
            records,
            scenarios=config.scenarios,
            backends=config.backends,
            repetitions=config.repetitions,
            profile=config.profile,
            seed=config.seed,
            engines=config.engines,
        )
        _write_json_atomic(summary_path, summary)
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
            _write_json_atomic(failure_path, failure)
        except OSError:
            pass
        if isinstance(exc, BenchmarkFailure):
            raise
        raise BenchmarkFailure(f"benchmark runner failed: {exc}") from exc


def _uint64(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 0 <= parsed <= 0xFFFFFFFFFFFFFFFF:
        raise argparse.ArgumentTypeError("must be an unsigned 64-bit integer")
    return parsed


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _split_cli_selection(
    values: Sequence[str], allowed: Sequence[str], label: str
) -> tuple[str, ...]:
    flattened = tuple(
        item.strip()
        for value in values
        for item in value.split(",")
        if item.strip()
    )
    try:
        return _validate_selection(flattened, allowed, label)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run StormBreaker allocator logic benchmarks in fresh processes."
    )
    parser.add_argument("--executable", type=Path, default=DEFAULT_EXECUTABLE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(DEFAULT_SCENARIOS),
        metavar="SCENARIO",
        help="space- or comma-separated scenario names",
    )
    parser.add_argument(
        "--engines",
        nargs="+",
        default=list(DEFAULT_ENGINES),
        metavar="ENGINE",
        help="space- or comma-separated benchmark engines",
    )
    parser.add_argument(
        "--backends",
        nargs="+",
        default=list(DEFAULT_BACKENDS),
        metavar="BACKEND",
        help="space- or comma-separated takeover backends",
    )
    parser.add_argument(
        "--repetitions", type=_positive_integer, default=DEFAULT_REPETITIONS
    )
    parser.add_argument("--seed", type=_uint64, default=DEFAULT_SEED)
    return parser


def parse_args(argv: Sequence[str] | None = None) -> RunnerConfig:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        scenarios = _split_cli_selection(args.scenarios, SCENARIOS, "scenarios")
        engines = _split_cli_selection(args.engines, ENGINES, "engines")
        backends = _split_cli_selection(args.backends, BACKENDS, "backends")
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    return RunnerConfig(
        executable=args.executable.resolve(),
        output_dir=args.output_dir.resolve(),
        profile=args.profile,
        scenarios=scenarios,
        engines=engines,
        backends=backends,
        repetitions=args.repetitions,
        seed=args.seed,
    )


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_args(argv)
    try:
        run_benchmark(config)
    except BenchmarkFailure as exc:
        print(f"benchmark failed closed: {exc}", file=sys.stderr)
        return 1
    print(f"raw JSONL: {config.output_dir / 'raw.jsonl'}")
    print(f"summary JSON: {config.output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
