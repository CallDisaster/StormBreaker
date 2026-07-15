#!/usr/bin/env python3
"""Blocked, fail-closed StormBreaker allocator benchmark for Warcraft III.

The importable parts of this module are deliberately standard-library only so
that the unit tests never import AutoTest or start Warcraft III. Windows and
image dependencies are loaded only by ``run_benchmark``.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import math
import ntpath
import os
import random
import shutil
import statistics
import struct
import sys
import tempfile
import time
import traceback
import uuid
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DXVK_ROOT = REPO_ROOT.parents[1]
DEFAULT_AUTOTEST_DIR = DXVK_ROOT / "AutoTest"
DEFAULT_WAR3_ROOT = Path(r"E:\Work\War3_AutoTestSandbox")
DEFAULT_MAP = DEFAULT_WAR3_ROOT / "(4)\u751f\u4e0e\u6b7bv1.28\u8bfb\u6863bug\u4fee\u590d.w3x"
DEFAULT_ASI = REPO_ROOT / "StormMemPoolFix" / "Build" / "StormBreaker.asi"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "stormbreaker_benchmark_results"

VARIANT_CONFIGS: dict[str, dict[str, str | bool | None]] = {
    "off": {
        "asiEnabled": False,
        "backend": None,
        "takeoverMode": None,
    },
    "large-tlsf": {
        "asiEnabled": True,
        "backend": "tlsf",
        "takeoverMode": "large",
    },
    "full-tlsf": {
        "asiEnabled": True,
        "backend": "tlsf",
        "takeoverMode": "full",
    },
    "full-mimalloc": {
        "asiEnabled": True,
        "backend": "mimalloc",
        "takeoverMode": "full",
    },
    "full-hybrid": {
        "asiEnabled": True,
        "backend": "hybrid",
        "takeoverMode": "full",
    },
}
VARIANTS = tuple(VARIANT_CONFIGS)
FAST_SAMPLE_INTERVAL_SEC = 0.2
SLOW_SAMPLE_INTERVAL_SEC = 1.0
SCREENSHOT_INTERVAL_SEC = 0.75
DEFAULT_READY_TIMEOUT_SEC = 300.0
DEFAULT_MEASURE_SEC = 30.0
DEFAULT_MEASURED_CYCLES = 10
DEFAULT_SEED = 20260712
DEFAULT_BOOTSTRAP_ITERATIONS = 10_000
DEFAULT_MEMORY_GATE_PCT = 3.0
DEFAULT_SPEED_GATE_PCT = 5.0
DEFAULT_HOOK_P99_GATE_PCT = 10.0
DEFAULT_VIRTUAL_SLOPE_IMPROVEMENT_PCT = 20.0
DEFAULT_FREE_REGION_IMPROVEMENT_PCT = 10.0
DEFAULT_STALL_IMPROVEMENT_PCT = 20.0
STORM_TOTAL_ALLOC_OFFSET = 0x5738C
STORM_MEMORY_INIT_OFFSET = 0x56F7C
STORM_DLL_SHA256 = "f8f519cfaa6275a5172a014f0abed2212284390a33f1194677155a7d408e63eb"
GAME_DLL_SHA256 = "e04d1716603c075eb0c8e1e21cf1093a664adc5249efab396bfa08d7b09d0c3a"
UINT32_MODULUS = 1 << 32
X86_ADDRESS_SPACE_LIMIT = 1 << 32
MEM_FREE = 0x10000
ALLOCATOR_STALL_THRESHOLD_NS = 10_000_000
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
PE32_MAGIC = 0x010B

PERF_ENV_VARS = (
    "DXVK_WAR3_PERF_RECORD_ON_START",
    "DXVK_WAR3_PERF_AUTO_EXPORT_SEC",
    "DXVK_WAR3_PERF_RECORD_AFTER_GAME_START",
)
BENCHMARK_SANITIZED_ENV_VARS = PERF_ENV_VARS + (
    "STORMBREAKER_MEMORY_BACKEND",
    "STORMBREAKER_TAKEOVER_MODE",
    "STORMBREAKER_ARTIFACT_DIR",
)

REPORT_MEMORY_METRICS = (
    "measurementPeakWorkingSetMB",
    "measurementPeakCommitMB",
    "measurementPeakPrivateMB",
    "measurementPeakVirtualMB",
    "measurementEndLargestFreeRegionMB",
    "measurementEndFreeRegionCount",
    "measurementVirtualGrowthSlopeMBPerSec",
)
PROMOTION_MEMORY_METRICS = (
    "measurementPeakPrivateMB",
    "measurementPeakCommitMB",
    "measurementPeakVirtualMB",
)
AGGREGATE_METRICS = (
    "readyElapsedSec",
    *REPORT_MEMORY_METRICS,
    "measurementPeakHandleCount",
    "measurementPeakStormAllocatedMB",
    "allocatorP99Nanoseconds",
    "allocateP99Nanoseconds",
    "allocatorStallOver10msCount",
)


class BenchmarkError(RuntimeError):
    """A benchmark precondition or hard validation failed."""


class RestoreError(BenchmarkError):
    """The exact pre-round ASI state could not be restored."""


@dataclass(frozen=True)
class RoundSpec:
    phase: str
    block: int
    order: int
    variant: str

    @property
    def key(self) -> str:
        return f"{self.phase}_b{self.block:02d}_o{self.order}_{self.variant}"

    @property
    def cycle(self) -> int:
        return self.block + 1


@dataclass(frozen=True)
class BenchmarkConfig:
    war3_root: Path
    map_path: Path
    asi_path: Path
    autotest_dir: Path
    output_dir: Path
    warmup_blocks: int = 1
    measured_blocks: int = DEFAULT_MEASURED_CYCLES
    seed: int = DEFAULT_SEED
    ready_timeout_sec: float = DEFAULT_READY_TIMEOUT_SEC
    measure_sec: float = DEFAULT_MEASURE_SEC
    memory_gate_pct: float = DEFAULT_MEMORY_GATE_PCT
    speed_gate_pct: float = DEFAULT_SPEED_GATE_PCT
    hook_p99_gate_pct: float = DEFAULT_HOOK_P99_GATE_PCT
    virtual_slope_improvement_pct: float = DEFAULT_VIRTUAL_SLOPE_IMPROVEMENT_PCT
    free_region_improvement_pct: float = DEFAULT_FREE_REGION_IMPROVEMENT_PCT
    stall_improvement_pct: float = DEFAULT_STALL_IMPROVEMENT_PCT
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS
    storm_total_alloc_offset: int = STORM_TOTAL_ALLOC_OFFSET
    storm_memory_init_offset: int = STORM_MEMORY_INIT_OFFSET


@dataclass(frozen=True)
class AutoTestApi:
    launch_instance: Callable[..., Mapping[str, Any]]
    stop: Callable[..., Mapping[str, Any]]
    preflight_instances: Callable[..., Mapping[str, Any]]
    cleanup_sessions: Callable[..., Mapping[str, Any]]
    build_instance_layout: Callable[..., Any]
    materialize_instance_root: Callable[..., Mapping[str, Any]]


def utcish_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def run_id_now() -> str:
    return datetime.now().strftime("sb_%Y%m%d_%H%M%S")


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_pe_identity(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise BenchmarkError(f"not a DOS/PE image: {path}")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        stream.seek(pe_offset)
        header = stream.read(26)
    if len(header) != 26 or header[:4] != b"PE\0\0":
        raise BenchmarkError(f"invalid PE signature: {path}")
    machine = struct.unpack_from("<H", header, 4)[0]
    characteristics = struct.unpack_from("<H", header, 22)[0]
    optional_magic = struct.unpack_from("<H", header, 24)[0]
    return {
        "machine": machine,
        "optionalHeaderMagic": optional_magic,
        "characteristics": characteristics,
        "isWin32X86": machine == IMAGE_FILE_MACHINE_I386 and optional_magic == PE32_MAGIC,
        "largeAddressAware": bool(characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True))
            stream.write("\n")


def generate_schedule(
    warmup_blocks: int = 1,
    measured_blocks: int = 10,
    seed: int = DEFAULT_SEED,
    variants: Sequence[str] = VARIANTS,
) -> list[RoundSpec]:
    """Generate deterministic, cyclically balanced complete blocks."""
    if warmup_blocks < 0 or measured_blocks <= 0:
        raise ValueError("warmup_blocks must be >= 0 and measured_blocks must be > 0")
    if len(variants) < 2 or len(set(variants)) != len(variants):
        raise ValueError("variants must contain at least two unique values")

    rng = random.Random(seed)
    base = list(variants)
    rng.shuffle(base)
    initial_rotation = rng.randrange(len(base))
    schedule: list[RoundSpec] = []
    global_block = 0
    for phase, block_count in (("warmup", warmup_blocks), ("measured", measured_blocks)):
        for phase_block in range(block_count):
            rotation = (initial_rotation + global_block) % len(base)
            ordered = base[rotation:] + base[:rotation]
            schedule.extend(
                RoundSpec(phase=phase, block=phase_block, order=order, variant=variant)
                for order, variant in enumerate(ordered)
            )
            global_block += 1
    return schedule


def variant_config(variant: str) -> Mapping[str, str | bool | None]:
    try:
        return VARIANT_CONFIGS[variant]
    except KeyError as exc:
        raise ValueError(f"unknown variant: {variant}") from exc


def build_scenario_manifest(
    schedule: Sequence[RoundSpec], measured_cycles: int
) -> dict[str, Any]:
    """Describe the lifecycle represented by the complete-block schedule."""
    measured = [spec for spec in schedule if spec.phase == "measured"]
    cycles_by_variant = {
        variant: [
            {
                "cycle": spec.cycle,
                "block": spec.block,
                "order": spec.order,
                "roundKey": spec.key,
            }
            for spec in measured
            if spec.variant == variant
        ]
        for variant in VARIANTS
    }
    complete = all(
        [row["cycle"] for row in rows] == list(range(1, measured_cycles + 1))
        for rows in cycles_by_variant.values()
    )
    return {
        "name": "isolated-map-load-ready-measure-exit",
        "cycleModel": "fresh-isolated-process-per-cycle",
        "measuredCyclesPerVariant": measured_cycles,
        "warmupCyclesPerVariant": 1,
        "variantCount": len(VARIANTS),
        "totalMeasuredRounds": measured_cycles * len(VARIANTS),
        "allocatorStallThresholdNanoseconds": ALLOCATOR_STALL_THRESHOLD_NS,
        "complete": complete,
        "cyclesByVariant": cycles_by_variant,
        "note": (
            "Cycles measure repeated launch/load/exit behavior; they do not claim "
            "to model repeated map reloads inside one long-lived process."
        ),
    }


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


def describe(values: Sequence[float]) -> dict[str, Any]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    if not finite:
        return {"n": 0, "median": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(finite),
        "median": round(statistics.median(finite), 6),
        "p95": round(percentile(finite, 0.95), 6),
        "min": round(min(finite), 6),
        "max": round(max(finite), 6),
    }


def linear_regression_slope(points: Sequence[tuple[float, float]]) -> float | None:
    finite = [
        (float(x), float(y))
        for x, y in points
        if math.isfinite(float(x)) and math.isfinite(float(y))
    ]
    if len(finite) < 2:
        return None
    mean_x = statistics.fmean(x for x, _ in finite)
    mean_y = statistics.fmean(y for _, y in finite)
    denominator = sum((x - mean_x) ** 2 for x, _ in finite)
    if denominator == 0.0:
        return None
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in finite)
    return round(numerator / denominator, 9)


def metric_series_slope(
    rows: Sequence[Mapping[str, Any]], x_key: str, y_key: str
) -> float | None:
    points: list[tuple[float, float]] = []
    for row in rows:
        try:
            x = float(row[x_key])
            y = float(row[y_key])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(x) and math.isfinite(y):
            points.append((x, y))
    return linear_regression_slope(points)


def bootstrap_ci(
    values: Sequence[float],
    *,
    confidence: float = 0.95,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = DEFAULT_SEED,
    statistic: Callable[[Sequence[float]], float] = statistics.median,
) -> dict[str, Any]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    if not finite:
        return {"n": 0, "confidence": confidence, "low": None, "high": None}
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if len(finite) == 1 or all(value == finite[0] for value in finite):
        point = round(float(statistic(finite)), 6)
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
        "low": round(percentile(estimates, alpha), 6),
        "high": round(percentile(estimates, 1.0 - alpha), 6),
    }


class UInt32WrapExtender:
    """Extend a monotonically increasing uint32 counter across wraparound."""

    def __init__(self) -> None:
        self._last: int | None = None
        self._wraps = 0

    def update(self, raw: int | None) -> int | None:
        if raw is None:
            return None
        value = int(raw)
        if not 0 <= value < UINT32_MODULUS:
            raise ValueError("counter value is not uint32")
        if self._last is not None and value < self._last:
            # A small decrease can be a reset or a non-monotonic source. Only a
            # high-to-low transition is treated as a true uint32 wrap.
            if self._last - value > UINT32_MODULUS // 2:
                self._wraps += 1
        self._last = value
        return self._wraps * UINT32_MODULUS + value


def _metric_value(round_row: Mapping[str, Any], metric: str) -> float | None:
    value = (round_row.get("metrics") or {}).get(metric)
    if value is None:
        return None
    try:
        converted = float(value)
    except (TypeError, ValueError):
        return None
    return converted if math.isfinite(converted) else None


def _stable_seed(base: int, label: str) -> int:
    digest = hashlib.sha256(f"{base}:{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def paired_delta_summary(
    rounds: Sequence[Mapping[str, Any]],
    baseline: str,
    candidate: str,
    metric: str,
    *,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    by_block: dict[int, dict[str, Mapping[str, Any]]] = {}
    for row in rounds:
        if row.get("phase") != "measured" or not row.get("ok"):
            continue
        variant = str(row.get("variant", ""))
        if variant not in (baseline, candidate):
            continue
        by_block.setdefault(int(row.get("block", -1)), {})[variant] = row

    pairs: list[dict[str, Any]] = []
    absolute: list[float] = []
    percentages: list[float] = []
    zero_baseline_regressions = 0
    for block in sorted(by_block):
        block_rows = by_block[block]
        if baseline not in block_rows or candidate not in block_rows:
            continue
        old = _metric_value(block_rows[baseline], metric)
        new = _metric_value(block_rows[candidate], metric)
        if old is None or new is None:
            continue
        delta = new - old
        delta_pct: float | None
        if old == 0.0:
            delta_pct = 0.0 if new == 0.0 else None
            if new > 0.0:
                zero_baseline_regressions += 1
        else:
            delta_pct = 100.0 * delta / old
        absolute.append(delta)
        if delta_pct is not None:
            percentages.append(delta_pct)
        pairs.append(
            {
                "block": block,
                "baseline": round(old, 6),
                "candidate": round(new, 6),
                "delta": round(delta, 6),
                "deltaPct": round(delta_pct, 6) if delta_pct is not None else None,
            }
        )

    return {
        "metric": metric,
        "baseline": baseline,
        "candidate": candidate,
        "pairs": pairs,
        "percentComparablePairs": len(percentages),
        "zeroBaselineRegressions": zero_baseline_regressions,
        "delta": describe(absolute),
        "deltaPct": describe(percentages),
        "bootstrap95MedianDeltaPct": bootstrap_ci(
            percentages,
            iterations=bootstrap_iterations,
            seed=_stable_seed(seed, f"{baseline}:{candidate}:{metric}"),
        ),
    }


def evaluate_results(
    rounds: Sequence[Mapping[str, Any]],
    *,
    measured_blocks: int,
    memory_gate_pct: float = DEFAULT_MEMORY_GATE_PCT,
    speed_gate_pct: float = DEFAULT_SPEED_GATE_PCT,
    hook_p99_gate_pct: float = DEFAULT_HOOK_P99_GATE_PCT,
    virtual_slope_improvement_pct: float = DEFAULT_VIRTUAL_SLOPE_IMPROVEMENT_PCT,
    free_region_improvement_pct: float = DEFAULT_FREE_REGION_IMPROVEMENT_PCT,
    stall_improvement_pct: float = DEFAULT_STALL_IMPROVEMENT_PCT,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    measured = [row for row in rounds if row.get("phase") == "measured"]
    coverage_rows: list[dict[str, Any]] = []
    coverage_ok = True
    for variant in VARIANTS:
        variant_rows = [row for row in measured if row.get("variant") == variant]
        successful = [row for row in variant_rows if row.get("ok")]
        row_ok = len(variant_rows) == measured_blocks and len(successful) == measured_blocks
        coverage_ok = coverage_ok and row_ok
        coverage_rows.append(
            {
                "variant": variant,
                "expected": measured_blocks,
                "observed": len(variant_rows),
                "successful": len(successful),
                "pass": row_ok,
            }
        )

    aggregates: dict[str, Any] = {}
    for variant in VARIANTS:
        successful = [
            row for row in measured if row.get("variant") == variant and row.get("ok")
        ]
        aggregates[variant] = {
            metric: describe(
                [value for row in successful if (value := _metric_value(row, metric)) is not None]
            )
            for metric in AGGREGATE_METRICS
        }

    comparisons = [
        ("off", candidate) for candidate in VARIANTS if candidate != "off"
    ] + [
        ("large-tlsf", "full-tlsf"),
        ("large-tlsf", "full-mimalloc"),
        ("large-tlsf", "full-hybrid"),
    ]
    pairwise: dict[str, Any] = {}
    for baseline, candidate in comparisons:
        label = f"{candidate}_vs_{baseline}"
        pairwise[label] = {
            metric: paired_delta_summary(
                rounds,
                baseline,
                candidate,
                metric,
                bootstrap_iterations=bootstrap_iterations,
                seed=seed,
            )
            for metric in AGGREGATE_METRICS
        }

    cycle_trends: dict[str, Any] = {}
    for variant in VARIANTS:
        successful = sorted(
            (
                row
                for row in measured
                if row.get("variant") == variant and row.get("ok")
            ),
            key=lambda row: int(row.get("block", -1)),
        )
        trend_rows = [
            {
                "cycle": int(row.get("block", -1)) + 1,
                "peakVirtualMB": _metric_value(row, "measurementPeakVirtualMB"),
                "largestFreeRegionMB": _metric_value(
                    row, "measurementEndLargestFreeRegionMB"
                ),
            }
            for row in successful
        ]
        cycle_trends[variant] = {
            "peakVirtualMBPerCycle": metric_series_slope(
                trend_rows, "cycle", "peakVirtualMB"
            ),
            "largestFreeRegionMBPerCycle": metric_series_slope(
                trend_rows, "cycle", "largestFreeRegionMB"
            ),
        }

    promotion = pairwise["full-hybrid_vs_large-tlsf"]

    def upper_gate(metric: str, limit: float) -> tuple[dict[str, Any], bool]:
        paired = promotion[metric]
        upper = paired["bootstrap95MedianDeltaPct"].get("high")
        passed = (
            len(paired["pairs"]) == measured_blocks
            and paired["percentComparablePairs"] == measured_blocks
            and paired["zeroBaselineRegressions"] == 0
            and upper is not None
            and float(upper) <= limit
        )
        return (
            {
                "baseline": "large-tlsf",
                "candidate": "full-hybrid",
                "metric": metric,
                "pairedCycles": len(paired["pairs"]),
                "decisionUpper95Pct": upper,
                "maxDeltaPct": limit,
                "pass": passed,
            },
            passed,
        )

    def lower_gate(metric: str, minimum: float) -> tuple[dict[str, Any], bool]:
        paired = promotion[metric]
        lower = paired["bootstrap95MedianDeltaPct"].get("low")
        passed = (
            len(paired["pairs"]) == measured_blocks
            and paired["percentComparablePairs"] == measured_blocks
            and paired["zeroBaselineRegressions"] == 0
            and lower is not None
            and float(lower) >= minimum
        )
        return (
            {
                "baseline": "large-tlsf",
                "candidate": "full-hybrid",
                "metric": metric,
                "pairedCycles": len(paired["pairs"]),
                "decisionLower95Pct": lower,
                "minImprovementPct": minimum,
                "pass": passed,
            },
            passed,
        )

    memory_rows: list[dict[str, Any]] = []
    for metric in PROMOTION_MEMORY_METRICS:
        row, _passed = upper_gate(metric, memory_gate_pct)
        row["maxRegressionPct"] = row.pop("maxDeltaPct")
        memory_rows.append(row)

    speed_row, speed_ok = upper_gate("readyElapsedSec", abs(speed_gate_pct))
    speed_row["maxRegressionPct"] = speed_row.pop("maxDeltaPct")
    hook_row, hook_p99_ok = upper_gate(
        "allocatorP99Nanoseconds", abs(hook_p99_gate_pct)
    )
    hook_row["maxRegressionPct"] = hook_row.pop("maxDeltaPct")
    slope_pair = promotion["measurementVirtualGrowthSlopeMBPerSec"]
    all_stable_slopes = (
        len(slope_pair["pairs"]) == measured_blocks
        and all(
            float(pair["baseline"]) <= 0.0 and float(pair["candidate"]) <= 0.0
            for pair in slope_pair["pairs"]
        )
    )
    all_positive_slope_baselines = (
        len(slope_pair["pairs"]) == measured_blocks
        and all(float(pair["baseline"]) > 0.0 for pair in slope_pair["pairs"])
    )
    slope_upper = slope_pair["bootstrap95MedianDeltaPct"].get("high")
    slope_ok = all_stable_slopes or (
        all_positive_slope_baselines
        and slope_pair["percentComparablePairs"] == measured_blocks
        and slope_upper is not None
        and float(slope_upper) <= -abs(virtual_slope_improvement_pct)
    )
    slope_row = {
        "baseline": "large-tlsf",
        "candidate": "full-hybrid",
        "metric": "measurementVirtualGrowthSlopeMBPerSec",
        "pairedCycles": len(slope_pair["pairs"]),
        "decisionUpper95Pct": slope_upper,
        "requiredImprovementPct": abs(virtual_slope_improvement_pct),
        "alreadyStable": all_stable_slopes,
        "pass": slope_ok,
    }
    free_row, free_ok = lower_gate(
        "measurementEndLargestFreeRegionMB", abs(free_region_improvement_pct)
    )

    stall_pair = promotion["allocatorStallOver10msCount"]
    all_zero_stalls = (
        len(stall_pair["pairs"]) == measured_blocks
        and all(
            float(pair["baseline"]) == 0.0 and float(pair["candidate"]) == 0.0
            for pair in stall_pair["pairs"]
        )
    )
    stall_upper = stall_pair["bootstrap95MedianDeltaPct"].get("high")
    stall_ok = all_zero_stalls or (
        len(stall_pair["pairs"]) == measured_blocks
        and stall_pair["percentComparablePairs"] == measured_blocks
        and stall_pair["zeroBaselineRegressions"] == 0
        and stall_upper is not None
        and float(stall_upper) <= -abs(stall_improvement_pct)
    )
    stall_row = {
        "baseline": "large-tlsf",
        "candidate": "full-hybrid",
        "metric": "allocatorStallOver10msCount",
        "pairedCycles": len(stall_pair["pairs"]),
        "decisionUpper95Pct": stall_upper,
        "requiredImprovementPct": abs(stall_improvement_pct),
        "alreadyZero": all_zero_stalls,
        "pass": stall_ok,
    }

    memory_ok = bool(memory_rows) and all(row["pass"] for row in memory_rows)
    address_space_ok = slope_ok and free_ok
    promotion_ok = (
        coverage_ok
        and memory_ok
        and speed_ok
        and hook_p99_ok
        and address_space_ok
        and stall_ok
    )
    overall = coverage_ok
    return {
        "ok": overall,
        "recommendedVariant": "full-hybrid" if promotion_ok else "large-tlsf",
        "recommendedBackend": "hybrid" if promotion_ok else "tlsf",
        "fullHybridPromoted": promotion_ok,
        "method": {
            "aggregation": "median and linear-interpolated p95",
            "pairing": "within measured block",
            "confidenceInterval": "seeded percentile bootstrap of paired median percent delta",
            "gateDecision": (
                "upper 95% endpoint for regression/lower-is-better gates; "
                "lower 95% endpoint for largest-free-region improvement"
            ),
        },
        "aggregates": aggregates,
        "cycleTrends": cycle_trends,
        "paired": pairwise,
        "gates": {
            "coverage": {"pass": coverage_ok, "rows": coverage_rows},
            "memory": {"pass": memory_ok, "rows": memory_rows},
            "hookP99": {"pass": hook_p99_ok, "rows": [hook_row]},
            "loadTime": {"pass": speed_ok, "rows": [speed_row]},
            "longTermAddressSpace": {
                "pass": address_space_ok,
                "rows": [slope_row, free_row],
            },
            "allocatorStalls": {"pass": stall_ok, "rows": [stall_row]},
            "fullHybridPromotion": {"pass": promotion_ok},
            "benchmarkValid": overall,
        },
    }


def canonical_windows_path(value: str | os.PathLike[str]) -> str:
    expanded = os.path.expandvars(os.fspath(value)).replace("/", "\\")
    return ntpath.normpath(expanded).casefold()


def path_is_within_windows(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    candidate = canonical_windows_path(path)
    boundary = canonical_windows_path(root)
    try:
        return ntpath.commonpath([candidate, boundary]) == boundary
    except ValueError:
        return False


def _important_modules(modules: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {"d3d9": [], "stormBreaker": [], "stormDll": [], "gameDll": []}
    for module in modules:
        row = dict(module)
        module_path = str(module.get("path") or module.get("name") or "")
        basename = ntpath.basename(module_path).casefold()
        if basename == "d3d9.dll":
            groups["d3d9"].append(row)
        elif basename == "stormbreaker.asi":
            groups["stormBreaker"].append(row)
        elif basename == "storm.dll":
            groups["stormDll"].append(row)
        elif basename == "game.dll":
            groups["gameDll"].append(row)
    return groups


def validate_modules(
    modules: Sequence[Mapping[str, Any]],
    *,
    variant: str,
    runtime_root: Path,
    deployed_asi_sha256: str | None,
    expected_d3d9_path: Path | None = None,
    expected_storm_sha256: str = STORM_DLL_SHA256,
    expected_game_sha256: str = GAME_DLL_SHA256,
) -> dict[str, Any]:
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant: {variant}")
    expected_d3d9 = expected_d3d9_path or Path(
        os.environ.get("WINDIR", r"C:\Windows")
    ) / "SysWOW64" / "d3d9.dll"
    expected_asi = runtime_root / "StormBreaker.asi"
    groups = _important_modules(modules)
    errors: list[str] = []

    if any("error" in module for module in modules):
        errors.append("module enumeration returned an error row")

    d3d9_paths = [str(row.get("path") or row.get("name") or "") for row in groups["d3d9"]]
    if len(d3d9_paths) != 1:
        errors.append(f"expected exactly one d3d9.dll module, found {len(d3d9_paths)}")
    elif canonical_windows_path(d3d9_paths[0]) != canonical_windows_path(expected_d3d9):
        errors.append(f"d3d9.dll is not the SysWOW64 system module: {d3d9_paths[0]}")

    storm_rows = groups["stormDll"]
    if len(storm_rows) != 1:
        errors.append(f"expected exactly one Storm.dll module, found {len(storm_rows)}")
    else:
        storm_path = Path(
            str(storm_rows[0].get("path") or storm_rows[0].get("name") or "")
        )
        if not path_is_within_windows(storm_path, runtime_root):
            errors.append(f"Storm.dll was not loaded from the instance root: {storm_path}")
        elif not storm_path.is_file():
            errors.append(f"loaded Storm.dll path is not a file: {storm_path}")
        else:
            storm_sha = file_sha256(storm_path)
            if storm_sha.casefold() != expected_storm_sha256.casefold():
                errors.append(
                    f"loaded Storm.dll SHA-256 mismatch: {storm_sha} != {expected_storm_sha256}"
                )

    game_rows = groups["gameDll"]
    if len(game_rows) != 1:
        errors.append(f"expected exactly one Game.dll module, found {len(game_rows)}")
    else:
        game_path = Path(
            str(game_rows[0].get("path") or game_rows[0].get("name") or "")
        )
        if not path_is_within_windows(game_path, runtime_root):
            errors.append(f"Game.dll was not loaded from the instance root: {game_path}")
        elif not game_path.is_file():
            errors.append(f"loaded Game.dll path is not a file: {game_path}")
        else:
            game_sha = file_sha256(game_path)
            if game_sha.casefold() != expected_game_sha256.casefold():
                errors.append(
                    f"loaded Game.dll SHA-256 mismatch: {game_sha} != {expected_game_sha256}"
                )

    asi_rows = groups["stormBreaker"]
    if variant == "off":
        if asi_rows:
            errors.append("off variant loaded StormBreaker.asi")
    else:
        if len(asi_rows) != 1:
            errors.append(f"expected exactly one StormBreaker.asi module, found {len(asi_rows)}")
        else:
            loaded_path = Path(str(asi_rows[0].get("path") or asi_rows[0].get("name") or ""))
            if canonical_windows_path(loaded_path) != canonical_windows_path(expected_asi):
                errors.append(f"StormBreaker.asi was not loaded from the instance root: {loaded_path}")
            elif not loaded_path.is_file():
                errors.append(f"loaded StormBreaker.asi path is not a file: {loaded_path}")
            elif not deployed_asi_sha256:
                errors.append("expected ASI SHA-256 was not supplied")
            else:
                actual_sha = file_sha256(loaded_path)
                if actual_sha.casefold() != deployed_asi_sha256.casefold():
                    errors.append(
                        f"loaded StormBreaker.asi SHA-256 mismatch: {actual_sha} != {deployed_asi_sha256}"
                    )

    return {
        "ok": not errors,
        "variant": variant,
        "expectedD3d9": str(expected_d3d9),
        "expectedAsi": str(expected_asi),
        "expectedStormSha256": expected_storm_sha256,
        "expectedGameSha256": expected_game_sha256,
        "errors": errors,
        "important": groups,
        "moduleCount": len(modules),
    }


def _recursive_values(value: Any, key: str) -> Iterator[Any]:
    if isinstance(value, Mapping):
        for current_key, current_value in value.items():
            if str(current_key) == key:
                yield current_value
            yield from _recursive_values(current_value, key)
    elif isinstance(value, list):
        for item in value:
            yield from _recursive_values(item, key)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BenchmarkError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise BenchmarkError(f"JSONL row is not an object at {path}:{line_number}")
            rows.append(row)
    return rows


def _backend_identity_values(row: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("backendName", "memoryBackend"):
        values.extend(
            str(value).strip().casefold()
            for value in _recursive_values(row, key)
            if isinstance(value, str)
        )
    backend = row.get("backend")
    if isinstance(backend, str):
        values.append(backend.strip().casefold())
    elif isinstance(backend, Mapping):
        for key in ("name", "kind", "selected"):
            value = backend.get(key)
            if isinstance(value, str):
                values.append(value.strip().casefold())
    return [value for value in values if value]


def _takeover_identity_values(row: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("takeoverMode", "memoryTakeoverMode"):
        values.extend(
            str(value).strip().casefold()
            for value in _recursive_values(row, key)
            if isinstance(value, str)
        )
    takeover = row.get("takeover")
    if isinstance(takeover, Mapping):
        mode = takeover.get("mode")
        if isinstance(mode, str):
            values.append(mode.strip().casefold())
    return [value for value in values if value]


def _numeric_values(value: Any, keys: Sequence[str]) -> list[float]:
    numbers: list[float] = []
    for key in keys:
        for candidate in _recursive_values(value, key):
            if isinstance(candidate, bool):
                continue
            try:
                converted = float(candidate)
            except (TypeError, ValueError):
                continue
            if math.isfinite(converted):
                numbers.append(converted)
    return numbers


def _counter_max(rows: Sequence[Mapping[str, Any]], keys: Sequence[str]) -> float | None:
    values = _numeric_values(rows, keys)
    return max(values) if values else None


def validate_metrics_rows(rows: Sequence[Mapping[str, Any]], variant: str) -> dict[str, Any]:
    expected = variant_config(variant)
    errors: list[str] = []
    if variant == "off":
        if rows:
            errors.append("off variant unexpectedly emitted StormBreaker metrics")
        return {"ok": not errors, "variant": variant, "rowCount": len(rows), "errors": errors}

    expected_backend = str(expected["backend"])
    expected_takeover = str(expected["takeoverMode"])
    backend_values: list[str] = []
    takeover_values: list[str] = []
    installed_match = False
    status_rows = 0
    for row in rows:
        hooks_values = list(_recursive_values(row, "hooksInstalled"))
        backends = _backend_identity_values(row)
        takeovers = _takeover_identity_values(row)
        if hooks_values or backends or takeovers:
            status_rows += 1
        backend_values.extend(value for value in backends if value)
        takeover_values.extend(value for value in takeovers if value)
        if (
            True in hooks_values
            and expected_backend in backends
            and expected_takeover in takeovers
        ):
            installed_match = True

    distinct_backends = sorted(set(backend_values))
    distinct_takeovers = sorted(set(takeover_values))
    if not rows:
        errors.append("metrics JSONL is missing or empty")
    if status_rows == 0:
        errors.append("metrics JSONL has no hook/backend/takeover status row")
    if distinct_backends != [expected_backend]:
        errors.append(
            f"metrics backend mismatch: expected {expected_backend}, observed {distinct_backends}"
        )
    if distinct_takeovers != [expected_takeover]:
        errors.append(
            "metrics takeover mismatch: "
            f"expected {expected_takeover}, observed {distinct_takeovers}"
        )
    if not installed_match:
        errors.append(
            "metrics never reported one coherent installed status row with "
            f"backend={expected_backend}, takeover={expected_takeover}"
        )

    required_counters = {
        "allocator stall >10ms": (
            "allocatorStallOver10msCount",
            "over10msCount",
        ),
        "backend fallback": ("fallbackAllocations",),
        "managed fallback": ("managedFallbackCalls",),
        "native fallback": ("nativeFallbackCalls",),
        "degraded calls": ("degradedCalls",),
        "registry insert failures": ("registryInsertFailures",),
        "pool failures": ("failureCount",),
        "hook/backend failures": ("failures",),
        "profiler dropped": ("dropped",),
        "profiler write errors": ("writeErrors",),
    }
    observed_counters: dict[str, float | None] = {}
    for label, keys in required_counters.items():
        value = _counter_max(rows, keys)
        observed_counters[label] = value
        if value is None:
            errors.append(f"metrics missing required counter: {label}")
        elif value < 0.0:
            errors.append(f"metrics counter is negative: {label}={value}")

    dirty_counters = {
        label: value
        for label, value in observed_counters.items()
        if label != "allocator stall >10ms" and value is not None and value != 0.0
    }
    if dirty_counters:
        errors.append(f"metrics reported fallback/degraded/failure health: {dirty_counters}")
    incomplete_values = list(_recursive_values(rows, "incomplete"))
    if not incomplete_values:
        errors.append("metrics missing profiler incomplete state")
    if any(value is True for value in incomplete_values):
        errors.append("profiler marked telemetry incomplete")
    return {
        "ok": not errors,
        "variant": variant,
        "rowCount": len(rows),
        "statusRowCount": status_rows,
        "backends": distinct_backends,
        "takeoverModes": distinct_takeovers,
        "installedMatch": installed_match,
        "counters": observed_counters,
        "errors": errors,
    }


def summarize_metrics_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, float | None]:
    summary: dict[str, float | None] = {
        "allocatorP99Nanoseconds": None,
        "allocateP99Nanoseconds": None,
        "allocatorStallOver10msCount": _counter_max(
            rows, ("allocatorStallOver10msCount", "over10msCount")
        ),
    }
    for row in reversed(rows):
        latency = row.get("latency")
        if not isinstance(latency, Mapping):
            continue

        def finite_value(key: str) -> float | None:
            try:
                value = float(latency.get(key))
            except (TypeError, ValueError):
                return None
            return value if math.isfinite(value) and value > 0 else None

        summary.update(
            {
                "allocatorP99Nanoseconds": finite_value("p99Nanoseconds"),
                "allocateP99Nanoseconds": finite_value("allocateP99Nanoseconds"),
            }
        )
        break
    return summary


class AsiRoundFiles:
    """Per-round transaction for both ASI loader locations."""

    def __init__(self, war3_root: Path, source_asi: Path, variant: str, backup_parent: Path):
        if variant not in VARIANTS:
            raise ValueError(f"unknown variant: {variant}")
        self.war3_root = Path(war3_root)
        self.source_asi = Path(source_asi)
        self.variant = variant
        self.backup_parent = Path(backup_parent)
        self.targets = (
            self.war3_root / "StormBreaker.asi",
            self.war3_root / "StormBreaker" / "StormBreaker.asi",
        )
        self.backup_dir: Path | None = None
        self.originals: dict[Path, dict[str, Any]] = {}
        self.deployed_sha256: str | None = None
        self.restore_result: dict[str, Any] | None = None

    @staticmethod
    def _remove_target(target: Path) -> None:
        if target.is_symlink():
            raise BenchmarkError(f"refusing to alter symlink ASI target: {target}")
        if target.exists():
            if not target.is_file():
                raise BenchmarkError(f"ASI target exists but is not a regular file: {target}")
            target.unlink()

    def _capture(self) -> None:
        if not self.source_asi.is_file():
            raise BenchmarkError(f"ASI build not found: {self.source_asi}")
        self.backup_parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(tempfile.mkdtemp(prefix="asi_backup_", dir=self.backup_parent))
        for index, target in enumerate(self.targets):
            if target.is_symlink():
                raise BenchmarkError(f"refusing to alter symlink ASI target: {target}")
            if target.exists() and not target.is_file():
                raise BenchmarkError(f"ASI target exists but is not a regular file: {target}")
            existed = target.is_file()
            backup = self.backup_dir / f"target_{index}.asi"
            original_sha = None
            if existed:
                shutil.copy2(target, backup)
                original_sha = file_sha256(target)
            self.originals[target] = {
                "existed": existed,
                "backup": backup,
                "sha256": original_sha,
            }

    def _prepare(self) -> None:
        for target in self.targets:
            self._remove_target(target)
        if self.variant != "off":
            root_target = self.targets[0]
            shutil.copy2(self.source_asi, root_target)
            self.deployed_sha256 = file_sha256(root_target)
            source_sha = file_sha256(self.source_asi)
            if self.deployed_sha256 != source_sha:
                raise BenchmarkError("deployed root ASI SHA-256 differs from current build")
        if any(target.exists() for target in self.targets[1:]):
            raise BenchmarkError("nested StormBreaker.asi was not disabled")
        if self.variant == "off" and any(target.exists() for target in self.targets):
            raise BenchmarkError("off variant did not disable both StormBreaker.asi files")

    def __enter__(self) -> "AsiRoundFiles":
        try:
            self._capture()
            self._prepare()
            return self
        except Exception:
            if self.originals:
                self._restore()
            raise

    def _restore(self) -> dict[str, Any]:
        errors: list[str] = []
        restored: list[dict[str, Any]] = []
        for target in self.targets:
            state = self.originals.get(target)
            if state is None:
                continue
            stage: Path | None = None
            try:
                self._remove_target(target)
                if state["existed"]:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.restore")
                    shutil.copy2(state["backup"], stage)
                    os.replace(stage, target)
                    actual_sha = file_sha256(target)
                    if actual_sha != state["sha256"]:
                        raise RestoreError(f"restored SHA-256 mismatch for {target}")
                elif target.exists():
                    raise RestoreError(f"target should have been absent after restore: {target}")
                restored.append(
                    {
                        "path": str(target),
                        "originallyExisted": bool(state["existed"]),
                        "sha256": state["sha256"],
                    }
                )
            except Exception as exc:
                errors.append(f"{target}: {exc}")
            finally:
                if stage is not None and stage.exists():
                    with contextlib.suppress(OSError):
                        stage.unlink()

        if self.backup_dir is not None:
            try:
                shutil.rmtree(self.backup_dir)
            except Exception as exc:
                errors.append(f"backup cleanup {self.backup_dir}: {exc}")
        result = {"ok": not errors, "restored": restored, "errors": errors}
        self.restore_result = result
        if errors:
            raise RestoreError("strict ASI restore failed: " + "; ".join(errors))
        return result

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._restore()
        return False


class ExclusiveRunLock:
    """A sandbox-scoped named mutex on Windows, with a portable test fallback."""

    ERROR_ALREADY_EXISTS = 183

    def __init__(self, sandbox_root: Path):
        identity = canonical_windows_path(sandbox_root)
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        self.name = f"Local\\StormBreakerBenchmark-{suffix}"
        self.handle: int | None = None
        self.fallback_path: Path | None = None

    def __enter__(self) -> "ExclusiveRunLock":
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
            kernel32.CreateMutexW.restype = wintypes.HANDLE
            handle = kernel32.CreateMutexW(None, False, self.name)
            if not handle:
                raise BenchmarkError(f"CreateMutexW failed: {ctypes.get_last_error()}")
            self.handle = int(handle)
            if ctypes.get_last_error() == self.ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                self.handle = None
                raise BenchmarkError(f"another benchmark owns exclusive lock {self.name}")
        else:
            self.fallback_path = Path(tempfile.gettempdir()) / f"{self.name.split('-')[-1]}.lock"
            try:
                descriptor = os.open(self.fallback_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError as exc:
                raise BenchmarkError("another benchmark owns the fallback lock") from exc
            os.close(descriptor)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self.handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(wintypes.HANDLE(self.handle))
            self.handle = None
        if self.fallback_path is not None:
            with contextlib.suppress(FileNotFoundError):
                self.fallback_path.unlink()
        return False


def build_launch_kwargs(
    config: BenchmarkConfig,
    variant: str,
    artifact_dir: Path,
    *,
    run_id: str,
    session_id: str,
    artifact_root: Path,
) -> dict[str, Any]:
    selected = variant_config(variant)
    env: dict[str, str] = {
        "STORMBREAKER_DISABLE_DEBUG_CONSOLE": "1",
        "STORMBREAKER_DISABLE_CONTROL_PANEL": "1",
        "STORMBREAKER_PROFILER": "off",
        "STORMBREAKER_TELEMETRY": "1",
        "STORMBREAKER_MEMORY_SAFETY": "0",
        "STORMBREAKER_MEMORY_MONITOR": "0",
        "STORMBREAKER_VERBOSE_LOG": "0",
    }
    if bool(selected["asiEnabled"]):
        env.update(
            {
                "STORMBREAKER_MEMORY_BACKEND": str(selected["backend"]),
                "STORMBREAKER_TAKEOVER_MODE": str(selected["takeoverMode"]),
                "STORMBREAKER_ARTIFACT_DIR": str(artifact_dir.resolve()),
            }
        )
    return {
        "sandbox_root": str(config.war3_root),
        "map_path": str(config.map_path),
        "run_id": run_id,
        "session_id": session_id,
        "artifact_root": str(artifact_root),
        "windowed": True,
        "use_isolated_desktop": True,
        "desktop_name": "",
        "opengl": False,
        "deploy_d3d9_before_launch": False,
        "profile": "",
        "disable_modules": "",
        "env_overrides_json": json.dumps(env, ensure_ascii=False),
        "extra_args": "",
        "reuse_existing_root": True,
    }


def validate_isolation_contract(
    launch_contract: Mapping[str, Any],
    launch_result: Mapping[str, Any],
    expected_desktop_name: str,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        expected_env = json.loads(str(launch_contract.get("env_overrides_json", "")))
    except (TypeError, ValueError, json.JSONDecodeError):
        expected_env = None
        errors.append("launch contract has invalid env_overrides_json")
    observed_env = launch_result.get("envOverrides")
    if not isinstance(expected_env, Mapping):
        expected_env = {}
    if not isinstance(observed_env, Mapping):
        errors.append("AutoTest launch result omitted envOverrides")
        observed_env = {}
    for name, expected_value in expected_env.items():
        if observed_env.get(name) != expected_value:
            errors.append(
                f"AutoTest environment mismatch for {name}: "
                f"{observed_env.get(name)!r} != {expected_value!r}"
            )
    for name in (
        "STORMBREAKER_MEMORY_BACKEND",
        "STORMBREAKER_TAKEOVER_MODE",
        "STORMBREAKER_ARTIFACT_DIR",
    ):
        if name not in expected_env and name in observed_env:
            errors.append(f"AutoTest unexpectedly supplied {name}")
    if launch_contract.get("use_isolated_desktop") is not True:
        errors.append("launch contract did not require an isolated desktop")
    if launch_contract.get("windowed") is not True:
        errors.append("isolated launch contract was not windowed")
    if launch_contract.get("reuse_existing_root") is not True:
        errors.append("launch contract did not use the materialized instance root")

    desktop = launch_result.get("desktop")
    if not isinstance(desktop, Mapping):
        errors.append("AutoTest launch result omitted the desktop object")
        observed_name = ""
        observed_handle = 0
    else:
        observed_name = str(desktop.get("name", "") or "")
        observed_handle = int(desktop.get("handle", 0) or 0)
        if desktop.get("ok") is not True:
            errors.append(f"AutoTest isolated desktop was not successful: {dict(desktop)}")
        if desktop.get("skipped"):
            errors.append("AutoTest skipped isolated desktop creation")
        if not observed_name:
            errors.append("AutoTest isolated desktop has no name")
        if observed_handle <= 0:
            errors.append("AutoTest isolated desktop has no live handle")
    if expected_desktop_name and observed_name != expected_desktop_name:
        errors.append(
            f"AutoTest desktop mismatch: {observed_name!r} != {expected_desktop_name!r}"
        )
    if launch_result.get("windowed") is not True:
        errors.append("AutoTest launch result did not confirm windowed mode")
    return {
        "ok": not errors,
        "required": True,
        "expectedDesktopName": expected_desktop_name,
        "observedDesktopName": observed_name,
        "observedDesktopHandle": observed_handle,
        "expectedEnvironment": dict(expected_env),
        "observedEnvironment": dict(observed_env),
        "errors": errors,
    }


@contextlib.contextmanager
def sanitized_parent_environment() -> Iterator[None]:
    saved = {name: os.environ.get(name) for name in BENCHMARK_SANITIZED_ENV_VARS}
    try:
        for name in BENCHMARK_SANITIZED_ENV_VARS:
            os.environ.pop(name, None)
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def import_autotest(autotest_dir: Path) -> AutoTestApi:
    directory = str(autotest_dir.resolve())
    if directory not in sys.path:
        sys.path.insert(0, directory)
    # Deliberately deferred: importing the MCP module has Windows runtime side
    # effects that pure unit tests must never trigger.
    from autotest_sessions import build_instance_layout, materialize_instance_root
    from war3_autotest_mcp import (
        cleanup_orphan_sessions,
        launch_war3_instance,
        preflight_instance_pool,
        stop_war3,
    )

    return AutoTestApi(
        launch_instance=launch_war3_instance,
        stop=stop_war3,
        preflight_instances=preflight_instance_pool,
        cleanup_sessions=cleanup_orphan_sessions,
        build_instance_layout=build_instance_layout,
        materialize_instance_root=materialize_instance_root,
    )


def _require_windows() -> None:
    if os.name != "nt":
        raise BenchmarkError("the live benchmark requires Windows")


def query_process_image_path(pid: int) -> str | None:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process_query_limited_information = 0x1000
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value
    finally:
        kernel32.CloseHandle(handle)


def list_processes() -> list[dict[str, Any]]:
    _require_windows()
    th32cs_snappROCESS = 0x00000002
    invalid_handle_value = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(th32cs_snappROCESS, 0)
    if int(snapshot) == invalid_handle_value:
        raise BenchmarkError(f"CreateToolhelp32Snapshot(process) failed: {ctypes.get_last_error()}")
    rows: list[dict[str, Any]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            rows.append({"pid": int(entry.th32ProcessID), "name": str(entry.szExeFile)})
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return rows


def find_sandbox_war3_processes(war3_root: Path) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for process in list_processes():
        if str(process.get("name", "")).casefold() != "war3.exe":
            continue
        path = query_process_image_path(int(process["pid"]))
        if path and path_is_within_windows(path, war3_root):
            matches.append({**process, "path": path})
    return matches


def open_process_for_sampling(pid: int) -> int:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process_query_information = 0x0400
    process_vm_read = 0x0010
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(
        process_query_information | process_vm_read,
        False,
        int(pid),
    )
    if not handle:
        raise BenchmarkError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    return int(handle)


def close_handle(handle: int | None) -> None:
    if handle:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def process_alive(handle: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    exit_code = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(wintypes.HANDLE(handle), ctypes.byref(exit_code)):
        return False
    return int(exit_code.value) == 259


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def bytes_to_mb(value: int | float) -> float:
    return round(float(value) / (1024.0 * 1024.0), 6)


def sample_memory_fast(handle: int) -> dict[str, Any]:
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(counters)
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not psapi.GetProcessMemoryInfo(
        wintypes.HANDLE(handle), ctypes.byref(counters), counters.cb
    ):
        raise BenchmarkError(f"GetProcessMemoryInfo failed: {ctypes.get_last_error()}")
    return {
        "workingSetMB": bytes_to_mb(counters.WorkingSetSize),
        "commitMB": bytes_to_mb(counters.PagefileUsage),
        "pageFaultCountRaw": int(counters.PageFaultCount),
    }


def summarize_virtual_regions(
    regions: Sequence[Mapping[str, Any]],
    *,
    address_limit: int = X86_ADDRESS_SPACE_LIMIT,
) -> dict[str, Any]:
    if address_limit <= 0:
        raise ValueError("address_limit must be positive")
    free_ranges: list[tuple[int, int]] = []
    for region in sorted(regions, key=lambda row: int(row.get("baseAddress", 0))):
        base = int(region.get("baseAddress", 0))
        size = int(region.get("regionSize", 0))
        state = int(region.get("state", 0))
        if base < 0 or size <= 0:
            raise ValueError(f"invalid virtual memory region: {dict(region)}")
        start = min(max(base, 0), address_limit)
        end = min(base + size, address_limit)
        if state != MEM_FREE or end <= start:
            continue
        if free_ranges and start <= free_ranges[-1][1]:
            previous_start, previous_end = free_ranges[-1]
            free_ranges[-1] = (previous_start, max(previous_end, end))
        else:
            free_ranges.append((start, end))

    sizes = [end - start for start, end in free_ranges]
    largest = max(sizes, default=0)
    total = sum(sizes)
    return {
        "addressLimitBytes": address_limit,
        "queriedRegionCount": len(regions),
        "freeRegionCount": len(free_ranges),
        "largestFreeRegionBytes": largest,
        "largestFreeRegionMB": bytes_to_mb(largest),
        "totalFreeAddressSpaceBytes": total,
        "totalFreeAddressSpaceMB": bytes_to_mb(total),
    }


def query_virtual_address_space(
    handle: int,
    *,
    address_limit: int = X86_ADDRESS_SPACE_LIMIT,
) -> dict[str, Any]:
    _require_windows()
    if not handle:
        raise BenchmarkError("VirtualQueryEx requires a process handle")
    if address_limit <= 0 or address_limit > X86_ADDRESS_SPACE_LIMIT:
        raise BenchmarkError("address-space limit must describe the 32-bit process")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    regions: list[dict[str, int]] = []
    address = 0
    started = time.perf_counter()
    while address < address_limit:
        information = MEMORY_BASIC_INFORMATION()
        returned = int(
            kernel32.VirtualQueryEx(
                wintypes.HANDLE(handle),
                ctypes.c_void_p(address),
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        )
        if returned == 0:
            raise BenchmarkError(
                "VirtualQueryEx failed at "
                f"0x{address:08X}: {ctypes.get_last_error()}"
            )
        base = int(information.BaseAddress or 0)
        size = int(information.RegionSize)
        if size <= 0 or base + size <= address:
            raise BenchmarkError(
                f"VirtualQueryEx returned a non-advancing region at 0x{address:08X}"
            )
        regions.append(
            {
                "baseAddress": base,
                "regionSize": size,
                "state": int(information.State),
                "protect": int(information.Protect),
                "type": int(information.Type),
            }
        )
        address = min(base + size, address_limit)
        if len(regions) > 1_000_000:
            raise BenchmarkError("VirtualQueryEx region walk exceeded its safety bound")

    summary = summarize_virtual_regions(regions, address_limit=address_limit)
    summary.update(
        {
            "queryComplete": address >= address_limit,
            "queryDurationMs": round(
                (time.perf_counter() - started) * 1000.0, 6
            ),
        }
    )
    return summary


class SlowMemorySampler:
    def __init__(self) -> None:
        import win32com.client

        self._wmi = win32com.client.GetObject("winmgmts:")

    def sample(self, pid: int, handle: int) -> dict[str, Any]:
        rows = self._wmi.ExecQuery(
            "Select ProcessId,PrivatePageCount,VirtualSize,HandleCount "
            f"from Win32_Process where ProcessId={int(pid)}"
        )
        for row in rows:
            sample = {
                "privateMB": bytes_to_mb(int(row.PrivatePageCount)),
                "virtualMB": bytes_to_mb(int(row.VirtualSize)),
                "handleCount": int(row.HandleCount),
            }
            sample.update(query_virtual_address_space(handle))
            return sample
        raise BenchmarkError(f"WMI did not find pid {pid}")


def read_process_bytes(handle: int, address: int, size: int) -> bytes | None:
    if not handle or not address or size <= 0:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    ok = kernel32.ReadProcessMemory(
        wintypes.HANDLE(handle),
        ctypes.c_void_p(address),
        ctypes.byref(buffer),
        size,
        ctypes.byref(read),
    )
    if not ok or int(read.value) != size:
        return None
    return bytes(buffer)


def read_u32(handle: int, address: int) -> int | None:
    raw = read_process_bytes(handle, address, 4)
    return None if raw is None else int.from_bytes(raw, "little", signed=False)


def read_u8(handle: int, address: int) -> int | None:
    raw = read_process_bytes(handle, address, 1)
    return None if raw is None else int(raw[0])


def enum_modules(pid: int) -> list[dict[str, Any]]:
    _require_windows()
    th32cs_snapmodule = 0x00000008
    th32cs_snapmodule32 = 0x00000010
    invalid_handle_value = ctypes.c_void_p(-1).value

    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", wintypes.WCHAR * 256),
            ("szExePath", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(
        th32cs_snapmodule | th32cs_snapmodule32, int(pid)
    )
    if int(snapshot) == invalid_handle_value:
        return [{"error": f"CreateToolhelp32Snapshot(module) failed: {ctypes.get_last_error()}"}]
    modules: list[dict[str, Any]] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Module32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            modules.append(
                {
                    "name": str(entry.szModule),
                    "path": str(entry.szExePath),
                    "base": int(ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0),
                    "size": int(entry.modBaseSize),
                }
            )
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return modules


def find_module_base(modules: Sequence[Mapping[str, Any]], basename: str) -> int:
    wanted = basename.casefold()
    for module in modules:
        module_path = str(module.get("path") or module.get("name") or "")
        if ntpath.basename(module_path).casefold() == wanted:
            return int(module.get("base", 0) or 0)
    return 0


def enumerate_pid_windows(pid: int, desktop_name: str = "") -> list[dict[str, Any]]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    candidates: list[dict[str, Any]] = []
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [enum_proc, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.EnumDesktopWindows.argtypes = [
        wintypes.HANDLE,
        enum_proc,
        wintypes.LPARAM,
    ]
    user32.EnumDesktopWindows.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL

    @enum_proc
    def callback(hwnd: int, _lparam: int) -> bool:
        window_pid = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if int(window_pid.value) != int(pid):
            return True
        rect = wintypes.RECT()
        if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            width = max(0, int(rect.right - rect.left))
            height = max(0, int(rect.bottom - rect.top))
            candidates.append(
                {
                    "hwnd": int(hwnd),
                    "visible": bool(user32.IsWindowVisible(hwnd)),
                    "width": width,
                    "height": height,
                    "area": width * height,
                }
            )
        return True

    if desktop_name:
        desktop_readobjects = 0x0001
        desktop_enumerate = 0x0040
        user32.OpenDesktopW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        user32.OpenDesktopW.restype = wintypes.HANDLE
        user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        user32.CloseDesktop.restype = wintypes.BOOL
        desktop = user32.OpenDesktopW(
            desktop_name,
            0,
            False,
            desktop_readobjects | desktop_enumerate,
        )
        if not desktop:
            raise BenchmarkError(
                f"OpenDesktopW failed for {desktop_name}: {ctypes.get_last_error()}"
            )
        try:
            # EnumDesktopWindows does not clear the calling thread's last
            # error on success. Clear stale errors from OpenDesktopW first so
            # ERROR_NO_MORE_FILES cannot be mistaken for an enumeration fault.
            ctypes.set_last_error(0)
            if not user32.EnumDesktopWindows(desktop, callback, 0):
                error = ctypes.get_last_error()
                if error:
                    raise BenchmarkError(
                        f"EnumDesktopWindows failed for {desktop_name}: {error}"
                    )
        finally:
            user32.CloseDesktop(desktop)
    else:
        ctypes.set_last_error(0)
        if not user32.EnumWindows(callback, 0):
            error = ctypes.get_last_error()
            if error:
                raise BenchmarkError(f"EnumWindows failed: {error}")

    candidates.sort(
        key=lambda row: (bool(row["visible"]), int(row["area"])), reverse=True
    )
    return candidates


def find_main_window(pid: int, desktop_name: str = "") -> int:
    for row in enumerate_pid_windows(pid, desktop_name):
        if row["visible"] and row["width"] >= 320 and row["height"] >= 240:
            return int(row["hwnd"])
    return 0


def wait_for_main_window(
    pid: int, desktop_name: str, timeout_sec: float = 30.0
) -> int:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        hwnd = find_main_window(pid, desktop_name)
        if hwnd:
            return hwnd
        time.sleep(0.1)
    return 0


def resize_isolated_window(
    hwnd: int,
    desktop_name: str,
    client_width: int = 1280,
    client_height: int = 720,
) -> dict[str, Any]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetClientRect.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    user32.SetWindowPos.restype = wintypes.BOOL
    before_window = wintypes.RECT()
    before_client = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(before_window)):
        raise BenchmarkError("GetWindowRect failed")
    if not user32.GetClientRect(hwnd, ctypes.byref(before_client)):
        raise BenchmarkError("GetClientRect failed")
    border_w = max(0, (before_window.right - before_window.left) - before_client.right)
    border_h = max(0, (before_window.bottom - before_window.top) - before_client.bottom)
    swp_noactivate = 0x0010
    swp_showwindow = 0x0040
    sw_restore = 9
    user32.ShowWindow(hwnd, sw_restore)
    moved = bool(
        user32.SetWindowPos(
            hwnd,
            0,
            40,
            40,
            client_width + border_w,
            client_height + border_h,
            swp_noactivate | swp_showwindow,
        )
    )
    time.sleep(0.2)
    after_window = wintypes.RECT()
    after_client = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(after_window))
    user32.GetClientRect(hwnd, ctypes.byref(after_client))
    client_size_ok = (
        int(after_client.right - after_client.left) == client_width
        and int(after_client.bottom - after_client.top) == client_height
    )
    if not client_size_ok:
        raise BenchmarkError(
            "War3 client size is not 1280x720: "
            f"{after_client.right - after_client.left}x{after_client.bottom - after_client.top}"
        )
    return {
        "hwnd": int(hwnd),
        "desktopName": desktop_name,
        "setWindowPos": moved,
        "foregroundRequested": False,
        "isForeground": False,
        "windowRect": [after_window.left, after_window.top, after_window.right, after_window.bottom],
        "clientRect": [after_client.left, after_client.top, after_client.right, after_client.bottom],
        "clientSizeOk": client_size_ok,
    }


def capture_window(hwnd: int) -> Any:
    from PIL import Image

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.GetWindowDC.argtypes = [wintypes.HWND]
    user32.GetWindowDC.restype = wintypes.HANDLE
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HANDLE]
    user32.ReleaseDC.restype = ctypes.c_int
    user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HANDLE, wintypes.UINT]
    user32.PrintWindow.restype = wintypes.BOOL
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HANDLE]
    gdi32.CreateCompatibleDC.restype = wintypes.HANDLE
    gdi32.CreateCompatibleBitmap.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_int,
    ]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HANDLE
    gdi32.SelectObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    gdi32.SelectObject.restype = wintypes.HANDLE
    gdi32.GetDIBits.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.UINT,
    ]
    gdi32.GetDIBits.restype = ctypes.c_int
    gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.DeleteDC.argtypes = [wintypes.HANDLE]
    gdi32.DeleteDC.restype = wintypes.BOOL
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise BenchmarkError("GetWindowRect failed during screenshot")
    width = int(rect.right - rect.left)
    height = int(rect.bottom - rect.top)
    if width <= 0 or height <= 0:
        raise BenchmarkError(f"invalid screenshot bounds: {width}x{height}")

    class BitmapInfoHeader(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    class RgbQuad(ctypes.Structure):
        _fields_ = [
            ("rgbBlue", ctypes.c_ubyte),
            ("rgbGreen", ctypes.c_ubyte),
            ("rgbRed", ctypes.c_ubyte),
            ("rgbReserved", ctypes.c_ubyte),
        ]

    class BitmapInfo(ctypes.Structure):
        _fields_ = [("bmiHeader", BitmapInfoHeader), ("bmiColors", RgbQuad * 1)]

    window_dc = user32.GetWindowDC(wintypes.HWND(hwnd))
    if not window_dc:
        raise BenchmarkError(f"GetWindowDC failed: {ctypes.get_last_error()}")
    memory_dc = gdi32.CreateCompatibleDC(window_dc)
    bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height) if memory_dc else 0
    old_object = gdi32.SelectObject(memory_dc, bitmap) if bitmap else 0
    try:
        if not memory_dc or not bitmap or not old_object:
            raise BenchmarkError(f"GDI screenshot setup failed: {ctypes.get_last_error()}")
        if not user32.PrintWindow(wintypes.HWND(hwnd), memory_dc, 2):
            raise BenchmarkError(f"PrintWindow failed: {ctypes.get_last_error()}")

        info = BitmapInfo()
        info.bmiHeader.biSize = ctypes.sizeof(BitmapInfoHeader)
        info.bmiHeader.biWidth = width
        info.bmiHeader.biHeight = -height
        info.bmiHeader.biPlanes = 1
        info.bmiHeader.biBitCount = 32
        info.bmiHeader.biCompression = 0
        pixels = (ctypes.c_ubyte * (width * height * 4))()
        copied = gdi32.GetDIBits(
            memory_dc,
            bitmap,
            0,
            height,
            pixels,
            ctypes.byref(info),
            0,
        )
        if int(copied) != height:
            raise BenchmarkError(
                f"GetDIBits copied {int(copied)} of {height} scan lines"
            )
        return Image.frombuffer(
            "RGB", (width, height), bytes(pixels), "raw", "BGRX", 0, 1
        ).copy()
    finally:
        if old_object:
            gdi32.SelectObject(memory_dc, old_object)
        if bitmap:
            gdi32.DeleteObject(bitmap)
        if memory_dc:
            gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(wintypes.HWND(hwnd), window_dc)


def image_ready_features(image: Any) -> dict[str, Any]:
    """Port of the successful legacy manual runner HUD readiness features."""
    import cv2
    import numpy as np

    array = np.asarray(image.convert("RGB"))
    height, width = array.shape[:2]
    luma = (
        0.299 * array[:, :, 0] + 0.587 * array[:, :, 1] + 0.114 * array[:, :, 2]
    ).astype(np.uint8)

    def crop_feature(name: str, y0: float, y1: float, x0: float, x1: float) -> dict[str, Any]:
        crop = luma[
            int(height * y0) : int(height * y1),
            int(width * x0) : int(width * x1),
        ]
        if crop.size <= 0:
            return {"name": name, "ok": False}
        edges = cv2.Canny(crop, 50, 120)
        return {
            "name": name,
            "avg": round(float(crop.mean()), 3),
            "std": round(float(crop.std()), 3),
            "dark45": round(float((crop < 45).mean()), 4),
            "dark70": round(float((crop < 70).mean()), 4),
            "bright180": round(float((crop > 180).mean()), 4),
            "edge": round(float((edges > 0).mean()), 4),
        }

    bottom = crop_feature("bottom", 0.72, 0.99, 0.0, 1.0)
    bottom_right = crop_feature("bottomRight", 0.72, 0.98, 0.72, 0.98)
    bottom_left = crop_feature("bottomLeft", 0.72, 0.98, 0.02, 0.23)
    top = crop_feature("topHud", 0.0, 0.06, 0.0, 1.0)
    center = crop_feature("center", 0.18, 0.62, 0.28, 0.72)
    score = 0.0
    score += max(0.0, (bottom_right.get("dark70", 0.0) - 0.70) * 4.0)
    score += max(0.0, (bottom_left.get("dark70", 0.0) - 0.70) * 4.0)
    score += max(0.0, (bottom.get("edge", 0.0) - 0.055) * 10.0)
    score += max(0.0, (top.get("edge", 0.0) - 0.070) * 5.0)
    score += max(0.0, (center.get("edge", 0.0) - 0.055) * 5.0)
    return {
        "width": int(width),
        "height": int(height),
        "score": round(score, 4),
        "bottom": bottom,
        "bottomRight": bottom_right,
        "bottomLeft": bottom_left,
        "topHud": top,
        "center": center,
    }


def is_ready_by_features(features: Mapping[str, Any], elapsed_sec: float) -> bool:
    if elapsed_sec < 5.0:
        return False
    bottom = features.get("bottom", {})
    bottom_right = features.get("bottomRight", {})
    bottom_left = features.get("bottomLeft", {})
    center = features.get("center", {})
    return (
        float(features.get("score", 0.0)) >= 2.6
        and float(bottom_right.get("dark70", 0.0)) >= 0.82
        and float(bottom_left.get("dark70", 0.0)) >= 0.85
        and float(bottom.get("edge", 0.0)) >= 0.075
        and float(center.get("edge", 0.0)) >= 0.095
    )


def _peak(samples: Sequence[Mapping[str, Any]], key: str) -> float | None:
    values: list[float] = []
    for sample in samples:
        value = sample.get(key)
        if value is None:
            continue
        try:
            converted = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(converted):
            values.append(converted)
    return round(max(values), 6) if values else None


def _minimum(samples: Sequence[Mapping[str, Any]], key: str) -> float | None:
    values: list[float] = []
    for sample in samples:
        try:
            value = float(sample[key])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(value):
            values.append(value)
    return round(min(values), 6) if values else None


def _last_finite(samples: Sequence[Mapping[str, Any]], key: str) -> float | None:
    for sample in reversed(samples):
        try:
            value = float(sample[key])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(value):
            return round(value, 6)
    return None


def _collect_round_metrics(
    samples: Sequence[Mapping[str, Any]], ready_elapsed: float | None
) -> dict[str, Any]:
    measurement = [
        row
        for row in samples
        if ready_elapsed is not None and float(row.get("elapsedSec", -1.0)) >= ready_elapsed
    ]
    return {
        "readyElapsedSec": ready_elapsed,
        "measurementPeakWorkingSetMB": _peak(measurement, "workingSetMB"),
        "measurementPeakCommitMB": _peak(measurement, "commitMB"),
        "measurementPeakPrivateMB": _peak(measurement, "privateMB"),
        "measurementPeakVirtualMB": _peak(measurement, "virtualMB"),
        "measurementPeakHandleCount": _peak(measurement, "handleCount"),
        "measurementPeakStormAllocatedMB": _peak(
            measurement, "stormTotalAllocatedExtendedMB"
        ),
        "measurementEndLargestFreeRegionMB": _last_finite(
            measurement, "largestFreeRegionMB"
        ),
        "measurementMinLargestFreeRegionMB": _minimum(
            measurement, "largestFreeRegionMB"
        ),
        "measurementEndFreeRegionCount": _last_finite(
            measurement, "freeRegionCount"
        ),
        "measurementPeakFreeRegionCount": _peak(measurement, "freeRegionCount"),
        "measurementVirtualGrowthSlopeMBPerSec": metric_series_slope(
            measurement, "elapsedSec", "virtualMB"
        ),
        "wholeRunPeakWorkingSetMB": _peak(samples, "workingSetMB"),
        "wholeRunPeakCommitMB": _peak(samples, "commitMB"),
        "wholeRunPeakPrivateMB": _peak(samples, "privateMB"),
        "wholeRunMinLargestFreeRegionMB": _minimum(
            samples, "largestFreeRegionMB"
        ),
    }


def sample_live_round(
    *,
    config: BenchmarkConfig,
    spec: RoundSpec,
    pid: int,
    handle: int,
    hwnd: int,
    start_perf: float,
    round_dir: Path,
    runtime_root: Path,
    deployed_sha256: str | None,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    screenshot_features: list[dict[str, Any]] = []
    modules_launch = enum_modules(pid)
    modules_ready: list[dict[str, Any]] = []
    modules_end: list[dict[str, Any]] = []
    storm_base = find_module_base(modules_launch, "storm.dll")
    storm_extender = UInt32WrapExtender()
    page_fault_extender = UInt32WrapExtender()
    slow_sampler = SlowMemorySampler()
    ready_elapsed: float | None = None
    ready_confirmations = 0
    last_image: Any = None
    errors: list[str] = []
    next_fast = time.perf_counter()
    next_slow = next_fast
    next_screenshot = next_fast

    while True:
        now = time.perf_counter()
        elapsed = now - start_perf
        if not process_alive(handle):
            errors.append("War3 exited before the round completed")
            break

        if now >= next_fast:
            sample: dict[str, Any] = {"elapsedSec": round(elapsed, 6)}
            try:
                sample.update(sample_memory_fast(handle))
                sample["pageFaultCountExtended"] = page_fault_extender.update(
                    int(sample["pageFaultCountRaw"])
                )
            except Exception as exc:
                sample["fastSampleError"] = str(exc)
            if storm_base:
                raw_total = read_u32(handle, storm_base + config.storm_total_alloc_offset)
                extended_total = storm_extender.update(raw_total)
                initialized = read_u8(handle, storm_base + config.storm_memory_init_offset)
                sample.update(
                    {
                        "stormBase": storm_base,
                        "stormTotalAllocatedRaw": raw_total,
                        "stormTotalAllocatedExtended": extended_total,
                        "stormTotalAllocatedExtendedMB": (
                            bytes_to_mb(extended_total) if extended_total is not None else None
                        ),
                        "stormMemorySystemInitialized": (
                            bool(initialized) if initialized is not None else None
                        ),
                    }
                )
            if now >= next_slow:
                try:
                    sample.update(slow_sampler.sample(pid, handle))
                except Exception as exc:
                    sample["slowSampleError"] = str(exc)
                while next_slow <= now:
                    next_slow += SLOW_SAMPLE_INTERVAL_SEC
                if not storm_base:
                    current_modules = enum_modules(pid)
                    storm_base = find_module_base(current_modules, "storm.dll")
            samples.append(sample)
            while next_fast <= now:
                next_fast += FAST_SAMPLE_INTERVAL_SEC

        if now >= next_screenshot:
            try:
                image = capture_window(hwnd)
                last_image = image
                features = image_ready_features(image)
                features["elapsedSec"] = round(elapsed, 6)
                screenshot_features.append(features)
                if is_ready_by_features(features, elapsed):
                    ready_confirmations += 1
                else:
                    ready_confirmations = 0
                if ready_elapsed is None and ready_confirmations >= 2:
                    ready_elapsed = round(elapsed, 6)
                    image.save(round_dir / "ready.png")
                    modules_ready = enum_modules(pid)
                    log(f"{spec.key}: HUD ready at {ready_elapsed:.3f}s")
            except Exception as exc:
                screenshot_features.append(
                    {"elapsedSec": round(elapsed, 6), "error": str(exc)}
                )
                ready_confirmations = 0
            while next_screenshot <= now:
                next_screenshot += SCREENSHOT_INTERVAL_SEC

        if ready_elapsed is not None and elapsed >= ready_elapsed + config.measure_sec:
            break
        if ready_elapsed is None and elapsed >= config.ready_timeout_sec:
            errors.append(f"HUD readiness timed out after {config.ready_timeout_sec:.1f}s")
            break

        wake_at = min(next_fast, next_slow, next_screenshot)
        time.sleep(max(0.01, min(0.05, wake_at - time.perf_counter())))

    try:
        final_image = capture_window(hwnd)
        last_image = final_image
        final_image.save(round_dir / "final.png")
    except Exception as exc:
        errors.append(f"final screenshot failed: {exc}")
        if last_image is not None:
            with contextlib.suppress(Exception):
                last_image.save(round_dir / "final.png")
    if process_alive(handle):
        modules_end = enum_modules(pid)
    if not modules_ready:
        modules_ready = modules_end or modules_launch
    if not modules_end:
        modules_end = modules_ready or modules_launch

    module_validation = validate_modules(
        modules_ready,
        variant=spec.variant,
        runtime_root=runtime_root,
        deployed_asi_sha256=deployed_sha256,
    )
    if not module_validation["ok"]:
        errors.extend(f"module gate: {error}" for error in module_validation["errors"])
    if ready_elapsed is None:
        errors.append("no ready screenshot was produced")
    if not (round_dir / "final.png").is_file():
        errors.append("no final screenshot was produced")

    metrics = _collect_round_metrics(samples, ready_elapsed)
    for key in (
        "measurementPeakWorkingSetMB",
        "measurementPeakCommitMB",
        "measurementPeakPrivateMB",
        "measurementPeakVirtualMB",
        "measurementEndLargestFreeRegionMB",
        "measurementEndFreeRegionCount",
        "measurementVirtualGrowthSlopeMBPerSec",
    ):
        if metrics.get(key) is None:
            errors.append(f"required sampled metric is missing: {key}")
    measurement_samples = [
        row
        for row in samples
        if ready_elapsed is not None
        and float(row.get("elapsedSec", -1.0)) >= ready_elapsed
    ]
    if not any(sample.get("queryComplete") is True for sample in measurement_samples):
        errors.append("VirtualQueryEx never completed during the measurement window")

    write_jsonl(round_dir / "samples.jsonl", samples)
    write_jsonl(round_dir / "screenshot_features.jsonl", screenshot_features)
    module_artifact = {
        "launch": modules_launch,
        "ready": modules_ready,
        "end": modules_end,
        "validation": module_validation,
    }
    write_json(round_dir / "modules.json", module_artifact)
    return {
        "ok": not errors,
        "errors": errors,
        "readyElapsedSec": ready_elapsed,
        "metrics": metrics,
        "sampleCount": len(samples),
        "screenshotFeatureCount": len(screenshot_features),
        "modules": module_artifact,
        "artifacts": {
            "samples": str(round_dir / "samples.jsonl"),
            "modules": str(round_dir / "modules.json"),
            "screenshotFeatures": str(round_dir / "screenshot_features.jsonl"),
            "readyScreenshot": str(round_dir / "ready.png"),
            "finalScreenshot": str(round_dir / "final.png"),
        },
    }


def run_one_round(
    config: BenchmarkConfig,
    spec: RoundSpec,
    round_dir: Path,
    api: AutoTestApi,
    *,
    run_id: str,
    session_id: str,
    autotest_artifact_root: Path,
) -> dict[str, Any]:
    round_dir.mkdir(parents=True, exist_ok=False)
    metrics_path: Path | None = None
    result: dict[str, Any] = {
        **asdict(spec),
        "cycle": spec.cycle,
        "key": spec.key,
        "startedAt": utcish_timestamp(),
        "ok": False,
        "errors": [],
        "fatal": False,
    }
    pid = 0
    hwnd = 0
    handle: int | None = None
    pid_verified = False
    session_registered = False
    desktop_name = ""
    runtime_root: Path | None = None
    stop_result: Mapping[str, Any] | None = None
    deployment: AsiRoundFiles | None = None
    base_suppression: AsiRoundFiles | None = None
    start_perf = time.perf_counter()

    try:
        if (config.war3_root / "d3d9.dll").exists():
            raise BenchmarkError("real sandbox-root d3d9.dll appeared; refusing to move or replace it")

        layout = api.build_instance_layout(
            config.war3_root,
            autotest_artifact_root,
            run_id,
            session_id,
        )
        runtime_root = Path(layout.instance_root).resolve(strict=False)
        materialized = dict(
            api.materialize_instance_root(layout, reuse_existing=False)
        )
        result["materialize"] = materialized
        result["instanceRoot"] = str(runtime_root)
        result["sessionId"] = session_id
        if not materialized.get("ok"):
            raise BenchmarkError(f"AutoTest instance materialization failed: {materialized}")
        if (runtime_root / "d3d9.dll").exists():
            raise BenchmarkError(
                "real instance-root d3d9.dll appeared; refusing to move or replace it"
            )

        deployment = AsiRoundFiles(
            runtime_root,
            config.asi_path,
            spec.variant,
            round_dir,
        )
        with deployment:
            try:
                base_suppression = AsiRoundFiles(
                    config.war3_root,
                    config.asi_path,
                    "off",
                    round_dir,
                )
                with base_suppression:
                    launch_kwargs = build_launch_kwargs(
                        config,
                        spec.variant,
                        round_dir,
                        run_id=run_id,
                        session_id=session_id,
                        artifact_root=autotest_artifact_root,
                    )
                    result["launchContract"] = launch_kwargs
                    with sanitized_parent_environment():
                        launch_result = dict(api.launch_instance(**launch_kwargs))
                result["baseFileRestore"] = base_suppression.restore_result
                result["launch"] = launch_result
                if not launch_result.get("ok"):
                    raise BenchmarkError(f"AutoTest launch failed: {launch_result}")
                session_registered = True
                actual_session_id = str(launch_result.get("sessionId", ""))
                if actual_session_id != session_id:
                    raise BenchmarkError(
                        f"AutoTest returned the wrong session: {actual_session_id} != {session_id}"
                    )
                actual_root = Path(str(launch_result.get("instanceRoot", ""))).resolve(
                    strict=False
                )
                if canonical_windows_path(actual_root) != canonical_windows_path(runtime_root):
                    raise BenchmarkError(
                        f"AutoTest returned the wrong instance root: {actual_root} != {runtime_root}"
                    )
                desktop = dict(launch_result.get("desktop", {}) or {})
                isolation_validation = validate_isolation_contract(
                    launch_kwargs,
                    launch_result,
                    str(layout.desktop_name),
                )
                result["isolationValidation"] = isolation_validation
                if not isolation_validation["ok"]:
                    raise BenchmarkError(
                        "AutoTest isolation gate failed: "
                        + "; ".join(isolation_validation["errors"])
                    )
                desktop_name = str(isolation_validation["observedDesktopName"])
                pid = int(launch_result.get("pid", 0) or 0)
                if pid <= 0:
                    raise BenchmarkError("AutoTest launch did not return a positive pid")
                metrics_path = round_dir / f"metrics_{pid}.jsonl"
                image_path = query_process_image_path(pid)
                result["processImagePath"] = image_path
                if not image_path or not path_is_within_windows(image_path, runtime_root):
                    raise BenchmarkError(
                        "launched pid does not resolve inside its AutoTest instance root: "
                        f"{image_path}"
                    )
                pid_verified = True
                handle = open_process_for_sampling(pid)
                hwnd = wait_for_main_window(pid, desktop_name, timeout_sec=30.0)
                if not hwnd:
                    raise BenchmarkError(
                        f"War3 window did not appear on isolated desktop {desktop_name}"
                    )
                result["window"] = resize_isolated_window(
                    hwnd, desktop_name, 1280, 720
                )
                live = sample_live_round(
                    config=config,
                    spec=spec,
                    pid=pid,
                    handle=handle,
                    hwnd=hwnd,
                    start_perf=start_perf,
                    round_dir=round_dir,
                    runtime_root=runtime_root,
                    deployed_sha256=deployment.deployed_sha256,
                )
                result.update(live)
            finally:
                if pid > 0 and pid_verified and hwnd and handle is not None:
                    result["gracefulExitRequest"] = request_graceful_exit(
                        pid,
                        hwnd,
                        handle,
                        desktop_name,
                        timeout_sec=20.0,
                    )
                force_required = bool(
                    session_registered
                    and (
                        pid <= 0
                        or handle is None
                        or process_alive(handle)
                    )
                )
                close_handle(handle)
                handle = None
                if session_registered:
                    stop_result = dict(
                        api.stop(
                            pid=pid,
                            session_id=session_id,
                            graceful_wait_sec=1,
                            force=force_required,
                            avoid_foreground_switch=True,
                        )
                    )
                    result["stop"] = stop_result
                    if not stop_result.get("ok") or not stop_result.get("stopped"):
                        result.setdefault("errors", []).append(
                            f"AutoTest failed to stop owned session {session_id}: {stop_result}"
                        )
                        result["fatal"] = True
                    if force_required:
                        result.setdefault("errors", []).append(
                            "the isolated session required Job Object termination after the 20s graceful timeout"
                        )

        result["instanceFileRestore"] = deployment.restore_result
    except RestoreError as exc:
        result.setdefault("errors", []).append(str(exc))
        result["fatal"] = True
        result["traceback"] = traceback.format_exc()
    except Exception as exc:
        result.setdefault("errors", []).append(str(exc))
        result["traceback"] = traceback.format_exc()

    if base_suppression is not None:
        result["baseFileRestore"] = base_suppression.restore_result
    if deployment is not None:
        result["instanceFileRestore"] = deployment.restore_result
    restore_rows = [
        row
        for row in (
            result.get("baseFileRestore"),
            result.get("instanceFileRestore"),
        )
        if isinstance(row, Mapping)
    ]
    result["fileRestore"] = {
        "ok": all(bool(row.get("ok")) for row in restore_rows),
        "base": result.get("baseFileRestore"),
        "instance": result.get("instanceFileRestore"),
    }

    try:
        cleanup = dict(
            api.cleanup_sessions(
                run_id=run_id,
                remove_instance_roots=True,
                forget_sessions=True,
            )
        )
        result["sessionCleanup"] = cleanup
        if not cleanup.get("ok"):
            result.setdefault("errors", []).append(
                f"AutoTest session cleanup failed: {cleanup}"
            )
            result["fatal"] = True
    except Exception as exc:
        result["sessionCleanup"] = {"ok": False, "error": str(exc)}
        result.setdefault("errors", []).append(
            f"AutoTest session cleanup raised: {exc}"
        )
        result["fatal"] = True

    telemetry_summary: dict[str, float | None] = {
        "allocatorP99Nanoseconds": None,
        "allocateP99Nanoseconds": None,
        "allocatorStallOver10msCount": None,
    }
    try:
        metric_files = sorted(round_dir.glob("metrics_*.jsonl"))
        if metrics_path is not None and metrics_path.exists():
            metric_rows = read_jsonl(metrics_path)
        else:
            metric_rows = []
        unexpected_metric_files = [
            str(path) for path in metric_files if metrics_path is None or path != metrics_path
        ]
        metrics_validation = validate_metrics_rows(metric_rows, spec.variant)
        telemetry_summary = summarize_metrics_rows(metric_rows)
        if spec.variant != "off" and any(
            value is None for value in telemetry_summary.values()
        ):
            metrics_validation["ok"] = False
            metrics_validation.setdefault("errors", []).append(
                f"latency summary is incomplete: {telemetry_summary}"
            )
        if unexpected_metric_files:
            metrics_validation["ok"] = False
            metrics_validation.setdefault("errors", []).append(
                f"unexpected metrics JSONL files: {unexpected_metric_files}"
            )
        metrics_validation["files"] = [str(path) for path in metric_files]
    except Exception as exc:
        metrics_validation = {
            "ok": False,
            "variant": spec.variant,
            "errors": [str(exc)],
        }
    result["metricsJsonl"] = str(metrics_path) if metrics_path is not None else None
    result["metricsValidation"] = metrics_validation
    result["telemetrySummary"] = telemetry_summary
    result.setdefault("metrics", {}).update(telemetry_summary)
    if not metrics_validation.get("ok"):
        result.setdefault("errors", []).extend(
            f"metrics gate: {error}" for error in metrics_validation.get("errors", [])
        )

    if stop_result is None and session_registered:
        result.setdefault("errors", []).append(
            "owned AutoTest session was not passed to stop_war3"
        )
        result["fatal"] = True
    result["ok"] = not result.get("errors") and bool(result.get("ok", True))
    # sample_live_round sets ok before stop/metrics; recompute from all hard gates.
    result["ok"] = (
        not result.get("errors")
        and bool(result.get("isolationValidation", {}).get("ok"))
        and bool(result.get("metricsValidation", {}).get("ok"))
        and bool(result.get("modules", {}).get("validation", {}).get("ok"))
        and bool(result.get("readyElapsedSec") is not None)
        and bool(result.get("stop", {}).get("stopped"))
        and not bool(result.get("stop", {}).get("forced"))
        and bool(result.get("fileRestore", {}).get("ok"))
    )
    result["endedAt"] = utcish_timestamp()
    result["durationSec"] = round(time.perf_counter() - start_perf, 6)
    write_json(round_dir / "round.json", result)
    return result


def request_graceful_exit(
    pid: int,
    hwnd: int,
    process_handle: int | None,
    desktop_name: str,
    timeout_sec: float = 4.0,
) -> dict[str, Any]:
    """Close only the owned isolated-desktop game and accept its quit dialog."""
    if os.name != "nt" or pid <= 0 or not hwnd:
        return {"ok": False, "skipped": True, "reason": "no owned Windows window"}

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.PostMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.PostMessageW.restype = wintypes.BOOL
    user32.GetClassNameW.argtypes = [
        wintypes.HWND,
        wintypes.LPWSTR,
        ctypes.c_int,
    ]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [
        wintypes.HWND,
        wintypes.LPWSTR,
        ctypes.c_int,
    ]
    user32.GetWindowTextW.restype = ctypes.c_int
    wm_close = 0x0010
    wm_command = 0x0111
    wm_keydown = 0x0100
    wm_keyup = 0x0101
    id_yes = 6
    vk_return = 0x0D

    close_sent = bool(user32.PostMessageW(wintypes.HWND(hwnd), wm_close, 0, 0))
    confirmed: list[dict[str, Any]] = []
    deadline = time.monotonic() + max(0.5, timeout_sec)

    while time.monotonic() < deadline:
        if process_handle is not None and not process_alive(process_handle):
            return {
                "ok": True,
                "closeSent": close_sent,
                "confirmed": confirmed,
                "exited": True,
            }

        for row in enumerate_pid_windows(pid, desktop_name):
            candidate = int(row["hwnd"])
            class_buffer = ctypes.create_unicode_buffer(256)
            title_buffer = ctypes.create_unicode_buffer(512)
            user32.GetClassNameW(
                wintypes.HWND(candidate), class_buffer, len(class_buffer)
            )
            user32.GetWindowTextW(
                wintypes.HWND(candidate), title_buffer, len(title_buffer)
            )
            class_name = class_buffer.value
            title = title_buffer.value
            if class_name == "#32770":
                command_sent = bool(
                    user32.PostMessageW(
                        wintypes.HWND(candidate), wm_command, id_yes, 0
                    )
                )
                user32.PostMessageW(
                    wintypes.HWND(candidate), wm_keydown, vk_return, 0
                )
                user32.PostMessageW(
                    wintypes.HWND(candidate), wm_keyup, vk_return, 0
                )
                confirmed.append(
                    {
                        "hwnd": candidate,
                        "class": class_name,
                        "title": title,
                        "commandSent": command_sent,
                    }
                )
        time.sleep(0.2)

    return {
        "ok": True,
        "closeSent": close_sent,
        "desktopName": desktop_name,
        "confirmed": confirmed,
        "exited": process_handle is not None and not process_alive(process_handle),
    }


def preflight(config: BenchmarkConfig) -> dict[str, Any]:
    _require_windows()
    required_files = (
        config.war3_root / "War3.exe",
        config.war3_root / "Storm.dll",
        config.war3_root / "Game.dll",
        config.map_path,
        config.asi_path,
        config.autotest_dir / "war3_autotest_mcp.py",
        config.autotest_dir / "autotest_sessions.py",
    )
    missing = [str(path) for path in required_files if not path.is_file()]
    if missing:
        raise BenchmarkError(f"required files are missing: {missing}")
    local_d3d9 = config.war3_root / "d3d9.dll"
    if local_d3d9.exists():
        raise BenchmarkError(
            f"fail-closed: real root d3d9.dll exists and will not be moved: {local_d3d9}"
        )
    system_d3d9 = Path(os.environ.get("WINDIR", r"C:\Windows")) / "SysWOW64" / "d3d9.dll"
    if not system_d3d9.is_file():
        raise BenchmarkError(f"required SysWOW64 d3d9.dll is missing: {system_d3d9}")
    existing = find_sandbox_war3_processes(config.war3_root)
    if config.warmup_blocks != 1:
        raise BenchmarkError("this benchmark contract requires exactly one warmup block")
    if config.measured_blocks != DEFAULT_MEASURED_CYCLES:
        raise BenchmarkError(
            f"this benchmark contract requires exactly {DEFAULT_MEASURED_CYCLES} measured cycles"
        )
    if config.measure_sec <= 0 or config.ready_timeout_sec <= 0:
        raise BenchmarkError("timeouts must be positive")
    if config.bootstrap_iterations <= 0:
        raise BenchmarkError("bootstrap_iterations must be positive")
    gate_values = (
        config.memory_gate_pct,
        config.speed_gate_pct,
        config.hook_p99_gate_pct,
        config.virtual_slope_improvement_pct,
        config.free_region_improvement_pct,
        config.stall_improvement_pct,
    )
    if any(value < 0 for value in gate_values):
        raise BenchmarkError("all gate percentages must be non-negative")
    war3_pe = read_pe_identity(config.war3_root / "War3.exe")
    if not war3_pe["isWin32X86"]:
        raise BenchmarkError(f"War3.exe is not the required Win32/x86 image: {war3_pe}")
    if not war3_pe["largeAddressAware"]:
        raise BenchmarkError(
            "War3.exe is not Large Address Aware; a 4 GiB VirtualQueryEx walk is invalid"
        )
    storm_sha = file_sha256(config.war3_root / "Storm.dll")
    if storm_sha.casefold() != STORM_DLL_SHA256:
        raise BenchmarkError(
            f"unsupported Storm.dll SHA-256: {storm_sha} != {STORM_DLL_SHA256}"
        )
    game_sha = file_sha256(config.war3_root / "Game.dll")
    if game_sha.casefold() != GAME_DLL_SHA256:
        raise BenchmarkError(
            f"unsupported Game.dll SHA-256: {game_sha} != {GAME_DLL_SHA256}"
        )
    # Verify live-only imports before any file deployment or launch.
    import cv2  # noqa: F401
    import numpy  # noqa: F401
    import PIL  # noqa: F401
    import win32com.client  # noqa: F401

    return {
        "war3Root": str(config.war3_root),
        "war3Exe": str(config.war3_root / "War3.exe"),
        "war3Pe": war3_pe,
        "map": str(config.map_path),
        "asi": str(config.asi_path),
        "asiSha256": file_sha256(config.asi_path),
        "autotestDir": str(config.autotest_dir),
        "systemD3d9": str(system_d3d9),
        "stormDllSha256": storm_sha,
        "gameDllSha256": game_sha,
        "rootD3d9Absent": True,
        "tmpcopyUntouched": str(config.war3_root / "d3d9.dll.tmpcopy"),
        "existingSandboxWar3": existing,
        "existingProcessesAreNotStopped": True,
        "multiInstanceIsolationRequired": True,
    }


def run_benchmark(config: BenchmarkConfig) -> tuple[int, dict[str, Any]]:
    run_id = run_id_now()
    run_dir = config.output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    summary: dict[str, Any] = {
        "runId": run_id,
        "startedAt": utcish_timestamp(),
        "config": {
            **asdict(config),
            "war3_root": str(config.war3_root),
            "map_path": str(config.map_path),
            "asi_path": str(config.asi_path),
            "autotest_dir": str(config.autotest_dir),
            "output_dir": str(config.output_dir),
        },
        "rounds": [],
        "ok": False,
    }
    exit_code = 1
    try:
        with ExclusiveRunLock(config.war3_root):
            summary["preflight"] = preflight(config)
            api = import_autotest(config.autotest_dir)
            auto_preflight = dict(
                api.preflight_instances(
                    sandbox_root=str(config.war3_root),
                    map_path=str(config.map_path),
                    instance_count=1,
                    run_id=run_id,
                    session_prefix="sb",
                    artifact_root=str(run_dir / "autotest_artifacts"),
                )
            )
            summary["autoTestPreflight"] = auto_preflight
            if not auto_preflight.get("ok"):
                raise BenchmarkError(
                    f"AutoTest multi-instance preflight failed: {auto_preflight}"
                )
            schedule = generate_schedule(
                config.warmup_blocks,
                config.measured_blocks,
                config.seed,
            )
            scenario = build_scenario_manifest(schedule, config.measured_blocks)
            if not scenario["complete"]:
                raise BenchmarkError("generated 10-cycle scenario is incomplete")
            summary["scenario"] = scenario
            summary["schedule"] = [
                {**asdict(spec), "cycle": spec.cycle} for spec in schedule
            ]
            for index, spec in enumerate(schedule, 1):
                log(f"round {index}/{len(schedule)}: {spec.key}")
                row = run_one_round(
                    config,
                    spec,
                    run_dir / "rounds" / spec.key,
                    api,
                    run_id=run_id,
                    session_id=f"r{index:03d}-{spec.variant}",
                    autotest_artifact_root=run_dir / "autotest_artifacts",
                )
                summary["rounds"].append(row)
                write_json(run_dir / "summary.partial.json", summary)
                if row.get("fatal"):
                    raise BenchmarkError(f"fatal round prevents safe continuation: {spec.key}")

            evaluation = evaluate_results(
                summary["rounds"],
                measured_blocks=config.measured_blocks,
                memory_gate_pct=config.memory_gate_pct,
                speed_gate_pct=config.speed_gate_pct,
                hook_p99_gate_pct=config.hook_p99_gate_pct,
                virtual_slope_improvement_pct=config.virtual_slope_improvement_pct,
                free_region_improvement_pct=config.free_region_improvement_pct,
                stall_improvement_pct=config.stall_improvement_pct,
                bootstrap_iterations=config.bootstrap_iterations,
                seed=config.seed,
            )
            summary["evaluation"] = evaluation
            summary["ok"] = bool(evaluation["ok"])
            exit_code = 0 if summary["ok"] else 1
    except Exception as exc:
        summary["ok"] = False
        summary["fatalError"] = str(exc)
        summary["traceback"] = traceback.format_exc()
        exit_code = 2
    finally:
        summary["endedAt"] = utcish_timestamp()
        write_json(run_dir / "summary.json", summary)
        latest = config.output_dir / "latest.json"
        write_json(latest, summary)
        log(f"summary: {run_dir / 'summary.json'}")
    return exit_code, summary


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _int_auto(value: str) -> int:
    return int(value, 0)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--war3-root", type=Path, default=DEFAULT_WAR3_ROOT)
    parser.add_argument("--map", dest="map_path", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--asi", dest="asi_path", type=Path, default=DEFAULT_ASI)
    parser.add_argument("--autotest-dir", type=Path, default=DEFAULT_AUTOTEST_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--measured-blocks", type=int, default=DEFAULT_MEASURED_CYCLES
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--ready-timeout-sec", type=_positive_float, default=DEFAULT_READY_TIMEOUT_SEC)
    parser.add_argument("--measure-sec", type=_positive_float, default=DEFAULT_MEASURE_SEC)
    parser.add_argument("--memory-gate-pct", type=_nonnegative_float, default=DEFAULT_MEMORY_GATE_PCT)
    parser.add_argument("--speed-gate-pct", type=_nonnegative_float, default=DEFAULT_SPEED_GATE_PCT)
    parser.add_argument(
        "--hook-p99-gate-pct",
        type=_nonnegative_float,
        default=DEFAULT_HOOK_P99_GATE_PCT,
    )
    parser.add_argument(
        "--virtual-slope-improvement-pct",
        type=_nonnegative_float,
        default=DEFAULT_VIRTUAL_SLOPE_IMPROVEMENT_PCT,
    )
    parser.add_argument(
        "--free-region-improvement-pct",
        type=_nonnegative_float,
        default=DEFAULT_FREE_REGION_IMPROVEMENT_PCT,
    )
    parser.add_argument(
        "--stall-improvement-pct",
        type=_nonnegative_float,
        default=DEFAULT_STALL_IMPROVEMENT_PCT,
    )
    parser.add_argument("--bootstrap-iterations", type=int, default=DEFAULT_BOOTSTRAP_ITERATIONS)
    parser.add_argument("--storm-total-alloc-offset", type=_int_auto, default=STORM_TOTAL_ALLOC_OFFSET)
    parser.add_argument("--storm-memory-init-offset", type=_int_auto, default=STORM_MEMORY_INIT_OFFSET)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    config = BenchmarkConfig(
        war3_root=args.war3_root.resolve(),
        map_path=args.map_path.resolve(),
        asi_path=args.asi_path.resolve(),
        autotest_dir=args.autotest_dir.resolve(),
        output_dir=args.output_dir.resolve(),
        warmup_blocks=1,
        measured_blocks=args.measured_blocks,
        seed=args.seed,
        ready_timeout_sec=args.ready_timeout_sec,
        measure_sec=args.measure_sec,
        memory_gate_pct=args.memory_gate_pct,
        speed_gate_pct=args.speed_gate_pct,
        hook_p99_gate_pct=args.hook_p99_gate_pct,
        virtual_slope_improvement_pct=args.virtual_slope_improvement_pct,
        free_region_improvement_pct=args.free_region_improvement_pct,
        stall_improvement_pct=args.stall_improvement_pct,
        bootstrap_iterations=args.bootstrap_iterations,
        storm_total_alloc_offset=args.storm_total_alloc_offset,
        storm_memory_init_offset=args.storm_memory_init_offset,
    )
    exit_code, _summary = run_benchmark(config)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
