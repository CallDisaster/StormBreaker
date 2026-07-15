from __future__ import annotations

"""Validate release ASIs and write the StormBreaker variant manifest."""

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Sequence


TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DEFAULT_BUILD_DIR = REPO_ROOT / "StormMemPoolFix" / "Build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "StormBreaker-variants.json"

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020


class ManifestFailure(RuntimeError):
    """A release artifact is absent or violates the required Win32 ABI."""


@dataclass(frozen=True)
class VariantSpec:
    file: str
    backend: str
    build_identity: str
    backend_locked: bool


VARIANTS = (
    VariantSpec(
        "StormBreaker.asi", "tlsf", "runtime-selectable-default-tlsf", False
    ),
    VariantSpec("StormBreaker-TLSF.asi", "tlsf", "locked-tlsf", True),
    VariantSpec(
        "StormBreaker-mimalloc.asi", "mimalloc", "locked-mimalloc", True
    ),
    VariantSpec("StormBreaker-hybrid.asi", "hybrid", "locked-hybrid", True),
)


def inspect_release_pe(path: Path) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ManifestFailure(f"cannot read release artifact {path}: {exc}") from exc

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ManifestFailure(f"release artifact is not a DOS/PE image: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff_end = pe_offset + 24
    if pe_offset < 0x40 or coff_end > len(data):
        raise ManifestFailure(f"release artifact has an invalid PE offset: {path}")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ManifestFailure(f"release artifact has no PE signature: {path}")

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    if machine != IMAGE_FILE_MACHINE_I386:
        raise ManifestFailure(
            f"release artifact is not x86 (machine=0x{machine:04X}): {path}"
        )
    if not characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE:
        raise ManifestFailure(f"release artifact is not large-address-aware: {path}")

    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "machine": "0x014C",
        "largeAddressAware": True,
    }


def build_manifest(
    build_dir: Path,
    *,
    built_at: str | None = None,
    cpp_tests: str = "not recorded",
    python_tests: str = "not recorded",
    logic_benchmarks: str = "not recorded",
    war3_autotest: str = "not run",
) -> dict[str, object]:
    variants: list[dict[str, object]] = []
    for spec in VARIANTS:
        details = inspect_release_pe(build_dir / spec.file)
        variants.append(
            {
                "file": spec.file,
                "backend": spec.backend,
                "buildIdentity": spec.build_identity,
                "backendLocked": spec.backend_locked,
                **details,
            }
        )

    timestamp = built_at or datetime.now().astimezone().isoformat(timespec="seconds")
    return {
        "schema": "stormbreaker.variant-manifest.v2",
        "architecture": "x86",
        "largeAddressAware": True,
        "builtAt": timestamp,
        "controlPanel": {
            "firstHeartbeat": "immediate after Hook installation",
            "intervalSeconds": 60,
            "logPath": ".\\StormBreaker\\StormMemory.log",
            "flushEachHeartbeat": True,
        },
        "defaults": {
            "backend": "tlsf",
            "takeoverMode": "large",
            "profiler": "off",
            "telemetry": "off",
            "mimallocPurgeDelayMs": -1,
            "mimallocArenaReserveMiB": 0,
            "mimallocPageFullRetain": 2,
            "mimallocPageMaxCandidates": 4,
        },
        "variants": variants,
        "verification": {
            "cppTests": cpp_tests,
            "pythonTests": python_tests,
            "logicBenchmarks": logic_benchmarks,
            "war3AutoTest": war3_autotest,
        },
    }


def write_manifest(output: Path, manifest: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate x86/LAA StormBreaker ASIs and write their manifest."
    )
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cpp-tests", default="not recorded")
    parser.add_argument("--python-tests", default="not recorded")
    parser.add_argument("--logic-benchmarks", default="not recorded")
    parser.add_argument("--war3-autotest", default="not run")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = build_manifest(
            args.build_dir.resolve(),
            cpp_tests=args.cpp_tests,
            python_tests=args.python_tests,
            logic_benchmarks=args.logic_benchmarks,
            war3_autotest=args.war3_autotest,
        )
        write_manifest(args.output.resolve(), manifest)
    except ManifestFailure as exc:
        print(f"manifest generation failed closed: {exc}", file=sys.stderr)
        return 1
    print(f"variant manifest: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
