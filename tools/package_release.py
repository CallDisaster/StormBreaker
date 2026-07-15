from __future__ import annotations

"""Validate and package the production StormBreaker 1.3.0 ASI."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence
import zipfile

from write_stormbreaker_variant_manifest import ManifestFailure, inspect_release_pe


VERSION = "1.3.0"
RELEASE_DATE = "2026-07-15"
TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DEFAULT_ASI = REPO_ROOT / "StormMemPoolFix" / "Build" / "StormBreaker.asi"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "dist"
ARCHIVE_ROOT = f"StormBreaker-{VERSION}-win32-x86"
FIXED_ZIP_TIME = (2026, 7, 15, 0, 0, 0)

PACKAGE_FILES = (
    (REPO_ROOT / "README.md", "README.md"),
    (REPO_ROOT / "CHANGELOG.md", "CHANGELOG.md"),
    (REPO_ROOT / "LICENSE.txt", "LICENSE.txt"),
    (
        REPO_ROOT / "Document" / "Release_1.3.0.md",
        "RELEASE_NOTES_1.3.0.md",
    ),
)


class PackageFailure(RuntimeError):
    """The release package cannot be produced safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def validate_version_resource(path: Path) -> None:
    data = path.read_bytes()
    utf16_version = VERSION.encode("utf-16le")
    if utf16_version not in data:
        raise PackageFailure(
            f"ASI does not contain the expected {VERSION} version resource: {path}"
        )


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")


def build_package(asi: Path, output_dir: Path) -> tuple[Path, Path, dict[str, object]]:
    try:
        pe = inspect_release_pe(asi)
    except ManifestFailure as exc:
        raise PackageFailure(str(exc)) from exc
    validate_version_resource(asi)

    missing = [str(source) for source, _ in PACKAGE_FILES if not source.is_file()]
    if missing:
        raise PackageFailure("missing release files: " + ", ".join(missing))

    output_dir.mkdir(parents=True, exist_ok=True)
    stage = output_dir / ARCHIVE_ROOT
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()

    shutil.copy2(asi, stage / "StormBreaker.asi")
    for source, destination in PACKAGE_FILES:
        shutil.copy2(source, stage / destination)

    manifest: dict[str, object] = {
        "schema": "stormbreaker.release.v1",
        "name": "StormBreaker",
        "version": VERSION,
        "releaseDate": RELEASE_DATE,
        "architecture": "win32-x86",
        "largeAddressAware": pe["largeAddressAware"],
        "backend": "tlsf",
        "takeover": "large-four-hook",
        "threshold": "0xFE7C",
        "nativeSmallRepair": "search",
        "sourceRevision": git_revision(),
        "reproducibleTimestampUtc": f"{RELEASE_DATE}T00:00:00Z",
        "asi": pe,
    }
    write_text(stage / "release-manifest.json", json.dumps(manifest, indent=2) + "\n")

    checksum_lines = []
    for file in sorted(stage.iterdir(), key=lambda item: item.name.lower()):
        if file.name != "SHA256SUMS.txt":
            checksum_lines.append(f"{sha256_file(file)}  {file.name}")
    write_text(stage / "SHA256SUMS.txt", "\n".join(checksum_lines) + "\n")

    archive = output_dir / f"{ARCHIVE_ROOT}.zip"
    temporary = archive.with_suffix(".zip.tmp")
    temporary.unlink(missing_ok=True)
    with zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as bundle:
        for file in sorted(stage.iterdir(), key=lambda item: item.name.lower()):
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{file.name}", FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, file.read_bytes(), compresslevel=9)
    temporary.replace(archive)

    archive_checksum = output_dir / f"{archive.name}.sha256"
    write_text(archive_checksum, f"{sha256_file(archive)}  {archive.name}\n")
    return archive, archive_checksum, manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asi", type=Path, default=DEFAULT_ASI)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        archive, checksum, manifest = build_package(
            args.asi.resolve(), args.output_dir.resolve()
        )
    except (OSError, PackageFailure) as exc:
        print(f"release packaging failed closed: {exc}", file=sys.stderr)
        return 1
    print(f"release archive: {archive}")
    print(f"archive checksum: {checksum}")
    print(f"ASI SHA-256: {manifest['asi']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
