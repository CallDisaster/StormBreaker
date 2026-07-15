#!/usr/bin/env python3
"""Run one guarded StormBreaker crash smoke test in a real War3 directory."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid
import winreg
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_AUTOTEST_DIR = (
    REPO_ROOT.parents[1] / "AutoTest"
)
DEFAULT_WAR3_ROOT = Path(r"E:\Work\Warcraft III")
DEFAULT_MAP = Path(r"E:\Work\War3\Maps\(4)生与死v1.28读档bug修复.w3x")
DEFAULT_ARTIFACT_ROOT = REPO_ROOT / "stormbreaker_benchmark_results"
EXPECTED_STORM_SHA256 = "F8F519CFAA6275A5172A014F0ABED2212284390A33F1194677155A7D408E63EB"
EXPECTED_GAME_SHA256 = "E04D1716603C075EB0C8E1E21CF1093A664ADC5249EFAB396BFA08D7B09D0C3A"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import stormbreaker_benchmark as bench  # noqa: E402


class SmokeError(RuntimeError):
    pass


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _mb(value: int | float) -> float:
    return round(float(value) / (1024.0 * 1024.0), 3)


def system_memory_status() -> dict[str, float]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise SmokeError(f"GlobalMemoryStatusEx failed: {ctypes.get_last_error()}")
    return {
        "availablePhysicalMB": _mb(status.ullAvailPhys),
        "availableCommitMB": _mb(status.ullAvailPageFile),
        "availableVirtualMB": _mb(status.ullAvailVirtual),
    }


def get_exit_code(handle: int) -> int | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    value = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(wintypes.HANDLE(handle), ctypes.byref(value)):
        return None
    return int(value.value)


def current_war3_pids() -> set[int]:
    return {
        int(row["pid"])
        for row in bench.list_processes()
        if str(row.get("name", "")).casefold() == "war3.exe"
    }


class RuntimeFiles:
    """Back up and restore the exact files touched by one direct-root run."""

    def __init__(self, root: Path, asi: Path, artifact_dir: Path):
        self.root = root
        self.source_asi = asi
        self.artifact_dir = artifact_dir
        self.root_asi = root / "StormBreaker.asi"
        self.nested_asi = root / "StormBreaker" / "StormBreaker.asi"
        self.runtime_log = root / "StormBreaker" / "StormMemory.log"
        self.map_target = root / "Maps" / "Test" / "WorldEditTestMap.w3x"
        self.targets = (
            self.root_asi,
            self.nested_asi,
            self.runtime_log,
            self.map_target,
        )
        self.states: dict[Path, dict[str, Any]] = {}
        self.deployed_sha256 = ""

    @staticmethod
    def _remove_regular(path: Path) -> None:
        if path.is_symlink():
            raise SmokeError(f"refusing to alter symlink: {path}")
        if path.exists() and not path.is_file():
            raise SmokeError(f"expected a regular file: {path}")
        if path.is_file():
            path.unlink()

    def __enter__(self) -> "RuntimeFiles":
        if not self.source_asi.is_file():
            raise SmokeError(f"ASI build not found: {self.source_asi}")
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = self.artifact_dir / "originals"
        backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            for index, target in enumerate(self.targets):
                if target.is_symlink():
                    raise SmokeError(f"refusing to alter symlink: {target}")
                if target.exists() and not target.is_file():
                    raise SmokeError(f"expected a regular file: {target}")
                existed = target.is_file()
                backup = backup_dir / f"{index:02d}-{target.name}"
                sha256 = None
                if existed:
                    shutil.copy2(target, backup)
                    sha256 = bench.file_sha256(target)
                self.states[target] = {
                    "existed": existed,
                    "backup": backup,
                    "sha256": sha256,
                }
                self._remove_regular(target)
            shutil.copy2(self.source_asi, self.root_asi)
            self.deployed_sha256 = bench.file_sha256(self.root_asi)
            if self.deployed_sha256 != bench.file_sha256(self.source_asi):
                raise SmokeError("deployed ASI hash differs from source build")
            return self
        except Exception:
            self.restore()
            raise

    def capture_runtime_outputs(self) -> None:
        if self.runtime_log.is_file():
            shutil.copy2(self.runtime_log, self.artifact_dir / "test-StormMemory.log")

    def restore(self) -> None:
        errors: list[str] = []
        for target in reversed(self.targets):
            state = self.states.get(target)
            if state is None:
                continue
            stage: Path | None = None
            try:
                self._remove_regular(target)
                if state["existed"]:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.restore")
                    shutil.copy2(state["backup"], stage)
                    os.replace(stage, target)
                    if bench.file_sha256(target) != state["sha256"]:
                        raise SmokeError(f"restored hash mismatch: {target}")
            except Exception as exc:
                errors.append(f"{target}: {exc}")
            finally:
                if stage is not None and stage.exists():
                    with contextlib.suppress(OSError):
                        stage.unlink()
        if errors:
            raise SmokeError("runtime restore failed: " + "; ".join(errors))

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.capture_runtime_outputs()
        self.restore()
        return False


class RegistrySnapshot:
    def __init__(self) -> None:
        self.entries: list[tuple[Any, str, int, str, bool, Any, int]] = []

    def capture(self) -> None:
        specifications = (
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Blizzard Entertainment\Warcraft III",
                winreg.KEY_WOW64_32KEY,
                "InstallPath",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Blizzard Entertainment\Warcraft III",
                winreg.KEY_WOW64_32KEY,
                "GamePath",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Blizzard Entertainment\Warcraft III",
                0,
                "InstallPath",
            ),
        )
        self.entries.clear()
        for hive, path, view, name in specifications:
            existed = False
            value: Any = None
            value_type = winreg.REG_SZ
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_QUERY_VALUE | view) as key:
                    value, value_type = winreg.QueryValueEx(key, name)
                    existed = True
            except FileNotFoundError:
                pass
            self.entries.append((hive, path, view, name, existed, value, value_type))

    def restore(self) -> None:
        errors: list[str] = []
        for hive, path, view, name, existed, value, value_type in self.entries:
            try:
                with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | view) as key:
                    if existed:
                        winreg.SetValueEx(key, name, 0, value_type, value)
                    else:
                        with contextlib.suppress(FileNotFoundError):
                            winreg.DeleteValue(key, name)
            except OSError as exc:
                errors.append(f"{path}::{name}: {exc}")
        if errors:
            raise SmokeError("registry restore failed: " + "; ".join(errors))


class OwnedProcess:
    """Ensure only the PID created by this run is stopped before file restore."""

    def __init__(self, stop_war3: Any, result: dict[str, Any]):
        self.stop_war3 = stop_war3
        self.result = result
        self.pid = 0
        self.handle: int | None = None
        self.owned = False

    def __enter__(self) -> "OwnedProcess":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self.handle is not None:
            bench.close_handle(self.handle)
            self.handle = None
        if self.owned and self.pid > 0:
            self.result["stop"] = self.stop_war3(
                pid=self.pid,
                graceful_wait_sec=1,
                force=True,
                avoid_foreground_switch=True,
            )
        time.sleep(0.75)
        return False


def import_autotest(directory: Path) -> tuple[Any, Any]:
    resolved = str(directory.resolve())
    if resolved not in sys.path:
        sys.path.insert(0, resolved)
    from war3_autotest_mcp import launch_war3_test, stop_war3

    return launch_war3_test, stop_war3


def read_fresh_log(root: Path, backend: str, mode: str) -> dict[str, Any]:
    path = root / "StormBreaker" / "StormMemory.log"
    if not path.is_file():
        return {
            "path": str(path),
            "bytes": 0,
            "hookInitialized": False,
            "backendLogged": False,
            "modeLogged": False,
            "addressSystemLogged": False,
            "tail": [],
        }
    text = path.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "hookInitialized": "Storm memory hooks installed" in text,
        "backendLogged": f"backend={backend}" in text,
        "modeLogged": f"mode={mode}" in text,
        "addressSystemLogged": "address=system" in text,
        "tail": text.splitlines()[-100:],
    }


def important_modules(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = {"stormbreaker.asi", "storm.dll", "game.dll", "d3d9.dll"}
    return [
        dict(row)
        for row in modules
        if str(row.get("name", "")).casefold() in wanted
    ]


def run_smoke(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = args.war3_root.resolve()
    map_path = args.map_path.resolve()
    asi_path = args.asi_path.resolve()
    autotest_dir = args.autotest_dir.resolve()
    for required in (root / "war3.exe", root / "Storm.dll", root / "Game.dll", map_path, asi_path):
        if not required.is_file():
            raise SmokeError(f"required file not found: {required}")
    if (root / "d3d9.dll").exists():
        raise SmokeError(f"local d3d9.dll is not allowed for this smoke test: {root / 'd3d9.dll'}")
    if bench.file_sha256(root / "Storm.dll").casefold() != EXPECTED_STORM_SHA256.casefold():
        raise SmokeError("Storm.dll SHA-256 is not the locked Warcraft III 1.27a build")
    if bench.file_sha256(root / "Game.dll").casefold() != EXPECTED_GAME_SHA256.casefold():
        raise SmokeError("Game.dll SHA-256 is not the locked Warcraft III 1.27a build")

    run_id = args.run_id or time.strftime(
        f"crash-smoke-{args.backend}-{args.mode}-%Y%m%d-%H%M%S"
    )
    artifact_dir = (args.artifact_root / run_id).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "runId": run_id,
        "war3Root": str(root),
        "map": str(map_path),
        "mapSha256": bench.file_sha256(map_path),
        "asiBuild": str(asi_path),
        "asiBuildSha256": bench.file_sha256(asi_path),
        "backend": args.backend,
        "mode": args.mode,
        "durationSec": args.duration_sec,
        "isolatedDesktop": args.isolated_desktop,
        "observations": [],
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    result_path = artifact_dir / "result.json"
    preexisting = current_war3_pids()
    result["preexistingWar3Pids"] = sorted(preexisting)
    registry = RegistrySnapshot()
    registry.capture()
    launch_war3_test, stop_war3 = import_autotest(autotest_dir)
    pid = 0
    owned_pid = False
    handle: int | None = None
    stopped_for_guard = False
    unexpected_exit = False
    latest_modules: list[dict[str, Any]] = []
    consecutive_hung_sec = 0.0
    max_consecutive_hung_sec = 0.0
    exit_code: int | None = None

    try:
        with (
            bench.ExclusiveRunLock(root),
            RuntimeFiles(root, asi_path, artifact_dir) as runtime,
            OwnedProcess(stop_war3, result) as process,
        ):
            env = {
                "STORMBREAKER_MEMORY_BACKEND": args.backend,
                "STORMBREAKER_TAKEOVER_MODE": args.mode,
                "STORMBREAKER_TLSF_ADDRESS_POLICY": args.address_policy,
                "STORMBREAKER_PROFILER": "off",
                "STORMBREAKER_TELEMETRY": "0",
                "STORMBREAKER_MEMORY_MONITOR": "0",
                "STORMBREAKER_MEMORY_SAFETY": "0",
                "STORMBREAKER_VERBOSE_LOG": "0",
                "STORMBREAKER_DISABLE_DEBUG_CONSOLE": "1",
                "STORMBREAKER_DISABLE_CONTROL_PANEL": "0",
            }
            desktop_name = f"War3AutoTest_{run_id}" if args.isolated_desktop else ""
            launch = launch_war3_test(
                war3_dir=str(root),
                map_path=str(map_path),
                windowed=True,
                use_isolated_desktop=args.isolated_desktop,
                desktop_name=desktop_name,
                auto_perf_record=False,
                deploy_d3d9_before_launch=False,
                enforce_video_baseline=False,
                env_overrides_json=json.dumps(env),
                extra_args=args.extra_args,
            )
            result["launch"] = launch
            if not launch.get("ok"):
                raise SmokeError(f"AutoTest launch failed: {launch}")
            pid = int(launch.get("pid", 0))
            result["pid"] = pid
            if pid <= 0 or pid in preexisting:
                raise SmokeError(f"AutoTest returned an unsafe PID: {pid}")
            image_path = bench.query_process_image_path(pid)
            result["processImagePath"] = image_path
            expected_image = root / "war3.exe"
            if not image_path or bench.canonical_windows_path(image_path) != bench.canonical_windows_path(expected_image):
                raise SmokeError(f"launched PID image mismatch: {image_path} != {expected_image}")
            owned_pid = True
            process.pid = pid
            process.owned = True
            handle = bench.open_process_for_sampling(pid)
            process.handle = handle

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.IsHungAppWindow.argtypes = [wintypes.HWND]
            user32.IsHungAppWindow.restype = wintypes.BOOL
            started = time.monotonic()
            next_sample = 0.0
            while True:
                now = time.monotonic()
                elapsed = now - started
                alive = bench.process_alive(handle)
                if not alive:
                    unexpected_exit = True
                    exit_code = get_exit_code(handle)
                    result["exitElapsedSec"] = round(elapsed, 3)
                    break
                modules = bench.enum_modules(pid)
                latest_modules = modules or latest_modules
                windows = bench.enumerate_pid_windows(pid, desktop_name)
                hung = any(
                    bool(user32.IsHungAppWindow(wintypes.HWND(int(row.get("hwnd", 0)))))
                    for row in windows
                    if int(row.get("hwnd", 0)) > 0
                )
                if hung:
                    consecutive_hung_sec += args.poll_interval_sec
                    max_consecutive_hung_sec = max(
                        max_consecutive_hung_sec, consecutive_hung_sec
                    )
                else:
                    consecutive_hung_sec = 0.0

                if elapsed >= next_sample:
                    process_memory = bench.sample_memory_fast(handle)
                    system_memory = system_memory_status()
                    result["observations"].append(
                        {
                            "elapsedSec": round(elapsed, 3),
                            "alive": True,
                            "hung": hung,
                            "windows": windows,
                            "modules": {
                                "stormBreaker": any(
                                    str(row.get("name", "")).casefold() == "stormbreaker.asi"
                                    for row in modules
                                ),
                                "storm": any(
                                    str(row.get("name", "")).casefold() == "storm.dll"
                                    for row in modules
                                ),
                                "game": any(
                                    str(row.get("name", "")).casefold() == "game.dll"
                                    for row in modules
                                ),
                            },
                            **process_memory,
                            **system_memory,
                        }
                    )
                    next_sample += args.sample_interval_sec
                    process_commit = float(process_memory.get("commitMB", 0.0) or 0.0)
                    available_commit = float(system_memory["availableCommitMB"])
                    if process_commit >= args.max_process_commit_mb:
                        result["memoryGuard"] = (
                            f"process commit {process_commit:.1f} MB reached "
                            f"limit {args.max_process_commit_mb:.1f} MB"
                        )
                        stopped_for_guard = True
                        break
                    if available_commit <= args.min_system_commit_headroom_mb:
                        result["memoryGuard"] = (
                            f"system commit headroom {available_commit:.1f} MB reached "
                            f"limit {args.min_system_commit_headroom_mb:.1f} MB"
                        )
                        stopped_for_guard = True
                        break
                if elapsed >= args.duration_sec:
                    break
                time.sleep(args.poll_interval_sec)

            result["survivedObservation"] = bool(handle and bench.process_alive(handle))
            result["unexpectedExit"] = unexpected_exit
            result["exitCode"] = exit_code
            result["maxConsecutiveHungSec"] = round(max_consecutive_hung_sec, 3)
            result["hungFailure"] = max_consecutive_hung_sec >= args.hung_failure_sec
            result["stoppedForMemoryGuard"] = stopped_for_guard
            result["importantModules"] = important_modules(latest_modules)
            result["moduleValidation"] = bench.validate_modules(
                latest_modules,
                variant="large-tlsf",
                runtime_root=root,
                deployed_asi_sha256=runtime.deployed_sha256,
                expected_storm_sha256=EXPECTED_STORM_SHA256,
                expected_game_sha256=EXPECTED_GAME_SHA256,
            )
            result["freshLog"] = read_fresh_log(root, args.backend, args.mode)
    except Exception as exc:
        result["error"] = repr(exc)
    finally:
        try:
            registry.restore()
            result["registryRestored"] = True
        except Exception as exc:
            result["registryRestored"] = False
            result["registryRestoreError"] = repr(exc)

    log = result.get("freshLog", {})
    config_valid = bool(
        log.get("hookInitialized")
        and log.get("backendLogged")
        and log.get("modeLogged")
        and (
            args.backend == "mimalloc"
            or args.address_policy != "system"
            or log.get("addressSystemLogged")
        )
    )
    result["configurationValid"] = config_valid
    module_valid = bool(result.get("moduleValidation", {}).get("ok"))
    result["ok"] = bool(
        result.get("survivedObservation")
        and not result.get("unexpectedExit")
        and not result.get("hungFailure")
        and not result.get("stoppedForMemoryGuard")
        and module_valid
        and config_valid
        and result.get("registryRestored")
        and "error" not in result
    )
    result["endedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if result["ok"]:
        return result, 0
    if result.get("unexpectedExit"):
        return result, 3
    return result, 2


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--war3-root", type=Path, default=DEFAULT_WAR3_ROOT)
    parser.add_argument("--map", dest="map_path", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--asi", dest="asi_path", type=Path, required=True)
    parser.add_argument("--backend", choices=("tlsf", "mimalloc", "hybrid"), required=True)
    parser.add_argument("--mode", choices=("large", "32k", "8k", "2k", "256", "full"), default="large")
    parser.add_argument("--address-policy", choices=("system", "clustered"), default="system")
    parser.add_argument("--duration-sec", type=float, default=100.0)
    parser.add_argument("--poll-interval-sec", type=float, default=1.0)
    parser.add_argument("--sample-interval-sec", type=float, default=5.0)
    parser.add_argument("--hung-failure-sec", type=float, default=15.0)
    parser.add_argument("--min-system-commit-headroom-mb", type=float, default=2048.0)
    parser.add_argument("--max-process-commit-mb", type=float, default=1800.0)
    parser.add_argument("--extra-args", default="")
    parser.add_argument("--isolated-desktop", action="store_true")
    parser.add_argument("--autotest-dir", type=Path, default=DEFAULT_AUTOTEST_DIR)
    parser.add_argument("--artifact-root", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    parser.add_argument("--run-id", default="")
    args = parser.parse_args(argv)
    if args.duration_sec <= 0:
        parser.error("--duration-sec must be positive")
    if args.poll_interval_sec <= 0 or args.sample_interval_sec <= 0:
        parser.error("poll and sample intervals must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result, exit_code = run_smoke(args)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": repr(exc)}, ensure_ascii=False, indent=2))
        return 2
    summary = {
        "ok": result.get("ok"),
        "runId": result.get("runId"),
        "pid": result.get("pid"),
        "survivedObservation": result.get("survivedObservation"),
        "unexpectedExit": result.get("unexpectedExit"),
        "hungFailure": result.get("hungFailure"),
        "stoppedForMemoryGuard": result.get("stoppedForMemoryGuard"),
        "moduleValid": result.get("moduleValidation", {}).get("ok"),
        "configurationValid": result.get("configurationValid"),
        "registryRestored": result.get("registryRestored"),
        "artifact": str((args.artifact_root / str(result.get("runId"))) / "result.json"),
        "error": result.get("error"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
