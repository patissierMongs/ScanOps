#!/usr/bin/env python3
"""Build and execute both Windows offline archives against a real local Nmap.

This is intentionally separate from ``runtime_e2e.py``: that harness validates the
checkout, while this one proves that the actual regular and all-in-one ZIP artifacts
can be unpacked, installed/started, and can execute their vendored staged engine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from process_control import popen_tracked
from runtime_e2e import (
    ApiClient,
    HOST,
    RuntimeE2EError,
    _capture_cleanup_error,
    _find_nmap,
    _initial_admin_password,
    _login,
    _port_is_bindable,
    _stop_process_tree,
    _tail,
    _wait_for_health,
    _wait_scan,
    log,
    require,
)


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_NAMES = {
    "regular": "ScanOps_offline.zip",
    "allinone": "ScanOps_allinone.zip",
}


def _write_report(directory: Path | None, report: dict) -> None:
    if directory is None:
        return
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package-runtime-smoke-result.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8",
    )


def _run_logged(label: str, command: list[str], log_path: Path | None,
                timeout: int, **kwargs) -> None:
    log(f"{label}: {' '.join(command)}")
    process = popen_tracked(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", **kwargs,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        cleanup_errors: list[str] = []
        _capture_cleanup_error(
            cleanup_errors, f"{label} timed-out process tree stop",
            lambda: _stop_process_tree(process),
        )
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(output, encoding="utf-8")
        detail = f"; cleanup failures: {'; '.join(cleanup_errors)}" if cleanup_errors else ""
        raise RuntimeE2EError(f"{label} timed out after {timeout}s{detail}") from exc
    cleanup_errors: list[str] = []
    _capture_cleanup_error(
        cleanup_errors, f"{label} completed process tree stop",
        lambda: _stop_process_tree(process),
    )
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8")
    if output:
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
    require(not cleanup_errors, "; ".join(cleanup_errors))
    require(process.returncode == 0, f"{label} failed with exit {process.returncode}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _archive_info(path: Path) -> dict:
    require(path.is_file(), f"archive was not created: {path}")
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, f"archive CRC check failed: {path.name}")
        names = set(archive.namelist())
        require("ScanOps/engine/scanops_engine/__main__.py" in names,
                f"vendored engine is missing from {path.name}")
        require("ScanOps/frontend/dist/index.html" in names,
                f"frontend dist is missing from {path.name}")
        count = len(names)
    return {"path": str(path), "bytes": path.stat().st_size, "files": count, "sha256": _sha256(path)}


def _copy_build_checkout(destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", ".venv", ".venv312", ".venv313", "node_modules", "data",
        "_e2e_data", "_e2e_chrome", "__pycache__", ".pytest_cache", ".vite",
        "*.pyc", "*.pyo", "*.log",
    )
    shutil.copytree(ROOT, destination, ignore=ignored)


def _build_archives(run_root: Path, evidence: Path | None,
                    command_timeout: int) -> tuple[dict, dict[str, Path]]:
    require(os.name == "nt", "package runtime smoke requires Windows")
    require(sys.version_info[:2] == (3, 12) and struct.calcsize("P") * 8 == 64,
            "package runtime smoke requires CPython 3.12 x64")
    require((ROOT / "frontend" / "dist" / "index.html").is_file(),
            "build frontend/dist before package runtime smoke")
    build_root = run_root / "build"
    build_root.mkdir()
    build_checkout = build_root / "ScanOps"
    _copy_build_checkout(build_checkout)
    archive_paths = {
        kind: build_root / name for kind, name in ARCHIVE_NAMES.items()
    }
    allinone_stage = build_root / "_allinone_stage"
    _run_logged(
        "regular ZIP build",
        [sys.executable, str(build_checkout / "packaging" / "build_zip.py")],
        evidence / "build-regular.log" if evidence else None,
        timeout=command_timeout, cwd=build_checkout,
    )
    _run_logged(
        "all-in-one ZIP build",
        [sys.executable, str(build_checkout / "packaging" / "build_allinone.py")],
        evidence / "build-allinone.log" if evidence else None,
        timeout=command_timeout, cwd=build_checkout,
    )
    require(allinone_stage.is_dir(), "all-in-one builder did not use the isolated stage")
    info = {kind: _archive_info(path) for kind, path in archive_paths.items()}
    return info, archive_paths


def _extract_archives(run_root: Path, archive_paths: dict[str, Path]) -> dict[str, Path]:
    apps = {}
    for kind, archive_path in archive_paths.items():
        destination = run_root / kind
        destination.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(destination)
        app = (destination / "ScanOps").resolve()
        require(app.is_dir(), f"{kind} archive has no ScanOps root")
        apps[kind] = app

    expected_dist = _tree_digest(ROOT / "frontend" / "dist")
    for kind, app in apps.items():
        actual = _tree_digest(app / "frontend" / "dist")
        require(actual == expected_dist, f"{kind} archive frontend does not match current dist")
    return apps


def _install_regular(app: Path, evidence: Path | None, command_timeout: int) -> Path:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    require(bool(powershell), "PowerShell is required for the regular artifact installer")
    _run_logged(
        "regular offline install",
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(app / "packaging" / "install.ps1")],
        evidence / "regular-install.log" if evidence else None,
        timeout=command_timeout, cwd=app,
    )
    python = app / "backend" / ".venv" / "Scripts" / "python.exe"
    require(python.is_file(), "regular artifact installer did not create its venv")
    return python


def _verify_imports(kind: str, python: Path, app: Path, evidence: Path | None,
                    command_timeout: int) -> None:
    command = [str(python)]
    if kind == "allinone":
        command.extend(["-E", "-s"])
    command.extend([
        "-c",
        "import fastapi,uvicorn,sqlalchemy,pydantic,pydantic_settings,multipart,openpyxl,"
        "scanops_engine; print(fastapi.__version__, sqlalchemy.__version__, "
        "pydantic.__version__, openpyxl.__version__, scanops_engine.__file__)",
    ])
    env = dict(os.environ)
    env.pop("PYTHONHOME", None)
    env["PYTHONUTF8"] = "1"
    if kind == "regular":
        env["PYTHONPATH"] = str(app / "engine")
    else:
        env.pop("PYTHONPATH", None)
    _run_logged(
        f"{kind} isolated imports", command,
        evidence / f"{kind}-imports.log" if evidence else None,
        timeout=command_timeout, cwd=app / "backend", env=env,
    )


def _start_server(kind: str, app: Path, data_dir: Path, api_port: int,
                  server_log: Path) -> tuple[subprocess.Popen, object]:
    env = dict(os.environ)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    for name in (
        "SCANOPS_HOST", "SCANOPS_PORT", "SCANOPS_NMAP_PATH",
        "SCANOPS_ENGINE_DIR", "SCANOPS_FRONTEND_DIST",
    ):
        env.pop(name, None)
    env.update({
        "PYTHONUTF8": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SCANOPS_DATA_DIR": str(data_dir),
        "SCANOPS_SCAN_SCOPE": f"{HOST}/32",
    })
    comspec = os.environ.get("COMSPEC") or shutil.which("cmd.exe")
    require(bool(comspec), "cmd.exe is required to exercise the shipped START.bat")
    launcher = app / "START.bat"
    require(launcher.is_file(), f"{kind} artifact START.bat is missing")
    command = [comspec, "/d", "/c", str(launcher)]
    log_handle = server_log.open("wb")
    process = popen_tracked(
        command, cwd=app, env=env, stdin=subprocess.DEVNULL,
        stdout=log_handle, stderr=subprocess.STDOUT,
    )
    log(f"{kind} artifact server pid={process.pid} url=http://{HOST}:{api_port}")
    return process, log_handle


def _copy_scan_evidence(kind: str, data_dir: Path, scan_id: int,
                        evidence: Path | None, *, required: bool) -> None:
    scan_dir = data_dir / "scans" / f"scan_{scan_id}"
    missing = []
    for name in ("spec.json", "events.ndjson", "run-state.json"):
        source = scan_dir / name
        if not source.is_file():
            missing.append(name)
            continue
        if evidence is not None:
            shutil.copy2(source, evidence / f"{kind}-{name}")
    if required:
        require(not missing, f"{kind} engine did not create {', '.join(missing)}")


def _smoke_artifact(kind: str, app: Path, run_root: Path,
                    scan_timeout: int, evidence: Path | None) -> dict:
    data_dir = run_root / f"{kind}-data"
    data_dir.mkdir()
    api_port = 8770
    require(_port_is_bindable(api_port, socket.SOCK_STREAM),
            f"default launcher port {api_port} is unavailable")
    server_log = run_root / f"{kind}-server.log"
    process: subprocess.Popen | None = None
    log_handle = None
    scan_id: int | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    result: dict = {}
    try:
        process, log_handle = _start_server(kind, app, data_dir, api_port, server_log)
        api = ApiClient(f"http://{HOST}:{api_port}")
        _wait_for_health(api, process, server_log)
        index = api.request("GET", "/")
        require(isinstance(index, bytes) and b'id="root"' in index,
                f"{kind} launcher did not serve its packaged frontend")
        token = _login(api, "admin", _initial_admin_password(data_dir))
        started = api.request(
            "POST", "/api/scans/run-staged", token=token,
            payload={
                "name": f"{kind} package runtime smoke",
                "targets": [HOST],
                "ports": f"T:{api_port}",
                "options": ["fast", "version_light"],
                "nse": ["http-headers", "http-server-header"],
                "batch_size": 1,
                "discovery": "pn",
            },
        )
        scan_id = int(started["id"])
        stages = _wait_scan(api, token, scan_id, scan_timeout, server_log)
        _copy_scan_evidence(kind, data_dir, scan_id, evidence, required=True)
        stage_status = {stage["stage"]: stage["status"] for stage in stages["stages"]}
        require(all(stage_status.get(name) == "done" for name in ("discovery", "tcp", "service")),
                f"{kind} staged engine did not finish all stages: {stage_status}")

        rows = api.request("GET", f"/api/findings?host={HOST}&state=", token=token)
        matches = [row for row in rows if int(row["port"]) == api_port and row["proto"] == "tcp"]
        observed = [(row.get("port"), row.get("proto"), row.get("service")) for row in rows]
        require(len(matches) == 1,
                f"{kind} artifact did not ingest its own server finding; rows={observed}")
        finding = matches[0]
        server = str(finding.get("server") or "")
        require("uvicorn" in server.lower(), f"{kind} Server header was not captured: {server!r}")
        require(finding.get("display_identity") == server,
                f"{kind} display_identity did not prefer Server: {finding}")

        result = {
            "server_pid": process.pid,
            "launcher": "START.bat",
            "default_paths": True,
            "api_port": api_port,
            "health": "ready",
            "scan_id": scan_id,
            "scan_status": stages["status"],
            "stages": stage_status,
            "service": finding.get("service"),
            "product": finding.get("product"),
            "server": server,
            "display_identity": finding.get("display_identity"),
            "engine_artifacts": ["spec.json", "events.ndjson", "run-state.json"],
        }
    except BaseException as exc:
        primary_error = exc
    finally:
        _capture_cleanup_error(
            cleanup_errors, f"{kind} process tree stop",
            lambda: _stop_process_tree(process),
        )
        if log_handle is not None:
            _capture_cleanup_error(cleanup_errors, f"{kind} server log close", log_handle.close)
        if evidence is not None and server_log.exists():
            _capture_cleanup_error(
                cleanup_errors, f"{kind} server log copy",
                lambda: shutil.copy2(server_log, evidence / f"{kind}-server.log"),
            )
        if scan_id is not None:
            _capture_cleanup_error(
                cleanup_errors, f"{kind} failed scan artifact copy",
                lambda: _copy_scan_evidence(
                    kind, data_dir, scan_id, evidence, required=False,
                ),
            )
        try:
            if not _port_is_bindable(api_port, socket.SOCK_STREAM):
                cleanup_errors.append(f"{kind} API port remains bound: {api_port}")
        except Exception as exc:
            cleanup_errors.append(f"{kind} API port verification: {exc}")
    if cleanup_errors:
        cleanup_message = "; ".join(cleanup_errors)
        if primary_error is None:
            primary_error = RuntimeE2EError(f"cleanup failures: {cleanup_message}")
        else:
            primary_error = RuntimeE2EError(
                f"{primary_error}; cleanup failures: {cleanup_message}"
            )
    if primary_error is not None:
        raise RuntimeE2EError(f"{kind} artifact smoke failed: {primary_error}\n{_tail(server_log)}") from primary_error
    return result


def _path_fingerprint(path: Path) -> dict:
    if not path.exists():
        return {"type": "missing"}
    if path.is_file():
        return {"type": "file", "bytes": path.stat().st_size, "sha256": _sha256(path)}
    return {"type": "directory", "sha256": _tree_digest(path)}


def run(args: argparse.Namespace, report: dict) -> None:
    evidence = Path(args.artifacts_dir).resolve() if args.artifacts_dir else None
    if evidence is not None:
        evidence.mkdir(parents=True, exist_ok=True)
    nmap_path = _find_nmap(args.nmap)
    report["nmap"] = nmap_path
    fixed_paths = {
        **{kind: ROOT.parent / name for kind, name in ARCHIVE_NAMES.items()},
        "allinone_stage": ROOT.parent / "_allinone_stage",
    }
    fixed_before = {kind: _path_fingerprint(path) for kind, path in fixed_paths.items()}
    temp = tempfile.TemporaryDirectory(prefix="scanops_package_runtime_")
    run_root = Path(temp.name).resolve()
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        archives, archive_paths = _build_archives(
            run_root, evidence, args.command_timeout,
        )
        report["archives"] = archives
        apps = _extract_archives(run_root, archive_paths)
        regular_python = _install_regular(
            apps["regular"], evidence, args.command_timeout,
        )
        allinone_python = apps["allinone"] / "runtime" / "python" / "python.exe"
        require(allinone_python.is_file(), "all-in-one embedded Python is missing")
        _verify_imports(
            "regular", regular_python, apps["regular"], evidence,
            args.command_timeout,
        )
        _verify_imports(
            "allinone", allinone_python, apps["allinone"], evidence,
            args.command_timeout,
        )
        report["regular"] = _smoke_artifact(
            "regular", apps["regular"], run_root, args.scan_timeout, evidence,
        )
        report["allinone"] = _smoke_artifact(
            "allinone", apps["allinone"], run_root, args.scan_timeout, evidence,
        )
        report["ok"] = True
    except BaseException as exc:
        primary_error = exc
        report["ok"] = False
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        _capture_cleanup_error(
            cleanup_errors, "isolated package workspace cleanup", temp.cleanup,
        )
        if run_root.exists():
            cleanup_errors.append(f"isolated package workspace remains: {run_root}")
        fixed_after = {kind: _path_fingerprint(path) for kind, path in fixed_paths.items()}
        fixed_untouched = fixed_before == fixed_after
        if not fixed_untouched:
            cleanup_errors.append("pre-existing sibling package outputs changed")
        report["cleanup"] = {
            "isolated_workspace_removed": not run_root.exists(),
            "fixed_sibling_outputs_untouched": fixed_untouched,
            "errors": cleanup_errors,
        }
        _write_report(evidence, report)

    if cleanup_errors:
        message = "; ".join(cleanup_errors)
        if primary_error is not None:
            raise RuntimeE2EError(f"{primary_error}; cleanup failures: {message}") from primary_error
        raise RuntimeE2EError(f"cleanup failures: {message}")
    if primary_error is not None:
        raise primary_error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nmap", default="", help="explicit nmap executable path")
    parser.add_argument("--scan-timeout", type=int, default=240,
                        help="seconds allowed for each real artifact scan")
    parser.add_argument("--command-timeout", type=int, default=900,
                        help="seconds allowed for each build/install/import subprocess")
    parser.add_argument("--artifacts-dir", default="", help="optional persistent evidence directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report: dict = {"ok": False, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    try:
        run(args, report)
    except Exception as exc:
        report.setdefault("error", f"{type(exc).__name__}: {exc}")
        report["ok"] = False
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        _write_report(Path(args.artifacts_dir).resolve() if args.artifacts_dir else None, report)
        print(f"PACKAGE RUNTIME SMOKE FAILED: {exc}", file=sys.stderr, flush=True)
        return 1
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    _write_report(Path(args.artifacts_dir).resolve() if args.artifacts_dir else None, report)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
