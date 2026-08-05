"""Vendored engine and offline package contract regressions."""
from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENGINE_ROOT = ROOT / "engine"
SCRIPTS_ROOT = ROOT / "scripts"
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from scanops_engine import cli, nmaprun, process_control  # noqa: E402
from scanops_engine.pipeline import Pipeline  # noqa: E402
from scanops_engine.spec import (  # noqa: E402
    DISCOVERY_PA,
    DISCOVERY_PS,
    JobSpec,
)
from scanops_engine.state import RunState  # noqa: E402
from scanops.api import scans as scans_api  # noqa: E402
from scanops.db import SessionLocal  # noqa: E402
from scanops.models import ScanRun  # noqa: E402
from scanops.scanning import engine_runner, nmap_runner  # noqa: E402
from tests.conftest import make_user, token_for  # noqa: E402
import package_runtime_smoke  # noqa: E402
import runtime_e2e  # noqa: E402


class _Sink:
    def __init__(self):
        self.events = []

    def emit(self, event, **data):
        self.events.append({"event": event, **data})


def test_engine_stop_sentinel_survives_stale_progress_save_until_resume(tmp_path):
    state_path = tmp_path / "run-state.json"
    initial = RunState(state_path)
    initial.save()
    stale_engine_state = RunState(state_path)

    engine_runner.signal_stop(tmp_path)
    stale_engine_state.mark_done("discovery")
    stale_engine_state.set("stop", False)
    stale_engine_state.save()

    assert engine_runner.stopped(tmp_path) is True
    assert RunState(state_path).stopped() is True
    assert json.loads(state_path.read_text(encoding="utf-8"))["stop"] is True

    engine_runner.clear_stop(tmp_path)
    assert engine_runner.stopped(tmp_path) is False
    assert RunState(state_path).stopped() is False


def test_nmap_stop_poll_does_not_wait_for_stdout(monkeypatch, tmp_path):
    released = threading.Event()
    terminated = []

    class SilentStream:
        def __iter__(self):
            released.wait(timeout=2)
            return
            yield  # pragma: no cover - keeps this method an iterator

        def close(self):
            released.set()

    class SilentProcess:
        pid = 12345

        def __init__(self):
            self.stdout = SilentStream()
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is None:
                released.wait(timeout=timeout)
            return self.returncode

        def kill(self):
            self.returncode = -15
            released.set()

    process = SilentProcess()
    monkeypatch.setattr(nmaprun, "popen_owned", lambda *args, **kwargs: process)
    monkeypatch.setattr(nmaprun, "close_kill_job", lambda proc: False)

    def terminate(proc):
        terminated.append(proc.pid)
        proc.kill()

    monkeypatch.setattr(nmaprun, "terminate_owned", terminate)
    polls = 0

    def stopped():
        nonlocal polls
        polls += 1
        return polls >= 2

    started = time.monotonic()
    result = nmaprun.run(
        "nmap", [], tmp_path / "silent", stop_requested=stopped, poll_interval=0.01,
    )

    assert time.monotonic() - started < 0.5
    assert result["stopped"] is True and result["rc"] == -15
    assert terminated == [process.pid]


def test_nmap_normal_progress_still_streams(monkeypatch, tmp_path):
    class ProgressProcess:
        pid = 23456
        stdout = io.StringIO("Stats: About 42.50% done; ETC: soon\n")

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(timeout=None):
            return 0

    monkeypatch.setattr(nmaprun, "popen_owned", lambda *args, **kwargs: ProgressProcess())
    monkeypatch.setattr(nmaprun, "close_kill_job", lambda proc: False)
    progress = []

    result = nmaprun.run("nmap", [], tmp_path / "progress", progress=progress.append)

    assert result["stopped"] is False and result["rc"] == 0
    assert progress == [42.5]
    assert "About 42.50% done" in (tmp_path / "progress.stdout.log").read_text(
        encoding="utf-8",
    )


@pytest.mark.parametrize("stopped_rc", [0, -15])
def test_pipeline_stop_result_is_stopped_without_error(monkeypatch, tmp_path, stopped_rc):
    spec = JobSpec.from_dict({
        "targets": ["127.0.0.1"],
        "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": False}, "service": {"enabled": False}},
    })
    sink = _Sink()

    def stopped_run(nmap, args, out_base, **kwargs):
        assert callable(kwargs["stop_requested"])
        (tmp_path / "stop-requested").touch()
        return {
            "rc": stopped_rc, "seconds": 0.02, "cmd": [nmap, *args], "stopped": True,
        }

    monkeypatch.setattr(nmaprun, "run", stopped_run)

    counts = Pipeline(spec, sink, "nmap").run()

    assert counts["errors"] == 0
    assert not any(event["event"] == "error" for event in sink.events)
    stopped_stage = next(event for event in sink.events if event["event"] == "stage_done")
    assert stopped_stage["counts"] == {"stopped": True}
    done = next(event for event in sink.events if event["event"] == "job_done")
    assert done["status"] == "stopped"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object ownership contract")
def test_engine_owned_job_stop_kills_descendant_but_not_unrelated_process(tmp_path):
    child_pid_path = tmp_path / "engine-child.pid"
    child_code = "import time; time.sleep(30)"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid)); "
        "time.sleep(30)"
    )
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    parent = process_control.popen_owned([sys.executable, "-c", parent_code])
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = int(child_pid_path.read_text())
        assert runtime_e2e._pid_is_running(child_pid) is True
        assert unrelated.poll() is None

        process_control.terminate_owned(parent)

        assert runtime_e2e._pid_is_running(child_pid) is False
        assert unrelated.poll() is None
        assert "taskkill" not in (ENGINE_ROOT / "scanops_engine" / "process_control.py").read_text(
            encoding="utf-8",
        ).lower()
    finally:
        if parent.poll() is None:
            process_control.terminate_owned(parent)
        if child_pid and runtime_e2e._pid_is_running(child_pid):
            subprocess.run(
                ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                capture_output=True, check=False,
            )
        if unrelated.poll() is None:
            unrelated.terminate()
            try:
                unrelated.wait(timeout=3)
            except subprocess.TimeoutExpired:
                unrelated.kill()
                unrelated.wait(timeout=3)


def test_backend_owner_exit_cleans_nested_engine_tree_but_not_unrelated(tmp_path):
    engine_pid_path = tmp_path / "owned-engine.pid"
    child_pid_path = tmp_path / "owned-nmap.pid"
    child_code = "import time; time.sleep(30)"
    engine_code = "\n".join([
        "import pathlib, sys, time",
        "from scanops_engine import process_control",
        "process_control.start_parent_guard()",
        f"child = process_control.popen_owned([sys.executable, '-c', {child_code!r}])",
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid))",
        "time.sleep(30)",
    ])
    owner_code = "\n".join([
        "import os, pathlib, sys, time",
        "from scanops.scanning import process_control",
        "env = dict(os.environ)",
        f"env['PYTHONPATH'] = {str(ENGINE_ROOT)!r} + os.pathsep + env.get('PYTHONPATH', '')",
        (
            "engine = process_control.popen_owned("
            f"[sys.executable, '-c', {engine_code!r}], env=env, child_guards_parent=True)"
        ),
        f"pathlib.Path({str(engine_pid_path)!r}).write_text(str(engine.pid))",
        "deadline = time.monotonic() + 5",
        f"while not pathlib.Path({str(child_pid_path)!r}).exists() and time.monotonic() < deadline:",
        "    time.sleep(0.02)",
        "os._exit(0)",
    ])
    unrelated = subprocess.Popen([sys.executable, "-c", child_code])
    owner = subprocess.Popen(
        [sys.executable, "-c", owner_code], cwd=str(ROOT / "backend"),
    )
    owned_pids = []
    try:
        owner.wait(timeout=10)
        owned_pids = [int(engine_pid_path.read_text()), int(child_pid_path.read_text())]
        deadline = time.monotonic() + 5
        while any(runtime_e2e._pid_is_running(pid) for pid in owned_pids) and time.monotonic() < deadline:
            time.sleep(0.05)

        assert all(runtime_e2e._pid_is_running(pid) is False for pid in owned_pids)
        assert unrelated.poll() is None
    finally:
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=3)
        for pid in owned_pids:
            if runtime_e2e._pid_is_running(pid):
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/PID", str(pid), "/T", "/F"],
                        capture_output=True, check=False,
                    )
                else:
                    os.kill(pid, signal.SIGKILL)
        if unrelated.poll() is None:
            unrelated.terminate()
            try:
                unrelated.wait(timeout=3)
            except subprocess.TimeoutExpired:
                unrelated.kill()
                unrelated.wait(timeout=3)


@pytest.mark.parametrize("_attempt", range(3))
def test_backend_owner_exit_cleans_direct_nmap_process(tmp_path, _attempt):
    child_pid_path = tmp_path / "direct-nmap.pid"
    log_path = tmp_path / "direct-nmap.log"
    child_code = "import time; time.sleep(30)"
    owner_code = "\n".join([
        "import os, pathlib, sys",
        "from scanops.scanning import nmap_runner",
        (
            "process = nmap_runner.popen("
            f"[sys.executable, '-c', {child_code!r}], pathlib.Path({str(log_path)!r}))"
        ),
        (
            f"pathlib.Path({str(child_pid_path)!r}).write_text("
            "str(getattr(process, '_scanops_guard_child_pgid', process.pid)))"
        ),
        "os._exit(0)",
    ])
    unrelated = subprocess.Popen([sys.executable, "-c", child_code])
    owner = subprocess.Popen(
        [sys.executable, "-c", owner_code], cwd=str(ROOT / "backend"),
    )
    child_pid = None
    try:
        owner.wait(timeout=10)
        child_pid = int(child_pid_path.read_text())
        deadline = time.monotonic() + 5
        while runtime_e2e._pid_is_running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)

        assert runtime_e2e._pid_is_running(child_pid) is False
        assert unrelated.poll() is None
    finally:
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=3)
        if child_pid and runtime_e2e._pid_is_running(child_pid):
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                    capture_output=True, check=False,
                )
            else:
                os.kill(child_pid, signal.SIGKILL)
        if unrelated.poll() is None:
            unrelated.terminate()
            try:
                unrelated.wait(timeout=3)
            except subprocess.TimeoutExpired:
                unrelated.kill()
                unrelated.wait(timeout=3)


@pytest.mark.skipif(os.name == "nt", reason="POSIX startup-handshake contract")
def test_posix_guard_cleans_child_when_handshake_reader_disappears(tmp_path):
    backend_control = nmap_runner.process_control
    child_pid_path = tmp_path / "handshake-child.pid"
    child_code = (
        "import os,pathlib,time; "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(os.getpid())); "
        "time.sleep(30)"
    )
    owner_read_fd, owner_write_fd = os.pipe()
    status_read_fd, status_write_fd = os.pipe()
    os.set_blocking(status_write_fd, False)
    try:
        while True:
            os.write(status_write_fd, b"x" * 4096)
    except BlockingIOError:
        pass
    os.set_blocking(status_write_fd, True)
    guard = subprocess.Popen(
        [
            sys.executable,
            str(Path(backend_control.__file__).resolve()),
            backend_control._POSIX_GUARD_ARG,
            str(owner_read_fd),
            str(status_write_fd),
            "",
            sys.executable,
            "-c",
            child_code,
        ],
        pass_fds=(owner_read_fd, status_write_fd),
        start_new_session=True,
    )
    os.close(owner_read_fd)
    owner_read_fd = -1
    os.close(status_write_fd)
    status_write_fd = -1
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = int(child_pid_path.read_text())
        os.close(status_read_fd)
        status_read_fd = -1
        guard.wait(timeout=10)
        deadline = time.monotonic() + 5
        while runtime_e2e._pid_is_running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert runtime_e2e._pid_is_running(child_pid) is False
    finally:
        for fd in (owner_read_fd, owner_write_fd, status_read_fd, status_write_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if guard.poll() is None:
            os.killpg(guard.pid, signal.SIGKILL)
            guard.wait(timeout=3)
        if child_pid and runtime_e2e._pid_is_running(child_pid):
            os.killpg(child_pid, signal.SIGKILL)


def test_direct_nmap_wait_cleans_descendant_after_leader_exit(tmp_path):
    descendant_pid_path = tmp_path / "direct-descendant.pid"
    log_path = tmp_path / "direct-descendant.log"
    descendant_code = "import time; time.sleep(30)"
    leader_code = (
        "import pathlib,subprocess,sys; "
        f"child=subprocess.Popen([sys.executable,'-c',{descendant_code!r}]); "
        f"pathlib.Path({str(descendant_pid_path)!r}).write_text(str(child.pid))"
    )
    process = nmap_runner.popen([sys.executable, "-c", leader_code], log_path)
    descendant_pid = None
    try:
        assert nmap_runner.wait_owned(process) == 0
        descendant_pid = int(descendant_pid_path.read_text())
        deadline = time.monotonic() + 5
        while runtime_e2e._pid_is_running(descendant_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert runtime_e2e._pid_is_running(descendant_pid) is False
    finally:
        if descendant_pid and runtime_e2e._pid_is_running(descendant_pid):
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(descendant_pid), "/T", "/F"],
                    capture_output=True, check=False,
                )
            else:
                os.kill(descendant_pid, signal.SIGKILL)


def test_engine_runner_spawn_uses_owned_tree_and_closes_parent_log(monkeypatch, tmp_path):
    out_dir = tmp_path / "engine-out"
    out_dir.mkdir()
    spec_path = out_dir / "spec.json"
    spec_path.write_text("{}", encoding="utf-8")
    log_path = out_dir / "engine.log"
    process = object()
    captured = {}
    monkeypatch.setattr(engine_runner._settings, "engine_dir", ENGINE_ROOT)

    def owned_spawn(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["log"] = kwargs["stdout"]
        captured["child_guards_parent"] = kwargs["child_guards_parent"]
        assert captured["log"].closed is False
        return process

    monkeypatch.setattr(engine_runner.process_control, "popen_owned", owned_spawn)

    assert engine_runner.spawn(spec_path, out_dir, log_path) is process
    assert captured["cmd"][1:3] == ["-m", "scanops_engine"]
    assert captured["child_guards_parent"] is True
    assert captured["log"].closed is True


@pytest.mark.parametrize("payload", [
    {"targets": ["-oX/tmp/engine.xml"]},
    {"targets": ["127.0.0.1"], "exclude": ["-iR10"]},
    {"targets_ports": {"-oN/tmp/rescan.log": [80]}},
    {"rescan_units": [{"ip": "-oG/tmp/rescan.gnmap", "port": 80, "proto": "tcp"}]},
])
def test_job_spec_rejects_leading_dash_in_every_target_shape(payload):
    with pytest.raises(ValueError, match="타겟|재스캔|제외"):
        JobSpec.from_dict(payload).validate()


@pytest.mark.parametrize("payload", [
    {"targets": ["2001:db8::1"]},
    {"targets": ["127.0.0.1"], "exclude": ["2001:db8::2"]},
    {"targets_ports": {"2001:db8::3": [80]}},
    {"rescan_units": [{"ip": "2001:db8::4", "port": 80, "proto": "tcp"}]},
])
def test_job_spec_rejects_ipv6_in_every_target_shape(payload):
    with pytest.raises(ValueError, match="IPv6"):
        JobSpec.from_dict(payload).validate()


@pytest.mark.parametrize("ports", ["99999", "443-22", "22,,80", "T:", "0"])
def test_job_spec_rejects_invalid_port_semantics(ports):
    with pytest.raises(ValueError, match="포트"):
        JobSpec.from_dict({
            "targets": ["127.0.0.1"],
            "stages": {"tcp": {"ports": ports}},
        }).validate()


@pytest.mark.parametrize("stage", ["tcp", "udp"])
def test_job_spec_rejects_enabled_protocol_with_empty_ports(stage):
    with pytest.raises(ValueError, match=f"{stage.upper()}.*포트.*비어"):
        JobSpec.from_dict({
            "targets": ["127.0.0.1"],
            "stages": {stage: {"enabled": True, "ports": ""}},
        }).validate()


@pytest.mark.parametrize("exclude", [
    [""],
    ["   "],
    ["scanner.internal"],
    ["2001:db8::1"],
    ["10.0.0.0/33"],
    ["10.0.0.1-10"],
    ["10.0.0.1,10.0.0.2"],
    [None],
])
def test_job_spec_rejects_non_ipv4_ip_or_cidr_exclude(exclude):
    with pytest.raises(ValueError, match="제외|IPv6"):
        JobSpec.from_dict({
            "targets": ["127.0.0.1"],
            "exclude": exclude,
        }).validate()


def test_job_spec_accepts_ipv4_ip_and_cidr_exclude():
    spec = JobSpec.from_dict({
        "targets": ["127.0.0.1"],
        "exclude": ["127.0.0.2", "10.0.0.7/24"],
    }).validate()
    assert spec.exclude == ["127.0.0.2", "10.0.0.7/24"]


@pytest.mark.parametrize("stage", ["discovery", "service"])
def test_job_spec_rejects_invalid_discovery_or_service_timing(stage):
    with pytest.raises(ValueError, match="타이밍"):
        JobSpec.from_dict({
            "targets": ["127.0.0.1"],
            "stages": {stage: {"timing": "-T9"}},
        }).validate()


@pytest.mark.parametrize("scan_type", ["", "udp", "-sS", "SYN", None])
def test_job_spec_rejects_unknown_tcp_scan_type(scan_type):
    with pytest.raises(ValueError, match=r"tcp\.scan_type"):
        JobSpec.from_dict({
            "targets": ["127.0.0.1"],
            "stages": {"tcp": {"scan_type": scan_type}},
        }).validate()


def test_rescan_units_only_spec_reaches_pipeline(monkeypatch, tmp_path):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({
        "out_dir": str(tmp_path / "out"),
        "rescan_units": [{"ip": "127.0.0.1", "port": 65530, "proto": "tcp"}],
    }), encoding="utf-8")
    called = []
    monkeypatch.setattr(cli.nmaprun, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(cli.Pipeline, "run", lambda self: called.append(True) or {"errors": 0})

    assert cli.main(["--spec", str(spec_path), "--no-stdout"]) == 0
    assert called == [True]


@pytest.mark.parametrize(
    "units",
    [
        [{"ip": "127.0.0.1", "port": 18080, "proto": "tcp"}],
        [{"ip": "127.0.0.1", "port": 18161, "proto": "udp"}],
        [
            {"ip": "127.0.0.1", "port": 18080, "proto": "tcp"},
            {"ip": "127.0.0.2", "port": 18161, "proto": "udp"},
        ],
    ],
)
def test_rescan_units_cli_runs_real_pipeline_without_cross_product(monkeypatch, tmp_path, units):
    """Exercise the CLI and Pipeline; only the external Nmap process is replaced."""
    spec_path = tmp_path / "spec.json"
    out_dir = tmp_path / "out"
    spec_path.write_text(json.dumps({
        "out_dir": str(out_dir),
        "rescan_units": units,
        "stages": {"service": {"confirm": False}},
    }), encoding="utf-8")
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        proto = "udp" if "-sU" in args else "tcp"
        raw_port = args[args.index("-p") + 1]
        port = int(raw_port.rsplit(":", 1)[-1])
        ip = args[-1]
        calls.append((ip, port, proto))
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            f'<port protocol="{proto}" portid="{port}"><state state="open"/>'
            '<service name="test" method="probed"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(cli.nmaprun, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(nmaprun, "run", fake_run)

    assert cli.main(["--spec", str(spec_path), "--no-stdout"]) == 0
    assert calls == [(u["ip"], u["port"], u["proto"]) for u in units]
    state = json.loads((out_dir / "run-state.json").read_text(encoding="utf-8"))
    assert "job" in state["stages_done"]


def test_cli_rejects_empty_target_spec(monkeypatch, tmp_path, capsys):
    spec_path = tmp_path / "empty.json"
    spec_path.write_text(json.dumps({"out_dir": str(tmp_path / "out")}), encoding="utf-8")
    monkeypatch.setattr(cli.nmaprun, "find_nmap", lambda explicit="": "nmap")

    assert cli.main(["--spec", str(spec_path), "--no-stdout"]) == 2
    assert "타겟이 없습니다" in capsys.readouterr().err


def test_nmap_failure_makes_cli_nonzero_and_never_marks_job_done(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({
        "out_dir": str(out_dir),
        "rescan_units": [{"ip": "127.0.0.1", "port": 18443, "proto": "tcp"}],
    }), encoding="utf-8")
    monkeypatch.setattr(cli.nmaprun, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(
        nmaprun, "run",
        lambda nmap, args, out_base, **kwargs: {
            "rc": 7, "seconds": 0.01, "cmd": [nmap, *args, "-oA", str(out_base)],
        },
    )

    assert cli.main(["--spec", str(spec_path), "--no-stdout"]) == 1
    state_path = out_dir / "run-state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert "job" not in state["stages_done"]
    events = [json.loads(line) for line in (out_dir / "events.ndjson").read_text(
        encoding="utf-8",
    ).splitlines()]
    assert any(event["event"] == "error" for event in events)
    done = next(event for event in events if event["event"] == "job_done")
    assert done["status"] == "failed" and done["counts"]["errors"] == 1


def test_pn_discovery_reports_final_live_count(tmp_path):
    spec = JobSpec.from_dict({
        "targets": ["127.0.0.1"],
        "out_dir": str(tmp_path),
        "stages": {"discovery": {"mode": "pn"}, "tcp": {"enabled": False},
                   "service": {"enabled": False}},
    })
    sink = _Sink()
    counts = Pipeline(spec, sink, "nmap").run()
    assert counts["live"] == 1
    assert next(e for e in sink.events if e["event"] == "job_done")["counts"]["live"] == 1


@pytest.mark.parametrize(
    ("cached_live", "targets", "expected_live"),
    [
        (None, ["127.0.0.1"], 1),
        (["127.0.0.1", "127.0.0.2"], ["127.0.0.0/30"], 2),
    ],
    ids=["fresh-pn", "cached-resume"],
)
def test_zero_open_live_count_agrees_across_engine_ingest_and_stages_api(
    client, monkeypatch, tmp_path, cached_live, targets, expected_live,
):
    """A live host with no finding rows must not collapse the persisted host count to zero."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    make_user("live-count-auditor", "password12", role="auditor")
    headers = {
        "Authorization": f"Bearer {token_for(client, 'live-count-auditor', 'password12')}"
    }

    db = SessionLocal()
    try:
        scan = ScanRun(
            name=f"zero-open-{'resume' if cached_live else 'fresh'}",
            command="단계스캔(엔진) · 발견 pn",
            status="done",
        )
        db.add(scan)
        db.commit()
        out_dir = scans_api._settings.scans_dir / f"scan_{scan.id}"
        out_dir.mkdir(parents=True)
        if cached_live is not None:
            (out_dir / "run-state.json").write_text(json.dumps({
                "stages_done": ["discovery"],
                "open_map": {},
                "live": cached_live,
                "service_done": [],
                "stop": False,
            }), encoding="utf-8")

        spec_dict = {
            "job_id": f"scan_{scan.id}",
            "targets": targets,
            "out_dir": str(out_dir),
            "stages": {
                "discovery": {"mode": "sn" if cached_live is not None else "pn"},
                "tcp": {"enabled": False},
                "service": {"enabled": False},
            },
        }
        (out_dir / "spec.json").write_text(json.dumps(spec_dict), encoding="utf-8")
        sink = _Sink()
        counts = Pipeline(JobSpec.from_dict(spec_dict), sink, "nmap").run()
        (out_dir / "events.ndjson").write_text(
            "\n".join(json.dumps(event) for event in sink.events) + "\n",
            encoding="utf-8",
        )

        assert counts["live"] == expected_live
        assert counts["open_tcp"] == counts["open_udp"] == counts["services"] == 0
        engine_runner.ingest_results(db, scan, out_dir)
        assert scan.host_count == expected_live
        assert scan.port_count == 0
        scan_id = scan.id
    finally:
        db.close()

    response = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == payload["overall"]["status"] == "done"
    assert payload["overall"]["counts"]["live"] == payload["host_count"] == expected_live
    discovery = next(stage for stage in payload["stages"] if stage["stage"] == "discovery")
    assert discovery["counts"]["live"] == expected_live


def test_default_discovery_and_tcp_sweep_argv_match_standalone_policy(
    monkeypatch, tmp_path,
):
    target = "127.0.0.1"
    excluded = ["127.0.0.2", "127.0.0.3"]
    spec = JobSpec.from_dict({
        "targets": [target],
        "exclude": excluded,
        "out_dir": str(tmp_path),
        "stages": {"service": {"enabled": False}},
    }).validate()
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        calls.append(list(args))
        if "-sn" in args:
            xml = (
                '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                f'<address addr="{target}" addrtype="ipv4"/></host></nmaprun>'
            )
        else:
            xml = "<nmaprun/>"
        Path(f"{out_base}.xml").write_text(xml, encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    counts = Pipeline(spec, _Sink(), "nmap").run()

    assert counts["errors"] == 0
    assert calls == [
        ["-sn", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", "-T4", "--reason",
         "--min-hostgroup", "64", "--max-retries", "2",
         "--max-parallelism", "100",
         "--exclude", ",".join(excluded), target],
        ["-sS", "-Pn", "-n", "--open", "-T4", "--reason",
         "--max-retries", "2", "--min-hostgroup", "64",
         "--defeat-rst-ratelimit", "--max-parallelism", "100",
         "-p", "1-65535", "--exclude", ",".join(excluded), target],
    ]
    assert all(args.count("--exclude") == 1 for args in calls)


@pytest.mark.skipif(sys.platform != "win32", reason="Npcap-backed loopback contract")
def test_real_nmap_multi_exclude_omits_every_excluded_loopback(tmp_path):
    nmap = nmaprun.find_nmap()
    if not nmap:
        pytest.skip("Nmap is not installed")
    spec = JobSpec.from_dict({
        "targets": ["127.0.0.1-3"],
        "exclude": ["127.0.0.2", "127.0.0.3"],
        "out_dir": str(tmp_path),
        "sudo": "never",
        "stages": {
            "tcp": {"enabled": False},
            "service": {"enabled": False},
        },
    }).validate()

    counts = Pipeline(spec, _Sink(), nmap).run()

    assert counts["errors"] == 0 and counts["live"] == 1
    assert nmaprun.hosts_up(tmp_path / "stage0-discovery.xml") == ["127.0.0.1"]


def test_pn_udp_sweep_argv_keeps_exclude_and_standalone_defaults(monkeypatch, tmp_path):
    target = "127.0.0.0/30"
    excluded = "127.0.0.2"
    spec = JobSpec.from_dict({
        "targets": [target],
        "exclude": [excluded],
        "out_dir": str(tmp_path),
        "stages": {
            "discovery": {"mode": "pn"},
            "tcp": {"enabled": False},
            "udp": {"enabled": True},
            "service": {"enabled": False},
        },
    }).validate()
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        calls.append(list(args))
        Path(f"{out_base}.xml").write_text("<nmaprun/>", encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    counts = Pipeline(spec, _Sink(), "nmap").run()

    assert counts["errors"] == 0
    assert calls == [[
        "-sU", "-Pn", "-n", "--open", "-T4", "--reason",
        "--max-retries", "2", "-p",
        "7,53,67,68,69,88,111,123,135,137,138,139,161,162,389,400,500,"
        "514,520,623,1900,2049,4500,5060,5353,5355,11211",
        "--exclude", excluded, target,
    ]]
    assert "-sS" not in calls[0] and "-sT" not in calls[0]


def test_custom_timing_is_used_by_discovery_sweeps_and_service(monkeypatch, tmp_path):
    ip = "127.0.0.1"
    spec = JobSpec.from_dict({
        "targets": [ip],
        "out_dir": str(tmp_path),
        "stages": {
            "discovery": {"timing": "-T2", "max_retries": 3},
            "tcp": {"ports": "80", "timing": "-T2"},
            "udp": {"enabled": True, "ports": "53", "timing": "-T2"},
            "service": {"timing": "-T2", "max_retries": 4, "nse": []},
        },
    }).validate()
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        calls.append(list(args))
        if "-sn" in args:
            port_xml = ""
        else:
            proto, port = ("udp", 53) if "-sU" in args else ("tcp", 80)
            service = '<service name="test" method="probed"/>' if "-sV" in args else ""
            port_xml = (
                f'<ports><port protocol="{proto}" portid="{port}">'
                f'<state state="open"/>{service}</port></ports>'
            )
        Path(f"{out_base}.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>{port_xml}</host></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    counts = Pipeline(spec, _Sink(), "nmap").run()

    assert counts["errors"] == 0 and len(calls) == 5
    assert all("-T2" in args and "-T4" not in args for args in calls)
    assert calls[0][calls[0].index("--max-retries") + 1] == "3"
    assert all(args[args.index("--max-retries") + 1] == "4" for args in calls[-2:])


@pytest.mark.parametrize(("scan_type", "scan_flag"), [
    ("syn", "-sS"),
    ("connect", "-sT"),
])
def test_tcp_scan_type_controls_sweep_and_service_golden_argv(
    monkeypatch, tmp_path, scan_type, scan_flag,
):
    ip = "127.0.0.1"
    spec = JobSpec.from_dict({
        "targets": [ip],
        "out_dir": str(tmp_path),
        "stages": {
            "discovery": {"mode": "pn"},
            "tcp": {"scan_type": scan_type, "ports": "80"},
            "service": {"nse": []},
        },
    }).validate()
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        calls.append(list(args))
        service = '<service name="http" method="probed"/>' if "-sV" in args else ""
        Path(f"{out_base}.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            f'<port protocol="tcp" portid="80"><state state="open"/>{service}</port>'
            '</ports></host></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    counts = Pipeline(spec, _Sink(), "nmap").run()
    defeat_rst = ["--defeat-rst-ratelimit"] if scan_type == "syn" else []

    assert counts["errors"] == 0
    assert calls == [
        [scan_flag, "-Pn", "-n", "--open", "-T4", "--reason",
         "--max-retries", "2", "--min-hostgroup", "64",
         *defeat_rst, "--max-parallelism", "100", "-p", "80", ip],
        [scan_flag, "-Pn", "-sV", "--version-all", "--open", "--reason", "-T4",
         "--max-retries", "2", "-p", "T:80", ip],
    ]


@pytest.mark.parametrize(("ports", "expected"), [
    ("T:80", [("tcp", "80")]),
    ("U:53", [("udp", "53")]),
])
def test_generated_staged_spec_never_invokes_unrequested_or_empty_protocol(
    monkeypatch, tmp_path, ports, expected,
):
    spec_dict = engine_runner.build_job_spec(
        1,
        ["127.0.0.1"],
        [],
        options=["udp"],
        ports=ports,
        nse=[],
        out_dir=tmp_path,
        batch_size=256,
        discovery="pn",
    )
    spec = JobSpec.from_dict(spec_dict).validate()
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        proto = "udp" if "-sU" in args else "tcp"
        port_spec = args[args.index("-p") + 1]
        calls.append((proto, port_spec))
        Path(f"{out_base}.xml").write_text("<nmaprun/>", encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args]}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    counts = Pipeline(spec, _Sink(), "nmap").run()

    assert counts["errors"] == 0
    assert calls == expected
    assert all(port_spec for _proto, port_spec in calls)


def test_cached_discovery_resume_reports_same_final_live_count(tmp_path):
    (tmp_path / "run-state.json").write_text(json.dumps({
        "stages_done": ["discovery"],
        "open_map": {},
        "live": ["127.0.0.1", "127.0.0.2"],
        "service_done": [],
        "stop": False,
    }), encoding="utf-8")
    spec = JobSpec.from_dict({
        "targets": ["127.0.0.0/30"],
        "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": False}, "service": {"enabled": False}},
    })
    sink = _Sink()

    counts = Pipeline(spec, sink, "nmap").run()

    discovery = next(event for event in sink.events if event.get("stage") == "discovery")
    assert discovery["counts"] == {"live": 2, "cached": True}
    assert counts["live"] == 2
    assert next(event for event in sink.events if event["event"] == "job_done")["counts"]["live"] == 2


def test_full_service_probe_splits_tcp_and_udp_commands(monkeypatch, tmp_path):
    ip = "127.0.0.1"
    excluded = "127.0.0.2"
    (tmp_path / "run-state.json").write_text(json.dumps({
        "stages_done": ["discovery"],
        "open_map": {ip: {"tcp": [54842, 54844], "udp": [63848]}},
        "live": [ip],
        "service_done": [],
        "stop": False,
    }), encoding="utf-8")
    spec = JobSpec.from_dict({
        "targets": [ip],
        "exclude": [excluded],
        "out_dir": str(tmp_path),
        "stages": {
            "tcp": {"enabled": False},
            "udp": {"enabled": False},
            "service": {"nse": ["banner"]},
        },
    })
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        proto = "udp" if "-sU" in args else "tcp"
        port_spec = args[args.index("-p") + 1]
        ports = [int(value) for value in port_spec.split(":", 1)[1].split(",")]
        calls.append({"proto": proto, "args": list(args), "base": Path(out_base)})
        port_xml = "".join(
            f'<port protocol="{proto}" portid="{port}"><state state="open"/>'
            '<service name="test" method="probed"/></port>'
            for port in ports
        )
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>{port_xml}</ports>'
            '</host></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    sink = _Sink()
    counts = Pipeline(spec, sink, "nmap").run()

    assert counts["errors"] == 0 and counts["services"] == 3
    assert [call["proto"] for call in calls] == ["tcp", "udp"]
    tcp, udp = calls
    assert tcp["base"].name == "stage3-127_0_0_1-tcp"
    assert udp["base"].name == "stage3-127_0_0_1-udp"
    assert tcp["args"][tcp["args"].index("-p") + 1] == "T:54842,54844"
    assert udp["args"][udp["args"].index("-p") + 1] == "U:63848"
    assert "-sS" in tcp["args"] and "-sU" not in tcp["args"]
    assert "-sU" in udp["args"] and "-sS" not in udp["args"]
    assert "--version-all" in tcp["args"] and "--version-all" not in udp["args"]
    assert tcp["args"] == [
        "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason", "-T4",
        "--max-retries", "2", "-p", "T:54842,54844", "--script", "banner",
        "--script-timeout", "10s", "--exclude", excluded, ip,
    ]
    assert udp["args"] == [
        "-sU", "-Pn", "-n", "-sV", "--open", "--reason", "-T4",
        "--max-retries", "2", "-p", "U:63848", "--script", "banner",
        "--script-timeout", "10s", "--exclude", excluded, ip,
    ]
    state = json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))
    assert ip in state["service_done"] and "job" in state["stages_done"]


@pytest.mark.parametrize(("stopped", "expected_status", "expected_errors"), [
    (False, "failed", 1),
    (True, "stopped", 0),
])
def test_mixed_service_does_not_mark_host_done_after_one_protocol_fails_or_stops(
    monkeypatch, tmp_path, stopped, expected_status, expected_errors,
):
    ip = "127.0.0.1"
    (tmp_path / "run-state.json").write_text(json.dumps({
        "stages_done": ["discovery"],
        "open_map": {ip: {"tcp": [54842], "udp": [63848]}},
        "live": [ip],
        "service_done": [],
        "stop": False,
    }), encoding="utf-8")
    spec = JobSpec.from_dict({
        "targets": [ip], "out_dir": str(tmp_path),
        "stages": {
            "tcp": {"enabled": False}, "udp": {"enabled": False},
            "service": {"nse": []},
        },
    })
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        proto = "udp" if "-sU" in args else "tcp"
        calls.append(proto)
        if proto == "udp":
            if stopped:
                (tmp_path / "stop-requested").touch()
            return {
                "rc": -15 if stopped else 7,
                "seconds": 0.01,
                "cmd": [nmap, *args],
                "stopped": stopped,
            }
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="54842"><state state="open"/>'
            '<service name="test" method="probed"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    sink = _Sink()
    counts = Pipeline(spec, sink, "nmap").run()

    assert calls == ["tcp", "udp"]
    assert counts["errors"] == expected_errors
    state = json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))
    assert ip not in state["service_done"] and "job" not in state["stages_done"]
    done = next(event for event in sink.events if event["event"] == "job_done")
    assert done["status"] == expected_status


def test_udp_open_filtered_is_kept_for_sweep_and_service(tmp_path):
    xml = tmp_path / "udp.xml"
    xml.write_text("""<?xml version="1.0"?><nmaprun><host><status state="up"/>
      <address addr="127.0.0.1" addrtype="ipv4"/><ports>
      <port protocol="udp" portid="53"><state state="open|filtered"/>
      <service name="domain"/></port></ports></host></nmaprun>""", encoding="utf-8")
    assert nmaprun.open_ports(xml, "udp") == {"127.0.0.1": [53]}
    assert [(r["proto"], r["port"]) for r in nmaprun.services(xml)] == [("udp", 53)]


def test_offline_zip_contains_engine(monkeypatch, tmp_path):
    import importlib.util

    module_path = ROOT / "packaging" / "build_zip.py"
    spec = importlib.util.spec_from_file_location("scanops_build_zip", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "OUT", tmp_path / "ScanOps_offline.zip")
    module.main()
    with zipfile.ZipFile(module.OUT) as bundle:
        names = set(bundle.namelist())
        expected = {
            f"ScanOps/engine/scanops_engine/{name}"
            for name in engine_runner.ENGINE_REQUIRED_FILES
        }
        assert expected <= names


SENSITIVE_PACKAGE_PATHS = (
    "backend/data/scanops.db",
    "backend/.venv-custom/secret.txt",
    "backend/.env",
    "backend/.env.production",
    "backend/secret.key",
    "backend/private.pem",
    "backend/INITIAL_ADMIN.txt",
    "backend/access-token.txt",
    "backend/credentials.json",
    "backend/session.token",
    "backend/id_rsa",
    "backend/id_ed25519",
    "backend/.npmrc",
    "backend/.pypirc",
    "backend/.ssh/id_rsa",
    "backend/secrets/config.json",
    "backend/private/config.json",
    "backend/service-account.json",
    "backend/client-secret.md",
    "engine/state.sqlite3",
    "engine/app.db-wal",
    "engine/archive.dbbackup",
    "engine/state.sqlitebackup",
    "frontend/dist/.env.production",
    "frontend/dist/credentials.json",
    "frontend/dist/data/session.token",
)


def _package_source(root: Path) -> None:
    safe_files = {
        "backend/scanops/app.py": "app = True\n",
        "backend/scanops/token_utils.py": "def parse_token(value): return value\n",
        "backend/scanops/database.py": "DATABASE = 'runtime'\n",
        "engine/scanops_engine/__main__.py": "raise SystemExit(0)\n",
        "frontend/dist/index.html": "<!doctype html>\n",
    }
    for relative, content in safe_files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for relative in SENSITIVE_PACKAGE_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("must not ship\n", encoding="utf-8")


def _assert_sensitive_entries_absent(module, names: set[str]) -> None:
    assert "ScanOps/backend/scanops/app.py" in names
    assert "ScanOps/backend/scanops/token_utils.py" in names
    assert "ScanOps/backend/scanops/database.py" in names
    forbidden = [
        name for name in names
        if module.is_forbidden_source_path(Path(name).relative_to("ScanOps"))
    ]
    assert forbidden == []
    for relative in SENSITIVE_PACKAGE_PATHS:
        assert f"ScanOps/{relative}" not in names
        assert module.is_forbidden_source_path(Path(relative))


def test_offline_zip_excludes_runtime_data_and_credentials(monkeypatch, tmp_path):
    import importlib.util

    module_path = ROOT / "packaging" / "build_zip.py"
    spec = importlib.util.spec_from_file_location("scanops_secure_build_zip", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    _package_source(source)
    monkeypatch.setattr(module, "ROOT", source)
    monkeypatch.setattr(module, "OUT", tmp_path / "ScanOps_offline.zip")

    module.main()

    with zipfile.ZipFile(module.OUT) as bundle:
        _assert_sensitive_entries_absent(module, set(bundle.namelist()))


def test_allinone_zip_excludes_runtime_data_and_credentials(monkeypatch, tmp_path):
    import importlib.util

    module_path = ROOT / "packaging" / "build_allinone.py"
    spec = importlib.util.spec_from_file_location("scanops_secure_build_allinone", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    _package_source(source)
    monkeypatch.setattr(module, "ROOT", source)
    monkeypatch.setattr(module, "OUT", tmp_path / "ScanOps_allinone.zip")
    app = tmp_path / "stage" / "ScanOps"
    app.mkdir(parents=True)

    module.copy_app(app)
    module.zip_bundle(app)

    with zipfile.ZipFile(module.OUT) as bundle:
        _assert_sensitive_entries_absent(module, set(bundle.namelist()))


def test_allinone_copy_and_embedded_python_path_include_engine(tmp_path):
    import importlib.util

    module_path = ROOT / "packaging" / "build_allinone.py"
    spec = importlib.util.spec_from_file_location("scanops_build_allinone", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = tmp_path / "app"
    app.mkdir()
    module.copy_app(app)
    package = app / "engine" / "scanops_engine"
    assert all((package / name).is_file() for name in engine_runner.ENGINE_REQUIRED_FILES)

    embed = tmp_path / "embed.zip"
    with zipfile.ZipFile(embed, "w") as archive:
        archive.writestr("python.exe", b"placeholder")
        archive.writestr("python312._pth", "python312.zip\n.\n")
    module.place_python(app, embed)
    pth = (app / "runtime" / "python" / "python312._pth").read_text(encoding="ascii")
    assert "..\\..\\backend" in pth and "..\\..\\engine" in pth


def test_offline_wheelhouse_resolves_only_for_documented_cp312_windows(tmp_path):
    base = [
        sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
        "--no-index", "--find-links", str(ROOT / "packaging" / "wheelhouse"),
        "--platform", "win_amd64", "--implementation", "cp", "--only-binary=:all:",
        "-r", str(ROOT / "backend" / "requirements.txt"),
    ]
    cp312 = subprocess.run(
        [*base, "--python-version", "3.12", "--abi", "cp312"],
        text=True, capture_output=True, check=False,
    )
    assert cp312.returncode == 0, cp312.stdout + cp312.stderr

    cp311 = subprocess.run(
        [*base, "--python-version", "3.11", "--abi", "cp311"],
        text=True, capture_output=True, check=False,
    )
    assert cp311.returncode != 0

    installer = (ROOT / "packaging" / "install.ps1").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Python 3.12 (x64)" in installer
    assert "Python 3.12 (x64)" in readme


@pytest.mark.skipif(sys.platform != "win32", reason="Windows exclusive-bind contract")
@pytest.mark.parametrize("sock_type", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_cleanup_port_probe_rejects_live_reusable_windows_listener(sock_type):
    listener = socket.socket(socket.AF_INET, sock_type)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((runtime_e2e.HOST, 0))
    port = int(listener.getsockname()[1])
    if sock_type == socket.SOCK_STREAM:
        listener.listen()
    try:
        assert runtime_e2e._port_is_bindable(port, sock_type) is False
    finally:
        listener.close()
    assert runtime_e2e._port_is_bindable(port, sock_type) is True


def test_cleanup_udp_probe_rejects_live_reusable_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((runtime_e2e.HOST, 0))
    port = int(listener.getsockname()[1])
    try:
        assert runtime_e2e._port_is_bindable(port, socket.SOCK_DGRAM) is False
    finally:
        listener.close()
    assert runtime_e2e._port_is_bindable(port, socket.SOCK_DGRAM) is True


def test_package_runtime_commands_have_a_hard_timeout(tmp_path):
    log_path = tmp_path / "timeout.log"
    child_pid_path = tmp_path / "child.pid"
    child_code = "import time; time.sleep(10)"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid)); "
        "time.sleep(10)"
    )
    child_pid = None
    try:
        with pytest.raises(runtime_e2e.RuntimeE2EError, match="timed out"):
            package_runtime_smoke._run_logged(
                "timeout contract", [sys.executable, "-c", parent_code],
                log_path, timeout=1,
            )
        child_pid = int(child_pid_path.read_text())
        assert runtime_e2e._pid_is_running(child_pid) is False
    finally:
        if child_pid and runtime_e2e._pid_is_running(child_pid):
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                    capture_output=True, check=False,
                )
            else:
                import signal
                import os
                os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows orphan cleanup contract")
def test_windows_stop_tree_kills_descendant_after_parent_exits(tmp_path):
    child_pid_path = tmp_path / "orphan.pid"
    child_code = "import time; time.sleep(10)"
    parent_code = (
        "import pathlib,subprocess,sys; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid))"
    )
    parent = runtime_e2e.popen_tracked([sys.executable, "-c", parent_code])
    parent.wait(timeout=5)
    child_pid = int(child_pid_path.read_text())
    try:
        assert runtime_e2e._pid_is_running(child_pid) is True
        runtime_e2e._stop_process_tree(parent)
        assert runtime_e2e._pid_is_running(child_pid) is False
    finally:
        if runtime_e2e._pid_is_running(child_pid):
            subprocess.run(
                ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                capture_output=True, check=False,
            )
