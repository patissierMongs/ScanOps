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


def test_run_state_retries_a_transient_windows_replace_lock(monkeypatch, tmp_path):
    from scanops_engine import state as state_module

    path = tmp_path / "run-state.json"
    state = RunState(path)
    state.set("live", ["127.0.0.1"])
    real_replace = state_module.os.replace
    calls = 0

    def flaky_replace(source, target):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise PermissionError(5, "transient sharing violation")
        return real_replace(source, target)

    monkeypatch.setattr(state_module.os, "replace", flaky_replace)
    state.save()

    assert calls == 3
    assert json.loads(path.read_text(encoding="utf-8"))["live"] == ["127.0.0.1"]
    assert list(tmp_path.glob(".run-state.json.*.tmp")) == []


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


def test_nmap_collects_hosts_that_hit_the_retransmission_cap(monkeypatch, tmp_path):
    class WarningProcess:
        pid = 23457
        stdout = io.StringIO(
            "Warning: 10.0.0.8 giving up on port because retransmission cap hit (2).\n"
            "Warning: 10.0.0.7 giving up on port because retransmission cap hit (2).\n"
            "Warning: 10.0.0.8 giving up on port because retransmission cap hit (2).\n"
        )

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(timeout=None):
            return 0

    monkeypatch.setattr(nmaprun, "popen_owned", lambda *args, **kwargs: WarningProcess())
    monkeypatch.setattr(nmaprun, "close_kill_job", lambda proc: False)

    result = nmaprun.run("nmap", [], tmp_path / "cap-hit")

    assert result["retransmission_cap_hosts"] == ["10.0.0.7", "10.0.0.8"]


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
    ["10.0.0.9-2"],      # 역순 범위는 여전히 거절
    ["10.0.0.300-5"],    # 옥텟 범위 초과
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


def test_job_spec_accepts_last_octet_range_exclude():
    """타겟 입력이 받는 범위 문법을 제외에서도 받는다(nmap --exclude 가 그대로 해석)."""
    spec = JobSpec.from_dict({
        "targets": ["10.0.0.0/24"],
        "exclude": ["10.0.0.1-10"],
    }).validate()
    assert spec.exclude == ["10.0.0.1-10"]


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
         # 발견은 -sn 이라 두 가지가 함께 빠진다 - SYN 스캔이 아니므로
         # --defeat-rst-ratelimit 을 얹으면 nmap 이 fatal 로 끝나고, nmap 문서상
         # --min-hostgroup 은 호스트 발견 단계에 아무 효과가 없다.
         "--max-retries", "2", "--max-parallelism", "100",
         "--exclude", ",".join(excluded), target],
        ["-sS", "-Pn", "-n", "--open", "-T4", "--reason",
         "--max-retries", "2", "--min-hostgroup", "64", "--max-parallelism", "100",
         "--defeat-rst-ratelimit",
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
        # UDP 는 ICMP 율제한 때문에 TCP 보다 재전송을 넉넉히 준다.
        "--max-retries", "4", "--min-hostgroup", "64", "--max-parallelism", "100", "-p",
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

    # 위치가 아니라 **역할**로 고른다. 스캔은 배치마다 sweep → 식별까지 끝내고 다음 배치로
    # 가므로 호출 순서가 discovery · tcp sweep · tcp 식별 · udp sweep · udp 식별 이다.
    def retries(args):
        return args[args.index("--max-retries") + 1]

    discovery = [args for args in calls if "-sn" in args]
    identify = [args for args in calls if "-sV" in args]
    sweeps = [args for args in calls if "-sn" not in args and "-sV" not in args]
    assert len(discovery) == 1 and len(identify) == 2 and len(sweeps) == 2
    assert retries(discovery[0]) == "3"
    assert all(retries(args) == "4" for args in identify), "식별은 service.max_retries 를 쓴다"


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
         "--max-retries", "2", "--min-hostgroup", "64", "--max-parallelism", "100",
         *defeat_rst, "-p", "80", ip],
        [scan_flag, "-Pn", "-sV", "--version-all", "--open", "--reason", "-T4",
         # 처리량 정책은 식별 단계에도 실린다 - 한 단계만 빠지면 그 단계가 꼬리가 된다.
         "--max-retries", "2", "-p", "T:80",
         "--min-hostgroup", "64", "--max-parallelism", "100", *defeat_rst, ip],
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
            "service": {"nse": ["banner"], "udp_nse": ["dns-nsid"]},
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
    assert tcp["base"].name == "stage3-tcp-b0-g0"
    # 정상 경로는 프로토콜당 한 프로세스다. 포트별로 쪼개는 것은 그 묶음이 죽었을 때뿐이다.
    assert udp["base"].name == "stage3-127_0_0_1-udp"
    assert tcp["args"][tcp["args"].index("-p") + 1] == "T:54842,54844"
    assert udp["args"][udp["args"].index("-p") + 1] == "U:63848"
    assert "-sS" in tcp["args"] and "-sU" not in tcp["args"]
    assert "-sU" in udp["args"] and "-sS" not in udp["args"]
    assert "--version-all" in tcp["args"] and "--version-all" not in udp["args"]
    assert tcp["args"] == [
        "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason", "-T4",
        "--max-retries", "2", "-p", "T:54842,54844",
        "--min-hostgroup", "64", "--max-parallelism", "100", "--defeat-rst-ratelimit",
        "--script", "banner", "--script-timeout", "2m", "--exclude", excluded, ip,
    ]
    # UDP도 웹에서 선택한 UDP/both 스크립트만 열린 UDP 포트 식별에 붙인다.
    assert udp["args"] == [
        "-sU", "-Pn", "-n", "-sV", "--open", "--reason", "-T4",
        "--max-retries", "4", "-p", "U:63848",
        "--min-hostgroup", "64", "--max-parallelism", "100",
        "--script", "dns-nsid", "--script-timeout", "3m", "--exclude", excluded, ip,
    ]
    state = json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))
    assert ip in state["service_done"] and "job" in state["stages_done"]


@pytest.mark.parametrize(("stopped", "expected_status", "expected_errors", "expected_calls"), [
    # 전체 스캔에서 stage3 는 enrichment 다. 식별 프로세스가 죽어도 폐쇄 권위는 sweep 이
    # 쥐고 있으므로 실행 전체를 실패로 만들지 않는다(대신 select 로 한 번 재시도한다).
    (False, "done", 0, ["tcp", "udp", "udp"]),
    # 중지는 저하가 아니다 — 사용자가 멈춘 것이므로 재시도도 하지 않고 즉시 끝낸다.
    (True, "stopped", 0, ["tcp", "udp"]),
])
def test_mixed_service_does_not_mark_host_done_after_one_protocol_fails_or_stops(
    monkeypatch, tmp_path, stopped, expected_status, expected_errors, expected_calls,
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

    assert calls == expected_calls
    assert counts["errors"] == expected_errors
    state = json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))
    # 어느 쪽이든 이 호스트는 done 으로 찍지 않는다. (다만 done 으로 마감된 실행은 /resume
    # 이 거절하므로, 다시 얻으려면 해당 발견을 골라 타겟 재스캔을 돌려야 한다.)
    assert ip not in state["service_done"]
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
        # 에어갭 번들은 결과 검사 도구를 싣는다 — 합성 트리에도 있어야 실제 계약을 검증한다.
        "scripts/check_scan_xml.py": "raise SystemExit(0)\n",
        "scripts/audit_closures.py": "raise SystemExit(0)\n",
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


def test_allinone_start_creates_and_prints_initial_admin_credentials(tmp_path):
    module = _load_allinone()
    app = tmp_path / "app"
    app.mkdir()
    module.write_launcher(app)

    start = (app / "START.bat").read_text(encoding="ascii")
    assert "run_bootstrap" in start and "INITIAL_ADMIN.txt" in start
    assert "read_text(encoding='utf-8')" in start
    assert "Username: admin" in start and "Password: '+pw" in start
    assert start.index("run_bootstrap") < start.index("-m uvicorn")
    assert "chcp 65001" in start
    assert "<this-server-ip>" not in start


def test_runtime_browser_failed_stage_fixture_matches_current_scan_schema(client):
    """The browser fixture uses raw SQL, so new non-null scan columns must be supplied."""
    from scanops.config import get_settings

    seeded = runtime_e2e._seed_failed_stage_scan(get_settings().data_dir)

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, seeded["id"])
        assert scan is not None
        assert scan.batch_total == 0 and scan.batch_size == 0
        assert scan.source_fingerprint == ""
    finally:
        db.close()


def test_offline_wheelhouse_resolves_only_for_documented_windows_pythons(tmp_path):
    """wheelhouse 는 문서화된 런타임(all-in-one 의 3.12/3.13)에서만 오프라인 해석돼야 한다.

    문서화되지 않은 버전(3.11)이 우연히 해석되면 '지원한다'는 착각을 만든다."""
    base = [
        sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
        "--no-index", "--find-links", str(ROOT / "packaging" / "wheelhouse"),
        "--platform", "win_amd64", "--implementation", "cp", "--only-binary=:all:",
        "-r", str(ROOT / "backend" / "requirements.txt"),
    ]
    for version in ("3.12", "3.13"):
        abi = "cp" + version.replace(".", "")
        resolved = subprocess.run(
            [*base, "--python-version", version, "--abi", abi],
            text=True, capture_output=True, check=False,
        )
        assert resolved.returncode == 0, resolved.stdout + resolved.stderr

    cp311 = subprocess.run(
        [*base, "--python-version", "3.11", "--abi", "cp311"],
        text=True, capture_output=True, check=False,
    )
    assert cp311.returncode != 0

    installer = (ROOT / "packaging" / "install.ps1").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # install.ps1 이 받는 런타임과 README 가 적은 전제는 같아야 한다(둘이 어긋나면
    # 운영자가 설치를 거절당하고도 이유를 못 찾는다).
    assert "Python 3.13 / 3.12 (x64)" in readme
    for version in ("3.13", "3.12"):
        assert f'"{version}"' in installer
    # all-in-one 은 두 런타임을 모두 담을 수 있으므로 그 사실도 문서에 있어야 한다.
    assert "--python 3.12" in readme
    assert "--arch x86" in readme


def test_non_ascii_windows_powershell_installer_has_utf8_bom():
    installer = ROOT / "packaging" / "install.ps1"
    data = installer.read_bytes()

    assert any(byte >= 0x80 for byte in data)
    assert data.startswith(b"\xef\xbb\xbf")


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


def _load_allinone():
    import importlib.util

    module_path = ROOT / "packaging" / "build_allinone.py"
    spec = importlib.util.spec_from_file_location("scanops_allinone_versions", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_allinone_default_keeps_the_established_output_contract():
    """인자 없이 부르는 기존 경로(package_runtime_smoke)가 이름/스테이지를 그대로 쓴다.

    기본 런타임은 3.13 이다. 산출물 '이름'은 계약이라 그대로 두고 안에 담기는 런타임만
    옮겼다 — smoke/CI 가 ScanOps_allinone.zip 을 이름으로 집어가기 때문."""
    module = _load_allinone()
    assert module.PYTHON == "3.13" and module.ABI == "cp313"
    assert module.ARCH == "x64" and module.PLATFORM == "win_amd64"
    assert module.OUT.name == "ScanOps_allinone.zip"
    assert module.STAGE.name == "_allinone_stage"

    module.configure("3.13")
    assert module.OUT.name == "ScanOps_allinone.zip"
    assert module.STAGE.name == "_allinone_stage"


def test_allinone_configure_binds_runtime_abi_and_output_per_version():
    module = _load_allinone()

    module.configure("3.12")
    assert module.ABI == "cp312"
    assert module.PYVER.startswith("3.12.")
    assert module.PYVER in module.EMBED_URL and "embed-amd64" in module.EMBED_URL
    # 버전별 산출물/스테이지가 서로 덮어쓰지 않아야 한다.
    assert module.OUT.name == "ScanOps_allinone_py312.zip"
    assert module.STAGE.name == "_allinone_stage_py312"

    module.configure("3.13")
    assert module.ABI == "cp313" and module.OUT.name == "ScanOps_allinone.zip"

    with pytest.raises(SystemExit):
        module.configure("3.11")


def test_allinone_configure_binds_x86_runtime_without_changing_x64_defaults():
    module = _load_allinone()

    module.configure("3.13", arch="x86")
    assert module.ARCH == "x86" and module.PLATFORM == "win32"
    assert "embed-win32" in module.EMBED_URL
    assert module.OUT.name == "ScanOps_allinone_x86.zip"
    assert module.STAGE.name == "_allinone_stage_x86"

    with pytest.raises(SystemExit, match="x86"):
        module.configure("3.12", arch="x86")

    module.configure("3.13")
    assert module.ARCH == "x64" and module.OUT.name == "ScanOps_allinone.zip"


def test_allinone_wheelhouse_covers_every_supported_python():
    """각 지원 버전의 win_amd64 바이너리 휠이 wheelhouse 에 있어야 완전 오프라인 빌드가 된다."""
    module = _load_allinone()
    wheels = {p.name for p in (ROOT / "packaging" / "wheelhouse").glob("*.whl")}
    for python in module.PY_RELEASES:
        abi = "cp" + python.replace(".", "")
        for dist in ("SQLAlchemy", "greenlet", "pydantic_core"):
            assert any(w.startswith(dist) and f"{abi}-{abi}-win_amd64" in w for w in wheels), (
                f"{dist} 의 {abi} win_amd64 휠이 wheelhouse 에 없습니다")

    for dist in ("SQLAlchemy", "pydantic_core"):
        assert any(w.startswith(dist) and "cp313-cp313-win32" in w for w in wheels), (
            f"{dist} 의 cp313 win32 휠이 wheelhouse 에 없습니다")


def test_allinone_ships_windows_conditional_dependencies():
    """pip 크로스 설치는 'colorama; platform_system == \"Windows\"' 를 빌드 호스트 기준으로
    평가해 빠뜨린다. click(uvicorn CLI)이 Windows 에서 import 하므로 명시 보강이 필요하다."""
    module = _load_allinone()
    assert "colorama" in module.WINDOWS_EXTRA_PACKAGES
    wheels = {p.name for p in (ROOT / "packaging" / "wheelhouse").glob("*.whl")}
    assert any(w.startswith("colorama-") for w in wheels)


def test_allinone_verify_site_rejects_mismatched_abi(tmp_path):
    module = _load_allinone()
    module.configure("3.13")
    site = tmp_path / "site"
    for pkg in ("fastapi", "uvicorn", "sqlalchemy", "pydantic", "pydantic_core",
                "pydantic_settings", "starlette", "openpyxl", "multipart",
                "click", "colorama"):
        (site / pkg).mkdir(parents=True)
    (site / "pydantic_core" / "_pydantic_core.cp312-win_amd64.pyd").write_bytes(b"x")

    with pytest.raises(SystemExit, match="cp313"):
        module.verify_site(site)


def test_allinone_verify_site_rejects_mismatched_architecture(tmp_path):
    module = _load_allinone()
    module.configure("3.13", arch="x86")
    site = tmp_path / "site"
    for pkg in ("fastapi", "uvicorn", "sqlalchemy", "pydantic", "pydantic_core",
                "pydantic_settings", "starlette", "openpyxl", "multipart",
                "click", "colorama"):
        (site / pkg).mkdir(parents=True)
    (site / "pydantic_core" / "_pydantic_core.cp313-win_amd64.pyd").write_bytes(b"x")

    with pytest.raises(SystemExit, match="win32"):
        module.verify_site(site)


def test_allinone_verify_site_reports_missing_dependency(tmp_path):
    module = _load_allinone()
    module.configure("3.12")
    site = tmp_path / "site"
    (site / "fastapi").mkdir(parents=True)   # 나머지는 일부러 비워 둔다

    with pytest.raises(SystemExit, match="빠진 패키지"):
        module.verify_site(site)


def test_allinone_verify_site_accepts_deliberately_trimmed_greenlet(tmp_path):
    """동기 SQLite 서버는 greenlet을 싣지 않는다; 검증기가 제거 정책과 충돌하면 안 된다."""
    module = _load_allinone()
    module.configure("3.13")
    site = tmp_path / "site"
    for pkg in ("fastapi", "uvicorn", "sqlalchemy", "pydantic", "pydantic_core",
                "pydantic_settings", "starlette", "openpyxl", "multipart",
                "click", "colorama"):
        (site / pkg).mkdir(parents=True)

    module.verify_site(site)
    assert "greenlet" in module.SITE_DROP_PACKAGES


# ── 산출물 완결성 → 닫힘 권한 (실제 Pipeline 으로 검증) ────────────────────────
#
# helper 에 임의 입력을 넣는 테스트는 자기 모델만 검증한다. 그래서 여기서는 fake nmap 이
# 실제 산출물을 만들고 **진짜 Pipeline** 이 돌게 한 뒤, 그 out_dir 을 워커의 판정에 넣는다.

_FINISHED_XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                 '<address addr="127.0.0.1" addrtype="ipv4"/>'
                 '<ports><port protocol="tcp" portid="443"><state state="open"/>'
                 '<service name="https" method="probed"/></port></ports></host>'
                 '<runstats><finished exit="success"/>'
                 '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')
# 실제 사고 파일과 같은 모양 — nmap 이 </nmaprun> 을 쓰지 못하고 죽었다.
_TRUNCATED_XML = '<?xml version="1.0"?><nmaprun><host><status state="up"/>'


def _run_pipeline(tmp_path, monkeypatch, *, broken: dict | None = None,
                  omit: set | None = None, spec_extra: dict | None = None):
    """fake nmap 으로 실제 Pipeline 을 돌린다.

    broken: {단계이름 조각: True} 인 산출물은 잘린 XML 로 쓴다.
    omit:   그 이름 조각을 가진 산출물은 아예 만들지 않는다(nmap 이 파일을 못 만든 경우).
    """
    broken, omit = broken or {}, omit or set()
    spec_dict = {
        "targets": ["127.0.0.1"], "exclude": [], "out_dir": str(tmp_path),
        "batch_size": 256,
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": True, "nse": []}},
    }
    spec_dict.update(spec_extra or {})

    def fake_run(nmap, args, out_base, **_kwargs):
        name = Path(out_base).name
        if any(frag in name for frag in omit):
            return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}
        body = _TRUNCATED_XML if any(f in name for f in broken) else _FINISHED_XML
        Path(str(out_base) + ".xml").write_text(body, encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    Pipeline(JobSpec.from_dict(spec_dict), _Sink(), "nmap").run()
    return spec_dict


@pytest.mark.parametrize(("case", "kwargs", "authority_ok"), [
    ("정상",                {},                                  True),
    # discovery 는 -Pn 이면 nmap 을 안 돌린다 → 이 경계는 sn 모드에서만 존재한다.
    ("discovery 잘림",      {"broken": {"stage0-discovery": 1},
                             "spec_extra": {"stages": {
                                 "discovery": {"mode": "sn"},
                                 "tcp": {"enabled": True, "ports": "443"},
                                 "udp": {"enabled": False, "ports": ""},
                                 "service": {"enabled": True, "nse": []}}}},  False),
    ("sweep 잘림",          {"broken": {"stage-tcp-b": 1}},       False),
    ("sweep 파일 부재",     {"omit": {"stage-tcp-b"}},            False),
    ("stage3 잘림(전체스캔)", {"broken": {"stage3-": 1}},          True),
])
def test_artifact_report_separates_authority_from_enrichment(
    tmp_path, monkeypatch, case, kwargs, authority_ok,
):
    """전체 스캔에서 authority(discovery·sweep)와 enrichment(stage3)의 완결성은 따로 센다.

    앞의 셋은 '못 본 것을 없다고 하는' 미탐 경로라 닫힘 권한을 뺏어야 하고,
    마지막은 포트 관측이 이미 끝난 실행이라 권한을 뺏으면 사라진 서비스가 영영 안 닫힌다.
    한쪽만 고정하면 반대 방향으로 넘어진다."""
    spec = _run_pipeline(tmp_path, monkeypatch, **kwargs)
    report = engine_runner.artifact_report(tmp_path, spec, force_scanned_hosts=False)
    bad = report["authority_missing"] + report["authority_broken"]
    assert (not bad) is authority_ok, f"{case}: {report}"
    if case == "stage3 잘림(전체스캔)":
        assert report["enrichment_broken"], "잘린 stage3 는 증거 저하로 남아야 한다"
    if case == "sweep 파일 부재":
        assert report["authority_missing"] == ["stage-tcp-b0.xml"]


def test_a_rescan_treats_stage3_as_authority(tmp_path, monkeypatch):
    """재스캔에는 sweep 이 없고 stage3 가 유일한 근거다 — 그때는 stage3 가 authority."""
    extra = {"rescan_units": [{"ip": "127.0.0.1", "port": 443, "proto": "tcp"}],
             "stages": {"service": {"enabled": True, "nse": []}}}
    bad_dir = tmp_path / "broken"
    bad_dir.mkdir()
    spec = _run_pipeline(bad_dir, monkeypatch, broken={"stage3-": 1}, spec_extra=extra)
    report = engine_runner.artifact_report(bad_dir, spec, force_scanned_hosts=True)
    assert report["authority_broken"] == ["stage3-127_0_0_1-tcp443.xml"]

    # 반대 경계 — 온전한 재스캔은 권한을 유지한다(과잉 보수 방지).
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    spec = _run_pipeline(good_dir, monkeypatch, spec_extra=extra)
    ok = engine_runner.artifact_report(good_dir, spec, force_scanned_hosts=True)
    assert not (ok["authority_missing"] + ok["authority_broken"])


# 결과가 빈 XML — 확인 패스(confirm)를 유발하는 1차 산출물.
_EMPTY_FINISHED_XML = ('<?xml version="1.0"?><nmaprun>'
                       '<runstats><finished exit="success"/>'
                       '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def test_a_rescan_confirm_pass_is_part_of_closure_authority(tmp_path, monkeypatch):
    """재스캔의 확인 패스 산출물이 없으면 닫으면 안 된다.

    운영 재스캔 spec 은 `service.confirm=True` 다(engine_runner.build_job_spec). 1차 probe 가
    빈손이면 Pipeline 이 `stage3-<ip>-<proto><port>-confirm.xml` 을 한 번 더 만든다. 그 파일을
    기대 목록에서 빼면, 확인 패스가 통째로 날아가도 '관측 0건'이 정상으로 통과해 기존
    Finding 이 closed/정상처리 가 된다."""
    extra = {"rescan_units": [{"ip": "127.0.0.1", "port": 443, "proto": "tcp"}],
             "stages": {"service": {"enabled": True, "nse": [], "confirm": True}}}

    def run_with(out_dir, omit_confirm: bool):
        def fake_run(nmap, args, out_base, **_kwargs):
            name = Path(out_base).name
            if omit_confirm and name.endswith("-confirm"):
                return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}
            # 1차는 '완결됐지만 결과 0건' → 엔진이 확인 패스를 돈다.
            body = _EMPTY_FINISHED_XML if not name.endswith("-confirm") else _FINISHED_XML
            Path(str(out_base) + ".xml").write_text(body, encoding="utf-8")
            return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

        monkeypatch.setattr(nmaprun, "run", fake_run)
        spec = {"targets": ["127.0.0.1"], "exclude": [], "out_dir": str(out_dir), **extra}
        Pipeline(JobSpec.from_dict(spec), _Sink(), "nmap").run()
        return engine_runner.artifact_report(out_dir, spec, force_scanned_hosts=True)

    gone = tmp_path / "no-confirm"
    gone.mkdir()
    report = run_with(gone, omit_confirm=True)
    assert report["authority_missing"] == ["stage3-127_0_0_1-tcp443-confirm.xml"], report

    # 반대 경계 — 확인 패스가 온전하면 권한을 유지한다(과잉 보수 방지).
    ok_dir = tmp_path / "with-confirm"
    ok_dir.mkdir()
    ok = run_with(ok_dir, omit_confirm=False)
    assert not (ok["authority_missing"] + ok["authority_broken"]), ok


def test_a_missing_service_probe_artifact_is_recorded_as_degraded(tmp_path, monkeypatch):
    """전체 스캔에서 stage3 가 아예 안 만들어진 것도 증거 저하로 남아야 한다.

    닫힘 권한은 sweep 이 쥐고 있으므로 뺏지 않는다. 다만 아무 표시도 안 남기면 서비스·NSE
    증거가 빠진 사실이 '정상 완료'로 숨는다."""
    spec = _run_pipeline(tmp_path, monkeypatch, omit={"stage3-"})
    report = engine_runner.artifact_report(tmp_path, spec, force_scanned_hosts=False)
    assert not (report["authority_missing"] + report["authority_broken"]), report
    assert report["enrichment_missing"] == ["stage3-tcp-b0-g0.xml"], report


def test_one_dead_udp_probe_no_longer_abandons_the_rest_of_the_identify_stage(
    monkeypatch, tmp_path,
):
    """보고된 'UDP 가 오류 내며 안 끝남'의 실제 지점.

    예전에는 식별 nmap 하나가 죽으면 _service 가 stage 를 통째로 중단해 뒤따르는 호스트가
    전부 식별되지 못한 채 실행이 failed 로 끝났다. 이제는 그 호스트만 저하로 남기고 계속한다.

    그리고 정상 경로는 묶어서 돌린다 — 포트마다 프로세스를 만들면 open|filtered 가 다수인
    UDP 에서 프로세스가 폭증해 고치려던 증상을 오히려 악화시킨다.
    """
    dead, alive = "127.0.0.1", "127.0.0.2"
    (tmp_path / "run-state.json").write_text(json.dumps({
        "stages_done": ["discovery"],
        "open_map": {dead: {"udp": [161, 500]}, alive: {"udp": [123]}},
        "live": [dead, alive],
        "service_done": [],
        "stop": False,
    }), encoding="utf-8")
    spec = JobSpec.from_dict({
        "targets": [dead, alive], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": False}, "udp": {"enabled": False},
                   "service": {"nse": [], "confirm": False}},
    })
    seen = []

    def fake_run(nmap, args, out_base, **_kwargs):
        targets = tuple(ip for ip in (dead, alive) if ip in args)
        pspec = args[args.index("-p") + 1].split(":")[1]
        ports = [int(x) for x in pspec.split(",")]
        seen.append((targets, tuple(ports), "--nsock-engine" in args))
        # 500 을 물고 있는 실행만 죽는다 — 묶음도, 쪼갠 뒤의 500 도.
        if dead in targets and 500 in ports:
            return {"rc": 7, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}
        rows = "".join(
            f'<port protocol="udp" portid="{p}"><state state="open" reason="udp-response"/>'
            '<service name="test" method="probed"/></port>' for p in ports)
        xml_hosts = "".join(
            '<host><status state="up"/>'
            f'<address addr="{target}" addrtype="ipv4"/><ports>{rows}</ports></host>'
            for target in targets
        )
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun>' + xml_hosts
            + '<runstats><finished exit="success"/></runstats></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    sink = _Sink()
    counts = Pipeline(spec, sink, "nmap").run()

    # 공유 호스트 집합이 없으므로 정상 호스트는 자기 포트 묶음 한 번으로 끝난다.
    assert [call for call in seen if call[0] == (alive,)] == [((alive,), (123,), False)]
    # 죽은 호스트는 묶음 → select 재시도 → 그때서야 포트별 분할.
    assert ((dead,), (161, 500), False) in seen and ((dead,), (161, 500), True) in seen
    assert ((dead,), (161,), False) in seen, "묶음이 죽은 뒤에야 포트별로 쪼갠다"
    assert (tmp_path / f"stage3-{dead.replace('.', '_')}-udp161.xml").exists()
    # 뒤따르는 호스트가 살아남는다 — stage 가 중단되지 않았다는 뜻.
    assert (tmp_path / f"stage3-{alive.replace('.', '_')}-udp.xml").exists()
    assert counts["errors"] == 0
    assert next(e for e in sink.events if e["event"] == "job_done")["status"] == "done"
    assert any(e["event"] == "service_degraded" and e["ip"] == dead for e in sink.events)


@pytest.mark.parametrize("proto", ["tcp", "udp"])
def test_rescan_unit_artifact_name_matches_what_the_authority_gate_expects(
    monkeypatch, tmp_path, proto,
):
    """재스캔은 stage3 가 유일한 폐쇄 근거다 — 파일명이 한 글자만 어긋나도 권한이 사라진다.

    호출자가 이미 tag="udp53" 을 넘기는데 분할 로직이 포트를 또 붙이면 udp5353 이 되어,
    성공한 재스캔이 산출물 부재로 partial 판정된다.
    """
    from scanops.scanning import engine_runner

    ip, port = "127.0.0.1", 53
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": False}, "udp": {"enabled": False},
                   "service": {"nse": [], "confirm": True}},
        "rescan_units": [{"ip": ip, "port": port, "proto": proto}],
    }

    def fake_run(nmap, args, out_base, **_kwargs):
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            f'<port protocol="{proto}" portid="{port}">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="domain" method="probed"/></port></ports>'
            '</host><runstats><finished exit="success"/></runstats></nmaprun>',
            encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    Pipeline(JobSpec.from_dict(spec_dict), _Sink(), "nmap").run()

    report = engine_runner.artifact_report(tmp_path, spec_dict, force_scanned_hosts=True)
    produced = sorted(p.name for p in tmp_path.glob("stage3-*.xml"))
    assert produced == [f"stage3-127_0_0_1-{proto}{port}.xml"], produced
    assert report["authority_missing"] == [] and report["authority_broken"] == []


def _audit_db(tmp_path, events):
    """(finding_id, scan_id) 목록으로 최소 DB 를 만든다."""
    import sqlite3

    db = tmp_path / "scanops.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, host_ip TEXT, port INT,"
        " proto TEXT, state TEXT, status TEXT);"
        "CREATE TABLE finding_events (id INTEGER PRIMARY KEY, finding_id INT,"
        " scan_id INT, type TEXT, detail TEXT);")
    for fid, scan_id in events:
        con.execute("INSERT INTO findings VALUES (?,?,?,?,?,?)",
                    (fid, f"10.0.0.{fid}", 22, "tcp", "closed", "정상처리"))
        con.execute("INSERT INTO finding_events VALUES (?,?,?,'CLOSED','포트 닫힘')",
                    (fid, fid, scan_id))
    con.commit()
    con.close()
    return db


def _spec_state(out_dir, live, *, tcp=True, udp=False):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "spec.json").write_text(json.dumps({
        "targets": live, "batch_size": 256,
        "stages": {"discovery": {"mode": "sn"},
                   "tcp": {"enabled": tcp, "ports": "1-65535"},
                   "udp": {"enabled": udp, "ports": "53,161"},
                   "service": {"enabled": True}},
    }), encoding="utf-8")
    (out_dir / "run-state.json").write_text(json.dumps({"live": live}), encoding="utf-8")


def _finished(path):
    path.write_text('<?xml version="1.0"?><nmaprun><runstats>'
                    '<finished exit="success"/></runstats></nmaprun>', encoding="utf-8")


def test_closure_audit_requires_the_expected_authority_not_just_present_files(tmp_path):
    """이 도구가 검출하려는 오류를 스스로 저지르면 안 된다.

    완결된 discovery 하나만 남고 포트 authority 인 sweep 이 통째로 없는데 '확인됨'이라
    하면, PR 이 완결성 게이트에서 고친 '있는 파일만 검사'와 같은 잘못이다.
    """
    import audit_closures

    scans = tmp_path / "scans"
    out = scans / "scan_1"
    _spec_state(out, ["10.0.0.1"])
    _finished(out / "stage0-discovery.xml")          # sweep 산출물은 없다

    mark, why, _spec, _state = audit_closures.scan_evidence(scans, 1)
    assert mark == "확인 불가", why
    assert "stage-tcp-b0.xml" in why

    _finished(out / "stage-tcp-b0.xml")              # 이제 기대 집합이 다 찼다
    assert audit_closures.scan_evidence(scans, 1)[0] == "확인됨"


def test_closure_audit_recognises_selective_rescan_artifacts_as_authority(tmp_path):
    """선택 재스캔은 sweep 이 없고 stage3 가 유일한 근거다 - 반대쪽 오탐도 막는다."""
    import audit_closures

    scans = tmp_path / "scans"
    out = scans / "scan_5"
    out.mkdir(parents=True)
    (out / "spec.json").write_text(json.dumps({
        "targets": ["10.0.0.1"],
        "rescan_units": [{"ip": "10.0.0.1", "port": 53, "proto": "udp"}],
        "stages": {"service": {"enabled": True}},
    }), encoding="utf-8")
    (out / "run-state.json").write_text("{}", encoding="utf-8")

    assert audit_closures.scan_evidence(scans, 5)[0] == "확인 불가"
    _finished(out / "stage3-10_0_0_1-udp53.xml")
    assert audit_closures.scan_evidence(scans, 5)[0] == "확인됨"


def test_closure_audit_does_not_let_one_host_vouch_for_another(tmp_path, capsys):
    """다른 호스트의 완결 XML 하나로 같은 scan 의 모든 닫힘을 확인해 줄 수는 없다."""
    import audit_closures

    scans = tmp_path / "scans"
    out = scans / "scan_1"
    _spec_state(out, ["10.0.0.1"])                   # live 는 .1 뿐
    _finished(out / "stage0-discovery.xml")
    _finished(out / "stage-tcp-b0.xml")
    db = _audit_db(tmp_path, [(1, 1), (2, 1)])       # findings: 10.0.0.1, 10.0.0.2

    rc = audit_closures.main(["--db", str(db), "--scans", str(scans), "--list"])
    out_text = capsys.readouterr().out

    assert rc == 1
    assert "확인됨      1건" in out_text and "확인 불가   1건" in out_text
    assert "10.0.0.2:22/tcp" in out_text             # 범위 밖 호스트가 의심으로 남는다


def test_audit_tools_print_only_characters_a_korean_windows_console_can_encode():
    """번들은 Windows 용이고 기본 코드페이지는 949 다.

    인코딩할 수 없는 글자 하나로 정작 확인해야 할 판정이 traceback 으로 끊긴다.
    실제로 CP949 는 em dash(U+2014)를 표현하지 못한다.
    """
    for name in ("audit_closures.py", "check_scan_xml.py"):
        text = (SCRIPTS_ROOT / name).read_text(encoding="utf-8")
        bad = sorted({ch for ch in text if not _cp949_ok(ch)})
        assert not bad, f"{name}: CP949 로 출력할 수 없는 문자 {bad}"


def _cp949_ok(ch: str) -> bool:
    try:
        ch.encode("cp949")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def test_audit_tools_survive_a_cp949_console(tmp_path, monkeypatch, capsys):
    """CP949 콘솔을 흉내 내 출력이 끝까지 나오는지 - 도구의 결론이 잘리면 안 된다."""
    import audit_closures

    scans = tmp_path / "scans"
    _spec_state(scans / "scan_1", ["10.0.0.1"])
    db = _audit_db(tmp_path, [(1, 1)])

    # 스트림을 보정하지 않는다 - 본문 자체가 CP949 안전해야만 끝까지 나온다.
    class _Cp949Out(io.TextIOWrapper):
        pass

    buffer = io.BytesIO()
    stream = _Cp949Out(buffer, encoding="cp949", errors="strict", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    rc = audit_closures.main(["--db", str(db), "--scans", str(scans)])
    stream.flush()
    printed = buffer.getvalue().decode("cp949")

    assert rc == 1
    assert "이 스크립트는 아무것도 바꾸지 않았습니다." in printed, "결론까지 출력돼야 한다"


def test_closure_audit_never_accepts_our_own_merged_xml_as_evidence(tmp_path):
    """_write_merged_xml 은 원본 실행이 어땠든 늘 exit="success" 를 찍는다.

    그 파일을 완결성 근거로 쓰면 이 도구가 정확히 검출하려는 오류를 스스로 저지른다.
    """
    import audit_closures

    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "scan_9.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="scanops"><runstats>'
        '<finished exit="success"/></runstats></nmaprun>', encoding="utf-8")

    mark, why = audit_closures.scan_evidence(scans, 9)[:2]
    assert mark == "확인 불가" and "병합본" in why

    # 반대 경계 — 진짜 nmap 업로드본은 근거가 된다.
    (scans / "scan_8.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="nmap"><runstats>'
        '<finished exit="success"/></runstats></nmaprun>', encoding="utf-8")
    assert audit_closures.scan_evidence(scans, 8)[0] == "확인됨"


def test_closure_audit_reports_suspects_and_changes_nothing(tmp_path, capsys):
    db = _audit_db(tmp_path, [(1, 1), (2, 2)])
    scans = tmp_path / "scans"
    _spec_state(scans / "scan_1", ["10.0.0.1"])
    _finished(scans / "scan_1" / "stage0-discovery.xml")
    _finished(scans / "scan_1" / "stage-tcp-b0.xml")

    import audit_closures

    before = db.read_bytes()
    rc = audit_closures.main(["--db", str(db), "--scans", str(scans), "--list"])
    out = capsys.readouterr().out

    assert rc == 1                       # 의심 건이 있으면 비영 종료
    assert "확인됨      1건" in out and "확인 불가   1건" in out
    assert "10.0.0.2:22/tcp" in out      # scan_2 는 산출물이 없어 의심
    assert db.read_bytes() == before, "읽기 전용이어야 한다"


def test_allinone_bundle_ships_the_result_inspection_tools(tmp_path):
    """검사 도구는 에어갭에서 쓰라고 만든 것이다 — 번들에 없으면 쓸 수가 없다.

    둘 다 stdlib 전용이라 번들 임베디드 파이썬으로 그대로 돌아간다.
    """
    import importlib.util

    module_path = ROOT / "packaging" / "build_allinone.py"
    spec = importlib.util.spec_from_file_location("scanops_allinone_tools", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = tmp_path / "app"
    app.mkdir()

    module.copy_app(app)
    module.write_launcher(app)

    for name in ("check_scan_xml.py", "audit_closures.py"):
        assert (app / "tools" / name).is_file(), name
    # 도구만 넣고 부를 방법을 안 주면 에어갭 운영자는 그것들이 있는지도 모른다.
    for bat, tool in (("CHECK.bat", "check_scan_xml.py"), ("AUDIT.bat", "audit_closures.py")):
        launcher = (app / bat).read_text(encoding="ascii")
        assert tool in launcher, bat
        assert "runtime\\python\\python.exe" in launcher, bat
        # 한국어 Windows 기본 코드페이지(949)로는 한글 출력이 깨지거나 죽는다.
        # 콘솔과 파이썬 stdout 을 함께 UTF-8 로 고정해야 어긋나지 않는다.
        assert "chcp 65001" in launcher, bat
        assert "PYTHONIOENCODING=utf-8" in launcher, bat

    # 인자 없이 실행하면 번들이 **실제로 쓰는** 경로를 봐야 한다. 도구 기본값은 cwd 기준이라
    # 그대로 두면 'DB 를 찾지 못했습니다' 로 끝난다(config._default_data_dir = 번들 루트/data).
    audit = (app / "AUDIT.bat").read_text(encoding="ascii")
    assert "%~dp0data\\scanops.db" in audit and "%~dp0data\\scans" in audit
    assert "%ARGS%" in audit, "사용자 인자가 있으면 그것으로 덮어써야 한다"
    check = (app / "CHECK.bat").read_text(encoding="ascii")
    assert "%~dp0data\\scans" in check and "%ARGS%" in check


def test_fully_recovered_split_is_not_reported_as_lost_evidence(monkeypatch, tmp_path):
    """묶음이 죽어도 쪼갠 것이 전부 살아나면 얻은 증거는 같다 — 저하가 아니다.

    묶음 이름만 기대하면 완전 복구를 '증거 손실'로 오탐한다. 최초 실패 이력은
    service_retry/service_split 이벤트가 따로 남긴다.
    """
    from scanops.scanning import engine_runner

    ip = "127.0.0.1"
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": False}, "udp": {"enabled": False},
                   "service": {"nse": [], "confirm": False}},
    }
    (tmp_path / "run-state.json").write_text(json.dumps({
        "stages_done": ["discovery"], "open_map": {ip: {"udp": [53, 161]}},
        "live": [ip], "service_done": [], "stop": False,
    }), encoding="utf-8")

    def fake_run(nmap, args, out_base, **_kwargs):
        pspec = args[args.index("-p") + 1].split(":")[1]
        ports = [int(x) for x in pspec.split(",")]
        if len(ports) > 1:                      # 묶음은 두 엔진 모두에서 죽는다
            return {"rc": 7, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            f'<port protocol="udp" portid="{ports[0]}">'
            '<state state="open" reason="udp-response"/>'
            '<service name="t" method="probed"/></port></ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>', encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    Pipeline(JobSpec.from_dict(spec_dict), _Sink(), "nmap").run()

    names = sorted(p.name for p in tmp_path.glob("stage3-*.xml"))
    assert names == ["stage3-127_0_0_1-udp161.xml", "stage3-127_0_0_1-udp53.xml"]
    report = engine_runner.artifact_report(tmp_path, spec_dict)
    assert report["authority_missing"] == [] and report["authority_broken"] == []
    assert report["enrichment_missing"] == [], report
    assert report["enrichment_broken"] == [], report


def test_a_partially_recovered_split_is_still_reported_as_degraded(tmp_path):
    """반대 경계 — 쪼갠 것 중 하나만 살아났으면 증거는 실제로 빠졌다."""
    from scanops.scanning import engine_runner

    ip = "127.0.0.1"
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path),
        "stages": {"service": {"nse": [], "confirm": False}},
    }
    (tmp_path / "run-state.json").write_text(json.dumps({
        "open_map": {ip: {"udp": [53, 161]}}, "live": [ip],
    }), encoding="utf-8")
    (tmp_path / "stage3-127_0_0_1-udp53.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats>'
        '<finished exit="success"/></runstats></nmaprun>', encoding="utf-8")

    report = engine_runner.artifact_report(tmp_path, spec_dict)
    assert report["enrichment_missing"] == ["stage3-127_0_0_1-udp.xml"], report


def test_audit_and_the_production_gate_agree_on_the_rescan_confirm_pass(tmp_path):
    """감사 도구와 운영 게이트가 같은 fixture 에서 같은 판정을 내려야 한다.

    확인 패스는 1차가 빈손일 때만 돈다. 감사가 그걸 안 세면 확인 패스가 실패했던 과거
    재스캔의 닫힘을 정상 근거로 인증하고, 무조건 세면 정상 재스캔을 전부 부재 판정한다.
    """
    import audit_closures
    from scanops.scanning import engine_runner

    ip, port = "10.0.0.1", 53
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path),
        "rescan_units": [{"ip": ip, "port": port, "proto": "udp"}],
        "stages": {"service": {"enabled": True, "confirm": True}},
    }
    scans = tmp_path.parent / "scans"
    out = scans / "scan_3"
    out.mkdir(parents=True)
    (out / "spec.json").write_text(json.dumps(spec_dict), encoding="utf-8")
    (out / "run-state.json").write_text("{}", encoding="utf-8")
    base = out / f"stage3-10_0_0_1-udp{port}.xml"

    def write(path, ports_xml):
        path.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                        f'<address addr="{ip}" addrtype="ipv4"/><ports>{ports_xml}</ports>'
                        '</host><runstats><finished exit="success"/>'
                        '</runstats></nmaprun>', encoding="utf-8")

    # 1차가 완결된 빈 결과 -> 확인 패스가 돌아야 했다. 그 산출물이 없으면 근거가 아니다.
    write(base, "")
    spec_for_gate = dict(spec_dict, out_dir=str(out))
    gate = engine_runner.artifact_report(out, spec_for_gate, force_scanned_hosts=True)
    assert gate["authority_missing"] == [f"stage3-10_0_0_1-udp{port}-confirm.xml"]
    assert audit_closures.scan_evidence(scans, 3)[0] == "확인 불가"

    write(out / f"stage3-10_0_0_1-udp{port}-confirm.xml", "")
    assert engine_runner.artifact_report(out, spec_for_gate, True)["authority_missing"] == []
    assert audit_closures.scan_evidence(scans, 3)[0] == "확인됨"

    # 반대 경계 - 1차에서 서비스를 찾았으면 확인 패스는 애초에 돌지 않는다.
    (out / f"stage3-10_0_0_1-udp{port}-confirm.xml").unlink()
    write(base, f'<port protocol="udp" portid="{port}">'
                '<state state="open" reason="udp-response"/>'
                '<service name="domain" method="probed"/></port>')
    assert engine_runner.artifact_report(out, spec_for_gate, True)["authority_missing"] == []
    assert audit_closures.scan_evidence(scans, 3)[0] == "확인됨"


def test_audit_uses_the_stored_scope_keys_not_a_wider_stage_range(tmp_path, capsys):
    """실행 당시의 정확한 권한 목록이 있으면 근사치로 덮으면 안 된다."""
    import audit_closures

    scans = tmp_path / "scans"
    out = scans / "scan_1"
    out.mkdir(parents=True)
    (out / "spec.json").write_text(json.dumps({
        "targets": ["10.0.0.1"], "batch_size": 256,
        "scanops": {"scope_keys": ["10.0.0.1|22|tcp"]},
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": False}, "service": {"enabled": True}},
    }), encoding="utf-8")
    (out / "run-state.json").write_text(json.dumps({"live": ["10.0.0.1"]}), encoding="utf-8")
    _finished(out / "stage-tcp-b0.xml")

    import sqlite3

    con = sqlite3.connect(tmp_path / "scanops.db")
    con.executescript(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, host_ip TEXT, port INT,"
        " proto TEXT, state TEXT, status TEXT);"
        "CREATE TABLE finding_events (id INTEGER PRIMARY KEY, finding_id INT,"
        " scan_id INT, type TEXT, detail TEXT);"
        "INSERT INTO findings VALUES (1,'10.0.0.1',23,'tcp','closed','정상처리');"
        "INSERT INTO finding_events VALUES (1,1,1,'CLOSED','포트 닫힘');")
    con.commit()
    con.close()

    rc = audit_closures.main(["--db", str(tmp_path / "scanops.db"),
                              "--scans", str(scans), "--list"])
    printed = capsys.readouterr().out

    # 23/tcp 는 저장된 권한 목록에 없다 - 넓은 stage 범위가 그것을 덮으면 안 된다.
    assert rc == 1, printed
    assert "확인 불가   1건" in printed


def test_audit_upload_path_respects_the_scaninfo_port_range(tmp_path):
    """업로드 XML 도 host 만이 아니라 scaninfo 의 실제 포트 범위까지 봐야 한다."""
    import audit_closures

    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "scan_4.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>'
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>', encoding="utf-8")

    mark, _why, _spec, state = audit_closures.scan_evidence(scans, 4)
    assert mark == "확인됨"
    assert audit_closures._upload_covers(state, "10.0.0.1", 22, "tcp") is True
    assert audit_closures._upload_covers(state, "10.0.0.1", 23, "tcp") is False
    assert audit_closures._upload_covers(state, "10.0.0.2", 22, "tcp") is False
    # 범위를 알 수 없는 프로토콜은 넘겨짚지 않는다.
    assert audit_closures._upload_covers(state, "10.0.0.1", 161, "udp") is None


def test_check_tool_reports_a_missing_path_instead_of_a_traceback(tmp_path, capsys):
    """서버를 한 번도 띄우지 않은 새 번들에는 data\\scans 가 아직 없다."""
    import check_scan_xml

    rc = check_scan_xml.main(["check_scan_xml.py", str(tmp_path / "never-created")])

    assert rc == 2
    assert "경로가 없습니다" in capsys.readouterr().out


def test_a_host_that_never_answered_discovery_keeps_its_open_findings(monkeypatch, tmp_path):
    """discovery 미응답은 '포트가 닫혔다'가 아니라 '아무것도 관측하지 못했다'이다.

    live 가 비면 sweep 이 아예 돌지 않는데, 그때 기대 산출물은 discovery 하나뿐이라
    완결성 검사가 **공허하게 통과**한다. 그 상태로 scope_keys 를 닫으면 패킷을 한 번도
    보내지 않은 포트가 전부 '닫힘 + 정상처리'가 된다.
    """
    from scanops.scanning import engine_runner

    ip = "10.0.0.1"
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path), "batch_size": 256,
        "stages": {"discovery": {"mode": "sn"}, "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": False}, "service": {"enabled": True}},
        "scanops": {"scope_keys": [f"{ip}|22|tcp"]},
    }
    calls = []

    def fake_run(nmap, args, out_base, **_kwargs):
        calls.append(args)
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
            '<hosts up="0" down="1" total="1"/></runstats></nmaprun>', encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    Pipeline(JobSpec.from_dict(spec_dict), _Sink(), "nmap").run()

    assert len(calls) == 1, "discovery 만 돌고 sweep 은 호출되지 않는다"
    report = engine_runner.artifact_report(tmp_path, spec_dict)
    assert report["authority_missing"] == [] and report["authority_broken"] == []
    # 완결성은 통과하지만 그 호스트를 관측하지는 않았다 - 닫힘 후보에서 빠져야 한다.
    assert engine_runner.observed_hosts(tmp_path, spec_dict) == set()
    assert engine_runner.observed_scope({f"{ip}|22|tcp"}, tmp_path, spec_dict) == set()


def test_pn_mode_and_a_completed_sweep_do_hold_real_port_authority(monkeypatch, tmp_path):
    """반대 경계 - -Pn 은 대상을 그대로 관측 대상으로 삼는다."""
    from scanops.scanning import engine_runner

    ip = "10.0.0.1"
    spec_dict = {
        "targets": [ip], "out_dir": str(tmp_path), "batch_size": 256,
        "stages": {"discovery": {"mode": "pn"}, "tcp": {"enabled": True, "ports": "22"},
                   "udp": {"enabled": False}, "service": {"enabled": False}},
    }

    def fake_run(nmap, args, out_base, **_kwargs):
        Path(str(out_base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
            '</runstats></nmaprun>', encoding="utf-8")
        return {"rc": 0, "seconds": 0.01, "cmd": [nmap, *args], "stopped": False}

    monkeypatch.setattr(nmaprun, "run", fake_run)
    Pipeline(JobSpec.from_dict(spec_dict), _Sink(), "nmap").run()

    assert engine_runner.observed_hosts(tmp_path, spec_dict) == {ip}
    assert engine_runner.observed_scope({f"{ip}|22|tcp"}, tmp_path, spec_dict) == {f"{ip}|22|tcp"}


def test_audit_treats_an_unswept_host_closure_as_unverifiable(tmp_path):
    """감사도 같은 판단을 해야 한다 - scope_keys 는 관측 증거가 아니다."""
    import audit_closures

    scans = tmp_path / "scans"
    out = scans / "scan_1"
    out.mkdir(parents=True)
    (out / "spec.json").write_text(json.dumps({
        "targets": ["10.0.0.1"], "batch_size": 256,
        "scanops": {"scope_keys": ["10.0.0.1|22|tcp"]},
        "stages": {"discovery": {"mode": "sn"}, "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": False}, "service": {"enabled": True}},
    }), encoding="utf-8")
    (out / "run-state.json").write_text(json.dumps({"live": []}), encoding="utf-8")
    _finished(out / "stage0-discovery.xml")

    _mark, _why, spec, state = audit_closures.scan_evidence(scans, 1)
    assert audit_closures._covers(spec, state, "10.0.0.1", 22, "tcp") is False

    # 반대 경계 - 응답한 호스트는 sweep 을 받았으므로 권한이 있다.
    (out / "run-state.json").write_text(json.dumps({"live": ["10.0.0.1"]}), encoding="utf-8")
    _finished(out / "stage-tcp-b0.xml")
    _mark, _why, spec, state = audit_closures.scan_evidence(scans, 1)
    assert audit_closures._covers(spec, state, "10.0.0.1", 22, "tcp") is True


def test_audit_upload_host_extraction_matches_production_up_hosts(tmp_path):
    """nmap 은 verbose 출력에서 down 호스트도 XML 에 넣는다 - 인입은 그것을 닫지 않는다."""
    import audit_closures
    from scanops.scanning.nmap_parse import up_hosts

    scans = tmp_path / "scans"
    scans.mkdir()
    xml = ('<?xml version="1.0"?><nmaprun scanner="nmap">'
           '<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>'
           '<host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
           '<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/></host>'
           '<runstats><finished exit="success"/></runstats></nmaprun>')
    (scans / "scan_4.xml").write_text(xml, encoding="utf-8")

    _mark, _why, _spec, state = audit_closures.scan_evidence(scans, 4)
    assert set(state["live"]) == up_hosts(xml.encode()), "production 계약과 같아야 한다"
    assert audit_closures._upload_covers(state, "10.0.0.1", 22, "tcp") is False
    assert audit_closures._upload_covers(state, "10.0.0.2", 22, "tcp") is True


def test_closure_audit_bounds_a_legacy_scan_by_the_ports_it_actually_scanned(tmp_path):
    """구형 spec(닫힘 후보 목록 없음)의 판정은 서버 인입과 같은 경계를 써야 한다.

    `scanops.scope_keys` 가 없는 실행은 stages 의 enabled·ports 가 유일한 범위 근거다.
    서버(api/scans._saved_stage_scope)도 같은 값으로 닫힘 후보를 세운다 - 두 쪽이 어긋나면
    감사 결과가 운영 동작을 설명하지 못한다.

    그리고 '범위를 모른다'를 '범위 안'으로 읽어서는 안 된다. _ports 의 None 은 전 포트가
    아니라 해석 실패이고(전 범위는 실제 집합으로 돌아온다), 그것을 확인됨으로 세면 이
    스크립트가 잡아내려는 오류를 스스로 저지르는 셈이다.
    """
    import audit_closures

    state = {"live": ["10.0.0.1"]}
    bounded = {"stages": {"discovery": {"mode": "sn"},
                          "tcp": {"enabled": True, "ports": "443"},
                          "udp": {"enabled": False, "ports": "53"}},
               "targets": ["10.0.0.1"]}
    # 스캔한 포트만 '범위 안'이다.
    assert audit_closures._covers(bounded, state, "10.0.0.1", 443, "tcp") is True
    assert audit_closures._covers(bounded, state, "10.0.0.1", 22, "tcp") is False
    assert audit_closures._covers(bounded, state, "10.0.0.1", 53, "udp") is False

    # 전 포트 스캔은 그 프로토콜 전체에 권한이 있다 - 과잉 보수로 넘어가면 안 된다.
    full = {"stages": {"discovery": {"mode": "sn"},
                       "tcp": {"enabled": True, "ports": "1-65535"},
                       "udp": {"enabled": False, "ports": ""}},
            "targets": ["10.0.0.1"]}
    assert audit_closures._covers(full, state, "10.0.0.1", 8443, "tcp") is True

    # 범위를 해석할 수 없으면 '확인 불가'다. True 도 False 도 아니다.
    unknown = {"stages": {"discovery": {"mode": "sn"},
                          "tcp": {"enabled": True, "ports": ""}},
               "targets": ["10.0.0.1"]}
    assert audit_closures._covers(unknown, state, "10.0.0.1", 443, "tcp") is None


def test_a_fully_recovered_group_does_not_report_its_superseded_artifact(tmp_path):
    """묶음이 죽고 호스트별 대체가 **전부** 살아났으면 증거 손실이 아니다.

    실패한 묶음 coverage 항목을 기대 집합에서 통째로 빼면, 그 파일이 어느 기대치에도 안
    들어가고 '기대 밖 산출물' 을 훑는 마지막 단계가 그것을 손상으로 다시 센다. 결과는
    완전히 복구된 스캔에 `nse_degraded` 와 호스트 없는 `artifact_broken` 이 붙는 것 -
    운영자는 있지도 않은 증거 손실을 쫓게 된다.
    """
    spec = {
        "job_id": 1, "targets": ["10.0.0.1"],
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": False, "ports": ""},
                   "udp": {"enabled": True, "ports": "53,161"},
                   "service": {"enabled": True, "nse": [], "confirm": False}},
    }
    # 묶음 하나가 죽었고(finished=false), 그 자리를 호스트별 실행이 대신했다.
    (tmp_path / "run-state.json").write_text(json.dumps({
        "open_map": {"10.0.0.1": {"udp": [53, 161]}},
        "coverage": [{"role": "enrichment", "artifact": "stage3-udp-b0-g0.xml",
                      "proto": "udp", "finished": False,
                      "hosts": ["10.0.0.1"], "ports": "U:53,161"}],
    }), encoding="utf-8")
    (tmp_path / "stage3-udp-b0-g0.xml").write_text(_TRUNCATED_XML, encoding="utf-8")
    # 대체 실행: 포트별로 쪼개 전부 완결됐다.
    for port in (53, 161):
        (tmp_path / f"stage3-10_0_0_1-udp{port}.xml").write_text(_FINISHED_XML, encoding="utf-8")

    report = engine_runner.artifact_report(tmp_path, spec, force_scanned_hosts=False)
    assert report["enrichment_broken"] == [], (
        f"완전 복구인데 증거 손실로 보고했다: {report['enrichment_broken']}"
    )
    assert report["enrichment_missing"] == []


def test_a_partially_recovered_group_still_reports_what_was_lost(tmp_path):
    """반대 경계 — 대체가 일부만 살아났으면 그 손실은 그대로 남아야 한다.

    대체된 산출물을 '기대 밖' 에서 빼는 것이 손실을 통째로 감추는 쪽으로 넘어가면 안 된다.
    """
    spec = {
        "job_id": 1, "targets": ["10.0.0.1"],
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": False, "ports": ""},
                   "udp": {"enabled": True, "ports": "53,161"},
                   "service": {"enabled": True, "nse": [], "confirm": False}},
    }
    (tmp_path / "run-state.json").write_text(json.dumps({
        "open_map": {"10.0.0.1": {"udp": [53, 161]}},
        "coverage": [{"role": "enrichment", "artifact": "stage3-udp-b0-g0.xml",
                      "proto": "udp", "finished": False,
                      "hosts": ["10.0.0.1"], "ports": "U:53,161"}],
    }), encoding="utf-8")
    (tmp_path / "stage3-udp-b0-g0.xml").write_text(_TRUNCATED_XML, encoding="utf-8")
    (tmp_path / "stage3-10_0_0_1-udp53.xml").write_text(_FINISHED_XML, encoding="utf-8")
    # 161 은 되찾지 못했다.
    (tmp_path / "stage3-10_0_0_1-udp161.xml").write_text(_TRUNCATED_XML, encoding="utf-8")

    report = engine_runner.artifact_report(tmp_path, spec, force_scanned_hosts=False)
    lost = set(report["enrichment_broken"]) | set(report["enrichment_missing"])
    assert lost, "부분 복구인데 손실을 하나도 보고하지 않았다"
    assert any("udp161" in name for name in lost), lost
