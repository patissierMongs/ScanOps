"""Stable scan failure persistence and API feedback."""
from __future__ import annotations

import json
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanops.api import scans as scans_api
from scanops.api.scans import _saved_stage_scope
from scanops.db import SessionLocal
from scanops.models import AuditLog, Finding, FindingEvent, ScanRun
from tests.conftest import make_user, token_for


class _Proc:
    def __init__(self, rc: int):
        self.rc = rc

    def wait(self) -> int:
        return self.rc

    def poll(self) -> int:
        return self.rc


def _headers(client):
    make_user("failure-auditor", "failurepw12", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'failure-auditor', 'failurepw12')}"}


def _scan_with_spec(tmp_path, spec: dict | str) -> int:
    db = SessionLocal()
    try:
        scan = ScanRun(name="failure test", targets="127.0.0.1", status="running")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    text = spec if isinstance(spec, str) else json.dumps(spec)
    (out_dir / "spec.json").write_text(text, encoding="utf-8")
    return scan_id


def _read_scan(scan_id: int) -> ScanRun:
    db = SessionLocal()
    try:
        return db.get(ScanRun, scan_id)
    finally:
        db.close()


@pytest.mark.parametrize("mode", ["chunk", "raw", "staged", "rescan"])
def test_scan_start_routes_turn_thread_start_failure_into_one_terminal_audit(
    client, monkeypatch, tmp_path, mode,
):
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _headers(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda _explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    finding_id = None
    if mode == "rescan":
        db = SessionLocal()
        try:
            finding = Finding(
                finding_key="127.0.0.1|18443|tcp", host_ip="127.0.0.1",
                port=18443, proto="tcp", state="open", service="https",
            )
            db.add(finding)
            db.commit()
            finding_id = finding.id
        finally:
            db.close()

    class FailingThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise OSError(r"C:\private\thread-start-failed")

    monkeypatch.setattr(scans_api.threading, "Thread", FailingThread)
    if mode == "chunk":
        response = client.post("/api/scans/run", headers=headers, json={
            "targets": ["127.0.0.1"], "ports": "18443", "preset": "quick",
        })
    elif mode == "raw":
        response = client.post("/api/scans/run-command", headers=headers, json={
            "command": "nmap -sV -p 18443 127.0.0.1",
        })
    elif mode == "staged":
        response = client.post("/api/scans/run-staged", headers=headers, json={
            "targets": ["127.0.0.1"], "ports": "T:18443", "discovery": "pn",
        })
    else:
        response = client.post("/api/findings/rescan", headers=headers, json={
            "finding_ids": [finding_id],
        })

    assert response.status_code == 500
    assert response.json() == {"detail": "스캔 실행 준비에 실패했습니다."}
    assert "private" not in response.text
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).one()
        assert scan.status == "failed"
        assert scan.failure_code == "launch_setup_failed"
        assert scan.failure_message == "스캔 실행 준비에 실패했습니다."
        assert scan.finished_at is not None
        failed = db.query(AuditLog).filter_by(action="SCAN_RUN", ok=0).all()
        assert len(failed) == 1 and failed[0].target == scan.targets
        assert db.query(AuditLog).filter_by(action="SCAN_RUN", ok=1).count() == 0
        scan_id = scan.id
    finally:
        db.close()

    base = scans_api._basename(scan_id)
    if mode in {"chunk", "raw"}:
        assert not chunker.sidecar_path(base).exists()
        assert not chunker.stop_path(base).exists()
    else:
        out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
        assert not (out_dir / "spec.json").exists()
        assert not (out_dir / "run-state.json").exists()
        assert not (out_dir / "stop-requested").exists()


@pytest.mark.parametrize("mode", ["engine", "raw", "chunk"])
def test_all_resume_branches_turn_thread_start_failure_terminal_and_keep_resume_state(
    client, monkeypatch, tmp_path, mode,
):
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _headers(client)
    db = SessionLocal()
    try:
        scan = ScanRun(name=f"resume {mode}", targets="127.0.0.1", status="canceled")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    base = scans_api._basename(scan_id)
    if mode == "engine":
        out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "spec.json").write_text(json.dumps({
            "targets": ["127.0.0.1"], "exclude": [], "out_dir": str(out_dir),
            "stages": {"tcp": {"ports": "18443"}, "udp": {"ports": ""}},
        }), encoding="utf-8")
        preserved_path = out_dir / "spec.json"
    elif mode == "raw":
        chunker.write_state(base, {
            "raw_argv": ["nmap", "-sV", "127.0.0.1", "-oA", str(base)], "stop": True,
        })
        preserved_path = chunker.sidecar_path(base)
    else:
        chunker.write_state(base, {
            "batches": [["127.0.0.1"]], "cursor": 0, "stop": True,
            "workflow": "manual", "preset": "quick", "ports": "18443", "nse": [],
        })
        preserved_path = chunker.sidecar_path(base)

    class FailingThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise OSError(r"C:\private\resume-thread-start-failed")

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda _explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)
    monkeypatch.setattr(scans_api.threading, "Thread", FailingThread)

    response = client.post(f"/api/scans/{scan_id}/resume", headers=headers)

    assert response.status_code == 500
    assert response.json() == {"detail": "스캔 실행 준비에 실패했습니다."}
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        assert scan.status == "failed" and scan.failure_code == "launch_setup_failed"
        assert scan.finished_at is not None
        assert db.query(AuditLog).filter_by(action="SCAN_RESUME", ok=0).count() == 1
        assert db.query(AuditLog).filter_by(action="SCAN_RESUME", ok=1).count() == 0
    finally:
        db.close()
    assert preserved_path.exists()


def test_single_import_write_failure_is_terminal_sanitized_and_removes_partial_artifacts(
    client, monkeypatch,
):
    headers = _headers(client)
    xml = b"""<?xml version="1.0"?>
<nmaprun start="1893456000">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="18443"/>
  <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="18443"><state state="open"/>
      <service name="unknown" method="table"/></port></ports>
  </host>
</nmaprun>"""
    original_write_bytes = Path.write_bytes

    def fail_merged_snapshot(path: Path, data: bytes) -> int:
        if path.name.startswith("scan_") and path.name.endswith(".xml") \
                and ".tcp_discovery." not in path.name:
            raise OSError(r"C:\private\disk-full")
        return original_write_bytes(path, data)

    monkeypatch.setattr(Path, "write_bytes", fail_merged_snapshot)

    response = client.post(
        "/api/scans/import",
        headers=headers,
        files={"file": ("partial.tcp_discovery.xml", xml, "text/xml")},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "XML 가져오기에 실패했습니다."}
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).order_by(ScanRun.id.desc()).one()
        assert scan.status == "failed"
        assert scan.finished_at is not None
        assert scan.failure_code == "import_failed"
        assert scan.failure_message == "XML 가져오기에 실패했습니다."
        assert "private" not in scan.failure_message
        assert scan.raw_xml_path == ""
        scan_id = scan.id
    finally:
        db.close()
    assert not (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").exists()
    assert not (
        scans_api._settings.scans_dir / f"scan_{scan_id}.tcp_discovery.xml"
    ).exists()


def test_single_import_ingest_failure_rolls_back_findings_and_removes_raw_xml(
    client, monkeypatch,
):
    from scanops.api import assets as assets_api

    headers = _headers(client)
    xml = b"""<?xml version="1.0"?>
<nmaprun start="1893456000">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="18443"/>
  <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="18443"><state state="open"/>
      <service name="http" product="Uvicorn" version="0.30" method="probed"/></port></ports>
  </host>
</nmaprun>"""

    def fail_after_finding_ingest(*_args, **_kwargs):
        raise OSError(r"C:\private\asset-match-failed")

    monkeypatch.setattr(assets_api, "match_assets", fail_after_finding_ingest)

    response = client.post(
        "/api/scans/import",
        headers=headers,
        files={"file": ("ordinary.xml", xml, "text/xml")},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "XML 가져오기에 실패했습니다."}
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).one()
        assert scan.status == "failed" and scan.failure_code == "import_failed"
        assert db.query(Finding).count() == 0
        assert db.query(FindingEvent).count() == 0
        scan_id = scan.id
    finally:
        db.close()
    assert not (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").exists()


def test_staged_ingest_failure_is_atomic_and_removes_merged_snapshot(
    monkeypatch, tmp_path,
):
    from scanops.api import assets as assets_api

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "out_dir": str(tmp_path / "ignored"),
    })
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["job"], "live": ["127.0.0.1"],
    }), encoding="utf-8")
    (out_dir / "stage3-127_0_0_1-tcp.xml").write_text("""<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="18443"><state state="open"/>
    <service name="http" product="Uvicorn" version="0.30" method="probed"/></port></ports>
</host></nmaprun>""", encoding="utf-8")
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: _Proc(0))

    def fail_after_finding_ingest(*_args, **_kwargs):
        raise OSError(r"C:\private\asset-match-failed")

    monkeypatch.setattr(assets_api, "match_assets", fail_after_finding_ingest)

    scans_api._engine_worker(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        assert scan.status == "failed" and scan.failure_code == "engine_ingest_failed"
        assert scan.raw_xml_path == ""
        assert scan.host_count == 0 and scan.port_count == 0
        assert db.query(Finding).count() == 0
        assert db.query(FindingEvent).count() == 0
    finally:
        db.close()
    assert not (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").exists()


def test_chunk_ingest_failure_rolls_back_batch_and_sets_terminal_failure(
    monkeypatch, tmp_path,
):
    from scanops.api import assets as assets_api
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    db = SessionLocal()
    try:
        scan = ScanRun(name="atomic batch", targets="127.0.0.1", status="running")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    base = scans_api._basename(scan_id)
    chunker.write_state(base, {
        "batches": [["127.0.0.1"]], "cursor": 0, "stop": False,
        "workflow": "manual", "preset": "quick", "ports": "18443", "nse": [],
    })
    xml = b"""<?xml version="1.0"?>
<nmaprun><scaninfo type="syn" protocol="tcp" numservices="1" services="18443"/>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="18443"><state state="open"/>
    <service name="http" product="Uvicorn" version="0.30" method="probed"/></port></ports>
</host></nmaprun>"""

    def fake_popen(argv, _log_path):
        output_base = Path(argv[argv.index("-oA") + 1])
        Path(f"{output_base}.xml").write_bytes(xml)
        return _Proc(0)

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda _explicit="": "nmap")
    monkeypatch.setattr(scans_api.nmap_runner, "popen", fake_popen)
    monkeypatch.setattr(scans_api, "_wait_scan_process",
                        lambda _scan_id, _proc, _watchdog=0, _out_base=None: 0)
    monkeypatch.setattr(
        assets_api, "match_assets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(r"C:\private\asset-match-failed")
        ),
    )

    scans_api._chunk_worker(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        assert scan.status == "failed" and scan.failure_code == "result_ingest_failed"
        assert scan.host_count == 0 and scan.port_count == 0
        assert db.query(Finding).count() == 0
        assert db.query(FindingEvent).count() == 0
    finally:
        db.close()
    assert chunker.read_state(base)["cursor"] == 0


def test_engine_cli_failure_is_persisted_sanitized_and_does_not_close_finding(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    key = "127.0.0.1|18443|tcp"
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        db.add(Finding(
            finding_key=key, host_ip="127.0.0.1", port=18443, proto="tcp",
            state="open", service="https", first_scan_id=initial.id, last_scan_id=initial.id,
        ))
        db.commit()
    finally:
        db.close()
    scan_id = _scan_with_spec(tmp_path, {
        "out_dir": str(tmp_path / "scans" / "ignored"),
        "rescan_units": [{"ip": "127.0.0.1", "port": 18443, "proto": "tcp"}],
        "scanops": {"scope_keys": [key]},
    })
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    (out_dir / "events.ndjson").write_text("\n".join([
        json.dumps({"event": "stage_start", "stage": "service"}),
        json.dumps({
            "event": "error", "stage": "service", "rc": 7,
            "cmd": "nmap --script secret C:\\private\\scan.xml",
        }),
        json.dumps({
            "event": "job_done", "status": "failed", "seconds": 0.2,
            "counts": {"errors": 1},
        }),
    ]), encoding="utf-8")
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: _Proc(1))

    scans_api._engine_worker(scan_id)

    scan = _read_scan(scan_id)
    assert scan.status == "failed"
    assert scan.failure_code == "engine_failed"
    assert scan.failure_message == "단계 스캔 중 오류가 발생했습니다."
    assert "private" not in scan.failure_message and "nmap" not in scan.failure_message
    db = SessionLocal()
    try:
        assert db.query(Finding).filter_by(finding_key=key).one().state == "open"
    finally:
        db.close()

    headers = _headers(client)
    detail = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["failure_code"] == "engine_failed"
    stages = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert stages.status_code == 200
    payload = stages.json()
    assert payload["status"] == payload["overall"]["status"] == "failed"
    assert payload["failure_message"] == scan.failure_message
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "private" not in serialized and "--script" not in serialized
    assert payload["stages"][0]["error"] == "서비스 식별 단계 실행에 실패했습니다."


def test_backend_stops_engine_by_sentinel_and_nonzero_stop_becomes_canceled(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"],
        "out_dir": str(tmp_path / "scans" / "ignored"),
    })
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    started = threading.Event()

    class EngineProcess:
        rc = 9

        def wait(self):
            assert scan_id not in scans_api._PROCS
            started.set()
            deadline = time.monotonic() + 5
            while not (out_dir / "stop-requested").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert (out_dir / "stop-requested").exists()
            return self.rc

        def poll(self):
            return self.rc

        def terminate(self):
            raise AssertionError("backend must not terminate the staged engine process directly")

    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: EngineProcess())
    worker = threading.Thread(target=scans_api._engine_worker, args=(scan_id,))
    worker.start()
    assert started.wait(timeout=2)

    response = client.post(f"/api/scans/{scan_id}/stop", headers=_headers(client))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "canceling"
    worker.join(timeout=5)

    assert not worker.is_alive()
    scan = _read_scan(scan_id)
    assert scan.status == "canceled"
    assert scan.failure_code == "" and scan.failure_message == ""


def test_engine_spawn_and_ingest_failures_have_distinct_stable_codes(monkeypatch, tmp_path):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    base_spec = {"targets": ["127.0.0.1"], "out_dir": str(tmp_path)}

    spawn_scan = _scan_with_spec(tmp_path, base_spec)

    def fail_spawn(*_args):
        raise OSError(r"C:\private\engine.exe could not start")

    monkeypatch.setattr(scans_api.engine_runner, "spawn", fail_spawn)
    scans_api._engine_worker(spawn_scan)
    spawn_result = _read_scan(spawn_scan)
    assert spawn_result.failure_code == "engine_launch_failed"
    assert "private" not in spawn_result.failure_message

    ingest_scan = _scan_with_spec(tmp_path, base_spec)
    ingest_dir = tmp_path / "scans" / f"scan_{ingest_scan}"
    (ingest_dir / "run-state.json").write_text(
        json.dumps({"stages_done": ["job"]}), encoding="utf-8",
    )
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: _Proc(0))

    def fail_ingest(*_args, **_kwargs):
        raise RuntimeError(r"C:\private\result.xml failed")

    monkeypatch.setattr(scans_api.engine_runner, "ingest_results", fail_ingest)
    scans_api._engine_worker(ingest_scan)
    ingest_result = _read_scan(ingest_scan)
    assert ingest_result.failure_code == "engine_ingest_failed"
    assert "private" not in ingest_result.failure_message


def test_engine_worker_wait_exception_closes_process_and_persists_safe_failure(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "out_dir": str(tmp_path),
    })

    class BrokenWaitProcess:
        def wait(self):
            raise RuntimeError(r"C:\private\worker interrupted")

    process = BrokenWaitProcess()
    closed = []
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: process)
    monkeypatch.setattr(
        scans_api.engine_runner, "close_owned", lambda proc: closed.append(proc),
    )

    scans_api._engine_worker(scan_id)

    assert closed == [process]
    scan = _read_scan(scan_id)
    assert scan.status == "failed" and scan.finished_at is not None
    assert scan.failure_code == "engine_wait_failed"
    assert scan.failure_message == "단계 스캔 엔진의 종료 상태를 확인하지 못했습니다."
    assert "private" not in scan.failure_message.lower()

    headers = _headers(client)
    scan_response = client.get(f"/api/scans/{scan_id}", headers=headers)
    stages_response = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert scan_response.status_code == stages_response.status_code == 200
    assert scan_response.json()["failure_code"] == "engine_wait_failed"
    stages = stages_response.json()
    assert stages["status"] == stages["overall"]["status"] == "failed"
    assert stages["failure_code"] == "engine_wait_failed"
    assert "private" not in scan_response.text.lower()
    assert "private" not in stages_response.text.lower()


def test_engine_timeline_persistence_exception_is_terminal_and_sanitized(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "out_dir": str(tmp_path),
    })
    process = _Proc(0)
    closed = []
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: process)
    monkeypatch.setattr(
        scans_api.engine_runner, "close_owned", lambda proc: closed.append(proc),
    )

    def fail_persist(*_args):
        raise OSError(r"C:\private\events.ndjson cannot be read")

    monkeypatch.setattr(scans_api, "_persist_stages", fail_persist)

    scans_api._engine_worker(scan_id)

    assert closed == [process]
    scan = _read_scan(scan_id)
    assert scan.status == "failed" and scan.finished_at is not None
    assert scan.failure_code == "engine_timeline_failed"
    assert scan.failure_message == "단계 스캔 진행 기록을 처리하지 못했습니다."
    assert "private" not in scan.failure_message.lower()

    headers = _headers(client)
    scan_response = client.get(f"/api/scans/{scan_id}", headers=headers)
    stages_response = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert scan_response.status_code == stages_response.status_code == 200
    assert scan_response.json()["failure_code"] == "engine_timeline_failed"
    stages = stages_response.json()
    assert stages["status"] == stages["overall"]["status"] == "failed"
    assert stages["failure_code"] == "engine_timeline_failed"
    assert "private" not in scan_response.text.lower()
    assert "private" not in stages_response.text.lower()


def test_engine_process_cleanup_exception_is_terminal_and_sanitized(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "out_dir": str(tmp_path),
    })
    process = _Proc(0)
    monkeypatch.setattr(scans_api.engine_runner, "spawn", lambda *_args: process)

    def fail_cleanup(proc):
        assert proc is process
        raise OSError(r"C:\private\engine process tree cannot close")

    monkeypatch.setattr(scans_api.engine_runner, "close_owned", fail_cleanup)

    scans_api._engine_worker(scan_id)

    scan = _read_scan(scan_id)
    assert scan.status == "failed" and scan.finished_at is not None
    assert scan.failure_code == "engine_cleanup_failed"
    assert scan.failure_message == "단계 스캔 엔진을 안전하게 종료하지 못했습니다."
    assert "private" not in scan.failure_message.lower()

    headers = _headers(client)
    scan_response = client.get(f"/api/scans/{scan_id}", headers=headers)
    stages_response = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert scan_response.status_code == stages_response.status_code == 200
    assert scan_response.json()["failure_code"] == "engine_cleanup_failed"
    stages = stages_response.json()
    assert stages["status"] == stages["overall"]["status"] == "failed"
    assert stages["failure_code"] == "engine_cleanup_failed"
    assert "private" not in scan_response.text.lower()
    assert "private" not in stages_response.text.lower()


@pytest.mark.parametrize(("status", "failure_code"), [
    ("failed", "engine_wait_failed"),
    ("failed", "engine_cleanup_failed"),
    ("failed", "engine_timeline_failed"),
    ("failed", "engine_ingest_failed"),
    ("interrupted", "server_restarted"),
])
def test_resume_finalizes_completed_engine_output_without_rerunning_nmap(
    client, monkeypatch, tmp_path, status, failure_code,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _headers(client)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"],
        "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {
            # -Pn 이면 엔진이 discovery nmap 을 돌리지 않는다(산출물도 없다).
            "discovery": {"mode": "pn"},
            "tcp": {"enabled": False, "ports": ""},
            "udp": {"enabled": False, "ports": ""},
        },
        "scanops": {"scope_keys": []},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["job"],
        "live": ["127.0.0.1"],
        "open_map": {},
        "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        "\n".join(json.dumps(event) for event in [
            {"event": "stage_start", "stage": "discovery"},
            {"event": "stage_done", "stage": "discovery", "counts": {"live": 1}},
            {"event": "job_done", "status": "done", "counts": {"live": 1}},
        ]) + "\n",
        encoding="utf-8",
    )
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scan.status = status
        scan.failure_code = failure_code
        scan.failure_message = scans_api._FAILURE_MESSAGES[failure_code]
        db.commit()
    finally:
        db.close()

    checked_scope = []
    monkeypatch.setattr(
        scans_api.scope, "check_scope", lambda hosts: checked_scope.append(list(hosts)),
    )

    def unexpected_execution(*_args, **_kwargs):
        pytest.fail("completed-output recovery must not invoke the engine or Nmap")

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", unexpected_execution)
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", unexpected_execution)
    monkeypatch.setattr(scans_api.engine_runner, "spawn", unexpected_execution)
    finalized = []

    def finalize_existing(db, scan, actual_out_dir, scope_keys, force_scanned_hosts, spec=None):
        finalized.append((actual_out_dir, scope_keys, force_scanned_hosts))
        scan.host_count = 1
        scan.port_count = 0
        db.flush()
        return {}

    monkeypatch.setattr(scans_api, "_commit_engine_ingest", finalize_existing)

    class ImmediateThread:
        def __init__(self, target, args=(), **_kwargs):
            self.target = target
            self.args = args

        def start(self):
            self.target(*self.args)

    monkeypatch.setattr(scans_api.threading, "Thread", ImmediateThread)

    response = client.post(f"/api/scans/{scan_id}/resume", headers=headers)

    assert response.status_code == 200, response.text
    assert checked_scope == [["127.0.0.1"]]
    assert finalized == [(out_dir, set(), False)]
    scan = _read_scan(scan_id)
    assert scan.status == "done" and scan.finished_at is not None
    assert scan.failure_code == "" and scan.failure_message == ""
    assert scan.host_count == 1 and scan.port_count == 0
    assert [stage["stage"] for stage in scan.stages_json] == ["discovery"]


def test_resume_never_reingests_a_done_scan_with_a_stale_recoverable_failure_code(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _headers(client)
    scan_id = _scan_with_spec(tmp_path, {})
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(
        json.dumps({"stages_done": ["job"]}), encoding="utf-8",
    )
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scan.status = "done"
        scan.failure_code = "engine_wait_failed"
        scan.failure_message = scans_api._FAILURE_MESSAGES["engine_wait_failed"]
        db.commit()
    finally:
        db.close()

    response = client.post(f"/api/scans/{scan_id}/resume", headers=headers)

    assert response.status_code == 400
    assert response.json()["detail"] == "이미 모든 단계가 완료되었습니다."


def test_completed_engine_finalize_thread_failure_keeps_recovery_retryable(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _headers(client)
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"],
        "exclude": [],
        "stages": {"tcp": {"ports": ""}, "udp": {"ports": ""}},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(
        json.dumps({"stages_done": ["job"], "stop": False}), encoding="utf-8",
    )
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scan.status = "failed"
        scan.failure_code = "engine_ingest_failed"
        scan.failure_message = scans_api._FAILURE_MESSAGES["engine_ingest_failed"]
        db.commit()
    finally:
        db.close()

    class FailingThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise OSError(r"C:\private\finalize-thread-start-failed")

    monkeypatch.setattr(scans_api.threading, "Thread", FailingThread)
    response = client.post(f"/api/scans/{scan_id}/resume", headers=headers)

    assert response.status_code == 500
    assert response.json() == {"detail": "스캔 실행 준비에 실패했습니다."}
    scan = _read_scan(scan_id)
    assert scan.status == "failed"
    assert scan.failure_code == "engine_ingest_failed"
    assert scan.failure_message == scans_api._FAILURE_MESSAGES["engine_ingest_failed"]
    assert (out_dir / "spec.json").exists()
    assert scans_api.engine_runner.is_done(out_dir)


def test_invalid_engine_spec_fails_before_spawn_and_resume_message_is_path_free(
    client, monkeypatch, tmp_path,
):
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, "{broken-json")
    spawned = []
    monkeypatch.setattr(
        scans_api.engine_runner, "spawn", lambda *_args: spawned.append(True) or _Proc(0),
    )

    scans_api._engine_worker(scan_id)

    scan = _read_scan(scan_id)
    assert scan.failure_code == "engine_spec_invalid"
    assert spawned == []
    headers = _headers(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    response = client.post(f"/api/scans/{scan_id}/resume", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "저장된 단계 스캔 설정을 해석하지 못했습니다."
    assert str(tmp_path) not in response.text


@pytest.mark.parametrize("engine_case", [
    "missing",
    "partial",
    "unreadable",
    "unimportable",
    "entrypoint_syntax_error",
    "entrypoint_import_error",
])
def test_unusable_packaged_engine_is_rejected_before_scan_record(
    client, monkeypatch, tmp_path, engine_case,
):
    headers = _headers(client)
    engine_dir = tmp_path / "engine"
    package = engine_dir / "scanops_engine"
    unreadable = None
    if engine_case != "missing":
        source_package = Path(__file__).resolve().parents[2] / "engine" / "scanops_engine"
        shutil.copytree(source_package, package)
        if engine_case == "partial":
            (package / "pipeline.py").unlink()
        elif engine_case == "unreadable":
            unreadable = package / "pipeline.py"
        elif engine_case == "unimportable":
            (package / "__init__.py").write_text(
                r'raise RuntimeError("C:\private\broken engine")' + "\n",
                encoding="utf-8",
            )
        elif engine_case == "entrypoint_syntax_error":
            (package / "__main__.py").write_text(
                "if True print('broken')\n",
                encoding="utf-8",
            )
        elif engine_case == "entrypoint_import_error":
            (package / "__main__.py").write_text(
                "from .missing_entrypoint import main\n",
                encoding="utf-8",
            )
    monkeypatch.setattr(scans_api.engine_runner._settings, "engine_dir", engine_dir)
    if unreadable is not None:
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if path == unreadable:
                raise PermissionError(r"C:\private\engine denied")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", guarded_open)
    db = SessionLocal()
    try:
        before = db.query(ScanRun).count()
    finally:
        db.close()

    response = client.post("/api/scans/run-staged", headers=headers, json={
        "targets": ["127.0.0.1"], "ports": "T:18443", "discovery": "pn",
    })

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "스캔 엔진 구성요소가 누락되었거나 손상되었습니다. 배포 패키지를 다시 설치하세요."
    )
    assert str(tmp_path) not in response.text
    assert "private" not in response.text.lower()
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == before
    finally:
        db.close()


def test_progress_api_never_exposes_raw_nmap_log_lines(client, tmp_path):
    log_path = tmp_path / "private-scan.log"
    log_path.write_text(
        "Stats: 0:00:10 elapsed; 1 hosts completed (1 up), 1 undergoing Service Scan\n"
        "Service scan Timing: About 50.00% done; ETC: 12:00 (0:00:10 remaining)\n"
        r"ERROR reading C:\private\targets.txt --script secret-script" + "\n",
        encoding="utf-8",
    )
    db = SessionLocal()
    try:
        scan = ScanRun(
            name="progress sanitized", status="running", log_path=str(log_path),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    response = client.get(f"/api/scans/{scan_id}/progress", headers=_headers(client))

    assert response.status_code == 200
    payload = response.json()
    assert "last_line" not in payload
    assert "private" not in response.text and "secret-script" not in response.text
    assert payload["percent"] == 50.0


@pytest.mark.parametrize(("stop_requested", "expected_status", "expected_code"), [
    (True, "canceled", ""),
    (False, "failed", "nmap_failed"),
])
def test_auto_worker_distinguishes_requested_stop_from_nmap_failure(
    monkeypatch, tmp_path, stop_requested, expected_status, expected_code,
):
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.scans_dir.mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        scan = ScanRun(name="auto stop race", targets="127.0.0.1", status="running")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    base = scans_api._basename(scan_id)
    chunker.write_state(base, {
        "batches": [["127.0.0.1"]], "cursor": 0, "stop": False, "workflow": "auto",
    })
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")

    def terminated_stage(*_args, **_kwargs):
        if stop_requested:
            state = chunker.read_state(base)
            state["stop"] = True
            chunker.write_state(base, state)
        raise scans_api._WorkerFailure("nmap_failed")

    monkeypatch.setattr(scans_api, "_run_auto_batch", terminated_stage)
    scans_api._chunk_worker(scan_id)

    result = _read_scan(scan_id)
    assert result.status == expected_status
    assert result.failure_code == expected_code
    assert chunker.read_state(base)["cursor"] == 0


def test_socket_errors_in_the_engine_log_do_not_cancel_closure_candidates(
    client, monkeypatch, tmp_path,
):
    """엔진 로그의 NSE/소켓 오류가 닫힘 후보를 통째로 지우면 안 된다.

    실측(Windows, nmap 7.99/Npcap 1.87)에서 `ike-version` 은 `Bind to 0.0.0.0:500 failed
    (10013)` 을 네 번 찍고도 "Nmap done" 과 rc=0 으로 끝났다 — 스크립트 소켓 하나가 실패했을
    뿐 포트 관측은 온전했다. 그런 실행에서 닫힘 후보를 비우면 이미 사라진 서비스가 영영
    닫히지 않아 오탐이 쌓인다. 사실은 failure_message 로 남기되 관측 권한은 지킨다."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    scope_key = "127.0.0.1|161|udp"
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": False, "ports": ""},
                   "udp": {"enabled": True, "ports": "161"}},
        "scanops": {"scope_keys": [scope_key]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["job"], "live": ["127.0.0.1"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    (out_dir / "engine.log").write_text(
        "NSOCK ERROR mksock_bind_addr(): Bind to 0.0.0.0:500 failed (IOD#4) (10013)\n"
        "Nmap done: 1 IP address (1 host up) scanned in 5.43 seconds\n",
        encoding="utf-8")
    # 포트 관측 자체는 온전히 끝났다 — 소켓 오류는 그 사실을 부정하지 않는다.
    (out_dir / "stage-udp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")

    seen: list[set] = []

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts, spec=None):
        seen.append(set(scope_keys))
        scan.host_count, scan.port_count = 1, 0
        db.flush()
        return {}

    monkeypatch.setattr(scans_api, "_commit_engine_ingest", capture)
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    # 닫힘 후보가 살아 있어야 한다 — 여기가 이번 회귀의 핵심.
    assert seen == [{scope_key}]
    scan = _read_scan(scan_id)
    assert scan.status == "done"
    # 사실 자체는 사라지지 않는다: 스크립트 결과를 다 믿지 말라는 신호로 남는다.
    assert scan.failure_code == "nse_degraded"
    assert "포트 결과는 온전" in scan.failure_message


def test_a_truncated_engine_xml_never_grants_closure(client, monkeypatch, tmp_path):
    """rc=0 · stages_done=["job"] 이어도 XML 이 끝맺히지 않았으면 닫으면 안 된다.

    엔진 파서(collect_results)는 XML 이 없거나 ParseError 면 그 파일을 빈 목록으로 넘긴다.
    그래서 nmap 이 XML 을 끝맺지 못한 채 죽어도 job 은 done 으로 마감되고, 이어지는 인입은
    '관측 0건'을 정상적인 미관측으로 받아 scope 안의 열린 Finding 을 닫는다. 닫힘은 상태까지
    '정상처리'로 바꾸므로 되돌리기 가장 어려운 미탐이 된다 — 단독 스캐너와 같은 계약
    (파싱 가능 + <finished exit="success">)을 웹 경로에도 건다."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    scope_key = "127.0.0.1|443|tcp"
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""}},
        "scanops": {"scope_keys": [scope_key]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["127.0.0.1"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    # 실제 사고 파일과 같은 모양 — nmap 이 </nmaprun> 을 쓰지 못하고 죽었다.
    (out_dir / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>', encoding="utf-8")

    seen: list[set] = []

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts, spec=None):
        seen.append(set(scope_keys))
        scan.host_count, scan.port_count = 1, 0
        db.flush()
        return {}

    monkeypatch.setattr(scans_api, "_commit_engine_ingest", capture)
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    assert seen == [set()], "잘린 XML 은 닫힘 후보를 하나도 넘기지 않는다"
    scan = _read_scan(scan_id)
    assert scan.status == "partial"
    assert scan.failure_code == "nmap_xml_incomplete"
    assert "stage-tcp-b0.xml" in scan.failure_message


def test_a_completed_engine_xml_keeps_its_closure_scope(client, monkeypatch, tmp_path):
    """반대 경계 — 끝맺힌 XML 은 닫힘 후보를 그대로 유지한다(과잉 보수 방지)."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    scope_key = "127.0.0.1|443|tcp"
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""}},
        "scanops": {"scope_keys": [scope_key]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["127.0.0.1"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    (out_dir / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")

    seen: list[set] = []

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts, spec=None):
        seen.append(set(scope_keys))
        scan.host_count, scan.port_count = 1, 0
        db.flush()
        return {}

    monkeypatch.setattr(scans_api, "_commit_engine_ingest", capture)
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    assert seen == [{scope_key}]
    scan = _read_scan(scan_id)
    assert scan.status == "done" and scan.failure_code == ""


def test_an_old_spec_without_scope_keys_still_ingests_host_wide(client, monkeypatch, tmp_path):
    """scope_keys 가 없는 저장 spec(구버전)은 host-wide 닫힘이라는 뜻이다 — None 은 빈 집합이 아니다.

    `scanops.scope_keys` 가 spec 에 없으면 워커는 scope_keys 를 None 으로 두고,
    `_commit_engine_ingest` 가 그 뜻으로 분기해 산출물에서 뽑은 scanned_hosts 로 범위를
    세운다(_auto_scope_keys). 그 사이에 낀 관측 필터가 None 을 그냥 순회하면
    `TypeError: 'NoneType' object is not iterable` 로 워커가 통째로 죽어, 정상 완료된 실행이
    engine_ingest_failed + raw_xml_path 삭제로 사라진다 — 살릴 수 있는 결과를 버리는 일이다.
    반대로 None 을 set() 으로 바꿔 넘기면 이번엔 인입이 닫힘을 아예 못 해 기존 오탐이 쌓인다.
    그래서 이 경계는 **실제 _commit_engine_ingest 를 태워** 끝까지 인입되는지로 고정한다.

    그리고 '살린다'가 곧 '전부 닫아도 된다'는 뜻은 아니다. 구형 spec 에는 닫힘 후보 목록이
    없을 뿐 **무엇을 스캔하기로 했는지**(stages.tcp/udp 의 enabled·ports)는 남아 있다. 그
    경계를 버리고 host 단위로 닫으면 이번엔 스캔한 적도 없는 포트가 '닫힘 + 정상처리'로
    인증된다 - 이 PR 이 내내 막아 온 바로 그 미탐이라, 여기서 함께 고정한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    db = SessionLocal()
    try:
        prior = ScanRun(name="prior", status="done")
        db.add(prior)
        db.commit()
        for key, port, proto in (("127.0.0.1|443|tcp", 443, "tcp"),
                                 ("127.0.0.1|22|tcp", 22, "tcp"),
                                 ("127.0.0.1|53|udp", 53, "udp")):
            db.add(Finding(
                finding_key=key, host_ip="127.0.0.1", port=port, proto=proto,
                state="open", first_scan_id=prior.id, last_scan_id=prior.id,
            ))
        db.commit()
    finally:
        db.close()
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
        # scanops 키 자체가 없다 — 이 PR 이전에 저장된 spec 의 모양.
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["127.0.0.1"],
        "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    # 443 이 이번엔 열려 있지 않다 — 범위 안이므로 닫혀야 한다.
    (out_dir / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")

    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    scan = _read_scan(scan_id)
    assert scan.status == "done", "구형 spec 은 여전히 정상 완료로 인입돼야 한다"
    assert scan.failure_code == ""
    assert scan.raw_xml_path, "결과 XML 을 지우고 실패로 마감하면 안 된다"
    db = SessionLocal()
    try:
        rows = {f.finding_key: f for f in
                db.query(Finding).filter(Finding.host_ip == "127.0.0.1").all()}
        # 스캔하기로 한 포트는 닫힌다 — 구형 결과도 닫힘 권한을 잃지 않는다.
        assert rows["127.0.0.1|443|tcp"].state == "closed"
        assert rows["127.0.0.1|443|tcp"].status == "정상처리"
        # 스캔하지 않은 포트는 건드리지 않는다. spec 에 닫힘 후보 목록이 없다는 것은
        # '무엇을 스캔했는지 모른다'가 아니라 '목록만 없다'는 뜻이다 - stages 의
        # enabled·ports 가 그 경계를 그대로 들고 있다.
        assert rows["127.0.0.1|22|tcp"].state == "open", "포트 범위 밖을 닫으면 안 된다"
        assert rows["127.0.0.1|53|udp"].state == "open", "비활성 프로토콜을 닫으면 안 된다"
        for key in ("127.0.0.1|22|tcp", "127.0.0.1|53|udp"):
            events = db.query(FindingEvent).filter(
                FindingEvent.finding_id == rows[key].id).all()
            assert not events, f"{key} 는 audit history 도 건드리지 않아야 한다"
    finally:
        db.close()


def test_unobserved_scope_and_degraded_enrichment_are_both_reported(
    client, monkeypatch, tmp_path,
):
    """미관측 scope 와 NSE 저하는 **다른 축**이라, 겹쳤을 때 둘 다 보여야 한다.

    이전에는 `if unobserved and not degraded` 라서 두 사실이 함께 일어나면 미관측이 통째로
    가려지고, 화면에는 "포트 결과는 온전하지만 스크립트 결과는 일부 빠졌을 수 있습니다" 만
    남았다 — 실제로는 그 호스트의 포트를 아예 못 봤는데 정반대로 읽히는 문구다. 코드는 더
    무거운 사실(포트 미관측)을 가리키고 메시지는 두 사실을 모두 실어야 한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    seen_key, unseen_key = "127.0.0.1|443|tcp", "127.0.0.2|443|tcp"
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["127.0.0.1", "127.0.0.2"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "sn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
        "scanops": {"scope_keys": [seen_key, unseen_key]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    # 127.0.0.2 는 discovery 에 응답하지 않아 live 에 없다 → sweep 이 아예 돌지 않았다.
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["127.0.0.1"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    for name in ("stage0-discovery.xml", "stage-tcp-b0.xml"):
        (out_dir / name).write_text(
            '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
            '<hosts up="1" down="1" total="2"/></runstats></nmaprun>', encoding="utf-8")
    # 동시에 NSE 소켓 오류도 있었다 — 저하 축.
    (out_dir / "engine.log").write_text(
        "NSOCK ERROR mksock_bind_addr(): Bind to 0.0.0.0:500 failed (IOD#4) (10013)\n",
        encoding="utf-8")

    seen: list[set] = []

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts, spec=None):
        seen.append(set(scope_keys))
        scan.host_count, scan.port_count = 1, 0
        db.flush()
        return {}

    monkeypatch.setattr(scans_api, "_commit_engine_ingest", capture)
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    # 못 본 호스트의 발견은 닫힘 후보에서 빠진다.
    assert seen == [{seen_key}]
    scan = _read_scan(scan_id)
    assert scan.status == "done"
    assert scan.failure_code == "observation_incomplete"
    assert "관측하지 못했습니다" in scan.failure_message
    assert "NSE" in scan.failure_message, "저하 사실이 미관측에 묻히면 안 된다"
    # 정반대 문구가 남으면 안 된다.
    assert "포트 결과는 온전" not in scan.failure_message


def test_an_old_full_port_spec_still_closes_everything_it_scanned(client, monkeypatch, tmp_path):
    """반대 경계 — 구형 spec 을 포트 범위로 묶는 것이 '구형은 안 닫는다'가 되면 안 된다.

    범위를 적용하는 수정은 과잉 보수로 넘어가기 쉽다. 전 포트 TCP 스캔은 실제로 65535 포트를
    다 봤으므로 그 프로토콜의 모든 발견에 닫힘 권한이 있다(_port_scope 가 전 범위를 None 으로
    돌려주는 이유). 여기서 닫지 못하면 이미 사라진 서비스가 영영 열린 채 남아 오탐이 쌓인다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    db = SessionLocal()
    try:
        prior = ScanRun(name="prior full", status="done")
        db.add(prior)
        db.commit()
        for key, port, proto in (("10.0.0.9|8443|tcp", 8443, "tcp"),
                                 ("10.0.0.9|161|udp", 161, "udp")):
            db.add(Finding(
                finding_key=key, host_ip="10.0.0.9", port=port, proto=proto,
                state="open", first_scan_id=prior.id, last_scan_id=prior.id,
            ))
        db.commit()
    finally:
        db.close()
    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.0.0.9"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["10.0.0.9"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    (out_dir / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")

    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        rows = {f.finding_key: f for f in
                db.query(Finding).filter(Finding.host_ip == "10.0.0.9").all()}
        # 전 포트를 봤으므로 TCP 는 목록에 없던 포트도 닫힌다.
        assert rows["10.0.0.9|8443|tcp"].state == "closed"
        # UDP 는 여전히 비활성 — 프로토콜 경계는 그대로다.
        assert rows["10.0.0.9|161|udp"].state == "open"
    finally:
        db.close()


def test_saved_stage_scope_reads_the_bounds_the_engine_actually_scanned():
    """`_saved_stage_scope` 의 세 갈래 - 전 포트(None) · 일부(집합) · 근거 없음(빈 집합)."""
    def spec(stages):
        return {"stages": stages}

    assert _saved_stage_scope(spec({"tcp": {"enabled": True, "ports": "1-65535"}}), "tcp") is None
    assert _saved_stage_scope(spec({"tcp": {"enabled": True, "ports": "80,443"}}), "tcp") == {80, 443}
    assert _saved_stage_scope(spec({"udp": {"enabled": False, "ports": "53"}}), "udp") == set()
    # 활성인데 범위가 비었으면 무엇을 봤는지 모른다 - 전 포트로 넘겨짚지 않는다.
    assert _saved_stage_scope(spec({"udp": {"enabled": True, "ports": ""}}), "udp") == set()
    # stages 자체가 없는 spec 도 죽지 않는다.
    assert _saved_stage_scope({}, "tcp") == set()


def test_an_old_completed_result_never_closes_a_port_observed_after_it(
    client, monkeypatch, tmp_path,
):
    """며칠 전 끝난 실행을 지금 마감해도, 그 뒤에 새로 관측된 포트를 닫으면 안 된다.

    구형 spec 은 닫힘 후보 목록이 없어 마감 시점의 현재 DB 에서 후보를 재구성한다. 그러면
    **그 스캔이 끝난 뒤에** 다른 스캔이 새로 관측한 발견까지 후보에 들어가고, 과거의 부재를
    근거로 최신 관측이 닫힌다 - 시간이 거꾸로 흐른다.

    `ingest()` 에는 이미 out-of-order 방어(`_is_older`)가 있지만 엔진 경로가 `scan_date` 를
    넘기지 않아 `when` 이 '지금'이 되면서 한 번도 발동하지 않았다. 병합 XML 은 이미
    `scan.started_at` 을 쓰고 있어서 DB 와 증거 파일의 시각이 서로 어긋나기도 했다.

    두 축을 다 고정한다: DB 상태·last_scan_id·last_seen·CLOSED 이벤트, 그리고 병합 XML.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    ran_at = datetime(2026, 8, 1, 3, 0, tzinfo=timezone.utc)
    observed_later = ran_at + timedelta(days=1)
    key = "10.9.9.9|443|tcp"

    db = SessionLocal()
    try:
        newer = ScanRun(name="8월 2일 정상 스캔", status="done")
        db.add(newer)
        db.commit()
        newer_id = newer.id
        db.add(Finding(
            finding_key=key, host_ip="10.9.9.9", port=443, proto="tcp",
            state="open", service="https", first_scan_id=newer_id, last_scan_id=newer_id,
            first_seen=observed_later, last_seen=observed_later,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.9.9.9"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
    })
    db = SessionLocal()
    try:
        stale = db.get(ScanRun, scan_id)
        stale.name = "8월 1일에 끝난 구형 실행"
        stale.started_at = ran_at
        db.commit()
    finally:
        db.close()

    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["10.9.9.9"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    # 8월 1일에는 443 이 닫혀 있었다. 그 사실이 8월 2일 관측을 뒤집어서는 안 된다.
    (out_dir / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")

    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    assert _read_scan(scan_id).status == "done"
    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == key).one()
        assert row.state == "open", "과거 결과가 더 새로운 관측을 닫으면 안 된다"
        assert row.status != "정상처리"
        assert row.last_scan_id == newer_id, "더 새로운 관측의 출처가 과거 스캔으로 바뀌면 안 된다"
        assert row.last_seen.replace(tzinfo=timezone.utc) == observed_later
        events = db.query(FindingEvent).filter(FindingEvent.finding_id == row.id).all()
        assert not [e for e in events if e.kind == "CLOSED"], "audit chronology 손상"
    finally:
        db.close()

    # 증거 파일에도 닫힘으로 남으면 안 된다 - DB 만 지키면 감사 산출물이 반대로 말한다.
    merged = (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").read_text(encoding="utf-8")
    assert 'portid="443"' not in merged or 'state="closed"' not in merged


def test_a_backdated_upload_does_not_record_a_newer_port_as_closed(client, monkeypatch, tmp_path):
    """지난 날짜의 XML 을 오늘 올려도, 그 뒤에 관측된 포트를 증거 파일에 닫힘으로 쓰면 안 된다.

    가져오기는 파일 안의 시각이 곧 관측 시각이라, 과거 XML 을 올리는 것이 정상 경로다.
    `ingest()` 는 `_is_older` 로 DB 를 지키지만, 닫힘 후보 집합은 병합 XML 의 closed 목록에도
    그대로 쓰인다. 후보에서 잘라내지 않으면 DB 는 열림인데 감사 산출물은 닫힘이라고 말한다 -
    한쪽만 지키면 둘이 반대로 증언한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    scanned_at = datetime(2026, 8, 1, 3, 0, tzinfo=timezone.utc)
    observed_later = scanned_at + timedelta(days=1)
    key = "10.8.8.8|8443|tcp"

    db = SessionLocal()
    try:
        newer = ScanRun(name="나중 관측", status="done")
        db.add(newer)
        db.commit()
        newer_id = newer.id
        db.add(Finding(
            finding_key=key, host_ip="10.8.8.8", port=8443, proto="tcp",
            state="open", service="https", first_scan_id=newer_id, last_scan_id=newer_id,
            first_seen=observed_later, last_seen=observed_later,
        ))
        target = ScanRun(name="과거 XML 가져오기", status="running")
        db.add(target)
        db.commit()
        target_id = target.id
    finally:
        db.close()

    raw_xml_path = scans_api._settings.scans_dir / f"scan_{target_id}.xml"
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, target_id)
        # 8월 1일 XML 은 8443 을 보지 못했다. 그 부재는 8월 2일 관측을 뒤집지 못한다.
        scans_api._commit_ingest(
            db, scan, [], {"10.8.8.8"}, {8443}, set(),
            scan_date=scanned_at, raw_xml_path=raw_xml_path,
        )
    finally:
        db.close()

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == key).one()
        assert row.state == "open", "과거 XML 이 더 새로운 관측을 닫으면 안 된다"
        assert row.last_scan_id == newer_id
    finally:
        db.close()

    merged = raw_xml_path.read_text(encoding="utf-8")
    assert 'portid="8443"' not in merged, "DB 는 열림인데 증거 파일이 닫힘이라 말하면 안 된다"


def _staged_out_dir(tmp_path, scan_id, *, live="10.9.9.9", finished_epoch, open_port=None):
    """완결된 TCP sweep 산출물 하나 — <finished time> 으로 관측 시각을 밝힌다."""
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": [live],
        "open_map": {live: {"tcp": [open_port]}} if open_port else {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    ports = (
        f'<ports><port protocol="tcp" portid="{open_port}">'
        '<state state="open" reason="syn-ack"/><service name="https"/></port></ports>'
    ) if open_port else ""
    (out_dir / "stage-tcp-b0.xml").write_text(
        f'<?xml version="1.0"?><nmaprun start="{finished_epoch - 3600}">'
        f'<host><status state="up"/><address addr="{live}" addrtype="ipv4"/>{ports}</host>'
        f'<runstats><finished time="{finished_epoch}" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")
    return out_dir


def _legacy_spec(tmp_path, target="10.9.9.9"):
    return {
        "targets": [target], "exclude": [],
        "out_dir": str(tmp_path / "ignored"),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
    }


def test_a_long_running_scan_still_applies_what_it_confirmed_later(client, monkeypatch, tmp_path):
    """스캔이 먼저 **시작**했다고 해서 그 결과가 오래된 것은 아니다.

    /24 staged 스캔은 몇 시간을 돈다. 시작 시각을 관측 시각으로 쓰면, 실행 중에 다른 스캔이
    남긴 결과가 더 새것으로 판정되어 이 스캔이 **나중에 실제로 확인한 열린 포트**가 통째로
    버려진다 - 노출을 숨기는 미탐이다. 최신성은 산출물이 밝힌 완료 시각으로 판단해야 한다.

        00:00  A 시작
        01:00  다른 스캔이 443/tcp 를 closed + 정상처리로 기록
        02:00  A 의 완결된 sweep 이 443/tcp open(syn-ack) 확인
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    started = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    other_at = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    swept_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    key = "10.9.9.9|443|tcp"

    db = SessionLocal()
    try:
        other = ScanRun(name="1시 스캔", status="done")
        db.add(other)
        db.commit()
        other_id = other.id
        db.add(Finding(
            finding_key=key, host_ip="10.9.9.9", port=443, proto="tcp",
            state="closed", status="정상처리", service="https",
            first_scan_id=other_id, last_scan_id=other_id,
            first_seen=other_at, last_seen=other_at,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, _legacy_spec(tmp_path))
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_id)
        run.started_at = started
        db.commit()
    finally:
        db.close()
    _staged_out_dir(tmp_path, scan_id, finished_epoch=int(swept_at.timestamp()), open_port=443)
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == key).one()
        assert row.state == "open", "나중에 확인한 열림을 시작 시각 때문에 버리면 미탐이다"
        assert row.reason == "syn-ack"
        assert row.last_scan_id == scan_id
        assert row.last_seen.replace(tzinfo=timezone.utc) == swept_at
        assert row.status != "정상처리", "다시 열렸으므로 조치 완료로 둘 수 없다"
        kinds = [e.type for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == row.id).all()]
        assert "REOPENED" in kinds
    finally:
        db.close()


def test_a_result_that_finished_before_a_newer_observation_still_yields(client, monkeypatch, tmp_path):
    """반대 방향 - sweep 이 **먼저 끝났으면** 그 뒤 관측이 이긴다(직전 라운드의 계약)."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    swept_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    newer_at = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)
    key = "10.9.9.9|443|tcp"

    db = SessionLocal()
    try:
        newer = ScanRun(name="8월 3일 스캔", status="done")
        db.add(newer)
        db.commit()
        newer_id = newer.id
        db.add(Finding(
            finding_key=key, host_ip="10.9.9.9", port=443, proto="tcp",
            state="open", service="https", first_scan_id=newer_id, last_scan_id=newer_id,
            first_seen=newer_at, last_seen=newer_at,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, _legacy_spec(tmp_path))
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_id)
        run.started_at = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
        db.commit()
    finally:
        db.close()
    # 8/1 02:00 에 끝난 sweep 은 443 을 보지 못했다 - 8/3 관측을 뒤집지 못한다.
    _staged_out_dir(tmp_path, scan_id, finished_epoch=int(swept_at.timestamp()))
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == key).one()
        assert row.state == "open" and row.last_scan_id == newer_id
        assert row.last_seen.replace(tzinfo=timezone.utc) == newer_at
        assert not [e for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == row.id).all() if e.type == "CLOSED"]
    finally:
        db.close()
    merged = (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").read_text(encoding="utf-8")
    assert 'state="closed"' not in merged


def _sweep_xml(host: str, *, finished_epoch: int, open_port: int | None = None) -> str:
    ports = (
        f'<ports><port protocol="tcp" portid="{open_port}">'
        '<state state="open" reason="syn-ack"/><service name="https"/></port></ports>'
    ) if open_port else ""
    host_el = (
        f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/>{ports}</host>'
        # --open 으로 돌린 sweep 은 열린 포트가 없는 호스트를 XML 에 아예 싣지 않는다.
        if open_port else ""
    )
    return (f'<?xml version="1.0"?><nmaprun start="{finished_epoch - 3600}">{host_el}'
            f'<runstats><finished time="{finished_epoch}" exit="success"/>'
            '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def test_one_batch_absence_never_borrows_another_batch_clock(client, monkeypatch, tmp_path):
    """배치마다 부재를 확인한 시각이 다르다 - 하나로 뭉치면 시각을 빌려 온다.

        00:00  b0 이 A 를 훑고 443 을 못 봤다
        01:00  다른 스캔이 A:443 을 open 으로 관측했다
        02:00  b1 이 B 를 훑고 443 을 못 봤다

    실행 전체의 max(finished)=02:00 을 A 에도 적용하면, b0 의 00:00 부재가 02:00 권한을
    얻어 01:00 관측을 닫는다. b1 은 A 를 본 적조차 없다. A 의 권한은 b0 의 00:00 뿐이고,
    B 에는 b1 의 02:00 이 그대로 적용돼야 한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    b0_at = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    other_at = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    b1_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)

    db = SessionLocal()
    try:
        other = ScanRun(name="1시 스캔", status="done")
        db.add(other)
        db.commit()
        other_id = other.id
        # A:443 은 b0 이 끝난 뒤에 관측됐다 - 닫히면 안 된다.
        db.add(Finding(
            finding_key="10.1.1.1|443|tcp", host_ip="10.1.1.1", port=443, proto="tcp",
            state="open", service="https", first_scan_id=other_id, last_scan_id=other_id,
            first_seen=other_at, last_seen=other_at,
        ))
        # B:443 은 b1 이 훑기 전에 관측됐다 - 닫혀야 한다.
        db.add(Finding(
            finding_key="10.1.1.2|443|tcp", host_ip="10.1.1.2", port=443, proto="tcp",
            state="open", service="https", first_scan_id=other_id, last_scan_id=other_id,
            first_seen=b0_at, last_seen=b0_at,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.1.1.1", "10.1.1.2"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"), "batch_size": 1,
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
        "scanops": {"scope_keys": ["10.1.1.1|443|tcp", "10.1.1.2|443|tcp"]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["10.1.1.1", "10.1.1.2"],
        "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 2}}) + "\n",
        encoding="utf-8")
    (out_dir / "stage-tcp-b0.xml").write_text(
        _sweep_xml("10.1.1.1", finished_epoch=int(b0_at.timestamp())), encoding="utf-8")
    (out_dir / "stage-tcp-b1.xml").write_text(
        _sweep_xml("10.1.1.2", finished_epoch=int(b1_at.timestamp())), encoding="utf-8")
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        first = db.query(Finding).filter(Finding.finding_key == "10.1.1.1|443|tcp").one()
        assert first.state == "open", "b1 의 시각을 빌려 A 를 닫으면 미탐이다"
        assert first.last_scan_id == other_id
        assert first.last_seen.replace(tzinfo=timezone.utc) == other_at
        assert not [e for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == first.id).all() if e.type == "CLOSED"]

        second = db.query(Finding).filter(Finding.finding_key == "10.1.1.2|443|tcp").one()
        assert second.state == "closed", "b1 이 실제로 훑은 B 는 닫혀야 한다(과잉 보수 방지)"
        assert second.last_seen.replace(tzinfo=timezone.utc) == b1_at
    finally:
        db.close()


def test_absence_times_only_covers_what_each_sweep_actually_swept(tmp_path):
    """부재 시각 맵은 '무엇을 훑었는가' 를 그대로 반영해야 한다.

    커버 범위를 산출물의 host 목록에서 읽으면 안 된다 - sweep 은 --open 으로 돌기 때문에
    열린 포트가 없는 호스트는 XML 에 아예 나타나지 않는다. 그런데 닫힘 판정이 필요한 것이
    정확히 그 호스트들이다. 엔진이 배치를 나눈 규칙을 되짚어 세운다.
    """
    from scanops.scanning import engine_runner

    b0_at = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    b1_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    (tmp_path / "run-state.json").write_text(json.dumps({
        "live": ["10.2.2.1", "10.2.2.2"], "open_map": {}, "stages_done": ["tcp"],
    }), encoding="utf-8")
    spec = {"batch_size": 1,
            "stages": {"tcp": {"enabled": True, "ports": "443"},
                       "udp": {"enabled": False, "ports": ""}}}
    # b0 의 XML 에는 호스트가 아예 없다(열린 포트가 없었다). 그래도 훑은 것은 사실이다.
    (tmp_path / "stage-tcp-b0.xml").write_text(
        _sweep_xml("10.2.2.1", finished_epoch=int(b0_at.timestamp())), encoding="utf-8")
    (tmp_path / "stage-tcp-b1.xml").write_text(
        _sweep_xml("10.2.2.2", finished_epoch=int(b1_at.timestamp())), encoding="utf-8")

    times = engine_runner.absence_times(tmp_path, spec)
    assert times == {("10.2.2.1", "tcp"): b0_at, ("10.2.2.2", "tcp"): b1_at}
    # 돌지 않은 프로토콜은 부재를 주장할 수 없다.
    assert ("10.2.2.1", "udp") not in times

    # 산출물이 없는 배치는 커버 목록에 들어가지 않는다.
    (tmp_path / "stage-tcp-b1.xml").unlink()
    assert set(engine_runner.absence_times(tmp_path, spec)) == {("10.2.2.1", "tcp")}


def test_ingest_never_closes_a_key_no_artifact_covered():
    """맵에 없는 키는 닫지 않는다 - '커버하지 않았다' 와 '시각을 모른다' 는 다르다."""
    from scanops.scanning.ingest import ingest

    db = SessionLocal()
    try:
        run = ScanRun(name="부분 커버", status="running")
        db.add(run)
        db.commit()
        for key, proto in (("10.3.3.1|443|tcp", "tcp"), ("10.3.3.1|53|udp", "udp")):
            db.add(Finding(
                finding_key=key, host_ip="10.3.3.1",
                port=int(key.split("|")[1]), proto=proto, state="open",
                first_scan_id=run.id, last_scan_id=run.id,
                first_seen=datetime(2026, 7, 1, tzinfo=timezone.utc),
                last_seen=datetime(2026, 7, 1, tzinfo=timezone.utc),
            ))
        db.commit()

        counts = ingest(
            db, run.id, [], {"10.3.3.1"},
            scope_keys={"10.3.3.1|443|tcp", "10.3.3.1|53|udp"},
            scan_date=datetime(2026, 8, 1, tzinfo=timezone.utc),
            # TCP 만 훑었다. UDP 부재는 이 실행이 증명할 수 없다.
            absence_at={("10.3.3.1", "tcp"): datetime(2026, 8, 1, tzinfo=timezone.utc)},
        )
        assert counts["closed"] == 1
        rows = {f.finding_key: f.state for f in db.query(Finding).all()}
        assert rows["10.3.3.1|443|tcp"] == "closed"
        assert rows["10.3.3.1|53|udp"] == "open", "훑지 않은 프로토콜을 닫으면 미탐이다"
    finally:
        db.close()


def test_selected_rescan_keeps_time_authority_per_port(client, monkeypatch, tmp_path):
    """선택 재스캔은 포트마다 별도 산출물이다 - 443 의 시각을 22 가 빌려 쓰면 안 된다.

        00:00  A:22 의 stage3 가 비어 있다(그 포트가 닫혔다)
        01:00  다른 스캔이 A:22 open 을 관측했다
        02:00  A:443 의 stage3 가 비어 있다

    두 unit 을 (ip, proto) 하나로 뭉치면 02:00 권한이 22 에도 적용돼 01:00 관측을 닫는다.
    443 산출물은 22 를 관측한 적이 없다. 일반 배치에서 막은 미탐이 포트 축에서 재발한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    at22 = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    other_at = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    at443 = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)

    db = SessionLocal()
    try:
        other = ScanRun(name="1시 스캔", status="done")
        db.add(other)
        db.commit()
        other_id = other.id
        db.add(Finding(
            finding_key="10.4.4.4|22|tcp", host_ip="10.4.4.4", port=22, proto="tcp",
            state="open", service="ssh", first_scan_id=other_id, last_scan_id=other_id,
            first_seen=other_at, last_seen=other_at,
        ))
        db.add(Finding(
            finding_key="10.4.4.4|443|tcp", host_ip="10.4.4.4", port=443, proto="tcp",
            state="open", service="https", first_scan_id=other_id, last_scan_id=other_id,
            first_seen=at22, last_seen=at22,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.4.4.4"], "exclude": [], "out_dir": str(tmp_path / "ignored"),
        "rescan_units": [{"ip": "10.4.4.4", "port": 22, "proto": "tcp"},
                         {"ip": "10.4.4.4", "port": 443, "proto": "tcp"}],
        "stages": {"service": {"enabled": True, "confirm": False}},
        "scanops": {"scope_keys": ["10.4.4.4|22|tcp", "10.4.4.4|443|tcp"]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8")
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["job"], "live": ["10.4.4.4"], "open_map": {}, "stop": False,
    }), encoding="utf-8")
    # 포트마다 별도 authority XML — 각자 자기 시각을 밝힌다(둘 다 열린 포트 없음).
    for port, when in ((22, at22), (443, at443)):
        (out_dir / f"stage3-10_4_4_4-tcp{port}.xml").write_text(
            f'<?xml version="1.0"?><nmaprun start="{int(when.timestamp()) - 60}">'
            f'<runstats><finished time="{int(when.timestamp())}" exit="success"/>'
            '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        ssh = db.query(Finding).filter(Finding.finding_key == "10.4.4.4|22|tcp").one()
        assert ssh.state == "open", "443 의 02:00 을 빌려 22 를 닫으면 미탐이다"
        assert ssh.last_scan_id == other_id
        assert ssh.last_seen.replace(tzinfo=timezone.utc) == other_at
        assert not [e for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == ssh.id).all() if e.type == "CLOSED"]

        https = db.query(Finding).filter(Finding.finding_key == "10.4.4.4|443|tcp").one()
        assert https.state == "closed", "자기 산출물이 증명한 443 은 닫혀야 한다"
        assert https.last_seen.replace(tzinfo=timezone.utc) == at443
    finally:
        db.close()

    # 증거 XML 도 DB 와 같은 말을 해야 한다.
    merged = (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").read_text(encoding="utf-8")
    assert 'portid="443"' in merged and 'portid="22"' not in merged


def test_selected_rescan_timeout_only_denies_its_own_port(client, monkeypatch, tmp_path):
    """22 timeout 뒤 443 성공이 같은 호스트의 22 판정을 덮어쓰면 안 된다."""
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    ip = "10.4.4.5"

    db = SessionLocal()
    try:
        previous = ScanRun(name="이전 스캔", status="done")
        db.add(previous)
        db.commit()
        previous_id = previous.id
        for port, service in ((22, "ssh"), (443, "https")):
            db.add(Finding(
                finding_key=f"{ip}|{port}|tcp", host_ip=ip, port=port, proto="tcp",
                state="open", service=service, first_scan_id=previous_id, last_scan_id=previous_id,
            ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": [ip], "exclude": [], "out_dir": str(tmp_path / "ignored"),
        "rescan_units": [
            {"ip": ip, "port": 22, "proto": "tcp"},
            {"ip": ip, "port": 443, "proto": "tcp"},
        ],
        "stages": {"service": {"enabled": True, "confirm": False}},
        "scanops": {"scope_keys": [f"{ip}|22|tcp", f"{ip}|443|tcp"]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 1}}) + "\n",
        encoding="utf-8",
    )
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["job"], "live": [ip], "open_map": {}, "stop": False,
        "coverage": [
            {"artifact": "stage3-10_4_4_5-tcp22.xml", "proto": "tcp", "role": "authority",
             "hosts": [ip], "ports": "T:22", "finished": True},
            {"artifact": "stage3-10_4_4_5-tcp443.xml", "proto": "tcp", "role": "authority",
             "hosts": [ip], "ports": "T:443", "finished": True},
        ],
    }), encoding="utf-8")
    (out_dir / "stage3-10_4_4_5-tcp22.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        '<host timedout="true"><status state="up"/><address addr="10.4.4.5" addrtype="ipv4"/>'
        '</host><runstats><finished time="1893455999" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")
    (out_dir / "stage3-10_4_4_5-tcp443.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
        '<runstats><finished time="1893456000" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>', encoding="utf-8")
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        rows = {row.port: row for row in db.query(Finding).filter(Finding.host_ip == ip).all()}
        assert rows[22].state == "open" and rows[22].last_scan_id == previous_id
        assert rows[443].state == "closed" and rows[443].last_scan_id == scan_id
        events = db.query(FindingEvent).all()
        assert not [e for e in events if e.finding_id == rows[22].id and e.type == "CLOSED"]
        assert [e for e in events if e.finding_id == rows[443].id and e.type == "CLOSED"]
    finally:
        db.close()


def test_the_merged_evidence_records_only_what_the_run_actually_closed(client, monkeypatch, tmp_path):
    """병합 XML 이 DB 와 반대로 증언하면 안 된다.

    예전에는 scope_keys 전체를 '닫힘' 으로 미리 써 버렸다. 인입이 시각·커버리지를 근거로
    살려 둔 발견까지 증거 파일에는 닫힘으로 남아, 나중에 그 파일을 읽는 사람은 DB 와
    정반대의 사실을 본다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    swept_at = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    newer_at = datetime(2026, 8, 2, 0, 0, tzinfo=timezone.utc)

    db = SessionLocal()
    try:
        other = ScanRun(name="다음날 스캔", status="done")
        db.add(other)
        db.commit()
        # 살아남아야 하는 발견(스윕보다 나중에 관측됨)
        db.add(Finding(
            finding_key="10.5.6.1|443|tcp", host_ip="10.5.6.1", port=443, proto="tcp",
            state="open", service="https", first_scan_id=other.id, last_scan_id=other.id,
            first_seen=newer_at, last_seen=newer_at,
        ))
        # 닫혀야 하는 발견
        db.add(Finding(
            finding_key="10.5.6.2|443|tcp", host_ip="10.5.6.2", port=443, proto="tcp",
            state="open", service="https", first_scan_id=other.id, last_scan_id=other.id,
            first_seen=swept_at, last_seen=swept_at,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.5.6.1", "10.5.6.2"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"), "batch_size": 256,
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
        "scanops": {"scope_keys": ["10.5.6.1|443|tcp", "10.5.6.2|443|tcp"]},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["10.5.6.1", "10.5.6.2"],
        "open_map": {}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 2}}) + "\n",
        encoding="utf-8")
    (out_dir / "stage-tcp-b0.xml").write_text(
        _sweep_xml("10.5.6.2", finished_epoch=int(swept_at.timestamp())), encoding="utf-8")
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    db = SessionLocal()
    try:
        kept = db.query(Finding).filter(Finding.finding_key == "10.5.6.1|443|tcp").one()
        gone = db.query(Finding).filter(Finding.finding_key == "10.5.6.2|443|tcp").one()
        assert kept.state == "open" and gone.state == "closed"
    finally:
        db.close()

    merged = (scans_api._settings.scans_dir / f"scan_{scan_id}.xml").read_text(encoding="utf-8")
    assert "10.5.6.2" in merged, "실제로 닫은 것은 증거에 남는다"
    # 살려 둔 발견을 닫힘으로 적으면 DB 와 정반대로 증언하는 것이다.
    body = merged.split('addr="10.5.6.1"')
    assert len(body) == 1 or 'state="closed"' not in body[1].split("</host>")[0]


def test_a_stale_open_never_survives_a_round_trip_through_the_merged_evidence(
    client, monkeypatch, tmp_path,
):
    """인입이 시간상 폐기한 open 은 증거에도 남으면 안 된다.

        00:00  b0 이 A:443 을 open 으로 관측
        01:00  다른 스캔이 A:443 을 closed + 정상처리로 기록
        02:00  b1 완료

    인입은 b0 의 관측(00:00)이 01:00 보다 낡았으므로 정확히 버린다. 그런데 증거 XML 이
    raw findings 를 전부 open 으로 적으면, 그 파일을 다시 가져올 때 과거 관측이 최신 노출로
    되살아난다 - DB 가 거절한 사실이 증거 경로로 되돌아오는 왕복 오염이다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    b0_at = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    other_at = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    b1_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)

    db = SessionLocal()
    try:
        other = ScanRun(name="1시 스캔", status="done")
        db.add(other)
        db.commit()
        other_id = other.id
        db.add(Finding(
            finding_key="10.8.8.1|443|tcp", host_ip="10.8.8.1", port=443, proto="tcp",
            state="closed", status="정상처리", service="https",
            first_scan_id=other_id, last_scan_id=other_id,
            first_seen=other_at, last_seen=other_at,
        ))
        db.commit()
    finally:
        db.close()

    scan_id = _scan_with_spec(tmp_path, {
        "targets": ["10.8.8.1", "10.8.8.2"], "exclude": [],
        "out_dir": str(tmp_path / "ignored"), "batch_size": 1,
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": False}},
        "scanops": {"scope_keys": []},
    })
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    (out_dir / "run-state.json").write_text(json.dumps({
        "stages_done": ["tcp", "job"], "live": ["10.8.8.1", "10.8.8.2"],
        "open_map": {"10.8.8.1": {"tcp": [443]}}, "stop": False,
    }), encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        json.dumps({"event": "job_done", "status": "done", "counts": {"live": 2}}) + "\n",
        encoding="utf-8")
    (out_dir / "stage-tcp-b0.xml").write_text(
        _sweep_xml("10.8.8.1", finished_epoch=int(b0_at.timestamp()), open_port=443),
        encoding="utf-8")
    (out_dir / "stage-tcp-b1.xml").write_text(
        _sweep_xml("10.8.8.2", finished_epoch=int(b1_at.timestamp())), encoding="utf-8")
    monkeypatch.setattr(scans_api.scope, "check_scope", lambda hosts: None)

    scans_api._finalize_completed_engine_worker(scan_id)

    def state_of():
        session = SessionLocal()
        try:
            row = session.query(Finding).filter(
                Finding.finding_key == "10.8.8.1|443|tcp").one()
            events = session.query(FindingEvent).filter(
                FindingEvent.finding_id == row.id).count()
            return (row.state, row.status, row.last_scan_id,
                    row.last_seen.replace(tzinfo=timezone.utc), events)
        finally:
            session.close()

    before = state_of()
    assert before[:4] == ("closed", "정상처리", other_id, other_at), (
        "낡은 관측은 인입에서 이미 거절된다")

    merged_path = scans_api._settings.scans_dir / f"scan_{scan_id}.xml"
    merged = merged_path.read_text(encoding="utf-8")
    # 호스트를 훑었다는 사실 자체는 남아도 된다(사실이다). 남으면 안 되는 것은 '443 이
    # 열려 있었다' 는 주장이다 - 인입은 그 관측이 낡았다며 버렸다.
    assert 'portid="443"' not in merged, "인입이 버린 open 을 증거가 주장하면 안 된다"
    assert 'state="open"' not in merged

    # 왕복: 이 증거 파일을 그대로 다시 가져와도 아무것도 바뀌지 않아야 한다.
    # 합성 스냅샷은 애초에 원본처럼 인입될 수 없다(개별 관측 시각이 사라진 파일이다).
    headers = _headers(client)
    again = client.post("/api/scans/import", headers=headers,
                        files={"file": ("snapshot.xml", merged.encode("utf-8"), "text/xml")})
    assert again.status_code == 400
    assert "스냅샷" in again.json()["detail"]
    assert state_of() == before, "왕복 후에도 상태·출처·이력이 그대로여야 한다"


def _legacy_snapshot(host: str, port: int, finished_epoch: int) -> bytes:
    """업그레이드 전 `_write_merged_xml` 이 만들던 모양 - 표식이 없다."""
    return (
        '<?xml version="1.0"?>'
        f'<nmaprun scanner="scanops" args="scanops bundled import" '
        f'start="{finished_epoch - 3600}" version="scanops" xmloutputversion="1.05">'
        f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/><ports>'
        f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
        '<service name="https" method="table"/></port></ports></host>'
        f'<runstats><finished time="{finished_epoch}" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ).encode("utf-8")


def test_a_snapshot_made_before_the_marker_existed_is_still_refused(client, monkeypatch, tmp_path):
    """업그레이드 전에 반출된 합성 XML 도 같은 오염 경로다.

    표식은 이번 버전부터 붙는다. 그 이전 파일에는 없지만 `scanner="scanops"` 는 처음부터
    있었고, nmap 은 자기 산출물에 언제나 `scanner="nmap"` 을 쓴다. 새 파일만 막으면 과거
    반출물로 같은 둔갑이 그대로 재현된다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    kept_at = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    stale_at = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)

    db = SessionLocal()
    try:
        prior = ScanRun(name="1시 스캔", status="done")
        db.add(prior)
        db.commit()
        prior_id = prior.id
        db.add(Finding(
            finding_key="10.9.9.1|443|tcp", host_ip="10.9.9.1", port=443, proto="tcp",
            state="closed", status="정상처리", service="https",
            first_scan_id=prior_id, last_scan_id=prior_id,
            first_seen=kept_at, last_seen=kept_at,
        ))
        db.commit()
    finally:
        db.close()

    def state_of():
        session = SessionLocal()
        try:
            row = session.query(Finding).filter(
                Finding.finding_key == "10.9.9.1|443|tcp").one()
            return (row.state, row.status, row.last_scan_id,
                    row.last_seen.replace(tzinfo=timezone.utc),
                    session.query(FindingEvent).filter(
                        FindingEvent.finding_id == row.id).count())
        finally:
            session.close()

    before = state_of()
    headers = _headers(client)
    legacy = _legacy_snapshot("10.9.9.1", 443, int(stale_at.timestamp()))
    refused = client.post("/api/scans/import", headers=headers,
                          files={"file": ("old_snapshot.xml", legacy, "text/xml")})
    assert refused.status_code == 400
    assert "스냅샷" in refused.json()["detail"]
    assert state_of() == before, "거절됐으면 상태·출처·이력이 그대로여야 한다"

    # 반대 경계 - 진짜 nmap 산출물은 계속 들어와야 한다.
    real = (
        '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sS 10.9.9.2" '
        f'start="{int(stale_at.timestamp()) - 60}">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
        '<host><status state="up"/><address addr="10.9.9.2" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
        '<service name="https"/></port></ports></host>'
        f'<runstats><finished time="{int(stale_at.timestamp())}" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ).encode("utf-8")
    accepted = client.post("/api/scans/import", headers=headers,
                           files={"file": ("real.xml", real, "text/xml")})
    assert accepted.status_code == 200, accepted.text
    db = SessionLocal()
    try:
        assert db.query(Finding).filter(
            Finding.finding_key == "10.9.9.2|443|tcp").one().state == "open"
    finally:
        db.close()


def test_a_quality_issue_names_the_same_host_while_running_as_after_it_ends(
    client, monkeypatch, tmp_path,
):
    """같은 문제를 실행 중과 완료 후가 **같은 모양**으로 말해야 한다.

    화면의 '단계별 문제' 카드는 `type`/`host`/`proto`/`port_spec` 을 읽는다. 예전에는
    라이브 응답이 parse_events 원본(`kind`/`host_ip`)을 그대로 흘려서 카드에 호스트가
    안 찍혔다 - 운영자가 문제를 지켜보는 바로 그 순간에만 어느 장비인지 안 보이고,
    스캔이 끝나면 나타났다. 반대로 영속 행에는 proto/port_spec 이 없어서, 끝나는 순간
    '어느 포트가 안 됐는지' 가 사라졌다. 양쪽 다 확인한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {"targets": ["10.0.0.5"], "out_dir": str(tmp_path)})
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    (out_dir / "events.ndjson").write_text("\n".join(json.dumps(ev) for ev in [
        {"event": "job_start", "stage": "service"},
        {"event": "service_degraded", "stage": "service", "proto": "udp",
         "hosts": ["10.0.0.5"], "failed_ports": [161, 500], "port_spec": "U:161,500",
         "message": "UDP 서비스 프로브가 일부 완료되지 않았습니다."},
    ]) + "\n", encoding="utf-8")

    headers = _headers(client)
    live = client.get(f"/api/scans/{scan_id}/stages", headers=headers).json()
    assert live["source"] == "live_events"
    issue = next(i for i in live["issues"] if i["type"] == "service_degraded")
    assert issue["host"] == "10.0.0.5", "실행 중에는 어느 장비인지 안 보인다"
    assert issue["proto"] == "udp" and issue["port_spec"] == "U:161,500"
    assert issue["status"] == "unresolved"

    # 이제 같은 스캔을 마감해 DB 투영으로 넘긴다 - 워커가 종료 시 하는 것과 같은 호출.
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scans_api._materialize_engine_terminal(
            db, scan, out_dir, {"targets": ["10.0.0.5"]},
            {"authority_missing": [], "authority_broken": []}, [],
        )
        scan.status = "done"
        db.commit()
    finally:
        db.close()

    ended = client.get(f"/api/scans/{scan_id}/stages", headers=headers).json()
    assert ended["source"] == "db", "영속 투영으로 넘어가지 않아 비교가 무의미하다"
    kept = next(i for i in ended["issues"] if i["type"] == "service_degraded")
    assert kept["host"] == "10.0.0.5"
    assert (kept["proto"], kept["port_spec"]) == ("udp", "U:161,500"), (
        "영구 보관되는 쪽이 어느 포트가 실패했는지를 잃었다"
    )
    assert {k: kept[k] for k in ("type", "host", "proto", "port_spec")} == \
           {k: issue[k] for k in ("type", "host", "proto", "port_spec")}


def test_the_delay_panel_survives_the_scan_finishing(client, monkeypatch, tmp_path):
    """지연 추적 패널은 스캔이 **끝난 뒤에** 더 많이 쓰인다.

    완료된 스캔의 /stages 는 이벤트가 아니라 DB 투영으로 그린다. 영속 행이 워치독·시간
    초과만 담고 proto/hosts/label/ports/phases/수확량을 버리면, 스캔이 종료되는 순간
    호스트별 소요와 nmap 내부 단계가 통째로 사라지고 '오래 걸린 실행' 표가 전부 '—' 가
    된다 - 하필 사람이 지연을 들여다보는 시점이 그때다.

    그래서 라이브와 완료의 trace 를 **같은 스캔에서** 비교한다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _scan_with_spec(tmp_path, {"targets": ["10.0.0.7"], "out_dir": str(tmp_path)})
    out_dir = tmp_path / "scans" / f"scan_{scan_id}"
    (out_dir / "events.ndjson").write_text("\n".join(json.dumps(ev) for ev in [
        {"event": "job_start", "stage": "service"},
        {"event": "command_start", "stage": "service", "execution_id": "x1",
         "argv": ["nmap", "-sS", "-p", "T:22,443", "10.0.0.7"], "artifact": "stage3-10_0_0_7-tcp",
         "proto": "tcp", "hosts": ["10.0.0.7"], "label": "10.0.0.7", "ports": "T:22,443",
         "ts": 1000.0},
        {"event": "command_done", "stage": "service", "execution_id": "x1", "outcome": "done",
         "seconds": 612.0, "rc": 0, "ts": 1612.0,
         "phases": {"Service scan": 600.0, "SYN Stealth Scan": 12.0},
         "hosts_found": 1, "open_ports": 2, "inferred_open": 0, "products": 2, "empty": False},
        {"event": "job_done", "status": "done"},
    ]) + "\n", encoding="utf-8")

    headers = _headers(client)
    live = client.get(f"/api/scans/{scan_id}/stages", headers=headers).json()["trace"]
    assert live["by_host"] and live["by_phase"], "라이브부터 비어 있으면 비교가 무의미하다"

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scans_api._materialize_engine_terminal(
            db, scan, out_dir, {"targets": ["10.0.0.7"]},
            {"authority_missing": [], "authority_broken": []}, [],
        )
        scan.status = "done"
        db.commit()
    finally:
        db.close()

    ended = client.get(f"/api/scans/{scan_id}/stages", headers=headers)
    assert ended.json()["source"] == "db", "DB 투영으로 안 넘어가면 비교가 무의미하다"
    trace = ended.json()["trace"]
    assert trace["by_host"] == live["by_host"], "끝나는 순간 호스트별 소요가 사라졌다"
    assert trace["by_phase"] == live["by_phase"], "끝나는 순간 nmap 내부 단계가 사라졌다"
    slow = trace["slowest"][0]
    assert (slow["label"], slow["ports"], slow["proto"]) == ("10.0.0.7", "T:22,443", "tcp"), (
        "오래 걸린 실행 표가 대상·포트 근거를 잃었다"
    )
    assert (slow["hosts_found"], slow["open_ports"], slow["products"]) == (1, 2, 2)
    assert slow["empty"] is False
