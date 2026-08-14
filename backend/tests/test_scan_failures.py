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
    monkeypatch.setattr(scans_api, "_wait_scan_process", lambda _scan_id, _proc: 0)
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

    def finalize_existing(db, scan, actual_out_dir, scope_keys, force_scanned_hosts):
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

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts):
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

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts):
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

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts):
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

    def capture(db, scan, actual_out_dir, scope_keys, force_scanned_hosts):
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
