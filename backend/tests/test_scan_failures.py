"""Stable scan failure persistence and API feedback."""
from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

import pytest

from scanops.api import scans as scans_api
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
