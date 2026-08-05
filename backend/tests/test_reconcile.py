"""재시작 시 고아 실행 정리 — running/canceling 을 interrupted 로(자동 복구 안 함)."""
import logging

import pytest
from fastapi.testclient import TestClient

from scanops.api.scans import reconcile_orphans
from scanops.db import SessionLocal
from scanops.models import ScanRun
from tests.conftest import make_user, token_for


def _mk(status):
    db = SessionLocal()
    try:
        s = ScanRun(name="t", status=status)
        db.add(s)
        db.commit()
        db.refresh(s)
        return s.id
    finally:
        db.close()


def _status(sid):
    db = SessionLocal()
    try:
        return db.get(ScanRun, sid).status
    finally:
        db.close()


def test_orphans_marked_interrupted(client):
    running = _mk("running")
    canceling = _mk("canceling")
    done = _mk("done")

    n = reconcile_orphans()
    assert n == 2
    assert _status(running) == "interrupted"
    assert _status(canceling) == "interrupted"
    assert _status(done) == "done"   # 완료된 건 안 건드림


def test_reconcile_idempotent(client):
    _mk("running")
    assert reconcile_orphans() == 1
    assert reconcile_orphans() == 0   # 두 번째는 정리할 게 없음


def test_reconcile_preserves_engine_timeline_for_initial_relogin_view(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _mk("running")
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "spec.json").write_text("{}", encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        '\n'.join([
            '{"event":"job_start"}',
            '{"event":"stage_start","stage":"discovery"}',
            '{"event":"stage_done","stage":"discovery","counts":{"live":1}}',
            '{"event":"stage_start","stage":"tcp"}',
            '{"event":"stage_progress","stage":"tcp","percent":50}',
        ]),
        encoding="utf-8",
    )

    assert reconcile_orphans() == 1
    make_user("relogin-viewer", "viewerpass12", role="viewer")
    headers = {
        "Authorization": f"Bearer {token_for(client, 'relogin-viewer', 'viewerpass12')}"
    }
    payload = client.get("/api/scans", headers=headers).json()
    restored = next(scan for scan in payload if scan["id"] == scan_id)

    assert restored["status"] == "interrupted"
    assert [stage["stage"] for stage in restored["stages_json"]] == ["discovery", "tcp"]
    assert restored["stages_json"][0]["status"] == "done"
    assert restored["stages_json"][1]["percent"] == 50


def test_reconcile_tolerates_malformed_engine_progress(client, monkeypatch, tmp_path):
    from scanops.api import scans as scans_api

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scan_id = _mk("running")
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "spec.json").write_text("{}", encoding="utf-8")
    (out_dir / "events.ndjson").write_text(
        '{"event":"stage_progress","stage":"tcp","percent":"half"}\n',
        encoding="utf-8",
    )

    assert reconcile_orphans() == 1
    assert _status(scan_id) == "interrupted"
    assert client.get("/api/health").status_code == 200


def test_health_reports_ready_after_successful_lifespan(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["errors"] == []


def test_reconcile_failure_is_logged_and_degrades_readiness(monkeypatch, caplog):
    import scanops.api.scans as scans_api
    import scanops.main as main_module

    def fail_reconcile():
        raise RuntimeError("injected reconcile failure")

    monkeypatch.setattr(scans_api, "reconcile_orphans", fail_reconcile)
    with caplog.at_level(logging.ERROR), TestClient(main_module.app) as isolated_client:
        response = isolated_client.get("/api/health")

    assert response.status_code == 503
    assert response.json()["ready"] is False
    assert any("scan reconciliation failed" in error for error in response.json()["errors"])
    assert "scan orphan reconciliation failed" in caplog.text


def test_invalid_scope_configuration_degrades_readiness(monkeypatch, caplog):
    import scanops.main as main_module

    monkeypatch.setattr(main_module.settings, "scan_scope", "10.0.0.0/8,broken-cidr")
    with caplog.at_level(logging.ERROR), TestClient(main_module.app) as isolated_client:
        response = isolated_client.get("/api/health")

    assert response.status_code == 503
    assert "invalid scan scope configuration" in response.json()["errors"]
    assert "invalid scan scope configuration" in caplog.text


def test_required_bootstrap_failure_prevents_startup(monkeypatch, caplog):
    import scanops.main as main_module
    import scanops.seed.bootstrap as bootstrap

    def fail_bootstrap():
        raise RuntimeError("injected bootstrap failure")

    monkeypatch.setattr(bootstrap, "run_bootstrap", fail_bootstrap)
    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError, match="injected bootstrap"):
        with TestClient(main_module.app):
            pass
    assert "required bootstrap failed" in caplog.text
