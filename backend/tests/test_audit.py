"""감사 로그 — 로그인/가져오기/규칙 행위가 기록되고, 조회는 admin 전용."""
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _hdr(client, user, pw):
    return {"Authorization": f"Bearer {token_for(client, user, pw)}"}


def test_login_recorded_and_admin_can_read(client):
    make_user("boss", "pw", role="admin")
    h = _hdr(client, "boss", "pw")   # 로그인 성공 1건 기록
    logs = client.get("/api/audit", headers=h).json()
    assert any(x["action"] == "LOGIN" and x["ok"] == 1 for x in logs)


def test_failed_login_is_globally_bounded_by_utc_hour(client, monkeypatch):
    from scanops.api import auth as auth_api
    from scanops.db import SessionLocal
    from scanops.models import AuditLog

    make_user("known-a", "rightpass12")
    make_user("known-b", "rightpass12")
    hour = {"value": "2026-07-29T08:00Z"}
    monkeypatch.setattr(auth_api, "_utc_hour_bucket", lambda: hour["value"])

    for username in ("known-a", "known-a", "known-b", "attacker-chosen-name"):
        response = client.post(
            "/api/auth/login", json={"username": username, "password": "wrong"},
        )
        assert response.status_code == 401

    db = SessionLocal()
    try:
        failed = db.query(AuditLog).filter_by(action="LOGIN", ok=0).all()
        assert len(failed) == 1
        assert failed[0].actor_user_id is None
        assert failed[0].actor_name == ""
        assert failed[0].target == "global"
        assert failed[0].detail == "실패 (UTC hour 2026-07-29T08:00Z)"
    finally:
        db.close()

    hour["value"] = "2026-07-29T09:00Z"
    response = client.post(
        "/api/auth/login", json={"username": "known-a", "password": "wrong"},
    )
    assert response.status_code == 401

    db = SessionLocal()
    try:
        failed = db.query(AuditLog).filter_by(action="LOGIN", ok=0).all()
        assert len(failed) == 2
        assert {row.detail for row in failed} == {
            "실패 (UTC hour 2026-07-29T08:00Z)",
            "실패 (UTC hour 2026-07-29T09:00Z)",
        }
    finally:
        db.close()


def test_bounded_audit_lookup_failure_does_not_break_auth_flow():
    from scanops.api.audit import record_once

    class BrokenAuditSession:
        rolled_back = False

        def query(self, *_args):
            raise RuntimeError("audit storage unavailable")

        def rollback(self):
            self.rolled_back = True

    db = BrokenAuditSession()
    record_once(db, None, "LOGIN", target="global", detail="failed", ok=False)
    assert db.rolled_back is True


def test_successful_login_is_recorded_every_time(client):
    from scanops.db import SessionLocal
    from scanops.models import AuditLog

    make_user("repeat-success", "rightpass12")
    for _ in range(2):
        response = client.post(
            "/api/auth/login",
            json={"username": "repeat-success", "password": "rightpass12"},
        )
        assert response.status_code == 200

    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter_by(
            action="LOGIN", target="repeat-success", ok=1,
        ).count() == 2
    finally:
        db.close()


def test_import_recorded(client):
    make_user("boss", "pw", role="admin")
    h = _hdr(client, "boss", "pw")
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    logs = client.get("/api/audit", headers=h).json()
    assert any(x["action"] == "SCAN_IMPORT" for x in logs)


def test_rule_changes_recorded(client):
    make_user("boss", "pw", role="admin")
    h = _hdr(client, "boss", "pw")
    r = client.post("/api/rules", headers=h,
                    json={"kind": "banned_service", "service": "telnet", "risk_level": "banned"})
    rid = r.json()["id"]
    client.delete(f"/api/rules/{rid}", headers=h)
    logs = client.get("/api/audit", headers=h).json()
    actions = {x["action"] for x in logs}
    assert "RULE_CREATE" in actions and "RULE_DELETE" in actions


def test_viewer_cannot_read_audit(client):
    make_user("v", "pw", role="viewer")
    h = _hdr(client, "v", "pw")
    assert client.get("/api/audit", headers=h).status_code == 403


def test_audit_action_filter(client):
    make_user("boss", "pw", role="admin")
    h = _hdr(client, "boss", "pw")
    logs = client.get("/api/audit?action=LOGIN", headers=h).json()
    assert logs and all(x["action"] == "LOGIN" for x in logs)
