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


def test_failed_login_recorded(client):
    make_user("boss", "pw", role="admin")
    r = client.post("/api/auth/login", json={"username": "boss", "password": "wrong"})
    assert r.status_code == 401
    h = _hdr(client, "boss", "pw")
    logs = client.get("/api/audit", headers=h).json()
    assert any(x["action"] == "LOGIN" and x["ok"] == 0 and x["target"] == "boss" for x in logs)


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
