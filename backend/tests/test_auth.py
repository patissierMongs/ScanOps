"""Phase B 검증 — 인증/역할."""
from tests.conftest import make_user, token_for


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_login_and_me(client):
    make_user("auditor1", "pw-good", role="auditor")
    tok = token_for(client, "auditor1", "pw-good")
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["username"] == "auditor1"
    assert r.json()["role"] == "auditor"


def test_login_wrong_password(client):
    make_user("u2", "right")
    r = client.post("/api/auth/login", json={"username": "u2", "password": "wrong"})
    assert r.status_code == 401


def test_me_requires_auth(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_role_guard_blocks_viewer(client):
    make_user("viewer1", "pw", role="viewer")
    tok = token_for(client, "viewer1", "pw")
    # 사용자 목록은 admin 전용 → viewer 는 403
    r = client.get("/api/users", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_admin_can_create_user(client):
    make_user("admin1", "pw", role="admin")
    tok = token_for(client, "admin1", "pw")
    r = client.post("/api/users", headers={"Authorization": f"Bearer {tok}"},
                    json={"username": "newbie", "password": "pw", "role": "auditor"})
    assert r.status_code == 201
    assert r.json()["username"] == "newbie"


# ---- 비밀번호 변경(본인) ----

def test_change_own_password(client):
    make_user("u3", "oldpass12", role="viewer")
    h = {"Authorization": f"Bearer {token_for(client, 'u3', 'oldpass12')}"}
    # 현재 비밀번호 틀림 → 400
    bad = client.post("/api/auth/change-password", headers=h,
                      json={"current_password": "nope", "new_password": "newpass12"})
    assert bad.status_code == 400
    # 정상 변경 → 200, 옛 비번 실패·새 비번 성공
    ok = client.post("/api/auth/change-password", headers=h,
                     json={"current_password": "oldpass12", "new_password": "newpass12"})
    assert ok.status_code == 200
    assert client.post("/api/auth/login", json={"username": "u3", "password": "oldpass12"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "u3", "password": "newpass12"}).status_code == 200


def test_change_password_too_short(client):
    make_user("u4", "oldpass12")
    h = {"Authorization": f"Bearer {token_for(client, 'u4', 'oldpass12')}"}
    short = client.post("/api/auth/change-password", headers=h,
                        json={"current_password": "oldpass12", "new_password": "short"})
    assert short.status_code == 400


# ---- 비밀번호 재설정(admin) ----

def test_admin_reset_password(client):
    make_user("admin2", "adminpw12", role="admin")
    make_user("target", "targetpw12", role="viewer")
    ha = {"Authorization": f"Bearer {token_for(client, 'admin2', 'adminpw12')}"}
    tid = next(u["id"] for u in client.get("/api/users", headers=ha).json() if u["username"] == "target")
    r = client.post(f"/api/users/{tid}/reset-password", headers=ha, json={"new_password": "resetpw12"})
    assert r.status_code == 200
    assert client.post("/api/auth/login", json={"username": "target", "password": "resetpw12"}).status_code == 200


def test_reset_password_requires_admin(client):
    make_user("aud2", "audpw1234", role="auditor")
    h = {"Authorization": f"Bearer {token_for(client, 'aud2', 'audpw1234')}"}
    r = client.post("/api/users/1/reset-password", headers=h, json={"new_password": "whatever12"})
    assert r.status_code == 403
