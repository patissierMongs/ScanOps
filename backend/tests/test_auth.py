"""Phase B 검증 — 인증/역할."""
import pytest

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
                    json={"username": "newbie", "password": "newbie12", "role": "auditor"})
    assert r.status_code == 201
    assert r.json()["username"] == "newbie"


def test_admin_cannot_create_user_with_short_password(client):
    make_user("admin-short", "adminpw12", role="admin")
    h = {"Authorization": f"Bearer {token_for(client, 'admin-short', 'adminpw12')}"}
    r = client.post("/api/users", headers=h,
                    json={"username": "weak", "password": "pw", "role": "viewer"})
    assert r.status_code == 400
    assert "8자" in r.json()["detail"]


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
    assert client.get("/api/auth/me", headers=h).status_code == 401
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
    old_target_token = token_for(client, "target", "targetpw12")
    tid = next(u["id"] for u in client.get("/api/users", headers=ha).json() if u["username"] == "target")
    r = client.post(f"/api/users/{tid}/reset-password", headers=ha, json={"new_password": "resetpw12"})
    assert r.status_code == 200
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {old_target_token}"}
    ).status_code == 401
    rejected = client.get("/api/audit?action=TOKEN_REJECTED", headers=ha).json()
    assert any(
        log["target"] == "target"
        and log["detail"] == "auth_version_mismatch"
        and log["ok"] == 0
        for log in rejected
    )
    assert client.post("/api/auth/login", json={"username": "target", "password": "resetpw12"}).status_code == 200

    logs = client.get("/api/audit?action=PASSWORD_RESET", headers=ha).json()
    assert any(log["target"] == "target" for log in logs)


def test_repeated_revoked_token_requests_create_one_bounded_audit_row(client):
    from scanops.db import SessionLocal
    from scanops.models import AuditLog

    make_user("bounded-admin", "adminpw12", role="admin")
    make_user("bounded-target", "targetpw12", role="viewer")
    admin_headers = {
        "Authorization": f"Bearer {token_for(client, 'bounded-admin', 'adminpw12')}"
    }
    old_token = token_for(client, "bounded-target", "targetpw12")
    target_id = next(
        user["id"] for user in client.get("/api/users", headers=admin_headers).json()
        if user["username"] == "bounded-target"
    )
    assert client.post(
        f"/api/users/{target_id}/reset-password", headers=admin_headers,
        json={"new_password": "newtarget12"},
    ).status_code == 200

    old_headers = {"Authorization": f"Bearer {old_token}"}
    assert [client.get("/api/auth/me", headers=old_headers).status_code for _ in range(5)] == [401] * 5
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter_by(
            actor_user_id=target_id,
            action="TOKEN_REJECTED",
            detail="auth_version_mismatch",
        ).count() == 1
    finally:
        db.close()


def test_reset_password_requires_admin(client):
    make_user("aud2", "audpw1234", role="auditor")
    h = {"Authorization": f"Bearer {token_for(client, 'aud2', 'audpw1234')}"}
    r = client.post("/api/users/1/reset-password", headers=h, json={"new_password": "whatever12"})
    assert r.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "auditor", "admin"])
def test_admin_reset_revokes_old_tokens_for_every_role(client, role):
    admin_name = f"reset-admin-{role}"
    target_name = f"reset-target-{role}"
    make_user(admin_name, "adminpw12", role="admin")
    make_user(target_name, "targetpw12", role=role)
    admin_headers = {
        "Authorization": f"Bearer {token_for(client, admin_name, 'adminpw12')}"
    }
    old_token = token_for(client, target_name, "targetpw12")
    target_id = next(
        user["id"] for user in client.get("/api/users", headers=admin_headers).json()
        if user["username"] == target_name
    )

    reset = client.post(
        f"/api/users/{target_id}/reset-password", headers=admin_headers,
        json={"new_password": "newtarget12"},
    )

    assert reset.status_code == 200
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {old_token}"},
    ).status_code == 401
    new_login = client.post(
        "/api/auth/login", json={"username": target_name, "password": "newtarget12"},
    )
    assert new_login.status_code == 200
    assert new_login.json()["role"] == role


def test_inactive_account_token_is_rejected_immediately(client):
    from scanops.db import SessionLocal
    from scanops.models import AuditLog, User

    make_user("deactivated", "targetpw12", role="auditor")
    token = token_for(client, "deactivated", "targetpw12")
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username="deactivated").one()
        user.is_active = 0
        db.commit()
    finally:
        db.close()

    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"},
    ).status_code == 401
    db = SessionLocal()
    try:
        rejected = db.query(AuditLog).filter_by(
            action="TOKEN_REJECTED", target="deactivated",
        ).one()
        assert rejected.detail == "inactive"
        assert rejected.ok == 0
    finally:
        db.close()


def test_self_password_change_revocation_is_audited(client):
    make_user("self-admin", "oldpass12", role="admin")
    token = token_for(client, "self-admin", "oldpass12")
    headers = {"Authorization": f"Bearer {token}"}

    changed = client.post(
        "/api/auth/change-password", headers=headers,
        json={"current_password": "oldpass12", "new_password": "newpass12"},
    )

    assert changed.status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    new_headers = {
        "Authorization": f"Bearer {token_for(client, 'self-admin', 'newpass12')}"
    }
    logs = client.get("/api/audit?action=PASSWORD_CHANGE", headers=new_headers).json()
    assert any(log["target"] == "self-admin" for log in logs)
