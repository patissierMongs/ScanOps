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


# ── 최초 비밀번호 복구가 정상적인 재설정을 망가뜨리면 안 된다 ──

def test_a_password_reset_survives_the_next_startup(client, monkeypatch):
    """`must_change_password` 는 최초 설치 전용 표식이 **아니다.**

    admin 이 다른 관리자의 비밀번호를 재설정하면(`/users/{uid}/reset-password`) 그 플래그가
    똑같이 켜지는데, 그쪽은 INITIAL_ADMIN.txt 를 만들지 않는다. 파일 부재까지 '손상' 으로
    읽으면 다음 기동이 관리자가 정해 준 비밀번호를 **조용히 갈아치운다** - 그 비밀번호를
    전달받은 원격 관리자는 로그인할 수 없고, 새 비밀번호는 서버에 직접 접근해야 읽을 수
    있는 파일에만 남는다.
    """
    from scanops.db import SessionLocal
    from scanops.models import User
    from scanops.seed.bootstrap import get_settings, run_bootstrap
    from scanops.security import hash_password, verify_password

    cred = get_settings().data_dir / "INITIAL_ADMIN.txt"
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if admin is None:
            admin = User(username="admin", role="admin", display_name="관리자",
                         password_hash=hash_password("bootstrap-pw"), must_change_password=1)
            db.add(admin)
        # 관리자가 정해 준 비밀번호 - reset_password 가 하는 그대로.
        admin.password_hash = hash_password("Chosen-By-Admin-1234")
        admin.auth_version = (admin.auth_version or 0) + 1
        admin.must_change_password = 1
        db.commit()
    finally:
        db.close()
    cred.unlink(missing_ok=True)          # 재설정은 안내 파일을 만들지 않는다

    run_bootstrap()

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        assert verify_password("Chosen-By-Admin-1234", admin.password_hash), (
            "재기동이 관리자가 정해 준 비밀번호를 갈아치웠다"
        )
    finally:
        db.close()
    assert not cred.exists(), "재설정한 계정에 최초 안내 파일이 새로 생겼다"


def test_a_corrupt_credential_file_still_reissues_the_bootstrap_password(client):
    """반대 경계 - 원래 의도는 그대로 지켜야 한다.

    최초 비밀번호를 쓰는 중인데 안내 파일이 손상되면 기존 해시를 역산할 수 없다. 그때는
    재발급해야 설치가 영구 잠기지 않는다.
    """
    from scanops.db import SessionLocal
    from scanops.models import User
    from scanops.seed.bootstrap import get_settings, run_bootstrap
    from scanops.security import hash_password, verify_password

    cred = get_settings().data_dir / "INITIAL_ADMIN.txt"
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if admin is None:
            admin = User(username="admin", role="admin", display_name="관리자",
                         password_hash=hash_password("x"), must_change_password=1)
            db.add(admin)
        admin.password_hash = hash_password("bootstrap-pw")
        admin.must_change_password = 1
        db.commit()
    finally:
        db.close()
    cred.write_text("garbage", encoding="ascii")

    run_bootstrap()

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        assert not verify_password("bootstrap-pw", admin.password_hash), (
            "안내 파일이 손상됐는데 재발급하지 않았다 - 설치가 영구 잠긴다"
        )
    finally:
        db.close()
    assert cred.exists() and "garbage" not in cred.read_text(encoding="utf-8")


# ---- 초기 비밀번호 상태에서는 변경 외 API 를 막는다 ----

def test_an_unchanged_initial_password_only_reaches_me_and_change_password(client):
    from scanops.db import SessionLocal
    from scanops.models import User
    from scanops.security import hash_password

    db = SessionLocal()
    try:
        db.add(User(username="fresh", password_hash=hash_password("issued-by-admin1"),
                    role="admin", display_name="fresh", must_change_password=1))
        db.commit()
    finally:
        db.close()
    headers = {"Authorization": f"Bearer {token_for(client, 'fresh', 'issued-by-admin1')}"}

    assert client.get("/api/auth/me", headers=headers).status_code == 200
    for method, path in (("GET", "/api/findings"), ("GET", "/api/scans"),
                         ("GET", "/api/dashboard"), ("GET", "/api/users"),
                         ("POST", "/api/scans/import")):
        r = client.request(method, path, headers=headers)
        assert r.status_code == 403, (method, path, r.status_code, r.text)
        assert "비밀번호" in r.json()["detail"]

    changed = client.post("/api/auth/change-password", headers=headers,
                          json={"current_password": "issued-by-admin1",
                                "new_password": "chosen-by-owner2"})
    assert changed.status_code == 200
    fresh = {"Authorization": f"Bearer {token_for(client, 'fresh', 'chosen-by-owner2')}"}
    assert client.get("/api/findings", headers=fresh).status_code == 200


# ---- 로그인 무차별 대입 억제 ----

def test_repeated_login_failures_lock_the_account_for_a_while(client):
    from scanops import login_guard

    make_user("bruted", "correct-horse-1")
    for _ in range(login_guard.USER_MAX_FAILURES - 1):
        assert client.post("/api/auth/login",
                           json={"username": "bruted", "password": "nope"}).status_code == 401
    locked = client.post("/api/auth/login", json={"username": "bruted", "password": "nope"})
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0

    still = client.post("/api/auth/login", json={"username": "bruted", "password": "correct-horse-1"})
    assert still.status_code == 429

    login_guard.reset()
    assert client.post("/api/auth/login",
                       json={"username": "bruted", "password": "correct-horse-1"}).status_code == 200


def test_a_successful_login_clears_the_failure_count(client):
    from scanops import login_guard

    make_user("forgetful", "right-password-1")
    for _ in range(login_guard.USER_MAX_FAILURES - 1):
        client.post("/api/auth/login", json={"username": "forgetful", "password": "nope"})
    assert client.post("/api/auth/login",
                       json={"username": "forgetful", "password": "right-password-1"}).status_code == 200
    for _ in range(login_guard.USER_MAX_FAILURES - 1):
        r = client.post("/api/auth/login", json={"username": "forgetful", "password": "nope"})
        assert r.status_code == 401


def test_login_lock_expires_on_its_own():
    from scanops import login_guard

    login_guard.reset()
    for i in range(login_guard.USER_MAX_FAILURES):
        login_guard.record_failure("x", "1.2.3.4", now=1000.0 + i)
    assert login_guard.retry_after("x", "1.2.3.4", now=1010.0) > 0
    assert login_guard.retry_after("x", "1.2.3.4", now=1010.0 + login_guard.LOCK_SECONDS) == 0
    assert login_guard.retry_after("other", "9.9.9.9", now=1010.0) == 0


def test_an_unknown_username_is_hashed_like_a_real_one(client, monkeypatch):
    from scanops.api import auth as auth_api

    calls = []
    real = auth_api.verify_password

    def spy(password, stored):
        calls.append(stored)
        return real(password, stored)

    monkeypatch.setattr(auth_api, "verify_password", spy)
    r = client.post("/api/auth/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401
    assert calls == [auth_api._DUMMY_HASH]
