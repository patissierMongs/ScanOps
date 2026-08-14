"""인증 라우터 — 로그인, 내 정보."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User
from ..schemas import LoginIn, PasswordChange, TokenOut, UserOut
from ..security import hash_password, make_token, validate_password, verify_password
from .audit import record, record_once
from .deps import _SECRET, authenticated_user

router = APIRouter()
_settings = get_settings()


def _utc_hour_bucket() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00Z")


def _record_failed_login(db: Session) -> None:
    record_once(
        db, None, "LOGIN", target="global",
        detail=f"실패 (UTC hour {_utc_hour_bucket()})", ok=False,
    )


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)) -> TokenOut:
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        _record_failed_login(db)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    if not user.is_active:
        _record_failed_login(db)
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다.")
    token = make_token(user.id, _SECRET, _settings.token_ttl_hours, user.auth_version)
    record(db, user, "LOGIN", target=body.username)
    return TokenOut(token=token, role=user.role, display_name=user.display_name)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(authenticated_user)) -> User:
    return user


@router.post("/change-password")
def change_password(
    body: PasswordChange,
    user: User = Depends(authenticated_user),
    db: Session = Depends(get_db),
) -> dict:
    """본인 비밀번호 변경 — 현재 비밀번호 검증 후 교체."""
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="현재 비밀번호가 올바르지 않습니다.")
    try:
        validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if body.new_password == body.current_password:
        # 강제 변경을 '같은 값으로 다시 저장'으로 통과시키면 잠금이 형식만 남는다.
        raise HTTPException(status_code=400, detail="이전과 다른 비밀번호여야 합니다.")
    user.password_hash = hash_password(body.new_password)
    user.auth_version += 1
    was_forced = bool(user.must_change_password)
    user.must_change_password = 0
    db.commit()
    record(db, user, "PASSWORD_CHANGE", target=user.username)
    if was_forced:
        _discard_initial_credentials(db, user)
    return {"ok": True}


def _discard_initial_credentials(db: Session, user: User) -> None:
    """최초 관리자 안내 파일을 지운다 — 그 비밀번호는 더 이상 유효하지 않다.

    평문 비밀번호가 담긴 파일을 '나중에 지우세요'로 두면 남는다. 실제로 지워진 뒤에야
    변경이 끝난 것이라, 삭제 결과를 감사 기록에 남긴다. 삭제에 실패해도 비밀번호 변경
    자체는 이미 커밋됐으므로 되돌리지 않는다 - 사람이 지울 수 있게 사실만 알린다.
    """
    path = _settings.data_dir / "INITIAL_ADMIN.txt"
    try:
        existed = path.exists()
        path.unlink(missing_ok=True)
    except OSError:
        record(db, user, "INITIAL_CREDENTIAL_DISCARD", target=path.name,
               detail="삭제 실패 - 직접 지우세요", ok=False)
        return
    if existed:
        record(db, user, "INITIAL_CREDENTIAL_DISCARD", target=path.name, detail="삭제됨")
