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
from .deps import _SECRET, current_user

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
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/change-password")
def change_password(
    body: PasswordChange,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """본인 비밀번호 변경 — 현재 비밀번호 검증 후 교체."""
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="현재 비밀번호가 올바르지 않습니다.")
    try:
        validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    user.password_hash = hash_password(body.new_password)
    user.auth_version += 1
    db.commit()
    record(db, user, "PASSWORD_CHANGE", target=user.username)
    return {"ok": True}
