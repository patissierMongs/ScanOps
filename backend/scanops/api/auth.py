"""인증 라우터 — 로그인, 내 정보."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User
from ..schemas import LoginIn, PasswordChange, TokenOut, UserOut
from ..security import hash_password, make_token, verify_password
from .audit import record
from .deps import _SECRET, current_user

_MIN_PASSWORD_LEN = 8

router = APIRouter()
_settings = get_settings()


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)) -> TokenOut:
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        record(db, user, "LOGIN", target=body.username, detail="실패", ok=False)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    if not user.is_active:
        record(db, user, "LOGIN", target=body.username, detail="비활성 계정", ok=False)
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다.")
    token = make_token(user.id, _SECRET, _settings.token_ttl_hours)
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
    if len(body.new_password) < _MIN_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail=f"새 비밀번호는 {_MIN_PASSWORD_LEN}자 이상이어야 합니다.")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}
