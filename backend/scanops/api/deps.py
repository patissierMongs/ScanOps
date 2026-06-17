"""인증 의존성 — 토큰에서 현재 사용자, 역할 가드."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User
from ..security import load_or_create_secret, verify_token

_settings = get_settings()
_SECRET = load_or_create_secret(_settings.secret_file)

# admin > auditor > viewer
_RANK = {"viewer": 0, "auditor": 1, "admin": 2}


def current_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> User:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    uid = verify_token(token, _SECRET)
    if uid is None:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    user = db.get(User, uid)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다.")
    return user


def require_role(min_role: str):
    """min_role 이상의 권한을 요구하는 의존성 팩토리."""
    def _guard(user: User = Depends(current_user)) -> User:
        if _RANK.get(user.role, -1) < _RANK[min_role]:
            raise HTTPException(status_code=403, detail="권한이 부족합니다.")
        return user
    return _guard
