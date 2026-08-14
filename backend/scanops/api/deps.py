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


def authenticated_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> User:
    """토큰이 가리키는 살아 있는 사용자. 비밀번호 변경 강제는 보지 않는다.

    비밀번호를 바꾸려면 먼저 로그인 상태여야 하므로, `/auth/me` 와 `/auth/change-password`
    는 이 의존성을 쓴다. 그 둘 말고는 전부 current_user 를 거쳐 잠긴다.
    """
    token = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    verified = verify_token(token, _SECRET)
    if verified is None:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    uid, token_version = verified
    user = db.get(User, uid)
    if user is None:
        raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다.")
    if not user.is_active or user.auth_version != token_version:
        # Import here to avoid the audit router's dependency on require_role creating a cycle.
        from .audit import record_once
        reason = "inactive" if not user.is_active else "auth_version_mismatch"
        record_once(db, user, "TOKEN_REJECTED", target=user.username, detail=reason, ok=False)
        raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다.")
    return user


def current_user(user: User = Depends(authenticated_user)) -> User:
    """실제 작업을 할 수 있는 사용자.

    남이 정해 준 비밀번호(최초 관리자 파일·admin 재설정)를 아직 쓰고 있으면 여기서 막는다.
    '로그인은 되지만 아무것도 못 한다'가 아니라 '먼저 바꾸라'는 뜻이고, 화면은 그 상태에서
    변경 창만 띄운다. 안내만 하고 통과시키면 파일에 평문으로 남은 비밀번호가 그대로 쓰인다.
    """
    if user.must_change_password:
        raise HTTPException(
            status_code=403,
            detail="비밀번호를 먼저 변경해야 합니다.",
        )
    return user


def require_role(min_role: str):
    """min_role 이상의 권한을 요구하는 의존성 팩토리."""
    def _guard(user: User = Depends(current_user)) -> User:
        if _RANK.get(user.role, -1) < _RANK[min_role]:
            raise HTTPException(status_code=403, detail="권한이 부족합니다.")
        return user
    return _guard
