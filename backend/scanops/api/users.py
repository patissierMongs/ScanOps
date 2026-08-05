"""사용자 관리 라우터 — admin 전용."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ROLES, User
from ..schemas import PasswordReset, UserCreate, UserOut
from ..security import hash_password, validate_password
from .audit import record
from .deps import require_role

router = APIRouter()

@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> User:
    try:
        validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"역할은 {ROLES} 중 하나여야 합니다.")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="이미 존재하는 아이디입니다.")
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
        display_name=body.display_name or body.username,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/{uid}/reset-password")
def reset_password(
    uid: int,
    body: PasswordReset,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """admin 이 임의 사용자의 비밀번호를 재설정(분실/유출 대응)."""
    user = db.get(User, uid)
    if user is None:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    try:
        validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    user.password_hash = hash_password(body.new_password)
    user.auth_version += 1
    db.commit()
    record(db, admin, "PASSWORD_RESET", target=user.username)
    return {"ok": True}
