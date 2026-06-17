"""감사 로그 라우터 + 기록 헬퍼 — 민감 행위를 '누가·언제·무엇'으로 남긴다.

record() 는 다른 라우터(스캔/규칙/로그인)에서 부른다. 조회는 admin 전용.
감사 기록 실패가 본 기능을 막으면 안 되므로 record() 는 예외를 삼킨다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, User
from ..schemas import AuditOut
from .deps import require_role

router = APIRouter()


def record(db: Session, actor: User | None, action: str,
           target: str = "", detail: str = "", ok: bool = True) -> None:
    """감사 한 줄 기록. 본 트랜잭션과 독립 커밋(호출부 롤백에 영향받지 않게)."""
    try:
        db.add(AuditLog(
            actor_user_id=actor.id if actor else None,
            actor_name=actor.username if actor else "",
            action=action, target=target[:256], detail=detail, ok=1 if ok else 0,
        ))
        db.commit()
    except Exception:
        db.rollback()


@router.get("", response_model=list[AuditOut])
def list_audit(
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=1000),
    action: str = "",
):
    """최근 감사 로그(최신순). action 으로 필터 가능."""
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    return q.order_by(AuditLog.id.desc()).limit(limit).all()
