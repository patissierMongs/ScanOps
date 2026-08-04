"""감사 로그 라우터 + 기록 헬퍼 — 민감 행위를 '누가·언제·무엇'으로 남긴다.

record() 는 다른 라우터(스캔/규칙/로그인)에서 부른다. 조회는 admin 전용.
감사 기록 실패가 본 기능을 막으면 안 되므로 record() 는 예외를 삼킨다.
"""
from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, User
from ..schemas import AuditOut
from .deps import require_role

router = APIRouter()
_RECORD_ONCE_LOCK = threading.Lock()


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


def record_once(db: Session, actor: User | None, action: str,
                target: str = "", detail: str = "", ok: bool = True) -> None:
    """동일 행위 키의 반복 감사 쓰기를 1건으로 제한한다.

    actor=None 인 전역 이벤트와 폐기 토큰처럼 공격자가 임의로 무한 재시도할 수
    있는 경로에만 사용한다.
    실제 비밀번호 변경/재설정 행위는 별도 감사 이벤트로 매번 남는다.
    """
    with _RECORD_ONCE_LOCK:
        try:
            actor_filter = (
                AuditLog.actor_user_id == actor.id
                if actor is not None
                else AuditLog.actor_user_id.is_(None)
            )
            exists = db.query(AuditLog.id).filter(
                actor_filter,
                AuditLog.action == action,
                AuditLog.target == target[:256],
                AuditLog.detail == detail,
                AuditLog.ok == (1 if ok else 0),
            ).first()
        except Exception:
            # 감사 중복 확인 장애도 로그인 응답을 500으로 바꾸지 않는다.
            db.rollback()
            return
        if exists is None:
            record(db, actor, action, target=target, detail=detail, ok=ok)


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
