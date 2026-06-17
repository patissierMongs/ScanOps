"""전역 이력 피드 라우터 — 모든 발견의 변화 이력을 한 화면 타임라인용으로.

발견별 드로어(/findings/{id}/events)와 달리, 전체 FindingEvent 를 Finding 과 조인해
host/port/service 를 동반한 평탄한 피드로 돌려준다. 타입/호스트/기간 필터 + 페이지네이션.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, FindingEvent, User
from ..schemas import EventFeed, EventFeedItem
from .deps import current_user

router = APIRouter()


@router.get("", response_model=EventFeed)
def event_feed(
    type: str | None = None,
    host: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    q = db.query(FindingEvent, Finding).join(Finding, FindingEvent.finding_id == Finding.id)
    if type:
        q = q.filter(FindingEvent.type == type)
    if host:
        q = q.filter(Finding.host_ip == host)
    if since:
        q = q.filter(FindingEvent.created_at >= since)
    if until:
        q = q.filter(FindingEvent.created_at <= until)

    total = q.count()
    rows = (
        q.order_by(FindingEvent.created_at.desc(), FindingEvent.id.desc())
        .offset(offset).limit(limit).all()
    )
    items = [
        EventFeedItem(
            id=ev.id, finding_id=ev.finding_id, type=ev.type, detail=ev.detail,
            host_ip=f.host_ip, port=f.port, service=f.service,
            actor_user_id=ev.actor_user_id, scan_id=ev.scan_id, created_at=ev.created_at,
        )
        for ev, f in rows
    ]
    return EventFeed(total=total, items=items)
