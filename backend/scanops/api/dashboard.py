"""대시보드 라우터 — 운영 요약 지표."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Finding, ScanRun, User
from .deps import current_user

router = APIRouter()


@router.get("")
def dashboard(_: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    open_q = db.query(Finding).filter(Finding.state == "open")
    now = datetime.now(timezone.utc)

    by_risk = dict(
        db.query(Finding.risk_level, func.count())
        .filter(Finding.state == "open").group_by(Finding.risk_level).all()
    )
    by_status = dict(
        db.query(Finding.status, func.count())
        .filter(Finding.state == "open").group_by(Finding.status).all()
    )
    by_dept = [
        {"dept": d or "(미지정)", "count": c}
        for d, c in db.query(Finding.dept, func.count())
        .filter(Finding.state == "open").group_by(Finding.dept).order_by(func.count().desc()).all()
    ]
    overdue = (
        open_q.filter(Finding.deadline.isnot(None), Finding.deadline < now,
                      Finding.status != "정상처리").count()
    )
    recent = [
        {"id": s.id, "name": s.name, "status": s.status,
         "host_count": s.host_count, "port_count": s.port_count,
         "started_at": s.started_at.isoformat()}
        for s in db.query(ScanRun).order_by(ScanRun.id.desc()).limit(5).all()
    ]
    return {
        "open_total": open_q.count(),
        "by_risk": by_risk,
        "by_status": by_status,
        "by_dept": by_dept,
        "overdue": overdue,
        "recent_scans": recent,
    }
