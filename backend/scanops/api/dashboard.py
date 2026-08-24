"""대시보드 라우터 — 운영 요약 지표."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ACTIVE_FINDING_STATES, RISK_LEVELS, Finding, ScanRun, User
from ..observation import is_confirmed_open, needs_confirmation
from .deps import current_user

router = APIRouter()


@router.get("")
def dashboard(_: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    # 이 지표들이 읽는 것은 아래 여섯 컬럼뿐이다. 예전에는 Finding 객체 전체를 실었는데,
    # 거기에는 배너·NSE·컴플라이언스 JSON 같은 큰 필드가 딸려 온다. 화면을 옮길 때마다
    # (App.jsx 가 매번 호출한다) 활성 발견 수만큼의 전송·할당이 반복됐다.
    # 계산은 그대로 두고 **싣는 열만** 줄인다 - 그래서 결과가 달라질 수 없다.
    active = db.query(
        Finding.state, Finding.reason, Finding.status, Finding.allowed,
        Finding.dept, Finding.risk_level,
    ).filter(Finding.state.in_(ACTIVE_FINDING_STATES)).all()
    unresolved = [f for f in active if f.status != "정상처리" and not f.allowed]
    now = datetime.now(timezone.utc)

    by_risk = dict(
        db.query(Finding.risk_level, func.count())
        .filter(Finding.state.in_(ACTIVE_FINDING_STATES)).group_by(Finding.risk_level).all()
    )
    by_status = dict(
        db.query(Finding.status, func.count())
        .filter(Finding.state.in_(ACTIVE_FINDING_STATES)).group_by(Finding.status).all()
    )
    by_dept_counts: dict[str, int] = {}
    unresolved_by_risk = {level: 0 for level in RISK_LEVELS}
    for finding in unresolved:
        dept = finding.dept or "(미지정)"
        by_dept_counts[dept] = by_dept_counts.get(dept, 0) + 1
        unresolved_by_risk[finding.risk_level] = unresolved_by_risk.get(finding.risk_level, 0) + 1
    by_dept = [
        {"dept": dept, "count": count}
        for dept, count in sorted(by_dept_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    # 세는 것만 하는 자리다. `db.query(Finding)...count()` 는 엔티티 전체를 감싼
    # 서브쿼리를 만든다 - 세는 데 필요 없는 열을 SQL 에 늘어놓는다.
    overdue = db.query(func.count(Finding.id)).filter(
        Finding.state.in_(ACTIVE_FINDING_STATES),
        Finding.deadline.isnot(None), Finding.deadline < now,
        Finding.status != "정상처리", Finding.allowed == 0,
    ).scalar() or 0
    recent_runs = db.query(ScanRun).order_by(ScanRun.id.desc()).limit(5).all()
    creator_ids = {scan.created_by for scan in recent_runs if scan.created_by is not None}
    creators = {
        user.id: (user.display_name or user.username)
        for user in db.query(User).filter(User.id.in_(creator_ids)).all()
    } if creator_ids else {}
    recent = [
        {"id": s.id, "name": s.name, "status": s.status,
          "host_count": s.host_count, "port_count": s.port_count,
          "created_by": s.created_by, "created_by_name": creators.get(s.created_by, ""),
          "started_at": s.started_at.isoformat()}
        for s in recent_runs
    ]
    return {
        # open_total 은 기존 클라이언트/내비게이션 배지 호환용 활성 발견 합계다. 아래 세 수치는
        # 증거 강도와 운영상 허용 여부를 별도 축으로 보여 주며 서로 배타적이라고 가정하지 않는다.
        "open_total": len(active),
        "confirmed_open_total": sum(
            1 for f in active if is_confirmed_open(f.state, f.reason)
        ),
        "confirmation_required_total": sum(
            1 for f in active if needs_confirmation(f.state, f.reason)
        ),
        "allowed_open_total": sum(1 for f in active if f.allowed),
        "unresolved_total": len(unresolved),
        "by_risk": by_risk,
        "unresolved_by_risk": unresolved_by_risk,
        "by_status": by_status,
        "by_dept": by_dept,
        "overdue": overdue,
        "recent_scans": recent,
    }
