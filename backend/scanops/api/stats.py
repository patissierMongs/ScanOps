"""통계 라우터 — 포트·서비스·제품 빈출 집계.

'우리 망에 무엇이 제일 많이 열려 있나'에 답하는 자리다. 발견 목록은 endpoint 하나씩을
보여 주고, 히트맵은 시간축을 보여 주며, 여기는 **분포**를 본다.

**확정 열림과 무응답 추정을 절대 한 수로 합치지 않는다.** UDP 는 응답이 없으면 nmap 이
`open|filtered` 로 보고하고 ScanOps 는 그것을 '무응답 추정' 으로 센다. 둘을 더해 한 칸에
쓰면 방화벽이 조용히 버리는 대역에서 UDP 포트가 상위를 싹쓸이하면서 "우리 망에 SNMP 가
제일 많다" 같은 거짓 결론이 나온다 — 실제로는 아무도 응답하지 않았다는 뜻인데도.
그래서 모든 행이 두 수를 따로 들고 다니고, 기본 정렬도 **확정 열림** 기준이다.

집계는 SQL 로 한다. 발견이 쌓인 설치에서 이 화면을 열 때마다 ORM 객체를 만들 이유가 없다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, case, distinct, func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ACTIVE_FINDING_STATES, Finding, User
from ..observation import needs_confirmation
from .deps import current_user

router = APIRouter()

# 한 축에서 돌려주는 최대 행 수. 화면은 상위 N 만 그리고 나머지는 '그 외' 로 접는다.
TOP_N = 40
# 기간 필터가 없을 때의 기본 — 전체. 0 이면 제한 없음.
DEFAULT_DAYS = 0

# 무응답 추정으로 세는 상태·근거. `observation.needs_confirmation` 과 같은 판정을
# SQL 로 옮긴 것이라, 둘이 어긋나면 통계와 발견 목록이 다른 말을 한다 - 계약 테스트가
# 같은 입력에 같은 답을 내는지 검사한다.
_INFERRED_STATE = "open|filtered"
_INFERRED_REASON = "no-response"


def _inferred_clause():
    """무응답 추정인가 — 상태가 `open|filtered` 이거나 근거가 무응답."""
    return case(
        (Finding.state == _INFERRED_STATE, 1),
        (Finding.reason == _INFERRED_REASON, 1),
        else_=0,
    )


def _base_filters(dept: str | None, risk: str | None, proto: str | None,
                  days: int, include_resolved: bool, include_allowed: bool) -> list:
    """모든 축이 공유하는 조건. 한 곳에서만 만들어 축마다 다른 모수를 쓰지 않게 한다."""
    clauses = [Finding.state.in_(ACTIVE_FINDING_STATES)]
    if dept:
        clauses.append(Finding.dept == dept)
    if risk:
        clauses.append(Finding.risk_level == risk)
    if proto in ("tcp", "udp"):
        clauses.append(Finding.proto == proto)
    if not include_resolved:
        clauses.append(Finding.status != "정상처리")
    if not include_allowed:
        clauses.append(Finding.allowed == 0)
    if days and days > 0:
        # **마지막 관측 시각** 기준이다. 그 기간에 실제로 본 것만 센다 - first_seen 으로
        # 자르면 오래전에 찾아 두고 최근에는 확인도 안 한 포트가 '지금 열려 있는 것' 으로
        # 섞인다.
        since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
        clauses.append(Finding.last_seen >= since)
    return clauses


def _rows(db: Session, group_cols: list, clauses: list, limit: int) -> list[dict]:
    """한 축의 집계 행. (그룹 키…, 호스트 수, 확정, 추정) 순으로 돌려준다."""
    inferred = _inferred_clause()
    query = db.query(
        *group_cols,
        func.count(distinct(Finding.host_ip)).label("hosts"),
        func.count().label("findings"),
        func.sum(inferred).cast(Integer).label("inferred"),
    ).filter(*clauses).group_by(*group_cols)
    out = []
    for row in query.all():
        keys = list(row)[:len(group_cols)]
        hosts, findings, inferred_n = row[-3], row[-2], row[-1] or 0
        out.append({
            "keys": keys,
            "hosts": int(hosts or 0),
            "findings": int(findings or 0),
            "confirmed": int(findings or 0) - int(inferred_n),
            "inferred": int(inferred_n),
        })
    # 확정 열림이 많은 순 - 추정만 잔뜩인 UDP 포트가 상위를 차지하지 않게 한다.
    out.sort(key=lambda r: (-r["confirmed"], -r["findings"], str(r["keys"])))
    return out[:limit]


@router.get("")
def stats(
    dept: str | None = None,
    risk: str | None = None,
    proto: str | None = None,
    days: int = DEFAULT_DAYS,
    include_resolved: bool = False,
    include_allowed: bool = False,
    limit: int = TOP_N,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    limit = max(1, min(int(limit or TOP_N), 200))
    clauses = _base_filters(dept, risk, proto, int(days or 0),
                            include_resolved, include_allowed)

    ports = [
        {"port": int(r["keys"][0]), "proto": (r["keys"][1] or "").lower(),
         **{k: r[k] for k in ("hosts", "findings", "confirmed", "inferred")}}
        for r in _rows(db, [Finding.port, Finding.proto], clauses, limit)
    ]
    services = [
        {"service": (r["keys"][0] or "").strip() or "(미식별)",
         **{k: r[k] for k in ("hosts", "findings", "confirmed", "inferred")}}
        for r in _rows(db, [Finding.service], clauses, limit)
    ]
    products = [
        {"product": (r["keys"][0] or "").strip() or "(미식별)",
         **{k: r[k] for k in ("hosts", "findings", "confirmed", "inferred")}}
        for r in _rows(db, [Finding.product], clauses, limit)
    ]

    inferred = _inferred_clause()
    total_findings, total_hosts, total_inferred = db.query(
        func.count(),
        func.count(distinct(Finding.host_ip)),
        func.sum(inferred).cast(Integer),
    ).filter(*clauses).one()
    total_findings = int(total_findings or 0)
    total_inferred = int(total_inferred or 0)

    by_risk = dict(
        db.query(Finding.risk_level, func.count()).filter(*clauses)
        .group_by(Finding.risk_level).all()
    )
    depts = [
        row[0] for row in db.query(distinct(Finding.dept))
        .filter(Finding.state.in_(ACTIVE_FINDING_STATES)).all() if row[0]
    ]

    return {
        "totals": {
            "findings": total_findings,
            "hosts": int(total_hosts or 0),
            "confirmed": total_findings - total_inferred,
            "inferred": total_inferred,
        },
        "ports": ports,
        "services": services,
        "products": products,
        "by_risk": by_risk,
        # 화면의 부서 선택지 - 필터가 걸린 뒤의 목록이 아니라 전체여야 다른 부서로 옮길 수 있다.
        "dept_options": sorted(depts),
        "filters": {
            "dept": dept or "", "risk": risk or "", "proto": proto or "",
            "days": int(days or 0), "include_resolved": bool(include_resolved),
            "include_allowed": bool(include_allowed), "limit": limit,
        },
        "truncated": {
            "ports": len(ports) >= limit,
            "services": len(services) >= limit,
            "products": len(products) >= limit,
        },
    }


@router.get("/export")
def export_stats(
    axis: str = "ports",
    dept: str | None = None,
    risk: str | None = None,
    proto: str | None = None,
    days: int = DEFAULT_DAYS,
    include_resolved: bool = False,
    include_allowed: bool = False,
    limit: int = 1000,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """현재 필터 그대로 CSV. 축 하나만 내보낸다(엑셀에서 합치는 편이 낫다)."""
    import csv
    import io

    from fastapi.responses import StreamingResponse

    data = stats(dept=dept, risk=risk, proto=proto, days=days,
                 include_resolved=include_resolved, include_allowed=include_allowed,
                 limit=max(1, min(int(limit or 1000), 5000)), _=user, db=db)
    axis = axis if axis in ("ports", "services", "products") else "ports"
    head = {
        "ports": ["포트", "프로토콜"],
        "services": ["서비스"],
        "products": ["제품"],
    }[axis]
    keys = {
        "ports": ["port", "proto"], "services": ["service"], "products": ["product"],
    }[axis]

    buf = io.StringIO()
    buf.write("﻿")          # 엑셀이 UTF-8 로 읽게 한다
    writer = csv.writer(buf)
    writer.writerow([*head, "호스트", "발견", "확정 열림", "무응답 추정"])
    for row in data[axis]:
        writer.writerow([*[row[k] for k in keys],
                         row["hosts"], row["findings"], row["confirmed"], row["inferred"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scanops-stats-{axis}.csv"'},
    )
