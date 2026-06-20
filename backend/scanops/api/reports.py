"""감사 리포트 라우터 — 발견 전체를 xlsx 로 산출(누가·언제·무엇을·어느 근거로)."""
from __future__ import annotations

import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import RISK_LABELS_KO, Finding, FindingEvent, ScanRun, User
from ..spreadsheet import safe_cell
from .deps import current_user

router = APIRouter()

_HEADERS = [
    "발견키", "IP", "호스트명", "포트", "프로토콜", "상태", "서비스", "제품", "버전",
    "식별", "분류", "용도", "위험등급", "운영상태", "부서", "마감", "등록 날짜", "스캔 날짜",
    "비고", "컴플라이언스근거",
]


def _row(f: Finding) -> list:
    comp = "; ".join(f"{c.get('std')}:{c.get('ref')}" for c in (f.compliance_json or []))
    return [
        f.finding_key, f.host_ip, f.hostname, f.port, f.proto, f.state, f.service,
        f.product, f.version, f.identification, f.category, f.usage,
        RISK_LABELS_KO.get(f.risk_level, f.risk_level),
        f.status, f.dept,
        f.deadline.strftime("%Y-%m-%d") if f.deadline else "",
        f.first_seen.strftime("%Y-%m-%d"), f.last_seen.strftime("%Y-%m-%d"),
        f.remarks, comp,
    ]


@router.get("/timeline")
def timeline(limit: int = 8, _: User = Depends(current_user), db: Session = Depends(get_db)):
    """시간축 히트맵 — 최근 스캔들을 열(시점)로, 포트(host|port|proto)를 행으로, 각 셀의 상태를
    4색으로(신규열림/지속열림/신규닫힘/지속닫힘). 발견 이벤트(NEW_OPEN/REOPENED/CLOSED)를
    스캔 순서대로 재생(replay)해 시점별 상태를 복원한다."""
    # started_at 동률(가져온 XML 들이 같은 스캔시각일 때)은 id 로 안정 정렬 → 시점 순서 보장.
    scans = (db.query(ScanRun)
             .order_by(ScanRun.started_at.desc(), ScanRun.id.desc())
             .limit(max(1, min(limit, 30))).all())
    scans = list(reversed(scans))   # 과거→현재
    scan_meta = [{"id": s.id, "label": s.started_at.strftime("%m-%d") if s.started_at else str(s.id),
                  "name": s.name} for s in scans]
    if not scans:
        return {"scans": [], "rows": [], "summary": {}}
    scan_ids = [s.id for s in scans]
    evs = (db.query(FindingEvent)
           .filter(FindingEvent.scan_id.in_(scan_ids),
                   FindingEvent.type.in_(("NEW_OPEN", "REOPENED", "CLOSED")))
           .all())
    by_finding: dict[int, dict[int, str]] = {}
    for e in evs:
        by_finding.setdefault(e.finding_id, {})[e.scan_id] = e.type
    if not by_finding:
        return {"scans": scan_meta, "rows": [], "summary": {}}
    findings = {f.id: f for f in db.query(Finding).filter(Finding.id.in_(by_finding.keys())).all()}

    rows = []
    summary = {"open_now": 0, "new_open": 0, "closed_recent": 0, "banned_open": 0}
    for fid, ev_map in by_finding.items():
        f = findings.get(fid)
        if f is None:
            continue
        cells, state = [], "none"   # state: none | open | closed
        for sid in scan_ids:
            t = ev_map.get(sid)
            if t in ("NEW_OPEN", "REOPENED"):
                cells.append("new_open"); state = "open"
            elif t == "CLOSED":
                cells.append("new_closed"); state = "closed"
            elif state == "open":
                cells.append("persist_open")
            elif state == "closed":
                cells.append("persist_closed")
            else:
                cells.append("none")
        last = cells[-1]
        if last in ("new_open", "persist_open"):
            summary["open_now"] += 1
            if last == "new_open":
                summary["new_open"] += 1
            if f.risk_level == "banned":
                summary["banned_open"] += 1
        elif last == "new_closed":
            summary["closed_recent"] += 1
        rows.append({"key": f.finding_key, "host": f.host_ip, "port": f.port, "proto": f.proto,
                     "service": f.service or "", "banned": f.risk_level == "banned", "cells": cells})
    rows.sort(key=lambda r: (r["host"], r["port"]))
    return {"scans": scan_meta, "rows": rows[:500], "summary": summary}


@router.get("/audit")
def audit_report(_: User = Depends(current_user), db: Session = Depends(get_db)):
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "감사리포트"
    ws.append(_HEADERS)
    for f in db.query(Finding).order_by(Finding.risk_level.desc(), Finding.host_ip, Finding.port).all():
        ws.append([safe_cell(v) for v in _row(f)])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=scanops_audit.xlsx"},
    )
