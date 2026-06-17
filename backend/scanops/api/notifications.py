"""부서통보 라우터 — 부서별 미조치 발견을 묶어 통보문 생성/기록.

에어갭 서버: '발송'은 통보문 텍스트 생성 + 기록(붙여넣기/파일용). 외부 전송 없음.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import RISK_LABELS_KO, Finding, Notification, User
from ..schemas import NotifyOut, NotifyPreview, NotifySend
from .deps import current_user, require_role

router = APIRouter()


def _open_findings_for_dept(db: Session, dept: str) -> list[Finding]:
    return (
        db.query(Finding)
        .filter(Finding.dept == dept, Finding.state == "open", Finding.status != "정상처리")
        .order_by(Finding.risk_level.desc(), Finding.host_ip, Finding.port)
        .all()
    )


def _build_body(dept: str, rows: list[Finding]) -> str:
    contact = next((r.contact for r in rows if r.contact), "")
    owners = sorted({r.owner for r in rows if r.owner})
    head = f"[{dept}] 네트워크 노출 점검 통보"
    lines = [head, f"미조치 발견 {len(rows)}건"]
    if owners:
        lines.append(f"담당자: {', '.join(owners)}")
    if contact:
        lines.append(f"담당 연락처: {contact}")
    lines.append("")
    for r in rows:
        dl = f" · 마감 {r.deadline:%Y-%m-%d}" if r.deadline else ""
        who = f" ({r.owner})" if r.owner else ""
        risk = RISK_LABELS_KO.get(r.risk_level, r.risk_level)
        lines.append(f"- {r.host_ip}:{r.port}/{r.proto} {r.service}{who} "
                     f"[{risk}] {r.status}{dl}")
    return "\n".join(lines)


@router.get("/preview", response_model=NotifyPreview)
def preview(dept: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = _open_findings_for_dept(db, dept)
    return NotifyPreview(dept=dept, finding_count=len(rows), body=_build_body(dept, rows))


@router.post("", response_model=NotifyOut, status_code=201)
def send(
    dept: str = "",
    payload: NotifySend | None = Body(default=None),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """통보 기록. payload.body 가 오면 프론트가 렌더한 문구를 저장, 없으면 서버 기본 생성."""
    d = (payload.dept if payload and payload.dept else dept).strip()
    if not d:
        raise HTTPException(status_code=400, detail="부서가 필요합니다.")
    rows = _open_findings_for_dept(db, d)
    body = payload.body if (payload and payload.body) else _build_body(d, rows)
    fids = payload.finding_ids if (payload and payload.finding_ids) else [r.id for r in rows]
    note = Notification(dept=d, finding_ids_json=fids, body=body, channel="file", sent_by=user.id)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.get("", response_model=list[NotifyOut])
def history(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.query(Notification).order_by(Notification.id.desc()).all()
