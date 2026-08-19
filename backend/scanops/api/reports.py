"""감사 리포트 라우터 — 발견 전체를 xlsx 로 산출(누가·언제·무엇을·어느 근거로)."""
from __future__ import annotations

import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..identity import display_identity
from ..models import RISK_LABELS_KO, Finding, User
from ..observation import exposure_text
from ..spreadsheet import safe_cell
from .deps import current_user

router = APIRouter()

_HEADERS = [
    "발견키", "IP", "호스트명", "포트", "프로토콜", "상태", "표시 식별", "Server",
    "서비스", "제품", "버전",
    "식별", "분류", "용도", "위험등급", "운영상태", "부서", "마감", "등록 날짜", "스캔 날짜",
    "비고", "컴플라이언스근거", "노출관측",
]


def _row(f: Finding) -> list:
    comp = "; ".join(f"{c.get('std')}:{c.get('ref')}" for c in (f.compliance_json or []))
    # 노출 관측(익명 FTP·무인증·평문·만료 인증서 등)은 '왜 위험한가'의 핵심 근거인데 감사본에만
    # 빠져 있었다 — 발견 뷰 내보내기(findings.py)엔 이미 있는 값이라 같은 규칙으로 한 칸 싣는다.
    # 값을 여기서 다시 만들지 않고 발견 뷰·필터와 **같은 함수**를 쓴다 - 같은 값을 뷰마다 따로
    # 만드는 것이 이 결함을 만든 원인이라, 세 번째 복사본을 두면 또 갈린다.
    exposure = exposure_text(f.exposure_json)
    return [
        f.finding_key, f.host_ip, f.hostname, f.port, f.proto, f.state,
        display_identity(server=f.server, product=f.product, version=f.version, service=f.service,
                         identification=f.identification),
        f.server, f.service, f.product, f.version, f.identification, f.category, f.usage,
        RISK_LABELS_KO.get(f.risk_level, f.risk_level),
        f.status, f.dept,
        f.deadline.strftime("%Y-%m-%d") if f.deadline else "",
        f.first_seen.strftime("%Y-%m-%d"), f.last_seen.strftime("%Y-%m-%d"),
        f.remarks, comp, exposure,
    ]


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
