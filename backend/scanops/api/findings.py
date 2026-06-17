"""발견 라우터 — 목록/조회/운영상태 변경(이력·감사 동반) + 선택컬럼 내보내기·재스캔명령."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import FINDING_STATUSES, RISK_LABELS_KO, Finding, FindingEvent, ScanRun, User
from ..schemas import (
    EventOut, FindingOut, FindingPatch, RescanIn, RescanOut, RescanRunIn, RescanRunOut,
)
from ..scanning import nmap_runner, scan_options, taxonomy
from ..scanning.ingest import ingest
from ..scanning.nmap_parse import parse_xml, up_hosts
from ..spreadsheet import safe_cell
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()


def _compliance(f: Finding) -> str:
    return "; ".join(f"{c.get('std')}:{c.get('ref')}" for c in (f.compliance_json or []))


# 내보내기/컬럼빌더 단일 진실원천: key → (헤더, 값 추출자). 프론트 lib/columns.js 가 이 키 집합을 미러링.
COLUMNS: list[tuple[str, str, object]] = [
    ("finding_key", "발견키", lambda f: f.finding_key),
    ("host_ip", "IP", lambda f: f.host_ip),
    ("hostname", "호스트명", lambda f: f.hostname),
    ("port", "포트", lambda f: f.port),
    ("proto", "프로토콜", lambda f: f.proto),
    ("state", "상태", lambda f: f.state),
    ("service", "서비스", lambda f: f.service),
    ("product", "제품", lambda f: f.product),
    ("version", "버전", lambda f: f.version),
    ("banner", "배너", lambda f: f.banner),
    ("cpe", "CPE", lambda f: f.cpe),
    ("rtt", "RTT", lambda f: f.rtt),
    ("identification", "식별", lambda f: f.identification),
    ("category", "분류", lambda f: f.category),
    ("usage", "용도", lambda f: f.usage),
    ("risk_level", "위험등급", lambda f: RISK_LABELS_KO.get(f.risk_level, f.risk_level)),
    ("remarks", "비고", lambda f: f.remarks),
    ("status", "운영상태", lambda f: f.status),
    ("dept", "부서", lambda f: f.dept),
    ("contact", "연락처", lambda f: f.contact),
    ("deadline", "마감", lambda f: f.deadline.strftime("%Y-%m-%d") if f.deadline else ""),
    ("first_seen", "등록 날짜", lambda f: f.first_seen.strftime("%Y-%m-%d")),
    ("last_seen", "스캔 날짜", lambda f: f.last_seen.strftime("%Y-%m-%d")),
    ("compliance", "컴플라이언스근거", _compliance),
    ("manual_note", "메모", lambda f: f.manual_note),
]
_COL_MAP = {key: (header, getter) for key, header, getter in COLUMNS}
_DEFAULT_COLS = ["host_ip", "port", "proto", "service", "version", "risk_level", "status", "dept", "deadline"]


def _filtered(db: Session, status, risk, host, q, state, dept=None):
    query = db.query(Finding)
    if status:
        query = query.filter(Finding.status == status)
    if risk:
        query = query.filter(Finding.risk_level == risk)
    if host:
        query = query.filter(Finding.host_ip == host)
    if state:
        query = query.filter(Finding.state == state)
    if dept:
        query = query.filter(Finding.dept == dept)
    if q:
        like = f"%{q}%"
        query = query.filter(Finding.service.like(like) | Finding.hostname.like(like))
    return query.order_by(Finding.host_ip, Finding.port)


@router.get("", response_model=list[FindingOut])
def list_findings(
    status: str | None = None,
    risk: str | None = None,
    host: str | None = None,
    q: str | None = None,
    state: str | None = "open",
    dept: str | None = None,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return _filtered(db, status, risk, host, q, state, dept).all()


# --- /export 와 /rescan-command 는 /{fid} 보다 먼저 등록해야 경로 충돌이 없다 ---

@router.get("/export")
def export_findings(
    cols: str = "",
    fmt: str = "csv",
    status: str | None = None,
    risk: str | None = None,
    host: str | None = None,
    q: str | None = None,
    state: str | None = "open",
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    keys = [c.strip() for c in cols.split(",") if c.strip()] or _DEFAULT_COLS
    unknown = [k for k in keys if k not in _COL_MAP]
    if unknown:
        raise HTTPException(status_code=400, detail=f"알 수 없는 컬럼: {unknown}")
    headers = [_COL_MAP[k][0] for k in keys]
    rows = _filtered(db, status, risk, host, q, state).all()

    if fmt == "xlsx":
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "발견"
        ws.append(headers)
        for f in rows:
            ws.append([safe_cell(_COL_MAP[k][1](f)) for k in keys])
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=scanops_findings.xlsx"},
        )

    # CSV — 한국 Excel 대비 UTF-8 BOM 선두 + RFC quoting
    sio = io.StringIO()
    w = csv.writer(sio, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(headers)
    for f in rows:
        w.writerow([safe_cell(_COL_MAP[k][1](f)) for k in keys])
    body = ("﻿" + sio.getvalue()).encode("utf-8")
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=scanops_findings.csv"},
    )


@router.post("/rescan-command", response_model=RescanOut)
def rescan_command(
    body: RescanIn,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(Finding).filter(Finding.id.in_(body.finding_ids)).all() if body.finding_ids else []
    hosts = sorted({f.host_ip for f in rows})
    ports = sorted({f.port for f in rows})
    if not hosts or not ports:
        return RescanOut(command="", hosts=hosts, ports=ports, finding_count=len(rows))
    flags = body.preset_flags.strip() or "-sV -Pn"
    port_str = ",".join(str(p) for p in ports)
    command = f"nmap {flags} -p {port_str} {' '.join(hosts)}"
    return RescanOut(command=command, hosts=hosts, ports=ports, finding_count=len(rows))


@router.post("/rescan", response_model=RescanRunOut)
def rescan_run(
    body: RescanRunIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """선택 발견의 호스트/포트로 실제 nmap 타겟 스캔 실행 → ingest(조치 자동검증).

    닫힘 판정은 선택한 포트(scope_keys)로만 한정 — 다른 포트 거짓 닫힘 방지.
    """
    rows = db.query(Finding).filter(Finding.id.in_(body.finding_ids)).all() if body.finding_ids else []
    if not rows:
        raise HTTPException(status_code=400, detail="재스캔할 발견을 선택하세요.")
    hosts = sorted({f.host_ip for f in rows})
    ports = sorted({f.port for f in rows})
    scope_keys = {f.finding_key for f in rows}

    nmap = nmap_runner.find_nmap(_settings.nmap_path)
    if not nmap:
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    opts = body.options or scan_options.DEFAULT_KEYS
    port_spec = body.ports.strip() or ",".join(str(p) for p in ports)

    scan = ScanRun(name=f"타겟 재스캔: {len(rows)}건", targets=" ".join(hosts),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    basename = _settings.scans_dir / f"scan_{scan.id}"
    xml_path = nmap_runner.xml_of(basename)
    log_path = _settings.scans_dir / f"scan_{scan.id}.log"
    try:
        argv = nmap_runner.build_command_opts(nmap, opts, port_spec, hosts, basename)
        scan.command = " ".join(argv)
        db.commit()
        rc = nmap_runner._spawn(argv, log_path, 3600)
        if rc != 0 or not xml_path.exists():
            scan.status = "failed"
            db.commit()
            raise HTTPException(status_code=500, detail=f"재스캔 실패 (코드 {rc}).")
        scan.raw_xml_path = str(xml_path)
        xml_bytes = xml_path.read_bytes()
        enriched = taxonomy.enrich_all(db, parse_xml(xml_bytes))
        counts = ingest(db, scan.id, enriched, up_hosts(xml_bytes), scope_keys=scope_keys)
        from .assets import match_assets
        match_assets(db)
        scan.host_count = len(hosts)
        scan.port_count = len(enriched)
        scan.status = "done"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    except ValueError as e:
        scan.status = "failed"
        db.commit()
        raise HTTPException(status_code=400, detail=str(e))
    return RescanRunOut(scan_id=scan.id, command=scan.command, counts=counts, hosts=hosts, ports=ports)


@router.get("/{fid}", response_model=FindingOut)
def get_finding(fid: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.get(Finding, fid)
    if row is None:
        raise HTTPException(status_code=404, detail="발견을 찾을 수 없습니다.")
    return row


@router.get("/{fid}/events", response_model=list[EventOut])
def finding_events(fid: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.get(Finding, fid) is None:
        raise HTTPException(status_code=404, detail="발견을 찾을 수 없습니다.")
    return db.query(FindingEvent).filter_by(finding_id=fid).order_by(FindingEvent.created_at).all()


@router.patch("/{fid}", response_model=FindingOut)
def patch_finding(
    fid: int,
    body: FindingPatch,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    row = db.get(Finding, fid)
    if row is None:
        raise HTTPException(status_code=404, detail="발견을 찾을 수 없습니다.")

    def log(type_: str, detail: str):
        db.add(FindingEvent(finding_id=fid, type=type_, detail=detail, actor_user_id=user.id))

    if body.status is not None and body.status != row.status:
        if body.status not in FINDING_STATUSES:
            raise HTTPException(status_code=400, detail=f"상태는 {FINDING_STATUSES} 중 하나여야 합니다.")
        log("STATUS_CHANGE", f"{row.status} → {body.status}")
        row.status = body.status
    if body.owner_user_id is not None and body.owner_user_id != row.owner_user_id:
        log("ASSIGN", f"담당자 #{body.owner_user_id} 배정")
        row.owner_user_id = body.owner_user_id
    if body.deadline is not None and body.deadline != row.deadline:
        log("DEADLINE", f"마감 {body.deadline:%Y-%m-%d} 설정")
        row.deadline = body.deadline
    if body.dept is not None:
        row.dept = body.dept
    if body.manual_note is not None and body.manual_note != row.manual_note:
        log("NOTE", "메모 변경")
        row.manual_note = body.manual_note
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return row
