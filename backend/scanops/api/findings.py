"""발견 라우터 — 목록/조회/운영상태 변경(이력·감사 동반) + 선택컬럼 내보내기·재스캔명령."""
from __future__ import annotations

import csv
import io
import json
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import FINDING_STATUSES, RISK_LABELS_KO, Finding, FindingEvent, ScanRun, User
from ..schemas import (
    EventOut, FindingOut, FindingPatch, RescanIn, RescanOut, RescanRunIn, RescanRunOut,
)
from ..scanning import engine_runner, nmap_runner
from ..scanning.nmap_parse import _extract_key_line
from ..spreadsheet import safe_cell
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()


def _purpose_evidence(f: Finding) -> list[str]:
    """포트가 '무엇이고 왜 열렸나'를 추정하는 근거를 한데 모은다 — 관리자에게 포트번호만 주던 것을
    넘어, 호스트명·서비스/제품/버전·식별·분류·NSE 추출(인증서 CN·SMB OS·NTLM·HTTP 제목 등)을 묶어 제시.
    """
    ev: list[str] = []
    if f.hostname:
        ev.append(f"호스트명(역DNS): {f.hostname}")
    svc = " ".join(x for x in (f.service, f.product, f.version) if x).strip()
    if svc:
        ev.append(f"서비스: {svc}" + (f" ({f.identification})" if f.identification else ""))
    if f.category or f.usage:
        ev.append(f"분류/용도: {' · '.join(x for x in (f.category, f.usage) if x)}")
    # NSE 추출 — 모든 스크립트 출력에서 핵심 한 줄(CN/OS/host/NTLM/title 등)을 뽑아 dedup.
    for s in (f.nse_json or []):
        key = _extract_key_line(s.get("id", ""), s.get("output", ""))
        if key and key not in ev:
            ev.append(key)
    if f.cpe:
        ev.append(f"CPE: {f.cpe}")
    return ev


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
    ("fingerprint", "핑거프린트", lambda f: f.fingerprint),
    ("rtt", "RTT", lambda f: f.rtt),
    ("identification", "식별", lambda f: f.identification),
    ("category", "분류", lambda f: f.category),
    ("usage", "용도", lambda f: f.usage),
    ("risk_level", "위험등급", lambda f: RISK_LABELS_KO.get(f.risk_level, f.risk_level)),
    ("remarks", "비고", lambda f: f.remarks),
    ("status", "운영상태", lambda f: f.status),
    ("reopened", "재발", lambda f: "재발" if f.reopened else ""),
    ("dept", "부서", lambda f: f.dept),
    ("owner", "담당자", lambda f: f.owner),
    ("contact", "연락처", lambda f: f.contact),
    ("deadline", "마감", lambda f: f.deadline.strftime("%Y-%m-%d") if f.deadline else ""),
    ("first_seen", "등록 날짜", lambda f: f.first_seen.strftime("%Y-%m-%d")),
    ("last_seen", "스캔 날짜", lambda f: f.last_seen.strftime("%Y-%m-%d")),
    ("compliance", "컴플라이언스근거", _compliance),
    ("purpose", "용도근거", lambda f: " · ".join(_purpose_evidence(f))),
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
    if not rows:
        return RescanOut(command="", commands=[], hosts=hosts, ports=ports, finding_count=len(rows))
    flags = body.preset_flags.strip() or "-sV -Pn -n"
    # 발견(IP:포트:proto)별 개별 명령 — 각 항목 nmap 1개(그 ip·그 포트만). 중복 제거.
    seen: set = set()
    commands: list[str] = []
    for f in sorted(rows, key=lambda r: (r.host_ip, r.port, r.proto or "tcp")):
        proto = (f.proto or "tcp").lower()
        u = (f.host_ip, f.port, proto)
        if u in seen:
            continue
        seen.add(u)
        udp = " -sU" if proto == "udp" else ""
        commands.append(f"nmap {flags}{udp} -p {f.port} {f.host_ip}")
    return RescanOut(command="\n".join(commands), commands=commands,
                     hosts=hosts, ports=ports, finding_count=len(rows))


def _start_engine_rescan(db: Session, user: User, rows: list[Finding], options: list[str]):
    """선택 발견 → 백그라운드 단계 엔진 재스캔(Stage3-only). 호스트별 정밀 -p(교차곱 제거),
    2-pass 확인, scope_keys 로 닫힘 판정 한정. scan_id 즉시 반환(진행은 /scans/{id}/stages)."""
    if not nmap_runner.find_nmap(_settings.nmap_path):
        raise HTTPException(status_code=400, detail="서버에서 nmap 을 찾을 수 없습니다.")
    units, scope_keys = engine_runner.rescan_targets(
        [(f.host_ip, f.port, f.proto, f.finding_key) for f in rows])
    hosts = sorted({u["ip"] for u in units})
    ports = sorted({u["port"] for u in units})

    scan = ScanRun(name=f"타겟 재스캔: {len(rows)}건", targets=" ".join(hosts),
                   status="running", created_by=user.id)
    db.add(scan)
    db.commit()
    out_dir = _settings.scans_dir / f"scan_{scan.id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = engine_runner.build_job_spec(scan.id, [], [], options or [], "", [],
                                        out_dir, 256, rescan_units=units)
    spec["scanops"] = {"scope_keys": sorted(scope_keys)}   # 워커가 읽어 ingest 닫힘 판정에 사용
    (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
    scan.command = engine_runner.describe(spec)
    db.commit()
    db.refresh(scan)
    from .audit import record
    from .scans import _engine_worker
    record(db, user, "SCAN_RUN", target=scan.targets, detail=f"#{scan.id} 타겟 재스캔 {len(rows)}건")
    threading.Thread(target=_engine_worker, args=(scan.id,), daemon=True).start()
    return scan, hosts, ports


@router.post("/rescan", response_model=RescanRunOut)
def rescan_run(
    body: RescanRunIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """선택 발견을 백그라운드 단계 엔진으로 재스캔 — 발견·찾기 생략, Stage3 만(호스트별 정밀).

    구버전 동기 블로킹(최대 1시간 HTTP 점유)에서 백그라운드로 전환: scan_id 즉시 반환,
    진행은 GET /scans/{id}/stages. 닫힘 판정은 선택 발견(scope_keys)으로 한정 →
    ingest 자동검증(처리중/마감 → 정상처리).
    """
    rows = db.query(Finding).filter(Finding.id.in_(body.finding_ids)).all() if body.finding_ids else []
    if not rows:
        raise HTTPException(status_code=400, detail="재스캔할 발견을 선택하세요.")
    scan, hosts, ports = _start_engine_rescan(db, user, rows, body.options)
    return RescanRunOut(scan_id=scan.id, command=scan.command, counts={}, hosts=hosts, ports=ports)


@router.post("/rescan-due", response_model=RescanRunOut)
def rescan_due(
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """마감 지났거나 처리중인 '열린' 발견을 일괄 재검증 — 라이프사이클 구동 재스캔.

    닫혔으면 ingest 가 정상처리 자동 확정(조치 완료 검증), 여전히 열렸으면 그대로 남는다.
    """
    now = datetime.now(timezone.utc)
    rows = db.query(Finding).filter(
        Finding.state == "open",
        or_(and_(Finding.deadline.isnot(None), Finding.deadline <= now),
            Finding.status == "처리중"),
    ).all()
    if not rows:
        raise HTTPException(status_code=400, detail="재검증할 마감·처리중 발견이 없습니다.")
    scan, hosts, ports = _start_engine_rescan(db, user, rows, [])
    return RescanRunOut(scan_id=scan.id, command=scan.command, counts={}, hosts=hosts, ports=ports)


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


@router.get("/{fid}/evidence")
def finding_evidence(fid: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    """용도 추정 근거 — 발견 상세에서 '왜 열렸나/무엇인가'를 보여줄 근거 줄 목록."""
    row = db.get(Finding, fid)
    if row is None:
        raise HTTPException(status_code=404, detail="발견을 찾을 수 없습니다.")
    return {"evidence": _purpose_evidence(row)}


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
