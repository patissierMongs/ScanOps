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
from ..identity import display_identity
from ..observation import current_reason, exposure_text
from ..models import (
    ACTIVE_FINDING_STATES, FINDING_STATUSES, RISK_LABELS_KO,
    Finding, FindingEvent, ScanRun, User,
)
from ..schemas import (
    EventOut, FindingOut, FindingPatch, RescanIn, RescanOut, RescanRunIn, RescanRunOut,
)
from ..scanning import engine_runner, nmap_runner, scan_options, scope
from ..scanning.nmap_parse import _extract_key_line, pretty_fingerprint
from ..spreadsheet import safe_cell
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()
_RESCAN_OPTION_KEYS = {"version_all", "version_light"}


def _purpose_evidence(f: Finding) -> list[str]:
    """포트가 '무엇이고 왜 열렸나'를 추정하는 근거를 한데 모은다 — 관리자에게 포트번호만 주던 것을
    넘어, 호스트명·서비스/제품/버전·식별·분류·NSE 추출(인증서 CN·SMB OS·NTLM·HTTP 제목 등)을 묶어 제시.
    """
    ev: list[str] = []
    if f.hostname:
        ev.append(f"호스트명(역DNS): {f.hostname}")
    if f.server:
        ev.append(f"Server: {f.server}")
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


def _exposure(f: Finding) -> str:
    """관측된 노출 사실을 한 줄로 - 표·필터·내보내기에서 '익명 FTP만' 같은 조회가 되게."""
    return exposure_text(f.exposure_json)


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
    # 같은 open 이라도 응답을 받아 확인한 것과 무응답으로 추정한 것은 다르다.
    # 상태만 내보내면 받는 사람은 그 차이를 알 방법이 없다.
    ("state_evidence", "상태 근거", lambda f: f.state_evidence),
    # 현재 상태를 뒷받침하지 않는 원문(닫힌 행에 남은 예전 syn-ack)은 내보내지 않는다 —
    # '근거 원문'이라는 이름 옆에 두면 읽는 사람이 현재 상태의 근거로 읽는다.
    ("reason", "근거 원문", lambda f: current_reason(f.state, f.reason)),
    ("display_identity", "표시 식별", lambda f: display_identity(
        server=f.server, product=f.product, version=f.version, service=f.service,
        identification=f.identification,
    )),
    ("server", "Server", lambda f: f.server),
    ("service", "서비스", lambda f: f.service),
    ("product", "제품", lambda f: f.product),
    ("version", "버전", lambda f: f.version),
    ("banner", "배너", lambda f: f.banner),
    ("cpe", "CPE", lambda f: f.cpe),
    ("fingerprint", "핑거프린트", lambda f: pretty_fingerprint(f.fingerprint)),
    ("rtt", "RTT", lambda f: f.rtt),
    ("identification", "식별", lambda f: f.identification),
    ("category", "분류", lambda f: f.category),
    ("usage", "용도", lambda f: f.usage),
    ("risk_level", "위험등급", lambda f: RISK_LABELS_KO.get(f.risk_level, f.risk_level)),
    ("remarks", "비고", lambda f: f.remarks),
    ("status", "운영상태", lambda f: f.status),
    ("reopened", "재발", lambda f: "재발" if f.reopened else ""),
    ("dept", "부서", lambda f: f.dept),
    ("owner", "담당자(자산대장)", lambda f: f.owner),
    # 배정 담당자는 자산대장 담당자와 다른 축이다. 표에서 둘을 구분해야 '누가 조치하는가'를
    # 필터·내보내기로도 추적할 수 있다.
    ("assignee", "배정 담당자", lambda f: f.assignee_name),
    ("contact", "연락처", lambda f: f.contact),
    ("deadline", "마감", lambda f: f.deadline.strftime("%Y-%m-%d") if f.deadline else ""),
    ("first_seen", "등록 날짜", lambda f: f.first_seen.strftime("%Y-%m-%d")),
    ("last_seen", "스캔 날짜", lambda f: f.last_seen.strftime("%Y-%m-%d")),
    ("exposure", "노출 관측", _exposure),
    ("compliance", "컴플라이언스근거", _compliance),
    ("purpose", "용도근거", lambda f: " · ".join(_purpose_evidence(f))),
    ("manual_note", "메모", lambda f: f.manual_note),
]
_COL_MAP = {key: (header, getter) for key, header, getter in COLUMNS}
_DEFAULT_COLS = [
    "host_ip", "port", "proto", "display_identity", "server", "service",
    "version", "risk_level", "status", "dept", "deadline",
]


def _filtered(db: Session, status, risk, host, q, state, dept=None):
    """DB 레벨 축소만 담당. 컬럼 단위 검색/정렬은 _view_rows 가 표시값 기준으로 처리한다."""
    query = db.query(Finding)
    if status:
        query = query.filter(Finding.status == status)
    if risk:
        query = query.filter(Finding.risk_level == risk)
    if host:
        query = query.filter(Finding.host_ip == host)
    if state:
        query = query.filter(
            Finding.state.in_(ACTIVE_FINDING_STATES) if state == "open" else Finding.state == state
        )
    if dept:
        query = query.filter(Finding.dept == dept)
    # q 는 여기서 처리하지 않는다: 계산 컬럼(표시 식별·용도근거 등)까지 '보이는 값'으로
    # 매칭해야 하므로 SQL 프리필터를 걸면 그런 행이 조용히 빠진다. _view_rows 가 담당.
    return query.order_by(Finding.host_ip, Finding.port)


# 표시값 계산이 비싼 컬럼 — 전체 검색에서 마지막에 평가해 조기 종료 확률을 높인다.
_EXPENSIVE_COLS = {"fingerprint", "purpose", "compliance"}
_SEARCH_ORDER = (
    [key for key, _h, _g in COLUMNS if key not in _EXPENSIVE_COLS]
    + [key for key, _h, _g in COLUMNS if key in _EXPENSIVE_COLS]
)
_NUMERIC_COLS = {"port"}


def _cell(finding: Finding, key: str) -> str:
    getter = _COL_MAP.get(key)
    if getter is None:
        return ""
    try:
        return str(getter[1](finding) or "")
    except Exception:      # 표시값 계산 실패가 목록 전체를 죽이면 안 된다
        return ""


# 제외 검색 접두사. `!ssh` = ssh 가 아닌 것만. 목록에서 몇 건을 빼고 보는 일이 훨씬 잦은데
# 그때마다 '아닌 것'을 표현할 방법이 없어 눈으로 걸러야 했다. `!!` 는 문자 그대로의 `!` 다
# (제외를 도입하면서 `!` 로 시작하는 값 자체를 검색할 길이 막히면 안 된다).
NEGATE = "!"


def parse_needle(text: str) -> tuple[str, bool]:
    """검색어 -> (실제 검색어, 제외 여부)."""
    if text.startswith(NEGATE * 2):
        return text[1:], False
    if text.startswith(NEGATE):
        return text[1:], True
    return text, False


def _hit(finding: Finding, needle: str, exact: bool) -> bool:
    if exact:
        return any(_cell(finding, key).strip().casefold() == needle for key in _SEARCH_ORDER)
    return any(needle in _cell(finding, key).casefold() for key in _SEARCH_ORDER)


def _matches(finding: Finding, raw: str, exact: bool) -> bool:
    """모든 컬럼의 '보이는 값' 중 하나라도 맞으면 통과. 첫 일치에서 멈춘다.

    `!` 로 시작하면 뒤집는다 - 어느 컬럼에도 맞지 않는 행만 남는다. 제외를 '일치하는 컬럼이
    하나라도 있으면 버린다'로 읽는 것이 사람이 기대하는 동작이다(어느 한 컬럼에만 없으면
    통과시키면 사실상 아무것도 걸러지지 않는다).
    """
    needle, negate = parse_needle(raw)
    if not needle:
        return True
    return _hit(finding, needle, exact) != negate


def _column_hit(finding: Finding, key: str, raw: str, exact: bool) -> bool:
    """컬럼 필터 한 칸. 전체 검색과 같은 `!` 규칙을 쓴다 - 규칙이 칸마다 다르면 못 외운다."""
    text, negate = parse_needle(raw)
    if not text:
        return True
    value = _cell(finding, key)
    hit = value.strip().casefold() == text if exact else text in value.casefold()
    return hit != negate


def _parse_filters(raw: str) -> dict[str, str]:
    """컬럼별 필터 — {"컬럼키": "검색어"} JSON. 알 수 없는 키는 거절(오타가 조용히 무시되지 않게)."""
    if not (raw or "").strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"filters 를 해석할 수 없습니다: {exc}")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="filters 는 객체여야 합니다.")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        if key not in _COL_MAP:
            raise HTTPException(status_code=400, detail=f"알 수 없는 필터 컬럼: {key}")
        text = str(value or "").strip().casefold()
        if text:
            out[key] = text
    return out


def _sort_key(key: str):
    if key in _NUMERIC_COLS:
        def numeric(finding: Finding):
            raw = _cell(finding, key)
            try:
                return (0, float(raw), "")
            except ValueError:
                return (1, 0.0, raw.casefold())
        return numeric

    def text(finding: Finding):
        value = _cell(finding, key)
        return (0 if value else 1, 0.0, value.casefold())
    return text


def _overdue_before(today: str):
    """마감초과 기준일 — 화면이 보낸 '오늘'(사용자 로컬 날짜)을 쓴다.

    서버 UTC 날짜로 판정하면 KST 오전처럼 날짜가 하루 어긋나는 시간대에서 화면의
    'N일 초과' 표시와 필터 결과가 달라진다. 값이 없으면(스크립트 호출 등) 서버 날짜로 폴백.
    """
    text = (today or "").strip()
    if text:
        try:
            return datetime.strptime(text, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="today 는 YYYY-MM-DD 형식이어야 합니다.")
    return datetime.now(timezone.utc).date()


def _view_rows(db: Session, *, status=None, risk=None, host=None, q=None, state="open",
               dept=None, match="contains", filters="", sort="", direction="asc",
               hide_normal=False, hide_allowed=False, overdue_only=False, today=""):
    """목록·내보내기 공통 뷰 — 표에 보이는 값 그대로 필터·정렬한다.

    '표 = 내보내기' 불변식을 지키려면 계산 컬럼(표시 식별·용도근거·컴플라이언스)도 같은 기준으로
    걸러야 한다. 그래서 DB 로 줄일 수 있는 것만 SQL 로 줄이고, 컬럼 단위 판정은 표시값으로 한다.

    화면 토글(정상처리 제외·마감초과만)도 **여기서** 걸러야 한다. 페이지를 자른 뒤 화면에서
    걸러내면 조건에 맞는 행이 뒷 페이지에 남아 첫 페이지가 빈 것처럼 보이고, 건수·내보내기도
    화면과 어긋난다.
    """
    rows = _filtered(db, status, risk, host, None, state, dept).all()
    if hide_normal:
        rows = [f for f in rows if f.status != "정상처리"]
    if hide_allowed:
        # 조직이 '허용'으로 정한 발견만 접는다. 정상처리(사람이 조치를 끝냈다)와는 다른 축이라
        # 토글도 따로 둔다 - 하나로 묶으면 둘 중 무엇 때문에 안 보이는지 알 수 없다.
        rows = [f for f in rows if not f.allowed]
    if overdue_only:
        limit_day = _overdue_before(today)
        rows = [f for f in rows if f.deadline is not None and f.deadline.date() < limit_day]
    column_filters = _parse_filters(filters)
    if column_filters:
        exact_cols = match == "exact"
        rows = [
            f for f in rows
            if all(_column_hit(f, key, text, exact_cols)
                   for key, text in column_filters.items())
        ]
    needle = (q or "").strip().casefold()
    if needle:
        rows = [f for f in rows if _matches(f, needle, match == "exact")]
    if sort:
        if sort not in _COL_MAP:
            raise HTTPException(status_code=400, detail=f"알 수 없는 정렬 컬럼: {sort}")
        rows.sort(key=_sort_key(sort), reverse=direction == "desc")
    return rows


@router.get("")
def list_findings(
    response: Response,
    status: str | None = None,
    risk: str | None = None,
    host: str | None = None,
    q: str | None = None,
    state: str | None = "open",
    dept: str | None = None,
    match: str = "contains",
    filters: str = "",
    sort: str = "",
    dir: str = "asc",
    hide_normal: bool = False,
    hide_allowed: bool = True,
    overdue_only: bool = False,
    today: str = "",
    limit: int = 0,
    offset: int = 0,
    cols: str = "",
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """발견 목록.

    `limit` 이 0 이면 전부 반환(하위호환). 페이지를 쓸 때는 전체 건수를 `X-Total-Count` 헤더로
    돌려주므로 응답 본문 모양은 그대로 목록이다.

    `cols` 로 화면이 실제로 쓰는 컬럼만 받으면 `fingerprint` 같은 큰 원문을 payload 에서 뺀다 —
    발견이 수천 건일 때 목록 응답 크기를 좌우하는 게 이 필드다.
    """
    if match not in ("contains", "exact"):
        raise HTTPException(status_code=400, detail="match 는 contains 또는 exact 여야 합니다.")
    if dir not in ("asc", "desc"):
        raise HTTPException(status_code=400, detail="dir 은 asc 또는 desc 여야 합니다.")
    rows = _view_rows(db, status=status, risk=risk, host=host, q=q, state=state, dept=dept,
                      match=match, filters=filters, sort=sort, direction=dir,
                      hide_normal=hide_normal, hide_allowed=hide_allowed,
                      overdue_only=overdue_only, today=today)
    response.headers["X-Total-Count"] = str(len(rows))
    if limit > 0:
        rows = rows[max(0, offset):max(0, offset) + limit]
    wanted = {c.strip() for c in cols.split(",") if c.strip()}
    include_fingerprint = not wanted or "fingerprint" in wanted
    out = []
    for finding in rows:
        item = FindingOut.model_validate(finding).model_dump(mode="json")
        if not include_fingerprint:
            item["fingerprint"] = ""
        out.append(item)
    return out


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
    match: str = "contains",
    filters: str = "",
    sort: str = "",
    dir: str = "asc",
    hide_normal: bool = False,
    hide_allowed: bool = True,
    overdue_only: bool = False,
    today: str = "",
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    keys = [c.strip() for c in cols.split(",") if c.strip()] or _DEFAULT_COLS
    unknown = [k for k in keys if k not in _COL_MAP]
    if unknown:
        raise HTTPException(status_code=400, detail=f"알 수 없는 컬럼: {unknown}")
    headers = [_COL_MAP[k][0] for k in keys]
    # 목록과 같은 뷰 함수를 쓴다 — 화면에서 걸러 본 것과 내보낸 것이 달라지면 안 된다.
    rows = _view_rows(db, status=status, risk=risk, host=host, q=q, state=state,
                      match=match, filters=filters, sort=sort, direction=dir,
                      hide_normal=hide_normal, hide_allowed=hide_allowed,
                      overdue_only=overdue_only, today=today)

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
    try:
        nmap_runner.validate_targets(hosts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
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


def _start_engine_rescan(db: Session, user: User, rows: list[Finding], options: list[str],
                         nse: list[str] | None = None):
    """선택 발견 → 백그라운드 단계 엔진 재스캔(Stage3-only). 호스트별 정밀 -p(교차곱 제거),
    2-pass 확인, scope_keys 로 닫힘 판정 한정. scan_id 즉시 반환(진행은 /scans/{id}/stages)."""
    hosts = sorted({row.host_ip for row in rows})
    try:
        nmap_runner.validate_targets(hosts)
        scope.check_scope(hosts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        engine_runner.ensure_available()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
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
    from .audit import record
    from .scans import _engine_worker, _fail_launch_setup
    launch_paths = [
        out_dir / "spec.json", out_dir / "run-state.json", out_dir / "stop-requested",
    ]
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        spec = engine_runner.build_job_spec(
            scan.id, [], [], options or [], "", nse, out_dir, 256, rescan_units=units,
        )
        spec["scanops"] = {"scope_keys": sorted(scope_keys)}
        (out_dir / "spec.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        scan.command = engine_runner.describe(spec)
        db.commit()
        db.refresh(scan)
        threading.Thread(target=_engine_worker, args=(scan.id,), daemon=True).start()
    except Exception:
        _fail_launch_setup(
            db, scan.id, user, scan.targets, launch_paths, artifact_dirs=[out_dir],
        )
    record(db, user, "SCAN_RUN", target=scan.targets, detail=f"#{scan.id} 타겟 재스캔 {len(rows)}건")
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
    if body.ports.strip():
        raise HTTPException(
            status_code=400,
            detail="타겟 재스캔은 선택한 발견의 IP:포트만 사용합니다. 포트를 별도로 지정할 수 없습니다.",
        )
    try:
        scan_options.validate_keys(body.options)
        scan_options.validate_nse(body.nse)
        unsupported = [key for key in body.options if key not in _RESCAN_OPTION_KEYS]
        if unsupported:
            raise ValueError(f"타겟 재스캔에서 지원하지 않는 옵션: {unsupported}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    rows = db.query(Finding).filter(Finding.id.in_(body.finding_ids)).all() if body.finding_ids else []
    if not rows:
        raise HTTPException(status_code=400, detail="재스캔할 발견을 선택하세요.")
    scan, hosts, ports = _start_engine_rescan(db, user, rows, body.options, body.nse)
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
        Finding.state.in_(ACTIVE_FINDING_STATES),
        or_(and_(Finding.deadline.isnot(None), Finding.deadline <= now),
            Finding.status == "처리중"),
    ).all()
    if not rows:
        raise HTTPException(status_code=400, detail="재검증할 마감·처리중 발견이 없습니다.")
    scan, hosts, ports = _start_engine_rescan(db, user, rows, [], None)
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

    supplied = body.model_fields_set
    if "status" in supplied and body.status is not None and body.status != row.status:
        if body.status not in FINDING_STATUSES:
            raise HTTPException(status_code=400, detail=f"상태는 {FINDING_STATUSES} 중 하나여야 합니다.")
        log("STATUS_CHANGE", f"{row.status} → {body.status}")
        row.status = body.status
    if "owner_user_id" in supplied and body.owner_user_id != row.owner_user_id:
        if body.owner_user_id is not None:
            owner = db.get(User, body.owner_user_id)
            if owner is None:
                raise HTTPException(status_code=400, detail="배정할 사용자를 찾을 수 없습니다.")
            if not owner.is_active:
                raise HTTPException(status_code=400, detail="비활성 사용자에게 배정할 수 없습니다.")
        log("ASSIGN", f"담당자 #{body.owner_user_id} 배정" if body.owner_user_id else "담당자 배정 해제")
        row.owner_user_id = body.owner_user_id
    if "deadline" in supplied and body.deadline != row.deadline:
        log("DEADLINE", f"마감 {body.deadline:%Y-%m-%d} 설정" if body.deadline else "마감 해제")
        row.deadline = body.deadline
    if "dept" in supplied and body.dept is not None:
        row.dept = body.dept
    if "manual_note" in supplied and body.manual_note is not None and body.manual_note != row.manual_note:
        log("NOTE", "메모 변경")
        row.manual_note = body.manual_note
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return row
