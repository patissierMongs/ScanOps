"""스캔 결과 인입 — 안정키로 finding upsert + 변화 이벤트 생성.

이게 ScanOps 의 핵심: diff 가 *발견의 시간적 정체성*과 묶여,
재스캔 시 "그 포트가 닫혔나"를 자동으로 판정한다.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..identity import display_identity
from ..models import ACTIVE_FINDING_STATES, Finding, FindingEvent
from .nmap_parse import server_observed


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """SQLite DateTime may return naive values; ScanOps stores those as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_older(candidate: datetime, reference: datetime | None) -> bool:
    return reference is not None and _as_utc(candidate) < _as_utc(reference)


def _split_key(key: str) -> tuple[str, int, str]:
    """`host|port|proto` 분해. 형식이 깨졌으면 매칭되지 않는 값으로 돌려준다."""
    parts = str(key).split("|", 2)
    if len(parts) != 3:
        return str(key), -1, ""
    try:
        return parts[0], int(parts[1]), parts[2].lower()
    except ValueError:
        return parts[0], -1, parts[2].lower()


def _close_row(db: Session, row, scan_id: int, closed_at) -> None:
    row.state = "closed"
    row.last_scan_id = scan_id
    row.last_seen = closed_at
    row.reopened = 0   # 다시 닫혔으므로 재발 태그 해제
    # 마감/배정이 걸려 있던 항목이 닫힘 → 조치 완료 자동 검증
    verified = row.status == "처리중" or row.deadline is not None
    row.status = "정상처리"
    detail = "포트 닫힘 — 조치 완료 자동 확인" if verified else "포트 닫힘"
    _event(db, row.id, scan_id, "CLOSED", detail, when=closed_at)


def _absence_for(absence_at: dict, host: str, port: int, proto: str) -> tuple[bool, object]:
    """이 발견의 부재를 증명한 산출물이 있는가, 있다면 언제 끝났는가.

    포트 단위 권한(선택 재스캔의 stage3)이 호스트 단위 권한(sweep)보다 좁으므로 먼저 본다.
    같은 호스트라도 22 를 훑은 산출물과 443 을 훑은 산출물은 서로의 부재를 증명하지 못한다.
    """
    for key in ((host, port, proto), (host, proto)):
        if key in absence_at:
            return True, absence_at[key]
    return False, None


def _as_when(observed, scan_date):
    """파일이 밝힌 관측 시각 우선, 없으면 스캔 시각, 그것도 없으면 현재."""
    if isinstance(observed, datetime):
        return observed
    return scan_date or _now()


def _key(f: dict) -> str:
    return f"{f['host_ip']}|{f['port']}|{f['proto']}"


def ingest(db: Session, scan_id: int, findings: list[dict], scanned_hosts: set[str],
           scope_keys: set[str] | None = None, scan_date: datetime | None = None,
           absence_at: dict | None = None, closed_keys: set | None = None,
           applied_keys: set | None = None, *, commit: bool = True) -> dict:
    """findings(이번 스캔의 열린 포트들)와 scanned_hosts(up 호스트)로 DB 갱신.

    scope_keys 가 주어지면(타겟 포트 재스캔) 닫힘 판정을 그 키(host|port|proto)로만
    한정 — 스캔하지 않은 다른 포트가 거짓 닫힘 처리되지 않게 한다. None 이면 호스트 전체.
    scan_date 는 '실제 스캔 실행일'(가져온 XML 은 파일 내 시각). first/last_seen 에 쓴다.
    None 이면 현재시각. 리턴: 변화 요약 카운트.

    absence_at 은 ``(host_ip, proto) -> 그 부재를 확인한 시각`` 이다. '이 포트가 없다' 는
    **그 호스트를 실제로 훑은 산출물**만 할 수 있는 말이라, 실행 전체의 시각 하나로 뭉치면
    다른 배치의 시각을 빌려 오게 된다 - 00:00 에 끝난 배치의 부재가 02:00 권한을 얻어 그
    사이 01:00 에 새로 열린 포트를 닫는다. 맵이 주어졌는데 키가 없으면 이 실행의 어떤
    산출물도 그 호스트/프로토콜을 커버하지 않았다는 뜻이므로 닫지 않는다.
    """
    when = scan_date or _now()
    counts = {"new": 0, "reopened": 0, "service_changed": 0,
              "version_changed": 0, "server_changed": 0, "unchanged": 0, "closed": 0}
    seen: set[str] = set()

    for f in findings:
        key = _key(f)
        seen.add(key)
        # 관측 시각은 **그 결과를 만든 파일**의 것이다. 스캔 하나의 시각으로 뭉뚱그리면,
        # 몇 시간 도는 스캔에서 나중에 확인한 열림이 '오래된 관측'으로 버려지거나(미탐)
        # 초반에 본 것이 그 뒤 다른 스캔의 최신 관측을 덮는다. 파일이 시각을 말하지 않으면
        # 스캔 시각으로 되돌아간다.
        when = _as_when(f.get("observed_at"), scan_date)
        row = db.query(Finding).filter(Finding.finding_key == key).first()
        if applied_keys is not None and (
            row is None or not _is_older(when, row.last_seen)
        ):
            applied_keys.add(key)
        if row is None:
            row = Finding(finding_key=key, first_scan_id=scan_id, first_seen=when, **_observed(f))
            row.last_scan_id = scan_id
            row.last_seen = when
            db.add(row)
            db.flush()
            identity = display_identity(
                server=f.get("server", ""),
                product=f.get("product", ""),
                version=f.get("version", ""),
                service=f.get("service", ""),
                identification=f.get("identification", ""),
            )
            prefix = f"{identity} " if identity else ""
            _event(
                db,
                row.id,
                scan_id,
                "NEW_OPEN",
                f"{prefix}{f['port']}/{f['proto']} 신규 발견",
                when=when,
            )
            counts["new"] += 1
            continue

        # Imports can arrive out of chronological order. Older evidence belongs in history,
        # but must never replace the current observation or manufacture change/reopen events.
        if _is_older(when, row.last_seen):
            if _is_older(when, row.first_seen):
                row.first_seen = when
                row.first_scan_id = scan_id
            continue

        # 기존 발견 갱신
        reopened = row.state not in ACTIVE_FINDING_STATES
        old_service, old_version, old_server = row.service, row.version, row.server
        observed = _observed(f)
        identity_observed = f.get("identity_observed") is not False
        if not identity_observed:
            # A successful sweep is authoritative for openness, not identity. Service/NSE
            # probing may transiently miss or filter this port, so preserve all prior identity,
            # classification, and evidence fields while advancing the observation timestamp.
            # reason 은 state 와 한 몸이다 — sweep 이 개방 여부의 권위라면 그렇게 판단한
            # 근거도 sweep 의 것이다. 둘을 떼면 state 는 새 관측인데 reason 은 옛 관측이 된다.
            observed = {key: observed[key] for key in ("state", "reason", "rtt")}
        elif not _server_was_observed(f):
            # Server NSE를 실행하지 않은 스캔은 기존 증거를 '없음'으로 덮지 않는다.
            observed.pop("server", None)
        for k, v in observed.items():
            setattr(row, k, v)
        row.last_scan_id = scan_id
        row.last_seen = when

        if reopened:
            _event(db, row.id, scan_id, "REOPENED", "닫혔던 포트가 다시 열림", when=when)
            # 재발은 별도 상태가 아니라 태그 — 정상처리됐던 건 미조치로 되돌려 다시 조치 대상으로,
            # reopened 플래그로 '재발' 사실만 표시한다.
            row.reopened = 1
            if row.status == "정상처리":
                row.status = "미조치"
            counts["reopened"] += 1

        # Reopening and identity changes are independent facts. A reopened endpoint may also
        # return a different service/version/Server and both transitions must remain auditable.
        identity_changed = False
        if identity_observed and old_service != f["service"]:
            _event(db, row.id, scan_id, "SERVICE_CHANGED",
                   f"{old_service} → {f['service']}", when=when)
            counts["service_changed"] += 1
            identity_changed = True
        if identity_observed and old_version != f["version"]:
            _event(db, row.id, scan_id, "VERSION_CHANGED",
                   f"{old_version} → {f['version']}", when=when)
            counts["version_changed"] += 1
            identity_changed = True
        if identity_observed and old_server != row.server:
            _event(db, row.id, scan_id, "SERVER_CHANGED",
                   f"{old_server or '—'} → {row.server or '—'}", when=when)
            counts["server_changed"] += 1
            identity_changed = True
        if not reopened and not identity_changed:
            counts["unchanged"] += 1

    # 명시적 scope_keys는 완료된 structured scan의 권한이다. discovery에서 호스트가
    # 관측되지 않았더라도 그 effective target/port/protocol 범위에서 사라진 finding은 닫는다.
    # None인 구형/import 경로만 기존처럼 실제 관측 host 범위를 사용한다.
    # 부재(닫힘)의 기준 시각은 개별 파일이 아니라 이 실행의 authority 완결 시각이다.
    when = scan_date or _now()
    if scope_keys is not None:
        # 후보 **키**를 돌면서 판단한다. 활성 행만 훑으면 '이미 닫혀 있던 포트를 이번에도
        # 없다고 확인했다' 는 사실이 남지 않아, 증거 XML 과 히트맵이 그 관측을 잃는다.
        rows: dict[str, Finding] = {}
        pending = sorted(set(scope_keys) - seen)
        for start in range(0, len(pending), 500):
            chunk = pending[start:start + 500]
            for row in db.query(Finding).filter(Finding.finding_key.in_(chunk)).all():
                rows[row.finding_key] = row
        for key in pending:
            host, port, proto = _split_key(key)
            closed_at = when
            if absence_at is not None:
                covered, stamp = _absence_for(absence_at, host, port, proto)
                if not covered:
                    continue    # 이 실행의 어떤 산출물도 이 호스트·포트·프로토콜을 훑지 않았다
                # 훑기는 했는데 시각을 밝히지 않은 산출물(옛 XML)은 실행 시각으로 갈음한다.
                # '커버하지 않았다' 와 '커버했지만 시각을 모른다' 는 다른 사실이다.
                closed_at = stamp or when
            row = rows.get(key)
            if row is not None and _is_older(closed_at, row.last_seen):
                continue        # 이 산출물보다 나중에 관측된 사실이 있다 - 우리 증거가 낡았다
            # 여기까지 왔으면 이 실행이 그 포트의 부재를 권위 있게 관측한 것이다.
            # 상태가 이미 닫힘이어도 '이번에도 없었다' 는 관측이므로 증거에는 남는다.
            if closed_keys is not None:
                closed_keys.add(key)
            if row is None or row.state not in ACTIVE_FINDING_STATES:
                continue
            _close_row(db, row, scan_id, closed_at)
            counts["closed"] += 1
    elif scanned_hosts:
        hosts = sorted(scanned_hosts)
        open_rows = []
        for start in range(0, len(hosts), 500):
            open_rows.extend(db.query(Finding).filter(
                Finding.state.in_(ACTIVE_FINDING_STATES),
                Finding.host_ip.in_(hosts[start:start + 500]),
            ).all())
        for row in open_rows:
            if row.finding_key in seen:
                continue
            closed_at = when
            if absence_at is not None:
                covered, stamp = _absence_for(
                    absence_at, row.host_ip, row.port, (row.proto or "").lower())
                if not covered:
                    continue
                closed_at = stamp or when
            if _is_older(closed_at, row.last_seen):
                continue
            if closed_keys is not None:
                closed_keys.add(row.finding_key)
            _close_row(db, row, scan_id, closed_at)
            counts["closed"] += 1

    if commit:
        db.commit()
    else:
        db.flush()
    return counts


def _observed(f: dict) -> dict:
    """스캔이 갱신하는 관측 + 분류 필드(운영상태는 제외)."""
    return {
        "host_ip": f["host_ip"], "hostname": f["hostname"], "port": f["port"],
        "proto": f["proto"], "state": f["state"], "reason": f.get("reason", ""),
        "service": f["service"],
        "product": f["product"], "version": f["version"],
        "server": f.get("server", ""), "banner": f["banner"],
        "cpe": f["cpe"], "rtt": f["rtt"], "identification": f["identification"],
        "nse_json": f["nse_json"], "remarks": f["remarks"],
        "category": f.get("category", ""), "usage": f.get("usage", ""),
        "risk_level": f.get("risk_level", "info"),
        "allowed": 1 if f.get("allowed") else 0,
        "compliance_json": f.get("compliance_json", []),
        "exposure_json": f.get("exposure_json", []),
    }


def _server_was_observed(f: dict) -> bool:
    """Parser 삼상태 플래그를 우선하고, 구형 내부 호출은 NSE/비어있지 않은 값으로 호환."""
    observed = f.get("server_observed")
    if isinstance(observed, bool):
        return observed
    return bool(f.get("server")) or server_observed(f.get("nse_json"))


def _event(db: Session, finding_id: int, scan_id: int, type_: str, detail: str,
           actor_user_id: int | None = None, when: datetime | None = None) -> None:
    # 스캔 생성 이벤트의 시각은 '실제 스캔 시각'(가져온 XML 은 파일 내 시각). 인입 시각 아님.
    ev = FindingEvent(finding_id=finding_id, scan_id=scan_id, type=type_,
                      detail=detail, actor_user_id=actor_user_id)
    if when is not None:
        ev.created_at = when
    db.add(ev)
