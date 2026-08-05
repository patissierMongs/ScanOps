"""스캔 결과 인입 — 안정키로 finding upsert + 변화 이벤트 생성.

이게 ScanOps 의 핵심: diff 가 *발견의 시간적 정체성*과 묶여,
재스캔 시 "그 포트가 닫혔나"를 자동으로 판정한다.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

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


def _key(f: dict) -> str:
    return f"{f['host_ip']}|{f['port']}|{f['proto']}"


def ingest(db: Session, scan_id: int, findings: list[dict], scanned_hosts: set[str],
           scope_keys: set[str] | None = None, scan_date: datetime | None = None,
           *, commit: bool = True) -> dict:
    """findings(이번 스캔의 열린 포트들)와 scanned_hosts(up 호스트)로 DB 갱신.

    scope_keys 가 주어지면(타겟 포트 재스캔) 닫힘 판정을 그 키(host|port|proto)로만
    한정 — 스캔하지 않은 다른 포트가 거짓 닫힘 처리되지 않게 한다. None 이면 호스트 전체.
    scan_date 는 '실제 스캔 실행일'(가져온 XML 은 파일 내 시각). first/last_seen 에 쓴다.
    None 이면 현재시각. 리턴: 변화 요약 카운트.
    """
    when = scan_date or _now()
    counts = {"new": 0, "reopened": 0, "service_changed": 0,
              "version_changed": 0, "server_changed": 0, "unchanged": 0, "closed": 0}
    seen: set[str] = set()

    for f in findings:
        key = _key(f)
        seen.add(key)
        row = db.query(Finding).filter(Finding.finding_key == key).first()
        if row is None:
            row = Finding(finding_key=key, first_scan_id=scan_id, first_seen=when, **_observed(f))
            row.last_scan_id = scan_id
            row.last_seen = when
            db.add(row)
            db.flush()
            _event(db, row.id, scan_id, "NEW_OPEN", f"{f['service']} {f['port']}/{f['proto']} 신규 발견", when=when)
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
            observed = {key: observed[key] for key in ("state", "rtt")}
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
    open_rows = []
    if scope_keys is not None:
        keys = sorted(scope_keys)
        for start in range(0, len(keys), 500):
            open_rows.extend(db.query(Finding).filter(
                Finding.state.in_(ACTIVE_FINDING_STATES),
                Finding.finding_key.in_(keys[start:start + 500]),
            ).all())
    elif scanned_hosts:
        hosts = sorted(scanned_hosts)
        for start in range(0, len(hosts), 500):
            open_rows.extend(db.query(Finding).filter(
                Finding.state.in_(ACTIVE_FINDING_STATES),
                Finding.host_ip.in_(hosts[start:start + 500]),
            ).all())
    for row in open_rows:
        if _is_older(when, row.last_seen):
            continue
        if row.finding_key in seen:
            continue
        row.state = "closed"
        row.last_scan_id = scan_id
        row.last_seen = when
        row.reopened = 0   # 다시 닫혔으므로 재발 태그 해제
        # 마감/배정이 걸려 있던 항목이 닫힘 → 조치 완료 자동 검증
        verified = row.status == "처리중" or row.deadline is not None
        row.status = "정상처리"
        detail = "포트 닫힘 — 조치 완료 자동 확인" if verified else "포트 닫힘"
        _event(db, row.id, scan_id, "CLOSED", detail, when=when)
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
        "proto": f["proto"], "state": f["state"], "service": f["service"],
        "product": f["product"], "version": f["version"],
        "server": f.get("server", ""), "banner": f["banner"],
        "cpe": f["cpe"], "rtt": f["rtt"], "identification": f["identification"],
        "nse_json": f["nse_json"], "remarks": f["remarks"],
        "category": f.get("category", ""), "usage": f.get("usage", ""),
        "risk_level": f.get("risk_level", "info"),
        "compliance_json": f.get("compliance_json", []),
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
