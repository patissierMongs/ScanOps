"""스캔 결과 인입 — 안정키로 finding upsert + 변화 이벤트 생성.

이게 ScanOps 의 핵심: diff 가 *발견의 시간적 정체성*과 묶여,
재스캔 시 "그 포트가 닫혔나"를 자동으로 판정한다.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import Finding, FindingEvent


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _key(f: dict) -> str:
    return f"{f['host_ip']}|{f['port']}|{f['proto']}"


def ingest(db: Session, scan_id: int, findings: list[dict], scanned_hosts: set[str],
           scope_keys: set[str] | None = None, scan_date: datetime | None = None) -> dict:
    """findings(이번 스캔의 열린 포트들)와 scanned_hosts(up 호스트)로 DB 갱신.

    scope_keys 가 주어지면(타겟 포트 재스캔) 닫힘 판정을 그 키(host|port|proto)로만
    한정 — 스캔하지 않은 다른 포트가 거짓 닫힘 처리되지 않게 한다. None 이면 호스트 전체.
    scan_date 는 '실제 스캔 실행일'(가져온 XML 은 파일 내 시각). first/last_seen 에 쓴다.
    None 이면 현재시각. 리턴: 변화 요약 카운트.
    """
    when = scan_date or _now()
    counts = {"new": 0, "reopened": 0, "service_changed": 0,
              "version_changed": 0, "unchanged": 0, "closed": 0}
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

        # 기존 발견 갱신
        reopened = row.state != "open"
        old_service, old_version = row.service, row.version
        for k, v in _observed(f).items():
            setattr(row, k, v)
        row.last_scan_id = scan_id
        row.last_seen = when

        if reopened:
            _event(db, row.id, scan_id, "REOPENED", "닫혔던 포트가 다시 열림", when=when)
            if row.status == "정상처리":
                row.status = "재발"
            counts["reopened"] += 1
        elif old_service != f["service"]:
            _event(db, row.id, scan_id, "SERVICE_CHANGED", f"{old_service} → {f['service']}", when=when)
            counts["service_changed"] += 1
        elif old_version != f["version"]:
            _event(db, row.id, scan_id, "VERSION_CHANGED", f"{old_version} → {f['version']}", when=when)
            counts["version_changed"] += 1
        else:
            counts["unchanged"] += 1

    # 닫힘 판정: 이번에 스캔된 호스트에서, 이전엔 열렸는데 이번에 안 보인 포트.
    if scanned_hosts:
        open_rows = db.query(Finding).filter(
            Finding.state == "open", Finding.host_ip.in_(scanned_hosts)
        ).all()
        for row in open_rows:
            if row.finding_key in seen:
                continue
            if scope_keys is not None and row.finding_key not in scope_keys:
                continue  # 타겟 재스캔 범위 밖 포트는 손대지 않음
            row.state = "closed"
            row.last_scan_id = scan_id
            row.last_seen = when
            # 마감/배정이 걸려 있던 항목이 닫힘 → 조치 완료 자동 검증
            verified = row.status == "처리중" or row.deadline is not None
            row.status = "정상처리"
            detail = "포트 닫힘 — 조치 완료 자동 확인" if verified else "포트 닫힘"
            _event(db, row.id, scan_id, "CLOSED", detail, when=when)
            counts["closed"] += 1

    db.commit()
    return counts


def _observed(f: dict) -> dict:
    """스캔이 갱신하는 관측 + 분류 필드(운영상태는 제외)."""
    return {
        "host_ip": f["host_ip"], "hostname": f["hostname"], "port": f["port"],
        "proto": f["proto"], "state": f["state"], "service": f["service"],
        "product": f["product"], "version": f["version"], "banner": f["banner"],
        "cpe": f["cpe"], "rtt": f["rtt"], "identification": f["identification"],
        "nse_json": f["nse_json"], "remarks": f["remarks"],
        "category": f.get("category", ""), "usage": f.get("usage", ""),
        "risk_level": f.get("risk_level", "info"),
        "compliance_json": f.get("compliance_json", []),
    }


def _event(db: Session, finding_id: int, scan_id: int, type_: str, detail: str,
           actor_user_id: int | None = None, when: datetime | None = None) -> None:
    # 스캔 생성 이벤트의 시각은 '실제 스캔 시각'(가져온 XML 은 파일 내 시각). 인입 시각 아님.
    ev = FindingEvent(finding_id=finding_id, scan_id=scan_id, type=type_,
                      detail=detail, actor_user_id=actor_user_id)
    if when is not None:
        ev.created_at = when
    db.add(ev)
