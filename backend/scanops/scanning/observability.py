"""종료된 스캔의 compact 조회 원장.

실행 중 재개·중지의 원천은 기존 sidecar다. 이 모듈은 orchestration이 종료 시 sidecar를
materialize하거나, ingest가 이미 정규화한 endpoint 관측을 같은 transaction에 기록할 때만
사용한다. 어떤 helper도 commit하지 않는다.
"""
from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import (
    EndpointObservation,
    ScanExecution,
    ScanHostObservation,
    ScanQualityIssue,
)

_HOST_STATUS_FIELDS = (
    "discovery_status",
    "tcp_sweep_status",
    "tcp_service_status",
    "udp_sweep_status",
    "udp_service_status",
)


# 라이브 실행 뷰가 쓰는 진단 필드. 여기 없는 것은 화면도 안 그린다.
_DIAGNOSTIC_INTS = ("watchdog_seconds", "timeout_count", "retransmission_cap_count")
_DIAGNOSTIC_LISTS = ("timed_out", "retransmission_cap_hosts")


def _diagnostics(raw: Mapping) -> dict | None:
    """실행의 진단값만 추린다. 하나도 없으면 None - 빈 dict 로 자리만 차지하지 않는다."""
    out: dict = {}
    for key in _DIAGNOSTIC_INTS:
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value:
            out[key] = value
    for key in _DIAGNOSTIC_LISTS:
        value = raw.get(key)
        if isinstance(value, list):
            hosts = [item for item in value if isinstance(item, str)]
            if hosts:
                out[key] = hosts
    return out or None


def _text(value, limit: int | None = None) -> str:
    result = value if isinstance(value, str) else ""
    return result[:limit] if limit is not None else result


def _datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _seconds(value) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return max(float(value), 0.0)
    return None


def _return_code(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _rows_by_key(rows: Iterable[Mapping], key: str) -> dict[str, Mapping]:
    result: dict[str, Mapping] = {}
    for raw in rows or ():
        if not isinstance(raw, Mapping):
            continue
        value = _text(raw.get(key))
        if value:
            result[value] = raw
    return result


def _issue_key(raw: Mapping) -> str:
    explicit = _text(raw.get("issue_key"), 384)
    if explicit:
        return explicit
    parts = (
        _issue_kind(raw),
        _text(raw.get("stage"), 32),
        _text(raw.get("host_ip"), 64),
        _text(raw.get("execution_key"), 256),
    )
    detail_hash = hashlib.sha256(_text(raw.get("detail")).encode("utf-8")).hexdigest()[:16]
    return "|".join((*parts, detail_hash))[:384]


def _issue_kind(raw: Mapping) -> str:
    """engine/UI event payloads historically called this field `type`."""
    return _text(raw.get("kind") or raw.get("type"), 32)


def materialize_terminal_observability(
    db: Session,
    scan_id: int,
    *,
    executions: Iterable[Mapping] = (),
    issues: Iterable[Mapping] = (),
    hosts: Iterable[Mapping] = (),
) -> dict[str, int]:
    """Upsert terminal execution/quality/host projections without committing.

    `executions`는 parse_events의 execution dict를 그대로 받을 수 있다. terminal 시점에도
    command_done이 없는 실행은 더 이상 실행 중이 아니므로 `interrupted`로 저장한다.
    issue는 `execution_id` 대신 `execution_key`를 주면 이 함수가 같은 scan의 FK를 연결한다.
    """
    execution_rows = list(executions or ())
    execution_input = {
        key[:256]: raw for key, raw in _rows_by_key(execution_rows, "id").items()
    }
    # 호출자가 DB 명칭을 직접 쓰는 것도 허용하되 저장 key는 하나로 정규화한다.
    for raw in execution_rows:
        if isinstance(raw, Mapping) and not _text(raw.get("id")):
            key = _text(raw.get("execution_key"))
            if key:
                execution_input[key[:256]] = raw

    execution_keys = list(execution_input)
    existing_executions = {
        row.execution_key: row
        for row in db.query(ScanExecution).filter(
            ScanExecution.scan_id == scan_id,
            ScanExecution.execution_key.in_(execution_keys),
        ).all()
    } if execution_keys else {}
    for key, raw in execution_input.items():
        row = existing_executions.get(key)
        if row is None:
            row = ScanExecution(scan_id=scan_id, execution_key=key)
            db.add(row)
            existing_executions[key] = row
        status = _text(raw.get("status"), 16) or "interrupted"
        if status == "running":
            status = "interrupted"
        argv = raw.get("argv") if isinstance(raw.get("argv"), list) else raw.get("argv_json")
        row.stage = _text(raw.get("stage"), 32)
        row.group_kind = _text(raw.get("group") or raw.get("group_kind"), 16) or "common"
        row.role = _text(raw.get("role"), 16)
        row.reason = _text(raw.get("reason"))
        row.artifact = _text(raw.get("artifact"), 256)
        row.argv_json = [arg for arg in (argv or []) if isinstance(arg, str)]
        if not (row.status in {"done", "timeout", "error", "stopped"} and status == "interrupted"):
            row.status = status
        row.started_at = _datetime(raw.get("started_at"))
        row.finished_at = _datetime(raw.get("finished_at"))
        row.seconds = _seconds(raw.get("seconds"))
        row.return_code = _return_code(raw.get("rc", raw.get("return_code")))
        # 완료된 스캔의 상세도 라이브와 같은 것을 보여야 한다. 이 값들을 안 남기면 상한이나
        # 호스트 시간 초과가 있었던 실행이 '시간 초과 undefined대' 처럼 그려진다.
        row.diagnostics_json = _diagnostics(raw)
    db.flush()  # issue의 execution_key를 새 행 id로 연결한다.

    issue_input: dict[str, Mapping] = {}
    for raw in issues or ():
        if not isinstance(raw, Mapping):
            continue
        kind = _issue_kind(raw)
        if kind:
            issue_input[_issue_key(raw)] = raw
    issue_keys = list(issue_input)
    existing_issues = {
        row.issue_key: row
        for row in db.query(ScanQualityIssue).filter(
            ScanQualityIssue.scan_id == scan_id,
            ScanQualityIssue.issue_key.in_(issue_keys),
        ).all()
    } if issue_keys else {}
    execution_by_key = {
        row.execution_key: row for row in db.query(ScanExecution).filter_by(scan_id=scan_id).all()
    }
    for key, raw in issue_input.items():
        row = existing_issues.get(key)
        if row is None:
            row = ScanQualityIssue(
                scan_id=scan_id,
                issue_key=key,
                kind=_issue_kind(raw),
            )
            db.add(row)
            existing_issues[key] = row
        execution_key = _text(raw.get("execution_key"), 256)
        if execution_key:
            execution = execution_by_key.get(execution_key)
            row.execution_id = execution.id if execution is not None else None
        row.kind = _issue_kind(raw)
        row.stage = _text(raw.get("stage"), 32)
        row.host_ip = _text(raw.get("host_ip"), 64)
        row.detail = _text(raw.get("detail"))

    host_input = {
        key[:64]: raw for key, raw in _rows_by_key(hosts, "host_ip").items()
    }
    host_ips = list(host_input)
    existing_hosts = {
        row.host_ip: row
        for row in db.query(ScanHostObservation).filter(
            ScanHostObservation.scan_id == scan_id,
            ScanHostObservation.host_ip.in_(host_ips),
        ).all()
    } if host_ips else {}
    for host_ip, raw in host_input.items():
        row = existing_hosts.get(host_ip)
        if row is None:
            row = ScanHostObservation(scan_id=scan_id, host_ip=host_ip)
            db.add(row)
            existing_hosts[host_ip] = row
        for field in _HOST_STATUS_FIELDS:
            if field in raw:
                setattr(row, field, _text(raw.get(field), 16) or "unknown")

    db.flush()
    return {
        "executions": len(execution_input),
        "quality_issues": len(issue_input),
        "host_observations": len(host_input),
    }


def set_quality_retry(
    db: Session,
    source_scan_id: int,
    retry_scan_id: int,
    issue_keys: Iterable[str] | None = None,
) -> int:
    """Mark the exact unresolved source issues included in a retry; does not commit."""
    query = db.query(ScanQualityIssue).filter(
        ScanQualityIssue.scan_id == source_scan_id,
        ScanQualityIssue.resolved_by_scan_id.is_(None),
    )
    if issue_keys is not None:
        selected = {key for key in issue_keys if isinstance(key, str) and key}
        if not selected:
            return 0
        query = query.filter(ScanQualityIssue.issue_key.in_(selected))
    rows = query.all()
    for row in rows:
        row.retry_scan_id = retry_scan_id
    db.flush()
    return len(rows)


def resolve_quality_issues(
    db: Session,
    source_scan_id: int,
    resolved_by_scan_id: int,
    issue_keys: Iterable[str],
) -> int:
    """Resolve only caller-proven exact issue keys; broad child-scan resolution is forbidden."""
    selected = {key for key in issue_keys if isinstance(key, str) and key}
    if not selected:
        return 0
    rows = db.query(ScanQualityIssue).filter(
        ScanQualityIssue.scan_id == source_scan_id,
        ScanQualityIssue.issue_key.in_(selected),
        ScanQualityIssue.resolved_by_scan_id.is_(None),
    ).all()
    for row in rows:
        row.resolved_by_scan_id = resolved_by_scan_id
        row.retry_scan_id = resolved_by_scan_id
    db.flush()
    return len(rows)


def record_endpoint_observations(
    db: Session,
    scan_id: int,
    findings: Iterable[Mapping],
    *,
    applied_keys: set[str],
    absences: Mapping[str, datetime],
    applied_absence_keys: set[str],
    scan_date: datetime | None,
) -> int:
    """Record positive observations and already-authorized absences; does not commit.

    `absences`는 ingest가 coverage·시각 검사를 통과한 기존 후보만 넘긴다. 포트 범위를
    확장하지 않으므로 이 함수는 한 번도 full closed-port cartesian rows를 만들지 않는다.
    """
    fallback_when = scan_date or datetime.now(timezone.utc)
    positives: dict[str, tuple[Mapping, datetime]] = {}
    for raw in findings or ():
        if not isinstance(raw, Mapping):
            continue
        try:
            key = f"{raw['host_ip']}|{int(raw['port'])}|{str(raw['proto']).lower()}"
        except (KeyError, TypeError, ValueError):
            continue
        when = _datetime(raw.get("observed_at")) or fallback_when
        current = positives.get(key)
        if current is None or when >= current[1]:
            positives[key] = (raw, when)

    keys = set(positives) | {key for key in absences if isinstance(key, str) and key}
    existing = {
        row.finding_key: row
        for row in db.query(EndpointObservation).filter(
            EndpointObservation.scan_id == scan_id,
            EndpointObservation.finding_key.in_(keys),
        ).all()
    } if keys else {}

    for key, (raw, when) in positives.items():
        row = existing.get(key)
        was_applied = bool(row.applied_to_current) if row is not None else False
        existing_when = _datetime(row.observed_at) if row is not None else None
        if existing_when is not None and existing_when > when:
            row.applied_to_current = 1 if was_applied or key in applied_keys else 0
            continue
        if row is None:
            row = EndpointObservation(
                scan_id=scan_id,
                finding_key=key,
                host_ip=_text(raw.get("host_ip"), 64),
                port=int(raw.get("port")),
                proto=_text(raw.get("proto"), 8).lower(),
                state=_text(raw.get("state"), 16) or "open",
                evidence_kind="positive",
            )
            db.add(row)
            existing[key] = row
        row.host_ip = _text(raw.get("host_ip"), 64)
        row.port = int(raw.get("port"))
        row.proto = _text(raw.get("proto"), 8).lower()
        row.state = _text(raw.get("state"), 16) or "open"
        row.reason = _text(raw.get("reason"), 32)
        row.evidence_kind = "positive"
        row.identity_observed = 0 if raw.get("identity_observed") is False else 1
        # 같은 scan을 재-finalize하면 현재 Finding은 이미 이 관측으로 바뀌어 있어 ingest의
        # applied set이 달라질 수 있다. 과거에 실제 적용됐다는 사실은 되돌리지 않는다.
        row.applied_to_current = 1 if was_applied or key in applied_keys else 0
        row.hostname = _text(raw.get("hostname"), 128)
        row.service = _text(raw.get("service"), 64)
        row.product = _text(raw.get("product"), 128)
        row.version = _text(raw.get("version"), 128)
        row.server = _text(raw.get("server"), 256)
        row.identification = _text(raw.get("identification"), 16) or "미확인"
        row.observed_at = when

    for key, observed_at in absences.items():
        if key in positives or not isinstance(key, str):
            continue
        parts = key.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            port = int(parts[1])
        except ValueError:
            continue
        row = existing.get(key)
        was_applied = bool(row.applied_to_current) if row is not None else False
        when = _datetime(observed_at) or fallback_when
        existing_when = _datetime(row.observed_at) if row is not None else None
        if existing_when is not None and existing_when > when:
            row.applied_to_current = 1 if was_applied or key in applied_absence_keys else 0
            continue
        if row is None:
            row = EndpointObservation(
                scan_id=scan_id,
                finding_key=key,
                host_ip=parts[0],
                port=port,
                proto=parts[2].lower(),
                state="closed",
                evidence_kind="absence",
            )
            db.add(row)
            existing[key] = row
        row.host_ip = parts[0][:64]
        row.port = port
        row.proto = parts[2].lower()[:8]
        row.state = "closed"
        row.reason = "scanops-scope"
        row.evidence_kind = "absence"
        row.identity_observed = 0
        row.applied_to_current = 1 if was_applied or key in applied_absence_keys else 0
        row.hostname = ""
        row.service = ""
        row.product = ""
        row.version = ""
        row.server = ""
        row.identification = "미확인"
        row.observed_at = when

    db.flush()
    return len(keys)
