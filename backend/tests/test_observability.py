"""Compact terminal observability projections and lifecycle contracts."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanops.db import SessionLocal, init_db
from scanops.models import (
    EndpointObservation,
    Finding,
    FindingEvent,
    ScanExecution,
    ScanHostObservation,
    ScanQualityIssue,
    ScanRun,
)
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import parse_xml
from scanops.scanning.observability import (
    materialize_terminal_observability,
    resolve_quality_issues,
    set_quality_retry,
)

XML = "tests/fixtures/sample_scan.xml"


def _scan(db, name="scan") -> ScanRun:
    row = ScanRun(name=name, status="done")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _one_finding() -> dict:
    return dict(parse_xml(XML)[0])


def test_terminal_materializer_is_idempotent_and_keeps_zero_port_hosts():
    init_db()
    db = SessionLocal()
    try:
        scan = _scan(db)
        first = materialize_terminal_observability(
            db,
            scan.id,
            executions=[{
                "id": "stage-tcp-b0.xml:1",
                "stage": "tcp",
                "group": "common",
                "artifact": "stage-tcp-b0.xml",
                "argv": ["nmap", "-p", "1-65535", "10.0.0.1"],
                "status": "running",
                "started_at": 1_700_000_000.0,
            }],
            issues=[{
                "issue_key": "timeout|tcp|10.0.0.1",
                "kind": "host_timeout",
                "stage": "tcp",
                "host_ip": "10.0.0.1",
                "execution_key": "stage-tcp-b0.xml:1",
                "detail": "host timeout",
            }],
            hosts=[{
                "host_ip": "10.0.0.1",
                "discovery_status": "up",
                "tcp_sweep_status": "timeout",
                "tcp_service_status": "not_applicable",
                "udp_sweep_status": "disabled",
                "udp_service_status": "disabled",
            }],
        )
        db.commit()
        assert first == {"executions": 1, "quality_issues": 1, "host_observations": 1}
        assert db.query(EndpointObservation).count() == 0  # 열린 포트가 없어도 host는 남는다.

        second = materialize_terminal_observability(
            db,
            scan.id,
            executions=[{
                "id": "stage-tcp-b0.xml:1",
                "stage": "tcp",
                "group": "common",
                "artifact": "stage-tcp-b0.xml",
                "argv": ["nmap", "-p", "1-65535", "10.0.0.1"],
                "status": "done",
                "started_at": 1_700_000_000.0,
                "finished_at": 1_700_000_003.0,
                "seconds": 3.0,
                "rc": 0,
            }],
            issues=[{
                "issue_key": "timeout|tcp|10.0.0.1",
                "kind": "host_timeout",
                "stage": "tcp",
                "host_ip": "10.0.0.1",
                "execution_key": "stage-tcp-b0.xml:1",
                "detail": "host timeout",
            }],
            hosts=[{"host_ip": "10.0.0.1", "tcp_sweep_status": "complete"}],
        )
        db.commit()

        assert second == first
        assert db.query(ScanExecution).count() == 1
        assert db.query(ScanQualityIssue).count() == 1
        assert db.query(ScanHostObservation).count() == 1
        execution = db.query(ScanExecution).one()
        assert execution.status == "done" and execution.return_code == 0
        assert execution.started_at == datetime.fromtimestamp(1_700_000_000, timezone.utc).replace(tzinfo=None)
        issue = db.query(ScanQualityIssue).one()
        assert issue.execution_id == execution.id
        assert db.query(ScanHostObservation).one().tcp_sweep_status == "complete"
    finally:
        db.close()


def test_ingest_records_positive_stale_and_authoritative_absence_without_duplicates():
    init_db()
    db = SessionLocal()
    try:
        finding = _one_finding()
        key = f"{finding['host_ip']}|{finding['port']}|{finding['proto']}"
        current_when = datetime(2026, 1, 1, tzinfo=timezone.utc)
        stale_when = datetime(2025, 1, 1, tzinfo=timezone.utc)
        close_when = datetime(2027, 1, 1, tzinfo=timezone.utc)

        current = _scan(db, "current")
        ingest(db, current.id, [finding], {finding["host_ip"]}, scan_date=current_when)
        current_observation = db.query(EndpointObservation).filter_by(scan_id=current.id).one()
        assert current_observation.state == "open"
        assert current_observation.evidence_kind == "positive"
        assert current_observation.applied_to_current == 1

        # 같은 scan id를 idempotent 재-finalize하더라도 더 오래된 artifact가 snapshot을
        # 역행시키면 안 된다.
        same_scan_stale = {**finding, "service": "older-same-scan", "observed_at": stale_when}
        ingest(
            db, current.id, [same_scan_stale], {finding["host_ip"]}, scan_date=stale_when,
        )
        db.refresh(current_observation)
        assert current_observation.service == finding["service"]
        assert current_observation.applied_to_current == 1

        stale_finding = {**finding, "service": "stale-service", "observed_at": stale_when}
        stale = _scan(db, "stale")
        ingest(db, stale.id, [stale_finding], {finding["host_ip"]}, scan_date=stale_when)
        stale_observation = db.query(EndpointObservation).filter_by(scan_id=stale.id).one()
        assert stale_observation.service == "stale-service"
        assert stale_observation.applied_to_current == 0
        assert db.query(Finding).filter_by(finding_key=key).one().service == finding["service"]

        closed = _scan(db, "closed")
        ingest(
            db,
            closed.id,
            [],
            {finding["host_ip"]},
            scope_keys={key},
            scan_date=close_when,
        )
        absence = db.query(EndpointObservation).filter_by(scan_id=closed.id).one()
        assert absence.state == "closed" and absence.evidence_kind == "absence"
        assert absence.applied_to_current == 1

        # 같은 scan finalization을 다시 실행해도 행이 늘거나 과거 적용 사실이 사라지지 않는다.
        ingest(
            db,
            closed.id,
            [],
            {finding["host_ip"]},
            scope_keys={key},
            scan_date=close_when,
        )
        assert db.query(EndpointObservation).filter_by(scan_id=closed.id).count() == 1
        assert db.query(EndpointObservation).filter_by(scan_id=closed.id).one().applied_to_current == 1
    finally:
        db.close()


def test_ingest_does_not_expand_never_seen_scope_keys_into_closed_rows():
    init_db()
    db = SessionLocal()
    try:
        finding = _one_finding()
        host = finding["host_ip"]
        opened = _scan(db, "opened")
        ingest(db, opened.id, [finding], {host})

        closed = _scan(db, "wide-scope")
        known = f"{host}|{finding['port']}|{finding['proto']}"
        never_seen = {f"{host}|{port}|tcp" for port in range(1000, 1100)}
        ingest(db, closed.id, [], {host}, scope_keys={known, *never_seen})

        rows = db.query(EndpointObservation).filter_by(scan_id=closed.id).all()
        assert [row.finding_key for row in rows] == [known]
    finally:
        db.close()


def test_quality_resolution_is_exact_and_child_delete_reopens_source_issue():
    init_db()
    db = SessionLocal()
    try:
        source = _scan(db, "source")
        child = _scan(db, "retry")
        materialize_terminal_observability(
            db,
            source.id,
            issues=[
                {"issue_key": "tcp-a", "kind": "host_timeout", "stage": "tcp",
                 "host_ip": "10.0.0.1"},
                {"issue_key": "udp-b", "kind": "host_timeout", "stage": "udp",
                 "host_ip": "10.0.0.2"},
            ],
        )
        assert set_quality_retry(db, source.id, child.id) == 2
        assert resolve_quality_issues(db, source.id, child.id, ["tcp-a"]) == 1
        db.commit()

        issues = {row.issue_key: row for row in db.query(ScanQualityIssue).all()}
        assert issues["tcp-a"].resolved is True
        assert issues["udp-b"].resolved is False
        assert issues["udp-b"].retry_scan_id == child.id

        db.delete(child)
        db.commit()
        db.expire_all()
        issues = {row.issue_key: row for row in db.query(ScanQualityIssue).all()}
        assert issues["tcp-a"].resolved is False and issues["tcp-a"].retry_scan_id is None
        assert issues["udp-b"].resolved is False and issues["udp-b"].retry_scan_id is None

        db.delete(source)
        db.commit()
        assert db.query(ScanQualityIssue).count() == 0
    finally:
        db.close()


def test_endpoint_observation_failure_rolls_back_finding_and_event(monkeypatch):
    init_db()
    db = SessionLocal()
    try:
        scan = _scan(db)

        def fail(*_args, **_kwargs):
            raise RuntimeError("observation write failed")

        monkeypatch.setattr("scanops.scanning.ingest.record_endpoint_observations", fail)
        with pytest.raises(RuntimeError, match="observation write failed"):
            ingest(db, scan.id, [_one_finding()], {"127.0.0.1"})
        db.rollback()

        assert db.query(Finding).count() == 0
        assert db.query(FindingEvent).count() == 0
        assert db.query(EndpointObservation).count() == 0
    finally:
        db.close()


def test_a_retry_with_broken_authority_resolves_nothing(monkeypatch):
    """재시도가 authority 산출물을 제대로 못 남겼으면 원래 이슈를 닫으면 안 된다.

    호스트 상태는 coverage 항목의 `finished` 플래그에서 나오므로, nmap 이 rc=0 으로 끝났지만
    그 뒤 authority XML 이 없거나 완결되지 않은 실행에서도 `done` 으로 찍힌다. 그 상태로
    이슈를 닫으면 `artifact_report` 가 `authority_missing`/`authority_broken` 으로 분류하고
    스캔을 partial 로 마감한 실행이 **원래 구멍을 메운 것처럼** 기록된다 - 재시도 안내가
    사라져 아무도 다시 보지 않는다.
    """
    from scanops.api import scans as scans_api

    called: list[str] = []
    monkeypatch.setattr(scans_api.observability, "resolve_quality_issues",
                        lambda *a, **k: called.append("resolved") or 0)

    spec = {"scanops": {"retry_of": 1}}
    broken = {"authority_missing": [], "authority_broken": ["stage-tcp-b0.xml"]}
    assert scans_api._resolve_retry_observations(None, 2, spec, broken) == 0
    assert called == [], "손상된 authority 로 이슈를 해결 처리했다"

    missing = {"authority_missing": ["stage0-discovery.xml"], "authority_broken": []}
    assert scans_api._resolve_retry_observations(None, 2, spec, missing) == 0
    assert called == [], "빠진 authority 로 이슈를 해결 처리했다"


def test_a_clean_retry_still_reaches_the_resolution_path(monkeypatch):
    """반대 경계 - authority 가 온전하면 판정 자체는 그대로 진행해야 한다.

    보수적으로 막는 것과 아예 못 닫게 하는 것은 다르다. 온전한 재시도까지 막으면 이슈가
    영영 남아 재시도 안내가 사라지지 않는다.
    """
    from scanops.api import scans as scans_api

    reached: list[str] = []

    class _Q:
        def filter(self, *_a, **_k):
            return self

        def filter_by(self, **_k):
            return self

        def all(self):
            reached.append("queried")
            return []

    class _DB:
        def query(self, *_a, **_k):
            return _Q()

    clean = {"authority_missing": [], "authority_broken": []}
    scans_api._resolve_retry_observations(_DB(), 2, {"scanops": {"retry_of": 1}}, clean)
    assert reached, "authority 가 온전한데 판정 경로에 들어가지도 않았다"


def _issue_scan(db, name, kinds):
    from scanops.models import ScanQualityIssue, ScanRun

    scan = ScanRun(name=name, targets="10.0.0.1", status="done", command="x")
    db.add(scan)
    db.commit()
    for kind, host in kinds:
        db.add(ScanQualityIssue(scan_id=scan.id, issue_key=f"{kind}|{host}", kind=kind,
                                stage="tcp", host_ip=host, detail="d"))
    db.commit()
    return scan


def test_the_retry_offer_matches_what_the_retry_endpoint_accepts(client):
    """이력이 제안하는 재스캔과 실행이 받아들이는 재스캔은 같은 집합이어야 한다.

    `retry_timed_out_hosts()` 는 `_durable_retry_detail()` 을 통해 **호스트가 붙은**
    timeout/재전송/저하 이슈만 받는다. 이력이 unresolved 전체로 `retry_required` 를 세우면,
    호스트 없는 `artifact_missing`/`command_error` 만 남은 스캔에서도 화면이 "N대 재스캔" 을
    띄우고 누르면 **항상 400** 이 난다. 이슈 개수를 호스트 수 자리에 넣는 것도 같은 문제다.
    """
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal

    db = SessionLocal()
    try:
        hostless = _issue_scan(db, "hostless",
                               [("artifact_missing", ""), ("command_error", "")])
        mixed = _issue_scan(db, "mixed",
                            [("host_timeout", "10.0.0.7"), ("artifact_missing", "")])
        history = scans_api._retry_history([hostless, mixed], db)

        offered = history[hostless.id]
        assert offered["retry_required"] is False, "재스캔할 수 없는 스캔에 재스캔을 제안한다"
        assert offered["retry_count"] == 0, "이슈 개수를 호스트 수로 보여 준다"
        # 재스캔은 못 해도 '확인 필요' 로는 남아야 한다 - 다른 축이다.
        assert offered["quality_status"] == "error"
        assert offered["unresolved_issue_count"] == 2
        assert (scans_api._durable_retry_detail(db, hostless.id) or {}).get("required") is not True

        # `retry_status` 도 같은 집합에서 나와야 한다. 화면은 이 값을 **먼저** 읽어
        # 재스캔 배지를 그리고, 같은 값이 `required` 면 품질 배지를 가린다 - unresolved
        # 전체로 세우면 '재스캔 필요 · 0대' 가 뜨면서 진짜 '품질 오류 · 2건' 이 숨는다.
        assert offered["retry_status"] != "required", (
            "재스캔할 수 없는데 배지를 띄우고 품질 오류를 가린다"
        )

        both = history[mixed.id]
        assert both["retry_required"] is True, "재시도 가능한 이슈가 있는데 제안하지 않는다"
        assert both["retry_count"] == 1, "재시도 대상 호스트만 세야 한다"
        assert scans_api._durable_retry_detail(db, mixed.id)["required"] is True
        assert both["retry_status"] == "required"
        assert both["quality_status"] == "error"      # 섞인 오류도 그대로 보인다

        # 섞였을 때 화면이 셀 수 있어야 하는 건 **재시도로 못 메우는 나머지**다. 화면은
        # retry_status == "required" 면 재스캔 배지를 띄우고 품질 배지에서는 이 수만
        # 말한다 - 이 값이 없으면(0 이면) artifact_missing 이 '재스캔 필요' 뒤에 묻혀,
        # 재스캔 한 번으로 다 끝난다는 거짓 안내가 된다.
        assert both["unresolved_issue_count"] == 2
        assert both["unresolved_other_count"] == 1, (
            "재시도로 사라지지 않는 이슈를 화면이 따로 셀 수 없다"
        )
        # 재시도 이슈만 있는 스캔은 나머지가 없어야 한다 - 같은 이슈를 두 배지가 두 번
        # 말하면 그것대로 틀린다.
        only_retryable = _issue_scan(db, "only-retryable", [("host_timeout", "10.0.0.9")])
        only = scans_api._retry_history([only_retryable], db)[only_retryable.id]
        assert only["retry_status"] == "required"
        assert only["unresolved_other_count"] == 0
        # 재시도할 수 없는 것만 있으면 배지가 전부를 말한다(재스캔 배지가 안 뜬다).
        assert offered["unresolved_other_count"] == offered["unresolved_issue_count"] == 2
    finally:
        db.close()


def test_a_finished_scan_keeps_the_diagnostics_the_live_view_showed():
    """완료된 스캔의 상세도 라이브와 같은 것을 보여야 한다.

    terminal 상태에서는 응답이 이벤트 대신 DB 행에서 만들어진다. 그 투영이 진단값을
    빠뜨리면 상한이나 호스트 시간 초과가 있었던 실행이 화면에서 '시간 초과 undefined대'
    처럼 그려지고, 어느 호스트가 걸렸는지도 사라진다 - `command_done` 이 그 값을 이미
    기록해 두었는데도.
    """
    init_db()
    db = SessionLocal()
    try:
        scan = _scan(db, "진단")
        materialize_terminal_observability(db, scan.id, executions=[{
            "id": "stage3-udp-b0-g0.xml:1", "stage": "udp_service", "group": "common",
            "artifact": "stage3-udp-b0-g0.xml", "argv": ["nmap", "-sU"],
            "status": "timeout", "seconds": 12.0, "rc": 0,
            "watchdog_seconds": 600, "timeout_count": 2,
            "timed_out": ["10.0.0.1", "10.0.0.2"],
            "retransmission_cap_count": 1, "retransmission_cap_hosts": ["10.0.0.3"],
        }], issues=[], hosts=[])
        db.commit()
        row = db.query(ScanExecution).filter_by(scan_id=scan.id).one()
        assert row.diagnostics_json == {
            "watchdog_seconds": 600, "timeout_count": 2,
            "timed_out": ["10.0.0.1", "10.0.0.2"],
            "retransmission_cap_count": 1, "retransmission_cap_hosts": ["10.0.0.3"],
        }, f"진단값이 저장되지 않았다: {row.diagnostics_json}"
    finally:
        db.close()

    # 응답 투영도 라이브와 같은 모양이어야 한다 - 저장만 하고 안 실어 보내면 소용이 없다.
    api_src = (Path(__file__).resolve().parents[1]
               / "scanops" / "api" / "scans.py").read_text(encoding="utf-8")
    projection = api_src.split("} for row in durable_executions]")[0]
    projection = projection[projection.rindex("executions = ["):]
    for key in ("watchdog_seconds", "timeout_count", "timed_out",
                "retransmission_cap_count", "retransmission_cap_hosts"):
        assert key in projection, f"완료된 스캔 응답에 {key} 가 없다"
    assert "row.diagnostics_json" in projection


def test_an_execution_without_diagnostics_stores_nothing():
    """반대 경계 — 진단값이 없으면 빈 dict 로 자리를 차지하지 않는다.

    옛 행은 이 값이 애초에 없었다. None 이어야 화면이 기본값으로 그린다.
    """
    init_db()
    db = SessionLocal()
    try:
        scan = _scan(db, "평범")
        materialize_terminal_observability(db, scan.id, executions=[{
            "id": "stage-tcp-b0.xml:1", "stage": "tcp", "status": "done",
            "seconds": 1.0, "rc": 0,
            "watchdog_seconds": 0, "timeout_count": 0, "timed_out": [],
            "retransmission_cap_count": 0, "retransmission_cap_hosts": [],
        }], issues=[], hosts=[])
        db.commit()
        row = db.query(ScanExecution).filter_by(scan_id=scan.id).one()
        assert row.diagnostics_json is None
    finally:
        db.close()
