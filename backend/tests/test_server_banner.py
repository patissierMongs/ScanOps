"""Server 관측값의 추출·인입·구형 DB 백필 회귀 계약."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine

import scanops.db as db_module
from scanops.db import SessionLocal
from scanops.models import Finding, FindingEvent, ScanRun, User
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import extract_server, parse_xml, server_observed


@pytest.mark.parametrize(
    ("nse", "expected"),
    [
        ([{"id": "HTTP-SERVER-HEADER", "output": "  Server:\t uvicorn   0.30  \r\n"}],
         "uvicorn 0.30"),
        ([{"id": "http-headers", "output": "Date: now\nSeRvEr:\tApache   2.4\r\nX-Test: 1"}],
         "Apache 2.4"),
        ([{"id": "fingerprint-strings", "output": "HTTP/1.1 200 OK\r\nsErVeR: gunicorn  \r\n"}],
         "gunicorn"),
        ([{"id": "http-server-header", "output": "  <EMPTY>  "}], ""),
        ([{"id": "http-server-header", "output": "\n  <empty>\n  nginx"}], "nginx"),
        ([
            {"id": "http-server-header", "output": ""},
            {"id": "http-server-header", "output": "   "},
            {"id": "http-headers", "output": "Server: fallback"},
        ], "fallback"),
        ([], ""),
        ([{"id": "http-title", "output": "Server: 제목일 뿐"}], ""),
    ],
)
def test_extract_server_sources_case_whitespace_and_empty_duplicates(nse, expected):
    assert extract_server(nse) == expected


def test_extract_server_uses_source_priority_not_script_order():
    nse = [
        {"id": "fingerprint-strings", "output": "Server: fingerprint"},
        {"id": "http-headers", "output": "Server: headers"},
        {"id": "http-server-header", "output": "direct"},
        {"id": "http-server-header", "output": "duplicate"},
    ]

    assert extract_server(nse) == "direct"


def test_server_observation_distinguishes_unobserved_from_observed_absence():
    assert server_observed([]) is False
    assert server_observed([{"id": "http-title", "output": "hello"}]) is False
    assert server_observed([{"id": "http-headers", "output": "Date: now"}]) is True
    assert server_observed([{"id": "http-server-header", "output": ""}]) is True


@pytest.mark.parametrize("output", [
    "ERROR: Script execution failed (use -d to debug)",
    "\nERROR: Header request failed",
])
def test_nse_failure_is_not_a_server_value_or_observation(output):
    nse = [{"id": "http-server-header", "output": output}]

    assert extract_server(nse) == ""
    assert server_observed(nse) is False


@pytest.mark.parametrize("output", [
    "HTTP/1.1 200 OK\r\nX-Server: decoy\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody server: decoy",
])
def test_fingerprint_server_requires_a_real_header_line(output):
    assert extract_server([{"id": "fingerprint-strings", "output": output}]) == ""


def test_unrelated_fingerprint_does_not_turn_failed_server_probe_into_observed_absence():
    nse = [
        {"id": "http-server-header", "output": "ERROR: Script execution failed"},
        {"id": "http-headers", "output": "ERROR: Header request failed"},
        {"id": "fingerprint-strings", "output": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"},
    ]

    assert extract_server(nse) == ""
    assert server_observed(nse) is False


def _server_xml(server: str, service: str = "apple-iphoto") -> bytes:
    return f"""<?xml version="1.0"?>
<nmaprun start="1893456000">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8770">
        <state state="open"/>
        <service name="{service}" method="table" conf="3"/>
        <script id="http-server-header" output="{server}"/>
      </port>
    </ports>
  </host>
</nmaprun>
""".encode()


def _scan(db, name: str) -> int:
    scan = ScanRun(name=name, status="done")
    db.add(scan)
    db.commit()
    return scan.id


def test_server_does_not_replace_nmap_service_taxonomy():
    parsed = parse_xml(_server_xml("uvicorn"))

    assert len(parsed) == 1
    assert parsed[0]["server"] == "uvicorn"
    assert parsed[0]["service"] == "apple-iphoto"


def test_new_open_event_prefers_server_identity_without_blank_prefix():
    db = SessionLocal()
    try:
        scan_id = _scan(db, "server-new-open")
        finding = parse_xml(_server_xml("uvicorn", service=""))[0]

        ingest(db, scan_id, [finding], {finding["host_ip"]})

        event = db.query(FindingEvent).filter_by(scan_id=scan_id, type="NEW_OPEN").one()
        assert event.detail == "uvicorn 8770/tcp 신규 발견"
    finally:
        db.close()


def test_ingest_server_change_emits_event_and_preserves_operational_fields():
    db = SessionLocal()
    try:
        owner = User(username="server-owner", password_hash="unused", role="auditor")
        db.add(owner)
        db.commit()

        first_scan_id = _scan(db, "server-before")
        finding = parse_xml(_server_xml("uvicorn"))[0]
        ingest(db, first_scan_id, [finding], {finding["host_ip"]})

        row = db.query(Finding).filter_by(port=8770).one()
        row.status = "처리중"
        row.reopened = 1
        row.owner_user_id = owner.id
        row.deadline = datetime(2030, 1, 2, tzinfo=timezone.utc)
        row.dept = "플랫폼팀"
        row.contact = "1234"
        row.owner = "김담당"
        row.manual_note = "운영 메모"
        db.commit()
        db.refresh(row)
        expected_deadline = row.deadline
        expected_first_seen = row.first_seen

        changed = dict(finding, server="gunicorn")
        second_scan_id = _scan(db, "server-after")
        counts = ingest(db, second_scan_id, [changed], {finding["host_ip"]})

        db.refresh(row)
        assert counts["server_changed"] == 1
        assert counts["service_changed"] == counts["version_changed"] == 0
        assert row.server == "gunicorn"
        assert row.service == "apple-iphoto"
        assert row.first_scan_id == first_scan_id
        assert row.first_seen == expected_first_seen
        assert (
            row.status, row.reopened, row.owner_user_id, row.deadline,
            row.dept, row.contact, row.owner, row.manual_note,
        ) == (
            "처리중", 1, owner.id, expected_deadline,
            "플랫폼팀", "1234", "김담당", "운영 메모",
        )
        event = db.query(FindingEvent).filter_by(
            finding_id=row.id, scan_id=second_scan_id, type="SERVER_CHANGED",
        ).one()
        assert event.detail == "uvicorn → gunicorn"
    finally:
        db.close()


def test_ingest_records_service_version_and_server_changes_from_same_scan():
    db = SessionLocal()
    try:
        first = parse_xml(_server_xml("uvicorn"))[0]
        first_scan_id = _scan(db, "identity-before")
        ingest(db, first_scan_id, [first], {first["host_ip"]})

        changed = dict(first, service="http", version="2.0", server="gunicorn")
        second_scan_id = _scan(db, "identity-after")
        counts = ingest(db, second_scan_id, [changed], {first["host_ip"]})

        assert counts["service_changed"] == 1
        assert counts["version_changed"] == 1
        assert counts["server_changed"] == 1
        finding = db.query(Finding).filter_by(port=8770).one()
        event_types = {
            event.type for event in db.query(FindingEvent).filter_by(
                finding_id=finding.id, scan_id=second_scan_id,
            )
        }
        assert {"SERVICE_CHANGED", "VERSION_CHANGED", "SERVER_CHANGED"} <= event_types
    finally:
        db.close()


def test_reopen_records_server_change_independently_from_reopen_event():
    db = SessionLocal()
    try:
        first = parse_xml(_server_xml("uvicorn"))[0]
        ingest(db, _scan(db, "server-before-close"), [first], {first["host_ip"]})
        ingest(db, _scan(db, "server-closed"), [], {first["host_ip"]})

        changed = dict(first, server="gunicorn")
        reopen_scan_id = _scan(db, "server-reopened")
        counts = ingest(db, reopen_scan_id, [changed], {first["host_ip"]})

        row = db.query(Finding).filter_by(port=8770).one()
        event_types = {
            event.type for event in db.query(FindingEvent).filter_by(
                finding_id=row.id, scan_id=reopen_scan_id,
            )
        }
        assert row.reopened == 1
        assert row.server == "gunicorn"
        assert counts["reopened"] == counts["server_changed"] == 1
        assert {"REOPENED", "SERVER_CHANGED"} <= event_types
    finally:
        db.close()


def test_ingest_preserves_unobserved_server_but_clears_observed_absence():
    db = SessionLocal()
    try:
        first = parse_xml(_server_xml("uvicorn"))[0]
        ingest(db, _scan(db, "server-present"), [first], {first["host_ip"]})

        unobserved = dict(first, server="", server_observed=False, nse_json=[], remarks="")
        counts = ingest(db, _scan(db, "server-not-probed"), [unobserved], {first["host_ip"]})
        row = db.query(Finding).filter_by(port=8770).one()
        assert row.server == "uvicorn"
        assert counts["server_changed"] == 0

        failed_probe = parse_xml(
            _server_xml("ERROR: Script execution failed (use -d to debug)")
        )[0]
        assert failed_probe["server"] == ""
        assert failed_probe["server_observed"] is False
        counts = ingest(db, _scan(db, "server-probe-failed"), [failed_probe], {first["host_ip"]})
        db.refresh(row)
        assert row.server == "uvicorn"
        assert counts["server_changed"] == 0

        unrelated_fingerprint = dict(
            first,
            server="",
            nse_json=[
                {"id": "http-server-header", "output": "ERROR: Script execution failed"},
                {"id": "fingerprint-strings", "output": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"},
            ],
        )
        unrelated_fingerprint["server_observed"] = server_observed(
            unrelated_fingerprint["nse_json"]
        )
        assert unrelated_fingerprint["server_observed"] is False
        counts = ingest(
            db, _scan(db, "server-unrelated-fingerprint"),
            [unrelated_fingerprint], {first["host_ip"]},
        )
        db.refresh(row)
        assert row.server == "uvicorn"
        assert counts["server_changed"] == 0

        observed_absence = parse_xml(_server_xml("&lt;empty&gt;"))[0]
        assert observed_absence["server"] == ""
        assert observed_absence["server_observed"] is True
        assert "<empty>" not in observed_absence["remarks"].lower()
        counts = ingest(db, _scan(db, "server-header-removed"), [observed_absence], {first["host_ip"]})
        db.refresh(row)
        assert row.server == ""
        assert counts["server_changed"] == 1
        event = db.query(FindingEvent).filter_by(finding_id=row.id, type="SERVER_CHANGED").one()
        assert event.detail == "uvicorn → —"
    finally:
        db.close()


def test_old_schema_nse_json_is_backfilled_when_server_column_is_added(tmp_path, monkeypatch):
    legacy_path = tmp_path / "legacy.db"
    legacy_engine = create_engine(f"sqlite:///{legacy_path.as_posix()}", future=True)
    nse_json = json.dumps([
        {"id": "fingerprint-strings", "output": "HTTP/1.1 200 OK\r\nserver: uvicorn\r\n"},
    ])
    with legacy_engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, auth_version INTEGER DEFAULT 0)"
        )
        conn.exec_driver_sql(
            "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, stages_json JSON, "
            "failure_code VARCHAR(64) DEFAULT '', failure_message VARCHAR(256) DEFAULT '')"
        )
        conn.exec_driver_sql(
            "CREATE TABLE findings ("
            "id INTEGER PRIMARY KEY, service VARCHAR(64) DEFAULT '', nse_json JSON, "
            "status VARCHAR(16) DEFAULT '미조치', owner VARCHAR(128) DEFAULT '', "
            "reopened INTEGER DEFAULT 0)"
        )
        conn.exec_driver_sql(
            "INSERT INTO findings (id, service, nse_json, status, owner, reopened) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (1, "apple-iphoto", nse_json, "처리중", "김담당", 0),
        )

    monkeypatch.setattr(db_module, "_engine", legacy_engine)
    db_module._migrate()
    db_module._migrate()  # 재시작 시에도 기존 백필 값을 건드리지 않아야 한다.

    with legacy_engine.connect() as conn:
        columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(findings)")}
        row = conn.exec_driver_sql(
            "SELECT service, server, status, owner FROM findings WHERE id=1"
        ).one()
    legacy_engine.dispose()

    assert "server" in columns
    assert tuple(row) == ("apple-iphoto", "uvicorn", "처리중", "김담당")
