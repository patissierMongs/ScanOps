"""Phase C 검증 — 파싱 + 안정키 upsert + diff 이벤트(핵심 차별점)."""
from datetime import datetime, timezone

from scanops.db import SessionLocal, init_db
from scanops.models import Finding, FindingEvent, ScanRun
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import parse_xml, up_hosts

XML = "tests/fixtures/sample_scan.xml"


def _scan(db) -> int:
    s = ScanRun(name="t", status="done")
    db.add(s)
    db.commit()
    return s.id


def test_parse_basic():
    fs = parse_xml(XML)
    assert len(fs) == 13
    ssh = next(f for f in fs if f["port"] == 22)
    assert ssh["service"] == "ssh" and ssh["identification"] == "확인"
    # method="table" 인 포트는 '추측'
    assert any(f["identification"] == "추측" for f in fs)
    # NSE 핵심줄 추출(ssl-cert CN)
    assert any("CN=" in f["remarks"] for f in fs)


def test_reason_is_parsed_and_stored_because_we_already_pay_for_it():
    """--reason 은 모든 단계에 이미 붙어 있는데 여태 파서가 버리고 있었다.

    'open' 안에서도 syn-ack(응답을 받아 확인)과 no-response(안 받고 추정)는 증거 강도가
    전혀 다르다. 이 구분이 open|filtered 를 정직하게 표시하기 위한 최소 재료다.
    """
    init_db()
    db = SessionLocal()
    try:
        parsed = parse_xml(XML)
        assert all("reason" in f for f in parsed)
        assert {f["reason"] for f in parsed} == {"syn-ack"}, "픽스처는 전부 syn-ack 이다"

        sid = _scan(db)
        ingest(db, sid, parsed, up_hosts(XML))

        assert db.query(Finding).filter(Finding.reason == "syn-ack").count() == 13
    finally:
        db.close()


def test_sweep_only_rescan_updates_reason_with_state_not_leaving_it_stale():
    """개방 여부의 권위가 sweep 이면 그렇게 판단한 근거도 sweep 의 것이다.

    reason 을 state 와 떼어 두면 state 는 새 관측인데 reason 은 옛 관측인 행이 만들어진다.
    """
    init_db()
    db = SessionLocal()
    try:
        sid = _scan(db)
        ingest(db, sid, parse_xml(XML), up_hosts(XML))
        row = db.query(Finding).filter_by(port=22).one()
        assert row.reason == "syn-ack"
        before_service = row.service

        # sweep-only 재관측: 개방은 확인했지만 식별은 안 했다(identity_observed=False).
        sweep = [f for f in parse_xml(XML) if f["port"] == 22]
        for f in sweep:
            f["identity_observed"] = False
            f["reason"] = "syn-ack"
            f["service"] = ""          # 식별 결과가 없다 — 기존 값이 보존돼야 한다
        ingest(db, _scan(db), sweep, up_hosts(XML))

        row = db.query(Finding).filter_by(port=22).one()
        assert row.reason == "syn-ack"          # 근거가 state 와 함께 갱신됨
        assert row.service == before_service    # 식별은 여전히 보존됨
    finally:
        db.close()


def test_first_scan_all_new():
    init_db()
    db = SessionLocal()
    try:
        sid = _scan(db)
        counts = ingest(db, sid, parse_xml(XML), up_hosts(XML))
        assert counts["new"] == 13
        assert db.query(Finding).count() == 13
        assert db.query(FindingEvent).filter_by(type="NEW_OPEN").count() == 13
    finally:
        db.close()


def test_rescan_detects_change_and_close():
    init_db()
    db = SessionLocal()
    try:
        s1 = _scan(db)
        fs = parse_xml(XML)
        ingest(db, s1, fs, up_hosts(XML))

        # 2차 스캔 시뮬레이션: 22번 서비스 변경 + 135번 사라짐(닫힘)
        fs2 = [dict(f) for f in fs if f["port"] != 135]
        for f in fs2:
            if f["port"] == 22:
                f["service"] = "openssh-mod"
        s2 = _scan(db)
        counts = ingest(db, s2, fs2, {"127.0.0.1"})

        assert counts["service_changed"] == 1
        assert counts["closed"] == 1
        assert db.query(FindingEvent).filter_by(type="SERVICE_CHANGED").count() == 1
        closed = db.query(Finding).filter_by(port=135).first()
        assert closed.state == "closed" and closed.status == "정상처리"
    finally:
        db.close()


def test_reopen_marks_recurrence():
    init_db()
    db = SessionLocal()
    try:
        fs = parse_xml(XML)
        s1 = _scan(db)
        ingest(db, s1, fs, up_hosts(XML))
        # 135 닫힘
        s2 = _scan(db)
        ingest(db, s2, [f for f in fs if f["port"] != 135], {"127.0.0.1"})
        # 135 다시 열림 → REOPENED. 재발은 별도 상태가 아니라 태그(reopened=1) + 미조치로 복귀.
        s3 = _scan(db)
        counts = ingest(db, s3, fs, {"127.0.0.1"})
        assert counts["reopened"] == 1
        row = db.query(Finding).filter_by(port=135).first()
        assert row.state == "open" and row.status == "미조치" and row.reopened == 1
    finally:
        db.close()


def test_legacy_reopen_status_migrated():
    """기존 DB의 '재발' 상태 → 미조치 + reopened 태그로 전환(경량 마이그레이션)."""
    from scanops.db import _migrate
    init_db()
    db = SessionLocal()
    try:
        row = Finding(finding_key="1.1.1.1|22|tcp", host_ip="1.1.1.1", port=22,
                      proto="tcp", state="open", status="재발", reopened=0)
        db.add(row)
        db.commit()
        rid = row.id
    finally:
        db.close()
    _migrate()
    db = SessionLocal()
    try:
        row = db.get(Finding, rid)
        assert row.status == "미조치" and row.reopened == 1
    finally:
        db.close()


def test_empty_scope_keys_disables_closure():
    """직접 명령(no_close)처럼 scope_keys=set() 면 미스캔 포트를 닫지 않는다."""
    init_db()
    db = SessionLocal()
    try:
        fs = parse_xml(XML)
        s1 = _scan(db)
        ingest(db, s1, fs, up_hosts(XML))
        open_before = db.query(Finding).filter_by(state="open").count()
        # 같은 호스트를 '포트 없음'으로 재인입하되 scope_keys=set() → 아무것도 닫히면 안 됨
        s2 = _scan(db)
        counts = ingest(db, s2, [], {"127.0.0.1"}, scope_keys=set())
        assert counts["closed"] == 0
        assert db.query(Finding).filter_by(state="open").count() == open_before
    finally:
        db.close()


def test_open_filtered_is_active_not_reopened_and_can_close():
    init_db()
    db = SessionLocal()
    try:
        finding = dict(parse_xml(XML)[0])
        finding["state"] = "open|filtered"
        s1 = _scan(db)
        ingest(db, s1, [finding], {finding["host_ip"]})

        s2 = _scan(db)
        counts = ingest(db, s2, [finding], {finding["host_ip"]})
        assert counts["reopened"] == 0

        s3 = _scan(db)
        counts = ingest(
            db, s3, [], {finding["host_ip"]},
            scope_keys={f"{finding['host_ip']}|{finding['port']}|{finding['proto']}"},
        )
        assert counts["closed"] == 1
    finally:
        db.close()


def test_stale_absence_does_not_close_or_rewrite_current_open_finding():
    init_db()
    db = SessionLocal()
    try:
        finding = dict(parse_xml(XML)[0])
        host = finding["host_ip"]
        key = f"{host}|{finding['port']}|{finding['proto']}"
        current_when = datetime(2026, 7, 29, 9, tzinfo=timezone.utc)
        stale_when = datetime(2025, 7, 29, 9, tzinfo=timezone.utc)

        current_scan = _scan(db)
        ingest(db, current_scan, [finding], {host}, scan_date=current_when)
        row = db.query(Finding).filter_by(finding_key=key).one()
        row.status = "처리중"
        row.reopened = 1
        db.commit()
        db.expire_all()  # SQLite reloads DateTime without tzinfo; comparison must remain safe.
        before_events = db.query(FindingEvent).count()

        stale_scan = _scan(db)
        counts = ingest(
            db, stale_scan, [], {host}, scope_keys={key}, scan_date=stale_when,
        )
        row = db.query(Finding).filter_by(finding_key=key).one()

        assert counts == {
            "new": 0, "reopened": 0, "service_changed": 0,
            "version_changed": 0, "server_changed": 0, "unchanged": 0, "closed": 0,
        }
        assert row.state == finding["state"]
        assert row.status == "처리중" and row.reopened == 1
        assert row.last_scan_id == current_scan
        assert row.last_seen == current_when.replace(tzinfo=None)
        assert db.query(FindingEvent).count() == before_events
    finally:
        db.close()


def test_stale_open_only_backfills_first_seen_without_reopening_or_overlaying_identity():
    init_db()
    db = SessionLocal()
    try:
        finding = dict(parse_xml(XML)[0])
        host = finding["host_ip"]
        key = f"{host}|{finding['port']}|{finding['proto']}"
        first_when = datetime(2025, 7, 29, 9, tzinfo=timezone.utc)
        closed_when = datetime(2026, 7, 29, 9, tzinfo=timezone.utc)
        stale_when = datetime(2024, 7, 29, 9, tzinfo=timezone.utc)

        first_scan = _scan(db)
        ingest(db, first_scan, [finding], {host}, scan_date=first_when)
        closed_scan = _scan(db)
        ingest(db, closed_scan, [], {host}, scope_keys={key}, scan_date=closed_when)
        db.expire_all()
        before_events = db.query(FindingEvent).count()

        stale = dict(finding)
        stale.update({
            "service": "stale-service", "version": "0.1", "server": "stale-server",
            "server_observed": True,
        })
        stale_scan = _scan(db)
        counts = ingest(db, stale_scan, [stale], {host}, scan_date=stale_when)
        row = db.query(Finding).filter_by(finding_key=key).one()

        assert all(value == 0 for value in counts.values())
        assert row.state == "closed" and row.status == "정상처리" and row.reopened == 0
        assert (row.service, row.version, row.server) == (
            finding["service"], finding["version"], finding.get("server", ""),
        )
        assert row.last_scan_id == closed_scan
        assert row.last_seen == closed_when.replace(tzinfo=None)
        assert row.first_scan_id == stale_scan
        assert row.first_seen == stale_when.replace(tzinfo=None)
        assert db.query(FindingEvent).count() == before_events
    finally:
        db.close()


def test_chronological_close_and_reopen_still_update_current_state():
    init_db()
    db = SessionLocal()
    try:
        finding = dict(parse_xml(XML)[0])
        host = finding["host_ip"]
        key = f"{host}|{finding['port']}|{finding['proto']}"
        times = [datetime(year, 1, 1, tzinfo=timezone.utc) for year in (2024, 2025, 2026)]

        opened_scan = _scan(db)
        ingest(db, opened_scan, [finding], {host}, scan_date=times[0])
        closed_scan = _scan(db)
        closed = ingest(db, closed_scan, [], {host}, scope_keys={key}, scan_date=times[1])
        reopened_scan = _scan(db)
        reopened = ingest(db, reopened_scan, [finding], {host}, scan_date=times[2])
        row = db.query(Finding).filter_by(finding_key=key).one()

        assert closed["closed"] == 1 and reopened["reopened"] == 1
        assert row.state == finding["state"] and row.reopened == 1
        assert row.last_scan_id == reopened_scan
        assert row.last_seen == times[2].replace(tzinfo=None)
        event_types = [event.type for event in db.query(FindingEvent).order_by(FindingEvent.id)]
        assert event_types == ["NEW_OPEN", "CLOSED", "REOPENED"]
    finally:
        db.close()


def test_two_workers_ingesting_the_same_new_endpoint_do_not_collide(monkeypatch):
    import threading
    import time as time_module

    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal, init_db
    from scanops.models import Finding, FindingEvent, ScanRun
    from scanops.scanning import ingest as ingest_module

    init_db()
    db = SessionLocal()
    try:
        a = ScanRun(name="a", targets="10.9.9.9", status="running", created_by=None)
        b = ScanRun(name="b", targets="10.9.9.9", status="running", created_by=None)
        db.add_all([a, b])
        db.commit()
        ids = (a.id, b.id)
    finally:
        db.close()

    real_identity = ingest_module.display_identity

    def slow_identity(**kwargs):
        time_module.sleep(0.3)
        return real_identity(**kwargs)

    monkeypatch.setattr(ingest_module, "display_identity", slow_identity)
    finding = {
        "host_ip": "10.9.9.9", "hostname": "", "port": 4444, "proto": "tcp", "state": "open",
        "reason": "syn-ack", "service": "http", "product": "", "version": "", "server": "",
        "banner": "", "cpe": "", "rtt": 0.0, "identification": "확인", "nse_json": None,
        "remarks": "",
    }
    errors: list = []

    def worker(scan_id):
        try:
            scans_api._ingest_auto_findings(
                scan_id, [dict(finding)], {"10.9.9.9"}, {4444}, set(),
                closure_hosts={"10.9.9.9"},
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == [], errors
    db = SessionLocal()
    try:
        rows = db.query(Finding).filter(Finding.finding_key == "10.9.9.9|4444|tcp").all()
        assert len(rows) == 1
        opened = db.query(FindingEvent).filter(
            FindingEvent.finding_id == rows[0].id, FindingEvent.type == "NEW_OPEN").count()
        assert opened == 1
    finally:
        db.close()
