"""Phase C 검증 — 파싱 + 안정키 upsert + diff 이벤트(핵심 차별점)."""
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
