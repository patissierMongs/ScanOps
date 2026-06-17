"""실제 nmap(WSL, --open 미사용) XML 회귀 — 열린 포트만 인입 + 닫힘=부재 검증."""
from scanops.db import SessionLocal, init_db
from scanops.models import Finding, FindingEvent, ScanRun
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import parse_xml, up_hosts

A = "tests/fixtures/scanA.xml"
B = "tests/fixtures/scanB.xml"


def test_only_open_ports_ingested():
    fs = parse_xml(A)
    # scanA 는 22/80/443/3306 closed + 3000/8080/9000 open. 열린 3개만.
    assert sorted(f["port"] for f in fs) == [3000, 8080, 9000]
    assert all(f["state"].startswith("open") for f in fs)


def test_closure_by_absence_with_real_scans():
    init_db()
    db = SessionLocal()
    try:
        s1 = ScanRun(name="A", status="done"); db.add(s1); db.commit()
        ingest(db, s1.id, parse_xml(A), up_hosts(A))
        # 3000 에 마감 배정
        f3000 = db.query(Finding).filter_by(port=3000).first()
        f3000.status = "처리중"
        db.commit()

        s2 = ScanRun(name="B", status="done"); db.add(s2); db.commit()
        counts = ingest(db, s2.id, parse_xml(B), up_hosts(B))

        # 3000 은 scanB 에서 부재 → 닫힘 + 조치 자동확인(정상처리)
        assert counts["closed"] == 1
        assert counts["reopened"] == 0  # 닫힌 포트 오집계 없음(회귀)
        f3000 = db.query(Finding).filter_by(port=3000).first()
        assert f3000.state == "closed" and f3000.status == "정상처리"
        ev = {e.type for e in db.query(FindingEvent).filter_by(finding_id=f3000.id)}
        assert "CLOSED" in ev
    finally:
        db.close()
