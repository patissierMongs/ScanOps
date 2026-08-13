"""상태 근거(nmap --reason) 해석 — 추정을 확인처럼 말하지 않는지."""
from pathlib import Path

from scanops.db import SessionLocal, init_db
from scanops.models import Finding, ScanRun
from scanops.observation import (CONFIRMED, INFERRED, OTHER, UNOBSERVED,
                                 is_confirmed_open, needs_confirmation, state_evidence)
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import parse_xml, up_hosts

XML = "tests/fixtures/sample_scan.xml"


def test_response_backed_reasons_are_confirmation():
    for reason in ("syn-ack", "udp-response", "localhost-response", "tcp-response"):
        assert state_evidence(reason) == CONFIRMED, reason


def test_silence_is_inference_not_confirmation():
    assert state_evidence("no-response") == INFERRED
    assert is_confirmed_open("open", "no-response") is False


def test_missing_reason_is_unobserved_and_never_reads_as_silence():
    """reason 컬럼 이전 행. '기록하지 않았다'와 '응답이 없었다'는 다른 사실이다."""
    assert state_evidence("") == UNOBSERVED
    assert state_evidence(None) == UNOBSERVED
    # 과거 데이터 전체가 재확인 대상이 되면 안 된다.
    assert needs_confirmation("open", "") is False


def test_unknown_reason_is_not_guessed_either_way():
    """nmap 의 reason 목록은 버전마다 늘어난다 — 모르는 값을 확인으로 넘겨짚지 않는다."""
    assert state_evidence("some-future-reason") == OTHER
    assert is_confirmed_open("open", "some-future-reason") is False


def test_open_filtered_is_never_confirmed_however_it_was_reasoned():
    """nmap 이 열림과 필터를 가르지 못한 상태다 — 근거가 무엇이든 확인이 아니다."""
    assert is_confirmed_open("open|filtered", "no-response") is False
    assert needs_confirmation("open|filtered", "no-response") is True


def test_finding_rows_expose_the_evidence_through_the_real_ingest_path():
    """실제 XML → parse_xml → ingest → Finding 속성까지 이어지는지."""
    init_db()
    db = SessionLocal()
    try:
        scan = ScanRun(name="t", status="done")
        db.add(scan)
        db.commit()
        ingest(db, scan.id, parse_xml(XML), up_hosts(XML))

        rows = db.query(Finding).all()
        assert rows and all(r.state_evidence == CONFIRMED for r in rows)
        assert not any(r.needs_confirmation for r in rows)
    finally:
        db.close()


def test_api_serves_the_evidence_so_it_is_not_write_only(client):
    """저장만 하고 안 쓰면 이 작업의 목적 자체가 없어진다 — 응답에 실제로 실리는지."""
    from tests.conftest import make_user, token_for

    make_user("obs-auditor", "pw", role="auditor")
    headers = {"Authorization": f"Bearer {token_for(client, 'obs-auditor', 'pw')}"}
    with open(XML, "rb") as source:
        client.post("/api/scans/import", headers=headers,
                    files={"file": ("sample_scan.xml", source, "text/xml")})

    body = client.get("/api/findings", headers=headers).json()
    items = body["items"] if isinstance(body, dict) else body
    assert items, "임포트된 발견이 있어야 한다"
    assert all(item["reason"] == "syn-ack" for item in items)
    assert all(item["state_evidence"] == CONFIRMED for item in items)
    assert all(item["needs_confirmation"] is False for item in items)
