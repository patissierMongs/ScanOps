"""상태 근거(nmap --reason) 해석 — 추정을 확인처럼 말하지 않는지."""
from pathlib import Path

from scanops.db import SessionLocal, init_db
from scanops.models import Finding, ScanRun
from scanops.observation import (ABSENT, CONFIRMED, INFERRED, OTHER, UNOBSERVED,
                                 is_confirmed_open, needs_confirmation, state_evidence)
from scanops.scanning.ingest import ingest
from scanops.scanning.nmap_parse import parse_xml, up_hosts

XML = "tests/fixtures/sample_scan.xml"


def test_response_backed_reasons_are_confirmation():
    for reason in ("syn-ack", "udp-response", "localhost-response", "tcp-response"):
        assert state_evidence("open", reason) == CONFIRMED, reason


def test_silence_is_inference_not_confirmation():
    assert state_evidence("open", "no-response") == INFERRED
    assert is_confirmed_open("open", "no-response") is False


def test_missing_reason_is_unobserved_and_never_reads_as_silence():
    """reason 컬럼 이전 행. '기록하지 않았다'와 '응답이 없었다'는 다른 사실이다."""
    assert state_evidence("open", "") == UNOBSERVED
    assert state_evidence("open", None) == UNOBSERVED
    # 과거 데이터 전체가 재확인 대상이 되면 안 된다.
    assert needs_confirmation("open", "") is False


def test_unknown_reason_is_not_guessed_either_way():
    """nmap 의 reason 목록은 버전마다 늘어난다 — 모르는 값을 확인으로 넘겨짚지 않는다."""
    assert state_evidence("open", "some-future-reason") == OTHER
    assert is_confirmed_open("open", "some-future-reason") is False


def test_a_closed_row_never_reuses_the_open_reason_as_its_own_evidence():
    """부재로 닫힌 행은 열려 있던 시절의 syn-ack 을 그대로 갖고 있다.

    reason 만 보고 판정하면 '닫힘을 응답으로 확인했다'고 말하게 된다 — 이 이슈가 내내
    고쳐 온 오류와 같은 형태다. 부재 판정은 능동 관측이 아니다.
    """
    assert state_evidence("closed", "syn-ack") == ABSENT
    assert state_evidence("closed", "") == ABSENT
    assert needs_confirmation("closed", "syn-ack") is False
    # 닫힘을 실제로 응답으로 확인한 경우만 '확인'이다.
    assert state_evidence("closed", "conn-refused") == CONFIRMED


def test_absence_closure_through_the_real_ingest_does_not_claim_confirmation():
    """리뷰가 재현한 전이 그대로 — open/syn-ack → scope 내 부재 → closed."""
    init_db()
    db = SessionLocal()
    try:
        first = ScanRun(name="open", status="done")
        db.add(first)
        db.commit()
        parsed = parse_xml(XML)
        ingest(db, first.id, parsed, up_hosts(XML))
        row = db.query(Finding).filter_by(port=22).one()
        assert row.state == "open" and row.reason == "syn-ack"

        # 다음 완결 스캔에서 같은 scope key 가 부재 → 닫힘
        second = ScanRun(name="absent", status="done")
        db.add(second)
        db.commit()
        ingest(db, second.id, [], up_hosts(XML), scope_keys={row.finding_key})

        row = db.query(Finding).filter_by(port=22).one()
        assert row.state == "closed"
        assert row.reason == "syn-ack"              # 마지막 관측의 근거는 기록으로 남되
        assert row.state_evidence == ABSENT         # 현재 상태의 근거로는 쓰이지 않는다
        assert row.needs_confirmation is False
    finally:
        db.close()


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


def test_saved_audit_xml_round_trips_the_reason_instead_of_dropping_it():
    """자동/staged 스캔이 남기는 감사 XML 왕복 — 화면엔 있는 근거가 파일에선 사라지면 안 된다.

    이 산출물은 다운로드·재인입되는 증거 파일이다. reason 을 빠뜨리면 같은 발견이
    파일에서만 '미관측'으로 조용히 바뀐다.
    """
    from scanops.api.scans import _write_merged_xml

    init_db()
    db = SessionLocal()
    try:
        scan = ScanRun(name="merged", status="done")
        db.add(scan)
        db.commit()
        findings = [
            {"host_ip": "10.0.0.1", "hostname": "", "port": 22, "proto": "tcp",
             "state": "open", "reason": "syn-ack", "service": "ssh", "product": "",
             "version": "", "banner": "", "cpe": "", "rtt": "", "identification": "확인",
             "nse_json": [], "remarks": ""},
            {"host_ip": "10.0.0.1", "hostname": "", "port": 161, "proto": "udp",
             "state": "open|filtered", "reason": "no-response", "service": "snmp",
             "product": "", "version": "", "banner": "", "cpe": "", "rtt": "",
             "identification": "미확인", "nse_json": [], "remarks": ""},
        ]
        out = Path("tests/_merged_reason_roundtrip.xml")
        try:
            _write_merged_xml(db, out, findings, {"10.0.0.1"}, set())
            reparsed = {(f["port"], f["proto"]): f["reason"] for f in parse_xml(out.read_bytes())}
        finally:
            out.unlink(missing_ok=True)

        assert reparsed[(22, "tcp")] == "syn-ack"
        assert reparsed[(161, "udp")] == "no-response"
    finally:
        db.close()


def test_export_does_not_carry_a_stale_reason_next_to_the_current_state():
    """내보내기의 '근거 원문' 옆에 닫힌 행의 옛 syn-ack 이 남으면 읽는 사람이 둘을 잇는다."""
    from scanops.observation import current_reason

    assert current_reason("closed", "syn-ack") == ""
    assert current_reason("open", "") == ""              # 미관측도 원문이 없다
    assert current_reason("open", "syn-ack") == "syn-ack"
    assert current_reason("closed", "conn-refused") == "conn-refused"
