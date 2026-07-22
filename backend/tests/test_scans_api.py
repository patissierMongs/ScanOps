"""Phase C(API) 검증 — XML 가져오기 → 발견 목록 → 운영상태 변경 + 이력."""
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _scan_xml(start: int, scaninfo: str, ports: str, host: str = "127.0.0.1") -> bytes:
    return f"""<?xml version="1.0"?>
<nmaprun start="{start}">
  {scaninfo}
  <host>
    <status state="up"/>
    <address addr="{host}" addrtype="ipv4"/>
    <ports>
      {ports}
    </ports>
  </host>
</nmaprun>
""".encode()


def _port(proto: str, port: int, state: str = "open", service: str = "svc") -> str:
    return (
        f'<port protocol="{proto}" portid="{port}">'
        f'<state state="{state}"/>'
        f'<service name="{service}" method="table" conf="3"/>'
        "</port>"
    )


def _auth(client, role="auditor"):
    make_user("op", "pw", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def test_import_creates_findings(client):
    h = _auth(client)
    with open(XML, "rb") as f:
        r = client.post("/api/scans/import", headers=h,
                        files={"file": ("sample.xml", f, "text/xml")})
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["new"] == 13
    r2 = client.get("/api/findings", headers=h)
    assert r2.status_code == 200 and len(r2.json()) == 13


def test_viewer_cannot_import(client):
    h = _auth(client, role="viewer")
    with open(XML, "rb") as f:
        r = client.post("/api/scans/import", headers=h,
                        files={"file": ("sample.xml", f, "text/xml")})
    assert r.status_code == 403


def test_patch_finding_lifecycle_and_events(client):
    h = _auth(client)
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    fid = client.get("/api/findings", headers=h).json()[0]["id"]

    r = client.patch(f"/api/findings/{fid}", headers=h,
                     json={"status": "처리중", "deadline": "2026-07-01T00:00:00"})
    assert r.status_code == 200 and r.json()["status"] == "처리중"

    ev = client.get(f"/api/findings/{fid}/events", headers=h).json()
    types = {e["type"] for e in ev}
    assert "NEW_OPEN" in types and "STATUS_CHANGE" in types and "DEADLINE" in types


def test_reimport_verifies_closure(client):
    """마감 걸린 발견이 재스캔에서 사라지면 정상처리로 자동 확인."""
    h = _auth(client)
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    # 135 포트에 마감 설정
    findings = client.get("/api/findings", headers=h).json()
    f135 = next(x for x in findings if x["port"] == 135)
    client.patch(f"/api/findings/{f135['id']}", headers=h,
                 json={"status": "처리중", "deadline": "2026-07-01T00:00:00"})

    # 135 를 뺀 XML 로 재가져오기
    import xml.etree.ElementTree as ET
    tree = ET.parse(XML)
    root = tree.getroot()
    for host in root.findall("host"):
        ports = host.find("ports")
        for p in ports.findall("port"):
            if p.get("portid") == "135":
                ports.remove(p)
    blob = ET.tostring(root)
    r = client.post("/api/scans/import", headers=h, files={"file": ("s2.xml", blob, "text/xml")})
    assert r.json()["counts"]["closed"] == 1
    closed = client.get(f"/api/findings/{f135['id']}", headers=h).json()
    assert closed["state"] == "closed" and closed["status"] == "정상처리"


def test_run_scan_auto_records_workflow_state(client, monkeypatch):
    from scanops.api import scans as scans_api
    from scanops.scanning import chunker

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    # 자동 워크플로는 관리자 권한을 전제하므로 테스트에선 특권 환경을 가정한다.
    monkeypatch.setattr(scans_api.nmap_runner, "is_admin", lambda: True)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    r = client.post("/api/scans/run", headers=h, json={
        "name": "auto",
        "workflow": "auto",
        "targets": ["127.0.0.1"],
        "batch_size": 1,
    })

    assert r.status_code == 200, r.text
    out = r.json()
    assert out["command"].startswith("자동 스캔")
    state = chunker.read_state(scans_api._basename(out["id"]))
    assert state["workflow"] == "auto"
    assert state["nse"] == []
    assert state["batches"] == [["127.0.0.1"]]


def test_run_scan_auto_blocked_without_admin(client, monkeypatch):
    """비특권이면 자동 스캔은 관리자 권한 안내와 함께 거절(반쪽짜리 -sT 발견 방지)."""
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.nmap_runner, "is_admin", lambda: False)
    r = client.post("/api/scans/run", headers=h, json={
        "name": "auto", "workflow": "auto", "targets": ["127.0.0.1"], "batch_size": 1,
    })
    assert r.status_code == 400
    assert "관리자 권한" in r.json()["detail"]


def test_scan_failure_reason_is_traceable(client, tmp_path):
    """실패 원인 추적성 — 단계 로그의 nmap 오류를 원인으로 뽑아 ScanRun.error 에 남기고 API 로 노출."""
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun

    h = _auth(client)
    db = SessionLocal()
    scan = ScanRun(name="fail", status="running")
    db.add(scan)
    db.commit()
    sid = scan.id
    db.close()

    # nmap stderr 스타일 로그 → 원인 추출(오류 줄 우선) + 종료코드 포함.
    log = tmp_path / "stage.log"
    log.write_text(
        "Starting Nmap 7.94 ( https://nmap.org )\n"
        "QUITTING! You requested a scan type which requires root privileges.\n",
        encoding="utf-8",
    )
    reason = scans_api._stage_reason("TCP 발견", 1, log)
    assert "QUITTING" in reason and "종료코드 1" in reason and "TCP 발견" in reason

    scans_api._mark(sid, "failed", reason)
    out = client.get(f"/api/scans/{sid}", headers=h).json()
    assert out["status"] == "failed"
    assert "QUITTING" in out["error"]          # API(ScanOut)로 원인 노출

    # 성공/취소로 다시 마킹하면 원인은 비워진다(잔재 방지).
    scans_api._mark(sid, "done")
    assert client.get(f"/api/scans/{sid}", headers=h).json()["error"] == ""


def test_log_tail_prefers_error_lines(tmp_path):
    from scanops.api import scans as scans_api
    log = tmp_path / "l.log"
    log.write_text("\n".join([
        "Starting Nmap", "Scanning 10.0.0.1", "Nmap scan report for 10.0.0.1",
        "Failed to resolve \"badhost\".", "line", "another",
    ]), encoding="utf-8")
    tail = scans_api._log_tail(log)
    assert "Failed to resolve" in tail          # 오류 줄이 마지막 평범한 줄보다 우선


def test_advance_cursor_does_not_clobber_concurrent_stop(tmp_path):
    """커서 전진이 그 사이 들어온 stop 을 덮어쓰지 않는다(중지 유실 레이스 수정).
    stale in-memory state 로 호출해도 fresh 재읽기로 stop 을 감지해 전진하지 않고 stop 을 보존."""
    from scanops.api import scans as scans_api
    from scanops.scanning import chunker

    base = tmp_path / "scan_9"
    chunker.write_state(base, {"batches": [["a"], ["b"]], "cursor": 0, "stop": False, "active_seconds": 0})

    st = chunker.read_state(base)
    assert scans_api._advance_cursor(base, st, 0, 1.0) is True     # 정상 전진
    assert chunker.read_state(base)["cursor"] == 1

    # 그 사이 stop 이 디스크에 반영됨 — 워커는 아직 stale st(stop=False)를 들고 있음.
    disk = chunker.read_state(base)
    disk["stop"] = True
    chunker.write_state(base, disk)
    stale = {"batches": [["a"], ["b"]], "cursor": 1, "stop": False, "active_seconds": 1.0}

    assert scans_api._advance_cursor(base, stale, 1, 1.0) is False  # 전진 거부
    after = chunker.read_state(base)
    assert after["stop"] is True                                   # stop 유실 안 됨
    assert after["cursor"] == 1                                    # 커서 안 밀림


def test_auto_batch_parallelizes_tcp_and_udp_identify(monkeypatch, tmp_path):
    """발견 이후 tcp_identify 와 udp_identify 가 동시(병렬)에 돈다 — 두 구간이 시간상 겹친다."""
    import time
    from pathlib import Path
    from scanops.api import scans as scans_api

    monkeypatch.setattr(scans_api.chunker, "read_state", lambda base: {})          # stop 없음
    monkeypatch.setattr(scans_api, "up_hosts", lambda x: {"10.0.0.5"})
    monkeypatch.setattr(scans_api, "parse_xml", lambda x: [])
    monkeypatch.setattr(scans_api, "_set_current_log", lambda sid, log: None)
    monkeypatch.setattr(scans_api, "_ingest_auto_findings", lambda *a, **k: None)
    monkeypatch.setattr(scans_api.nmap_runner, "open_ports_from_xml",
                        lambda p, protocol="tcp": [80] if str(p).endswith("tcp_discovery.xml") else [])

    intervals: dict = {}

    def fake_run_stage(sid, argv, log, set_current=True):
        s = str(log)
        stage = "discovery" if ".tcp_discovery." in s else ("tcp" if ".tcp_identify." in s else "udp")
        t0 = time.monotonic()
        Path(s[:-4] + ".xml").write_bytes(b"<nmaprun/>")   # .exists() 통과용
        time.sleep(0.15)
        intervals[stage] = (t0, time.monotonic())
        return 0

    monkeypatch.setattr(scans_api, "_run_stage", fake_run_stage)

    ok = scans_api._run_auto_batch(4242, "nmap", ["10.0.0.5"], tmp_path / "scan_4242.b0",
                                   {"ports": "", "nse": []})
    assert ok is True
    assert {"discovery", "tcp", "udp"} <= set(intervals)              # 세 단계 모두 실행
    assert intervals["discovery"][1] <= intervals["tcp"][0]           # 발견은 식별보다 먼저 끝남
    tcp_s, tcp_e = intervals["tcp"]
    udp_s, udp_e = intervals["udp"]
    assert tcp_s < udp_e and udp_s < tcp_e                            # tcp ∥ udp 구간 겹침(병렬)


def test_import_bundle_preserves_discovery_and_scopes_closure(client):
    h = _auth(client)
    initial = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>',
        _port("tcp", 22, service="ssh") + _port("tcp", 80, service="http"),
    )
    assert client.post("/api/scans/import", headers=h, files={"file": ("initial.xml", initial, "text/xml")}).status_code == 200

    discovery = _scan_xml(
        1782050100,
        '<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>',
        _port("tcp", 22, service="ssh"),
    )
    identify_empty = b"""<?xml version="1.0"?>
<nmaprun start="1782050101">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
  <runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""
    udp = _scan_xml(
        1782050102,
        '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>',
        _port("udp", 53, state="open|filtered", service="domain"),
    )

    r = client.post(
        "/api/scans/import-bundle",
        headers=h,
        files=[
            ("files", ("scan_20260621_1.tcp_discovery.xml", discovery, "text/xml")),
            ("files", ("scan_20260621_1.tcp_identify.xml", identify_empty, "text/xml")),
            ("files", ("scan_20260621_1.udp_identify.xml", udp, "text/xml")),
        ],
    )
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 1
    assert r.json()["counts"]["closed"] == 1

    findings = client.get("/api/findings?state=", headers=h).json()
    by_port = {(f["proto"], f["port"]): f for f in findings}
    assert by_port[("tcp", 22)]["state"] == "open"
    assert by_port[("tcp", 80)]["state"] == "closed"
    assert by_port[("udp", 53)]["state"] == "open|filtered"

    heat = client.get("/api/heatmap", headers=h).json()
    row80 = next(r for r in heat["rows"] if r["host_ip"] == "127.0.0.1" and r["port"] == 80)
    assert row80["current_state"] == "신규닫힘"


def test_udp_stage_import_does_not_close_existing_tcp(client):
    h = _auth(client)
    initial = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>',
        _port("tcp", 22, service="ssh"),
    )
    assert client.post("/api/scans/import", headers=h, files={"file": ("initial.xml", initial, "text/xml")}).status_code == 200
    udp = _scan_xml(
        1782050100,
        '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>',
        _port("udp", 53, state="open|filtered", service="domain"),
    )
    r = client.post("/api/scans/import", headers=h, files={"file": ("scan_a.udp_identify.xml", udp, "text/xml")})
    assert r.status_code == 200, r.text

    findings = client.get("/api/findings?state=", headers=h).json()
    by_port = {(f["proto"], f["port"]): f for f in findings}
    assert by_port[("tcp", 22)]["state"] == "open"
    assert by_port[("udp", 53)]["state"] == "open|filtered"
