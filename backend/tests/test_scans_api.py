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
