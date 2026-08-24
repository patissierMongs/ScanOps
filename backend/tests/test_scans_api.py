"""Phase C(API) 검증 — XML 가져오기 → 발견 목록 → 운영상태 변경 + 이력."""
import hashlib
import json

import pytest

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


def test_xml_import_rejects_oversized_upload(client, monkeypatch):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "upload_max_bytes", 32)
    r = client.post(
        "/api/scans/import", headers=h,
        files={"file": ("large.xml", b"<nmaprun>" + b" " * 64 + b"</nmaprun>", "text/xml")},
    )
    assert r.status_code == 413
    assert "32 bytes" in r.json()["detail"]


def test_xml_bundle_rejects_oversized_total(client, monkeypatch):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "upload_max_bytes", 100)
    monkeypatch.setattr(scans_api._settings, "upload_bundle_max_bytes", 50)
    r = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", ("a.xml", b"<nmaprun>" + b" " * 20 + b"</nmaprun>", "text/xml")),
        ("files", ("b.xml", b"<nmaprun>" + b" " * 20 + b"</nmaprun>", "text/xml")),
    ])
    assert r.status_code == 413


def test_malformed_single_xml_is_stable_400_without_persistent_artifacts(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import AuditLog, Finding, ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    malformed = b"<nmaprun><broken>"

    single = client.post(
        "/api/scans/import", headers=h,
        files={"file": (r"C:\private\secret.xml", malformed, "text/xml")},
    )
    bundled = client.post(
        "/api/scans/import-bundle", headers=h,
        files=[("files", ("broken.xml", malformed, "text/xml"))],
    )

    expected = "XML 파싱 실패: XML 형식이 올바르지 않습니다."
    assert single.status_code == bundled.status_code == 400
    assert single.json()["detail"] == bundled.json()["detail"] == expected
    assert "private" not in single.text.lower() and "parseerror" not in single.text.lower()
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == 0
        assert db.query(Finding).count() == 0
        assert db.query(AuditLog).filter_by(action="SCAN_IMPORT", ok=1).count() == 0
        assert db.query(AuditLog).filter_by(action="SCAN_IMPORT", ok=0).count() == 2
    finally:
        db.close()
    scans_dir = tmp_path / "scans"
    assert not scans_dir.exists() or list(scans_dir.iterdir()) == []


def test_malformed_multi_stage_bundle_is_atomic_and_does_not_expose_parser_details(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import AuditLog, Finding, ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    discovery = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>',
        _port("tcp", 443, service="https"),
    )
    malformed = b"<nmaprun><broken>"

    response = client.post(
        "/api/scans/import-bundle", headers=h,
        files=[
            ("files", (r"C:\private\scan_bad.tcp_discovery.xml", discovery, "text/xml")),
            ("files", (r"C:\private\scan_bad.tcp_identify.xml", malformed, "text/xml")),
        ],
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "XML 파싱 실패: XML 형식이 올바르지 않습니다."
    assert "private" not in response.text.lower() and "parseerror" not in response.text.lower()
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == 0
        assert db.query(Finding).count() == 0
        assert db.query(AuditLog).filter_by(action="SCAN_IMPORT", ok=1).count() == 0
        assert db.query(AuditLog).filter_by(action="SCAN_IMPORT", ok=0).count() == 1
    finally:
        db.close()
    scans_dir = tmp_path / "scans"
    assert not scans_dir.exists() or list(scans_dir.iterdir()) == []


def test_bundle_partial_success_hides_unexpected_internal_error_details(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.scans_dir.mkdir(parents=True)
    valid = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>',
        _port("tcp", 443, service="https"),
    )
    real_import = scans_api._import_single_xml

    def import_or_fail(db, user, name, xml_bytes):
        if name == "bad.xml":
            raise RuntimeError(r"C:\private\scan.xml: database failed")
        return real_import(db, user, name, xml_bytes)

    monkeypatch.setattr(scans_api, "_import_single_xml", import_or_fail)
    response = client.post(
        "/api/scans/import-bundle", headers=h,
        files=[
            ("files", ("good.xml", valid, "text/xml")),
            ("files", ("bad.xml", valid, "text/xml")),
        ],
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["imported"] == 1 and payload["failed"] == 1
    assert payload["errors"] == [{"name": "bad.xml", "error": "XML 가져오기에 실패했습니다."}]
    assert "private" not in response.text.lower() and "database failed" not in response.text.lower()


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


def test_patch_finding_can_clear_deadline_and_owner(client):
    h = _auth(client)
    make_user("owner", "ownerpw12", role="auditor")
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    finding = client.get("/api/findings", headers=h).json()[0]
    from scanops.db import SessionLocal
    from scanops.models import User
    db = SessionLocal()
    try:
        owner_id = db.query(User).filter_by(username="owner").one().id
    finally:
        db.close()

    assigned = client.patch(
        f"/api/findings/{finding['id']}", headers=h,
        json={"owner_user_id": owner_id, "deadline": "2026-07-01T00:00:00"},
    )
    assert assigned.status_code == 200
    cleared = client.patch(
        f"/api/findings/{finding['id']}", headers=h,
        json={"owner_user_id": None, "deadline": None},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["owner_user_id"] is None
    assert cleared.json()["deadline"] is None
    details = [e["detail"] for e in client.get(
        f"/api/findings/{finding['id']}/events", headers=h
    ).json()]
    assert "담당자 배정 해제" in details
    assert "마감 해제" in details


def test_patch_finding_rejects_unknown_owner_without_500(client):
    h = _auth(client)
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    fid = client.get("/api/findings", headers=h).json()[0]["id"]
    response = client.patch(f"/api/findings/{fid}", headers=h, json={"owner_user_id": 999999})
    assert response.status_code == 400
    assert "사용자" in response.json()["detail"]


def test_patch_finding_rejects_inactive_owner_and_session_remains_usable(client):
    h = _auth(client)
    make_user("inactive-owner", "ownerpw12", role="auditor")
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    finding = client.get("/api/findings", headers=h).json()[0]

    from scanops.db import SessionLocal
    from scanops.models import User
    db = SessionLocal()
    try:
        owner = db.query(User).filter_by(username="inactive-owner").one()
        owner.is_active = 0
        db.commit()
        owner_id = owner.id
    finally:
        db.close()

    response = client.patch(
        f"/api/findings/{finding['id']}", headers=h, json={"owner_user_id": owner_id},
    )
    assert response.status_code == 400
    assert "비활성" in response.json()["detail"]
    followup = client.get(f"/api/findings/{finding['id']}", headers=h)
    assert followup.status_code == 200
    assert followup.json()["owner_user_id"] is None


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
    assert state["nse"] is None
    assert state["batches"] == [["127.0.0.1"]]


@pytest.mark.parametrize("endpoint", ["/api/scans/run", "/api/scans/run-staged", "/api/scans/estimate"])
@pytest.mark.parametrize("exclude", [
    ["127.0.0.1", "not-an-ip"],
    ["127.0.0.0/99"],
    ["2001:db8::1"],
    ["127.0.0.0/30"],
])
def test_structured_scan_endpoints_reject_invalid_or_all_excluded_before_side_effects(
    client, monkeypatch, endpoint, exclude,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(
        scans_api.nmap_runner, "find_nmap",
        lambda explicit="": (_ for _ in ()).throw(AssertionError("rejected request checked nmap")),
    )
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(AssertionError("rejected request checked engine")),
    )
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rejected request started worker")),
    )

    response = client.post(endpoint, headers=h, json={
        "targets": ["127.0.0.0/30"],
        "exclude": exclude,
        "workflow": "manual",
        "ports": "T:443",
    })

    assert response.status_code == 400, response.text
    assert client.get("/api/scans", headers=h).json() == []


@pytest.mark.parametrize(("options", "detail"), [
    (["syn", "connect"], "SYN"),
    (["connect", "udp"], "UDP"),
])
def test_staged_incompatible_scan_types_are_rejected_before_side_effects(
    client, monkeypatch, options, detail,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(AssertionError("invalid options checked engine")),
    )
    monkeypatch.setattr(
        scans_api.nmap_runner, "find_nmap",
        lambda explicit="": (_ for _ in ()).throw(AssertionError("invalid options checked nmap")),
    )
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid options started worker")),
    )

    response = client.post("/api/scans/run-staged", headers=h, json={
        "targets": ["127.0.0.1"],
        "options": options,
        "ports": "T:443,U:53",
    })

    assert response.status_code == 400, response.text
    assert detail in response.json()["detail"]
    assert client.get("/api/scans", headers=h).json() == []


def test_excludes_are_deduplicated_and_persisted_compact_for_estimate_legacy_and_staged(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api
    from scanops.scanning import chunker

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    body = {
        "targets": ["127.0.0.0/30", "127.0.0.2"],
        "exclude": ["127.0.0.1", "127.0.0.3/32", "127.0.0.1"],
        "workflow": "manual",
        "ports": "T:443",
        "exclude_ports": "2222",
        "options": ["syn"],
        "batch_size": 256,
    }

    estimate = client.post("/api/scans/estimate", headers=h, json=body)
    assert estimate.status_code == 200, estimate.text
    assert estimate.json()["host_count"] == 2
    assert estimate.json()["exclude"] == ["127.0.0.1", "127.0.0.3"]

    legacy = client.post("/api/scans/run", headers=h, json=body)
    assert legacy.status_code == 200, legacy.text
    state = chunker.read_state(scans_api._basename(legacy.json()["id"]))
    assert state["batches"] == [["127.0.0.0", "127.0.0.2"]]
    assert state["exclude"] == ["127.0.0.1", "127.0.0.3"]

    staged = client.post("/api/scans/run-staged", headers=h, json={**body, "discovery": "pn"})
    assert staged.status_code == 200, staged.text
    spec_path = scans_api._settings.scans_dir / f"scan_{staged.json()['id']}" / "spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert spec["targets"] == ["127.0.0.0", "127.0.0.2"]
    assert spec["exclude"] == ["127.0.0.1", "127.0.0.3"]
    assert spec["exclude_ports"] == "2222"

    history = client.get("/api/scans", headers=h).json()
    staged_history = next(row for row in history if row["id"] == staged.json()["id"])
    assert staged_history["summary"]["excluded_ports"] == "2222"
    assert staged_history["summary"]["targets"] == "127.0.0.0 – 127.0.0.2 · 대상 2대"


def test_staged_pn_spec_uses_expanded_effective_hosts_for_engine_batching(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    response = client.post("/api/scans/run-staged", headers=h, json={
        "targets": ["198.51.100.0/23"],
        "exclude": ["198.51.100.0/24"],
        "options": ["syn"],
        "ports": "T:443",
        "batch_size": 64,
        "discovery": "pn",
    })

    assert response.status_code == 200, response.text
    spec_path = scans_api._settings.scans_dir / f"scan_{response.json()['id']}" / "spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert len(spec["targets"]) == 256
    assert spec["targets"][0] == "198.51.101.0"
    assert spec["targets"][-1] == "198.51.101.255"
    assert spec["exclude"] == ["198.51.100.0/24"]
    assert spec["batch_size"] == 64


@pytest.mark.parametrize("mode", ["legacy", "staged"])
def test_resume_checks_saved_targets_against_scope_but_exclusions_for_syntax_only(
    client, monkeypatch, mode,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    endpoint = "/api/scans/run" if mode == "legacy" else "/api/scans/run-staged"
    body = {
        "targets": ["127.0.0.1"],
        "exclude": ["203.0.113.9"],
        "workflow": "manual",
        "options": ["connect"],
        "ports": "T:443",
        "discovery": "pn",
    }
    created = client.post(endpoint, headers=h, json=body)
    assert created.status_code == 200, created.text
    scan_id = created.json()["id"]

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scan.status = "canceled"
        db.commit()
    finally:
        db.close()

    real_check_scope = scans_api.scope.check_scope
    checked = []

    def check_saved_targets(hosts):
        checked.append(list(hosts))
        real_check_scope(hosts, spec="127.0.0.0/24")

    monkeypatch.setattr(scans_api.scope, "check_scope", check_saved_targets)
    monkeypatch.setattr(
        scans_api.engine_runner, "is_engine_scan",
        lambda out_dir: mode == "staged",
    )
    resumed = client.post(f"/api/scans/{scan_id}/resume", headers=h)

    assert resumed.status_code == 200, resumed.text
    assert checked == [["127.0.0.1"]]


def test_legacy_resume_rejects_excluded_host_reinserted_into_saved_batches(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun
    from scanops.scanning import chunker

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    created = client.post("/api/scans/run", headers=h, json={
        "targets": ["127.0.0.0/30"],
        "exclude": ["127.0.0.1"],
        "workflow": "manual",
        "options": ["connect"],
        "ports": "T:443",
    })
    assert created.status_code == 200, created.text
    scan_id = created.json()["id"]

    base = scans_api._basename(scan_id)
    state = chunker.read_state(base)
    state["batches"][0].append("127.0.0.1")
    chunker.write_state(base, state)
    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scan.status = "canceled"
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(
        scans_api.nmap_runner, "find_nmap",
        lambda explicit="": (_ for _ in ()).throw(AssertionError("invalid state checked nmap")),
    )
    monkeypatch.setattr(scans_api.engine_runner, "is_engine_scan", lambda out_dir: False)
    resumed = client.post(f"/api/scans/{scan_id}/resume", headers=h)

    assert resumed.status_code == 400, resumed.text
    assert "제외 대상" in resumed.json()["detail"]


def test_staged_effective_scope_closes_unobserved_included_finding_but_keeps_excluded(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    h = _auth(client)
    included, excluded = "127.0.0.2", "127.0.0.1"
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        db.add_all([
            Finding(
                finding_key=f"{included}|443|tcp", host_ip=included, port=443,
                proto="tcp", state="open", first_scan_id=initial.id, last_scan_id=initial.id,
            ),
            Finding(
                finding_key=f"{excluded}|443|tcp", host_ip=excluded, port=443,
                proto="tcp", state="open", first_scan_id=initial.id, last_scan_id=initial.id,
            ),
        ])
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    response = client.post("/api/scans/run-staged", headers=h, json={
        "targets": ["127.0.0.0/30"],
        "exclude": [excluded, "127.0.0.3/32"],
        "ports": "T:443",
        "options": ["syn"],
        "discovery": "pn",
    })
    assert response.status_code == 200, response.text
    scan_id = response.json()["id"]
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    spec = json.loads((out_dir / "spec.json").read_text(encoding="utf-8"))
    assert set(spec["scanops"]["scope_keys"]) == {f"{included}|443|tcp"}
    (out_dir / "run-state.json").write_text(
        json.dumps({"live": [], "open_map": {}}), encoding="utf-8",
    )

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        counts = scans_api.engine_runner.ingest_results(
            db, scan, out_dir, scope_keys=set(spec["scanops"]["scope_keys"]),
        )
        assert counts["closed"] == 1
        rows = {row.host_ip: row for row in db.query(Finding).filter_by(port=443).all()}
        assert rows[included].state == "closed"
        assert rows[excluded].state == "open"
    finally:
        db.close()


@pytest.mark.parametrize("workflow", ["manual", "auto"])
def test_completed_legacy_batch_closes_unobserved_effective_host_only(client, workflow):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    included, excluded = "127.0.0.2", "127.0.0.1"
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        current = ScanRun(name=f"legacy-{workflow}", status="running")
        db.add_all([initial, current])
        db.commit()
        db.add_all([
            Finding(
                finding_key=f"{included}|443|tcp", host_ip=included, port=443,
                proto="tcp", state="open", first_scan_id=initial.id, last_scan_id=initial.id,
            ),
            Finding(
                finding_key=f"{excluded}|443|tcp", host_ip=excluded, port=443,
                proto="tcp", state="open", first_scan_id=initial.id, last_scan_id=initial.id,
            ),
        ])
        db.commit()
        scan_id = current.id
    finally:
        db.close()

    if workflow == "manual":
        scans_api._ingest_batch(
            scan_id,
            b'<?xml version="1.0"?><nmaprun>'
            b'<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
            b'</nmaprun>',
            closure_hosts={included},
        )
    else:
        scans_api._ingest_auto_findings(
            scan_id, [], set(), {443}, set(), closure_hosts={included},
        )

    db = SessionLocal()
    try:
        rows = {row.host_ip: row for row in db.query(Finding).filter_by(port=443).all()}
        assert rows[included].state == "closed"
        assert rows[excluded].state == "open"
    finally:
        db.close()

@pytest.mark.parametrize(("extra", "expected"), [({}, "default"), ({"nse": []}, [])])
def test_staged_scan_preserves_omitted_vs_explicit_empty_nse(
    client, monkeypatch, extra, expected,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    response = client.post("/api/scans/run-staged", headers=h, json={
        "targets": ["127.0.0.1"],
        "discovery": "pn",
        **extra,
    })

    assert response.status_code == 200, response.text
    spec_path = scans_api._settings.scans_dir / f"scan_{response.json()['id']}" / "spec.json"
    service = json.loads(spec_path.read_text(encoding="utf-8"))["stages"]["service"]
    if expected == "default":
        assert service["nse"] == scans_api.scan_options.NSE_DEFAULT_KEYS
    else:
        assert service["nse"] == expected


def test_manual_preset_explicit_ports_match_display_state_and_worker_argv(client, monkeypatch):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun
    from scanops.scanning import chunker

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "is_engine_scan", lambda out_dir: False)
    captured = []
    real_build = scans_api.nmap_runner.build_command

    def capture_build(*args, **kwargs):
        argv = real_build(*args, **kwargs)
        captured.append(argv)
        return argv

    monkeypatch.setattr(scans_api.nmap_runner, "build_command", capture_build)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    response = client.post("/api/scans/run", headers=h, json={
        "workflow": "manual",
        "preset": "quick",
        "ports": "443",
        "nse": [],
        "targets": ["127.0.0.1"],
        "exclude": ["192.0.2.1", "198.51.100.0/24"],
    })

    assert response.status_code == 200, response.text
    scan = response.json()
    state = chunker.read_state(scans_api._basename(scan["id"]))
    assert state["ports"] == "443"
    assert state["nse"] == []
    assert "-p 443" in scan["command"]
    assert "--top-ports" not in scan["command"]
    assert "--script" not in scan["command"]
    assert "--exclude 192.0.2.1,198.51.100.0/24" in scan["command"]

    class FinishedProc:
        def wait(self, timeout=None):
            return 0

    spawned = []

    def fake_popen(argv, log_path):
        spawned.append(argv)
        base = argv[argv.index("-oA") + 1]
        with open(f"{base}.xml", "w", encoding="utf-8") as stream:
            stream.write("<nmaprun/>")
        return FinishedProc()

    monkeypatch.setattr(scans_api.nmap_runner, "popen", fake_popen)
    monkeypatch.setattr(
        scans_api, "_ingest_batch",
        lambda scan_id, xml, closure_hosts=None: None,
    )

    scans_api._chunk_worker(scan["id"])
    initial_worker_argv = captured[-1]

    state = chunker.read_state(scans_api._basename(scan["id"]))
    state["cursor"] = 0
    chunker.write_state(scans_api._basename(scan["id"]), state)
    db = SessionLocal()
    try:
        row = db.get(ScanRun, scan["id"])
        row.status = "canceled"
        db.commit()
    finally:
        db.close()

    class ImmediateThread:
        def __init__(self, target, args=(), **kwargs):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)

    monkeypatch.setattr(scans_api.threading, "Thread", ImmediateThread)
    resumed = client.post(f"/api/scans/{scan['id']}/resume", headers=h)
    assert resumed.status_code == 200, resumed.text
    resumed_worker_argv = captured[-1]

    for argv in (captured[0], initial_worker_argv, resumed_worker_argv):
        assert argv[argv.index("-p") + 1] == "443"
        assert "--top-ports" not in argv
        assert "--script" not in argv
    assert len(spawned) == 2
    for argv in spawned:
        assert argv.count("--exclude") == 1
        assert argv[argv.index("--exclude") + 1] == "192.0.2.1,198.51.100.0/24"


def test_legacy_auto_applies_one_canonical_exclude_to_all_nmap_stages(monkeypatch, tmp_path):
    from pathlib import Path

    from scanops.api import scans as scans_api

    captured = []

    def write_stage(_scan_id, argv, _log_path, _watchdog=0, _out_base=None):
        captured.append(argv)
        base = Path(argv[argv.index("-oA") + 1])
        if str(base).endswith(".udp_identify"):
            scaninfo = '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>'
            ports = _port("udp", 53)
        else:
            scaninfo = '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
            ports = _port("tcp", 443)
        Path(f"{base}.xml").write_bytes(_scan_xml(1893456000, scaninfo, ports))

    monkeypatch.setattr(scans_api, "_checked_stage", write_stage)
    monkeypatch.setattr(scans_api, "_ingest_auto_findings", lambda *args, **kwargs: None)

    assert scans_api._run_auto_batch(
        1,
        "nmap",
        ["scanner.internal"],
        tmp_path / "auto-b0",
        {
            "ports": "T:443,U:53",
            "nse": [],
            "udp_all_targets": True,
            "exclude": ["192.0.2.1", "198.51.100.0/24"],
        },
    ) is True

    assert len(captured) == 3
    for argv in captured:
        assert argv.count("--exclude") == 1
        assert argv[argv.index("--exclude") + 1] == "192.0.2.1,198.51.100.0/24"


@pytest.mark.parametrize(("bad", "detail"), [
    ("-oX/tmp/structured.xml", "허용되지 않는 타겟"),
    ("2001:db8::1", "IPv6"),
    ("0-255.0-255.0-255.0-255", "지원하지 않는 복합 IP 범위"),
])
def test_all_structured_scan_modes_reject_invalid_target_before_side_effects(
    client, monkeypatch, bad, detail,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": None)
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(AssertionError("invalid target reached engine availability check")),
    )
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid target started a worker")),
    )
    requests = [
        ("/api/scans/run", {"workflow": "manual", "preset": "quick", "targets": [bad]}),
        ("/api/scans/run", {"workflow": "manual", "options": ["connect"], "targets": [bad]}),
        ("/api/scans/run", {"workflow": "auto", "targets": [bad]}),
        ("/api/scans/run-staged", {"targets": [bad], "discovery": "pn"}),
        ("/api/scans/estimate", {"targets": [bad]}),
    ]

    responses = [client.post(path, headers=h, json=body) for path, body in requests]
    assert [response.status_code for response in responses] == [400, 400, 400, 400, 400]
    assert all(detail in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


@pytest.mark.parametrize(("target", "batch_size", "hosts", "batches"), [
    ("192.0.2.0/30", 2, 4, 2),
    ("192.0.2.1-3", 256, 3, 1),
])
def test_estimate_preserves_supported_cidr_and_last_octet_range(
    client, target, batch_size, hosts, batches,
):
    h = _auth(client)
    response = client.post("/api/scans/estimate", headers=h, json={
        "targets": [target], "batch_size": batch_size,
    })

    assert response.status_code == 200, response.text
    assert response.json()["host_count"] == hosts
    assert response.json()["batch_count"] == batches


@pytest.mark.parametrize(("bad", "detail"), [
    ("10.0.0.0/999", "잘못된 CIDR"),
    ("10.0.0.0/8", "너무 많습니다"),
    ("10.999.0.1-2", "잘못된 IP 범위"),
])
def test_cidr_rejected_before_scope_engine_worker_or_scan_record(
    client, monkeypatch, bad, detail,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(
        scans_api.scope, "check_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("invalid CIDR reached scope check")
        ),
    )
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(
            AssertionError("invalid CIDR reached engine availability check")
        ),
    )
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("invalid CIDR started a worker")
        ),
    )

    requests = [
        ("/api/scans/run", {"workflow": "auto", "targets": [bad]}),
        ("/api/scans/run-staged", {"targets": [bad], "discovery": "pn"}),
        ("/api/scans/estimate", {"targets": [bad]}),
    ]
    responses = [client.post(path, headers=h, json=body) for path, body in requests]

    assert [response.status_code for response in responses] == [400, 400, 400]
    assert all(detail in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


@pytest.mark.parametrize("ports", ["99999", "443-22", "22,,80", "T:"])
def test_all_structured_scan_modes_reject_invalid_ports_before_side_effects(
    client, monkeypatch, ports,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": None)
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(AssertionError("invalid ports reached engine availability check")),
    )
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid ports started a worker")),
    )
    requests = [
        ("/api/scans/run", {"workflow": "manual", "preset": "quick", "ports": ports, "targets": ["127.0.0.1"]}),
        ("/api/scans/run", {"workflow": "manual", "options": ["connect"], "ports": ports, "targets": ["127.0.0.1"]}),
        ("/api/scans/run", {"workflow": "auto", "ports": ports, "targets": ["127.0.0.1"]}),
        ("/api/scans/run-staged", {"ports": ports, "targets": ["127.0.0.1"], "discovery": "pn"}),
        ("/api/scans/estimate", {"ports": ports, "targets": ["127.0.0.1"]}),
    ]

    responses = [client.post(path, headers=h, json=body) for path, body in requests]
    assert [response.status_code for response in responses] == [400, 400, 400, 400, 400]
    assert all("포트" in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


@pytest.mark.parametrize(("field", "value", "detail"), [
    ("workflow", "unknown", "workflow"),
    ("options", ["--script=unsafe"], "스캔 옵션"),
    ("nse", ["unsafe-script"], "NSE"),
    ("batch_size", 0, "batch_size"),
    ("batch_size", -1, "batch_size"),
    ("batch_size", 1025, "batch_size"),
    ("discovery", "skip", "discovery"),
])
def test_run_staged_and_estimate_share_structured_validation(
    client, monkeypatch, field, value, detail,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(
        scans_api.nmap_runner, "find_nmap",
        lambda explicit="": (_ for _ in ()).throw(
            AssertionError("invalid input reached nmap availability check")
        ),
    )
    monkeypatch.setattr(
        scans_api.engine_runner, "ensure_available",
        lambda: (_ for _ in ()).throw(
            AssertionError("invalid input reached engine availability check")
        ),
    )
    body = {"targets": ["127.0.0.1"], field: value}
    responses = [client.post(path, headers=h, json=body) for path in (
        "/api/scans/run", "/api/scans/run-staged", "/api/scans/estimate",
    )]

    assert [response.status_code for response in responses] == [400, 400, 400]
    assert all(detail in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


@pytest.mark.parametrize(("ports", "expected_tcp", "expected_udp"), [
    ("T:80", (True, "80"), (False, "")),
    ("U:53", (False, ""), (True, "53")),
])
def test_run_staged_and_estimate_use_only_explicit_protocol_ports(
    client, monkeypatch, ports, expected_tcp, expected_udp,
):
    from scanops.api import scans as scans_api

    h = _auth(client)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)
    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    body = {
        "targets": ["127.0.0.1"],
        "ports": ports,
        "options": ["udp"],
        "staged": True,
        "discovery": "pn",
    }

    estimate = client.post("/api/scans/estimate", headers=h, json=body)
    response = client.post("/api/scans/run-staged", headers=h, json=body)

    assert estimate.status_code == 200, estimate.text
    assert response.status_code == 200, response.text
    out_dir = scans_api._settings.scans_dir / f"scan_{response.json()['id']}"
    stages = json.loads((out_dir / "spec.json").read_text(encoding="utf-8"))["stages"]
    assert (stages["tcp"]["enabled"], stages["tcp"]["ports"]) == expected_tcp
    assert (stages["udp"]["enabled"], stages["udp"]["ports"]) == expected_udp


def test_explicit_udp_ports_without_udp_option_are_rejected_before_side_effects(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(
        scans_api.engine_runner,
        "ensure_available",
        lambda: (_ for _ in ()).throw(
            AssertionError("invalid protocol selection reached engine availability check")
        ),
    )
    monkeypatch.setattr(
        scans_api.threading,
        "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("invalid protocol selection started a worker")
        ),
    )
    body = {
        "targets": ["127.0.0.1"],
        "ports": "U:53",
        "options": [],
        "staged": True,
        "discovery": "pn",
    }

    responses = [
        client.post("/api/scans/run-staged", headers=h, json=body),
        client.post("/api/scans/estimate", headers=h, json=body),
    ]

    assert [response.status_code for response in responses] == [400, 400]
    assert all("UDP 포트" in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


def test_legacy_auto_estimate_accepts_default_tcp_and_udp_ports_without_staged_options(client):
    from scanops.scanning import scan_options

    h = _auth(client)
    response = client.post("/api/scans/estimate", headers=h, json={
        "targets": ["127.0.0.1"],
        "workflow": "auto",
        "options": [],
        "ports": scan_options.DEFAULT_PORTS,
        "staged": False,
    })

    assert response.status_code == 200, response.text
    assert response.json()["host_count"] == 1


def test_manual_unknown_preset_rejected_by_run_and_estimate_before_availability(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api

    h = _auth(client)
    monkeypatch.setattr(
        scans_api.nmap_runner, "find_nmap",
        lambda explicit="": (_ for _ in ()).throw(
            AssertionError("unknown preset reached nmap availability check")
        ),
    )
    body = {
        "workflow": "manual", "preset": "missing", "targets": ["127.0.0.1"],
    }
    responses = [client.post(path, headers=h, json=body) for path in (
        "/api/scans/run", "/api/scans/estimate",
    )]

    assert [response.status_code for response in responses] == [400, 400]
    assert all("알 수 없는 프리셋" in response.json()["detail"] for response in responses)
    assert client.get("/api/scans", headers=h).json() == []


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

    # 미확정 관측은 평소 접혀 있다 - 여기서 볼 것은 인입이 상태를 보존하는가이므로 펼친다.
    findings = client.get("/api/findings?state=&hide_unconfirmed=false", headers=h).json()
    by_port = {(f["proto"], f["port"]): f for f in findings}
    assert by_port[("tcp", 22)]["state"] == "open"
    assert by_port[("tcp", 80)]["state"] == "closed"
    assert by_port[("udp", 53)]["state"] == "open|filtered"

    heat = client.get("/api/heatmap", headers=h).json()
    row80 = next(r for r in heat["rows"] if r["host_ip"] == "127.0.0.1" and r["port"] == 80)
    assert row80["current_state"] == "신규닫힘"


def test_auto_discovery_fallback_preserves_existing_identity_and_evidence(
    client, monkeypatch, tmp_path,
):
    from pathlib import Path

    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, FindingEvent, ScanRun

    ip, port = "127.0.0.1", 54842
    key = f"{ip}|{port}|tcp"
    preserved = {
        "hostname": "api.internal",
        "service": "http",
        "product": "Uvicorn",
        "version": "0.30",
        "server": "uvicorn/0.30",
        "banner": "Uvicorn 0.30",
        "cpe": "cpe:/a:encode:uvicorn:0.30",
        "identification": "확인",
        "nse_json": [{"id": "http-server-header", "output": "uvicorn/0.30"}],
        "remarks": "server=uvicorn/0.30",
        "category": "기존 웹",
        "usage": "기존 API",
        "risk_level": "high",
        "compliance_json": [{"std": "legacy", "ref": "keep"}],
    }
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        row = Finding(
            finding_key=key, host_ip=ip, port=port, proto="tcp", state="open",
            first_scan_id=initial.id, last_scan_id=initial.id, **preserved,
        )
        current = ScanRun(name="legacy auto", status="running")
        db.add_all([row, current])
        db.commit()
        current_id = current.id
    finally:
        db.close()

    def write_stage(_scan_id, argv, _log_path, _watchdog=0, _out_base=None):
        base = Path(argv[argv.index("-oA") + 1])
        if str(base).endswith(".tcp_discovery"):
            xml = _scan_xml(
                1893456000,
                f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
                _port("tcp", port, service="unknown"),
                host=ip,
            )
        else:
            xml = _scan_xml(
                1893456001,
                f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
                _port("tcp", port, state="filtered", service="unknown"),
                host=ip,
            )
        Path(f"{base}.xml").write_bytes(xml)

    monkeypatch.setattr(scans_api, "_checked_stage", write_stage)
    assert scans_api._run_auto_batch(
        current_id,
        "nmap",
        [ip],
        tmp_path / "auto-b0",
        {"ports": f"T:{port}", "nse": [], "udp_all_targets": False},
    ) is True

    db = SessionLocal()
    try:
        row = db.query(Finding).filter_by(finding_key=key).one()
        for field, value in preserved.items():
            assert getattr(row, field) == value
        assert row.state == "open" and row.last_scan_id == current_id
        event_types = {
            event.type for event in db.query(FindingEvent).filter_by(scan_id=current_id)
        }
        assert not {"SERVICE_CHANGED", "VERSION_CHANGED", "SERVER_CHANGED"} & event_types
    finally:
        db.close()


def test_stage_bundle_discovery_fallback_preserves_existing_identity_snapshot(client):
    from scanops.db import SessionLocal
    from scanops.models import Finding, FindingEvent, ScanRun

    h = _auth(client)
    ip, port = "127.0.0.1", 54842
    key = f"{ip}|{port}|tcp"
    preserved = {
        "hostname": "api.internal",
        "service": "http",
        "product": "Uvicorn",
        "version": "0.30",
        "server": "uvicorn/0.30",
        "banner": "Uvicorn 0.30",
        "cpe": "cpe:/a:encode:uvicorn:0.30",
        "identification": "확인",
        "nse_json": [{"id": "http-server-header", "output": "uvicorn/0.30"}],
        "remarks": "server=uvicorn/0.30",
        "category": "기존 웹",
        "usage": "기존 API",
        "risk_level": "high",
        "compliance_json": [{"std": "legacy", "ref": "keep"}],
    }
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        db.add(Finding(
            finding_key=key, host_ip=ip, port=port, proto="tcp", state="open",
            first_scan_id=initial.id, last_scan_id=initial.id, **preserved,
        ))
        db.commit()
    finally:
        db.close()

    discovery = _scan_xml(
        1893456000,
        f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
        _port("tcp", port, service="unknown"),
        host=ip,
    )
    identify_filtered = _scan_xml(
        1893456001,
        f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
        _port("tcp", port, state="filtered", service="unknown"),
        host=ip,
    )
    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", ("legacy.tcp_discovery.xml", discovery, "text/xml")),
        ("files", ("legacy.tcp_identify.xml", identify_filtered, "text/xml")),
    ])

    assert response.status_code == 200, response.text
    scan_id = response.json()["scans"][0]["scan_id"]
    counts = response.json()["counts"]
    assert counts["service_changed"] == 0
    assert counts["version_changed"] == 0
    assert counts["server_changed"] == 0
    db = SessionLocal()
    try:
        row = db.query(Finding).filter_by(finding_key=key).one()
        for field, value in preserved.items():
            assert getattr(row, field) == value
        event_types = {
            event.type for event in db.query(FindingEvent).filter_by(scan_id=scan_id)
        }
        assert not {"SERVICE_CHANGED", "VERSION_CHANGED", "SERVER_CHANGED"} & event_types
    finally:
        db.close()

    heatmap = client.get("/api/heatmap", headers=h).json()
    snapshot = next(row for row in heatmap["rows"] if row["key"] == key)
    assert snapshot["service"] == "http"
    assert snapshot["product"] == "Uvicorn"
    assert snapshot["version"] == "0.30"
    assert snapshot["server"] == "uvicorn/0.30"


def test_single_discovery_bundle_preserves_existing_identity_and_creates_new_port(client):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, FindingEvent, ScanRun

    h = _auth(client)
    ip, existing_port, new_port = "127.0.0.1", 54842, 54843
    existing_key = f"{ip}|{existing_port}|tcp"
    new_key = f"{ip}|{new_port}|tcp"
    preserved = {
        "hostname": "api.internal",
        "service": "http",
        "product": "Uvicorn",
        "version": "0.30",
        "server": "uvicorn/0.30",
        "banner": "Uvicorn 0.30",
        "cpe": "cpe:/a:encode:uvicorn:0.30",
        "identification": "확인",
        "nse_json": [{"id": "http-server-header", "output": "uvicorn/0.30"}],
        "remarks": "server=uvicorn/0.30",
        "category": "기존 웹",
        "usage": "기존 API",
        "risk_level": "high",
        "compliance_json": [{"std": "legacy", "ref": "keep"}],
    }
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        db.add(Finding(
            finding_key=existing_key,
            host_ip=ip,
            port=existing_port,
            proto="tcp",
            state="open",
            first_scan_id=initial.id,
            last_scan_id=initial.id,
            **preserved,
        ))
        db.commit()
    finally:
        db.close()

    discovery = _scan_xml(
        1893456000,
        '<scaninfo type="syn" protocol="tcp" numservices="2" '
        f'services="{existing_port},{new_port}"/>',
        _port("tcp", existing_port, service="unknown")
        + _port("tcp", new_port, service="unknown"),
        host=ip,
    )
    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", ("partial.tcp_discovery.xml", discovery, "text/xml")),
    ])

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["imported"] == 1 and payload["counts"]["new"] == 1
    scan_id = payload["scans"][0]["scan_id"]
    db = SessionLocal()
    try:
        existing = db.query(Finding).filter_by(finding_key=existing_key).one()
        for field, value in preserved.items():
            assert getattr(existing, field) == value
        created = db.query(Finding).filter_by(finding_key=new_key).one()
        assert created.state == "open" and created.service == "unknown"
        assert created.last_scan_id == scan_id
        existing_events = {
            event.type
            for event in db.query(FindingEvent).filter_by(
                finding_id=existing.id, scan_id=scan_id,
            )
        }
        assert not {"SERVICE_CHANGED", "VERSION_CHANGED", "SERVER_CHANGED"} & existing_events
        assert db.query(FindingEvent).filter_by(
            finding_id=created.id, scan_id=scan_id, type="NEW_OPEN",
        ).count() == 1
        scan = db.get(ScanRun, scan_id)
        assert scan.raw_xml_path.endswith(f"scan_{scan_id}.xml")
    finally:
        db.close()

    original = scans_api._settings.scans_dir / f"scan_{scan_id}.tcp_discovery.xml"
    assert original.read_bytes() == discovery
    heatmap = client.get("/api/heatmap", headers=h).json()
    snapshot = next(row for row in heatmap["rows"] if row["key"] == existing_key)
    assert snapshot["display_identity"] == "uvicorn/0.30"


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

    # 미확정 관측은 평소 접혀 있다 - 여기서 볼 것은 인입이 상태를 보존하는가이므로 펼친다.
    findings = client.get("/api/findings?state=&hide_unconfirmed=false", headers=h).json()
    by_port = {(f["proto"], f["port"]): f for f in findings}
    assert by_port[("tcp", 22)]["state"] == "open"
    assert by_port[("udp", 53)]["state"] == "open|filtered"


def test_limited_legacy_scan_only_closes_ports_in_scaninfo_scope(client):
    h = _auth(client)
    initial = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>',
        _port("tcp", 22, service="ssh") + _port("tcp", 80, service="http"),
    )
    client.post("/api/scans/import", headers=h, files={"file": ("initial.xml", initial, "text/xml")})

    limited = _scan_xml(
        1782050100,
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>',
        "",
    )
    r = client.post("/api/scans/import", headers=h, files={"file": ("limited.xml", limited, "text/xml")})
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["closed"] == 1
    # 미확정 관측은 평소 접혀 있다 - 여기서 볼 것은 인입이 상태를 보존하는가이므로 펼친다.
    findings = client.get("/api/findings?state=&hide_unconfirmed=false", headers=h).json()
    by_port = {f["port"]: f for f in findings}
    assert by_port[22]["state"] == "closed"
    assert by_port[80]["state"] == "open"


def test_limited_staged_scan_persists_exact_tcp_udp_closure_scope(client, monkeypatch):
    from scanops.api import scans as scans_api
    from scanops.config import get_settings
    import json

    h = _auth(client)
    initial = _scan_xml(
        1782050000,
        '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>'
        '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>',
        _port("tcp", 22, service="ssh")
        + _port("tcp", 80, service="http")
        + _port("udp", 53, state="open|filtered", service="domain"),
    )
    assert client.post(
        "/api/scans/import", headers=h, files={"file": ("initial.xml", initial, "text/xml")},
    ).status_code == 200

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)

    response = client.post("/api/scans/run-staged", headers=h, json={
        "name": "limited staged",
        "targets": ["127.0.0.1"],
        "ports": "T:22,U:53",
        "options": ["syn", "udp"],
        "discovery": "pn",
    })
    assert response.status_code == 200, response.text
    scan_id = response.json()["id"]
    spec = json.loads(
        (get_settings().scans_dir / f"scan_{scan_id}" / "spec.json").read_text(encoding="utf-8")
    )
    assert set(spec["scanops"]["scope_keys"]) == {
        "127.0.0.1|22|tcp", "127.0.0.1|53|udp",
    }
    assert "127.0.0.1|80|tcp" not in spec["scanops"]["scope_keys"]


def test_port_scope_expands_open_ended_ranges_and_keeps_protocol_sticky():
    from scanops.api import scans as scans_api

    assert scans_api._port_scope("T:1-", "T") is None
    upper = scans_api._port_scope("T:1024-", "T")
    assert len(upper) == 65535 - 1024 + 1
    assert min(upper) == 1024 and max(upper) == 65535
    lower = scans_api._port_scope("T:-1024", "T")
    assert len(lower) == 1024
    assert min(lower) == 1 and max(lower) == 1024
    assert scans_api._port_scope("T:20-22", "T") == {20, 21, 22}

    sticky = "T:22,U:-1024,2048"
    assert scans_api._port_scope(sticky, "T") == {22}
    udp = scans_api._port_scope(sticky, "U")
    assert len(udp) == 1025 and {1, 1024, 2048} <= udp


def test_legacy_auto_open_ended_scope_closes_only_missing_ports_in_range(client):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    ip = "127.0.0.1"
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        current = ScanRun(name="auto open ended", status="running")
        db.add_all([initial, current])
        db.commit()
        db.add_all([
            Finding(
                finding_key=f"{ip}|443|tcp", host_ip=ip, port=443, proto="tcp",
                state="open", service="https", first_scan_id=initial.id,
                last_scan_id=initial.id,
            ),
            Finding(
                finding_key=f"{ip}|65000|tcp", host_ip=ip, port=65000, proto="tcp",
                state="open", service="unknown", first_scan_id=initial.id,
                last_scan_id=initial.id,
            ),
        ])
        db.commit()
        current_id = current.id
    finally:
        db.close()

    scans_api._ingest_auto_findings(
        current_id, [], {ip}, scans_api._port_scope("T:1024-", "T"), set(),
    )

    db = SessionLocal()
    try:
        rows = {row.port: row for row in db.query(Finding).filter_by(host_ip=ip).all()}
        assert rows[443].state == "open"
        assert rows[65000].state == "closed"
        assert rows[65000].last_scan_id == current_id
    finally:
        db.close()


def test_staged_open_ended_scope_closes_only_missing_ports_in_range(
    client, monkeypatch,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    h = _auth(client)
    ip = "127.0.0.1"
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        db.add_all([
            Finding(
                finding_key=f"{ip}|443|tcp", host_ip=ip, port=443, proto="tcp",
                state="open", service="https", first_scan_id=initial.id,
                last_scan_id=initial.id,
            ),
            Finding(
                finding_key=f"{ip}|65000|tcp", host_ip=ip, port=65000, proto="tcp",
                state="open", service="unknown", first_scan_id=initial.id,
                last_scan_id=initial.id,
            ),
        ])
        db.commit()
    finally:
        db.close()

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)
    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    response = client.post("/api/scans/run-staged", headers=h, json={
        "name": "staged open ended",
        "targets": [ip],
        "ports": "T:-1024",
        "options": ["syn"],
        "discovery": "pn",
    })
    assert response.status_code == 200, response.text
    scan_id = response.json()["id"]
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    spec = json.loads((out_dir / "spec.json").read_text(encoding="utf-8"))
    assert set(spec["scanops"]["scope_keys"]) == {f"{ip}|443|tcp"}
    (out_dir / "run-state.json").write_text(
        json.dumps({"live": [ip], "open_map": {}}), encoding="utf-8",
    )

    db = SessionLocal()
    try:
        scan = db.get(ScanRun, scan_id)
        scans_api.engine_runner.ingest_results(
            db, scan, out_dir, scope_keys=set(spec["scanops"]["scope_keys"]),
        )
        db.commit()
        rows = {row.port: row for row in db.query(Finding).filter_by(host_ip=ip).all()}
        assert rows[443].state == "closed"
        assert rows[443].last_scan_id == scan_id
        assert rows[65000].state == "open"
    finally:
        db.close()


def test_import_malformed_xml_returns_400_no_orphan_scan(client):
    """깨진 XML 가져오기 → 500 이 아니라 400 으로 정직하게 거절하고 좀비 스캔을 남기지 않는다.

    회귀 방지: scan_start() 의 ParseError 가 try 밖에서 500 으로 전파되던 버그 수정 검증.
    """
    h = _auth(client)
    for bad in (b"<nmaprun><host><ports><port unclosed", b"not xml at all @#$", b""):
        r = client.post("/api/scans/import", headers=h,
                        files={"file": ("bad.xml", bad, "text/xml")})
        assert r.status_code == 400, f"expected 400 for malformed, got {r.status_code}: {r.text}"
    # 파싱 실패로 좀비 running 스캔이 생성되지 않아야 한다.
    scans = client.get("/api/scans", headers=h).json()
    assert all(s["status"] != "running" for s in scans), scans
    # 정상 XML 은 여전히 200(회귀 없음).
    good = _scan_xml(1700000000, '<scaninfo type="syn" protocol="tcp" services="22"/>', _port("tcp", 22))
    assert client.post("/api/scans/import", headers=h,
                       files={"file": ("good.xml", good, "text/xml")}).status_code == 200


def _targets_fingerprint(hosts: list[str]) -> str:
    digest = hashlib.sha256()
    for host in hosts:
        encoded = host.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _standalone_empty_xml(start: int, proto: str, services: str, total: int) -> bytes:
    scan_type = "udp" if proto == "udp" else "syn"
    return f"""<?xml version="1.0"?>
<nmaprun start="{start}">
  <scaninfo type="{scan_type}" protocol="{proto}" numservices="1" services="{services}"/>
  <runstats>
    <finished time="{start + 1}" exit="success"/>
    <hosts up="0" down="{total}" total="{total}"/>
  </runstats>
</nmaprun>
""".encode()


def _standalone_observed_xml(
    start: int,
    proto: str,
    service: int,
    host: str,
    *,
    include_port: bool = True,
) -> bytes:
    scan_type = "udp" if proto == "udp" else "syn"
    port = _port(proto, service) if include_port else ""
    return f"""<?xml version="1.0"?>
<nmaprun start="{start}">
  <scaninfo type="{scan_type}" protocol="{proto}" numservices="1" services="{service}"/>
  <host>
    <status state="up"/>
    <address addr="{host}" addrtype="ipv4"/>
    <ports>{port}</ports>
  </host>
  <runstats>
    <finished time="{start + 1}" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
""".encode()


def _standalone_manifest(
    xml_name: str,
    xml_bytes: bytes,
    *,
    raw_targets: list[str],
    exclude: list[str],
    closure_targets: list[str],
    stage_id: str = "tcp_discovery",
    authoritative: bool = True,
) -> bytes:
    effective = [host for host in raw_targets if host not in exclude]
    contract = {
        "schema": 1,
        "raw_targets": raw_targets,
        "exclude": exclude,
        "max_hosts": 65536,
        "requested_host_count": len(raw_targets),
        "effective_host_count": len(effective),
        "effective_targets_sha256": _targets_fingerprint(effective),
        "batch_size": 0,
        "host_timeout": "",
        "units": [{
            "batch_index": 0,
            "stage_id": stage_id,
            "authoritative": authoritative,
            "closure_targets": closure_targets,
            "xml_basename": xml_name,
            "xml_size": len(xml_bytes),
            "xml_sha256": hashlib.sha256(xml_bytes).hexdigest(),
        }],
    }
    return json.dumps({"tool": "scanops_scanner", "import_contract": contract}).encode()


def test_standalone_manifest_closes_included_unobserved_but_preserves_excluded(client):
    """성공한 standalone 실행 범위는 host가 XML에 없어도 닫되 exclude는 범위 밖에 둔다."""
    h = _auth(client)
    port = 54443
    included, excluded = "127.0.0.1", "127.0.0.2"
    for index, host in enumerate((included, excluded)):
        initial = _scan_xml(
            1893456000 + index,
            f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
            _port("tcp", port, service="https"),
            host=host,
        )
        response = client.post(
            "/api/scans/import", headers=h,
            files={"file": (f"initial-{index}.xml", initial, "text/xml")},
        )
        assert response.status_code == 200, response.text

    name = "offline.tcp_discovery.xml"
    empty = _standalone_empty_xml(1893456100, "tcp", str(port), total=1)
    manifest = _standalone_manifest(
        name,
        empty,
        raw_targets=[included, excluded],
        exclude=[excluded],
        closure_targets=[included],
    )
    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (name, empty, "text/xml")),
        ("files", ("offline.manifest.json", manifest, "application/json")),
    ])

    assert response.status_code == 200, response.text
    assert response.json()["counts"]["closed"] == 1
    rows = {
        row["host_ip"]: row
        for row in client.get("/api/findings?state=", headers=h).json()
        if row["port"] == port and row["proto"] == "tcp"
    }
    assert rows[included]["state"] == "closed"
    assert rows[excluded]["state"] == "open"


def test_strong_single_manifest_rejects_scanned_host_outside_unit_and_server_scope(
    client, monkeypatch, tmp_path,
):
    """A matching hash/runstats count cannot substitute a different observed host."""
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    monkeypatch.setattr(scans_api._settings, "scan_scope", "127.0.0.0/8")
    requested, unexpected, port = "127.0.0.1", "192.0.2.55", 54448
    name = "single.xml"
    xml = _standalone_observed_xml(
        1893456200, "tcp", port, unexpected, include_port=False,
    )
    manifest = _standalone_manifest(
        name,
        xml,
        raw_targets=[requested],
        exclude=[],
        closure_targets=[requested],
        stage_id="single",
    )
    before_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}

    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (name, xml, "text/xml")),
        ("files", ("single.manifest.json", manifest, "application/json")),
    ])

    assert response.status_code == 400, response.text
    assert "unit target" in response.json()["detail"]
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == 0
        assert db.query(Finding).count() == 0
    finally:
        db.close()
    after_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}
    assert after_files == before_files


def test_strong_stage_bundle_host_mismatch_is_atomic(client, monkeypatch, tmp_path):
    """A later mismatched unit must reject the bundle before a valid unit can close data."""
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import Finding, FindingEvent, ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    monkeypatch.setattr(scans_api._settings, "scan_scope", "127.0.0.0/8")
    scans_api._settings.ensure_dirs()
    requested, unexpected = "127.0.0.1", "192.0.2.56"
    tcp_port, udp_port = 54449, 54450
    initial = _scan_xml(
        1893456000,
        '<scaninfo type="syn" protocol="tcp" numservices="1" '
        f'services="{tcp_port}"/><scaninfo type="udp" protocol="udp" '
        f'numservices="1" services="{udp_port}"/>',
        _port("tcp", tcp_port) + _port("udp", udp_port),
        host=requested,
    )
    assert client.post(
        "/api/scans/import", headers=h,
        files={"file": ("seed.xml", initial, "text/xml")},
    ).status_code == 200

    tcp_name = "mismatch.tcp_discovery.xml"
    udp_name = "mismatch.udp_identify.xml"
    tcp_xml = _standalone_empty_xml(1893456300, "tcp", str(tcp_port), total=1)
    udp_xml = _standalone_observed_xml(1893456301, "udp", udp_port, unexpected)
    manifest = json.loads(_standalone_manifest(
        tcp_name,
        tcp_xml,
        raw_targets=[requested],
        exclude=[],
        closure_targets=[requested],
    ))
    manifest["import_contract"]["units"].append({
        "batch_index": 0,
        "stage_id": "udp_identify",
        "authoritative": True,
        "closure_targets": [requested],
        "xml_basename": udp_name,
        "xml_size": len(udp_xml),
        "xml_sha256": hashlib.sha256(udp_xml).hexdigest(),
    })
    db = SessionLocal()
    try:
        before_scans = db.query(ScanRun).count()
        before_events = db.query(FindingEvent).count()
    finally:
        db.close()
    before_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}

    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (tcp_name, tcp_xml, "text/xml")),
        ("files", (udp_name, udp_xml, "text/xml")),
        ("files", ("mismatch.manifest.json", json.dumps(manifest).encode(), "application/json")),
    ])

    assert response.status_code == 400, response.text
    assert "unit target" in response.json()["detail"]
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == before_scans
        assert db.query(FindingEvent).count() == before_events
        rows = {
            (row.host_ip, row.proto, row.port): row.state
            for row in db.query(Finding).all()
        }
        assert rows[(requested, "tcp", tcp_port)] == "open"
        assert rows[(requested, "udp", udp_port)] == "open"
        assert not any(host == unexpected for host, _proto, _port_num in rows)
    finally:
        db.close()
    after_files = {path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file()}
    assert after_files == before_files


@pytest.mark.parametrize("break_contract", ["schema", "hash", "exclude", "count"])
def test_invalid_standalone_manifest_is_atomic(client, break_contract):
    """인식된 strong 계약은 손상 시 legacy로 강등하지 않고 어떤 부작용도 없이 거절한다."""
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    h = _auth(client)
    host, excluded, port = "127.0.0.1", "127.0.0.2", 54444
    initial = _scan_xml(
        1893456000,
        f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
        _port("tcp", port),
        host=host,
    )
    assert client.post(
        "/api/scans/import", headers=h,
        files={"file": ("initial.xml", initial, "text/xml")},
    ).status_code == 200
    before_scans = len(client.get("/api/scans", headers=h).json())

    name = "bad.tcp_discovery.xml"
    empty = _standalone_empty_xml(1893456100, "tcp", str(port), total=1)
    manifest = json.loads(_standalone_manifest(
        name,
        empty,
        raw_targets=[host, excluded],
        exclude=[excluded],
        closure_targets=[host],
    ))
    contract = manifest["import_contract"]
    if break_contract == "schema":
        contract["schema"] = 99
    elif break_contract == "hash":
        contract["units"][0]["xml_sha256"] = "0" * 64
    elif break_contract == "exclude":
        contract["units"][0]["closure_targets"] = [excluded]
    else:
        contract["effective_host_count"] = 2

    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (name, empty, "text/xml")),
        ("files", ("bad.manifest.json", json.dumps(manifest).encode(), "application/json")),
    ])
    assert response.status_code == 400, response.text
    assert len(client.get("/api/scans", headers=h).json()) == before_scans
    db = SessionLocal()
    try:
        row = db.query(Finding).filter_by(finding_key=f"{host}|{port}|tcp").one()
        assert row.state == "open"
        assert db.query(ScanRun).count() == before_scans
    finally:
        db.close()


def test_strong_bundle_uses_protocol_specific_closure_targets(client):
    """TCP 전체 batch 권한이 실제 UDP subset까지 교차 확장되어서는 안 된다."""
    h = _auth(client)
    first, second = "127.0.0.1", "127.0.0.2"
    tcp_port, udp_port = 54445, 54446
    for index, host in enumerate((first, second)):
        initial = _scan_xml(
            1893456000 + index,
            '<scaninfo type="syn" protocol="tcp" numservices="1" '
            f'services="{tcp_port}"/><scaninfo type="udp" protocol="udp" '
            f'numservices="1" services="{udp_port}"/>',
            _port("tcp", tcp_port) + _port("udp", udp_port),
            host=host,
        )
        assert client.post(
            "/api/scans/import", headers=h,
            files={"file": (f"seed-{index}.xml", initial, "text/xml")},
        ).status_code == 200

    tcp_name = "unit.tcp_discovery.xml"
    udp_name = "unit.udp_identify.xml"
    tcp_xml = _standalone_empty_xml(1893456100, "tcp", str(tcp_port), total=2)
    udp_xml = _standalone_empty_xml(1893456101, "udp", str(udp_port), total=1)
    manifest = json.loads(_standalone_manifest(
        tcp_name,
        tcp_xml,
        raw_targets=[first, second],
        exclude=[],
        closure_targets=[first, second],
    ))
    manifest["import_contract"]["units"].append({
        "batch_index": 0,
        "stage_id": "udp_identify",
        "authoritative": True,
        "closure_targets": [first],
        "xml_basename": udp_name,
        "xml_size": len(udp_xml),
        "xml_sha256": hashlib.sha256(udp_xml).hexdigest(),
    })
    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (tcp_name, tcp_xml, "text/xml")),
        ("files", (udp_name, udp_xml, "text/xml")),
        ("files", ("unit.manifest.json", json.dumps(manifest).encode(), "application/json")),
    ])

    assert response.status_code == 200, response.text
    rows = {
        (row["host_ip"], row["proto"], row["port"]): row["state"]
        for row in client.get("/api/findings?state=", headers=h).json()
    }
    assert rows[(first, "tcp", tcp_port)] == "closed"
    assert rows[(second, "tcp", tcp_port)] == "closed"
    assert rows[(first, "udp", udp_port)] == "closed"
    assert rows[(second, "udp", udp_port)] == "open"


def test_observation_only_manifest_unit_cannot_close_missing_finding(client):
    """TCP identify/실패 unit은 XML이 성공 형태여도 manifest 권한이 false면 가산만 한다."""
    h = _auth(client)
    host, port = "127.0.0.1", 54447
    initial = _scan_xml(
        1893456000,
        f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{port}"/>',
        _port("tcp", port),
        host=host,
    )
    assert client.post(
        "/api/scans/import", headers=h,
        files={"file": ("seed.xml", initial, "text/xml")},
    ).status_code == 200

    name = "observe.tcp_identify.xml"
    empty = _standalone_empty_xml(1893456100, "tcp", str(port), total=1)
    manifest = _standalone_manifest(
        name,
        empty,
        raw_targets=[host],
        exclude=[],
        closure_targets=[],
        stage_id="tcp_identify",
        authoritative=False,
    )
    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (name, empty, "text/xml")),
        ("files", ("observe.manifest.json", manifest, "application/json")),
    ])

    assert response.status_code == 200, response.text
    assert response.json()["counts"]["closed"] == 0
    row = next(
        row for row in client.get("/api/findings?state=", headers=h).json()
        if row["host_ip"] == host and row["port"] == port and row["proto"] == "tcp"
    )
    assert row["state"] == "open"


def test_observation_only_manifest_rejects_finding_outside_effective_batch(client):
    """Observation-only units may add evidence, but only for their declared batch."""
    from scanops.db import SessionLocal
    from scanops.models import Finding, ScanRun

    h = _auth(client)
    requested, unexpected, port = "127.0.0.1", "127.0.0.2", 54451
    name = "observe-mismatch.tcp_identify.xml"
    xml = _standalone_observed_xml(1893456400, "tcp", port, unexpected)
    manifest = _standalone_manifest(
        name,
        xml,
        raw_targets=[requested],
        exclude=[],
        closure_targets=[],
        stage_id="tcp_identify",
        authoritative=False,
    )

    response = client.post("/api/scans/import-bundle", headers=h, files=[
        ("files", (name, xml, "text/xml")),
        ("files", ("observe-mismatch.manifest.json", manifest, "application/json")),
    ])

    assert response.status_code == 400, response.text
    assert "unit target" in response.json()["detail"]
    db = SessionLocal()
    try:
        assert db.query(ScanRun).count() == 0
        assert db.query(Finding).count() == 0
    finally:
        db.close()


def _run_xml(args: str, ports: str, start: int = 1_700_000_000,
             host: str = "127.0.0.1") -> bytes:
    """`<nmaprun args=...>` 까지 갖춘 XML — 실행 인자로 sweep/식별을 구분하는 경로용."""
    return f"""<?xml version="1.0"?>
<nmaprun start="{start}" args="{args}">
  <scaninfo type="syn" protocol="tcp" services="22"/>
  <host>
    <status state="up"/>
    <address addr="{host}" addrtype="ipv4"/>
    <ports>
      {ports}
    </ports>
  </host>
</nmaprun>
""".encode()


_IDENTIFIED_SSH = (
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" method="probed" conf="10" product="OpenSSH" version="8.9p1"/>'
    "</port>"
)
_SWEPT_SSH = (
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" method="table" conf="3"/>'
    "</port>"
)


def test_probed_identity_reads_the_run_arguments():
    from scanops.scanning.nmap_parse import probed_identity

    assert probed_identity(_run_xml("nmap -sS -sV -p 22 10.0.0.1", _IDENTIFIED_SSH)) is True
    assert probed_identity(_run_xml("nmap -A -p 22 10.0.0.1", _IDENTIFIED_SSH)) is True
    # -s 뒤의 스캔 타입 문자는 붙여 쓸 수 있다. -sSV 를 sweep 으로 보면 진짜 식별이 반영되지 않는다.
    assert probed_identity(_run_xml("nmap -sSV -p 22 10.0.0.1", _IDENTIFIED_SSH)) is True
    assert probed_identity(_run_xml("nmap -sSUV -p 22 10.0.0.1", _IDENTIFIED_SSH)) is True
    assert probed_identity(_run_xml("nmap -sS -p T:1-65535 10.0.0.1", _SWEPT_SSH)) is False
    assert probed_identity(_run_xml("nmap -sSU -p 22 10.0.0.1", _SWEPT_SSH)) is False
    assert probed_identity(_run_xml("nmap -sn 10.0.0.0/24", _SWEPT_SSH)) is False
    # args 가 없는 XML 은 판단하지 않는다 — 여기서 '식별 아님'으로 몰면 정상 인입이 멈춘다.
    assert probed_identity(_scan_xml(1, "", _IDENTIFIED_SSH)) is None


def test_a_sweep_never_overwrites_observed_identity_even_if_the_filename_hides_the_stage(client):
    """포트만 훑은 실행이 앞서 관측한 식별을 포트 표 이름으로 덮지 않는다.

    발견 단계 sweep 도 nmap 은 `service name="ssh"`(포트 표)를 채워 넣는다. 단계는 보통
    파일명으로 읽지만, 중단본 번호나 사람이 바꾼 이름이면 그 단서가 사라진다. 그때도
    XML 자신의 실행 인자(-sV 없음)로 sweep 임을 알아야 한다."""
    h = _auth(client)

    identified = _run_xml("nmap -sS -sV --version-all -p 22 127.0.0.1", _IDENTIFIED_SSH)
    r = client.post("/api/scans/import", headers=h,
                    files={"file": ("scan_a.tcp_identify.xml", identified, "text/xml")})
    assert r.status_code == 200, r.text
    before = client.get("/api/findings", headers=h).json()
    assert [f["display_identity"] for f in before] == ["OpenSSH 8.9p1"]

    # 파일명에서 단계를 못 읽는 형태(중단본 번호가 뒤에 붙은 옛 이름)로 sweep 을 넣는다.
    swept = _run_xml("nmap -sS -p T:1-65535 127.0.0.1", _SWEPT_SSH)
    r2 = client.post("/api/scans/import", headers=h,
                     files={"file": ("scan_a.tcp_discovery-2.xml", swept, "text/xml")})
    assert r2.status_code == 200, r2.text

    after = client.get("/api/findings", headers=h).json()
    assert len(after) == 1
    assert after[0]["display_identity"] == "OpenSSH 8.9p1"
    assert after[0]["product"] == "OpenSSH" and after[0]["version"] == "8.9p1"


def test_interrupted_scan_results_are_rejected_on_import(client):
    """중단된 스캔은 어떤 경로로도 발견 관리에 들어오지 않는다.

    부분 결과는 열린 포트를 다 보지 못한 상태다. 관측으로 받으면 못 본 포트가 미탐이
    되고, 재시도가 잘린 자리의 filtered 를 믿으면 오탐이 된다. 스캐너가 올리지 않지만
    사람이 파일을 끌어다 놓는 경로가 남아 있으므로 서버에서도 막는다."""
    h = _auth(client)
    swept = _run_xml("nmap -sS -p T:1-65535 127.0.0.1", _SWEPT_SSH)

    single = client.post(
        "/api/scans/import", headers=h,
        files={"file": ("scan.10_0_0_1.tcp_discovery.interrupted.xml", swept, "text/xml")},
    )
    assert single.status_code == 400
    assert "중단된 스캔" in single.json()["detail"]

    bundle = client.post(
        "/api/scans/import-bundle", headers=h,
        files=[("files", ("interrupted/scan.10_0_0_1.tcp_identify.xml", swept, "text/xml"))],
    )
    assert bundle.status_code == 400
    assert "중단된 스캔" in bundle.json()["detail"]

    assert client.get("/api/findings", headers=h).json() == []


def test_a_complete_result_named_like_a_report_still_imports(client):
    """'interrupted' 가 이름 일부일 뿐인 온전한 결과까지 막으면 안 된다."""
    h = _auth(client)
    identified = _run_xml("nmap -sS -sV -p 22 127.0.0.1", _IDENTIFIED_SSH)
    r = client.post("/api/scans/import", headers=h,
                    files={"file": ("interrupted_hosts_report.xml", identified, "text/xml")})
    assert r.status_code == 200, r.text
    assert len(client.get("/api/findings", headers=h).json()) == 1


def test_scan_summary_says_전체_instead_of_a_port_count(client):
    """이력 표는 명령줄이 아니라 요약을 보여준다 — 전체는 '전체'라고 적는다."""
    from scanops.scanning.scan_summary import summarize_command

    full = summarize_command(
        "nmap -sS -p T:1-65535 --stats-every 10s 10.0.0.0/24", "10.0.0.0/24")
    assert full["ports"] == "전체" and full["protocols"] == ["TCP"]
    assert full["targets"] == "10.0.0.0 – 10.0.0.255 · 대상 256대"

    # 전체에서 일부만 뺀 경우는 개수가 아니라 그 사실이 중요하다.
    partial = summarize_command(
        "nmap -sS -p 1-65535 --exclude-ports 9100,515 --exclude 10.0.0.9 10.0.0.0/24",
        "10.0.0.0/24")
    assert partial["ports"] == "전체 (일부 제외)"
    assert partial["excluded_ports"] == "9100,515"
    assert partial["targets"] == "10.0.0.0 – 10.0.0.255 · 대상 255대"

    # 두 프로토콜을 다른 범위로 스캔했으면 둘 다 적는다. TCP 범위만 보이면 그 옆의 UDP
    # 뱃지와 붙어 'UDP 도 22,80 을 봤다'로 읽힌다 - 실제로는 53 하나뿐이다.
    both = summarize_command("nmap -sS -sU -p T:22,80,U:53 10.0.0.1", "10.0.0.1")
    assert both["protocols"] == ["TCP", "UDP"] and both["ports"] == "TCP 22,80 · UDP 53"

    # 접두사가 없으면 두 프로토콜이 같은 범위라 나눠 적을 것이 없다.
    shared = summarize_command("nmap -sS -sU -p 1-1024 10.0.0.1", "10.0.0.1")
    assert shared["ports"] == "1-1024"

    top = summarize_command("nmap -sT --top-ports 1000 10.0.0.1", "10.0.0.1")
    assert top["ports"] == "상위 1000개"

    many = summarize_command("nmap -sS -p 1-65535 10.0.0.1 10.0.0.2 10.0.0.3",
                             "10.0.0.1 10.0.0.2 10.0.0.3")
    assert many["targets"] == "10.0.0.1 – 10.0.0.3 · 대상 3대"

    unordered = summarize_command(
        "nmap -sS -p 22 10.0.0.9 10.0.0.2 10.0.0.15", "10.0.0.9 10.0.0.2 10.0.0.15")
    assert unordered["targets"] == "10.0.0.2 – 10.0.0.15 · 대상 3대"


def test_scan_list_carries_the_summary(client):
    from scanops.db import SessionLocal
    from scanops.models import ScanRun

    h = _auth(client)
    db = SessionLocal()
    db.add(ScanRun(name="t", targets="10.0.0.0/24", status="done",
                   command="nmap -sS -p T:1-65535 --exclude-ports 9100 10.0.0.0/24"))
    db.commit(); db.close()

    rows = client.get("/api/scans", headers=h).json()
    assert rows[0]["summary"]["ports"] == "전체 (일부 제외)"
    assert rows[0]["summary"]["protocols"] == ["TCP"]
    assert rows[0]["command"]          # 원문은 상세에서 볼 수 있게 남아 있다


def test_timed_out_hosts_are_retained_and_retried_as_a_narrow_staged_scan(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.scans_dir.mkdir(parents=True)
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    db = SessionLocal()
    source = ScanRun(
        name="원본", targets="10.0.0.1 10.0.0.2 10.0.0.3", status="done",
        command="단계스캔(엔진) · TCP 전체 · UDP 53 · --exclude-ports 2222",
    )
    db.add(source)
    db.commit()
    source_id = source.id
    db.close()

    source_dir = scans_api._settings.scans_dir / f"scan_{source_id}"
    source_dir.mkdir()
    spec = {
        "job_id": f"scan_{source_id}",
        "targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "exclude": ["10.0.0.99"], "exclude_ports": "2222", "batch_size": 2,
        "out_dir": str(source_dir),
        "stages": {
            "discovery": {"enabled": True, "mode": "sn"},
            "tcp": {"enabled": True, "ports": "1-65535"},
            "udp": {"enabled": True, "ports": "53"},
            "service": {"enabled": True, "version_all": False},
        },
        "scanops": {"scope_keys": [
            "10.0.0.1|22|tcp", "10.0.0.2|443|tcp", "10.0.0.3|53|udp",
        ]},
    }
    (source_dir / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    (source_dir / "run-state.json").write_text(json.dumps({
        "gave_up": ["10.0.0.3", "10.0.0.2"],
        "gave_up_by_stage": {
            "tcp": ["10.0.0.2"], "service:udp": ["10.0.0.3"],
        },
        "retransmission_cap_by_stage": {"udp": ["10.0.0.1"]},
    }), encoding="utf-8")

    before = client.get("/api/scans", headers=h).json()[0]
    assert before["retry_status"] == "required"
    assert before["retry_count"] == 3
    assert before["retry_stages"] == ["tcp", "service:udp", "udp"]

    response = client.post(f"/api/scans/{source_id}/retry-timeouts", headers=h)
    assert response.status_code == 200, response.text
    child_id = response.json()["id"]
    child_spec = json.loads((
        scans_api._settings.scans_dir / f"scan_{child_id}" / "spec.json"
    ).read_text(encoding="utf-8"))
    assert child_spec["targets"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert child_spec["exclude"] == []
    assert child_spec["exclude_ports"] == "2222"
    assert child_spec["stages"]["discovery"] == {"enabled": True, "mode": "pn"}
    assert all(
        child_spec["stages"][stage]["max_retries"] == 4
        for stage in ("tcp", "udp", "service")
    )
    assert child_spec["scanops"]["scope_keys"] == [
        "10.0.0.1|22|tcp", "10.0.0.2|443|tcp", "10.0.0.3|53|udp",
    ]
    assert child_spec["scanops"]["retry_of"] == source_id
    assert child_spec["scanops"]["retry_targets"] == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]

    history = client.get("/api/scans", headers=h).json()
    original = next(scan for scan in history if scan["id"] == source_id)
    assert original["retry_status"] == "running"
    assert original["retry_required"] is False
    assert original["retry_scan_id"] == child_id
    duplicate = client.post(f"/api/scans/{source_id}/retry-timeouts", headers=h)
    assert duplicate.status_code == 400 and "이미 진행 중" in duplicate.json()["detail"]

    db = SessionLocal()
    child = db.get(ScanRun, child_id)
    child.status = "done"
    db.commit()
    db.close()
    resolved = client.get("/api/scans", headers=h).json()
    original = next(scan for scan in resolved if scan["id"] == source_id)
    assert original["retry_status"] == "resolved"
    again = client.post(f"/api/scans/{source_id}/retry-timeouts", headers=h)
    assert again.status_code == 400 and "이미 완료" in again.json()["detail"]


def test_durable_retry_resolves_only_exact_successful_host_and_stage_and_delete_reopens(
    client, tmp_path, monkeypatch,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanQualityIssue, ScanRun
    from scanops.scanning import observability

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    db = SessionLocal()
    try:
        source = ScanRun(name="source", status="done")
        child = ScanRun(name="child", status="running")
        db.add_all([source, child])
        db.flush()
        observability.materialize_terminal_observability(db, source.id, issues=[
            {"issue_key": "tcp-a", "kind": "host_timeout", "stage": "tcp",
             "host_ip": "10.0.0.1", "detail": "tcp timeout"},
            {"issue_key": "tcp-b", "kind": "host_timeout", "stage": "tcp",
             "host_ip": "10.0.0.2", "detail": "tcp timeout"},
            {"issue_key": "udp-a", "kind": "host_timeout", "stage": "udp",
             "host_ip": "10.0.0.1", "detail": "udp timeout"},
        ])
        observability.set_quality_retry(
            db, source.id, child.id, issue_keys=["tcp-a", "tcp-b", "udp-a"],
        )
        source_id, child_id = source.id, child.id
        db.commit()
    finally:
        db.close()

    child_dir = scans_api._settings.scans_dir / f"scan_{child_id}"
    child_dir.mkdir(parents=True)
    spec = {
        "targets": ["10.0.0.1", "10.0.0.2"],
        "scanops": {"retry_of": source_id},
    }
    (child_dir / "events.ndjson").write_text("\n".join(json.dumps(event) for event in [
        {"event": "stage_plan", "stages": ["tcp"]},
        {"event": "command_start", "stage": "tcp", "execution_id": "retry-tcp",
         "group": "common", "role": "authority", "reason": "retry",
         "artifact": "stage-tcp-b0", "argv": ["nmap", "10.0.0.1", "10.0.0.2"],
         "ts": 10},
        {"event": "command_done", "stage": "tcp", "execution_id": "retry-tcp",
         "outcome": "timeout", "seconds": 2, "rc": 0,
         "timed_out": ["10.0.0.2"], "timeout_count": 1,
         "retransmission_cap_hosts": [], "retransmission_cap_count": 0, "ts": 12},
        {"event": "job_done", "status": "done", "seconds": 2, "counts": {}},
    ]), encoding="utf-8")
    (child_dir / "run-state.json").write_text(json.dumps({
        "live": ["10.0.0.1", "10.0.0.2"],
        "coverage": [{
            "artifact": "stage-tcp-b0.xml", "proto": "tcp", "role": "authority",
            "hosts": ["10.0.0.1", "10.0.0.2"], "ports": "T:1-65535", "finished": True,
        }],
    }), encoding="utf-8")

    db = SessionLocal()
    try:
        child = db.get(ScanRun, child_id)
        scans_api._materialize_engine_terminal(
            db, child, child_dir, spec,
            {name: [] for name in (
                "authority_missing", "authority_broken",
                "enrichment_missing", "enrichment_broken",
            )}, [],
        )
        child.status = "done"
        db.commit()
        by_key = {
            issue.issue_key: issue for issue in db.query(ScanQualityIssue).filter_by(
                scan_id=source_id
            )
        }
        assert by_key["tcp-a"].resolved_by_scan_id == child_id
        assert by_key["tcp-b"].resolved_by_scan_id is None
        assert by_key["udp-a"].resolved_by_scan_id is None
    finally:
        db.close()

    listed = next(row for row in client.get("/api/scans", headers=h).json()
                  if row["id"] == source_id)
    detailed = client.get(f"/api/scans/{source_id}", headers=h).json()
    assert listed["retry_status"] == detailed["retry_status"] == "required"
    assert listed["retry_count"] == detailed["retry_count"] == 2
    import shutil
    shutil.rmtree(child_dir)
    stages = client.get(f"/api/scans/{child_id}/stages", headers=h).json()
    assert stages["source"] == "db"
    assert stages["executions"][0]["id"] == "retry-tcp"
    assert stages["hosts"][0]["tcp_sweep_status"] in {"done", "timeout"}

    make_user("delete-admin", "delete-pass-1234", role="admin")
    admin = {"Authorization": f"Bearer {token_for(client, 'delete-admin', 'delete-pass-1234')}"}
    assert client.delete(f"/api/scans/{child_id}", headers=admin).status_code == 200
    db = SessionLocal()
    try:
        by_key = {
            issue.issue_key: issue for issue in db.query(ScanQualityIssue).filter_by(
                scan_id=source_id
            )
        }
        assert all(issue.retry_scan_id is None for issue in by_key.values())
        assert all(issue.resolved_by_scan_id is None for issue in by_key.values())
    finally:
        db.close()
    reopened = next(row for row in client.get("/api/scans", headers=h).json()
                    if row["id"] == source_id)
    assert reopened["retry_status"] == "required"
    assert reopened["retry_count"] == 2
    assert reopened["unresolved_issue_count"] == 3


def test_scan_list_and_detail_expose_the_same_creator_and_quality_summary(client):
    from scanops.db import SessionLocal
    from scanops.models import ScanRun, User
    from scanops.scanning import observability

    make_user("scan-owner", "owner-pass-1234", role="auditor")
    h = {"Authorization": f"Bearer {token_for(client, 'scan-owner', 'owner-pass-1234')}"}
    db = SessionLocal()
    try:
        owner = db.query(User).filter_by(username="scan-owner").one()
        scan = ScanRun(name="owned", status="done", created_by=owner.id)
        db.add(scan)
        db.flush()
        observability.materialize_terminal_observability(db, scan.id, issues=[{
            "issue_key": "cap-a", "kind": "retransmission_cap", "stage": "tcp",
            "host_ip": "10.0.0.9", "detail": "max retries 2",
        }])
        scan_id = scan.id
        db.commit()
    finally:
        db.close()

    listed = next(row for row in client.get("/api/scans", headers=h).json()
                  if row["id"] == scan_id)
    detail = client.get(f"/api/scans/{scan_id}", headers=h).json()

    for key in (
        "created_by", "created_by_name", "quality_status", "unresolved_issue_count",
        "unresolved_host_count", "retry_status", "retry_count", "retry_stages",
    ):
        assert detail[key] == listed[key]
    assert listed["created_by_name"] == "scan-owner"
    assert listed["quality_status"] == "warning"
    assert listed["unresolved_issue_count"] == listed["unresolved_host_count"] == 1


def test_retry_endpoint_uses_durable_issues_when_run_state_is_missing(
    client, monkeypatch, tmp_path,
):
    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanQualityIssue, ScanRun
    from scanops.scanning import observability

    h = _auth(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(scans_api.engine_runner, "ensure_available", lambda: None)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    db = SessionLocal()
    try:
        source = ScanRun(name="durable source", status="done", targets="10.0.0.2")
        db.add(source)
        db.flush()
        observability.materialize_terminal_observability(db, source.id, issues=[{
            "issue_key": "tcp-timeout", "kind": "host_timeout", "stage": "tcp",
            "host_ip": "10.0.0.2", "detail": "timeout",
        }])
        source_id = source.id
        db.commit()
    finally:
        db.close()
    source_dir = scans_api._settings.scans_dir / f"scan_{source_id}"
    source_dir.mkdir()
    (source_dir / "spec.json").write_text(json.dumps({
        "job_id": f"scan_{source_id}", "targets": ["10.0.0.2"], "exclude": [],
        "exclude_ports": "", "batch_size": 1, "out_dir": str(source_dir),
        "stages": {
            "discovery": {"enabled": True, "mode": "sn"},
            "tcp": {"enabled": True, "ports": "1-65535", "max_retries": 2},
            "udp": {"enabled": False, "ports": "", "max_retries": 2},
            "service": {"enabled": True, "max_retries": 2, "version_all": False},
        },
        "scanops": {"scope_keys": ["10.0.0.2|443|tcp"]},
    }), encoding="utf-8")
    assert not (source_dir / "run-state.json").exists()

    response = client.post(f"/api/scans/{source_id}/retry-timeouts", headers=h)

    assert response.status_code == 200, response.text
    child_id = response.json()["id"]
    child_spec = json.loads((
        scans_api._settings.scans_dir / f"scan_{child_id}" / "spec.json"
    ).read_text(encoding="utf-8"))
    assert child_spec["targets"] == ["10.0.0.2"]
    assert child_spec["scanops"]["retry_stages"] == ["tcp"]
    db = SessionLocal()
    try:
        issue = db.query(ScanQualityIssue).filter_by(
            scan_id=source_id, issue_key="tcp-timeout",
        ).one()
        assert issue.retry_scan_id == child_id
        assert issue.resolved_by_scan_id is None
    finally:
        db.close()


def test_deleting_a_scan_removes_only_the_findings_it_alone_proves(client):
    """스캔 삭제는 그 스캔이 유일한 근거인 발견만 지운다.

    여러 스캔에 걸쳐 살아 있는 발견까지 지우면 사람이 달아 둔 상태·메모와 이전 이력이
    함께 사라진다. 살아남는 발견은 사라진 스캔을 가리키지 않도록 참조만 끊는다."""
    from scanops.db import SessionLocal
    from scanops.models import Finding, FindingEvent, ScanRun

    make_user("boss", "boss-pass-1234", role="admin")
    admin = {"Authorization": f"Bearer {token_for(client, 'boss', 'boss-pass-1234')}"}

    db = SessionLocal()
    old, new = ScanRun(name="old", status="done"), ScanRun(name="new", status="done")
    db.add_all([old, new]); db.commit()
    only_new = Finding(finding_key="127.0.0.1|1234|tcp", host_ip="127.0.0.1", port=1234,
                       proto="tcp", state="open", first_scan_id=new.id, last_scan_id=new.id)
    spanning = Finding(finding_key="127.0.0.1|22|tcp", host_ip="127.0.0.1", port=22,
                       proto="tcp", state="open", first_scan_id=old.id, last_scan_id=new.id)
    db.add_all([only_new, spanning]); db.commit()
    db.add(FindingEvent(finding_id=spanning.id, scan_id=new.id, type="NEW_OPEN"))
    db.commit()
    new_id, spanning_id = new.id, spanning.id
    db.close()

    r = client.delete(f"/api/scans/{new_id}", headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["findings_deleted"] == 1

    db = SessionLocal()
    try:
        assert db.get(ScanRun, new_id) is None
        rows = db.query(Finding).all()
        assert [f.port for f in rows] == [22]              # 걸쳐 있던 발견은 남는다
        kept = db.get(Finding, spanning_id)
        assert kept.last_scan_id is None                    # 사라진 스캔을 가리키지 않는다
        assert all(e.scan_id is None for e in db.query(FindingEvent).all())
    finally:
        db.close()


def test_scan_delete_needs_admin_and_refuses_while_running(client):
    from scanops.db import SessionLocal
    from scanops.models import ScanRun

    auditor = _auth(client)
    db = SessionLocal()
    running, done = ScanRun(name="r", status="running"), ScanRun(name="d", status="done")
    db.add_all([running, done]); db.commit()
    running_id, done_id = running.id, done.id
    db.close()

    assert client.delete(f"/api/scans/{done_id}", headers=auditor).status_code == 403

    make_user("boss2", "boss-pass-1234", role="admin")
    admin = {"Authorization": f"Bearer {token_for(client, 'boss2', 'boss-pass-1234')}"}
    stopped = client.delete(f"/api/scans/{running_id}", headers=admin)
    assert stopped.status_code == 409 and "중지" in stopped.json()["detail"]
    assert client.delete(f"/api/scans/{done_id}", headers=admin).status_code == 200
    assert client.delete(f"/api/scans/{done_id}", headers=admin).status_code == 404


def test_engine_log_problems_finds_what_the_xml_never_records():
    """rc=0 · exit="success" 인 실행에서도 NSE/소켓 실패는 로그에만 남는다."""
    import tempfile
    from pathlib import Path as _Path
    from scanops.scanning import engine_runner

    with tempfile.TemporaryDirectory() as tmp:
        log = _Path(tmp) / "engine.log"
        log.write_bytes(
            "Service scan Timing: About 100.00% done\n"
            "NSOCK ERROR mksock_bind_addr(): Bind to 0.0.0.0:500 failed (IOD#4)\n"
            "Trying to delete NSI, but could not find 1 of the purportedly pending events\n"
            .encode("utf-8"))
        problems = engine_runner.log_problems(log)
        assert len(problems) == 2 and "NSOCK ERROR" in problems[0]

        # 조용히 성공한 실행까지 의심하면 닫힘이 영영 안 된다.
        quiet = _Path(tmp) / "quiet.log"
        quiet.write_bytes(b"Nmap done: 9 IP addresses (9 hosts up)\n")
        assert engine_runner.log_problems(quiet) == []
        # 로그가 없어도 터지지 않는다.
        assert engine_runner.log_problems(_Path(tmp) / "missing.log") == []


def test_watchdog_out_of_range_is_rejected_before_any_job_is_created(client, monkeypatch):
    """요청 경계에서 걸러야 한다 - 레거시 경로는 이 값을 threading.Timer 에 그대로 넘긴다.

    제약 없는 int 였을 때 -1 · 86401 · 10**100 이 전부 통과했다. 마지막 값은
    threading.TIMEOUT_MAX(약 9.2e9)를 넘어 타이머 스레드가 OverflowError 로 즉시 죽는다 -
    API 는 스캔을 시작했다고 응답하는데 상한만 조용히 사라진다. 사용자가 켰다고 믿는 보호가
    없는 채로 도는, 가장 나쁜 실패 방식이다.

    그래서 **작업을 만들기 전에** 422 로 거절하고, 스캔 행도 남지 않아야 한다.
    """
    from scanops.api import scans as scans_api
    from scanops.scanning import chunker

    h = _auth(client, "admin")
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", NoopThread)
    body = {
        "name": "wd", "workflow": "auto", "options": ["syn"], "ports": "T:80",
        "targets": ["127.0.0.1"], "batch_size": 256,
    }
    before_count = len(client.get("/api/scans", headers=h).json())

    for bad in (-1, 86401, 10 ** 100):
        for endpoint in ("/api/scans/run", "/api/scans/run-staged"):
            payload = {**body, "watchdog_seconds": bad}
            if endpoint.endswith("run-staged"):
                payload["discovery"] = "pn"
            response = client.post(endpoint, headers=h, json=payload)
            assert response.status_code == 422, (
                f"{endpoint} 가 watchdog_seconds={bad} 를 수락했다: {response.text[:200]}")

    # 거절된 요청이 스캔 행을 남기면 안 된다 - '시작했다'는 흔적만 남는 것이 더 나쁘다.
    assert len(client.get("/api/scans", headers=h).json()) == before_count

    # 경계값은 그대로 받아야 한다(과잉 거절이 아니어야 한다).
    ok = client.post("/api/scans/run", headers=h,
                     json={**body, "watchdog_seconds": 86400})
    assert ok.status_code == 200, ok.text
    state = chunker.read_state(scans_api._basename(ok.json()["id"]))
    assert state["watchdog_seconds"] == 86400


def test_windows_ansi_error_text_does_not_hide_the_marker():
    """오류 문구가 ANSI 코드페이지라 UTF-8 로 못 읽혀도 표식 탐지는 살아 있어야 한다."""
    import tempfile
    from pathlib import Path as _Path
    from scanops.scanning import engine_runner

    with tempfile.TemporaryDirectory() as tmp:
        log = _Path(tmp) / "engine.log"
        log.write_bytes(
            b"NSOCK ERROR mksock_bind_addr(): Bind to 0.0.0.0:500 failed "
            + "액세스 권한에 의해 금지된 방법".encode("cp949") + b" (10013)\n")
        assert engine_runner.log_problems(log)


# ── 단계 스캔 결과 폴더 가져오기 ──

_ENGINE_SN = (
    '<?xml version="1.0"?><nmaprun start="1782050000">'
    '<host><status state="up" reason="echo-reply"/>'
    '<address addr="127.0.0.1" addrtype="ipv4"/></host>'
    '<runstats><finished time="1782050000" exit="success"/>'
    '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
).encode()


def _engine_files(run="scan_7"):
    """단계 엔진이 결과 폴더에 실제로 남기는 이름들."""
    tcp = '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>'
    udp = '<scaninfo type="udp" protocol="udp" numservices="1" services="161"/>'
    return [
        (f"{run}/stage0-discovery.xml", _ENGINE_SN),
        (f"{run}/stage-tcp-b0.xml", _scan_xml(1782050001, tcp,
                                              _port("tcp", 22) + _port("tcp", 80))),
        (f"{run}/stage-udp-b0.xml", _scan_xml(1782050002, udp,
                                              _port("udp", 161, service="svc"))),
        (f"{run}/stage3-tcp-b0-g0.xml", _scan_xml(1782050003, tcp,
                                                  _port("tcp", 22, service="ssh")
                                                  + _port("tcp", 80, service="http"))),
        (f"{run}/stage3-udp-b0-g0.xml", _scan_xml(1782050004, udp,
                                                  _port("udp", 161, service="snmp"))),
    ]


def _upload(client, h, files):
    return client.post(
        "/api/scans/import-bundle", headers=h,
        files=[("files", (n, b, "application/octet-stream")) for n, b in files],
    )


def test_every_artifact_the_engine_writes_is_recognised_as_part_of_its_run(client):
    """엔진이 남기는 이름을 하나라도 못 알아보면 그 파일만 낱개 행으로 떨어진다.

    호스트 격리 재시도의 접미사는 프로토콜(`tcp`)일 때도 있고 포트가 붙은 tag(`tcp443`,
    `udp161`)일 때도 있다 - 후자를 놓치면 공통 실행이 실패해 격리로 넘어간 호스트의 결과가
    이력에 따로 흩어진다. 마침 그런 실행이 가장 봐야 할 실행이다.

    묶음은 **실제 배치**(`bN`)로 하고, 같은 배치·같은 역할의 다른 파일은 슬롯 접미사로
    가른다. 파일마다 배치를 하나씩 만들면 배치 하나짜리 스캔이 이력에 '4배치' 로 적히고
    스윕과 식별이 서로 무관한 단계처럼 보인다.
    """
    from scanops.api.scans import _engine_stage_info

    slots: dict[tuple, str] = {}
    for name, expected_batch, expected_role in (
        ("scan_7/stage0-discovery.xml", "b0", "engine_discovery"),
        ("scan_7/stage-tcp-b0.xml", "b0", "tcp_discovery"),
        ("scan_7/stage-udp-b0.xml", "b0", "udp_sweep"),
        ("scan_7/stage-tcp-b3.xml", "b3", "tcp_discovery"),
        ("scan_7/stage3-tcp-b0-g0.xml", "b0", "tcp_identify"),
        ("scan_7/stage3-tcp-b0-g2.xml", "b0", "tcp_identify"),
        ("scan_7/stage3-udp-b1-g0.xml", "b1", "udp_identify"),
        ("scan_7/stage3-10_0_0_5-tcp.xml", "b0", "tcp_identify"),
        ("scan_7/stage3-10_0_0_5-udp-confirm.xml", "b0", "udp_identify"),
        ("scan_7/stage3-10_0_0_5-tcp443.xml", "b0", "tcp_identify"),
        ("scan_7/stage3-10_0_0_5-udp161-confirm.xml", "b0", "udp_identify"),
    ):
        info = _engine_stage_info(name)
        assert info is not None, f"엔진 산출물을 못 알아본다: {name}"
        run_key, batch, slot = info
        assert run_key == "scan_7"
        assert batch == expected_batch, f"{name}: 배치 {batch}"
        # 스윕은 열림만 증명하므로 식별과 **다른 역할**이어야 한다 - 같으면 빈 식별이 스윕을 덮는다.
        assert slot.split("#", 1)[0] == expected_role, f"{name}: 역할 {slot}"
        # 자리가 겹치면 뒤에 온 파일이 앞엣것을 조용히 덮어쓴다.
        assert (batch, slot) not in slots, (
            f"{name} 이 {slots.get((batch, slot))} 와 같은 자리({batch}/{slot})를 쓴다"
        )
        slots[(batch, slot)] = name

    # 실제 배치는 넷(b0·b1·b3)이 아니라 셋이다 - 파일 수만큼 배치가 생기면 안 된다.
    assert {batch for batch, _slot in slots} == {"b0", "b1", "b3"}

    # 남의 것을 가져가면 안 된다 - 단독 스캐너 모양과 직접 돌린 nmap XML 은 각자 경로가 있다.
    for name in ("scan_3.b0.tcp_discovery.xml", "my_own_nmap.xml", "scan_5.xml",
                 "stage_notes.xml", "stage3.xml"):
        assert _engine_stage_info(name) is None, f"엔진 것이 아닌데 가져갔다: {name}"


def test_a_single_batch_folder_is_recorded_as_one_batch(client):
    """배치 하나짜리 스캔이 이력에 여러 배치로 적히면 안 된다.

    파일마다 합성 배치 키를 주면 `len(batches)` 가 파일 수가 되어 '· 3배치' 처럼 적히고,
    단계 산출물도 배치 번호가 제각각 붙는다. 배치는 스캔이 대상을 나눈 단위이지 산출물
    개수가 아니다.
    """
    h = _auth(client)
    r = _upload(client, h, _engine_files())        # stage0 + 스윕 2 + 식별 2 = 파일 5개, 배치 1개
    assert r.status_code == 200, r.text
    scan_id = r.json()["scans"][0]["scan_id"]
    command = client.get(f"/api/scans/{scan_id}", headers=h).json()["command"]
    assert "배치" not in command, f"배치 하나인데 배치 수가 적혔다: {command}"


def test_a_staged_result_folder_imports_as_one_scan_not_one_row_per_file(client):
    """결과 폴더 하나 = 이력 한 줄.

    단계 엔진은 파일명에 실행 식별자를 넣지 않고 **폴더 하나를 실행 하나**로 쓴다. 파일명
    base 로 묶는 규칙(STAGE_FILE_RE)이 이 이름들에 하나도 맞지 않아, 예전에는 파일마다 별도
    스캔 행이 생겼다 - 결과 폴더를 통째로 가져오면 이력이 아무 말도 하지 않는 줄로 찼다.
    """
    h = _auth(client)
    files = _engine_files()
    r = _upload(client, h, files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["file_count"] == len(files)
    assert body["imported"] == 1, f"파일마다 행이 생겼다: {body['scans']}"
    assert body["failed"] == 0
    assert "단계 스캔 묶음" in body["scans"][0]["name"]


def test_the_staged_folder_keeps_identification_over_the_sweep_for_both_protocols(client):
    """스윕은 열림을 증명하고 식별은 정체를 밝힌다 - 남는 것은 식별 쪽이어야 한다.

    TCP 는 원래 그랬지만 UDP 는 두 단계 결과가 한 통에 들어가 같은 포트가 두 번 담겼고,
    어느 쪽이 남는지가 파일명 정렬에 좌우됐다.
    """
    h = _auth(client)
    assert _upload(client, h, _engine_files()).status_code == 200
    rows = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                      headers=h).json()
    by_port = {(f["proto"], f["port"]): f for f in rows}
    assert len(rows) == 3, rows
    assert by_port[("tcp", 22)]["service"] == "ssh"
    assert by_port[("tcp", 80)]["service"] == "http"
    assert by_port[("udp", 161)]["service"] == "snmp", "UDP 는 스윕 결과가 식별을 덮었다"


def test_host_discovery_never_closes_a_port_it_did_not_look_at(client):
    """`-sn` 산출물은 포트를 하나도 보지 않는다(<scaninfo> 가 아예 없다).

    관측하지 않은 것으로 닫으면 열린 포트가 '정상처리' 로 사라진다 - 이 저장소가 내내
    막아 온 미탐이다. 발견 단계는 살아 있는 호스트만 보태고 닫힘 범위에는 들어가지 않는다.
    """
    h = _auth(client)
    tcp = '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>'
    # 스윕이 22·80 을 열린 것으로 봤고, 같은 폴더의 발견 파일에는 포트가 없다.
    files = [
        ("scan_8/stage-tcp-b0.xml", _scan_xml(1782050001, tcp,
                                              _port("tcp", 22) + _port("tcp", 80))),
        ("scan_8/stage0-discovery.xml", _ENGINE_SN),
    ]
    assert _upload(client, h, files).status_code == 200
    rows = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                      headers=h).json()
    assert {f["port"]: f["state"] for f in rows} == {22: "open", 80: "open"}
    assert all(f["status"] != "정상처리" for f in rows)


def _udp_xml(start, ports, service="snmp", scanned="161,162"):
    body = "".join(
        f'<port protocol="udp" portid="{n}"><state state="open|filtered" reason="no-response"/>'
        f'<service name="{service}" method="table" conf="3"/></port>' for n in ports
    )
    return _scan_xml(
        start, f'<scaninfo type="udp" protocol="udp" numservices="2" services="{scanned}"/>',
        body, host="10.42.0.1")


def test_an_empty_identification_stage_never_closes_what_the_sweep_proved_open(client):
    """식별은 **보강**이지 스윕에 대한 권한이 아니다.

    스윕이 161 을 열린 것으로 증명했는데 같은 배치의 stage3 가 아무 응답도 못 받는 일은
    흔하다(UDP 는 특히). 그때 스윕 증거까지 사라지면 이미 열려 있던 발견이 닫히고
    '정상처리' 가 되어 감사 이력까지 망가진다 - 되돌리기 가장 어려운 미탐이다.

    실제 실행 경로(`engine_runner.collect_results`)는 스윕을 fallback 으로 깔고 stage3 가
    **보고한 키만** 덮어쓴다. 가져오기가 그 규칙과 갈리면 같은 산출물이 돌린 경로냐 가져온
    경로냐에 따라 다른 결론을 낸다.
    """
    h = _auth(client)
    # 1) 스윕만 먼저 인입해 열린 발견을 만든다.
    first = _upload(client, h, [("scan_42/stage-udp-b0.xml", _udp_xml(1782050001, [161]))])
    assert first.status_code == 200, first.text
    before = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                        headers=h).json()
    assert [(f["port"], f["state"]) for f in before] == [(161, "open|filtered")]

    # 2) 같은 스윕 + 아무것도 못 찾은 stage3 를 함께 인입한다.
    again = _upload(client, h, [
        ("scan_42/stage-udp-b0.xml", _udp_xml(1782050001, [161])),
        ("scan_42/stage3-udp-b0-g0.xml", _udp_xml(1782050002, [])),
    ])
    assert again.status_code == 200, again.text
    assert again.json()["counts"]["closed"] == 0, "빈 식별 단계가 스윕의 양성 관측을 닫았다"
    after = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                       headers=h).json()
    assert [(f["port"], f["state"], f["status"]) for f in after] == [
        (161, "open|filtered", "미조치")
    ]


def test_no_engine_artifact_is_dropped_when_another_shares_its_batch(client):
    """같은 (배치, 역할) 자리에 두 파일이 들어오면 뒤엣것이 앞엣것을 조용히 덮어썼다.

    엔진은 서비스 식별을 배치 안에서 여러 `gN` 으로 나눈다. 그 그룹들이 서로 다른 포트를
    봤는데 하나만 남으면 나머지 관측이 통째로 사라진다 - 파일은 올렸고 오류도 없으니
    사라졌다는 사실조차 안 보인다.
    """
    h = _auth(client)
    files = [
        ("scan_42/stage-udp-b0.xml", _udp_xml(1782050001, [161, 162])),
        # 같은 배치의 서로 다른 식별 그룹이 각각 다른 포트를 밝힌다.
        ("scan_42/stage3-udp-b0-g0.xml", _udp_xml(1782050002, [161], service="snmp")),
        ("scan_42/stage3-udp-b0-g1.xml", _udp_xml(1782050003, [162], service="snmptrap")),
    ]
    r = _upload(client, h, files)
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 1
    rows = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                      headers=h).json()
    by_port = {f["port"]: f["service"] for f in rows}
    assert by_port == {161: "snmp", 162: "snmptrap"}, (
        f"식별 그룹이 서로를 덮었다: {by_port}"
    )


def test_the_sweep_never_overwrites_what_identification_found(client):
    """스윕은 **열림만 증명**한다 - 서비스 정체는 식별 단계가 밝힌다.

    두 단계를 같은 자리에 담으면 배치 키 정렬상 스윕이 뒤에 처리되어(`svc-b0-g0` <
    `sweep-b0`) 식별이 밝힌 서비스명을 덮어쓴다. 실제 실행 경로
    (`engine_runner.collect_results`)가 스윕 행에 `identity_observed=False` 를 붙이는 이유가
    이것이다 - "Sweep proves openness only ... must not erase an existing identity".

    서비스명을 서로 다르게 두어야 이 덮어쓰기가 보인다. 같은 이름이면 어느 쪽이 남든 표가
    똑같아, 검사하지 않는 테스트가 된다(실제로 그렇게 놓쳤다).
    """
    h = _auth(client)
    r = _upload(client, h, [
        # 스윕은 정체를 모른 채 열림만 본다.
        ("scan_42/stage-udp-b0.xml", _udp_xml(1782050001, [161], service="unknown")),
        # 식별이 같은 포트를 snmp 로 밝힌다.
        ("scan_42/stage3-udp-b0-g0.xml", _udp_xml(1782050002, [161], service="snmp")),
    ])
    assert r.status_code == 200, r.text
    rows = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                      headers=h).json()
    assert [f["service"] for f in rows] == ["snmp"], (
        f"스윕이 식별을 덮어썼다: {[(f['port'], f['service']) for f in rows]}"
    )


def test_identification_wins_only_for_the_keys_it_actually_reported(client):
    """식별이 다룬 포트만 서비스 정보를 얻고, 나머지는 스윕 증거 그대로 남아야 한다."""
    h = _auth(client)
    r = _upload(client, h, [
        ("scan_42/stage-udp-b0.xml", _udp_xml(1782050001, [161, 162])),
        ("scan_42/stage3-udp-b0-g0.xml", _udp_xml(1782050002, [161], service="snmp")),
    ])
    assert r.status_code == 200 and r.json()["counts"]["closed"] == 0
    rows = client.get("/api/findings?state=&hide_unconfirmed=false&hide_tcpwrapped=false",
                      headers=h).json()
    by_port = {f["port"]: f for f in rows}
    assert set(by_port) == {161, 162}, "식별이 안 다룬 포트가 사라졌다"
    assert by_port[161]["service"] == "snmp"
    # 162 는 스윕만 봤다 - 열림은 증명됐지만 정체는 관측되지 않았다.
    assert by_port[162]["state"] == "open|filtered"


def test_a_whole_scans_folder_splits_into_one_row_per_actual_run(client):
    """`data/scans/` 를 통째로 올려도 실행별로 갈려야 한다.

    폴더에는 세 가지가 섞여 있다: 단계 스캔 폴더, 레거시가 흩어 놓은 파일, 사람이 직접 돌린
    nmap XML. 여기에 XML 이 아닌 부산물(run-state.json, -oA 가 남긴 .nmap)도 딸려 온다.
    """
    h = _auth(client)
    tcp = '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>'
    files = [
        *[(f"scans/{n}", b) for n, b in _engine_files("scan_7")],
        ("scans/scan_9/stage0-discovery.xml", _ENGINE_SN),
        ("scans/scan_9/stage-tcp-b0.xml",
         _scan_xml(1782050005, tcp, _port("tcp", 22), host="10.2.0.1")),
        ("scans/scan_3.b0.tcp_discovery.xml",
         _scan_xml(1782050006, tcp, _port("tcp", 22), host="10.3.0.1")),
        ("scans/scan_3.b0.tcp_identify.xml",
         _scan_xml(1782050007, tcp, _port("tcp", 22, service="ssh"), host="10.3.0.1")),
        ("scans/my_own_nmap.xml",
         _scan_xml(1782050008, tcp, _port("tcp", 80), host="10.4.0.1")),
        ("scans/scan_7/run-state.json", b"{}"),
        ("scans/scan_7/stage-tcp-b0.nmap", b"# nmap text output"),
    ]
    r = _upload(client, h, files)
    assert r.status_code == 200, r.text
    body = r.json()
    # XML 이 아닌 두 개는 세지도 않는다.
    assert body["file_count"] == len(files) - 2
    # 단계 폴더 2개 + 레거시 묶음 1개 + 직접 돌린 nmap 1개.
    assert body["imported"] == 4, [s["name"] for s in body["scans"]]
    assert body["failed"] == 0
    names = " ".join(s["name"] for s in body["scans"])
    assert "scan_7 단계 스캔 묶음" in names
    assert "scan_9 단계 스캔 묶음" in names
    assert "scan_3.b0 자동 스캔 묶음" in names, "레거시 묶음 규칙이 깨졌다"
    assert "my_own_nmap.xml" in names, "직접 돌린 nmap XML 을 못 받는다"
