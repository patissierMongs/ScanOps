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

    def write_stage(_scan_id, argv, _log_path):
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

    findings = client.get("/api/findings?state=", headers=h).json()
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

    def write_stage(_scan_id, argv, _log_path):
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

    findings = client.get("/api/findings?state=", headers=h).json()
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
    findings = client.get("/api/findings?state=", headers=h).json()
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
