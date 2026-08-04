"""스캔 허용 대역(scope) 게이트 — 범위 밖 타겟은 시작 전에 거절, 미설정 시 무제한."""
import pytest

from scanops.scanning.scope import check_scope, parse_scope
from tests.conftest import make_user, token_for


def test_no_scope_allows_everything():
    # spec 이 비면 어떤 타겟도 통과(하위호환)
    check_scope(["8.8.8.8", "1.2.3.4", "example.com"], spec="")


def test_in_scope_passes():
    check_scope(["10.0.12.5", "10.255.0.1"], spec="10.0.0.0/8")


def test_out_of_scope_rejected():
    with pytest.raises(ValueError) as e:
        check_scope(["10.0.0.1", "192.168.1.1"], spec="10.0.0.0/8")
    assert "192.168.1.1" in str(e.value)


def test_hostname_rejected_when_scope_set():
    # IP 가 아닌 토큰은 CIDR 검증 불가 → scope 모드에선 거절
    with pytest.raises(ValueError):
        check_scope(["scanme.example.com"], spec="10.0.0.0/8")


def test_parse_scope_rejects_mixed_garbage():
    with pytest.raises(ValueError, match="not-an-ip"):
        parse_scope("10.0.0.0/8, not-an-ip 192.168.0.0/16")


def test_invalid_nonempty_scope_never_becomes_unrestricted():
    with pytest.raises(ValueError, match="잘못된 스캔 대역"):
        check_scope(["8.8.8.8"], spec="not-an-ip")


def test_multiple_scope_ranges():
    check_scope(["10.0.0.1", "192.168.1.1"], spec="10.0.0.0/8 192.168.0.0/16")


def test_is_ip_token():
    from scanops.scanning.scope import is_ip_token
    assert is_ip_token("10.0.0.1") and is_ip_token("10.0.0.0/24")
    assert not is_ip_token("scanme.example.com") and not is_ip_token("-sV")


def test_check_raw_scope_no_scope_passes():
    from scanops.scanning.scope import check_raw_scope
    check_raw_scope(["-sV", "scanme.example.com"], spec="")   # scope 미설정 → 통과


def test_check_raw_scope_requires_ip_target():
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError):   # 호스트명만 → IP/CIDR 타겟 없음으로 거절
        check_raw_scope(["-sV", "scanme.example.com"], spec="10.0.0.0/8")


def test_check_raw_scope_blocks_file_input():
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError):   # -iL 파일 타겟 차단
        check_raw_scope(["-sV", "-iL", "hosts.txt", "10.0.0.5"], spec="10.0.0.0/8")


def test_check_raw_scope_in_scope_passes():
    from scanops.scanning.scope import check_raw_scope
    check_raw_scope(["-sV", "-p", "22", "10.0.12.5"], spec="10.0.0.0/8")


def test_check_raw_scope_out_of_scope_rejected():
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError):
        check_raw_scope(["-sV", "8.8.8.8"], spec="10.0.0.0/8")


@pytest.mark.parametrize("target", ["scanme.example.com", "10.0.0.1-254"])
def test_check_raw_scope_rejects_mixed_unverifiable_target(target):
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError, match="scope"):
        check_raw_scope(["-sV", "10.0.0.1", target], spec="10.0.0.0/8")


@pytest.mark.parametrize("source", [
    "-iR10", "-iR=10", "-iLhosts.txt", "-iL=hosts.txt",
    "--excludefile=hosts.txt", "--exclude-file=hosts.txt", "--resume=old.nmap",
])
def test_check_raw_scope_blocks_compact_unscoped_target_sources(source):
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError, match="scope"):
        check_raw_scope(["-sV", source, "10.0.0.1"], spec="10.0.0.0/8")


def test_check_raw_scope_distinguishes_known_option_values_from_targets():
    from scanops.scanning.scope import check_raw_scope
    check_raw_scope([
        "-sV", "-p", "22,80", "--script", "http-title", "--script-timeout", "30s",
        "--host-timeout", "30s",
        "--", "10.0.12.5",
    ], spec="10.0.0.0/8")


@pytest.mark.parametrize("tokens", [
    ["-sn", "--script", "resolveall", "10.0.0.5"],
    ["-sn", "--script=targets-asn", "10.0.0.5"],
    ["-sn", "--script", "http-title or resolveall", "10.0.0.5"],
    ["-sn", "--script-args", "newtargets,resolveall.hosts=localhost", "10.0.0.5"],
    ["-sn", "--script-args=newtargets,resolveall.hosts=localhost", "10.0.0.5"],
    ["-sn", "--script-args-file", "args.txt", "10.0.0.5"],
    ["-sn", "--script-args-f=args.txt", "10.0.0.5"],
    ["-sn", "--script-a=newtargets", "10.0.0.5"],
    ["-sn", "--script-ar=newtargets", "10.0.0.5"],
    ["-sn", "--scr=resolveall", "10.0.0.5"],
    ["-sn", "--scrip=resolveall", "10.0.0.5"],
])
def test_check_raw_scope_rejects_dynamic_or_unmanaged_nse(tokens):
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError, match="scope"):
        check_raw_scope(tokens, spec="10.0.0.0/8")


@pytest.mark.parametrize("tokens", [
    ["-sn", "-sI", "203.0.113.10", "10.0.0.5"],
    ["-sn", "-sI203.0.113.10", "10.0.0.5"],
    ["-sn", "-b", "203.0.113.10", "10.0.0.5"],
    ["-sn", "-b203.0.113.10", "10.0.0.5"],
    ["-sn", "--proxies", "http://203.0.113.10:8080", "10.0.0.5"],
    ["-sn", "--prox=http://203.0.113.10:8080", "10.0.0.5"],
    ["-sn", "--dns-servers", "203.0.113.10", "10.0.0.5"],
    ["-sn", "--dns-s=203.0.113.10", "10.0.0.5"],
])
def test_check_raw_scope_rejects_active_auxiliary_network_targets(tokens):
    from scanops.scanning.scope import check_raw_scope
    with pytest.raises(ValueError, match="scope"):
        check_raw_scope(tokens, spec="10.0.0.0/8")


def _auditor_headers(client):
    make_user("scope-auditor", "scopepw12", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'scope-auditor', 'scopepw12')}"}


def test_run_command_rejects_nse_newtargets_before_persisting_or_starting(client, monkeypatch):
    from scanops.api import scans as scans_api
    from scanops.scanning import scope as scope_module

    headers = _auditor_headers(client)
    monkeypatch.setattr(scope_module.get_settings(), "scan_scope", "127.0.0.2/32")
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("rejected NSE command started a worker")
        ),
    )

    response = client.post("/api/scans/run-command", headers=headers, json={
        "command": (
            "nmap -sn --script resolveall "
            "--script-args newtargets,resolveall.hosts=localhost 127.0.0.2"
        ),
    })

    assert response.status_code == 400
    assert "scope" in response.json()["detail"]
    assert client.get("/api/scans", headers=headers).json() == []


def test_run_staged_raw_and_selected_rescan_share_scope_gate(client, monkeypatch):
    from scanops.api import scans as scans_api
    from scanops.scanning import scope as scope_module

    headers = _auditor_headers(client)
    # XML import is evidence ingestion, not an active network operation; use it to seed a finding.
    xml = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="18443"><state state="open"/>'
        '<service name="https" method="probed"/></port></ports></host></nmaprun>'
    ).encode()
    seeded = client.post(
        "/api/scans/import", headers=headers,
        files={"file": ("scope.xml", xml, "text/xml")},
    )
    assert seeded.status_code == 200
    finding_id = client.get("/api/findings", headers=headers).json()[0]["id"]

    monkeypatch.setattr(scope_module.get_settings(), "scan_scope", "10.0.0.0/8")
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")

    requests = [
        client.post("/api/scans/run", headers=headers, json={
            "targets": ["127.0.0.1"], "workflow": "manual",
        }),
        client.post("/api/scans/run-staged", headers=headers, json={
            "targets": ["127.0.0.1"], "ports": "T:18443", "discovery": "pn",
        }),
        client.post("/api/scans/run-command", headers=headers, json={
            "command": "nmap -sV -p 18443 127.0.0.1",
        }),
        client.post("/api/findings/rescan", headers=headers, json={
            "finding_ids": [finding_id],
        }),
    ]
    assert [response.status_code for response in requests] == [400, 400, 400, 400]
    assert all(
        "scope" in response.json()["detail"] and "127.0.0.1" in response.json()["detail"]
        for response in requests
    )


def test_engine_chunk_and_raw_resume_revalidate_current_scope(client, monkeypatch, tmp_path):
    import json

    from scanops.api import scans as scans_api
    from scanops.config import get_settings
    from scanops.db import SessionLocal
    from scanops.models import ScanRun
    from scanops.scanning import chunker
    from scanops.scanning import scope as scope_module

    headers = _auditor_headers(client)
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    db = SessionLocal()
    try:
        scans = [ScanRun(name=kind, targets="127.0.0.1", status="canceled")
                 for kind in ("engine", "chunk", "raw")]
        db.add_all(scans)
        db.commit()
        ids = [scan.id for scan in scans]
    finally:
        db.close()

    engine_dir = get_settings().scans_dir / f"scan_{ids[0]}"
    engine_dir.mkdir(parents=True, exist_ok=True)
    (engine_dir / "spec.json").write_text(json.dumps({
        "targets": ["127.0.0.1"], "out_dir": str(engine_dir),
    }), encoding="utf-8")
    chunker.write_state(scans_api._basename(ids[1]), {
        "batches": [["127.0.0.1"]], "cursor": 0, "stop": True,
    })
    chunker.write_state(scans_api._basename(ids[2]), {
        "raw_argv": ["nmap", "-sV", "127.0.0.1"], "stop": True,
    })

    monkeypatch.setattr(scope_module.get_settings(), "scan_scope", "10.0.0.0/8")
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")

    responses = [client.post(f"/api/scans/{scan_id}/resume", headers=headers) for scan_id in ids]
    assert [response.status_code for response in responses] == [400, 400, 400]
    assert all(
        "scope" in response.json()["detail"] and "127.0.0.1" in response.json()["detail"]
        for response in responses
    )


@pytest.mark.parametrize(("bad_target", "detail"), [
    ("-oX/tmp/resumed.xml", "허용되지 않는 타겟"),
    ("2001:db8::1", "IPv6"),
])
def test_engine_and_chunk_resume_reject_invalid_saved_targets_without_scope(
    client, monkeypatch, tmp_path, bad_target, detail,
):
    import json

    from scanops.api import scans as scans_api
    from scanops.config import get_settings
    from scanops.db import SessionLocal
    from scanops.models import ScanRun
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _auditor_headers(client)
    db = SessionLocal()
    try:
        scans = [ScanRun(name=kind, targets="saved", status="canceled") for kind in ("engine", "chunk")]
        db.add_all(scans)
        db.commit()
        ids = [scan.id for scan in scans]
    finally:
        db.close()

    engine_dir = get_settings().scans_dir / f"scan_{ids[0]}"
    engine_dir.mkdir(parents=True, exist_ok=True)
    (engine_dir / "spec.json").write_text(json.dumps({
        "targets": ["127.0.0.1"], "exclude": [bad_target],
        "out_dir": str(engine_dir),
    }), encoding="utf-8")
    chunker.write_state(scans_api._basename(ids[1]), {
        "batches": [[bad_target]], "cursor": 0, "stop": True,
    })
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": None)
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid saved target started a worker")),
    )

    responses = [client.post(f"/api/scans/{scan_id}/resume", headers=headers) for scan_id in ids]
    assert [response.status_code for response in responses] == [400, 400]
    details = [response.json()["detail"] for response in responses]
    assert all(detail in item for item in details), details
    db = SessionLocal()
    try:
        assert [db.get(ScanRun, scan_id).status for scan_id in ids] == ["canceled", "canceled"]
    finally:
        db.close()


@pytest.mark.parametrize("bad_ports", ["99999", "443-22", "22,,80", "T:"])
def test_engine_and_chunk_resume_reject_invalid_saved_ports_before_side_effects(
    client, monkeypatch, tmp_path, bad_ports,
):
    import json

    from scanops.api import scans as scans_api
    from scanops.db import SessionLocal
    from scanops.models import ScanRun
    from scanops.scanning import chunker

    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _auditor_headers(client)
    db = SessionLocal()
    try:
        scans = [ScanRun(name=kind, targets="127.0.0.1", status="canceled")
                 for kind in ("engine-port", "chunk-port")]
        db.add_all(scans)
        db.commit()
        ids = [scan.id for scan in scans]
    finally:
        db.close()

    engine_dir = scans_api._settings.scans_dir / f"scan_{ids[0]}"
    engine_dir.mkdir(parents=True, exist_ok=True)
    (engine_dir / "spec.json").write_text(json.dumps({
        "targets": ["127.0.0.1"], "out_dir": str(engine_dir),
        "stages": {"tcp": {"ports": bad_ports}},
    }), encoding="utf-8")
    chunker.write_state(scans_api._basename(ids[1]), {
        "batches": [["127.0.0.1"]], "cursor": 0, "stop": True,
        "workflow": "auto", "ports": bad_ports,
    })
    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": None)
    monkeypatch.setattr(
        scans_api.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid saved ports started a worker")),
    )

    responses = [client.post(f"/api/scans/{scan_id}/resume", headers=headers) for scan_id in ids]
    assert [response.status_code for response in responses] == [400, 400]
    assert all("포트" in response.json()["detail"] for response in responses)
    db = SessionLocal()
    try:
        assert [db.get(ScanRun, scan_id).status for scan_id in ids] == ["canceled", "canceled"]
    finally:
        db.close()
