import pytest

from tests.conftest import make_user, token_for


def _auditor(client):
    make_user("edge-auditor", "edgepass123", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'edge-auditor', 'edgepass123')}"}


@pytest.mark.parametrize("target", ["10.0.0.999", "256.1.1.1", "10.0.300.1"])
def test_dotted_quad_with_an_octet_over_255_is_rejected_not_scanned(client, monkeypatch, target):
    from scanops.api import scans as scans_api

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    headers = _auditor(client)
    for path in ("/api/scans/run-staged", "/api/scans/run", "/api/scans/estimate"):
        r = client.post(path, headers=headers, json={
            "targets": [target], "ports": "80", "options": ["connect"], "nse": [],
        })
        assert r.status_code == 400, (path, r.status_code, r.text)
        assert "IPv4" in r.json()["detail"]
    assert client.get("/api/scans", headers=headers).json() == []


def test_hostname_targets_are_still_accepted_by_validation():
    from scanops.scanning.nmap_runner import validate_targets

    assert validate_targets(["localhost", "scanme.example.com", "10.0.0.1-20"]) == [
        "localhost", "scanme.example.com", "10.0.0.1-20"]


@pytest.mark.parametrize("body", [
    {"ports": "8081,8770", "exclude_ports": "8081,8770", "options": ["connect"]},
    {"ports": "8081,8770", "exclude_ports": "1-65535", "options": ["connect"]},
    {"ports": "T:80,U:53", "exclude_ports": "80,53", "options": ["syn", "udp"]},
    {"ports": "80", "exclude_ports": "80", "workflow": "auto", "options": []},
])
def test_excluding_every_requested_port_is_rejected_before_launch(client, monkeypatch, body):
    from scanops.api import scans as scans_api

    monkeypatch.setattr(scans_api.nmap_runner, "find_nmap", lambda explicit="": "nmap")
    headers = _auditor(client)
    path = "/api/scans/run" if body.get("workflow") == "auto" else "/api/scans/run-staged"
    r = client.post(path, headers=headers, json={"targets": ["127.0.0.1"], "nse": [], **body})
    assert r.status_code == 400, r.text
    assert "남지 않았습니다" in r.json()["detail"]
    assert client.get("/api/scans", headers=headers).json() == []


@pytest.mark.parametrize("body", [
    {"ports": "8081,8770", "exclude_ports": "8081", "options": ["connect"]},
    {"ports": "T:80,U:53", "exclude_ports": "80", "options": ["syn", "udp"]},
    {"ports": "", "exclude_ports": "80,443", "options": ["connect"]},
])
def test_partial_port_exclusion_still_validates(client, body):
    headers = _auditor(client)
    r = client.post("/api/scans/estimate", headers=headers,
                    json={"targets": ["127.0.0.1"], "nse": [], **body})
    assert r.status_code == 200, r.text
