"""완성 단계 갭 테스트 — 예외 경로/경계값/동시성(누락되기 쉬운 '해피패스 밖').

기존 통합 테스트는 정상 흐름 위주라, 여기서는 실패/비정상 입력과 동시성 안전성만 노린다:
  · 깨진/빈/비-XML 가져오기 → graceful 400 또는 0건
  · nmap 바이너리 부재 시 실행 계열 엔드포인트가 400 으로 정직하게 거절
  · 같은 XML 재가져오기 idempotent(안정키 upsert — 중복 행 없음)
  · 동시 상태 변경(PATCH)에서 500/DB 잠금 없이 일관 상태 수렴
"""
from __future__ import annotations

import threading

import pytest

from scanops.db import SessionLocal
from scanops.models import Finding
from scanops.scanning import nmap_parse, nmap_runner

from .conftest import make_user, token_for

# 최소 유효 nmap XML(호스트 없음) — 파서는 통과하되 발견 0건이어야 한다.
EMPTY_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000">'
    b"<runstats><finished time=\"1700000000\" exit=\"success\"/></runstats></nmaprun>"
)
# 한 호스트/한 열린 포트 — 가져오기 후 발견 1건.
ONE_HOST_XML = (
    b'<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000">'
    b'<scaninfo type="syn" protocol="tcp" services="22"/>'
    b'<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
    b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
    b'<service name="ssh" product="OpenSSH" method="probed"/></port></ports></host>'
    b"</nmaprun>"
)


@pytest.fixture()
def auditor_headers(client):
    make_user("edge_auditor", "pw-auditor", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'edge_auditor', 'pw-auditor')}"}


def _import(client, headers, name, data):
    return client.post(
        "/api/scans/import",
        headers=headers,
        files={"file": (name, data, "text/xml")},
    )


# --- 비정상 입력: 가져오기 파싱 실패 경로 ---------------------------------------

def test_import_malformed_xml_returns_400(client, auditor_headers):
    r = _import(client, auditor_headers, "broken.xml", b"<nmaprun><host>")
    assert r.status_code == 400, r.text
    assert "XML" in r.json()["detail"]


def test_import_non_xml_bytes_returns_400(client, auditor_headers):
    r = _import(client, auditor_headers, "junk.xml", b"this is not xml at all \x00\xff")
    assert r.status_code == 400, r.text


def test_import_empty_valid_xml_yields_zero_findings(client, auditor_headers):
    r = _import(client, auditor_headers, "empty.xml", EMPTY_XML)
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["new"] == 0
    assert client.get("/api/findings", headers=auditor_headers).json() == []


def test_import_requires_auditor_role(client):
    """viewer(권한 부족)는 가져오기 403 — 권한 경계 회귀 방지."""
    make_user("edge_viewer", "pw-viewer", role="viewer")
    tok = token_for(client, "edge_viewer", "pw-viewer")
    r = _import(client, {"Authorization": f"Bearer {tok}"}, "empty.xml", EMPTY_XML)
    assert r.status_code == 403, r.text


# --- 안정키 upsert idempotency: 같은 XML 재가져오기 -----------------------------

def test_reimport_same_xml_is_idempotent(client, auditor_headers):
    r1 = _import(client, auditor_headers, "one.xml", ONE_HOST_XML)
    assert r1.status_code == 200 and r1.json()["counts"]["new"] == 1
    before = len(client.get("/api/findings", headers=auditor_headers).json())

    r2 = _import(client, auditor_headers, "one.xml", ONE_HOST_XML)
    assert r2.status_code == 200, r2.text
    # 두 번째 가져오기는 새 발견 0 — 같은 finding_key 는 갱신될 뿐 중복 생성되지 않는다.
    assert r2.json()["counts"]["new"] == 0
    after = len(client.get("/api/findings", headers=auditor_headers).json())
    assert after == before == 1


# --- nmap 부재: 실행 계열 엔드포인트가 정직하게 400 ------------------------------

@pytest.fixture()
def no_nmap(monkeypatch):
    """find_nmap 이 None 을 돌려주도록 고정 — CI(nmap 설치)든 아니든 결정적으로."""
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda *a, **k: None)


@pytest.mark.parametrize(
    "path, body",
    [
        ("/api/scans/run", {"name": "t", "targets": ["10.0.0.5"], "workflow": "manual", "preset": "quick"}),
        ("/api/scans/run-command", {"name": "t", "command": "-sV -p 22 10.0.0.5"}),
        ("/api/scans/run-staged", {"name": "t", "targets": ["10.0.0.5"], "workflow": "manual"}),
    ],
)
def test_run_endpoints_reject_when_nmap_missing(client, auditor_headers, no_nmap, path, body):
    r = client.post(path, headers=auditor_headers, json=body)
    assert r.status_code == 400, r.text
    assert "nmap" in r.json()["detail"].lower()


# --- 파서 단위: 깨진 입력은 ParseError 로 명확히 실패 --------------------------

def test_parse_xml_raises_on_malformed():
    import xml.etree.ElementTree as ET

    with pytest.raises(ET.ParseError):
        nmap_parse.parse_xml(b"<nmaprun><host")


def test_up_hosts_ignores_down_and_mac_only():
    xml = (
        b'<nmaprun><host><status state="down"/>'
        b'<address addr="10.0.0.9" addrtype="ipv4"/></host>'
        b'<host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/>'
        b"<ports/></host></nmaprun>"
    )
    assert nmap_parse.up_hosts(xml) == {"10.0.0.10"}


# --- 동시성: 같은 발견에 대한 병렬 상태 변경 -----------------------------------

def test_concurrent_status_patches_converge(client, auditor_headers):
    """여러 스레드가 같은 발견을 동시에 '처리중'으로 바꿔도 500/DB 잠금 없이 수렴.

    WAL + busy_timeout 하에서 짧은 트랜잭션은 안전해야 한다. 최종 상태 일관 +
    발견 행 수 불변(중복/유실 없음)을 확인한다.
    """
    assert _import(client, auditor_headers, "one.xml", ONE_HOST_XML).status_code == 200
    fid = client.get("/api/findings", headers=auditor_headers).json()[0]["id"]

    codes: list[int] = []
    lock = threading.Lock()

    def worker():
        r = client.patch(f"/api/findings/{fid}", headers=auditor_headers, json={"status": "처리중"})
        with lock:
            codes.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert codes and all(c == 200 for c in codes), codes
    db = SessionLocal()
    try:
        assert db.query(Finding).count() == 1          # 중복 생성 없음
        assert db.get(Finding, fid).status == "처리중"   # 일관 수렴
    finally:
        db.close()
