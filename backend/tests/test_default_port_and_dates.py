"""신규 — 기본포트 사용 금지(서비스+포트) 규칙 · 스캔 날짜(실제 스캔일) · 위험등급 한글 내보내기."""
from scanops.scanning.nmap_parse import scan_start
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client, role="auditor"):
    make_user("op", "pw", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _seed(client, h):
    with open(XML, "rb") as f:
        r = client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    assert r.status_code == 200, r.text
    return client.get("/api/findings", headers=h).json()


def test_scan_start_parses_epoch():
    dt = scan_start('<nmaprun start="1700000000"><host/></nmaprun>')
    assert dt is not None and dt.year == 2023
    assert scan_start("<nmaprun><host/></nmaprun>") is None


def test_default_port_rule_matches_service_and_port(client):
    """ssh/22 식 — 서비스+포트가 모두 맞을 때만 매칭. 포트 같아도 서비스 다르면 0."""
    h = _auth(client)
    findings = _seed(client, h)
    target = next(f for f in findings if f["service"])
    svc, port = target["service"], target["port"]

    r = client.post("/api/rules", headers=h, json={
        "kind": "port_rule", "service": svc, "port": port, "risk_level": "banned", "note": "기본포트 금지"})
    assert r.status_code == 201, r.text
    assert r.json()["match_count"] >= 1
    f = client.get(f"/api/findings/{target['id']}", headers=h).json()
    assert f["risk_level"] == "banned"   # 금지 등급 지정 가능
    client.delete(f"/api/rules/{r.json()['id']}", headers=h)

    r2 = client.post("/api/rules", headers=h, json={
        "kind": "port_rule", "service": "zzz-not-" + svc, "port": port, "risk_level": "high"})
    assert r2.status_code == 201
    assert r2.json()["match_count"] == 0   # 포트 같아도 서비스 불일치 → 매칭 없음


def test_port_only_rule_still_supported(client):
    """서비스 없이 포트만 준 규칙(하위호환)은 포트만으로 매칭."""
    h = _auth(client)
    _seed(client, h)
    r = client.post("/api/rules", headers=h, json={"kind": "port_rule", "port": 135, "risk_level": "high"})
    assert r.status_code == 201 and r.json()["match_count"] >= 1


def test_scan_date_from_imported_xml(client):
    """가져온 XML 의 스캔 날짜(start)가 first/last_seen 에 반영(인입 시각 아님)."""
    h = _auth(client)
    findings = _seed(client, h)
    with open(XML, "rb") as fp:
        sdate = scan_start(fp.read())
    assert sdate is not None, "fixture 에 start 가 있어야 함"
    day = sdate.strftime("%Y-%m-%d")
    f = findings[0]
    assert str(f["last_seen"]).startswith(day)
    assert str(f["first_seen"]).startswith(day)


def test_import_events_use_scan_time(client):
    """가져온 XML 의 NEW_OPEN 이력 시각은 파일 스캔시각(인입 시각 아님)."""
    h = _auth(client)
    findings = _seed(client, h)
    with open(XML, "rb") as fp:
        sdate = scan_start(fp.read())
    assert sdate is not None
    day = sdate.strftime("%Y-%m-%d")
    events = client.get(f"/api/findings/{findings[0]['id']}/events", headers=h).json()
    new_open = next(e for e in events if e["type"] == "NEW_OPEN")
    assert str(new_open["created_at"]).startswith(day)


def test_exception_status_rejected(client):
    """예외승인 폐지 → 더 이상 유효 상태가 아니므로 PATCH 거절."""
    h = _auth(client)
    findings = _seed(client, h)
    r = client.patch(f"/api/findings/{findings[0]['id']}", headers=h, json={"status": "예외승인"})
    assert r.status_code == 400


def test_export_risk_level_is_korean(client):
    h = _auth(client)
    findings = _seed(client, h)
    svc = next(f["service"] for f in findings if f["service"])
    client.post("/api/rules", headers=h, json={"kind": "banned_service", "service": svc, "risk_level": "banned"})
    r = client.get("/api/findings/export", headers=h,
                   params={"cols": "host_ip,service,risk_level", "fmt": "csv"})
    assert r.status_code == 200
    text = r.content.decode("utf-8-sig")
    assert "금지" in text          # 한글 등급으로 출력
    assert "banned" not in text    # 영어 원시값이 그대로 나오면 안 됨
