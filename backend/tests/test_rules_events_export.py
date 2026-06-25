"""신규 엔드포인트 검증 — 위험규칙/전역이력/선택컬럼 내보내기/재스캔명령."""
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client, role="auditor"):
    make_user("op", "pw", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _seed_findings(client, h):
    with open(XML, "rb") as f:
        r = client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})
    assert r.status_code == 200, r.text
    return client.get("/api/findings", headers=h).json()


# ---- 위험규칙 ----

def test_rule_crud_and_match_count(client):
    h = _auth(client)
    findings = _seed_findings(client, h)
    assert any(f["port"] == 135 for f in findings)

    r = client.post("/api/rules", headers=h,
                    json={"kind": "port_rule", "port": 135, "risk_level": "high", "note": "RPC 차단"})
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["match_count"] >= 1  # 135 포트 발견을 잡아야 한다

    lst = client.get("/api/rules", headers=h).json()
    assert len(lst) == 1 and lst[0]["match_count"] >= 1

    d = client.delete(f"/api/rules/{rule['id']}", headers=h)
    assert d.status_code == 204
    assert client.get("/api/rules", headers=h).json() == []


def test_banned_service_promotes_to_banned(client):
    h = _auth(client)
    findings = _seed_findings(client, h)
    target = findings[0]
    svc = target["service"]
    assert svc  # 서비스명이 있어야 banned_service 매칭

    # 해당 서비스 금지 규칙 추가 → 기존 발견이 즉시 '금지'로 재분류
    r = client.post("/api/rules", headers=h,
                    json={"kind": "banned_service", "service": svc, "risk_level": "banned"})
    assert r.status_code == 201, r.text

    f = client.get(f"/api/findings/{target['id']}", headers=h).json()
    assert f["risk_level"] == "banned"

    # 규칙 삭제 → 등급 원복(금지 아님)
    client.delete(f"/api/rules/{r.json()['id']}", headers=h)
    f2 = client.get(f"/api/findings/{target['id']}", headers=h).json()
    assert f2["risk_level"] != "banned"


def test_rule_validation_and_role(client):
    h = _auth(client)
    # port_rule 인데 port 없음 → 400
    bad = client.post("/api/rules", headers=h, json={"kind": "port_rule", "risk_level": "high"})
    assert bad.status_code == 400
    # 알 수 없는 kind → 400
    bad2 = client.post("/api/rules", headers=h, json={"kind": "nope", "service": "x"})
    assert bad2.status_code == 400
    # viewer 는 생성 불가 → 403 (별도 유저)
    make_user("viewer1", "pw", role="viewer")
    hv = {"Authorization": f"Bearer {token_for(client, 'viewer1', 'pw')}"}
    forbidden = client.post("/api/rules", headers=hv, json={"kind": "port_rule", "port": 1})
    assert forbidden.status_code == 403


# ---- 전역 이력 피드 ----

def test_event_feed(client):
    h = _auth(client)
    findings = _seed_findings(client, h)
    fid = findings[0]["id"]
    client.patch(f"/api/findings/{fid}", headers=h, json={"status": "처리중"})

    feed = client.get("/api/events", headers=h).json()
    assert feed["total"] >= 1
    item = feed["items"][0]
    assert {"host_ip", "port", "service", "type", "detail"} <= set(item)

    only_new = client.get("/api/events", headers=h, params={"type": "NEW_OPEN"}).json()
    assert only_new["total"] >= 1
    assert all(i["type"] == "NEW_OPEN" for i in only_new["items"])


# ---- 선택 컬럼 내보내기 ----

def test_export_csv_has_bom(client):
    h = _auth(client)
    _seed_findings(client, h)
    r = client.get("/api/findings/export", headers=h,
                   params={"cols": "host_ip,port,service,risk_level", "fmt": "csv"})
    assert r.status_code == 200
    assert r.content[:3] == b"\xef\xbb\xbf"  # UTF-8 BOM
    text = r.content.decode("utf-8-sig")
    header = text.splitlines()[0]
    assert "IP" in header and "포트" in header and "서비스" in header


def test_export_xlsx(client):
    h = _auth(client)
    _seed_findings(client, h)
    r = client.get("/api/findings/export", headers=h, params={"cols": "host_ip,port", "fmt": "xlsx"})
    assert r.status_code == 200
    assert r.content[:2] == b"PK"  # xlsx(zip) 시그니처
    assert "spreadsheetml" in r.headers["content-type"]


def test_export_fingerprint_and_owner_columns(client):
    """수집은 되는데 노출 안 되던 값(핑거프린트·담당자)을 선택 컬럼으로 내보낼 수 있어야 한다."""
    h = _auth(client)
    client.post("/api/assets/bulk", headers=h, json=[{"ip": "127.0.0.1", "owner": "김운영"}])
    _seed_findings(client, h)
    r = client.get("/api/findings/export", headers=h,
                   params={"cols": "host_ip,port,owner,fingerprint", "fmt": "csv"})
    assert r.status_code == 200
    text = r.content.decode("utf-8-sig")
    header = text.splitlines()[0]
    assert "담당자" in header and "핑거프린트" in header
    # MinIO(포트 9000/9001)는 -sV 가 식별했어도 fingerprint-strings 원문에 Server 단서가 남는다
    assert "MinIO" in text
    assert "김운영" in text   # 자산대장 IP 매칭으로 채워진 담당자


def test_finding_exposes_fingerprint_field(client):
    """FindingOut 이 fingerprint(미식별 서비스 원시 응답)를 노출해 표/서랍에서 바로 보이게."""
    h = _auth(client)
    findings = _seed_findings(client, h)
    fp = [f for f in findings if f.get("fingerprint")]
    assert fp, "fingerprint-strings 가 있는 발견은 fingerprint 필드가 채워져야 한다"


def test_purpose_surfaces_server_header(client):
    """-sV 가 식별 못 해도 Server 헤더(uvicorn 류)를 용도근거로 끌어올린다."""
    h = _auth(client)
    _seed_findings(client, h)
    r = client.get("/api/findings/export", headers=h,
                   params={"cols": "host_ip,port,purpose", "fmt": "csv"})
    assert r.status_code == 200
    assert "server=" in r.content.decode("utf-8-sig")


def test_export_unknown_column(client):
    h = _auth(client)
    _seed_findings(client, h)
    r = client.get("/api/findings/export", headers=h, params={"cols": "host_ip,bogus"})
    assert r.status_code == 400


def test_export_sanitizes_formula_injection(client):
    """스캔 대상이 제어하는 값이 수식으로 시작하면 CSV 셀이 작은따옴표로 무력화돼야 한다."""
    h = _auth(client)
    findings = _seed_findings(client, h)
    fid = findings[0]["id"]
    client.patch(f"/api/findings/{fid}", headers=h, json={"manual_note": "=cmd|'/c calc'!A1"})
    r = client.get("/api/findings/export", headers=h,
                   params={"cols": "host_ip,manual_note", "fmt": "csv"})
    assert r.status_code == 200
    text = r.content.decode("utf-8-sig")
    assert "'=cmd" in text       # 작은따옴표 프리픽스로 무력화됨
    assert ",=cmd" not in text   # 생 수식이 셀 선두에 그대로 오면 안 됨


def test_pretty_fingerprint_unit():
    """probe 그룹 분리 + 들여쓰기 정리 + 동일 응답 중복 제거. 프론트 columns.js prettyFingerprint 와 동일 출력."""
    from scanops.scanning.nmap_parse import pretty_fingerprint
    raw = ("\n  GenericLines, SSLSessionReq: \n    HTTP/1.1 400 Bad Request\n    Connection: close"
           "\n  GetRequest: \n    HTTP/1.0 200 OK\n    Server: uvicorn"
           "\n  Help: \n    HTTP/1.1 400 Bad Request\n    Connection: close")  # GenericLines 와 동일 본문 → 합쳐짐
    assert pretty_fingerprint(raw) == (
        "[GenericLines, SSLSessionReq]\nHTTP/1.1 400 Bad Request\nConnection: close"
        "\n\n[GetRequest]\nHTTP/1.0 200 OK\nServer: uvicorn"
    )
    assert pretty_fingerprint("") == ""
    assert pretty_fingerprint(None) == ""


def test_safe_cell_unit():
    from scanops.spreadsheet import safe_cell
    for danger in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"):
        assert safe_cell(danger) == "'" + danger
    assert safe_cell("http") == "http"   # 평범한 문자열 불변
    assert safe_cell(443) == 443          # 숫자 불변
    assert safe_cell("") == ""


# ---- 재스캔 명령 ----

def test_rescan_command(client):
    h = _auth(client)
    findings = _seed_findings(client, h)
    ids = [f["id"] for f in findings[:3]]
    r = client.post("/api/findings/rescan-command", headers=h, json={"finding_ids": ids})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["command"].startswith("nmap ")
    assert out["finding_count"] == 3
    assert len(out["ports"]) >= 1 and len(out["hosts"]) >= 1
    # 발견(IP:포트)별 개별 명령 — 각 명령은 단일 포트·단일 호스트만
    assert len(out["commands"]) >= 1
    for c in out["commands"]:
        assert c.startswith("nmap ") and " -p " in c
        tail = c.split(" -p ", 1)[1].split()       # [port, host]
        assert len(tail) == 2 and "," not in tail[0]   # 포트 1개, 호스트 1개(교차곱 아님)


def test_rescan_command_empty(client):
    h = _auth(client)
    r = client.post("/api/findings/rescan-command", headers=h, json={"finding_ids": []})
    assert r.status_code == 200
    assert r.json()["command"] == ""


# ---- 백그라운드 엔진 재스캔(Stage3-only) ----

def test_rescan_run_starts_engine_job(client, monkeypatch):
    """동기→백그라운드 전환: scan_id 반환 + spec.json 에 targets_ports·confirm·scope_keys.

    엔진 워커(spawn)는 막아 실제 nmap 이 안 돌게 한다 — 검증 대상은 job 구성.
    """
    import json
    import scanops.api.scans as scans_mod
    from scanops.config import get_settings
    monkeypatch.setattr(scans_mod, "_engine_worker", lambda scan_id: None)

    h = _auth(client)
    findings = _seed_findings(client, h)
    ids = [f["id"] for f in findings[:2]]
    r = client.post("/api/findings/rescan", headers=h, json={"finding_ids": ids})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["scan_id"] >= 1
    assert len(out["hosts"]) >= 1 and len(out["ports"]) >= 1

    spec = json.loads((get_settings().scans_dir / f"scan_{out['scan_id']}" / "spec.json")
                      .read_text(encoding="utf-8"))
    assert spec["rescan_units"]                           # 발견(IP:포트)별 개별 단위
    assert all({"ip", "port", "proto"} <= set(u) for u in spec["rescan_units"])
    assert spec["stages"]["service"]["confirm"] is True   # 2-pass 정밀 확인
    assert spec["scanops"]["scope_keys"]                  # 닫힘 판정 한정 키


def test_rescan_due_picks_in_progress(client, monkeypatch):
    import scanops.api.scans as scans_mod
    monkeypatch.setattr(scans_mod, "_engine_worker", lambda scan_id: None)
    h = _auth(client)
    findings = _seed_findings(client, h)
    client.patch(f"/api/findings/{findings[0]['id']}", headers=h, json={"status": "처리중"})
    r = client.post("/api/findings/rescan-due", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["scan_id"] >= 1


def test_rescan_due_empty(client):
    h = _auth(client)
    _seed_findings(client, h)   # 전부 미조치·마감없음 → due 없음
    r = client.post("/api/findings/rescan-due", headers=h)
    assert r.status_code == 400


# ---- 자산 연락처/커스텀필드 + 발견 전파 ----

def test_asset_contact_extra_and_propagation(client):
    h = _auth(client)
    findings = _seed_findings(client, h)
    host = findings[0]["host_ip"]

    r = client.post("/api/assets/bulk", headers=h, json=[
        {"ip": host, "dept": "보안팀", "owner": "김담당",
         "contact": "010-1234-5678", "extra": {"종류": "서버", "OS": "Ubuntu"}},
    ])
    assert r.status_code == 200, r.text

    a = client.get("/api/assets", headers=h).json()[0]
    assert a["contact"] == "010-1234-5678"
    assert a["extra"]["종류"] == "서버" and a["extra"]["OS"] == "Ubuntu"

    # IP 매칭으로 발견에 부서/연락처/담당자 전파
    f = client.get(f"/api/findings/{findings[0]['id']}", headers=h).json()
    assert f["dept"] == "보안팀" and f["contact"] == "010-1234-5678"
    assert f["owner"] == "김담당"   # 자산 담당자명 → 발견(통보용)
