"""Phase G 검증 — 대시보드 지표 + 감사 리포트(xlsx)."""
import io

import openpyxl
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client):
    make_user("op", "pw", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _import(client, h):
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})


def test_dashboard_metrics(client):
    h = _auth(client)
    _import(client, h)
    d = client.get("/api/dashboard", headers=h).json()
    assert d["open_total"] == 13
    assert d["by_risk"].get("high", 0) >= 1
    assert sum(d["by_status"].values()) == 13
    assert d["overdue"] == 0


def test_overdue_counts_after_deadline(client):
    h = _auth(client)
    _import(client, h)
    fid = client.get("/api/findings", headers=h).json()[0]["id"]
    # 과거 마감 → 초과로 집계
    client.patch(f"/api/findings/{fid}", headers=h,
                 json={"status": "처리중", "deadline": "2020-01-01T00:00:00"})
    d = client.get("/api/dashboard", headers=h).json()
    assert d["overdue"] == 1


def test_audit_report_xlsx(client):
    h = _auth(client)
    _import(client, h)
    r = client.get("/api/reports/audit", headers=h)
    assert r.status_code == 200
    assert "spreadsheetml" in r.headers["content-type"]
    wb = openpyxl.load_workbook(io.BytesIO(r.content))
    ws = wb.active
    assert ws.max_row == 14  # 헤더 + 13 발견
    assert ws.cell(1, 1).value == "발견키"


def test_timeline_heatmap(client):
    """시간축 히트맵 — 2회 가져오기 후 시점(열)·행·셀 길이/상태 검증."""
    h = _auth(client)
    _import(client, h)   # scan 1: 전체 open → NEW_OPEN
    # 135 포트를 뺀 XML 로 2회차 → 그 포트 CLOSED, 나머지 persist_open
    import xml.etree.ElementTree as ET
    tree = ET.parse(XML); root = tree.getroot()
    for host in root.findall("host"):
        ports = host.find("ports")
        for p in ports.findall("port"):
            if p.get("portid") == "135":
                ports.remove(p)
    client.post("/api/scans/import", headers=h, files={"file": ("s2.xml", ET.tostring(root), "text/xml")})

    r = client.get("/api/reports/timeline?limit=8", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["scans"]) == 2
    assert data["rows"], "행이 있어야 한다"
    for row in data["rows"]:
        assert len(row["cells"]) == 2          # 시점 수만큼 셀
    # 135 행은 [new_open, new_closed], 살아있는 포트는 [new_open, persist_open]
    row135 = next((x for x in data["rows"] if x["port"] == 135), None)
    assert row135 and row135["cells"] == ["new_open", "new_closed"]
    assert any(x["cells"] == ["new_open", "persist_open"] for x in data["rows"])
