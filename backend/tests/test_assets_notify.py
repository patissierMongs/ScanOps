"""Phase F 검증 — 자산대장 매칭(IP→부서) + 부서통보."""
import io

import openpyxl
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client, role="auditor"):
    make_user("op", "pw", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _import(client, h):
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})


def test_asset_matches_findings_dept(client):
    h = _auth(client)
    client.post("/api/assets", headers=h,
                json={"ip": "127.0.0.1", "hostname": "loc", "dept": "인프라운영팀", "owner": "홍길동"})
    _import(client, h)
    rows = client.get("/api/findings", headers=h).json()
    assert rows and all(r["dept"] == "인프라운영팀" for r in rows)


def test_asset_xlsx_import(client):
    h = _auth(client)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["IP", "호스트명", "부서", "담당자"])
    ws.append(["127.0.0.1", "loc", "보안팀", "김보안"])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    r = client.post("/api/assets/import", headers=h,
                    files={"file": ("assets.xlsx", buf, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200 and r.json()["added"] == 1
    assert client.get("/api/assets", headers=h).json()[0]["dept"] == "보안팀"


def test_dept_notification(client):
    h = _auth(client)
    client.post("/api/assets", headers=h, json={"ip": "127.0.0.1", "dept": "인프라운영팀"})
    _import(client, h)

    pv = client.get("/api/notifications/preview", headers=h, params={"dept": "인프라운영팀"}).json()
    assert pv["finding_count"] >= 1 and "인프라운영팀" in pv["body"]

    r = client.post("/api/notifications", headers=h, params={"dept": "인프라운영팀"})
    assert r.status_code == 201 and "미조치 발견" in r.json()["body"]
    assert len(client.get("/api/notifications", headers=h).json()) == 1
