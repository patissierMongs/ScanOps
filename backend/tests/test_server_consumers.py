"""Server 관측값이 사용자-facing 경로에서 일관되게 우선되는지 검증."""
from __future__ import annotations

import csv
import io

import openpyxl

from scanops.db import SessionLocal
from scanops.identity import display_identity
from scanops.models import Finding
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client):
    make_user("server-auditor", "pw", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'server-auditor', 'pw')}"}


def _import_sample(client, headers):
    with open(XML, "rb") as source:
        response = client.post(
            "/api/scans/import", headers=headers,
            files={"file": ("sample.xml", source, "text/xml")},
        )
    assert response.status_code == 200, response.text


def _update_finding(port: int, **values):
    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.port == port).one()
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()
    finally:
        db.close()


def _headers(ws) -> dict[str, int]:
    return {cell.value: cell.column for cell in ws[1]}


def test_display_identity_priority():
    assert display_identity(
        server="uvicorn", product="Generic HTTP", version="1.0", service="apple-iphoto",
    ) == "uvicorn"
    assert display_identity(product="OpenSSH", version="9.6", service="ssh") == "OpenSSH 9.6"
    assert display_identity(service="ssh") == "ssh"


def test_default_csv_and_selected_xlsx_export_server_identity(client):
    headers = _auth(client)
    _import_sample(client, headers)
    _update_finding(9000, server="=1+1", service="http", product="Golang net/http server", version="")

    default_csv = client.get("/api/findings/export", headers=headers, params={"fmt": "csv"})
    assert default_csv.status_code == 200, default_csv.text
    csv_rows = list(csv.DictReader(io.StringIO(default_csv.content.decode("utf-8-sig"))))
    csv_row = next(row for row in csv_rows if row["포트"] == "9000")
    assert csv_row["표시 식별"] == "'=1+1"
    assert csv_row["Server"] == "'=1+1"
    assert csv_row["서비스"] == "http"

    selected_xlsx = client.get(
        "/api/findings/export", headers=headers,
        params={"fmt": "xlsx", "cols": "port,display_identity,server,service"},
    )
    assert selected_xlsx.status_code == 200, selected_xlsx.text
    ws = openpyxl.load_workbook(io.BytesIO(selected_xlsx.content)).active
    columns = _headers(ws)
    row_num = next(row for row in range(2, ws.max_row + 1) if ws.cell(row, columns["포트"]).value == 9000)
    assert ws.cell(row_num, columns["표시 식별"]).value == "'=1+1"
    assert ws.cell(row_num, columns["Server"]).value == "'=1+1"
    assert ws.cell(row_num, columns["서비스"]).value == "http"


def test_audit_report_includes_server_identity_and_escapes_formula(client):
    headers = _auth(client)
    _import_sample(client, headers)
    _update_finding(9000, server="=1+1", service="http", product="Golang net/http server", version="")

    response = client.get("/api/reports/audit", headers=headers)

    assert response.status_code == 200, response.text
    ws = openpyxl.load_workbook(io.BytesIO(response.content)).active
    columns = _headers(ws)
    row_num = next(row for row in range(2, ws.max_row + 1) if ws.cell(row, columns["포트"]).value == 9000)
    assert ws.cell(row_num, columns["표시 식별"]).value == "'=1+1"
    assert ws.cell(row_num, columns["Server"]).value == "'=1+1"
    assert ws.cell(row_num, columns["서비스"]).value == "http"


def test_notification_uses_server_then_labels_semantic_service(client):
    headers = _auth(client)
    client.post("/api/assets", headers=headers, json={"ip": "127.0.0.1", "dept": "인프라팀"})
    _import_sample(client, headers)
    _update_finding(9000, server="uvicorn", service="apple-iphoto", product="", version="")

    response = client.get(
        "/api/notifications/preview", headers=headers, params={"dept": "인프라팀"},
    )

    assert response.status_code == 200, response.text
    assert "127.0.0.1:9000/tcp uvicorn (서비스: apple-iphoto)" in response.json()["body"]


def test_heatmap_reuses_server_extractor_and_report_escapes_formula(client):
    headers = _auth(client)
    xml = b"""<?xml version="1.0"?>
<nmaprun start="1893456000">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8770">
        <state state="open"/>
        <service name="apple-iphoto" method="table" conf="3"/>
        <script id="http-server-header" output="uvicorn"/>
      </port>
      <port protocol="tcp" portid="8771">
        <state state="open"/>
        <service name="http" method="table" conf="3"/>
        <script id="http-server-header" output="=1+1"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    imported = client.post(
        "/api/scans/import", headers=headers,
        files={"file": ("server.xml", xml, "text/xml")},
    )
    assert imported.status_code == 200, imported.text
    _update_finding(8770, server="")
    _update_finding(8771, server="")

    data = client.get("/api/heatmap", headers=headers).json()
    uvicorn = next(row for row in data["rows"] if row["port"] == 8770)
    assert uvicorn["server"] == "uvicorn"
    assert uvicorn["display_identity"] == "uvicorn"
    assert uvicorn["service"] == "apple-iphoto"

    report = client.get("/api/heatmap/report", headers=headers)
    assert report.status_code == 200, report.text
    ws = openpyxl.load_workbook(io.BytesIO(report.content))["02_현재포트현황"]
    columns = _headers(ws)
    row_num = next(row for row in range(2, ws.max_row + 1) if ws.cell(row, columns["포트"]).value == 8771)
    assert ws.cell(row_num, columns["표시 식별"]).value == "'=1+1"
    assert ws.cell(row_num, columns["Server"]).value == "'=1+1"
    assert ws.cell(row_num, columns["서비스"]).value == "http"
