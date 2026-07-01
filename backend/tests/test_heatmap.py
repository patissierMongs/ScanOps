"""스캔 시간축 히트맵 — XML 기반 상태 계산과 XLSX 보고서."""
from __future__ import annotations

import io
from pathlib import Path

import openpyxl

from tests.conftest import make_user, token_for

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _auth(client):
    make_user("op", "pw", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _import(client, headers, path: Path, name: str | None = None):
    with path.open("rb") as f:
        return client.post(
            "/api/scans/import",
            headers=headers,
            files={"file": (name or path.name, f, "text/xml")},
        )


def _row(data: dict, port: int) -> dict:
    return next(r for r in data["rows"] if r["host_ip"] == "127.0.0.1" and r["port"] == port)


def test_heatmap_tracks_open_and_closed_ports(client):
    headers = _auth(client)
    assert _import(client, headers, SAMPLES / "scanA.xml").status_code == 200
    assert _import(client, headers, SAMPLES / "scanB.xml").status_code == 200

    data = client.get("/api/heatmap", headers=headers).json()

    assert data["summary"]["scan_count"] == 2
    assert data["summary"]["phase_count"] == 2

    port_3000 = _row(data, 3000)
    assert [c["state"] for c in port_3000["cells"]] == ["신규열림", "신규닫힘"]
    assert port_3000["current_state"] == "신규닫힘"

    port_8080 = _row(data, 8080)
    assert [c["state"] for c in port_8080["cells"]] == ["신규열림", "기존열림"]
    assert port_8080["current_state"] == "기존열림"


def test_narrow_port_scan_does_not_overwrite_heatmap_current(client, tmp_path):
    headers = _auth(client)
    assert _import(client, headers, SAMPLES / "scanA.xml").status_code == 200
    narrow_xml = tmp_path / "narrow.xml"
    narrow_xml.write_text(
        """<?xml version="1.0"?>
<nmaprun start="1893456000">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="1">
        <state state="closed"/>
        <service name="tcpmux" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    assert _import(client, headers, narrow_xml, "narrow.xml").status_code == 200

    data = client.get("/api/heatmap", headers=headers).json()
    port_3000 = _row(data, 3000)

    assert [c["state"] for c in port_3000["cells"]] == ["신규열림", "대상 외"]
    assert port_3000["current_state"] == "신규열림"

    current = client.get("/api/heatmap/current", headers=headers).json()
    assert any(r["host_ip"] == "127.0.0.1" and r["port"] == 3000 for r in current["items"])


def test_heatmap_report_xlsx_has_operational_sheets(client):
    headers = _auth(client)
    assert _import(client, headers, SAMPLES / "scanA.xml").status_code == 200
    assert _import(client, headers, SAMPLES / "scanB.xml").status_code == 200

    res = client.get("/api/heatmap/report", headers=headers)

    assert res.status_code == 200
    assert "spreadsheetml" in res.headers["content-type"]
    wb = openpyxl.load_workbook(io.BytesIO(res.content))
    assert wb.sheetnames == ["00_보고요약", "01_시간축히트맵", "02_현재포트현황", "03_시점비교"]
    assert wb["01_시간축히트맵"].cell(1, 1).value == "IP"
