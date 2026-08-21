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


def test_dashboard_separates_evidence_allowed_and_unresolved(client):
    from scanops.db import SessionLocal
    from scanops.models import Finding

    h = _auth(client)
    db = SessionLocal()
    try:
        rows = [
            Finding(finding_key="10.0.0.1|80|tcp", host_ip="10.0.0.1", port=80,
                    proto="tcp", state="open", reason="syn-ack", risk_level="high",
                    dept="운영팀", status="미조치"),
            Finding(finding_key="10.0.0.2|161|udp", host_ip="10.0.0.2", port=161,
                    proto="udp", state="open|filtered", reason="no-response",
                    risk_level="medium", dept="운영팀", status="처리중"),
            Finding(finding_key="10.0.0.3|443|tcp", host_ip="10.0.0.3", port=443,
                    proto="tcp", state="open", reason="syn-ack", risk_level="info",
                    dept="운영팀", status="미조치", allowed=1),
            Finding(finding_key="10.0.0.4|22|tcp", host_ip="10.0.0.4", port=22,
                    proto="tcp", state="open", reason="syn-ack", risk_level="high",
                    dept="보안팀", status="정상처리"),
            Finding(finding_key="10.0.0.5|25|tcp", host_ip="10.0.0.5", port=25,
                    proto="tcp", state="closed", reason="reset", risk_level="high",
                    dept="운영팀", status="미조치"),
        ]
        db.add_all(rows)
        db.commit()
    finally:
        db.close()

    payload = client.get("/api/dashboard", headers=h).json()

    assert payload["open_total"] == 4
    assert payload["confirmed_open_total"] == 3
    assert payload["confirmation_required_total"] == 1
    assert payload["allowed_open_total"] == 1
    assert payload["unresolved_total"] == 2
    assert payload["by_dept"] == [{"dept": "운영팀", "count": 2}]
    assert payload["unresolved_by_risk"]["high"] == 1
    assert payload["unresolved_by_risk"]["medium"] == 1


def test_overdue_counts_after_deadline(client):
    h = _auth(client)
    _import(client, h)
    fid = client.get("/api/findings", headers=h).json()[0]["id"]
    # 과거 마감 → 초과로 집계
    client.patch(f"/api/findings/{fid}", headers=h,
                 json={"status": "처리중", "deadline": "2020-01-01T00:00:00", "dept": "마감팀"})
    d = client.get("/api/dashboard", headers=h).json()
    assert d["overdue"] == 1
    before = client.get(
        "/api/notifications/preview", headers=h, params={"dept": "마감팀"},
    ).json()
    assert "마감 2020-01-01" in before["body"]

    cleared = client.patch(f"/api/findings/{fid}", headers=h, json={"deadline": None})

    assert cleared.status_code == 200 and cleared.json()["deadline"] is None
    assert client.get("/api/dashboard", headers=h).json()["overdue"] == 0
    after = client.get(
        "/api/notifications/preview", headers=h, params={"dept": "마감팀"},
    ).json()
    assert after["finding_count"] == 1
    assert "2020-01-01" not in after["body"]


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
