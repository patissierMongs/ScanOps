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


def test_the_dashboard_does_not_haul_every_finding_row_to_count_them(client):
    """대시보드는 세는 데 필요한 열만 실어야 한다.

    화면을 옮길 때마다 호출되는 엔드포인트다(App.jsx). 예전에는 활성 발견의 Finding
    객체를 통째로 실었는데, 거기엔 배너·NSE·컴플라이언스 JSON 같은 큰 필드가 딸려 온다.
    발견이 쌓인 설치에서는 평범한 화면 이동마다 그만큼의 전송과 할당이 반복된다.

    지표가 읽는 것은 여섯 컬럼뿐이다. 그래서 (1) 큰 필드를 SELECT 하지 않고,
    (2) 그래도 결과는 예전과 **똑같아야** 한다.
    """
    from sqlalchemy import event

    from scanops.db import _engine

    h = _auth(client)
    _import(client, h)

    statements: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(_engine, "before_cursor_execute", record)
    try:
        data = client.get("/api/dashboard", headers=h).json()
    finally:
        event.remove(_engine, "before_cursor_execute", record)

    selects = [s for s in statements if "FROM findings" in s]
    assert selects, "findings 를 읽지도 않았다 - 이 검사는 아무것도 안 보고 있다"
    # 지표가 쓰지 않는 큰 필드. 하나라도 실리면 예전 방식으로 돌아간 것이다.
    for column in ("findings.banner", "findings.nse_json", "findings.compliance_json",
                   "findings.exposure_json"):
        assert not any(column in s for s in selects), (
            f"{column} 까지 실어 나른다 - 세는 데 필요 없는 열이다"
        )

    # 줄인 뒤에도 답은 같아야 한다.
    assert data["open_total"] == 13
    assert sum(data["by_status"].values()) == 13
    assert data["overdue"] == 0
    assert data["confirmed_open_total"] + data["confirmation_required_total"] >= 1
    assert sum(row["count"] for row in data["by_dept"]) == data["unresolved_total"]
