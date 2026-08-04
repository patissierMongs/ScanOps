"""Phase F 검증 — 자산대장 매칭(IP→부서) + 부서통보."""
import io
import zipfile

import openpyxl
import pytest
from fastapi import HTTPException
from scanops.db import SessionLocal
from scanops.models import Finding
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client, role="auditor"):
    make_user("op", "pw", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _import(client, h):
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", f, "text/xml")})


def _xlsx_bytes(rows, sparse_cell=None):
    wb = openpyxl.Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    if sparse_cell:
        ws[sparse_cell] = "bomb"
    buf = io.BytesIO()
    wb.save(buf)
    wb.close()
    return buf.getvalue()


def test_asset_matches_findings_dept(client):
    h = _auth(client)
    client.post("/api/assets", headers=h,
                json={"ip": "127.0.0.1", "hostname": "loc", "dept": "인프라운영팀", "owner": "홍길동"})
    _import(client, h)
    rows = client.get("/api/findings", headers=h).json()
    assert rows and all(r["dept"] == "인프라운영팀" for r in rows)


def test_manual_finding_dept_without_asset_survives_later_scan_import(client):
    h = _auth(client)
    _import(client, h)
    finding = client.get("/api/findings", headers=h).json()[0]

    response = client.patch(
        f"/api/findings/{finding['id']}", headers=h, json={"dept": "수동배정부서"},
    )
    assert response.status_code == 200 and response.json()["dept"] == "수동배정부서"

    _import(client, h)

    assert client.get(f"/api/findings/{finding['id']}", headers=h).json()["dept"] == "수동배정부서"


def test_asset_xlsx_import(client):
    h = _auth(client)
    data = _xlsx_bytes([
        ["IP", "호스트명", "부서", "담당자"],
        ["127.0.0.1", "loc", "보안팀", "김보안"],
    ])
    r = client.post("/api/assets/import", headers=h,
                    files={"file": ("assets.xlsx", data, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200 and r.json()["added"] == 1
    assert client.get("/api/assets", headers=h).json()[0]["dept"] == "보안팀"


def test_asset_import_rejects_oversized_upload(client, monkeypatch):
    from scanops.api import assets as assets_api

    h = _auth(client)
    monkeypatch.setattr(assets_api._settings, "upload_max_bytes", 16)
    r = client.post(
        "/api/assets/import", headers=h,
        files={"file": ("large.xlsx", b"x" * 17,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert r.status_code == 413


def test_dept_notification(client):
    h = _auth(client)
    client.post("/api/assets", headers=h, json={"ip": "127.0.0.1", "dept": "인프라운영팀"})
    _import(client, h)

    pv = client.get("/api/notifications/preview", headers=h, params={"dept": "인프라운영팀"}).json()
    assert pv["finding_count"] >= 1 and "인프라운영팀" in pv["body"]

    r = client.post("/api/notifications", headers=h, params={"dept": "인프라운영팀"})
    assert r.status_code == 201 and "미조치 발견" in r.json()["body"]
    assert len(client.get("/api/notifications", headers=h).json()) == 1


def test_omitted_asset_fields_preserve_asset_and_finding_attribution(client):
    h = _auth(client)
    created = client.post("/api/assets", headers=h, json={
        "ip": "127.0.0.1", "dept": "보안팀", "owner": "김담당", "contact": "1234",
    }).json()
    _import(client, h)

    response = client.patch(f"/api/assets/{created['id']}", headers=h, json={"ip": "127.0.0.1"})
    assert response.status_code == 200
    assert response.json()["dept"] == "보안팀"
    findings = client.get("/api/findings", headers=h).json()
    assert findings and all(
        f["dept"] == "보안팀" and f["owner"] == "김담당" and f["contact"] == "1234"
        for f in findings
    )


def test_explicit_blank_asset_fields_clear_finding_attribution(client):
    h = _auth(client)
    created = client.post("/api/assets", headers=h, json={
        "ip": "127.0.0.1", "dept": "보안팀", "owner": "김담당", "contact": "1234",
    }).json()
    _import(client, h)

    response = client.patch(f"/api/assets/{created['id']}", headers=h, json={
        "ip": "127.0.0.1", "dept": " ", "owner": "", "contact": "",
    })
    assert response.status_code == 200
    findings = client.get("/api/findings", headers=h).json()
    assert findings and all(
        f["dept"] == "" and f["owner"] == "" and f["contact"] == "" for f in findings
    )
    preview = client.get("/api/notifications/preview", headers=h, params={"dept": "보안팀"}).json()
    assert preview["finding_count"] == 0
    assert "김담당" not in preview["body"] and "1234" not in preview["body"]


def test_deleting_asset_clears_finding_attribution(client):
    auditor = _auth(client)
    created = client.post("/api/assets", headers=auditor, json={
        "ip": "127.0.0.1", "dept": "보안팀", "owner": "김담당", "contact": "1234",
    }).json()
    _import(client, auditor)
    make_user("asset-admin", "adminpw12", role="admin")
    admin = {"Authorization": f"Bearer {token_for(client, 'asset-admin', 'adminpw12')}"}

    assert client.delete(f"/api/assets/{created['id']}", headers=admin).status_code == 204
    findings = client.get("/api/findings", headers=auditor).json()
    assert findings and all(
        f["dept"] == "" and f["owner"] == "" and f["contact"] == "" for f in findings
    )
    preview = client.get(
        "/api/notifications/preview", headers=auditor, params={"dept": "보안팀"},
    ).json()
    assert preview["finding_count"] == 0
    assert "김담당" not in preview["body"] and "1234" not in preview["body"]


def test_bulk_import_preserves_unmapped_fields_and_merges_extra_keys(client):
    h = _auth(client)
    client.post("/api/assets", headers=h, json={
        "ip": "127.0.0.1", "hostname": "server-a", "dept": "보안팀",
        "owner": "김담당", "contact": "1234", "extra": {"OS": "Linux", "Rack": "R1"},
    })
    response = client.post("/api/assets/bulk", headers=h, json=[{
        "ip": "127.0.0.1", "dept": "", "extra": {"Rack": "", "Zone": "A"},
    }])
    assert response.status_code == 200
    asset = client.get("/api/assets", headers=h).json()[0]
    assert asset["dept"] == ""
    assert asset["hostname"] == "server-a"
    assert asset["owner"] == "김담당"
    assert asset["contact"] == "1234"
    assert asset["extra"] == {"OS": "Linux", "Zone": "A"}


def test_direct_xlsx_blank_clears_only_mapped_field(client):
    h = _auth(client)
    client.post("/api/assets", headers=h, json={
        "ip": "127.0.0.1", "hostname": "server-a", "dept": "보안팀",
        "owner": "김담당", "contact": "1234", "extra": {"OS": "Linux"},
    })
    data = _xlsx_bytes([["IP", "부서"], ["127.0.0.1", ""]])

    response = client.post(
        "/api/assets/import", headers=h,
        files={"file": ("mapped-blank.xlsx", data,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )

    assert response.status_code == 200
    assert response.json()["updated"] == 1
    asset = client.get("/api/assets", headers=h).json()[0]
    assert asset["dept"] == ""
    assert asset["hostname"] == "server-a"
    assert asset["owner"] == "김담당"
    assert asset["contact"] == "1234"
    assert asset["extra"] == {"OS": "Linux"}


def test_asset_ip_change_recomputes_old_fallback_and_new_attribution(client):
    h = _auth(client)
    _import(client, h)
    db = SessionLocal()
    try:
        db.add(Finding(
            finding_key="127.0.0.2|8081|tcp", host_ip="127.0.0.2", port=8081, proto="tcp",
        ))
        db.commit()
    finally:
        db.close()

    client.post("/api/assets", headers=h, json={"ip": "127.0.0.1", "dept": "기존팀"})
    moving = client.post(
        "/api/assets", headers=h,
        json={"ip": "127.0.0.1", "dept": "이동팀", "owner": "이담당", "contact": "5678"},
    ).json()

    response = client.patch(
        f"/api/assets/{moving['id']}", headers=h,
        json={"ip": "127.0.0.2"},
    )

    assert response.status_code == 200
    findings = client.get("/api/findings", headers=h).json()
    old_rows = [f for f in findings if f["host_ip"] == "127.0.0.1"]
    new_row = next(f for f in findings if f["host_ip"] == "127.0.0.2")
    assert old_rows and all(f["dept"] == "기존팀" for f in old_rows)
    assert new_row["dept"] == "이동팀"
    assert new_row["owner"] == "이담당"
    assert new_row["contact"] == "5678"


def test_deleting_newest_same_ip_asset_falls_back_to_previous_asset(client):
    auditor = _auth(client)
    _import(client, auditor)
    client.post("/api/assets", headers=auditor, json={"ip": "127.0.0.1", "dept": "기존팀"})
    newest = client.post(
        "/api/assets", headers=auditor, json={"ip": "127.0.0.1", "dept": "신규팀"},
    ).json()
    make_user("asset-fallback-admin", "adminpw12", role="admin")
    admin = {"Authorization": f"Bearer {token_for(client, 'asset-fallback-admin', 'adminpw12')}"}

    assert client.delete(f"/api/assets/{newest['id']}", headers=admin).status_code == 204
    findings = client.get("/api/findings", headers=auditor).json()
    assert findings and all(f["dept"] == "기존팀" for f in findings)


def test_asset_xlsx_compressed_and_expanded_size_boundaries(client, monkeypatch):
    from scanops.api import assets as assets_api

    h = _auth(client)
    data = _xlsx_bytes([["IP", "부서"], ["10.0.0.1", "보안팀"]])
    content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        expanded = sum(entry.file_size for entry in archive.infolist())

    monkeypatch.setattr(assets_api._settings, "upload_max_bytes", len(data))
    monkeypatch.setattr(assets_api._settings, "asset_xlsx_max_uncompressed_bytes", expanded)
    exact = client.post(
        "/api/assets/import", headers=h, files={"file": ("exact.xlsx", data, content_type)},
    )
    assert exact.status_code == 200

    monkeypatch.setattr(assets_api._settings, "upload_max_bytes", len(data) - 1)
    assert client.post(
        "/api/assets/import", headers=h, files={"file": ("compressed-over.xlsx", data, content_type)},
    ).status_code == 413

    monkeypatch.setattr(assets_api._settings, "upload_max_bytes", len(data))
    monkeypatch.setattr(assets_api._settings, "asset_xlsx_max_uncompressed_bytes", expanded - 1)
    assert client.post(
        "/api/assets/import", headers=h, files={"file": ("expanded-over.xlsx", data, content_type)},
    ).status_code == 413


def test_asset_xlsx_zip_entry_count_boundary(monkeypatch):
    from scanops.api import assets as assets_api

    def archive_with_entries(count: int) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index in range(count):
                archive.writestr(f"empty/{index}", b"")
        return out.getvalue()

    monkeypatch.setattr(assets_api._settings, "asset_xlsx_max_entries", 3)
    assets_api._validate_xlsx_archive(archive_with_entries(3))
    with pytest.raises(HTTPException) as exc:
        assets_api._validate_xlsx_archive(archive_with_entries(4))
    assert exc.value.status_code == 413
    assert "ZIP 항목 수" in exc.value.detail


def test_asset_xlsx_sheet_dimension_boundaries(client, monkeypatch):
    from scanops.api import assets as assets_api

    h = _auth(client)
    data = _xlsx_bytes([["IP", "부서"], ["10.0.0.2", "보안팀"]])
    upload = {"file": ("dimensions.xlsx", data,
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_rows", 2)
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_columns", 2)
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_cells", 4)
    assert client.post("/api/assets/import", headers=h, files=upload).status_code == 200

    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_rows", 1)
    assert client.post("/api/assets/import", headers=h, files=upload).status_code == 413
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_rows", 2)
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_columns", 1)
    assert client.post("/api/assets/import", headers=h, files=upload).status_code == 413
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_columns", 2)
    monkeypatch.setattr(assets_api._settings, "asset_sheet_max_cells", 3)
    assert client.post("/api/assets/import", headers=h, files=upload).status_code == 413


def test_asset_xlsx_sparse_dimension_bomb_is_rejected(client):
    h = _auth(client)
    data = _xlsx_bytes([["IP"]], sparse_cell="XFD100001")

    response = client.post(
        "/api/assets/import", headers=h,
        files={"file": ("sparse.xlsx", data,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )

    assert response.status_code == 413
