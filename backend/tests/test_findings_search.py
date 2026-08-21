"""발견 목록 검색·컬럼 필터·정렬·페이지 — 화면과 내보내기가 같은 뷰를 쓰는지까지.

핵심 계약: 검색/필터/정렬은 **표에 보이는 값** 기준이다. 계산 컬럼(표시 식별·용도근거 등)을
SQL 로만 거르면 그런 값으로만 일치하는 행이 조용히 빠지므로, 서버가 표시값으로 판정한다.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from scanops.db import SessionLocal
from scanops.models import Finding, ScanRun

from .conftest import make_user, token_for


def _auth(client, role="auditor"):
    make_user(f"find_{role}", "Finding-pass-1234", role)
    return {"Authorization": "Bearer " + token_for(client, f"find_{role}", "Finding-pass-1234")}


def _add(**kw):
    base = {
        "finding_key": kw.get("finding_key") or f"{kw['host_ip']}|{kw['port']}|tcp",
        "proto": "tcp", "state": "open", "status": "미조치", "risk_level": "info",
        "service": "", "product": "", "version": "", "server": "", "hostname": "",
    }
    base.update(kw)
    db = SessionLocal()
    try:
        db.add(Finding(**base))
        db.commit()
    finally:
        db.close()


def _seed():
    _add(host_ip="10.0.0.1", port=22, service="ssh", product="OpenSSH", version="9.7",
         hostname="bastion.corp")
    _add(host_ip="10.0.0.2", port=8770, service="apple-iphoto", server="uvicorn",
         hostname="api.corp")
    _add(host_ip="10.0.0.10", port=443, service="https", product="nginx", version="1.24",
         hostname="www.corp")


def _names(rows):
    return sorted(f"{r['host_ip']}:{r['port']}" for r in rows)


# ── 전체 검색: 일부 포함 / 정확히 ──

def test_search_covers_every_column_including_computed_ones(client):
    """'표시 식별'은 DB 컬럼이 아니다 — SQL 로만 거르면 uvicorn 검색이 아무것도 못 찾는다."""
    auth = _auth(client)
    _seed()
    rows = client.get("/api/findings?q=uvicorn", headers=auth).json()
    assert _names(rows) == ["10.0.0.2:8770"]

    # 용도근거(purpose)는 호스트명·서비스를 조합한 계산 컬럼이다.
    assert _names(client.get("/api/findings?q=bastion", headers=auth).json()) == ["10.0.0.1:22"]


def test_exact_match_requires_the_whole_cell_to_equal_the_term(client):
    auth = _auth(client)
    _seed()
    partial = client.get("/api/findings?q=ssh&match=contains", headers=auth).json()
    assert _names(partial) == ["10.0.0.1:22"]

    # 'ssh' 는 'OpenSSH 9.7' 의 일부일 뿐 어떤 셀과도 완전히 같지 않다… 서비스명 'ssh' 는 같다.
    exact = client.get("/api/findings?q=ssh&match=exact", headers=auth).json()
    assert _names(exact) == ["10.0.0.1:22"]
    # 반면 부분 문자열은 정확히 모드에서 걸리지 않는다.
    assert client.get("/api/findings?q=uvico&match=exact", headers=auth).json() == []
    assert _names(client.get("/api/findings?q=uvico&match=contains", headers=auth).json()) == ["10.0.0.2:8770"]


def test_search_is_case_insensitive(client):
    auth = _auth(client)
    _seed()
    assert _names(client.get("/api/findings?q=UVICORN", headers=auth).json()) == ["10.0.0.2:8770"]
    # 정확히 모드도 대소문자는 무시한다 — 'nginx' 제품명 셀 전체와 같으므로 걸린다.
    assert _names(client.get("/api/findings?q=NGINX&match=exact", headers=auth).json()) == ["10.0.0.10:443"]
    # 그러나 셀 일부일 뿐인 값은 여전히 안 걸린다.
    assert client.get("/api/findings?q=NGIN&match=exact", headers=auth).json() == []


# ── 컬럼별 필터 ──

def test_column_filters_narrow_only_that_column(client):
    auth = _auth(client)
    _seed()
    filters = json.dumps({"service": "ssh"})
    assert _names(client.get(f"/api/findings?filters={filters}", headers=auth).json()) == ["10.0.0.1:22"]

    # 같은 문자열이라도 다른 컬럼을 지정하면 걸리지 않는다 — 전체 검색과의 차이가 이것이다.
    filters = json.dumps({"hostname": "ssh"})
    assert client.get(f"/api/findings?filters={filters}", headers=auth).json() == []


def test_column_filters_combine_with_and(client):
    auth = _auth(client)
    _seed()
    both = json.dumps({"host_ip": "10.0.0.", "service": "https"})
    assert _names(client.get(f"/api/findings?filters={both}", headers=auth).json()) == ["10.0.0.10:443"]

    impossible = json.dumps({"service": "ssh", "hostname": "www"})
    assert client.get(f"/api/findings?filters={impossible}", headers=auth).json() == []


def test_unknown_filter_column_is_rejected_instead_of_ignored(client):
    """오타를 조용히 무시하면 '필터를 걸었는데 다 나온다'로 보인다."""
    auth = _auth(client)
    _seed()
    bad = json.dumps({"nope": "x"})
    assert client.get(f"/api/findings?filters={bad}", headers=auth).status_code == 400
    assert client.get("/api/findings?filters=not-json", headers=auth).status_code == 400
    assert client.get("/api/findings?sort=nope", headers=auth).status_code == 400
    assert client.get("/api/findings?match=fuzzy", headers=auth).status_code == 400


# ── 정렬 ──

def test_sorting_by_port_is_numeric_not_lexicographic(client):
    """문자열 정렬이면 443 < 8770 < 22 가 된다 — 포트는 숫자로 정렬해야 한다."""
    auth = _auth(client)
    _seed()
    rows = client.get("/api/findings?sort=port&dir=asc", headers=auth).json()
    assert [r["port"] for r in rows] == [22, 443, 8770]
    rows = client.get("/api/findings?sort=port&dir=desc", headers=auth).json()
    assert [r["port"] for r in rows] == [8770, 443, 22]


def test_sorting_by_a_computed_column_uses_the_displayed_value(client):
    auth = _auth(client)
    _seed()
    rows = client.get("/api/findings?sort=display_identity&dir=asc", headers=auth).json()
    # 표시 식별 = Server → 제품+버전 → 서비스 순. nginx 1.24 / OpenSSH 9.7 / uvicorn
    assert [r["host_ip"] for r in rows] == ["10.0.0.10", "10.0.0.1", "10.0.0.2"]


def test_empty_values_sort_last_so_filled_rows_stay_on_top(client):
    auth = _auth(client)
    _seed()
    _add(host_ip="10.0.0.99", port=9999)      # hostname 비어 있음
    rows = client.get("/api/findings?sort=hostname&dir=asc", headers=auth).json()
    assert rows[-1]["host_ip"] == "10.0.0.99"


# ── 페이지 + payload ──

def test_paging_reports_the_full_count_in_a_header(client):
    auth = _auth(client)
    _seed()
    r = client.get("/api/findings?limit=2&offset=0&sort=port", headers=auth)
    assert r.headers["X-Total-Count"] == "3"
    assert [row["port"] for row in r.json()] == [22, 443]

    r = client.get("/api/findings?limit=2&offset=2&sort=port", headers=auth)
    assert r.headers["X-Total-Count"] == "3"
    assert [row["port"] for row in r.json()] == [8770]


def test_total_count_reflects_filters_not_the_whole_table(client):
    auth = _auth(client)
    _seed()
    r = client.get("/api/findings?q=uvicorn&limit=50", headers=auth)
    assert r.headers["X-Total-Count"] == "1"


def test_fingerprint_payload_is_dropped_unless_that_column_is_shown(client):
    """수천 건 목록에서 응답 크기를 좌우하는 건 이 원문이다. 안 보이면 실어 보내지 않는다."""
    auth = _auth(client)
    _add(host_ip="10.0.0.3", port=8080, service="http",
         nse_json=[{"id": "fingerprint-strings", "output": "GetRequest:\n  server: uvicorn"}])
    shown = client.get("/api/findings?cols=host_ip,fingerprint", headers=auth).json()
    assert "uvicorn" in shown[0]["fingerprint"]

    hidden = client.get("/api/findings?cols=host_ip,port", headers=auth).json()
    assert hidden[0]["fingerprint"] == ""
    # 컬럼을 안 넘기면(구 클라이언트) 종전대로 전부 준다.
    assert "uvicorn" in client.get("/api/findings", headers=auth).json()[0]["fingerprint"]


# ── 표 = 내보내기 ──

def test_export_applies_the_same_search_filters_and_sort_as_the_table(client):
    """화면에서 걸러 본 것과 내보낸 것이 다르면 보고서가 조용히 틀린다."""
    auth = _auth(client)
    _seed()
    query = "cols=host_ip,port&fmt=csv&q=corp&filters=" + json.dumps({"service": "s"}) + "&sort=port&dir=desc"
    body = client.get(f"/api/findings/export?{query}", headers=auth).content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(body)))
    exported = [tuple(r) for r in rows[1:]]

    listed = client.get(f"/api/findings?q=corp&filters={json.dumps({'service': 's'})}&sort=port&dir=desc",
                        headers=auth).json()
    assert exported == [(r["host_ip"], str(r["port"])) for r in listed]
    assert exported == [("10.0.0.10", "443"), ("10.0.0.1", "22")]


# ── 화면 토글은 페이지를 자르기 전에 적용돼야 한다 ──

def _seed_many(normal=200, open_rows=1):
    for i in range(normal):
        _add(host_ip=f"10.1.{i // 250}.{i % 250}", port=1000 + i, status="정상처리")
    for i in range(open_rows):
        _add(host_ip=f"10.9.9.{i}", port=2000 + i, status="미조치")


def test_hide_normal_runs_before_paging_so_the_first_page_is_not_empty(client):
    """페이지를 자른 뒤 화면에서 걸러내면, 조건에 맞는 행이 뒷 페이지에 남아 첫 페이지가 빈 것처럼
    보인다. 정상처리 200건 뒤에 미조치 1건이 있는 배치가 정확히 그 상황이다."""
    auth = _auth(client)
    _seed_many(normal=200, open_rows=1)

    r = client.get("/api/findings?hide_normal=true&limit=200&offset=0", headers=auth)
    rows = r.json()
    assert r.headers["X-Total-Count"] == "1"      # 화면에 실제로 보일 건수
    assert [row["host_ip"] for row in rows] == ["10.9.9.0"]
    assert all(row["status"] != "정상처리" for row in rows)


def test_overdue_only_runs_before_paging_too(client):
    auth = _auth(client)
    for i in range(200):
        _add(host_ip=f"10.2.0.{i % 250}", port=3000 + i, status="미조치",
             deadline=datetime(2999, 1, 1))
    _add(host_ip="10.9.9.9", port=4000, status="미조치", deadline=datetime(2000, 1, 1))

    r = client.get("/api/findings?overdue_only=true&today=2026-08-11&limit=200&offset=0", headers=auth)
    assert r.headers["X-Total-Count"] == "1"
    assert [row["host_ip"] for row in r.json()] == ["10.9.9.9"]


def test_overdue_uses_the_client_date_not_the_server_timezone(client):
    """화면의 'N일 초과' 표시는 사용자 로컬 날짜 기준이다. 서버 UTC 로 판정하면 KST 오전처럼
    날짜가 하루 어긋나는 시간대에서 표시와 필터 결과가 달라진다."""
    auth = _auth(client)
    _add(host_ip="10.3.0.1", port=22, status="미조치", deadline=datetime(2026, 8, 10))

    # 사용자의 오늘이 8/11 이면 8/10 마감은 초과다.
    assert len(client.get("/api/findings?overdue_only=true&today=2026-08-11", headers=auth).json()) == 1
    # 사용자의 오늘이 아직 8/10 이면 초과가 아니다.
    assert client.get("/api/findings?overdue_only=true&today=2026-08-10", headers=auth).json() == []
    assert client.get("/api/findings?overdue_only=true&today=nope", headers=auth).status_code == 400


def test_export_matches_the_filtered_view_beyond_one_page(client):
    """건수·화면·내보내기가 같은 뷰를 봐야 한다. 예전엔 CSV 에 정상처리 200건이 그대로 들어갔다."""
    auth = _auth(client)
    _seed_many(normal=200, open_rows=1)

    body = client.get("/api/findings/export?cols=host_ip,status&fmt=csv&hide_normal=true",
                      headers=auth).content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(body)))[1:]
    assert rows == [["10.9.9.0", "미조치"]]


def test_findings_without_a_deadline_are_never_overdue(client):
    auth = _auth(client)
    _add(host_ip="10.4.0.1", port=22, status="미조치")
    assert client.get("/api/findings?overdue_only=true&today=2026-08-11", headers=auth).json() == []


def test_finding_exposes_current_reason_and_scan_provenance(client):
    auth = _auth(client)
    db = SessionLocal()
    try:
        first = ScanRun(name="최초", status="done")
        latest = ScanRun(name="최근", status="done")
        db.add_all([first, latest])
        db.flush()
        finding = Finding(
            finding_key="10.50.0.1|22|tcp", host_ip="10.50.0.1", port=22, proto="tcp",
            state="closed", reason="syn-ack", first_scan_id=first.id, last_scan_id=latest.id,
        )
        db.add(finding)
        db.commit()
        finding_id, first_id, latest_id = finding.id, first.id, latest.id
    finally:
        db.close()

    payload = client.get(f"/api/findings/{finding_id}", headers=auth).json()
    assert payload["reason"] == "syn-ack"       # 원본 provenance는 보존
    assert payload["current_reason"] == ""      # 현재 closed의 근거처럼 재사용하지 않음
    assert payload["first_scan_id"] == first_id
    assert payload["last_scan_id"] == latest_id


def test_risk_sort_uses_operational_ordinal(client):
    auth = _auth(client)
    for index, level in enumerate(("medium", "info", "banned", "low", "high"), start=1):
        _add(host_ip=f"10.60.0.{index}", port=8000 + index, risk_level=level)

    descending = client.get(
        "/api/findings?sort=risk_level&dir=desc", headers=auth,
    ).json()
    ascending = client.get(
        "/api/findings?sort=risk_level&dir=asc", headers=auth,
    ).json()

    assert [row["risk_level"] for row in descending] == [
        "banned", "high", "medium", "low", "info",
    ]
    assert [row["risk_level"] for row in ascending] == [
        "info", "low", "medium", "high", "banned",
    ]
