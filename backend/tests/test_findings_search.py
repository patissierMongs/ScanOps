"""발견 목록 검색·컬럼 필터·정렬·페이지 — 화면과 내보내기가 같은 뷰를 쓰는지까지.

핵심 계약: 검색/필터/정렬은 **표에 보이는 값** 기준이다. 계산 컬럼(표시 식별·용도근거 등)을
SQL 로만 거르면 그런 값으로만 일치하는 행이 조용히 빠지므로, 서버가 표시값으로 판정한다.
"""
from __future__ import annotations

import csv
import io
import json

from scanops.db import SessionLocal
from scanops.models import Finding

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
