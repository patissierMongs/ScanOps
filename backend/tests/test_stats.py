"""포트·서비스 빈출 통계 — 확정 열림과 무응답 추정을 절대 합치지 않는다."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from scanops.db import SessionLocal
from scanops.models import Finding
from scanops.observation import needs_confirmation
from tests.conftest import make_user, token_for


def _auth(client):
    make_user("op", "pw", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _add(**kw):
    """발견 하나. 기본은 확정 열림(syn-ack)."""
    # **지금 기준 상대 시각**이다. 고정 날짜를 쓰면 시간이 흐르면서 기간 필터 검사가
    # 조용히 무의미해진다(전부 기간 밖이 되어 0 == 0 으로 통과한다).
    defaults = dict(state="open", reason="syn-ack", proto="tcp", service="",
                    product="", dept="", risk_level="info", status="미조치", allowed=0,
                    last_seen=_now() - timedelta(days=1))
    defaults.update(kw)
    key = f"{defaults['host_ip']}|{defaults['port']}|{defaults['proto']}"
    db = SessionLocal()
    try:
        db.add(Finding(finding_key=key, **defaults))
        db.commit()
    finally:
        db.close()


def test_inferred_open_never_counts_as_confirmed(client):
    """무응답 추정을 확정 열림과 합치면 통계가 거짓말을 한다.

    UDP 는 응답이 없으면 nmap 이 `open|filtered` 로 보고한다. 그걸 확정 열림과 한 수로
    합치면 방화벽이 조용히 버리는 대역에서 UDP 포트가 상위를 싹쓸이하면서 '우리 망에
    SNMP 가 제일 많다' 는 결론이 나온다 - 실제로는 아무도 응답하지 않았다는 뜻인데도.
    """
    h = _auth(client)
    # SNMP: 무응답 추정 5대. TCP 22: 확정 열림 2대.
    for i in range(5):
        _add(host_ip=f"10.0.0.{i}", port=161, proto="udp", service="snmp",
             state="open|filtered", reason="no-response")
    for i in range(2):
        _add(host_ip=f"10.0.1.{i}", port=22, proto="tcp", service="ssh")

    data = client.get("/api/stats", headers=h).json()
    rows = {(r["port"], r["proto"]): r for r in data["ports"]}

    snmp = rows[(161, "udp")]
    assert snmp["inferred"] == 5 and snmp["confirmed"] == 0, (
        f"응답도 없는 UDP 포트를 확정 열림으로 셌다: {snmp}"
    )
    ssh = rows[(22, "tcp")]
    assert ssh["confirmed"] == 2 and ssh["inferred"] == 0

    # 정렬은 확정 열림 기준 - 추정만 잔뜩인 포트가 1위로 올라오면 안 된다.
    assert data["ports"][0]["port"] == 22, (
        f"무응답 추정이 많은 포트가 상위를 차지했다: {data['ports'][0]}"
    )
    assert data["totals"] == {"findings": 7, "hosts": 7, "confirmed": 2, "inferred": 5}


def test_the_inferred_rule_matches_the_findings_list(client):
    """통계의 '추정' 판정은 발견 목록과 같아야 한다.

    발견 목록은 `needs_confirmation()` 으로 접고, 통계는 같은 판정을 SQL 로 옮겼다.
    둘이 어긋나면 '접힌 건수 3' 인데 통계는 5 라고 말하는 화면이 된다.
    """
    h = _auth(client)
    cases = [
        ("open", "syn-ack", False),
        ("open", "no-response", True),
        ("open|filtered", "no-response", True),
        ("open|filtered", "", True),
    ]
    for i, (state, reason, _) in enumerate(cases):
        _add(host_ip=f"10.9.0.{i}", port=1000 + i, state=state, reason=reason)

    data = client.get("/api/stats", headers=h).json()
    by_port = {r["port"]: r for r in data["ports"]}
    for i, (state, reason, expected_inferred) in enumerate(cases):
        row = by_port[1000 + i]
        sql_says = row["inferred"] == 1
        python_says = needs_confirmation(state, reason)
        assert sql_says == python_says == expected_inferred, (
            f"{state!r}/{reason!r}: 통계는 추정={sql_says}, 발견 목록은 {python_says}"
        )


def test_filters_narrow_every_axis_the_same_way(client):
    """부서·위험·프로토콜·기간 필터가 모든 축에 같은 모수를 만든다."""
    h = _auth(client)
    old = _now() - timedelta(days=90)
    _add(host_ip="10.2.0.1", port=80, service="http", dept="영업", risk_level="high")
    _add(host_ip="10.2.0.2", port=80, service="http", dept="개발", risk_level="low")
    _add(host_ip="10.2.0.3", port=53, proto="udp", service="domain", dept="영업",
         risk_level="high")
    _add(host_ip="10.2.0.4", port=443, service="https", dept="영업", risk_level="high",
         last_seen=old)

    everything = client.get("/api/stats", headers=h).json()
    assert everything["totals"]["findings"] == 4

    by_dept = client.get("/api/stats?dept=영업", headers=h).json()
    assert by_dept["totals"]["findings"] == 3
    assert {r["service"] for r in by_dept["services"]} == {"http", "domain", "https"}

    by_proto = client.get("/api/stats?proto=udp", headers=h).json()
    assert [r["port"] for r in by_proto["ports"]] == [53]

    by_risk = client.get("/api/stats?risk=low", headers=h).json()
    assert by_risk["totals"]["findings"] == 1

    recent = client.get("/api/stats?days=30", headers=h).json()
    assert recent["totals"]["findings"] == 3, "기간 밖의 오래된 관측이 섞였다"
    assert 443 not in {r["port"] for r in recent["ports"]}

    # 부서 선택지는 필터와 무관하게 전체여야 다른 부서로 옮겨 갈 수 있다.
    assert set(by_dept["dept_options"]) == {"영업", "개발"}


def test_resolved_and_allowed_are_out_by_default(client):
    """정상처리·운영상 허용은 기본 모수에서 빠진다 - 발견 목록과 같은 기본값이다."""
    h = _auth(client)
    _add(host_ip="10.3.0.1", port=8080, service="http")
    _add(host_ip="10.3.0.2", port=8080, service="http", status="정상처리")
    _add(host_ip="10.3.0.3", port=8080, service="http", allowed=1)

    default = client.get("/api/stats", headers=h).json()
    assert default["ports"][0]["hosts"] == 1, "정상처리·허용까지 셌다"

    both = client.get(
        "/api/stats?include_resolved=true&include_allowed=true", headers=h).json()
    assert both["ports"][0]["hosts"] == 3


def test_export_carries_the_same_numbers_as_the_screen(client):
    """CSV 는 화면과 같은 수를 내보내야 한다 - 다르면 보고서가 화면과 어긋난다."""
    h = _auth(client)
    _add(host_ip="10.4.0.1", port=3306, service="mysql")
    _add(host_ip="10.4.0.2", port=3306, service="mysql")
    _add(host_ip="10.4.0.3", port=161, proto="udp", service="snmp",
         state="open|filtered", reason="no-response")

    screen = client.get("/api/stats", headers=h).json()
    csv = client.get("/api/stats/export?axis=ports", headers=h)
    assert csv.status_code == 200
    assert csv.text.startswith("﻿"), "엑셀이 한글을 깨뜨리지 않게 BOM 이 필요하다"

    lines = [l for l in csv.text.lstrip("﻿").splitlines() if l.strip()]
    assert lines[0] == "포트,프로토콜,호스트,발견,확정 열림,무응답 추정"
    rows = {int(l.split(",")[0]): l.split(",") for l in lines[1:]}
    for row in screen["ports"]:
        cells = rows[row["port"]]
        assert [int(cells[2]), int(cells[3]), int(cells[4]), int(cells[5])] == [
            row["hosts"], row["findings"], row["confirmed"], row["inferred"]
        ], f"CSV 와 화면이 다르다: {cells} vs {row}"


def test_the_aggregate_does_not_load_finding_objects(client):
    """집계는 SQL 로 한다 - 세는 데 배너·NSE JSON 을 실어 나를 이유가 없다."""
    from sqlalchemy import event

    from scanops.db import _engine

    h = _auth(client)
    _add(host_ip="10.5.0.1", port=22, service="ssh")

    seen: list[str] = []
    record = lambda c, cu, s, p, ctx, e: seen.append(s)  # noqa: E731
    event.listen(_engine, "before_cursor_execute", record)
    try:
        assert client.get("/api/stats", headers=h).status_code == 200
    finally:
        event.remove(_engine, "before_cursor_execute", record)

    selects = [s for s in seen if "FROM findings" in s]
    assert selects, "findings 를 읽지도 않았다 - 이 검사는 아무것도 안 보고 있다"
    for column in ("findings.banner", "findings.nse_json", "findings.compliance_json"):
        assert not any(column in s for s in selects), f"{column} 까지 실어 나른다"
