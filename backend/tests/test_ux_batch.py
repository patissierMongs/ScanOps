"""화면에서 바로 드러나는 계약들 — 요약 표기·필터·삭제·허용·강제 변경·가져오기 검증.

이 파일이 지키는 공통 원칙은 하나다: **화면이 사실만 말한다.** 모르면 모른다고 하고,
숨긴 것은 숨겼다고 하며, 지웠다면 실제로 지워져 있어야 한다.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from scanops.api import scans as scans_api
from scanops.db import SessionLocal
from scanops.models import Finding, FindingEvent, RiskRule, ScanRun, User
from scanops.scanning import scan_summary, xml_verdict
from tests.conftest import make_user, token_for

FIXTURE = Path("tests/fixtures/sample_scan.xml")


def _auth(client, role="admin"):
    make_user("ux-op", "uxpassword12", role=role)
    return {"Authorization": f"Bearer {token_for(client, 'ux-op', 'uxpassword12')}"}


def _finished_xml(*, proto="tcp", services="443", port=443, up=1) -> bytes:
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        f'<scaninfo type="syn" protocol="{proto}" numservices="1" services="{services}"/>'
        '<host><status state="up"/><address addr="10.5.5.5" addrtype="ipv4"/><ports>'
        f'<port protocol="{proto}" portid="{port}"><state state="open" reason="syn-ack"/>'
        '<service name="https"/></port></ports></host>'
        f'<runstats><finished exit="success"/><hosts up="{up}" down="0" total="{up}"/>'
        '</runstats></nmaprun>'
    ).encode("utf-8")


# ── 1. 스캔 범위 요약이 없는 사실을 지어내지 않는다 ────────────────────────────
def test_a_scan_summary_never_invents_a_port_range_it_was_not_told():
    """명령 표기가 argv 가 아니면 '기본 1000개 TCP' 로 넘겨짚지 않는다.

    엔진 스캔·자동 스캔·가져오기는 실행된 argv 가 아니라 사람이 읽는 설명을 command 에
    남긴다. 그 설명에 `-p` 가 없다는 이유로 nmap 기본값을 가정하면, 전 포트 TCP+UDP
    스캔이 이력에서 '상위 1000개 TCP' 로 보인다 - 스캔하지 않은 범위를 봤다고 말하고,
    스캔한 범위는 숨기는 이중 오류다.
    """
    blind = scan_summary.summarize_command("단계스캔(엔진) · 발견 sn · 서비스 -sV", "10.0.0.0/24")
    assert blind["ports"] == scan_summary.UNKNOWN_PORTS
    assert blind["protocols"] == [], "무슨 프로토콜을 봤는지 모르면 뱃지도 달지 않는다"

    # 만든 쪽이 범위를 적어 주면 그대로 읽는다.
    noted = scan_summary.summarize_command(
        "단계스캔(엔진) · 발견 sn · TCP 1-65535 · UDP 53,161  ·  "
        + scan_summary.scope_note("1-65535", "53,161"),
        "10.0.0.0/24",
    )
    assert noted["protocols"] == ["TCP", "UDP"]
    assert noted["ports"] == "TCP 전체 · UDP 53,161"

    # 진짜 nmap argv 에서는 기존 판정을 유지한다(포트 플래그가 없으면 실제로 기본 1000개).
    real = scan_summary.summarize_command("nmap -sT 10.0.0.1", "10.0.0.1")
    assert real["ports"] == "기본 1000개" and real["protocols"] == ["TCP"]


def test_the_engine_and_import_paths_record_the_range_they_actually_scanned():
    from scanops.scanning import engine_runner

    staged = engine_runner.describe({
        "stages": {"discovery": {"mode": "sn"},
                   "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": True, "ports": "53,161"},
                   "service": {"version_all": False}},
    })
    summary = scan_summary.summarize_command(staged, "10.0.0.0/24")
    assert summary["protocols"] == ["TCP", "UDP"]
    assert summary["ports"] == "TCP 전체 · UDP 53,161"

    # UDP 만 스캔한 XML 을 가져오면 UDP 스캔으로 보여야 한다 - TCP 로 표시되면 정반대다.
    udp_xml = _finished_xml(proto="udp", services="53,161", port=53)
    imported = scan_summary.summarize_command(
        scans_api._import_command("weekly.udp_identify.xml", udp_xml), "10.5.5.5")
    assert imported["protocols"] == ["UDP"] and imported["ports"] == "53,161"


# ── 3. `!` 제외 필터 ──────────────────────────────────────────────────────────
def test_every_filter_treats_a_leading_bang_as_exclude(client):
    headers = _auth(client)
    db = SessionLocal()
    try:
        run = ScanRun(name="ux", status="done")
        db.add(run)
        db.commit()
        for port, service in ((22, "ssh"), (443, "https"), (3389, "ms-wbt-server")):
            db.add(Finding(
                finding_key=f"10.5.5.5|{port}|tcp", host_ip="10.5.5.5", port=port,
                proto="tcp", state="open", service=service,
                first_scan_id=run.id, last_scan_id=run.id,
            ))
        db.commit()
    finally:
        db.close()

    def services(**params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        rows = client.get(f"/api/findings?state=open&{query}", headers=headers).json()
        return sorted(f["service"] for f in rows)

    assert services(q="ssh") == ["ssh"]
    assert services(q="!ssh") == ["https", "ms-wbt-server"], "전체 검색 제외"
    # 컬럼 필터도 같은 규칙 - 화면마다 규칙이 다르면 외울 수 없다.
    assert services(filters=json.dumps({"service": "!ssh"})) == ["https", "ms-wbt-server"]
    assert services(filters=json.dumps({"service": "ssh"})) == ["ssh"]
    # `!!` 는 문자 그대로의 `!` - 제외를 도입하면서 `!` 검색 자체가 막히면 안 된다.
    assert services(q="!!ssh") == [], "'!ssh' 라는 값은 없으므로 아무것도 안 남는다"


def test_the_event_feed_host_filter_uses_the_same_exclude_rule(client):
    headers = _auth(client)
    db = SessionLocal()
    try:
        run = ScanRun(name="ux", status="done")
        db.add(run)
        db.commit()
        for ip in ("10.5.5.5", "10.5.5.6"):
            finding = Finding(finding_key=f"{ip}|22|tcp", host_ip=ip, port=22, proto="tcp",
                              state="open", first_scan_id=run.id, last_scan_id=run.id)
            db.add(finding)
            db.flush()
            db.add(FindingEvent(finding_id=finding.id, scan_id=run.id,
                                type="NEW_OPEN", detail="22/tcp"))
        db.commit()
    finally:
        db.close()

    def hosts(host):
        feed = client.get(f"/api/events?host={host}", headers=headers).json()
        return sorted({item["host_ip"] for item in feed["items"]})

    assert hosts("10.5.5.5") == ["10.5.5.5"]
    assert hosts("!10.5.5.5") == ["10.5.5.6"]


# ── 6. 최초 로그인 비밀번호 강제 변경 ──────────────────────────────────────────
def test_a_borrowed_password_can_log_in_but_do_nothing_until_it_is_changed(client, tmp_path):
    """INITIAL_ADMIN.txt 의 비밀번호는 평문으로 파일에 남는다.

    '로그인 후 바꾸세요' 라는 안내만으로는 남는다. 바꾸기 전까지는 어떤 작업도 못 하게 막고,
    바꾸는 순간 파일을 지운다 - 파일이 실제로 사라져야 변경이 끝난 것이다.
    """
    cred = scans_api._settings.data_dir / "INITIAL_ADMIN.txt"
    cred.write_text("ScanOps 최초 관리자 계정\n  비밀번호: bootstrappw12\n", encoding="utf-8")
    db = SessionLocal()
    try:
        from scanops.security import hash_password
        db.add(User(username="firstadmin", password_hash=hash_password("bootstrappw12"),
                    role="admin", display_name="관리자", must_change_password=1))
        db.commit()
    finally:
        db.close()

    token = token_for(client, "firstadmin", "bootstrappw12")
    headers = {"Authorization": f"Bearer {token}"}

    # 로그인 자체는 된다 - 비밀번호를 바꾸려면 로그인 상태여야 하기 때문이다.
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200 and me.json()["must_change_password"] == 1

    # 그러나 실제 작업은 전부 막힌다.
    blocked = client.get("/api/findings", headers=headers)
    assert blocked.status_code == 403
    assert "비밀번호를 먼저 변경" in blocked.json()["detail"]

    # 같은 비밀번호로 '변경'해 잠금만 푸는 우회를 막는다.
    same = client.post("/api/auth/change-password", headers=headers,
                       json={"current_password": "bootstrappw12",
                             "new_password": "bootstrappw12"})
    assert same.status_code == 400
    assert cred.exists(), "변경이 거절됐으면 파일도 그대로여야 한다"

    changed = client.post("/api/auth/change-password", headers=headers,
                          json={"current_password": "bootstrappw12",
                                "new_password": "realpassword34"})
    assert changed.status_code == 200
    assert not cred.exists(), "변경했으면 평문 비밀번호 파일은 사라져야 한다"

    # 비밀번호가 바뀌었으니 토큰도 무효 - 새로 받아 정상 작업.
    fresh = {"Authorization": f"Bearer {token_for(client, 'firstadmin', 'realpassword34')}"}
    assert client.get("/api/findings", headers=fresh).status_code == 200


def test_an_admin_reset_also_requires_the_owner_to_choose_a_new_password(client):
    headers = _auth(client)
    created = client.post("/api/users", headers=headers, json={
        "username": "newbie", "password": "temporary1234", "role": "viewer",
    })
    assert created.status_code == 201
    assert created.json()["must_change_password"] == 1, "admin 이 정해 준 비밀번호다"

    victim = {"Authorization": f"Bearer {token_for(client, 'newbie', 'temporary1234')}"}
    assert client.get("/api/findings", headers=victim).status_code == 403


# ── 8. 가져오기 자동 검증 ─────────────────────────────────────────────────────
def test_importing_a_truncated_xml_reports_the_verdict_without_making_it_a_failure(client):
    headers = _auth(client)
    broken = b'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
    response = client.post("/api/scans/import", headers=headers,
                           files={"file": ("broken.xml", broken, "text/xml")})
    # 파싱 자체가 안 되는 XML 은 애초에 가져오기가 거절한다.
    assert response.status_code == 400

    # 끝맺혔지만 NSE 가 통째로 빈 경우는 결과가 쓸모 있으므로 받되, 사실을 남긴다.
    nse_less = _finished_xml(proto="udp", services="53", port=53)
    ok = client.post("/api/scans/import", headers=headers,
                     files={"file": ("weekly.udp_identify.xml", nse_less, "text/xml")})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["reviews"] and body["reviews"][0]["mark"] == xml_verdict.RESCAN

    scan = client.get(f"/api/scans/{body['scan_id']}", headers=headers).json()
    assert scan["status"] == "done", "검증은 참고지 실패가 아니다"
    assert scan["failure_code"] == "import_unverified"
    assert "NSE" in scan["failure_message"]


def test_a_clean_import_carries_no_verdict_noise(client):
    headers = _auth(client)
    with FIXTURE.open("rb") as handle:
        ok = client.post("/api/scans/import", headers=headers,
                         files={"file": ("s.xml", handle, "text/xml")})
    assert ok.status_code == 200, ok.text
    scan = client.get(f"/api/scans/{ok.json()['scan_id']}", headers=headers).json()
    assert scan["failure_code"] == "", "정상 결과에까지 참고 딱지를 붙이면 신호가 죽는다"


# ── 9. 스캔 삭제가 발견을 실제로 지운다 ───────────────────────────────────────
def test_deleting_every_scan_that_saw_a_finding_actually_removes_it(client):
    """여러 스캔에 걸친 발견도, 마지막 근거가 사라지면 함께 사라져야 한다.

    예전 조건은 first·last 가 **둘 다** 그 스캔인 행만 지웠다. 그래서 두 번 관측된 발견은
    나중 스캔을 지울 때 참조만 NULL 로 끊기고, 이어서 남은 스캔을 지워도 조건에 걸리지 않아
    영영 남았다 - 가리키는 스캔이 없으니 화면에서 지울 방법조차 사라진다.
    """
    headers = _auth(client)
    db = SessionLocal()
    try:
        first, second = ScanRun(name="1회", status="done"), ScanRun(name="2회", status="done")
        db.add_all([first, second])
        db.commit()
        first_id, second_id = first.id, second.id
        db.add(Finding(
            finding_key="10.5.5.5|22|tcp", host_ip="10.5.5.5", port=22, proto="tcp",
            state="open", first_scan_id=first_id, last_scan_id=second_id,
        ))
        db.commit()
    finally:
        db.close()

    # 나중 스캔만 지우면 발견은 남는다 - 첫 관측 스캔이 아직 근거로 살아 있다.
    assert client.delete(f"/api/scans/{second_id}", headers=headers).status_code == 200
    assert client.get("/api/findings?state=open", headers=headers).json(), "아직 근거가 있다"

    # 마지막 근거까지 지우면 발견도 사라진다.
    removed = client.delete(f"/api/scans/{first_id}", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["findings_deleted"] == 1
    assert client.get("/api/findings?state=open", headers=headers).json() == []
    db = SessionLocal()
    try:
        assert db.query(Finding).count() == 0
        assert db.query(FindingEvent).count() == 0, "이벤트도 함께 정리된다"
    finally:
        db.close()


def test_a_scan_delete_never_touches_findings_another_scan_still_supports(client):
    """반대 경계 - 다른 스캔이 여전히 뒷받침하는 발견은 사람이 달아 둔 것까지 보존한다."""
    headers = _auth(client)
    db = SessionLocal()
    try:
        keep, drop = ScanRun(name="유지", status="done"), ScanRun(name="삭제", status="done")
        db.add_all([keep, drop])
        db.commit()
        keep_id, drop_id = keep.id, drop.id
        db.add(Finding(
            finding_key="10.5.5.5|22|tcp", host_ip="10.5.5.5", port=22, proto="tcp",
            state="open", status="처리중", manual_note="담당자 확인 중",
            first_scan_id=keep_id, last_scan_id=drop_id,
        ))
        db.commit()
    finally:
        db.close()

    assert client.delete(f"/api/scans/{drop_id}", headers=headers).json()["findings_deleted"] == 0
    db = SessionLocal()
    try:
        row = db.query(Finding).one()
        assert row.status == "처리중" and row.manual_note == "담당자 확인 중"
        assert row.first_scan_id == keep_id and row.last_scan_id is None
    finally:
        db.close()


# ── 10. 허용 규칙은 정상처리와 다른 축이다 ────────────────────────────────────
def test_an_allowed_rule_hides_findings_without_hiding_the_unclassified(client):
    """'조직이 허용했다'와 '아직 아무 규칙도 안 걸렸다'는 둘 다 risk_level=info 다.

    등급만 보고 접으면 미분류 발견까지 사라져 정작 봐야 할 것이 안 보인다. 허용은 별도
    플래그로 남기고, 정상처리와도 별도 토글로 관리한다.
    """
    headers = _auth(client)
    db = SessionLocal()
    try:
        run = ScanRun(name="ux", status="done")
        db.add(run)
        db.commit()
        # ssh 는 허용 규칙 대상, unknown-svc 는 아무 규칙도 안 걸리는 미분류.
        for port, service in ((22, "ssh"), (9999, "unknown-svc")):
            db.add(Finding(
                finding_key=f"10.5.5.5|{port}|tcp", host_ip="10.5.5.5", port=port,
                proto="tcp", state="open", service=service,
                first_scan_id=run.id, last_scan_id=run.id,
            ))
        db.commit()
    finally:
        db.close()

    created = client.post("/api/rules", headers=headers, json={
        "kind": "service_rule", "service": "ssh", "port": None,
        "risk_level": "info", "note": "사내 표준 관리 포트",
    })
    assert created.status_code == 201, created.text

    def services(query=""):
        rows = client.get(f"/api/findings?state=open{query}", headers=headers).json()
        return sorted(f["service"] for f in rows)

    # 기본은 접힌다 - 허용은 매번 보고 싶은 것이 아니다.
    assert services() == ["unknown-svc"], "미분류는 그대로 보여야 한다"
    # 정상처리 토글과 독립적으로 펼칠 수 있다.
    assert services("&hide_allowed=false") == ["ssh", "unknown-svc"]

    db = SessionLocal()
    try:
        allowed = db.query(Finding).filter(Finding.service == "ssh").one()
        unclassified = db.query(Finding).filter(Finding.service == "unknown-svc").one()
        assert allowed.allowed == 1 and allowed.risk_level == "info"
        assert unclassified.allowed == 0 and unclassified.risk_level == "info", (
            "등급은 같지만 허용 플래그로 갈린다")
    finally:
        db.close()


def test_removing_an_allow_rule_brings_the_finding_back(client):
    """허용을 취소하면 다시 보여야 한다 - 한 번 숨긴 것이 규칙과 무관하게 굳으면 안 된다."""
    headers = _auth(client)
    db = SessionLocal()
    try:
        run = ScanRun(name="ux", status="done")
        db.add(run)
        db.commit()
        db.add(Finding(
            finding_key="10.5.5.5|22|tcp", host_ip="10.5.5.5", port=22, proto="tcp",
            state="open", service="ssh", first_scan_id=run.id, last_scan_id=run.id,
        ))
        db.commit()
    finally:
        db.close()

    rule = client.post("/api/rules", headers=headers, json={
        "kind": "service_rule", "service": "ssh", "port": None,
        "risk_level": "info", "note": "",
    }).json()
    assert client.get("/api/findings?state=open", headers=headers).json() == []

    client.delete(f"/api/rules/{rule['id']}", headers=headers)
    rows = client.get("/api/findings?state=open", headers=headers).json()
    assert [f["service"] for f in rows] == ["ssh"]
    assert rows[0]["allowed"] == 0
