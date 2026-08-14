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
def test_a_borrowed_password_is_flagged_and_its_file_disappears_when_changed(client, tmp_path):
    """INITIAL_ADMIN.txt 의 비밀번호는 평문으로 파일에 남는다.

    화면은 이 표시를 보고 첫 로그인에 변경 창을 띄운다(닫을 수 없다). 서버가 모든 API 를
    막는 대신 표시만 내려 주고, 변경이 끝나면 평문 비밀번호 파일을 지운다 - '나중에
    지우세요' 라는 안내만으로는 남기 때문이다.
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

    # 화면이 강제 변경 창을 띄우는 근거가 이 표시다.
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200 and me.json()["must_change_password"] == 1

    # 같은 비밀번호로 '변경'해 표시만 지우는 우회를 막는다.
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

    # 표시가 내려가 다음 로그인에는 창이 뜨지 않는다.
    fresh = {"Authorization": f"Bearer {token_for(client, 'firstadmin', 'realpassword34')}"}
    assert client.get("/api/auth/me", headers=fresh).json()["must_change_password"] == 0


def test_an_admin_reset_also_requires_the_owner_to_choose_a_new_password(client):
    headers = _auth(client)
    created = client.post("/api/users", headers=headers, json={
        "username": "newbie", "password": "temporary1234", "role": "viewer",
    })
    assert created.status_code == 201
    assert created.json()["must_change_password"] == 1, "admin 이 정해 준 비밀번호다"

    victim = {"Authorization": f"Bearer {token_for(client, 'newbie', 'temporary1234')}"}
    assert client.get("/api/auth/me", headers=victim).json()["must_change_password"] == 1


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


# ── 단독 스캐너 실행 하나 = 스캔 이력 한 줄 ────────────────────────────────────
def _stage_xml(host: str, *, stage: str, port: int | None) -> bytes:
    proto = "udp" if stage == "udp_identify" else "tcp"
    services = "53,161" if proto == "udp" else "1-65535"
    ports = (
        f'<ports><port protocol="{proto}" portid="{port}">'
        '<state state="open" reason="syn-ack"/><service name="https"/></port></ports>'
    ) if port else ""
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap" start="1785542400">'
        f'<scaninfo type="syn" protocol="{proto}" numservices="2" services="{services}"/>'
        f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/>{ports}</host>'
        '<runstats><finished time="1785546000" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ).encode("utf-8")


def _manifest(names: list[str]) -> bytes:
    return json.dumps({
        "tool": "scanops_scanner",
        "name": "weekly",
        "import_xml_files": names,
    }).encode("utf-8")


def test_a_standalone_run_becomes_one_scan_row_not_one_per_batch(client):
    """단독 스캐너 실행 하나는 이력에서 한 줄이어야 한다.

    예전에는 배치마다, 심지어 단계 하나만 남은 배치마다 별도 ScanRun 이 생겼다. /24 스캔은
    열린 포트가 없는 배치가 대부분이라 tcp_discovery 파일 하나짜리 행이 이력을 가득 채웠고,
    그 행들은 아무것도 말해 주지 않으면서 자리만 차지했다. 웹에서 돌린 단계 스캔은 배치가
    몇 개든 한 줄이므로 가져온 실행도 같아야 한다.
    """
    headers = _auth(client)
    files = {
        # b0000: 열린 포트가 있어 식별까지 돈 배치
        "weekly.10_0_0_0.b0000.tcp_discovery.xml": _stage_xml("10.0.0.1", stage="tcp_discovery", port=443),
        "weekly.10_0_0_0.b0000.tcp_identify.xml": _stage_xml("10.0.0.1", stage="tcp_identify", port=443),
        # b0001: 열린 포트가 없어 발견 단계 XML 만 남은 배치 - 예전에는 이것도 한 줄이었다
        "weekly.10_0_0_0.b0001.tcp_discovery.xml": _stage_xml("10.0.0.2", stage="tcp_discovery", port=None),
    }
    upload = [("files", (name, data, "text/xml")) for name, data in files.items()]
    upload.append(("files", ("weekly.manifest.json", _manifest(list(files)), "application/json")))

    response = client.post("/api/scans/import-bundle", headers=headers, files=upload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported"] == 1, "실행 하나는 스캔 하나다"

    scans = client.get("/api/scans", headers=headers).json()
    assert len(scans) == 1
    scan = scans[0]
    # 웹에서 돌린 단계 스캔처럼 타임라인이 남는다.
    stages = [(s["stage"], s["batch"]) for s in scan["stages_json"]]
    assert stages == [("tcp_discovery", 0), ("tcp_identify", 0), ("tcp_discovery", 1)]
    # 범위도 XML 이 밝힌 그대로 - '기본 1000개' 로 넘겨짚지 않는다.
    assert scan["summary"]["protocols"] == ["TCP"]
    assert scan["summary"]["ports"] == "전체"

    # 두 배치의 관측이 모두 한 스캔에 들어간다.
    hosts = {f["host_ip"] for f in client.get("/api/findings?state=open", headers=headers).json()}
    assert hosts == {"10.0.0.1"}, "열린 포트가 있는 호스트만 발견으로 남는다"
    assert scan["host_count"] == 2, "관측한 호스트는 두 배치 모두 세어야 한다"


def test_without_a_manifest_files_are_still_only_grouped_by_name(client):
    """반대 경계 - manifest 가 없으면 어떤 파일들이 한 실행인지 단언할 근거가 없다.

    파일명 base 로만 묶고 그 이상은 넘겨짚지 않는다. 서로 다른 실행의 결과를 한 줄로
    합치면 이번엔 없는 사실(같은 실행이었다)을 만들어 내는 셈이다.
    """
    headers = _auth(client)
    files = {
        "monday.10_0_0_0.tcp_discovery.xml": _stage_xml("10.0.0.1", stage="tcp_discovery", port=443),
        "tuesday.10_0_0_0.tcp_discovery.xml": _stage_xml("10.0.0.2", stage="tcp_discovery", port=8443),
    }
    upload = [("files", (name, data, "text/xml")) for name, data in files.items()]

    response = client.post("/api/scans/import-bundle", headers=headers, files=upload)
    assert response.status_code == 200, response.text
    assert response.json()["imported"] == 2, "다른 실행은 다른 줄이다"


def test_progress_says_which_batch_and_stage_is_running(client):
    """진행률 숫자 하나로는 '멈춘 것인지 도는 것인지'조차 알 수 없다."""
    from scanops.scanning import chunker

    headers = _auth(client)
    db = SessionLocal()
    try:
        scan = ScanRun(name="진행 중", targets="10.0.0.0/24", status="running")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    base = scans_api._basename(scan_id)
    chunker.write_state(base, {
        "batches": [["10.0.0.1", "10.0.0.2"], ["10.0.0.3"]], "cursor": 0,
        "workflow": "auto", "stage": "tcp_identify", "stage_hosts": 2, "stop": False,
    })

    progress = client.get(f"/api/scans/{scan_id}/progress", headers=headers).json()
    assert progress["batches_total"] == 2 and progress["batches_done"] == 0
    assert progress["stage"] == "tcp_identify"
    assert progress["stage_hosts"] == 2
    assert progress["batch_label"] == "10.0.0.1 외 1대"
    assert progress["elapsed_seconds"] is not None, "실행 중이면 경과 시간을 말할 수 있다"
