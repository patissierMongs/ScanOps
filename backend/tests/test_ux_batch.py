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
def test_bootstrap_repairs_a_blank_initial_admin_password_file():
    """계정만 커밋되고 안내 파일이 비면 에어갭 설치가 영구 잠기므로 재발급한다."""
    from scanops.seed.bootstrap import run_bootstrap
    from scanops.security import hash_password, verify_password

    cred = scans_api._settings.data_dir / "INITIAL_ADMIN.txt"
    cred.write_text("ScanOps 최초 관리자 계정\n  아이디: admin\n  비밀번호: \n", encoding="utf-8")
    db = SessionLocal()
    try:
        db.add(User(username="admin", password_hash=hash_password("unrecoverable12"),
                    role="admin", display_name="관리자", must_change_password=1))
        db.commit()
    finally:
        db.close()

    run_bootstrap()
    line = next(line for line in cred.read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("비밀번호:"))
    password = line.split(":", 1)[1].strip()
    assert password and len(password) >= 8
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").one()
        assert verify_password(password, admin.password_hash)
        assert admin.auth_version == 1
    finally:
        db.close()
    assert not list(cred.parent.glob(f".{cred.name}.*.tmp"))


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


def test_a_batched_scan_reports_its_split_while_running_and_after(client):
    """배치 구성은 실행 중에도, 끝난 뒤에도 말할 수 있어야 한다.

    예전에는 sidecar 에만 있어서 실행이 끝나면 사라졌다. 이력을 나중에 읽는 사람에게는
    '이 스캔이 어떻게 돌았는지'가 통째로 없는 정보가 된다.
    """
    from scanops.scanning import chunker

    headers = _auth(client)
    db = SessionLocal()
    try:
        scan = ScanRun(name="배치 스캔", targets="10.0.0.0/24", status="running",
                       batch_total=4, batch_size=64)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    chunker.write_state(scans_api._basename(scan_id), {
        "batches": [["10.0.0.1"], ["10.0.0.65"], ["10.0.0.129"], ["10.0.0.193"]],
        "cursor": 2, "workflow": "auto", "stop": False,
    })

    progress = client.get(f"/api/scans/{scan_id}/progress", headers=headers).json()
    assert (progress["batches_done"], progress["batches_total"]) == (2, 4)
    assert progress["batch_size"] == 64

    # 끝난 뒤에도 목록 응답만으로 구성을 말할 수 있다.
    db = SessionLocal()
    try:
        row = db.get(ScanRun, scan_id)
        row.status = "done"
        db.commit()
    finally:
        db.close()
    listed = next(s for s in client.get("/api/scans", headers=headers).json()
                  if s["id"] == scan_id)
    assert (listed["batch_total"], listed["batch_size"]) == (4, 64)


def test_a_staged_engine_scan_counts_batches_from_its_own_artifacts(client, monkeypatch, tmp_path):
    """단계 엔진에는 sidecar cursor 가 없다 - 산출물이 곧 진행 기록이다.

    TCP 는 끝났는데 UDP 가 도는 중인 배치는 아직 '끝난' 것이 아니므로, 프로토콜별 완료
    수의 최솟값을 쓴다. 한쪽만 세면 진행이 실제보다 앞서 보인다.
    """
    monkeypatch.setattr(scans_api._settings, "data_dir", tmp_path)
    scans_api._settings.ensure_dirs()
    headers = _auth(client)
    db = SessionLocal()
    try:
        scan = ScanRun(name="단계 스캔", targets="10.0.0.0/24", status="running",
                       batch_total=3, batch_size=128)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    out_dir = scans_api._settings.scans_dir / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "spec.json").write_text(json.dumps({
        "targets": ["10.0.0.0/24"], "exclude": [], "out_dir": str(out_dir), "batch_size": 128,
        "stages": {"discovery": {"mode": "sn"},
                   "tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": True, "ports": "53"},
                   "service": {"enabled": True}},
    }), encoding="utf-8")
    finished = ('<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
                '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')
    for name in ("stage-tcp-b0.xml", "stage-tcp-b1.xml", "stage-udp-b0.xml"):
        (out_dir / name).write_text(finished, encoding="utf-8")

    progress = client.get(f"/api/scans/{scan_id}/progress", headers=headers).json()
    assert progress["batches_total"] == 3
    assert progress["batches_done"] == 1, "UDP 가 아직 안 끝난 배치는 세지 않는다"
    assert progress["batch_size"] == 128


# ── 가져오기도 XML 이 밝힌 완료 시각을 쓴다 ────────────────────────────────────
def _timed_xml(host: str, *, start: int, finished: int, port: int | None = None,
               services: str = "443") -> bytes:
    """--open 산출물 흉내 - 열린 포트가 없으면 host 요소 자체가 없다."""
    ports = (
        f'<ports><port protocol="tcp" portid="{port}">'
        '<state state="open" reason="syn-ack"/><service name="https"/></port></ports>'
    ) if port else ""
    host_el = (f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/>'
               f'{ports}</host>') if port else ""
    return (
        f'<?xml version="1.0"?><nmaprun scanner="nmap" start="{start}">'
        f'<scaninfo type="syn" protocol="tcp" numservices="2" services="{services}"/>'
        f'{host_el}<runstats><finished time="{finished}" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ).encode("utf-8")


def _seed_finding(key: str, host: str, port: int, *, state: str, status: str, when):
    db = SessionLocal()
    try:
        run = ScanRun(name="중간 스캔", status="done")
        db.add(run)
        db.commit()
        run_id = run.id
        db.add(Finding(
            finding_key=key, host_ip=host, port=port, proto="tcp",
            state=state, status=status, service="https",
            first_scan_id=run_id, last_scan_id=run_id, first_seen=when, last_seen=when,
        ))
        db.commit()
        return run_id
    finally:
        db.close()


def test_a_single_import_uses_the_time_the_xml_finished_not_when_it_started(client):
    """start=00:00 · finished=02:00 인 XML 은 01:00 관측보다 새것이다.

    시작 시각을 쓰면 '01:00 에 닫힘으로 기록된 행' 이 더 새것으로 판정되어, 이 XML 이
    02:00 에 실제로 확인한 열린 포트가 통째로 버려진다 - 노출을 숨기는 미탐이다.
    """
    headers = _auth(client)
    middle = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    _seed_finding("10.7.7.7|443|tcp", "10.7.7.7", 443,
                  state="closed", status="정상처리", when=middle)

    xml = _timed_xml("10.7.7.7", start=int(datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp()),
                     finished=int(finished.timestamp()), port=443)
    response = client.post("/api/scans/import", headers=headers,
                           files={"file": ("late.xml", xml, "text/xml")})
    assert response.status_code == 200, response.text

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == "10.7.7.7|443|tcp").one()
        assert row.state == "open", "완료 시각을 쓰지 않으면 나중 관측이 버려진다"
        assert row.status != "정상처리"
        assert row.last_seen.replace(tzinfo=timezone.utc) == finished
        kinds = [e.type for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == row.id).all()]
        assert "REOPENED" in kinds
    finally:
        db.close()


def test_an_import_that_finished_before_a_newer_observation_yields_to_it(client):
    """반대 방향 - XML 이 먼저 끝났으면 그 뒤 관측이 이긴다."""
    headers = _auth(client)
    finished = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    newer = datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc)
    run_id = _seed_finding("10.7.7.8|443|tcp", "10.7.7.8", 443,
                           state="open", status="미조치", when=newer)

    # 8/1 02:00 에 끝난 XML 은 443 을 보지 못했다 - 8/3 관측을 뒤집지 못한다.
    xml = _timed_xml("10.7.7.8", start=int(datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp()),
                     finished=int(finished.timestamp()), port=None)
    response = client.post("/api/scans/import", headers=headers,
                           files={"file": ("early.xml", xml, "text/xml")})
    assert response.status_code == 200, response.text

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.finding_key == "10.7.7.8|443|tcp").one()
        assert row.state == "open" and row.last_scan_id == run_id
        assert row.last_seen.replace(tzinfo=timezone.utc) == newer
    finally:
        db.close()


def test_a_bundle_applies_each_batch_own_clock_not_the_earliest(client):
    """묶음도 배치마다 시각이 다르다 - min 하나로 뭉치면 뒤 배치일수록 미탐이 커진다.

        b0 finished 00:00 (A 를 훑고 443 못 봄)
        01:00 다른 스캔이 A:443 을 open 으로 관측
        b1 finished 02:00 (B 를 훑고 443 못 봄)
    """
    headers = _auth(client)
    b0 = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
    middle = datetime(2026, 8, 1, 1, 0, tzinfo=timezone.utc)
    b1 = datetime(2026, 8, 1, 2, 0, tzinfo=timezone.utc)
    _seed_finding("10.7.7.1|443|tcp", "10.7.7.1", 443,
                  state="open", status="미조치", when=middle)
    _seed_finding("10.7.7.2|443|tcp", "10.7.7.2", 443,
                  state="open", status="미조치", when=b0)

    # 각 배치는 자기 호스트를 훑었고 80 만 열려 있었다(443 은 사라졌다).
    files = {
        "run.10_7_7_1.b0000.tcp_discovery.xml": _timed_xml(
            "10.7.7.1", start=int(b0.timestamp()) - 60, finished=int(b0.timestamp()),
            port=80, services="80,443"),
        "run.10_7_7_2.b0001.tcp_discovery.xml": _timed_xml(
            "10.7.7.2", start=int(b1.timestamp()) - 60, finished=int(b1.timestamp()),
            port=80, services="80,443"),
    }
    upload = [("files", (name, data, "text/xml")) for name, data in files.items()]
    response = client.post("/api/scans/import-bundle", headers=headers, files=upload)
    assert response.status_code == 200, response.text

    db = SessionLocal()
    try:
        first = db.query(Finding).filter(Finding.finding_key == "10.7.7.1|443|tcp").one()
        assert first.state == "open", "b1 의 시각을 빌려 A 를 닫으면 미탐이다"
        assert first.last_seen.replace(tzinfo=timezone.utc) == middle
        second = db.query(Finding).filter(Finding.finding_key == "10.7.7.2|443|tcp").one()
        assert second.state == "closed", "b1 이 실제로 훑은 B 는 닫혀야 한다"
        assert second.last_seen.replace(tzinfo=timezone.utc) == b1
    finally:
        db.close()


# ── 담당 배정: 조작 수단이 화면에 없던 라이프사이클 단계 ──────────────────────
def test_an_auditor_can_list_assignees_and_assign_a_finding(client):
    """발견을 고치는 권한(auditor)과 사용자를 관리하는 권한(admin)은 다르다.

    배정하려면 사람 목록이 필요한데 `/api/users` 는 admin 전용이라, auditor 는 배정할 수
    있는 API 를 갖고도 고를 목록을 받지 못했다. 이름표에 필요한 최소한만 내려 주는 별도
    목록을 둔다 - admin 전용 목록을 통째로 열어 줄 이유가 없다.
    """
    make_user("assign-auditor", "auditorpw123", role="auditor")
    headers = {"Authorization": f"Bearer {token_for(client, 'assign-auditor', 'auditorpw123')}"}
    make_user("handler", "handlerpw123", role="viewer")
    make_user("resigned", "resignedpw12", role="viewer")

    db = SessionLocal()
    try:
        db.query(User).filter(User.username == "resigned").update({User.is_active: 0})
        run = ScanRun(name="배정", status="done")
        db.add(run)
        db.commit()
        finding = Finding(
            finding_key="10.6.6.6|22|tcp", host_ip="10.6.6.6", port=22, proto="tcp",
            state="open", service="ssh", first_scan_id=run.id, last_scan_id=run.id,
        )
        db.add(finding)
        db.commit()
        finding_id = finding.id
        handler_id = db.query(User).filter(User.username == "handler").one().id
    finally:
        db.close()

    # admin 전용 목록은 여전히 막혀 있다.
    assert client.get("/api/users", headers=headers).status_code == 403

    people = client.get("/api/users/assignable", headers=headers)
    assert people.status_code == 200, people.text
    names = [p["username"] for p in people.json()]
    assert "handler" in names
    assert "resigned" not in names, "비활성 계정에 배정하면 아무도 보지 않는 발견이 생긴다"
    # 이름표에 필요한 최소한만 - 역할·활성여부는 내려 주지 않는다.
    assert set(people.json()[0]) == {"id", "username", "display_name"}

    assigned = client.patch(f"/api/findings/{finding_id}", headers=headers,
                            json={"owner_user_id": handler_id})
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["owner_user_id"] == handler_id
    # 화면이 id 를 사람 이름으로 다시 조회하지 않아도 되게 이름을 함께 내린다.
    assert assigned.json()["assignee_name"] == "handler"

    db = SessionLocal()
    try:
        kinds = [e.type for e in db.query(FindingEvent).filter(
            FindingEvent.finding_id == finding_id).all()]
        assert "ASSIGN" in kinds, "배정은 감사 이력에 남아야 한다"
    finally:
        db.close()

    # 빈 값으로 해제할 수 있어야 한다 - 배정만 되고 못 푸는 건 반쪽이다.
    cleared = client.patch(f"/api/findings/{finding_id}", headers=headers,
                           json={"owner_user_id": None})
    assert cleared.status_code == 200
    assert cleared.json()["owner_user_id"] is None
    assert cleared.json()["assignee_name"] == ""


def test_the_assignee_is_a_separate_axis_from_the_asset_register_owner(client):
    """자산대장 담당자(owner)와 배정 담당자는 다른 사실이다 - 표에서도 갈라야 한다."""
    from scanops.api.findings import COLUMNS

    labels = {key: header for key, header, _getter in COLUMNS}
    assert labels["owner"] == "담당자(자산대장)"
    assert labels["assignee"] == "배정 담당자"


# ── NSE 노출 신호: 수집만 하고 안 쓰던 데이터 ─────────────────────────────────
def _nse_finding(service: str, port: int, nse: list[dict]) -> dict:
    from scanops.scanning.nmap_parse import exposure_signals
    return {
        "host_ip": "10.11.11.11", "hostname": "", "port": port, "proto": "tcp",
        "state": "open", "reason": "syn-ack", "service": service, "product": "",
        "version": "", "server": "", "banner": "", "cpe": "", "rtt": "",
        "identification": "확인", "nse_json": nse, "remarks": "",
        "exposure_json": exposure_signals(nse),
    }


def test_an_anonymous_ftp_is_no_longer_the_same_finding_as_a_locked_one(client):
    """익명 FTP 와 잠긴 FTP 가 같은 발견이던 것이 이 작업의 출발점이다.

    스캐너는 ftp-anon 을 이미 돌리고 있었고 그 답도 XML 에 있었는데, remarks 문자열
    한 줄로만 남아 등급에도 필터에도 쓰이지 못했다.
    """
    from scanops.scanning.taxonomy import enrich_all

    db = SessionLocal()
    try:
        anon = _nse_finding("ftp", 21, [
            {"id": "ftp-anon", "output": "Anonymous FTP login allowed (FTP code 230)"}])
        locked = _nse_finding("ftp", 21, [
            {"id": "ftp-anon", "output": "ERROR: Script execution failed (use -d to debug)"}])
        enrich_all(db, [anon, locked])
    finally:
        db.close()

    assert anon["exposure_json"] == [
        {"kind": "anon_access", "detail": "익명 FTP 로그인 허용"}]
    assert locked["exposure_json"] == [], "실패로 끝난 스크립트는 관측이 아니다"

    # 근거가 갈린다 - 이제 표·필터·내보내기에서 '익명 접근 가능한 것만' 을 뽑을 수 있다.
    assert any(c["std"] == "노출관측" for c in anon["compliance_json"])
    assert not any(c["std"] == "노출관측" for c in locked["compliance_json"])

    # 등급까지 갈리지는 **않는다**. 시드가 ftp 라는 서비스 자체를 이미 high 로 보기 때문이다.
    # 같은 서비스의 인스턴스 구분(익명이냐 아니냐)은 등급과 다른 축이라, 한 필드에 두 사실을
    # 싣지 않는다 - allowed 를 risk_level 과 분리한 것과 같은 이유다.
    assert anon["risk_level"] == locked["risk_level"] == "high"


def test_exposure_raises_an_unclassified_service_that_would_otherwise_read_as_info(client):
    """하한이 실제로 작동하는 자리 - 표준 포트를 벗어난 서비스.

    시드는 서비스 이름으로 등급을 매기므로, 비표준 포트의 미식별 FTP 는 아무 규칙에도
    걸리지 않아 info 로 남는다. 그런데 익명 접근이 관측됐다면 그것만으로 우선순위가 있다.
    """
    from scanops.scanning.taxonomy import enrich_all

    db = SessionLocal()
    try:
        odd = _nse_finding("unknown-svc", 2121, [
            {"id": "ftp-anon", "output": "Anonymous FTP login allowed (FTP code 230)"}])
        plain = _nse_finding("unknown-svc", 2121, [])
        enrich_all(db, [odd, plain])
    finally:
        db.close()

    assert plain["risk_level"] == "info", "관측된 노출이 없으면 미분류 그대로다"
    assert odd["risk_level"] == "high", "익명 접근 관측은 그 자체로 우선순위가 있다"


def test_exposure_raises_the_floor_but_an_org_rule_still_wins(client):
    """노출 신호는 하한을 올릴 뿐이다.

    등급을 올리는 것은 운영자의 우선순위를 바꾸는 일이라, 조직이 명시적으로 '허용' 으로
    정했다면 그 판단이 이겨야 한다. 그래서 규칙보다 **먼저** 적용한다.
    """
    from scanops.scanning.taxonomy import enrich_all

    headers = _auth(client)
    created = client.post("/api/rules", headers=headers, json={
        "kind": "port_rule", "service": "", "port": 23,
        "risk_level": "info", "note": "격리망 콘솔 - 승인됨",
    })
    assert created.status_code == 201, created.text

    db = SessionLocal()
    try:
        telnet = _nse_finding("telnet", 23, [
            {"id": "telnet-encryption", "output": "\n  Telnet server does not support encryption"}])
        enrich_all(db, [telnet])
    finally:
        db.close()

    # 관측 사실은 그대로 남지만 등급은 조직 판단을 따른다.
    assert telnet["exposure_json"] == [
        {"kind": "plaintext", "detail": "Telnet 암호화 미지원(평문 전송)"}]
    assert telnet["risk_level"] == "info"
    assert telnet["allowed"] is True
    # 근거는 둘 다 남아 사람이 검증할 수 있다.
    stds = {c["std"] for c in telnet["compliance_json"]}
    assert {"노출관측", "조직규칙"} <= stds


def test_exposure_never_lowers_a_grade(client):
    """하한이지 확정값이 아니다 - taxonomy 가 더 높게 본 것을 끌어내리면 안 된다."""
    from scanops.scanning.taxonomy import apply_exposure

    finding = {"risk_level": "high", "compliance_json": [],
               "exposure_json": [{"kind": "self_issued", "detail": "자체 발급"}]}
    apply_exposure(finding)
    assert finding["risk_level"] == "high"


def test_certificate_facts_beyond_the_common_name_are_kept(client):
    """ssl-cert 는 CN 만 쓰고 만료·자체발급·키 길이를 버리고 있었다."""
    from scanops.scanning.nmap_parse import exposure_signals

    signals = exposure_signals([{"id": "ssl-cert", "output": (
        "Subject: commonName=legacy.local\n"
        "Issuer: commonName=legacy.local\n"
        "Public Key type: rsa\nPublic Key bits: 1024\n"
        "Not valid before: 2018-01-01T00:00:00\n"
        "Not valid after:  2020-01-01T00:00:00\n")}])
    kinds = {s["kind"] for s in signals}
    assert kinds == {"cert_expired", "self_issued", "weak_key"}

    # 유효한 인증서는 아무 신호도 만들지 않는다(모든 TLS 포트에 딱지가 붙으면 신호가 죽는다).
    healthy = exposure_signals([{"id": "ssl-cert", "output": (
        "Subject: commonName=good.example\nIssuer: commonName=DigiCert\n"
        "Public Key bits: 4096\nNot valid after:  2099-01-01T00:00:00\n")}])
    assert healthy == []


# ── 서비스 특성: 만들어만 두고 한 번도 안 쓰던 컬럼 ───────────────────────────
def test_service_traits_are_seeded_and_explain_the_grade(client):
    """Category.encryption/auth/exposure 는 컬럼만 있고 값이 0/105 였다.

    이 세 값은 프로토콜 명세·제품 기본값으로 정해지는 **기대값**이다. 그 인스턴스에서
    실제로 관측한 사실(exposure_json)과는 다른 축이라, 등급을 바꾸지 않고 근거로만 남긴다
    - 시드 등급이 이미 그 사실을 반영해 매겨져 있기 때문이다.
    """
    from scanops.models import Category
    from scanops.scanning.taxonomy import enrich_all

    db = SessionLocal()
    try:
        seeded = db.query(Category).filter(Category.service_name == "redis").one()
        assert (seeded.encryption, seeded.auth, seeded.exposure) == (
            "평문", "기본 무인증", "내부 전용")
        # 명세로 정해지지 않는 서비스는 비워 둔다 - 지어내지 않는다.
        kafka = db.query(Category).filter(Category.service_name == "kafka").one()
        assert (kafka.encryption, kafka.auth, kafka.exposure) == ("", "", "")

        telnet = _nse_finding("telnet", 23, [])
        before = telnet.copy()
        enrich_all(db, [telnet])
    finally:
        db.close()

    refs = [c["ref"] for c in telnet["compliance_json"] if c["std"] == "서비스특성"]
    assert "전송 구간: 평문" in refs
    # 특성은 등급을 바꾸지 않는다(시드가 이미 그 판단을 반영했다).
    assert telnet["risk_level"] == "high"
    assert before.get("risk_level") is None


def test_existing_databases_get_the_traits_backfilled(client):
    """시드는 '비어 있을 때만' 돌기 때문에 운영 중인 DB 는 영영 채워지지 않는다.

    등급·분류처럼 사람이 손댔을 수 있는 값은 건드리지 않고 빈 특성 칸만 메운다.
    """
    from scanops.models import Category
    from scanops.scanning.taxonomy import seed_categories

    db = SessionLocal()
    try:
        row = db.query(Category).filter(Category.service_name == "redis").one()
        row.encryption = ""
        row.auth = ""
        row.exposure = ""
        row.risk_level = "low"          # 사람이 낮춰 둔 등급
        db.commit()

        seed_categories(db)

        again = db.query(Category).filter(Category.service_name == "redis").one()
        assert again.encryption == "평문", "빈 특성은 채워진다"
        assert again.risk_level == "low", "사람이 정한 등급은 건드리지 않는다"
    finally:
        db.close()


# ── 지원 종료 버전: -sV 가 읽어 놓고 위험에 반영하지 않던 값 ─────────────────
def test_an_end_of_life_version_raises_the_floor_with_a_dated_reason(client):
    """`version` 은 diff(VERSION_CHANGED)까지 되면서 위험은 못 올리고 있었다.

    표는 에어갭에서 자동 갱신될 수 없으므로, 판단에 쓴 표의 기준일을 근거에 함께 실어
    읽는 사람이 얼마나 오래된 판단인지 알 수 있게 한다.
    """
    from scanops.scanning.taxonomy import enrich_all

    db = SessionLocal()
    try:
        old = _nse_finding("http", 80, [])
        old.update({"product": "Apache httpd", "version": "2.2.15"})
        current = _nse_finding("http", 80, [])
        current.update({"product": "Apache httpd", "version": "2.4.58"})
        enrich_all(db, [old, current])
    finally:
        db.close()

    assert old["risk_level"] == "high"
    assert current["risk_level"] == "medium", "지원되는 버전은 서비스 기본 등급 그대로다"

    reason = next(c["ref"] for c in old["compliance_json"] if c["std"] == "지원종료")
    assert "Apache httpd 2.2" in reason
    assert "2.2.15" in reason, "무엇을 관측했는지 함께 적는다"
    assert "표 기준일" in reason, "얼마나 오래된 판단인지 알 수 있어야 한다"
    assert not any(c["std"] == "지원종료" for c in current["compliance_json"])


def test_an_unreadable_version_is_never_called_out_of_date(client):
    """모르는 것을 오래됐다고 하지 않는다 - 이 PR 이 내내 지킨 규칙이다."""
    from scanops.scanning.taxonomy import eol_finding

    assert eol_finding("Apache httpd", "") is None
    assert eol_finding("Apache httpd", "unknown") is None
    assert eol_finding("", "2.2.15") is None
    # 벤더가 버전별 EOL 을 공표하지 않는 제품은 표에 없다 - 지어내지 않는다.
    assert eol_finding("nginx", "1.14.0") is None
    assert eol_finding("OpenSSH", "7.4") is None


def test_a_banner_that_is_not_one_plain_version_is_left_unjudged(client):
    """실측 배너 세 가지가 전부 오탐이었다 - 앞의 숫자만 읽으면 다 틀린다.

    놓치는 쪽은 등급이 안 오를 뿐이지만, 잘못 잡는 쪽은 근거 없이 우선순위를 흔든다.
    """
    from scanops.scanning.taxonomy import eol_finding

    # MariaDB 는 MySQL 프로토콜 호환으로 '5.5.5-' 를 앞에 붙인다. 앞을 읽으면 지원 중인
    # 10.11 조차 EOL MySQL 5.5.5 로 잡힌다.
    assert eol_finding("MySQL", "5.5.5-10.11.6-MariaDB") is None
    assert eol_finding("MySQL", "5.5.5-10.3.34-MariaDB") is None
    # nmap 이 버전을 못 좁히면 범위를 낸다. '모른다'를 '오래됐다'로 바꾸지 않는다.
    assert eol_finding("Samba smbd", "3.X - 4.X") is None
    # 배포판 패키지는 업스트림이 끝나도 백포트로 계속 고쳐진다 - 업스트림 표가 안 맞는다.
    assert eol_finding("Samba smbd", "4.15.13-Ubuntu") is None
    # 숫자 자리에 붙은 문자 접미사는 버전의 일부다(OpenSSL) - 여기까지 버리면 안 된다.
    assert eol_finding("OpenSSL", "1.0.2k") is not None


def test_a_version_shorter_than_the_threshold_is_not_guessed(client):
    """'8' 은 8.0.x 일 수도 있다 - 자리수가 모자라면 판단하지 않는다."""
    from scanops.scanning.taxonomy import eol_finding

    assert eol_finding("MySQL", "8") is None, "기준 8.0 과 겹치는 자리가 같다 - 알 수 없다"
    assert eol_finding("MySQL", "7") is not None, "7 < 8 은 자리수와 무관하게 분명하다"
    assert eol_finding("Apache httpd", "2.4") is None
    assert eol_finding("Apache httpd", "2.4.58") is None, "기준 이상은 자리수가 길어도 같다"


def test_an_org_rule_still_overrides_an_eol_verdict(client):
    """EOL 도 하한일 뿐이다 - 조직이 허용으로 정했으면 그 판단이 이긴다."""
    from scanops.scanning.taxonomy import enrich_all

    headers = _auth(client)
    assert client.post("/api/rules", headers=headers, json={
        "kind": "product_rule", "service": "", "port": None, "product": "Apache httpd",
        "risk_level": "info", "note": "격리망 레거시 - 교체 계획 승인됨",
    }).status_code == 201

    db = SessionLocal()
    try:
        old = _nse_finding("http", 80, [])
        old.update({"product": "Apache httpd", "version": "2.2.15"})
        enrich_all(db, [old])
    finally:
        db.close()

    assert old["risk_level"] == "info" and old["allowed"] is True
    # 근거는 남아 사람이 검증할 수 있다.
    assert any(c["std"] == "지원종료" for c in old["compliance_json"])
    assert any(c["std"] == "조직규칙" for c in old["compliance_json"])


def test_an_eol_verdict_survives_rule_edits(client):
    """규칙 편집이 EOL 판정을 지우면 안 된다 - 없어진 위험은 아무도 못 본다.

    `reclassify_all()` 은 저장된 행에서 classify() 입력을 다시 만들어 넘기는데, 여기서
    `version` 이 빠져 있었다. 그래서 EOL 은 최초 인입에서만 high 였고, 위험규칙을
    만들거나 고치거나 지우는 순간(세 API 가 모두 이 함수를 부른다) 조용히 info 로
    내려갔다. 이 발견과 아무 상관 없는 규칙이어도 마찬가지였다.
    """
    from scanops.scanning.taxonomy import enrich_all

    headers = _auth(client)
    db = SessionLocal()
    try:
        data = _nse_finding("unknown", 8080, [])
        data.update({"product": "PHP", "version": "7.4.33"})
        enrich_all(db, [data])
        assert data["risk_level"] == "high", "최초 분류는 되고 있었다"
        db.add(Finding(
            finding_key="10.11.11.11|8080|tcp", host_ip="10.11.11.11", port=8080,
            proto="tcp", state="open", service="unknown", product="PHP",
            version="7.4.33", risk_level=data["risk_level"],
            compliance_json=data["compliance_json"], status="미조치",
        ))
        db.commit()
    finally:
        db.close()

    def _verdict():
        db = SessionLocal()
        try:
            row = db.query(Finding).filter_by(finding_key="10.11.11.11|8080|tcp").one()
            return row.risk_level, [c["std"] for c in (row.compliance_json or [])]
        finally:
            db.close()

    # 이 발견과 전혀 매칭되지 않는 규칙이다 - 건드릴 이유가 없다.
    created = client.post("/api/rules", headers=headers, json={
        "kind": "port_rule", "service": "", "port": 3389, "product": "", "cpe": "",
        "risk_level": "high", "note": "RDP 노출 금지",
    })
    assert created.status_code == 201
    rule_id = created.json()["id"]

    level, stds = _verdict()
    assert level == "high" and "지원종료" in stds, "규칙 생성이 EOL 판정을 지웠다"

    assert client.put(f"/api/rules/{rule_id}", headers=headers, json={
        "kind": "port_rule", "service": "", "port": 3390, "product": "", "cpe": "",
        "risk_level": "medium", "note": "RDP 노출 금지(포트 정정)",
    }).status_code == 200
    level, stds = _verdict()
    assert level == "high" and "지원종료" in stds, "규칙 수정이 EOL 판정을 지웠다"

    assert client.delete(f"/api/rules/{rule_id}", headers=headers).status_code == 204
    level, stds = _verdict()
    assert level == "high" and "지원종료" in stds, "규칙 삭제가 EOL 판정을 지웠다"


def _ssl_cert_nse(keytype: str, bits: int, *, not_after: str = "2099-01-01T00:00:00",
                  subject: str = "commonName=example.internal",
                  issuer: str = "commonName=Example Corp CA") -> list[dict]:
    """nmap ssl-cert 가 실제로 내는 형식 - type/bits 를 나란히, 만료는 시각까지 낸다."""
    return [{"id": "ssl-cert", "output": (
        f"Subject: {subject}\n"
        f"Issuer: {issuer}\n"
        f"Public Key type: {keytype}\n"
        f"Public Key bits: {bits}\n"
        "Not valid before: 2026-01-01T00:00:00\n"
        f"Not valid after:  {not_after}\n")}]


def exposure_signals_of(nse: list[dict]) -> list[dict]:
    from scanops.scanning.nmap_parse import exposure_signals
    return exposure_signals(nse)


def test_key_strength_is_read_with_the_algorithm_not_bits_alone(client):
    """같은 비트수가 알고리즘마다 다른 강도를 뜻한다 - 2048 을 전부에 들이대면 틀린다.

    P-256 은 오늘날 TLS 의 기본에 가까운데, 그 전부에 '약한 공개키' 근거와 medium 하한을
    달면 정작 봐야 할 RSA 1024 가 묻힌다. NIST SP 800-57 Part 1 Rev.5 의 112비트 강도
    기준으로 RSA/DSA/DH 는 2048, ECC 는 224 다.
    """
    from scanops.scanning.taxonomy import enrich_all

    db = SessionLocal()
    try:
        ec256 = _nse_finding("https", 443, _ssl_cert_nse("ec", 256))
        rsa1024 = _nse_finding("https", 443, _ssl_cert_nse("rsa", 1024))
        rsa2048 = _nse_finding("https", 443, _ssl_cert_nse("rsa", 2048))
        ec192 = _nse_finding("https", 443, _ssl_cert_nse("ec", 192))
        enrich_all(db, [ec256, rsa1024, rsa2048, ec192])
    finally:
        db.close()

    def weak(finding):
        kinds = [s["kind"] for s in finding["exposure_json"]]
        stds = [c["ref"] for c in finding["compliance_json"] if c["std"] == "노출관측"]
        return "weak_key" in kinds, any("약한 공개키" in ref for ref in stds)

    # 음성 경계 - 관측에도 등급 근거에도 남지 않아야 한다.
    assert weak(ec256) == (False, False), "EC 256 은 RSA 3072 급이다"
    assert weak(rsa2048) == (False, False)
    # 양성 경계 - 파서부터 위험 하한까지 그대로 이어져야 한다.
    assert weak(rsa1024) == (True, True)
    assert weak(ec192) == (True, True), "ECC 는 224 미만이 약하다"

    base = _nse_finding("https", 443, [])
    db = SessionLocal()
    try:
        enrich_all(db, [base])
    finally:
        db.close()
    assert ec256["risk_level"] == base["risk_level"], "정상 인증서가 등급을 올리면 안 된다"
    assert rsa1024["risk_level"] == "medium"


def test_an_unreadable_key_algorithm_is_not_called_weak(client):
    """모르는 곡선을 비트수만 보고 약하다고 하면 정확히 거꾸로 말하게 된다."""
    from scanops.scanning.nmap_parse import exposure_signals

    # Ed25519 는 256bit 로 128비트 강도다 - RSA 임계값을 들이대면 약한 키가 된다.
    assert exposure_signals(_ssl_cert_nse("ed25519", 256)) == []
    assert exposure_signals(_ssl_cert_nse("unknown", 512)) == []


def test_a_certificate_expiring_later_today_is_not_called_expired(client):
    """nmap 은 시각까지 내는데 날짜만 읽고 자정으로 되돌리면 하루를 통째로 잃는다.

    오늘 23:59 에 끝나는 인증서가 그날 내내 '이미 만료' 로 잡혔다. 만료는 medium 하한을
    올리는 신호라, 아직 유효한 인증서가 운영자의 우선순위를 하루 먼저 흔든다.
    """
    from datetime import timedelta

    from scanops.scanning.nmap_parse import exposure_signals

    now = datetime.now(timezone.utc)

    def expired(not_after: str) -> bool:
        return any(s["kind"] == "cert_expired"
                   for s in exposure_signals(_ssl_cert_nse("rsa", 2048, not_after=not_after)))

    # 음성 경계 - 오늘 끝나지만 아직 남아 있다.
    assert not expired(now.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%dT%H:%M:%S"))
    assert not expired((now + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S"))
    # 양성 경계 - 1초 전에 끝났다.
    assert expired((now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S"))
    assert expired("2025-01-01T00:00:00")
    # 시간대 표기가 붙어도 같은 뜻이어야 한다.
    assert expired("2025-01-01T00:00:00Z")
    assert not expired((now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S") + "+00:00")
    # 읽지 못하면 만료를 주장하지 않는다.
    assert not expired("not-a-date")
    assert not expired("")


def test_an_expiry_given_as_a_bare_date_is_read_as_the_end_of_that_day(client):
    """날짜만 있으면 그날 끝으로 본다 - 자정으로 읽으면 그날이 통째로 만료가 된다."""
    from scanops.scanning.nmap_parse import exposure_signals

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def expired(not_after: str) -> bool:
        return any(s["kind"] == "cert_expired"
                   for s in exposure_signals(_ssl_cert_nse("rsa", 2048, not_after=not_after)))

    assert not expired(today), "오늘 날짜만 적혀 있으면 아직 끝나지 않았다"
    assert expired("2025-01-01")


def test_the_same_dn_is_reported_as_self_issued_not_self_signed(client):
    """issuer = subject 는 self-issued 일 뿐 self-signed 를 증명하지 않는다.

    RFC 5280 3.2 는 그 인증서 안의 공개키로 서명이 검증될 때만 self-signed 라고 구분한다.
    ssl-cert 문자열에는 서명 검증 결과가 없으므로 '자가서명'은 관측보다 강한 결론이다 -
    같은 DN 을 쓰는 사설 CA 가 발급한(= 체인 검증을 통과하는) 인증서도 여기 걸린다.
    """
    from scanops.scanning.taxonomy import enrich_all

    same = _ssl_cert_nse("rsa", 2048, subject="commonName=SameName",
                         issuer="commonName=SameName")
    signals = [s for s in exposure_signals_of(same)]
    kinds = {s["kind"] for s in signals}
    assert "self_issued" in kinds and "self_signed" not in kinds
    detail = next(s["detail"] for s in signals if s["kind"] == "self_issued")
    assert "자가서명" not in detail, "관측하지 않은 것을 관측했다고 말하면 안 된다"
    assert "확인 불가" in detail, "무엇을 확인하지 못했는지 함께 적는다"

    # 등급 근거에도 같은 문구로 실린다.
    db = SessionLocal()
    try:
        finding = _nse_finding("https", 443, same)
        enrich_all(db, [finding])
    finally:
        db.close()
    ref = next(c["ref"] for c in finding["compliance_json"] if c["std"] == "노출관측")
    assert "자체 발급" in ref and "자가서명" not in ref

    # 발급자가 다르면 신호 자체가 없다.
    other = _ssl_cert_nse("rsa", 2048, subject="commonName=leaf",
                          issuer="commonName=Real CA")
    assert not any(s["kind"] == "self_issued" for s in exposure_signals_of(other))


def test_a_self_issued_certificate_is_recorded_but_does_not_raise_the_grade(client):
    """관측했다는 것과 더 위험하다는 것은 다른 층이다.

    RFC 5280 3.2 는 자체 발급 인증서를 CA 의 키 교체·정책 변경을 받치는 정상 메커니즘으로
    설명한다. 발급자와 주체가 같다는 사실만으로는 체인 검증 실패도 취약성도 증명되지 않는다 -
    같은 DN 을 쓰는 사설 CA 가 발급한 인증서는 실제로 체인 검증을 통과한다. 표·필터에는
    남겨 두되, 이 사실 하나로 우선순위를 올리지는 않는다.
    """
    from scanops.scanning.taxonomy import enrich_all

    same = _ssl_cert_nse("rsa", 2048, subject="commonName=SameName",
                         issuer="commonName=SameName")
    db = SessionLocal()
    try:
        # 미분류 서비스 - 하한이 실제로 물릴 수 있는 유일한 자리다(info 에서만 올라간다).
        plain = _nse_finding("unknown", 9999, [])
        issued = _nse_finding("unknown", 9999, same)
        # 대조군: 같은 자리에서 하한을 주는 관측은 여전히 등급을 올려야 한다.
        expired = _nse_finding("unknown", 9999,
                               _ssl_cert_nse("rsa", 2048, not_after="2025-01-01T00:00:00"))
        enrich_all(db, [plain, issued, expired])
    finally:
        db.close()

    assert plain["risk_level"] == "info"
    assert issued["risk_level"] == "info", "자체 발급만으로는 등급이 오르지 않는다"
    assert expired["risk_level"] == "medium", "하한을 주는 관측은 그대로 올린다"

    # 그래도 관측 사실과 이유는 남아 표·필터·상세에서 보인다.
    assert any(s["kind"] == "self_issued" for s in issued["exposure_json"])
    ref = next(c["ref"] for c in issued["compliance_json"] if c["std"] == "노출관측")
    assert "자체 발급" in ref and "등급은 올리지 않는다" in ref
