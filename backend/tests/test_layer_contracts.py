"""계층 경계 계약 — 생산한 필드를 소비하는가, 같은 값을 한 곳에서 유도하는가.

이 파일이 있는 이유는 감사에서 지적받은 재발 패턴 때문이다. 한쪽에 필드를 추가할 때 반대쪽이
그걸 쓰는지 아무도 검사하지 않아서, 같은 결함이 자리만 바꿔 계속 나왔다 - NSE 는 돌리는데
모델링을 안 하고, 모델에는 있는데 내보내기에서 빠지고, 같은 값을 뷰마다 다시 유도해 갈렸다.

증상 하나를 그 자리에서 때우는 대신 **경계마다 계약을 못 박는다.**
"""
from __future__ import annotations

import io

import openpyxl

from scanops.api import findings as findings_api
from scanops.api import reports as reports_api
from tests.conftest import make_user, token_for

XML = "tests/fixtures/sample_scan.xml"


def _auth(client):
    make_user("contract-op", "contractpw12", role="auditor")
    return {"Authorization": f"Bearer {token_for(client, 'contract-op', 'contractpw12')}"}


def _import(client, headers):
    with open(XML, "rb") as f:
        client.post("/api/scans/import", headers=headers,
                    files={"file": ("s.xml", f, "text/xml")})


# ── 모델 → 내보내기 ──────────────────────────────────────────────────────────
def test_the_audit_workbook_has_one_cell_per_header():
    """헤더와 행이 어긋나면 모든 칸이 한 칸씩 밀린다 - 증빙에서 제일 조용한 사고다."""
    from scanops.models import Finding

    row = reports_api._row(Finding(
        finding_key="10.0.0.1|443|tcp", host_ip="10.0.0.1", port=443, proto="tcp",
        state="open", first_seen=__import__("datetime").datetime(2026, 1, 1),
        last_seen=__import__("datetime").datetime(2026, 1, 2),
    ))
    assert len(row) == len(reports_api._HEADERS)


def test_an_observed_exposure_reaches_the_audit_workbook(client):
    """발견 내보내기에는 있는데 공식 증빙에서만 빠지면, 감사 자리에서 등급을 설명할 수 없다."""
    headers = _auth(client)
    _import(client, headers)

    from scanops.db import SessionLocal
    from scanops.models import Finding
    db = SessionLocal()
    try:
        row = db.query(Finding).first()
        row.exposure_json = [{"kind": "anon_access", "detail": "익명 FTP 로그인 허용"}]
        db.commit()
        key = row.finding_key
    finally:
        db.close()

    # 두 내보내기가 같은 사실을 담아야 한다.
    assert any(col[0] == "exposure" for col in findings_api.COLUMNS), "발견 내보내기 컬럼"
    assert "노출관측" in reports_api._HEADERS, "감사 리포트 헤더"

    report = client.get("/api/reports/audit", headers=headers)
    assert report.status_code == 200
    sheet = openpyxl.load_workbook(io.BytesIO(report.content)).active
    header = [c.value for c in next(sheet.iter_rows(max_row=1))]
    column = header.index("노출관측")
    hit = [r for r in sheet.iter_rows(min_row=2, values_only=True) if r[0] == key]
    assert hit and hit[0][column] == "익명 FTP 로그인 허용"


def test_exposure_text_has_a_single_definition():
    """같은 값을 뷰마다 다시 만들면 화면과 증빙이 갈린다 - 유도는 한 곳에서만."""
    from scanops.observation import exposure_text
    from scanops.models import Finding

    signals = [{"kind": "anon_access", "detail": "익명 FTP 로그인 허용"},
               {"kind": "weak_key", "detail": "약한 공개키 RSA 1024bit (2048 미만)"}]
    finding = Finding(finding_key="k", host_ip="10.0.0.1", port=21, proto="tcp",
                      state="open", exposure_json=signals)
    assert findings_api._exposure(finding) == exposure_text(signals)
    assert reports_api.exposure_text is exposure_text, "리포트도 같은 함수를 쓴다"


# ── 하나의 데이터, 하나의 유도 ────────────────────────────────────────────────
def test_the_heatmap_keeps_deriving_server_from_the_scan_snapshot(client):
    """히트맵이 스캔 스냅샷에서 Server 를 다시 뽑는 것은 **의도된 계약**이다.

    감사가 이걸 '뷰마다 다시 유도해 값이 갈린다'고 지적했지만, 그 재유도는 `server` 컬럼이
    생기기 전에 인입된 발견도 제대로 보이게 하려는 것이다(test_server_consumers 가 finding 의
    server 를 일부러 비워 그 경로를 고정한다). finding 필드로 통일하면 옛 발견의 표시 식별이
    nmap 의 저신뢰 추측(`apple-iphoto`)으로 되돌아간다.

    그래서 여기서는 통일하지 않고, **왜 다른지**를 못 박는다 - 다음에 누가 '일관성'을 이유로
    되돌리려 할 때 이 테스트가 이유를 말해 준다.
    """
    from scanops.api import heatmap as heatmap_api
    import inspect

    source = inspect.getsource(heatmap_api)
    assert "extract_server" in source, (
        "히트맵은 스캔 스냅샷에서 Server 를 뽑는다 - 옛 발견의 표시 식별을 살리기 위한 것이다"
    )


# ── 안전 컨트롤은 fail-closed ────────────────────────────────────────────────
def _scan_body(**over):
    body = {"name": "계약", "targets": ["10.9.9.9"], "options": ["syn"], "ports": "",
            "nse": [], "workflow": "manual", "discovery": "pn", "batch_size": 64,
            "exclude": [], "exclude_ports": ""}
    body.update(over)
    return body


def test_the_staged_engine_refuses_a_port_exclusion_it_cannot_honor(client):
    """조용히 받고 무시하는 것이 제일 나쁘다 - 뺐다고 믿은 포트가 그대로 스캔된다.

    단계 엔진은 --exclude-ports 를 넘길 자리가 없다(build_job_spec 에 인자가 없다). 근본
    구현은 엔진 쪽 일이라 여기서 하지 않지만, **못 지키는 약속을 받지는 않는다.**
    """
    headers = _auth(client)
    refused = client.post("/api/scans/run-staged", headers=headers,
                          json=_scan_body(exclude_ports="445,3389"))
    assert refused.status_code == 400
    assert "포트 제외" in refused.json()["detail"]

    # 예상치도 같은 입력을 거절해야 한다 - 못 돌릴 요청의 예상을 보여주면 안 된다.
    est = client.post("/api/scans/estimate", headers=headers,
                      json=_scan_body(staged=True, exclude_ports="445"))
    assert est.status_code == 400

    # 제외를 안 쓰면 단계 스캔 자체는 막히지 않는다(과잉 차단 방지).
    ok = client.post("/api/scans/estimate", headers=headers, json=_scan_body(staged=True))
    assert ok.status_code == 200


def test_the_manual_path_still_honors_a_port_exclusion(client):
    """수동 경로는 실제로 지킨다 - fail-closed 를 넣으면서 되는 길까지 막으면 안 된다."""
    from scanops.api.scans import _with_nmap_excludes

    argv = _with_nmap_excludes(["nmap", "-sS", "10.9.9.9"], [], "445,3389")
    assert "--exclude-ports" in argv
    assert "445,3389" in " ".join(argv)


# ── nmap → 파서: 수집한 것을 버리지 않는다 ───────────────────────────────────
_HOSTSCRIPT_XML = (
    '<?xml version="1.0"?><nmaprun scanner="nmap">'
    '<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>'
    '<service name="microsoft-ds"/></port>'
    '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
    '<service name="http"/></port></ports>'
    '<hostscript>'
    '<script id="smb-protocols" output="&#10;  dialects:&#10;'
    '    NT LM 0.12 (SMBv1) [dangerous, but default]&#10;    2.02&#10;"/>'
    '<script id="smb-os-discovery" output="&#10;  OS: Windows Server 2012 R2&#10;'
    '  Computer name: FILE01&#10;"/>'
    '</hostscript>'
    '<times srtt="1200"/></host>'
    '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>'
    "</nmaprun>"
).encode("utf-8")


def test_a_hostrule_script_reaches_the_finding_it_describes():
    """hostrule NSE 출력은 <hostscript> 로 나온다 - 파서가 <port> 밑만 읽어 통째로 버렸다.

    실측으로 확인한 사실이다(hostrule 스크립트 출력: <port> 밑 0건, <hostscript> 밑 1건).
    그래서 smb-protocols 기반 SMBv1 탐지와 smb-os-discovery 비고가 **한 번도 안 떴다.**
    살아 보이는 죽은 탐지기는 없느니만 못하다 - 없는 신호를 '확인함'으로 읽게 한다.
    """
    from scanops.scanning.nmap_parse import exposure_signals, parse_xml

    rows = {f["port"]: f for f in parse_xml(_HOSTSCRIPT_XML)}
    smb, web = rows[445], rows[80]

    assert {s["id"] for s in smb["nse_json"]} == {"smb-protocols", "smb-os-discovery"}
    assert "legacy_protocol" in {s["kind"] for s in exposure_signals(smb["nse_json"])}
    assert "Windows Server 2012 R2" in smb["remarks"], "smb-os-discovery 비고도 같이 살아난다"

    # 호스트 사실이라고 아무 포트에나 붙이면 80/tcp 에 'SMBv1 지원'이 뜬다.
    assert web["nse_json"] == []
    assert exposure_signals(web["nse_json"]) == []


def test_an_unmapped_host_script_is_kept_rather_than_dropped():
    """표에 없는 hostrule 스크립트를 조용히 버리면 같은 병이 다시 난다."""
    from scanops.scanning.nmap_parse import parse_xml

    xml = _HOSTSCRIPT_XML.replace(b'id="smb-protocols"', b'id="some-new-hostrule"')
    rows = {f["port"]: f for f in parse_xml(xml)}
    assert "some-new-hostrule" in {s["id"] for s in rows[80]["nse_json"]}
    assert "some-new-hostrule" in {s["id"] for s in rows[445]["nse_json"]}


# ── 진행 표시: 분자와 분모는 같은 모집단 ─────────────────────────────────────
def test_batch_progress_counts_the_batches_that_actually_exist(tmp_path):
    """실행 전 추정치(전체 대상)와 실제 산출물(live)을 분모·분자로 섞으면 없는 배치가 생긴다.

    /24 256대를 batch_size 64 로 걸었는데 discovery 를 통과한 것이 1대뿐이면, 엔진이 만드는
    sweep 배치는 b0 하나다. 그런데 분모를 실행 전 값 4로 두면 '배치 2/4' 같은 표시가 나온다 -
    b1~b3 는 존재한 적이 없다.
    """
    import json

    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    out.mkdir()
    spec = {"batch_size": 64, "stages": {"tcp": {"enabled": True}, "udp": {"enabled": False}}}

    # discovery 전 - live 를 모르면 0 을 돌려 호출자가 실행 전 추정치를 쓰게 둔다.
    (out / "run-state.json").write_text(json.dumps({}), encoding="utf-8")
    assert engine_runner.swept_total(out, spec) == 0

    # discovery 후 live 1대 - 실제 배치는 하나뿐이다.
    (out / "run-state.json").write_text(json.dumps({"live": ["10.0.0.9"]}), encoding="utf-8")
    assert engine_runner.swept_total(out, spec) == 1

    # 경계: 정확히 나누어떨어질 때와 아닐 때
    (out / "run-state.json").write_text(
        json.dumps({"live": [f"10.0.0.{i}" for i in range(1, 65)]}), encoding="utf-8")
    assert engine_runner.swept_total(out, spec) == 1
    (out / "run-state.json").write_text(
        json.dumps({"live": [f"10.0.0.{i}" for i in range(1, 66)]}), encoding="utf-8")
    assert engine_runner.swept_total(out, spec) == 2
