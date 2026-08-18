"""계층 경계 계약 — 생산한 필드를 소비하는가, 같은 값을 한 곳에서 유도하는가.

이 파일이 있는 이유는 감사에서 지적받은 재발 패턴 때문이다. 한쪽에 필드를 추가할 때 반대쪽이
그걸 쓰는지 아무도 검사하지 않아서, 같은 결함이 자리만 바꿔 계속 나왔다 - NSE 는 돌리는데
모델링을 안 하고, 모델에는 있는데 내보내기에서 빠지고, 같은 값을 뷰마다 다시 유도해 갈렸다.

증상 하나를 그 자리에서 때우는 대신 **경계마다 계약을 못 박는다.**
"""
from __future__ import annotations

import io
from pathlib import Path as pathlib_Path

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


def test_the_staged_engine_puts_the_port_exclusion_on_every_stage(tmp_path):
    """안전 컨트롤은 한 단계라도 새면 의미가 없다.

    여태 단계 경로는 exclude_ports 를 조용히 무시했다 - 취급주의 포트를 뺐다고 믿은 요청이
    그대로 스캔됐다. 이제 엔진이 받아 **발견·TCP·UDP·서비스 전부**의 nmap 인자에 싣는다.
    """
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.spec import JobSpec

    spec = JobSpec.from_dict({
        "job_id": "j", "targets": ["10.0.0.1"], "exclude": ["10.0.0.9"],
        "exclude_ports": "9100,515", "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "1-1000"},
                   "udp": {"enabled": True, "ports": "53"}},
    })
    spec.validate()
    assert spec.exclude_ports == "9100,515"
    # 저장·재적재를 왕복해도 남아야 이어가기에서 새지 않는다.
    assert JobSpec.from_dict(spec.to_dict()).exclude_ports == "9100,515"

    from scanops_engine.pipeline import Pipeline

    class _Sink:
        def emit(self, *a, **k):
            pass

    args = Pipeline(spec, _Sink(), "nmap")._exclude_args()
    assert "--exclude-ports" in args and "9100,515" in args
    assert "--exclude" in args and "10.0.0.9" in args, "호스트 제외도 그대로"

    # 문법이 틀리면 엔진이 거절한다 - spec.json 은 별도 프로세스가 읽는 입력이다.
    import pytest

    bad = JobSpec.from_dict({"job_id": "j", "targets": ["10.0.0.1"],
                             "exclude_ports": "포트아님", "out_dir": str(tmp_path)})
    with pytest.raises(ValueError):
        bad.validate()


def test_the_web_scan_request_carries_the_port_exclusion_into_the_saved_spec(client):
    """화면에서 넣은 값이 실행 spec 까지 도달하는지 - 중간에서 끊기면 조용한 무시로 되돌아간다."""
    from scanops.scanning import engine_runner

    spec = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn"], "", None, pathlib_Path("/tmp/x"), 64,
        exclude_ports="9100",
    )
    assert spec["exclude_ports"] == "9100"


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


def test_an_unmapped_host_script_is_not_copied_onto_every_port():
    """'조용히 버리지 않는다'를 모든 포트 복제로 구현한 것이 잘못이었다.

    hostrule 은 정의상 포트 인자를 받지 않는다(nmap NSE 문서). '어느 포트인지 모른다'가
    '모든 포트의 사실'이 될 수는 없다 - 그건 보존이 아니라 **없는 귀속을 지어내는 것**이고,
    22/tcp 와 443/tcp 에 같은 증거가 붙는다. 저장량도 포트 수에 비례해 늘어난다.

    모르는 것은 붙이지 않되, 조용히 사라지지도 않는다 - 파서가 로그로 남긴다.
    """
    import json
    import logging

    from scanops.scanning.nmap_parse import parse_xml, unmapped_host_scripts

    big = "A" * 65536
    ports = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/>'
        f'<service name="x"/></port>' for p in range(1000, 1512)
    )
    xml = (
        '<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/>'
        f"<ports>{ports}</ports>"
        f'<hostscript><script id="some-new-hostrule" output="{big}"/></hostscript>'
        '</host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/>'
        "</runstats></nmaprun>"
    ).encode()

    rows = parse_xml(xml)
    assert len(rows) == 512
    assert all(r["nse_json"] == [] for r in rows), "무관한 포트에 귀속시키지 않는다"

    # 저장량이 포트 수에 비례해 늘어나면 XML 하나로 DB 를 채울 수 있다.
    stored = sum(len(json.dumps(r["nse_json"], ensure_ascii=False).encode()) for r in rows)
    assert stored < len(xml), f"입력보다 커지면 안 된다 ({stored} vs {len(xml)})"

    # 버린 사실 자체는 남는다.
    assert unmapped_host_scripts([{"id": "some-new-hostrule"}]) == ["some-new-hostrule"]
    assert unmapped_host_scripts([{"id": "smb-protocols"}]) == [], "매핑이 있으면 버리지 않는다"


def test_script_evidence_on_one_finding_is_bounded_and_says_so():
    """가져오기 XML 은 외부 입력이다 - 업로드 상한은 파싱 **전** 크기에만 걸린다.

    조용히 자르면 읽는 사람이 그것을 전체로 오해하므로, 잘렸으면 잘렸다고 적는다.
    """
    from scanops.scanning.nmap_parse import _MAX_NSE_BYTES, _MAX_NSE_SCRIPTS, cap_nse

    one = cap_nse([{"id": "huge", "output": "B" * (_MAX_NSE_BYTES * 2)}])
    assert len(one) == 1 and "잘림" in one[0]["output"]
    assert len(one[0]["output"].encode()) < _MAX_NSE_BYTES * 1.1

    many = cap_nse([{"id": f"s{i}", "output": "x" * 4096} for i in range(_MAX_NSE_SCRIPTS * 2)])
    assert sum(len(s["output"].encode()) for s in many) <= _MAX_NSE_BYTES * 1.1
    assert any(s["id"] == "scanops-evidence-capped" for s in many), "생략한 사실을 적는다"

    # 평범한 출력은 그대로 지나간다 - 상한이 정상 경로를 건드리면 안 된다.
    plain = [{"id": "ssl-cert", "output": "Subject: commonName=a"}]
    assert cap_nse(plain) == plain


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
