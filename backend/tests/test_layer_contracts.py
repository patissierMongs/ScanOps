"""계층 경계 계약 — 생산한 필드를 소비하는가, 같은 값을 한 곳에서 유도하는가.

이 파일이 있는 이유는 감사에서 지적받은 재발 패턴 때문이다. 한쪽에 필드를 추가할 때 반대쪽이
그걸 쓰는지 아무도 검사하지 않아서, 같은 결함이 자리만 바꿔 계속 나왔다 - NSE 는 돌리는데
모델링을 안 하고, 모델에는 있는데 내보내기에서 빠지고, 같은 값을 뷰마다 다시 유도해 갈렸다.

증상 하나를 그 자리에서 때우는 대신 **경계마다 계약을 못 박는다.**
"""
from __future__ import annotations

import io
import json
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


# ── 웹·단독·엔진의 기본 설정은 하나여야 한다 ─────────────────────────────────
def _standalone_default_nse() -> set[str]:
    """단독 스캐너의 기본 NSE 세트 - 소스에서 직접 읽는다(별도 프로세스라 import 불가)."""
    import re

    text = (pathlib_Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py"
            ).read_text(encoding="utf-8")
    block = re.search(r"DEFAULT_NSE_SCRIPTS = \((.*?)\)", text, re.S).group(1)
    return {s for s in re.findall(r"[a-z0-9\-]+", block.replace('"', "")) if s}


def test_the_three_scan_paths_share_one_default_nse_set():
    """웹·단독·엔진이 같은 스크립트를 돌려야 결과를 서로 도킹할 수 있다.

    엔진 목록만 9건으로 달랐다. 운영 경로에서는 build_job_spec 이 웹 목록을 항상 채워 넣어
    실제 동작은 같았지만, **안 쓰이는 기본값이라도 다르면 읽는 사람을 속인다** - 실제로
    "단계 스캔은 telnet/vnc/smb 를 안 돌린다"는 잘못된 결론이 이 목록 때문에 나왔다.

    엔진은 백엔드를 import 하지 않는 독립 패키지라 파생시킬 수 없다. 사본을 두되 드리프트를
    여기서 막는다.
    """
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.spec import DEFAULT_NSE

    from scanops.scanning import scan_options

    web = set(scan_options.NSE_DEFAULT_KEYS)
    assert set(DEFAULT_NSE) == web, "엔진 폴백이 웹 기본값과 달라졌다"
    assert _standalone_default_nse() == web, "단독 스캐너가 웹 기본값과 달라졌다"


def test_the_three_scan_paths_share_one_udp_port_set():
    """포트 기본값이 갈리면 같은 대역을 스캔해도 결과 집합이 달라진다."""
    import re
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.spec import DEFAULT_UDP_PORTS

    from scanops.scanning import scan_options

    text = (pathlib_Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py"
            ).read_text(encoding="utf-8")
    alone = re.search(r'^UDP_DEFAULT_PORTS\s*=\s*"([^"]+)"', text, re.M).group(1)

    assert DEFAULT_UDP_PORTS == scan_options.UDP_DEFAULT_PORTS
    assert alone == scan_options.UDP_DEFAULT_PORTS


def test_a_staged_web_scan_runs_the_same_scripts_as_the_manual_path():
    """spec 까지가 아니라 **실제 nmap 인자**에 같은 스크립트가 실리는지 본다.

    목록만 대조하면 중간에서 끊기는 것을 못 잡는다 - 프론트가 빈 배열을 보내면 0건이 되는
    경로가 실제로 있다.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.pipeline import Pipeline
    from scanops_engine.spec import JobSpec

    from scanops.scanning import engine_runner, scan_options

    selected = ["http-title", "snmp-info", "dns-nsid"]
    built = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn", "udp", "version"], "", selected,
        Path("/tmp/x"), 64)
    spec = JobSpec.from_dict(built)
    assert spec.service.nse == ["http-title", "dns-nsid"]
    assert spec.service.udp_nse == ["snmp-info", "dns-nsid"]

    class _Sink:
        def emit(self, *a, **k):
            pass

    # 웹에서 고른 스크립트가 프로토콜별로 걸러져 실제 TCP/UDP 식별 인자까지 가야 한다.
    recorded = {}

    def fake_nmap(stage, args, base, fatal=True):
        recorded["udp" if "-sU" in args else "tcp"] = args
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe = Pipeline(spec, _Sink(), "nmap")
    pipe._nmap = fake_nmap
    pipe._probe_protocol("10.0.0.1", "tcp", [443], spec.service, confirm=False)
    pipe._probe_protocol("10.0.0.1", "udp", [161], spec.service, confirm=False)
    tcp_scripts = recorded["tcp"][recorded["tcp"].index("--script") + 1]
    udp_scripts = recorded["udp"][recorded["udp"].index("--script") + 1]
    assert tcp_scripts == "http-title,dns-nsid"
    assert udp_scripts == "snmp-info,dns-nsid"
    assert "snmp-info" not in tcp_scripts and "http-title" not in udp_scripts


# ── 제외는 전선뿐 아니라 닫힘 권한에서도 빠져야 한다 ─────────────────────────
def test_an_excluded_port_is_not_a_closure_candidate(client):
    """프로브를 보내지 않은 포트를 '부재를 확인했다'며 닫으면 정확히 거꾸로다.

    운영자가 보호하려고 뺀 포트가 오히려 closed + 정상처리로 사라진다. 전선에서만 빼고
    후보에 남겨 두면 이 PR 이 여덟 라운드 걸려 막은 미탐이 새 기능으로 되돌아온다.
    """
    from scanops.api.scans import _auto_scope_keys, _excluded_port_scope, _port_scope
    from scanops.db import SessionLocal
    from scanops.models import Finding

    db = SessionLocal()
    try:
        for port in (80, 9100):
            db.add(Finding(finding_key=f"127.0.0.1|{port}|tcp", host_ip="127.0.0.1",
                           port=port, proto="tcp", state="open", service="x"))
        db.add(Finding(finding_key="127.0.0.1|53|udp", host_ip="127.0.0.1",
                       port=53, proto="udp", state="open", service="domain"))
        db.commit()

        scope_t = _port_scope("T:80,9100", "T")
        scope_u = _port_scope("U:53", "U")

        # 제외 없음 - 셋 다 후보다.
        plain = _auto_scope_keys(db, {"127.0.0.1"}, [], scope_t, scope_u)
        assert "127.0.0.1|9100|tcp" in plain and "127.0.0.1|80|tcp" in plain

        # T:9100 제외 - 9100 만 빠지고 나머지는 그대로 닫힐 수 있어야 한다.
        guarded = _auto_scope_keys(
            db, {"127.0.0.1"}, [], scope_t, scope_u,
            tcp_excluded=_excluded_port_scope("T:9100", "T"),
            udp_excluded=_excluded_port_scope("T:9100", "U"),
        )
        assert "127.0.0.1|9100|tcp" not in guarded, "제외한 포트가 닫힘 후보에 남았다"
        assert "127.0.0.1|80|tcp" in guarded, "관측한 포트는 계속 닫힐 수 있어야 한다"
        assert "127.0.0.1|53|udp" in guarded, "T: 제외가 UDP 를 건드리면 안 된다"

        # T:/U: 혼합
        mixed = _auto_scope_keys(
            db, {"127.0.0.1"}, [], scope_t, scope_u,
            tcp_excluded=_excluded_port_scope("T:9100,U:53", "T"),
            udp_excluded=_excluded_port_scope("T:9100,U:53", "U"),
        )
        assert mixed == {"127.0.0.1|80|tcp"}

        # 전 범위 제외 - 그 프로토콜은 통째로 후보가 아니다.
        none_tcp = _auto_scope_keys(
            db, {"127.0.0.1"}, [], scope_t, scope_u,
            tcp_excluded=_excluded_port_scope("T:1-65535", "T"),
            udp_excluded=_excluded_port_scope("T:1-65535", "U"),
        )
        assert not any(k.endswith("|tcp") for k in none_tcp)
        assert "127.0.0.1|53|udp" in none_tcp
    finally:
        db.close()


def test_a_staged_scan_saves_a_closure_scope_without_the_excluded_ports(client, monkeypatch):
    """실행 시점에 저장되는 scope_keys 자체에 제외가 반영돼야 마감·재개도 안전하다.

    워커는 띄우지 않는다 - 이 파일이 보는 것은 '무엇을 저장했는가'이고, 실제 엔진을 돌리면
    산출물 디렉터리가 세션 내내 남는다. 임시 데이터 경로는 세션 공유인데 DB 는 테스트마다
    초기화돼 스캔 ID 가 1부터 다시 시작하므로, 남은 scan_N/ 을 뒤 테스트가 자기 것으로
    주워 간다(실제로 resume 테스트를 CI 에서 깨뜨렸다).
    """
    import shutil

    from scanops.api import scans as scans_api
    from scanops.config import get_settings
    from scanops.db import SessionLocal
    from scanops.models import Finding

    class _NoThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scans_api.threading, "Thread", _NoThread)

    headers = _auth(client)
    db = SessionLocal()
    try:
        for port in (80, 9100):
            db.add(Finding(finding_key=f"10.4.4.4|{port}|tcp", host_ip="10.4.4.4",
                           port=port, proto="tcp", state="open", service="x"))
        db.commit()
    finally:
        db.close()

    started = client.post("/api/scans/run-staged", headers=headers, json=_scan_body(
        targets=["10.4.4.4"], ports="T:80,9100", exclude_ports="T:9100"))
    assert started.status_code == 200, started.text
    out_dir = get_settings().scans_dir / f"scan_{started.json()['id']}"
    try:
        spec = json.loads((out_dir / "spec.json").read_text(encoding="utf-8"))
        keys = set(spec["scanops"]["scope_keys"])
        assert "10.4.4.4|9100|tcp" not in keys, "제외한 포트가 저장된 닫힘 범위에 남았다"
        assert "10.4.4.4|80|tcp" in keys
        assert spec["exclude_ports"] == "T:9100"
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_an_unqualified_exclusion_protects_both_protocols(client):
    """nmap 은 접두사 없는 번호를 스캔 중인 protocol list 전부에 적용한다.

    실측으로 확인했다 - `-p T:80,U:53 --exclude-ports 53` 은 UDP scaninfo 가
    `numservices=0` 이 되지만, `--exclude-ports T:53` 은 UDP 53 을 그대로 스캔한다.
    화면이 예시로 먼저 보여 주는 표기(`9100, 515, 631`)가 접두사 없는 형식이라, 여기서
    갈리면 일반 경로에서 UDP 가 통째로 보호되지 않는다.
    """
    from scanops.api.scans import _auto_scope_keys, _excluded_port_scope, _port_scope
    from scanops.db import SessionLocal
    from scanops.models import Finding

    db = SessionLocal()
    try:
        db.add(Finding(finding_key="127.0.0.1|53|tcp", host_ip="127.0.0.1",
                       port=53, proto="tcp", state="open", service="domain"))
        db.add(Finding(finding_key="127.0.0.1|53|udp", host_ip="127.0.0.1",
                       port=53, proto="udp", state="open", service="domain"))
        db.add(Finding(finding_key="127.0.0.1|80|tcp", host_ip="127.0.0.1",
                       port=80, proto="tcp", state="open", service="http"))
        db.commit()

        scope_t, scope_u = _port_scope("T:53,80", "T"), _port_scope("U:53", "U")

        def candidates(exclude):
            return _auto_scope_keys(
                db, {"127.0.0.1"}, [], scope_t, scope_u,
                tcp_excluded=_excluded_port_scope(exclude, "T"),
                udp_excluded=_excluded_port_scope(exclude, "U"),
            )

        # 접두사 없음 - 두 프로토콜 모두 보호된다.
        assert candidates("53") == {"127.0.0.1|80|tcp"}
        # T: 로 한정하면 UDP 는 그대로 후보다(nmap 과 같은 의미).
        assert candidates("T:53") == {"127.0.0.1|53|udp", "127.0.0.1|80|tcp"}
        assert candidates("U:53") == {"127.0.0.1|53|tcp", "127.0.0.1|80|tcp"}
        # 접두사가 한 번 나오면 그 뒤로는 그 프로토콜에만 걸린다.
        assert candidates("80,T:53") == {"127.0.0.1|53|udp"}
        # 제외가 없으면 전부 후보 - 과잉 보호로 넘어가지 않는다.
        assert candidates("") == {"127.0.0.1|53|tcp", "127.0.0.1|53|udp", "127.0.0.1|80|tcp"}
    finally:
        db.close()


def test_the_scan_range_parser_keeps_its_own_unqualified_rule():
    """제외 의미를 고치면서 스캔 범위 해석까지 바꾸면 안 된다 - 다른 계약이다."""
    from scanops.api.scans import _port_scope

    assert _port_scope("80", "T") == {80}
    assert _port_scope("80", "U") == set(), "스캔 범위는 앱이 T:/U: 를 명시해 넘긴다"


# ── 타임아웃으로 포기한 호스트는 부재를 말할 자격이 없다 ─────────────────────
_TIMEDOUT_XML = (
    '<?xml version="1.0"?><nmaprun scanner="nmap">'
    '<scaninfo type="syn" protocol="tcp" numservices="2" services="22,443"/>'
    '<host timedout="true"><status state="up" reason="user-set"/>'
    '<address addr="10.0.0.9" addrtype="ipv4"/><times srtt="1000"/></host>'
    '<host><status state="up" reason="syn-ack"/><address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
    '<service name="ssh"/></port></ports></host>'
    '<runstats><finished exit="success"/><hosts up="2" down="0" total="2"/></runstats>'
    "</nmaprun>"
).encode("utf-8")


def test_a_host_nmap_gave_up_on_is_not_treated_as_observed():
    """`--host-timeout` 으로 포기한 호스트는 up 이지만 관측을 마치지 못했다.

    nmap 은 `<host timedout="true">` 로 적고 `<ports>` 를 통째로 생략하며, 실행 자체는
    `finished exit="success"` 로 끝난다. 표식을 읽지 않으면 '살아 있고 열린 포트가 없다'로
    보여 그 호스트의 기존 발견이 전부 닫힘 + 정상처리가 된다.

    단독 스캐너는 저강도에서 `--host-timeout 30m` 을 기본으로 켠다 - 노후 장비를 지키려고
    고른 설정이 정확히 그 장비의 발견을 지우는 자리다.
    """
    from scanops.scanning.nmap_parse import parse_xml, timed_out_hosts, up_hosts

    assert timed_out_hosts(_TIMEDOUT_XML) == {"10.0.0.9"}
    assert up_hosts(_TIMEDOUT_XML) == {"10.0.0.1"}, "포기한 호스트는 닫힘 판정에서 뺀다"
    # 정상 호스트의 관측은 그대로 살아 있어야 한다(과잉 보수로 넘어가지 않는다).
    assert [f["host_ip"] for f in parse_xml(_TIMEDOUT_XML)] == ["10.0.0.1"]


def test_the_engine_denies_absence_authority_to_a_timed_out_host(tmp_path):
    """엔진은 커버리지를 배치 슬라이스로 되짚으므로 observed_hosts 만 막으면 절반만 막힌다."""
    import json

    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    out.mkdir()
    (out / "run-state.json").write_text(
        json.dumps({"live": ["10.0.0.1", "10.0.0.9"]}), encoding="utf-8")
    (out / "stage-tcp-b0.xml").write_bytes(_TIMEDOUT_XML)
    spec = {"batch_size": 64, "stages": {"tcp": {"enabled": True}, "udp": {"enabled": False}}}

    assert engine_runner.timed_out_hosts(out) == {"10.0.0.9"}
    assert engine_runner.observed_hosts(out, spec) == {"10.0.0.1"}

    absence = engine_runner.absence_times(out, spec)
    assert ("10.0.0.1", "tcp") in absence, "관측을 마친 호스트는 부재를 말할 수 있다"
    assert ("10.0.0.9", "tcp") not in absence, "포기한 호스트에 부재 권한을 주면 안 된다"


# ── 호스트당 상한은 단계마다 별개다 ───────────────────────────────────────────
def _timedout_only_xml(ip: str, proto: str = "tcp") -> bytes:
    """nmap 이 상한을 넘겨 포기한 호스트 - 포트 표가 통째로 없고 실행은 정상 종료한다."""
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        f'<scaninfo type="syn" protocol="{proto}" numservices="1" services="443"/>'
        f'<host timedout="true"><status state="up" reason="user-set"/>'
        f'<address addr="{ip}" addrtype="ipv4"/></host>'
        '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>'
        "</nmaprun>"
    ).encode("utf-8")


def _clean_xml(ip: str, proto: str = "tcp", port: int = 22) -> bytes:
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        f'<scaninfo type="syn" protocol="{proto}" numservices="1" services="{port}"/>'
        f'<host><status state="up" reason="syn-ack"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<ports><port protocol="{proto}" portid="{port}">'
        '<state state="open" reason="syn-ack"/><service name="ssh"/></port></ports></host>'
        '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>'
        "</nmaprun>"
    ).encode("utf-8")


def _pipeline(tmp_path, spec_dict):
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.pipeline import Pipeline
    from scanops_engine.spec import JobSpec

    class _Sink:
        def emit(self, *a, **k):
            pass

    spec = JobSpec.from_dict(spec_dict).validate()
    return Pipeline(spec, _Sink(), "nmap"), spec


def test_every_engine_stage_carries_its_own_host_timeout(tmp_path):
    """`--host-timeout` 이 한 단계라도 빠지면 그 단계가 트러블메이커에 그대로 붙잡힌다.

    그리고 값은 **단계마다 별개**여야 한다. TCP 전수는 포트 수(65535)가 소요를 지배하고
    UDP 는 포트 수가 적은 대신 ICMP 율제한이 지배한다 - 한 값으로 묶으면 느린 쪽에 맞춰
    빠른 쪽의 트러블메이커를 놓치거나, 빠른 쪽에 맞춰 정상 호스트를 포기한다.
    """
    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {
            "discovery": {"host_timeout": "2m"},
            "tcp": {"enabled": True, "ports": "1-65535", "host_timeout": "20m"},
            "udp": {"enabled": True, "ports": "53", "host_timeout": "10m"},
            "service": {"host_timeout": "10m", "udp_host_timeout": "5m"},
        },
    })
    seen = {}

    def fake(stage, args, base, fatal=True):
        seen[f"{stage}:{pathlib_Path(base).name}"] = list(map(str, args))
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._discovery()
    pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    pipe._sweep_batch("udp", 0, ["10.0.0.1"])
    pipe._probe_protocol("10.0.0.1", "tcp", [443], spec.service, confirm=False)
    pipe._probe_protocol("10.0.0.1", "udp", [53], spec.service, confirm=False)

    def limit(key):
        argv = seen[key]
        assert "--host-timeout" in argv, f"{key} 단계에 상한이 없다"
        return argv[argv.index("--host-timeout") + 1]

    assert limit("discovery:stage0-discovery") == "2m"
    assert limit("tcp:stage-tcp-b0") == "20m"
    assert limit("udp:stage-udp-b0") == "10m"
    assert limit("service:stage3-10_0_0_1-tcp") == "10m"
    # UDP 식별은 이 프로젝트에서 실제로 죽어 온 자리라 TCP 와 따로 더 짧게 잡는다.
    assert limit("service:stage3-10_0_0_1-udp") == "5m"


def test_the_engine_records_what_each_nmap_process_covered(tmp_path):
    """커버리지는 되짚는 게 아니라 **생산자가 적는다**.

    여태 백엔드는 '이 배치가 어느 호스트를 맡았나'를 `live[i*b:(i+1)*b]` 로 되짚었다.
    되짚기는 규칙이 바뀌면 조용히 어긋나고, 재시도처럼 부분집합을 훑은 실행을 아예 표현하지
    못한다. 엔진이 명령줄에 올린 목록을 그대로 적어 두면 둘 다 사라진다.
    """
    import json

    pipe, _ = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "out_dir": str(tmp_path), "batch_size": 2,
        "stages": {"tcp": {"enabled": True, "ports": "22"}},
    })

    def fake(stage, args, base, fatal=True):
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    for bi, batch in enumerate([["10.0.0.1", "10.0.0.2"], ["10.0.0.3"]]):
        pipe._sweep_batch("tcp", bi, batch)

    log = json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))["coverage"]
    sweeps = [e for e in log if e["role"] == "authority"]
    assert [e["artifact"] for e in sweeps] == ["stage-tcp-b0.xml", "stage-tcp-b1.xml"]
    assert [e["hosts"] for e in sweeps] == [["10.0.0.1", "10.0.0.2"], ["10.0.0.3"]]
    assert {e["proto"] for e in sweeps} == {"tcp"}


# ── 타임아웃 산출물의 '역할'을 구분하지 않으면 양방향으로 틀린다 ──────────────
def _write_state(out, payload):
    import json

    out.mkdir(parents=True, exist_ok=True)
    (out / "run-state.json").write_text(json.dumps(payload), encoding="utf-8")


def test_a_timed_out_rescan_artifact_denies_closure(tmp_path):
    """재스캔에서 stage3 가 timedout 이면 그 발견을 닫으면 안 된다.

    조치 검증(재스캔)은 닫힘이 실제로 일어나는 가장 중요한 경로다. 그런데 observed_hosts 는
    force_scanned_hosts 분기에서 선택 호스트를 그대로 돌려주며 포기 판정을 아예 건너뛰었다 -
    이번 방어가 정작 가장 중요한 경로에만 빠져 있었다.
    """
    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    spec = {"rescan_units": [{"ip": "127.0.0.1", "port": 18443, "proto": "tcp"}],
            "stages": {"service": {"confirm": True}}}
    _write_state(out, {"coverage": [
        {"artifact": "stage3-127_0_0_1-tcp18443.xml", "proto": "tcp", "role": "authority",
         "hosts": ["127.0.0.1"], "ports": "T:18443", "finished": True},
    ]})
    (out / "stage3-127_0_0_1-tcp18443.xml").write_bytes(_timedout_only_xml("127.0.0.1"))

    assert engine_runner.observed_hosts(out, spec, True) == set()
    assert engine_runner.observed_scope(
        {"127.0.0.1|18443|tcp"}, out, spec, True) == set(), "포기당한 관측은 닫힘 권한이 없다"
    assert ("127.0.0.1", 18443, "tcp") not in engine_runner.absence_times(out, spec, True)

    # 반대 경계 - 온전히 끝난 재스캔은 그대로 닫을 수 있어야 한다(과잉 보수로 넘어가지 않는다).
    (out / "stage3-127_0_0_1-tcp18443.xml").write_bytes(_clean_xml("127.0.0.1", port=18443))
    assert engine_runner.observed_hosts(out, spec, True) == {"127.0.0.1"}
    assert engine_runner.observed_scope({"127.0.0.1|18443|tcp"}, out, spec, True) == {
        "127.0.0.1|18443|tcp"}


def test_rescan_timeout_authority_is_kept_per_port(tmp_path):
    """한 호스트의 재스캔 포트들은 서로의 timeout 판정을 덮어쓰지 않는다."""
    from scanops.scanning import engine_runner

    ip = "127.0.0.1"
    out = tmp_path / "scan_multi_port"
    spec = {
        "rescan_units": [
            {"ip": ip, "port": 22, "proto": "tcp"},
            {"ip": ip, "port": 443, "proto": "tcp"},
        ],
        "stages": {"service": {"confirm": False}},
    }
    _write_state(out, {"coverage": [
        {"artifact": "stage3-127_0_0_1-tcp22.xml", "proto": "tcp", "role": "authority",
         "hosts": [ip], "ports": "T:22", "finished": True},
        {"artifact": "stage3-127_0_0_1-tcp443.xml", "proto": "tcp", "role": "authority",
         "hosts": [ip], "ports": "T:443", "finished": True},
    ]})
    (out / "stage3-127_0_0_1-tcp22.xml").write_bytes(_timedout_only_xml(ip))
    (out / "stage3-127_0_0_1-tcp443.xml").write_text(
        '<?xml version="1.0"?><nmaprun scanner="nmap">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
        '<runstats><finished time="1893456000" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>',
        encoding="utf-8",
    )

    scope = {f"{ip}|22|tcp", f"{ip}|443|tcp"}
    assert engine_runner.observed_scope(scope, out, spec, True) == {f"{ip}|443|tcp"}
    absence = engine_runner.absence_times(out, spec, True)
    assert (ip, 22, "tcp") not in absence
    assert (ip, 443, "tcp") in absence


def test_an_enrichment_timeout_does_not_strip_a_completed_sweep(tmp_path):
    """전체 스캔에서 stage3 는 enrichment 다 - 그 타임아웃이 sweep 의 권한을 뺏으면 안 된다.

    sweep 이 22/open 과 443/부재를 끝까지 관측했는데 식별만 늦어 포기당한 경우, 권한까지
    빼면 사라진 443 이 영원히 열린 채로 남는다. 이 PR 이 스스로 적어 둔 계약
    ("Service probing is enrichment, not authority over a successful open-port sweep")과도
    정면으로 어긋난다.
    """
    from scanops.scanning import engine_runner

    out = tmp_path / "scan_2"
    spec = {"batch_size": 64, "stages": {"tcp": {"enabled": True}, "udp": {"enabled": False}}}
    _write_state(out, {"live": ["10.0.0.1"], "coverage": [
        {"artifact": "stage-tcp-b0.xml", "proto": "tcp", "role": "authority",
         "hosts": ["10.0.0.1"], "ports": "1-65535", "finished": True},
        {"artifact": "stage3-10_0_0_1-tcp.xml", "proto": "tcp", "role": "enrichment",
         "hosts": ["10.0.0.1"], "ports": "T:22", "finished": True},
    ]})
    (out / "stage-tcp-b0.xml").write_bytes(_clean_xml("10.0.0.1"))
    (out / "stage3-10_0_0_1-tcp.xml").write_bytes(_timedout_only_xml("10.0.0.1"))

    assert engine_runner.timed_out_hosts(out, "tcp") == set(), "enrichment 는 권한을 뺏지 않는다"
    assert engine_runner.observed_hosts(out, spec) == {"10.0.0.1"}
    assert engine_runner.observed_scope({"10.0.0.1|443|tcp"}, out, spec) == {"10.0.0.1|443|tcp"}
    assert ("10.0.0.1", "tcp") in engine_runner.absence_times(out, spec)


def test_a_udp_timeout_does_not_strip_tcp_authority(tmp_path):
    """프로토콜 축이 없으면 UDP 타임아웃 하나가 완결된 TCP sweep 의 권한까지 지운다."""
    from scanops.scanning import engine_runner

    out = tmp_path / "scan_3"
    spec = {"batch_size": 64, "stages": {"tcp": {"enabled": True}, "udp": {"enabled": True}}}
    _write_state(out, {"live": ["10.0.0.1"], "coverage": [
        {"artifact": "stage-tcp-b0.xml", "proto": "tcp", "role": "authority",
         "hosts": ["10.0.0.1"], "ports": "1-65535", "finished": True},
        {"artifact": "stage-udp-b0.xml", "proto": "udp", "role": "authority",
         "hosts": ["10.0.0.1"], "ports": "53", "finished": True},
    ]})
    (out / "stage-tcp-b0.xml").write_bytes(_clean_xml("10.0.0.1"))
    (out / "stage-udp-b0.xml").write_bytes(_timedout_only_xml("10.0.0.1", "udp"))

    assert engine_runner.timed_out_hosts(out, "tcp") == set()
    assert engine_runner.timed_out_hosts(out, "udp") == {"10.0.0.1"}
    scope = engine_runner.observed_scope({"10.0.0.1|443|tcp", "10.0.0.1|53|udp"}, out, spec)
    assert scope == {"10.0.0.1|443|tcp"}, "TCP 는 살고 UDP 만 권한을 잃는다"
    absence = engine_runner.absence_times(out, spec)
    assert ("10.0.0.1", "tcp") in absence and ("10.0.0.1", "udp") not in absence


def test_the_web_request_carries_both_host_timeouts_into_the_spec():
    """화면의 두 값이 실행 spec 까지 도달하는지 - 중간에서 끊기면 조용한 무시로 되돌아간다."""
    from pathlib import Path

    from scanops.api.scans import _host_timeouts
    from scanops.scanning import engine_runner, scan_options

    class _Body:
        host_timeout = "30m"
        udp_host_timeout = "0"

    spec = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn", "udp", "version"], "", None, Path("/tmp/x"), 64,
        host_timeouts=_host_timeouts(_Body()))
    assert spec["stages"]["tcp"]["host_timeout"] == "30m"
    assert spec["stages"]["service"]["host_timeout"] == "30m"
    # "0" 은 명시적 끄기다 - 빈 값(지정 없음)과 다르다.
    assert spec["stages"]["udp"]["host_timeout"] == "0"

    # 지정이 없으면 단계별 기본값을 쓴다.
    class _Empty:
        host_timeout = ""
        udp_host_timeout = ""

    plain = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn", "udp", "version"], "", None, Path("/tmp/x"), 64,
        host_timeouts=_host_timeouts(_Empty()))
    assert plain["stages"]["tcp"]["host_timeout"] == scan_options.HOST_TIMEOUT_DEFAULTS["tcp"]
    assert plain["stages"]["udp"]["host_timeout"] == scan_options.HOST_TIMEOUT_DEFAULTS["udp"]
    assert (plain["stages"]["tcp"]["host_timeout"]
            != plain["stages"]["udp"]["host_timeout"]), "TCP·UDP 상한은 따로 간다"


def test_the_scan_paths_share_one_host_timeout_grammar():
    """상한 값의 문법이 갈리면 같은 값이 한쪽에서만 안전 제어가 된다.

    특히 `None` 은 양쪽 모두 **거절**해야 한다. 조용히 ""(미적용)으로 바꾸면 state/spec 한
    줄로 상한만 풀려 막으려던 지연이 그대로 돌아온다 - #48 이 정확히 그 사고였다.
    """
    import re
    import sys

    import pytest

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.spec import validate_host_timeout

    for good, want in (("15m", "15m"), ("30s", "30s"), ("2h", "2h"),
                       ("900", "900"), ("0", ""), ("", ""), ("  10m  ", "10m")):
        assert validate_host_timeout(good) == want

    for bad in ("15x", "m15", "-5m", "abc"):
        with pytest.raises(ValueError):
            validate_host_timeout(bad)
    with pytest.raises(ValueError):
        validate_host_timeout(None)      # 끄기가 아니라 거절

    # 단독 스캐너는 별도 프로세스라 import 할 수 없다 - 문법 원본을 소스에서 읽어 대조한다.
    text = (pathlib_Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py"
            ).read_text(encoding="utf-8")
    standalone = re.search(r"^STATS_RE = re\.compile\(r\"(.+?)\"\)", text, re.M).group(1)
    engine = re.search(
        r"^_HOST_TIMEOUT_RE = re\.compile\(r\"(.+?)\"\)",
        (pathlib_Path(__file__).resolve().parents[2] / "engine" / "scanops_engine" / "spec.py"
         ).read_text(encoding="utf-8"), re.M).group(1)
    assert engine == standalone, "엔진과 단독 스캐너의 시간 형식이 달라졌다"

    # 기본값도 nmap 이 받는 형식이어야 한다 - 여기서 어긋나면 모든 단계 스캔이 400 이 된다.
    from scanops.scanning import scan_options

    for stage, value in scan_options.HOST_TIMEOUT_DEFAULTS.items():
        assert validate_host_timeout(value) == value, f"{stage} 기본값이 문법에 안 맞는다"


def test_the_service_stage_probes_hosts_concurrently(tmp_path):
    """식별 단계는 프로세스마다 타깃이 1개라 nmap 의 호스트 병렬성을 쓸 수 없다.

    그래서 직렬로 두면 소요가 호스트 수에 그대로 비례한다 - /24 한 대역이면 nmap 프로세스
    수백 개를 하나씩 세우고 기다린다. 호스트당 상한을 켠 뒤로는 느린 호스트의 대기시간까지
    그대로 더해진다. 전체 스캔의 stage3 는 enrichment 라 닫힘 권한 경로가 아니므로
    (권한은 discovery + sweep) 여기를 동시에 돌려도 권한 판정은 그대로다.
    """
    import threading

    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": [f"10.0.0.{i}" for i in range(1, 9)],
        "out_dir": str(tmp_path),
        "stages": {"service": {"workers": 4}},
    })
    pipe.open_map = {f"10.0.0.{i}": {"tcp": [22]} for i in range(1, 9)}

    lock = threading.Lock()
    live, peak = 0, 0

    def fake(stage, args, base, fatal=True):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        threading.Event().wait(0.05)
        with lock:
            live -= 1
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._service()
    assert peak > 1, "식별이 여전히 호스트 하나씩 직렬로 돈다"
    assert peak <= 4, "상한을 넘겨 프로세스를 띄우면 스캔 서버가 죽는다"
    # 모든 호스트가 실제로 식별됐고 재개 표식도 남아야 한다.
    assert all(pipe.state.service_done(f"10.0.0.{i}") for i in range(1, 9))


def test_a_rescan_still_probes_one_host_at_a_time(tmp_path):
    """재스캔은 stage3 가 유일한 폐쇄 근거다 - 실패하면 그 자리에서 멈춰야 한다.

    동시에 여러 개를 띄워 두면 '이미 시작한 것들을 어떻게 하나'가 애매해진다.
    권한이 걸린 경로에서는 애매함을 만들지 않는다.
    """
    import threading

    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "targets_ports": {"10.0.0.1": [22], "10.0.0.2": [22], "10.0.0.3": [22]},
        "stages": {"service": {"workers": 8}},
    })
    pipe.open_map = {ip: {"tcp": [22]} for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")}

    lock = threading.Lock()
    live, peak = 0, 0

    def fake(stage, args, base, fatal=True):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        threading.Event().wait(0.02)
        with lock:
            live -= 1
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._service()
    assert peak == 1, "재스캔은 직렬이어야 한다"


# ── 배치는 sweep 부터 식별까지 끝내고 다음 배치로 간다 ──────────────────────
def test_a_batch_is_finished_before_the_next_one_starts(tmp_path):
    """예전에는 TCP sweep 을 전 배치에 대해 끝내고, UDP sweep 을 전 배치에 대해 끝내고,
    그제서야 식별을 돌았다. 그래서 호스트가 100대를 넘으면 식별이 시작되기까지 아무 서비스
    정보도 나오지 않았고, 중간에 멈추면 그때까지의 결과가 포트 목록에서 끝났다.

    배치 단위로 닫으면 배치 하나가 끝날 때마다 **완성된** 결과가 나온다.
    """
    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1", "10.0.0.2"], "out_dir": str(tmp_path),
        "batch_size": 1,
        "stages": {"tcp": {"enabled": True, "ports": "1-65535"},
                   "udp": {"enabled": True, "ports": "53"},
                   "service": {"nse": []}},
    })
    order = []

    def fake(stage, args, base, fatal=True):
        name = pathlib_Path(base).name
        order.append(name)
        host = str(args[-1])
        proto = "udp" if "-sU" in args else "tcp"
        port = 53 if proto == "udp" else 22
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml(host, proto, port))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._scan_batches(["10.0.0.1", "10.0.0.2"])

    # 배치 0 의 모든 일이 배치 1 의 첫 일보다 먼저 끝나야 한다.
    b0 = [i for i, n in enumerate(order) if "b0" in n or "10_0_0_1" in n]
    b1 = [i for i, n in enumerate(order) if "b1" in n or "10_0_0_2" in n]
    assert b0 and b1 and max(b0) < min(b1), f"배치가 섞여 있다: {order}"
    # 그리고 배치 안에서는 sweep 이 식별보다 먼저다 - 식별은 sweep 이 찾은 포트를 쓴다.
    assert order.index("stage-tcp-b0") < order.index("stage3-tcp-b0-g0")


def test_engine_reports_five_stages_and_the_hosts_active_inside_each_batch(tmp_path):
    """이력은 '서비스 중'이 아니라 TCP/UDP 단계와 실제 병렬 호스트를 말해야 한다."""
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.pipeline import Pipeline
    from scanops_engine.spec import JobSpec

    class Sink:
        def __init__(self):
            self.events = []

        def emit(self, event, **fields):
            self.events.append({"event": event, **fields})

    sink = Sink()
    spec = JobSpec.from_dict({
        "job_id": "progress", "targets": ["10.0.0.1", "10.0.0.2"],
        "out_dir": str(tmp_path), "batch_size": 1,
        "stages": {"tcp": {"enabled": True, "ports": "22"},
                   "udp": {"enabled": True, "ports": "53"},
                   "service": {"nse": [], "udp_nse": []}},
    }).validate()
    pipe = Pipeline(spec, sink, "nmap")

    def fake(stage, args, base, fatal=True):
        host = str(args[-1])
        proto = "udp" if "-sU" in args else "tcp"
        port = 53 if proto == "udp" else 22
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml(host, proto, port))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._scan_batches(["10.0.0.1", "10.0.0.2"])

    assert pipe._stage_plan() == [
        "discovery", "tcp", "tcp_service", "udp", "udp_service",
    ]
    activity = [event for event in sink.events if event["event"] == "stage_activity"]
    assert {event["stage"] for event in activity} == {
        "tcp", "tcp_service", "udp", "udp_service",
    }
    assert any(event["stage"] == "tcp" and event["current_hosts"] == ["10.0.0.1"]
               and event["batch"] == 1 and event["batch_total"] == 2
               for event in activity)
    assert any(event["stage"] == "udp_service"
               and event["current_hosts"] == ["10.0.0.2"]
               and event["completed_hosts"] == 0
               for event in activity)


def test_tcp_service_probe_uses_one_batch_union_on_firewall_free_lan(tmp_path):
    """TCP는 배치 등장 포트 합집합을 한 번 실행해 Nmap 호스트 병렬성을 사용한다."""
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.pipeline import Pipeline
    from scanops_engine.spec import JobSpec
    from scanops.scanning import engine_runner

    class Sink:
        def __init__(self):
            self.events = []

        def emit(self, event, **fields):
            self.events.append({"event": event, **fields})

    hosts = [f"10.0.0.{i}" for i in range(1, 5)]
    spec_dict = {
        "job_id": "union", "targets": hosts, "out_dir": str(tmp_path), "batch_size": 16,
        "stages": {"tcp": {"enabled": False}, "udp": {"enabled": False},
                   "service": {"enabled": True, "confirm": False, "nse": []}},
    }
    sink = Sink()
    pipe = Pipeline(JobSpec.from_dict(spec_dict).validate(), sink, "nmap")
    pipe.open_map = {
        hosts[0]: {"tcp": [22, 80, 443]},
        hosts[1]: {"tcp": [22, 80, 443, 4444]},
        hosts[2]: {"tcp": [22, 80, 443, 3333]},
        hosts[3]: {"tcp": [22, 80, 443, 8888]},
    }
    seen = []

    def fake(stage, args, base, fatal=True):
        seen.append((stage, list(args), pathlib_Path(base).name))
        selected = [host for host in hosts if host in args]
        xml_hosts = "".join(
            f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh"/></port></ports></host>' for host in selected
        )
        pathlib_Path(str(base) + ".xml").write_text(
            '<?xml version="1.0"?><nmaprun>' + xml_hosts
            + '<runstats><finished exit="success"/></runstats></nmaprun>', encoding="utf-8",
        )
        return {"rc": 0, "seconds": 0.1, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._scan_batches(hosts)

    assert len(seen) == 1
    commands = {
        (tuple(host for host in hosts if host in args), args[args.index("-p") + 1])
        for stage, args, _base in seen if stage == "service"
    }
    assert commands == {(tuple(hosts), "T:22,80,443,3333,4444,8888")}
    assert {base for _stage, _args, base in seen} == {"stage3-tcp-b0-g0"}
    activity = [event for event in sink.events
                if event["event"] == "stage_activity" and event["stage"] == "tcp_service"]
    assert activity[0]["current_hosts"] == hosts
    assert activity[-1]["completed_hosts"] == 4
    assert engine_runner.artifact_report(tmp_path, spec_dict)["enrichment_missing"] == []


def test_identify_only_covers_the_ports_that_batch_actually_found(tmp_path):
    """식별은 전체 포트 범위를 다시 훑지 않는다 - 그 배치에서 열린 포트만 본다.

    여기가 새면 전수 스캔을 두 번 하는 셈이 되어 소요가 배로 늘어난다.
    """
    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "1-65535"},
                   "service": {"nse": []}},
    })
    seen = {}

    def fake(stage, args, base, fatal=True):
        seen[pathlib_Path(base).name] = list(map(str, args))
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1", "tcp", 22))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._scan_batches(["10.0.0.1"])

    sweep = seen["stage-tcp-b0"]
    assert sweep[sweep.index("-p") + 1] == "1-65535", "sweep 은 전수 그대로"
    probe = seen["stage3-tcp-b0-g0"]
    assert probe[probe.index("-p") + 1] == "T:22", "식별은 그 배치가 찾은 포트만"


def test_hosts_nmap_gave_up_on_are_collected_for_a_later_scan(tmp_path):
    """포기당한 호스트는 따로 모아 둬야 나중에 그 호스트만 다시 돌릴 수 있다.

    안 남기면 '왜 이 대역만 결과가 비지?' 를 알아낼 방법이 없다. 그리고 재시도로 끝까지
    훑으면 목록에서 빠져야 한다 - 한 번 걸렸다고 영구 낙인이 아니다.
    """
    import json

    from scanops.scanning import engine_runner

    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "22", "host_timeout": "5m"},
                   "service": {"enabled": False}},
    })

    def timed_out(stage, args, base, fatal=True):
        pathlib_Path(str(base) + ".xml").write_bytes(_timedout_only_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = timed_out
    pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    assert json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))["gave_up"] \
        == ["10.0.0.1"]
    assert engine_runner.gave_up_hosts(tmp_path) == ["10.0.0.1"]
    # 그 호스트는 이 실행에서 부재를 말할 자격도 없다.
    assert engine_runner.timed_out_hosts(tmp_path, "tcp") == {"10.0.0.1"}

    def clean(stage, args, base, fatal=True):
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = clean
    pipe._sweep_batch("tcp", 1, ["10.0.0.1"])
    assert engine_runner.gave_up_hosts(tmp_path) == [], "끝까지 훑었으면 목록에서 빠진다"


def test_retransmission_cap_hosts_are_collected_by_stage_for_a_later_scan(tmp_path, monkeypatch):
    """cap-hit은 host timeout과 별개지만 같은 재스캔 대기열에 원인별로 남아야 한다."""
    from scanops.scanning import engine_runner

    pipe, _ = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1", "10.0.0.2"], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "22"},
                   "service": {"enabled": False}},
    })
    from scanops_engine import nmaprun

    def cap_hit(nmap, args, base, **kwargs):
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1", "tcp", 22))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False,
                "retransmission_cap_hosts": ["10.0.0.2"]}

    monkeypatch.setattr(nmaprun, "run", cap_hit)
    pipe._sweep_batch("tcp", 0, ["10.0.0.1", "10.0.0.2"])

    retry = engine_runner.gave_up_detail(tmp_path)
    assert retry["targets"] == ["10.0.0.2"]
    assert retry["by_stage"] == {"tcp": ["10.0.0.2"]}
    assert retry["reasons_by_stage"] == {
        "tcp": {"10.0.0.2": ["retransmission_cap"]},
    }


def test_a_clean_udp_sweep_does_not_erase_a_tcp_timeout(tmp_path):
    """한 프로토콜 성공은 다른 프로토콜의 timeout 증거를 지우면 안 된다."""
    from scanops.scanning import engine_runner

    pipe, _ = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "22"},
                   "udp": {"enabled": True, "ports": "53"},
                   "service": {"enabled": False}},
    })

    def mixed(stage, args, base, fatal=True):
        xml = (_timedout_only_xml("10.0.0.1") if stage == "tcp"
               else _clean_xml("10.0.0.1", "udp", 53))
        pathlib_Path(str(base) + ".xml").write_bytes(xml)
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = mixed
    pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    pipe._sweep_batch("udp", 0, ["10.0.0.1"])

    assert engine_runner.gave_up_hosts(tmp_path) == ["10.0.0.1"]


def test_discovery_and_service_timeouts_are_also_collected(tmp_path):
    """timeout 재스캔 목록은 sweep뿐 아니라 호스트 발견·서비스/NSE 상한도 포함한다."""
    from scanops.scanning import engine_runner

    discovery_dir = tmp_path / "discovery"
    pipe, _ = _pipeline(discovery_dir, {
        "job_id": "d", "targets": ["10.0.0.1"], "out_dir": str(discovery_dir),
        "stages": {"discovery": {"enabled": True, "mode": "sn", "host_timeout": "1m"},
                   "tcp": {"enabled": False}, "service": {"enabled": False}},
    })

    def timed_out(stage, args, base, fatal=True):
        pathlib_Path(str(base) + ".xml").write_bytes(_timedout_only_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = timed_out
    pipe._discovery()
    assert engine_runner.gave_up_hosts(discovery_dir) == ["10.0.0.1"]

    service_dir = tmp_path / "service"
    service, spec = _pipeline(service_dir, {
        "job_id": "s", "targets": ["10.0.0.2"], "out_dir": str(service_dir),
        "stages": {"service": {"nse": [], "udp_nse": ["dns-nsid"],
                                "udp_host_timeout": "1m"}},
    })
    def service_timed_out(stage, args, base, fatal=True):
        pathlib_Path(str(base) + ".xml").write_bytes(_timedout_only_xml("10.0.0.2"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    service._nmap = service_timed_out
    service._probe_protocol("10.0.0.2", "udp", [53], spec.service, confirm=False,
                            isolate=True)
    assert engine_runner.gave_up_hosts(service_dir) == ["10.0.0.2"]


def test_a_resumed_scan_skips_batches_it_already_finished(tmp_path):
    """중지·이어가기 경계가 배치다 - 끝낸 배치의 sweep 도 식별도 다시 돌지 않는다."""
    spec_dict = {
        "job_id": "j", "targets": ["10.0.0.1", "10.0.0.2"], "out_dir": str(tmp_path),
        "batch_size": 1,
        "stages": {"tcp": {"enabled": True, "ports": "22"}, "service": {"nse": []}},
    }
    pipe, _ = _pipeline(tmp_path, spec_dict)
    calls = []

    def fake(stage, args, base, fatal=True):
        calls.append(pathlib_Path(base).name)
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml(str(args[-1])))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._scan_batches(["10.0.0.1", "10.0.0.2"])
    first = list(calls)
    assert first, "첫 실행이 아무 일도 하지 않았다"

    # 같은 out_dir 로 다시 - 이미 끝낸 배치는 건너뛴다.
    resumed, _ = _pipeline(tmp_path, spec_dict)
    calls.clear()
    resumed._nmap = fake
    resumed._scan_batches(["10.0.0.1", "10.0.0.2"])
    assert calls == [], f"이미 끝낸 배치를 다시 돌았다: {calls}"
