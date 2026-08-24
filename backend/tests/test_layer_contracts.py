"""계층 경계 계약 — 생산한 필드를 소비하는가, 같은 값을 한 곳에서 유도하는가.

이 파일이 있는 이유는 감사에서 지적받은 재발 패턴 때문이다. 한쪽에 필드를 추가할 때 반대쪽이
그걸 쓰는지 아무도 검사하지 않아서, 같은 결함이 자리만 바꿔 계속 나왔다 - NSE 는 돌리는데
모델링을 안 하고, 모델에는 있는데 내보내기에서 빠지고, 같은 값을 뷰마다 다시 유도해 갈렸다.

증상 하나를 그 자리에서 때우는 대신 **경계마다 계약을 못 박는다.**
"""
from __future__ import annotations

import io
import json
import threading
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

    def fake_nmap(stage, args, base, fatal=True, targets=None):
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


def _stage_argvs(tmp_path):
    """네 단계 × 두 프로토콜의 실제 argv 를 한 번에 뽑는다 - 정책은 전 단계가 함께 진다."""
    pipe, spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {
            "discovery": {},
            "tcp": {"enabled": True, "ports": "1-65535"},
            "udp": {"enabled": True, "ports": "53"},
            "service": {},
        },
    })
    seen = {}

    def fake(stage, args, base, fatal=True, targets=None):
        seen[f"{stage}:{pathlib_Path(base).name}"] = list(map(str, args))
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = fake
    pipe._discovery()
    pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    pipe._sweep_batch("udp", 0, ["10.0.0.1"])
    pipe._probe_protocol("10.0.0.1", "tcp", [443], spec.service, confirm=False)
    pipe._probe_protocol("10.0.0.1", "udp", [53], spec.service, confirm=False)
    return seen


def test_no_engine_stage_carries_a_host_timeout_but_scripts_stay_bounded(tmp_path):
    """뺀 것은 **호스트 상한뿐**이다. 스크립트 상한은 성질이 달라 그대로 둔다.

    `--host-timeout` 은 걸린 호스트의 포트 표를 아예 쓰지 않고 실행은 `exit="success"` 로
    끝낸다. 그래서 상한 하나가 그 호스트의 기존 발견을 전부 닫고 '정상처리'까지 만든다 -
    되돌리기 가장 어려운 미탐이다.

    `--script-timeout` 은 그렇지 않다. nmap 문서: "Any script instance which exceeds that
    time will be terminated and no output will be shown." 초과한 스크립트 인스턴스만 죽고
    포트 표는 남는다(실측 A/B 로도 rc=0 · 완결 XML · port=open 확인). 즉 관측 손실 없이
    느린 NSE 꼬리만 자르므로 유지하는 것이 맞다 - 처음에 이 둘을 같이 묶어 뺀 것이
    잘못이었다.
    """
    for key, argv in _stage_argvs(tmp_path).items():
        assert "--host-timeout" not in argv, f"{key} 단계에 호스트 상한이 되살아났다"
    # NSE 를 싣는 식별 단계는 스크립트 상한을 함께 실어야 한다.
    for key in ("service:stage3-10_0_0_1-tcp", "service:stage3-10_0_0_1-udp"):
        argv = _stage_argvs(tmp_path)[key]
        if "--script" in argv:
            assert "--script-timeout" in argv, f"{key} 단계에 스크립트 상한이 없다"


def test_the_load_caps_are_carried_only_where_nmap_honours_them(tmp_path):
    """처리량 플래그는 **가속이 아니라 부하 상한**이고, 효과가 있는 단계에만 싣는다.

    `--max-parallelism` 은 동시 프로브의 상한이라 어느 단계든 의미가 있다(빠른 LAN 에서
    적응형 병렬성을 100 으로 묶는 것이 의도다).

    `--min-hostgroup` 은 다르다. nmap 문서는 이 옵션이 호스트 발견 단계(`-sn` 포함)에
    **효과가 없다**고 명시한다. 없는 효과를 명령줄에 적어 두면 읽는 사람이 그 단계도 묶여
    도는 줄 안다 - 그래서 발견 단계에서는 뺀다.

    `--defeat-rst-ratelimit` 은 SYN 스캔 전용이다(`-sT`·`-sU`·`-sn` 과 함께 주면 nmap 이
    fatal 로 끝난다).
    """
    seen = _stage_argvs(tmp_path)
    assert set(seen) == {
        "discovery:stage0-discovery", "tcp:stage-tcp-b0", "udp:stage-udp-b0",
        "service:stage3-10_0_0_1-tcp", "service:stage3-10_0_0_1-udp",
    }
    for key, argv in seen.items():
        assert argv[argv.index("--max-parallelism") + 1] == "100", f"{key}: 병렬 상한"

    discovery = "discovery:stage0-discovery"
    assert "--min-hostgroup" not in seen[discovery], "nmap 이 무시하는 옵션을 싣지 않는다"
    for key, argv in seen.items():
        if key == discovery:
            continue
        # 나머지는 포트/버전 스캔이라 실제로 묶을 대상이 있다(스윕은 배치 전체,
        # 식별은 배치의 열린 포트 합집합을 한 프로세스로 돈다).
        assert argv[argv.index("--min-hostgroup") + 1] == "64", f"{key}: 호스트 그룹"

    syn = {"tcp:stage-tcp-b0", "service:stage3-10_0_0_1-tcp"}
    for key, argv in seen.items():
        assert ("--defeat-rst-ratelimit" in argv) is (key in syn), f"{key}: RST 율제한 우회"


def test_udp_gets_more_retries_than_tcp_in_sweep_and_identify(tmp_path):
    """UDP 무응답은 '닫힘'이 아니라 '못 봄'(open|filtered)이다.

    닫힌 UDP 포트의 ICMP port-unreachable 은 대상 **OS 스택 자체가** 율제한한다(흔히 초당
    1회). TCP 와 같은 재전송 상한을 쓰면 그 백오프를 못 기다려 실제로 닫힌 포트가 계속
    판정 불가로 남는다 - 스윕과 식별 **양쪽 모두** 늘려야 의미가 있다.
    """
    seen = _stage_argvs(tmp_path)

    def retries(key):
        argv = seen[key]
        return argv[argv.index("--max-retries") + 1]

    assert retries("discovery:stage0-discovery") == "2"
    assert retries("tcp:stage-tcp-b0") == "2"
    assert retries("service:stage3-10_0_0_1-tcp") == "2"
    assert retries("udp:stage-udp-b0") == "4"
    assert retries("service:stage3-10_0_0_1-udp") == "4"


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

    def fake(stage, args, base, fatal=True, targets=None):
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


def test_the_retry_policy_reaches_the_spec_split_by_protocol():
    """웹 요청이 만드는 spec 에도 프로토콜별 재전송 상한이 실제로 실리는지.

    중간에서 끊기면 UI 는 4 를 말하는데 실행은 2 로 도는 조용한 불일치가 된다.
    """
    from pathlib import Path

    from scanops.scanning import engine_runner, scan_options

    spec = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn", "udp", "version"], "", None, Path("/tmp/x"), 64)
    stages = spec["stages"]
    assert stages["discovery"]["max_retries"] == scan_options.MAX_RETRIES_DEFAULT
    assert stages["tcp"]["max_retries"] == scan_options.MAX_RETRIES_DEFAULT
    assert stages["service"]["max_retries"] == scan_options.MAX_RETRIES_DEFAULT
    assert stages["udp"]["max_retries"] == scan_options.UDP_MAX_RETRIES_DEFAULT
    assert stages["service"]["udp_max_retries"] == scan_options.UDP_MAX_RETRIES_DEFAULT
    assert (scan_options.UDP_MAX_RETRIES_DEFAULT
            > scan_options.MAX_RETRIES_DEFAULT), "UDP 는 TCP 보다 넉넉해야 한다"
    # 상한은 더 이상 spec 에 실리지 않는다 - 남아 있으면 엔진이 그 값을 그대로 쓴다.
    for stage in stages.values():
        assert "host_timeout" not in stage and "udp_host_timeout" not in stage
    # 워치독은 기본 꺼짐이다. 느린 망을 '실패'로 바꾸지 않으려면 켜는 쪽이 선택이어야 한다.
    assert spec["watchdog_seconds"] == 0


def test_the_watchdog_kills_the_process_without_forging_a_success(tmp_path):
    """워치독은 `--host-timeout` 의 대체가 아니라 **정반대 성질**의 안전장치다.

    `--host-timeout` 은 관측을 버리면서 실행을 `exit="success"` 로 끝내 미관측 닫힘 권한을
    준다. 워치독은 프로세스를 밖에서 끝내므로 그때까지 쓰인 XML 은 남고, rc 가 0 이 아니라
    닫힘 권한을 얻지 못한다. 그 성질이 뒤집히면 워치독을 둔 이유가 통째로 사라진다.
    """
    import os
    import sys
    import time as _time

    import pytest

    if os.name != "posix":
        pytest.skip("스텁 실행기를 셸 스크립트로 만든다(검사 대상 로직은 OS 무관)")

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    # run() 은 argv 를 [nmap, --stats-every, .., -oA, base] 로 고정 조립한다. 그 모양을
    # 그대로 받아 무시하고 잠들 스텁이 필요하다 - 진짜 nmap 을 몇 분씩 붙잡아 둘 수는 없다.
    def stub(body: str) -> str:
        path = tmp_path / f"stub-{abs(hash(body))}.sh"
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="ascii")
        path.chmod(0o755)
        return str(path)

    started = _time.time()
    result = nmaprun.run(
        stub("exec sleep 30"), ["-sS"], tmp_path / "slow",
        sudo_mode="never", stats="5s", watchdog_seconds=1, poll_interval=0.05,
    )
    assert result["timed_out_by_watchdog"] is True
    assert result["rc"] != 0, "워치독이 끊은 실행이 성공으로 보이면 안 된다"
    assert _time.time() - started < 20, "워치독이 실제로 끊지 못했다"

    # 끄면(0) 그대로 끝까지 기다린다 - 기본값이 조용히 상한을 거는 일은 없어야 한다.
    quick = nmaprun.run(
        stub("exit 0"), ["-sS"], tmp_path / "quick",
        sudo_mode="never", stats="5s", watchdog_seconds=0, poll_interval=0.05,
    )
    assert quick["timed_out_by_watchdog"] is False and quick["rc"] == 0


def test_the_watchdog_leaves_parseable_xml_with_the_hosts_it_finished(tmp_path):
    """'그때까지 쓴 관측은 남는다'가 실제로 참이어야 한다.

    `-oA` 가 증분 기록이라는 것만으로는 부족하다. 중간에 끊긴 XML 은 `</nmaprun>` 이 없어
    표준 파서가 통째로 거절하고, 그러면 **이미 끝난 호스트의 관측까지 함께 사라진다**
    (실측: 킬 직후 547바이트, "no element found"). SIGTERM·SIGINT 로 바꿔도 nmap 은
    닫아 주지 않는다.

    그래서 워치독이 끊은 뒤 마지막 완결 `</host>` 까지만 남기고 루트를 닫는다. `runstats` 는
    만들지 않으므로 산출물 완결성 검사는 그대로 실패한다 - 관측은 살리되 닫힘 권한은 주지
    않는 것이 이 복구의 존재 이유다.
    """
    import shutil
    import sys

    import pytest

    if not shutil.which("nmap"):
        pytest.skip("실제 nmap 이 있어야 중간 종료를 재현할 수 있다")

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    base = tmp_path / "wd"
    result = nmaprun.run(
        "nmap",
        ["-sT", "-Pn", "-n", "-p", "1-400", "--max-rate", "300",
         "--max-hostgroup", "1", "127.0.0.1-40"],
        base, sudo_mode="never", stats="5s", watchdog_seconds=6, poll_interval=0.1,
    )
    assert result["timed_out_by_watchdog"] is True and result["rc"] != 0

    xml = pathlib_Path(str(base) + ".xml")
    if not result["xml_repaired"]:
        # 끝난 호스트가 하나도 없으면 살릴 것이 없다 - 그때는 손대지 않는 것이 정직하다.
        pytest.skip("워치독이 첫 호스트 완료 전에 끊었다")

    # 표준 파서로 읽혀야 하고, 끝난 호스트의 관측이 실제로 남아 있어야 한다.
    import xml.etree.ElementTree as ET

    root = ET.parse(xml).getroot()
    assert len(root.findall("host")) >= 1
    assert len(nmaprun.hosts_up(xml)) >= 1, "복구된 XML 에서 관측을 못 읽는다"
    # 그러나 완결 표식은 없어야 한다 - 있으면 미관측 닫힘 권한을 얻는다.
    assert root.find("runstats") is None
    from scanops.scanning.engine_runner import _xml_run_finished

    assert _xml_run_finished(xml) is False, "복구본이 닫힘 권한을 얻으면 안 된다"


def test_a_crashed_nmap_call_still_closes_its_execution_record(tmp_path):
    """연 것은 반드시 닫는다.

    `command_start` 뒤 `nmaprun.run()` 이 던지면 뒤따르는 `command_done` 도, 상위의
    `job_done` 도 기록되지 않는다. 읽는 쪽은 `job_done` 이 있을 때만 열린 실행을 닫으므로
    그 실행은 UI 에서 영원히 '실행 중' 으로 남고, 경과시간이 폴링할 때마다 늘어난다 -
    워커가 이미 그 스캔을 실패로 마감한 뒤에도 그렇다.
    """
    import sys

    import pytest

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    events = []

    class _Sink:
        def emit(self, event, **fields):
            events.append((event, fields))

    pipe, _spec = _pipeline(tmp_path, {
        "job_id": "j", "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {"tcp": {"enabled": True, "ports": "22"}},
    })
    pipe.sink = _Sink()

    def boom(*args, **kwargs):
        raise OSError("cannot spawn nmap")

    original, nmaprun.run = nmaprun.run, boom
    try:
        with pytest.raises(OSError):
            pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    finally:
        nmaprun.run = original

    names = [event for event, _ in events]
    assert names.count("command_start") == names.count("command_done") == 1, names
    done = next(fields for event, fields in events if event == "command_done")
    assert done["outcome"] == "error" and done["rc"] is None
    assert done["error"] == "OSError"
    # 예외는 삼키지 않는다 - 실패를 기록만 하고 성공처럼 넘어가면 더 나쁘다.


def test_a_terminal_scan_never_reports_a_still_running_command(tmp_path, monkeypatch):
    """생산자가 손쓸 수 없는 종료(프로세스 강제 종료·머신 손실)도 있다.

    그때는 DB 의 lifecycle 이 유일한 진실이다. 스캔이 끝난 것으로 마감됐는데 실행 기록만
    '실행 중' 이면, 화면은 폴링할 때마다 늘어나는 경과시간을 계속 보여준다.
    """
    import json
    import time as _time

    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    out.mkdir()
    started = _time.time() - 3600
    (out / "events.ndjson").write_text("\n".join(json.dumps(ev) for ev in [
        {"event": "job_start", "ts": started},
        {"event": "stage_start", "ts": started, "stage": "tcp"},
        {"event": "command_start", "ts": started, "execution_id": "x1", "stage": "tcp",
         "group": "common", "reason": "sweep", "artifact": "stage-tcp-b0",
         "argv": ["nmap.exe", "-sS", "10.0.0.1"]},
    ]), encoding="utf-8")

    # 이벤트만 보면 아직 도는 중이고 경과시간이 계속 자란다.
    live = engine_runner.parse_events(out)["executions"][0]
    assert live["status"] == "running" and live["seconds"] >= 3599

    # API 는 DB 의 terminal status 로 그 기록을 닫아야 한다.
    from scanops.api import scans as scans_api

    executions = [dict(live)]
    scan_status = "failed"
    if scan_status not in ("running", "canceling"):
        for execution in executions:
            if execution.get("status") == "running":
                execution["status"] = "error"
                execution["interrupted"] = True
    assert executions[0]["status"] == "error" and executions[0]["interrupted"] is True
    # 위 블록은 scan_stages 안의 로직과 같은 모양이어야 한다 - 소스에서 대조한다.
    source = (pathlib_Path(scans_api.__file__)).read_text(encoding="utf-8")
    body = source.split("def scan_stages(")[1]
    assert 'execution["interrupted"] = True' in body
    assert 'if scan.status not in ("running", "canceling"):' in body


def test_every_surface_that_lost_the_host_timeout_can_turn_the_watchdog_on():
    """상한을 없앤 경로마다 대체 제어를 **실제로 켤 수 있어야** 한다.

    기본이 0(끔)인 것과, 제어 자체가 그 표면에 없는 것은 다른 문제다. 후자면 사용자는
    보호만 잃고 대체는 얻지 못한다 - 그게 순수한 후퇴다.

    표면 셋을 모두 본다: 단독 스캐너 CLI · 웹 staged · 웹 legacy/auto.
    """
    from pathlib import Path as _Path

    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import spec as engine_spec

    from scanops.scanning import scan_options
    from scanops.schemas import ScanRunIn

    root = pathlib_Path(__file__).resolve().parents[2]

    # 1) 단독 스캐너: CLI 옵션이 있고, plan 을 거쳐 실행 루프까지 닿아야 한다.
    standalone = (root / "scanner" / "scanops_scanner.py").read_text(encoding="utf-8")
    assert '"--watchdog"' in standalone, "단독 스캐너에 워치독 옵션이 없다"
    assert '"watchdog_seconds": validate_watchdog(' in standalone
    assert "watchdog_seconds=watchdog" in standalone, "plan 값이 실행 루프까지 안 간다"

    # 2) 웹 API 계약: 요청 본문이 값을 받고 기본은 끔이며, **범위를 경계에서 거절**한다.
    #    레거시 경로가 이 값을 threading.Timer 에 그대로 넘기므로, TIMEOUT_MAX 를 넘는
    #    값은 타이머 스레드가 즉시 죽어 '요청은 수락됐는데 상한만 없는' 상태가 된다.
    import pytest as _pytest

    assert ScanRunIn.model_fields["watchdog_seconds"].default == 0
    body = ScanRunIn(targets=["10.0.0.1"], watchdog_seconds=900)
    assert body.watchdog_seconds == 900
    for bad in (-1, scan_options.WATCHDOG_SECONDS_MAX + 1, 10 ** 100):
        with _pytest.raises(ValueError):
            ScanRunIn(targets=["10.0.0.1"], watchdog_seconds=bad)

    # 세 층의 상한이 같아야 한다 - 갈리면 한 층에서 통과한 값이 다른 층에서 거절된다.
    engine_max = engine_spec._MAX_WATCHDOG_SECONDS
    standalone_src = (root / "scanner" / "scanops_scanner.py").read_text(encoding="utf-8")
    assert scan_options.WATCHDOG_SECONDS_MAX == engine_max == 24 * 60 * 60
    assert "0 <= seconds <= 24 * 60 * 60" in standalone_src

    # 3) staged: 요청 값이 엔진 spec 까지 실린다.
    from scanops.scanning import engine_runner

    spec = engine_runner.build_job_spec(
        1, ["10.0.0.1"], [], ["syn"], "", None, _Path("/tmp/x"), 64, watchdog_seconds=900)
    assert spec["watchdog_seconds"] == 900

    # 4) legacy/auto: 요청 값이 sidecar state 에 저장되고, 워커가 그걸 읽어 넘긴다.
    scans_src = (root / "backend" / "scanops" / "api" / "scans.py").read_text(encoding="utf-8")
    assert '"watchdog_seconds": int(body.watchdog_seconds or 0)' in scans_src
    assert 'watchdog = int(state.get("watchdog_seconds") or 0)' in scans_src
    assert '_wait_scan_process(scan_id, proc, int(st.get("watchdog_seconds")' in scans_src, \
        "청킹 배치가 상한을 안 받는다"

    # 5) 웹 UI 가 실제로 그 필드를 보낸다. 파일 어딘가에 문자열이 있는지만 보면 안 된다 -
    #    이전 판이 정확히 그렇게 검사해서, staged 분기에만 실린 것을 통과시켰다.
    #    **두 요청 분기를 각각 뜯어** 확인한다.
    ui = (root / "frontend" / "src" / "views" / "Scans.jsx").read_text(encoding="utf-8")
    body = ui.split("const body = staged")[1].split("api(endpoint")[0]
    staged_branch, legacy_branch = body.split(": {", 1)
    assert "watchdog_seconds:" in staged_branch, "staged 요청 본문이 워치독을 안 보낸다"
    assert "watchdog_seconds:" in legacy_branch, "legacy/auto 요청 본문이 워치독을 안 보낸다"

    # 6) 컨트롤 자체가 staged 전용으로 숨겨져 있으면 안 된다 - 백엔드는 두 경로 모두
    #    받는데 화면에서 단계 스캔을 끄면 값을 정할 방법이 없어진다.
    control = ui.split("실행 상한 — nmap 프로세스 하나당")[0]
    tail = control.rsplit("<section", 1)[1] if "<section" in control else control
    assert "{staged &&" not in tail, "실행 상한 컨트롤이 staged 전용으로 갇혀 있다"


def test_the_two_run_modes_lay_out_their_artifacts_differently():
    """산출물 위치는 두 실행 방식이 **다르다**. 한쪽 규칙을 공통이라고 적으면 안 된다.

    화면은 워치독이 끊은 실행의 관측을 어디서 찾는지 안내한다. 그런데 `scan_<id>` 는
    단계 엔진에서만 디렉터리다 - `out_dir` 를 mkdir 하고 그 안에 stage-*.xml 을 넣는다.
    레거시는 같은 문자열을 **파일 접두사**로 써서(`_basename` + `.b<batch>` + `.<stage>`)
    `data/scans/` 바로 아래에 흩어 놓는다.

    그래서 '공통 폴더' 라고 안내하면 한 번에 실행을 쓴 관리자는 **없는 폴더**를 연다.
    UI 문자열이 아니라 경로 함수가 실제로 만드는 부모와 이름을 확인한다 - 문자열 검사는
    이 가정이 틀려도 그대로 통과했다.
    """
    from scanops.api import scans as scans_api
    from scanops.scanning import nmap_runner

    # 실제 설정값을 그대로 쓴다 - 검사하는 것은 루트가 아니라 그 아래의 **모양**이다.
    scans_dir = scans_api._settings.scans_dir

    # 레거시: _basename 은 디렉터리가 아니라 접두사다.
    base = scans_api._basename(7)
    assert base == scans_dir / "scan_7"

    # 워커가 실제로 만드는 이름(_chunk_worker: base + '.b<cursor>', 자동 단계가 '.<stage>')
    batch_base = pathlib_Path(str(base) + ".b0")
    stage_base = pathlib_Path(str(batch_base) + ".tcp_discovery")
    legacy_xml = nmap_runner.xml_of(stage_base)
    assert legacy_xml.parent == scans_dir, "레거시 XML 은 data/scans 바로 아래에 있다"
    assert legacy_xml.name == "scan_7.b0.tcp_discovery.xml"

    # 단계 엔진: 같은 문자열이 진짜 디렉터리이고 산출물은 그 안에 있다
    # (engine_runner 가 out_dir 을 mkdir 하고 pipeline 이 그 안에 stage-*.xml 을 쓴다).
    staged_dir = scans_dir / "scan_8"
    staged_xml = staged_dir / "stage-tcp-b0.xml"
    assert staged_xml.parent == staged_dir

    # 두 모양이 실제로 다르다는 것이 이 계약의 요지다.
    assert legacy_xml.parent != staged_xml.parent

    # 화면도 두 모양을 따로 안내해야 한다 - 한쪽 규칙만 적으면 다른 쪽이 없는 곳을 연다.
    ui = (pathlib_Path(__file__).resolve().parents[2]
          / "frontend" / "src" / "views" / "Scans.jsx").read_text(encoding="utf-8")
    warning = ui.split("watchdogMin > 0 &&")[1].split("</section>")[0]
    assert "staged ?" in warning, "회수 경로 안내가 실행 방식별로 갈리지 않는다"
    assert "scan_&lt;스캔번호&gt;/" in warning          # staged: 폴더
    assert ".b&lt;배치&gt;.&lt;단계&gt;.xml" in warning  # legacy: 파일 접두사


def test_the_three_scan_paths_agree_on_the_throughput_numbers():
    """웹·엔진·단독 스캐너가 같은 숫자를 써야 같은 프리셋이 같은 스캔이 된다.

    엔진은 백엔드를 import 하지 않는 독립 패키지고 단독 스캐너는 별도 프로세스라, 세 곳이
    사본을 들 수밖에 없다. 사본이 갈리는 것을 막는 자리는 여기뿐이다.
    """
    import re
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import spec as engine_spec

    from scanops.scanning import nmap_runner, scan_options

    root = pathlib_Path(__file__).resolve().parents[2]
    standalone = (root / "scanner" / "scanops_scanner.py").read_text(encoding="utf-8")

    def const(name):
        return re.search(rf'^{name} = "(.+?)"$', standalone, re.M).group(1)

    assert const("MIN_HOSTGROUP") == str(engine_spec.DEFAULT_MIN_HOSTGROUP) == "64"
    assert const("MAX_PARALLELISM") == str(engine_spec.DEFAULT_MAX_PARALLELISM) == "100"
    assert (const("MAX_RETRIES") == str(engine_spec.DEFAULT_MAX_RETRIES)
            == str(scan_options.MAX_RETRIES_DEFAULT) == nmap_runner.MAX_RETRIES)
    assert (const("UDP_MAX_RETRIES") == str(engine_spec.DEFAULT_UDP_MAX_RETRIES)
            == str(scan_options.UDP_MAX_RETRIES_DEFAULT) == nmap_runner.UDP_MAX_RETRIES)
    by_key = {option["key"]: option["flags"] for option in scan_options.SCAN_OPTIONS}
    assert by_key["min_hostgroup"] == ["--min-hostgroup", "64"]
    assert by_key["max_parallel"] == ["--max-parallelism", "100"]
    assert by_key["max_retries"] == ["--max-retries", nmap_runner.MAX_RETRIES]
    # 호스트 상한만 어느 층에도 남아 있으면 안 된다. 스크립트 상한은 유지 대상이다.
    #
    # argv 로 나가는 **문자열 리터럴**만 본다. 소스 전체를 훑으면 "--host-timeout 과 달리"
    # 처럼 왜 스크립트 상한만 남겼는지 적어 둔 주석까지 걸려, 이유를 기록할 수 없게 된다.
    assert '"--host-timeout"' not in standalone
    assert '"--script-timeout"' in standalone, "스크립트 상한은 관측을 버리지 않으므로 유지한다"
    assert not hasattr(engine_spec, "validate_host_timeout")
    assert not hasattr(scan_options, "HOST_TIMEOUT_DEFAULTS")


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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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

    def timed_out(stage, args, base, fatal=True, targets=None):
        pathlib_Path(str(base) + ".xml").write_bytes(_timedout_only_xml("10.0.0.1"))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    pipe._nmap = timed_out
    pipe._sweep_batch("tcp", 0, ["10.0.0.1"])
    assert json.loads((tmp_path / "run-state.json").read_text(encoding="utf-8"))["gave_up"] \
        == ["10.0.0.1"]
    assert engine_runner.gave_up_hosts(tmp_path) == ["10.0.0.1"]
    # 그 호스트는 이 실행에서 부재를 말할 자격도 없다.
    assert engine_runner.timed_out_hosts(tmp_path, "tcp") == {"10.0.0.1"}

    def clean(stage, args, base, fatal=True, targets=None):
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

    def mixed(stage, args, base, fatal=True, targets=None):
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

    def timed_out(stage, args, base, fatal=True, targets=None):
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
    def service_timed_out(stage, args, base, fatal=True, targets=None):
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

    def fake(stage, args, base, fatal=True, targets=None):
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


def test_the_three_paths_repair_a_truncated_xml_the_same_way(tmp_path):
    """끊긴 XML 복구는 세 경로가 각자 들고 있다 - 같은 입력에 같은 결과를 내야 한다.

    엔진은 따로 설치되는 패키지라 백엔드가 import 할 수 없고(`ensure_available`), 단독
    스캐너는 파일 하나로 복사되어 돈다. 그래서 구현이 셋이다. 한쪽만 고치면 같은 산출물이
    돌린 경로냐 가져온 경로냐에 따라 다르게 복구된다.

    핵심 성질은 **runstats 를 만들지 않는 것**이다. 완결성 검사가 그것을 요구하므로,
    복구본은 관측만 제공하고 미관측 닫힘 권한은 얻지 못한다.
    """
    import importlib.util
    import sys
    import xml.etree.ElementTree as ET

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    from scanops.scanning import nmap_runner

    spec = importlib.util.spec_from_file_location(
        "standalone_for_repair",
        pathlib_Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py",
    )
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)

    implementations = {
        "engine": nmaprun._repair_truncated_xml,
        "backend": nmap_runner.repair_truncated_xml,
        "standalone": standalone.repair_truncated_xml,
    }

    host = ('<host><status state="up"/><address addr="10.0.0.%d" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
            '</port></ports></host>')
    # 워치독이 두 번째 호스트를 쓰다 말고 끊은 모양.
    truncated = ('<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp"/>'
                 + (host % 1) + '<host><status state="up"/><address addr="10.0.0.2"')
    complete = ('<?xml version="1.0"?><nmaprun>' + (host % 1)
                + '<runstats><finished exit="success"/></runstats></nmaprun>')

    for name, repair in implementations.items():
        cut = tmp_path / f"{name}-cut.xml"
        cut.write_text(truncated, encoding="utf-8")
        assert repair(cut) is True, f"{name}: 끊긴 XML 을 복구하지 않았다"
        root = ET.fromstring(cut.read_bytes())          # 표준 파서를 통과해야 한다
        assert [h.find("address").get("addr") for h in root.findall("host")] == ["10.0.0.1"], name
        assert root.find("runstats") is None, f"{name}: 복구본이 닫힘 권한을 얻었다"

        # 이미 온전한 파일은 건드리지 않는다.
        whole = tmp_path / f"{name}-whole.xml"
        whole.write_text(complete, encoding="utf-8")
        assert repair(whole) is False, f"{name}: 온전한 XML 을 건드렸다"
        assert whole.read_text(encoding="utf-8") == complete, name

        # 살릴 호스트가 없으면 손대지 않는다 - 빈 파일로 두는 편이 정직하다.
        headless = tmp_path / f"{name}-headless.xml"
        headless.write_text('<?xml version="1.0"?><nmaprun><scaninfo type="syn"', encoding="utf-8")
        assert repair(headless) is False, f"{name}: 살릴 호스트가 없는데 손댔다"


def test_a_fired_watchdog_never_reports_success_on_any_path(tmp_path, monkeypatch):
    """상한에 걸린 실행은 **세 경로 모두** 실패로 끝나야 한다.

    종료 신호를 받은 nmap 이 0 으로 끝낼 수 있다. 그 rc 를 그대로 돌려주면 호출부가 '정상
    완료' 로 읽어 복구된 **부분** XML 에 미관측 닫힘 권한을 준다 - 훑지도 않은 포트가
    '닫힘/정상처리' 가 되고, 워치독을 둔 이유가 통째로 뒤집힌다.

    단계 엔진과 단독 스캐너는 이미 못박고 있었는데 레거시/자동 경로만 빠져 있었다.
    """
    import threading

    from scanops.api import scans as scans_api
    from scanops.scanning import nmap_runner

    base = tmp_path / "b0"
    nmap_runner.xml_of(base).write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host><host><status state="up"',
        encoding="utf-8",
    )

    class _Proc:
        def poll(self):
            return None

        def terminate(self):
            fired.set()

    fired = threading.Event()
    proc = _Proc()
    monkeypatch.setattr(scans_api.chunker, "stop_requested", lambda _base: False)
    # 상한에 걸렸는데도 nmap 이 0 으로 끝나는 경우.
    monkeypatch.setattr(nmap_runner, "wait_owned", lambda _p: 0 if fired.wait(5) else 0)

    rc = scans_api._wait_scan_process(1, proc, watchdog_seconds=0.05, out_base=base)
    assert rc != 0, "워치독이 끊었는데 성공으로 보고했다 - 부분 XML 이 닫힘 권한을 얻는다"

    # 세 구현이 같은 규칙을 쓰는지 소스에서 확인한다. 한쪽만 고치면 같은 산출물이 경로에
    # 따라 다르게 판정된다.
    engine_src = (pathlib_Path(__file__).resolve().parents[2]
                  / "engine" / "scanops_engine" / "nmaprun.py").read_text(encoding="utf-8")
    scanner_src = (pathlib_Path(__file__).resolve().parents[2]
                   / "scanner" / "scanops_scanner.py").read_text(encoding="utf-8")
    assert "if watchdog_fired and rc == 0:" in engine_src
    assert "rc = rc or -1" in scanner_src


def test_the_legacy_watchdog_repairs_the_artifact_it_cut(tmp_path, monkeypatch):
    """워치독이 끊은 산출물을 **레거시 경로도** 복구해야 한다.

    복구가 단계 엔진과 단독 스캐너에만 있었을 때, 레거시/자동 워크플로에서 상한을 켜면
    587바이트짜리 파싱 불가 XML 만 남았다(실측). 그런데 화면과 docstring 은 '그때까지 끝난
    호스트의 관측은 남는다' 고 약속했다 - 제어를 네 표면에 다 달아 놓고 약속은 두 곳에서만
    지킨 셈이다.
    """
    from scanops.api import scans as scans_api
    from scanops.scanning import nmap_runner

    base = tmp_path / "b0"
    nmap_runner.xml_of(base).write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host><host><status state="up"',
        encoding="utf-8",
    )

    class _Proc:
        """상한에 걸려 밖에서 끝난 프로세스."""

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    proc = _Proc()
    monkeypatch.setattr(scans_api.chunker, "stop_requested", lambda _base: False)
    fired = threading.Event()
    original_terminate = proc.terminate

    def _terminate():
        original_terminate()
        fired.set()

    proc.terminate = _terminate
    # 상한이 걸릴 때까지 실제로 기다린다 - 즉시 반환하면 타이머가 아직 안 터져 경합이 된다.
    monkeypatch.setattr(nmap_runner, "wait_owned",
                        lambda _p: -15 if fired.wait(5) else 0)

    rc = scans_api._wait_scan_process(1, proc, watchdog_seconds=0.05, out_base=base)
    # 상한 초과는 전용 코드로 돌려준다 - 시작 실패(-1)와 겹치면 화면이 거짓 원인을 말한다.
    assert rc == scans_api.WATCHDOG_RC
    assert getattr(proc, "terminated", False), "워치독이 프로세스를 끝내지 않았다"

    import xml.etree.ElementTree as ET
    root = ET.fromstring(nmap_runner.xml_of(base).read_bytes())
    assert [h.find("address").get("addr") for h in root.findall("host")] == ["10.0.0.1"]
    assert root.find("runstats") is None, "복구본이 닫힘 권한을 얻었다"


def test_a_watchdog_stop_is_not_reported_as_a_launch_failure(tmp_path, monkeypatch):
    """상한 초과는 '프로세스를 못 띄웠다' 와 다른 사실이다.

    둘 다 `-1` 로 돌려주면 `_checked_stage` 가 `nmap_launch_failed` 로 바꾸고, 화면에는
    "스캔 도구를 시작하지 못했습니다" 라는 거짓 원인이 남는다. 운영자는 nmap 설치를
    의심하며 시간을 쓴다.
    """
    import threading

    from scanops.api import scans as scans_api
    from scanops.scanning import nmap_runner

    base = tmp_path / "b0"
    nmap_runner.xml_of(base).write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host><host><status state="up"',
        encoding="utf-8",
    )

    fired = threading.Event()

    class _Proc:
        def poll(self):
            return None

        def terminate(self):
            fired.set()

    monkeypatch.setattr(scans_api.chunker, "stop_requested", lambda _base: False)
    monkeypatch.setattr(nmap_runner, "wait_owned", lambda _p: 0 if fired.wait(5) else 0)
    monkeypatch.setattr(nmap_runner, "popen", lambda *_a, **_k: _Proc())
    monkeypatch.setattr(scans_api, "_set_current_log", lambda *_a, **_k: None)

    try:
        scans_api._checked_stage(1, ["nmap"], tmp_path / "l.log", 0.05, base)
        raise AssertionError("상한을 넘겼는데 실패로 처리되지 않았다")
    except scans_api._WorkerFailure as exc:
        assert exc.code != "nmap_launch_failed", "상한 초과를 시작 실패로 보고한다"
        assert exc.code == "watchdog_exceeded"
    # 화면에 보일 문구가 있어야 한다 - 코드만 있고 문구가 없으면 원인이 비어 보인다.
    assert scans_api._FAILURE_MESSAGES.get("watchdog_exceeded")
    # 시작 실패는 그대로 시작 실패여야 한다.
    monkeypatch.setattr(nmap_runner, "popen",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("no nmap")))
    try:
        scans_api._checked_stage(1, ["nmap"], tmp_path / "l.log", 0, base)
        raise AssertionError("띄우지도 못했는데 실패로 처리되지 않았다")
    except scans_api._WorkerFailure as exc:
        assert exc.code == "nmap_launch_failed"


def test_a_failed_retry_never_destroys_the_first_attempts_artifacts(tmp_path):
    """재시도는 임시 base 로 돌고, **채택했을 때만** 원래 자리를 덮어야 한다.

    같은 ``-oA`` 를 쓰면 nmap 이 시작하자마자 첫 실행의 파일을 잘라 버린다. 워치독이 끊은 뒤
    복구해 둔 관측이 그 순간 사라지고, 재시도까지 실패하면 첫 실행이 남긴 부분 관측만 더
    나쁜 것으로 바뀐다 - terminal 인입은 부분 stage3 산출물도 읽으므로 그 손실이 그대로
    결과가 된다.

    엔진과 단독 스캐너가 **같은 규칙**을 써야 한다. 한쪽만 고치면 같은 실패가 경로에 따라
    다르게 끝난다.
    """
    import importlib.util
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    spec = importlib.util.spec_from_file_location(
        "standalone_for_retry",
        pathlib_Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py",
    )
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)

    base = tmp_path / "stage3-udp-b0-g0"
    alt = nmaprun.retry_base(base)
    # 접두사여야 이름이 단계로 끝난다 - 단계를 이름 끝으로 판별하는 곳이 여럿이다.
    assert alt.name == "retry~stage3-udp-b0-g0"
    assert alt.name.endswith(base.name)

    for suffix in nmaprun.OUTPUT_SUFFIXES:
        (tmp_path / f"stage3-udp-b0-g0{suffix}").write_text("first", encoding="utf-8")
        (tmp_path / f"retry~stage3-udp-b0-g0{suffix}").write_text("worse", encoding="utf-8")

    # 채택하지 않으면 첫 실행이 그대로 남고 재시도 파일은 사라진다.
    nmaprun.discard_artifacts(alt)
    for suffix in nmaprun.OUTPUT_SUFFIXES:
        kept = tmp_path / f"stage3-udp-b0-g0{suffix}"
        assert kept.read_text(encoding="utf-8") == "first", "첫 실행 산출물이 사라졌다"
        assert not (tmp_path / f"retry~stage3-udp-b0-g0{suffix}").exists(), "유령 파일이 남았다"

    # 채택하면 그때 옮긴다.
    for suffix in nmaprun.OUTPUT_SUFFIXES:
        (tmp_path / f"retry~stage3-udp-b0-g0{suffix}").write_text("better", encoding="utf-8")
    nmaprun.adopt_artifacts(alt, base)
    for suffix in nmaprun.OUTPUT_SUFFIXES:
        assert (tmp_path / f"stage3-udp-b0-g0{suffix}").read_text(encoding="utf-8") == "better"
        assert not (tmp_path / f"retry~stage3-udp-b0-g0{suffix}").exists()

    # 채택 조건은 '읽을 수 있는 산출물이 실제로 있는가' 다. 파일이 없을 때도 참인 조건을
    # 쓰면 아무것도 남기지 못한 재시도를 멀쩡하다고 읽는다.
    empty = tmp_path / "nothing"
    assert nmaprun.xml_usable(empty) is False
    (tmp_path / "nothing.xml").write_text("<nmaprun><host", encoding="utf-8")
    assert nmaprun.xml_usable(empty) is False
    (tmp_path / "nothing.xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
    assert nmaprun.xml_usable(empty) is True

    # 두 경로가 같은 이름 규칙을 쓰는지 - 단독 스캐너도 접두사여야 한다.
    std_alt = standalone.Path(str(base)).with_name(f"retry~{base.name}")
    assert std_alt.name == alt.name

    # 엔진의 그룹 UDP 폴백이 실제로 임시 base 를 쓰는지 소스에서 확인한다.
    pipeline_src = (pathlib_Path(__file__).resolve().parents[2]
                    / "engine" / "scanops_engine" / "pipeline.py").read_text(encoding="utf-8")
    fallback = pipeline_src.split('_UDP_RETRY_ENGINE] + args')[1].split("self.sink.emit")[0]
    assert "alt_base" in fallback, "그룹 UDP 재시도가 첫 실행과 같은 base 를 쓴다"
    assert "adopt_artifacts" in fallback and "discard_artifacts" in fallback


def test_the_trace_panel_reads_the_fields_the_backend_actually_sends(tmp_path):
    """서버가 내는 이름과 화면이 읽는 이름이 같아야 한다.

    되살린 패널이 옛 스키마(`runs_total`·`seconds_total`·`elapsed_seconds`)를 읽는데
    서버가 새 이름을 내보내면, 첫 가드에서 걸려 **아무것도 안 그려진다.** 오류도 안 나고
    빈 화면도 아니고 그냥 없다 - 실제로 그렇게 되살렸다가 놓쳤다.

    그래서 문자열 존재가 아니라 **실제 fold_trace 출력의 키**로 검사한다.
    """
    import re
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops.scanning import engine_runner

    trace = engine_runner.fold_trace([
        {"stage": "tcp_service", "proto": "tcp", "status": "done", "seconds": 12.0,
         "hosts": ["10.0.0.1"], "phases": {"Service scan": 10.0},
         "hosts_found": 1, "open_ports": 2, "inferred_open": 0, "products": 1,
         "empty": False, "label": "10.0.0.1", "ports": "T:22,443"},
        {"stage": "tcp", "proto": "tcp", "status": "running", "seconds": 5.0,
         "hosts": ["10.0.0.1", "10.0.0.2"], "phases": {}, "label": "2대", "ports": "T:1-65535"},
    ])

    panel = (pathlib_Path(__file__).resolve().parents[2]
             / "frontend" / "src" / "ui" / "ScanTrace.jsx").read_text(encoding="utf-8")
    # 패널이 trace 에서 직접 읽는 이름들.
    read = set(re.findall(r"trace[?]?\.(\w+)", panel))
    missing = sorted(name for name in read if name not in trace)
    assert not missing, f"화면이 읽는데 서버가 안 보내는 필드: {missing}"

    # 행 안에서 읽는 이름도 맞아야 한다 - 여기가 어긋나면 표가 비거나 '—' 로 찬다.
    assert "elapsed_seconds" in trace["running"][0], "진행 중 실행의 경과시간 키가 다르다"
    for key in ("stage", "proto", "runs", "seconds"):
        assert key in trace["by_stage"][0], f"단계별 행에 {key} 가 없다"
    for key in ("host", "runs", "seconds"):
        assert key in trace["by_host"][0], f"호스트별 행에 {key} 가 없다"
    for key in ("stage", "seconds", "phases", "empty", "hosts_found", "open_ports", "products"):
        assert key in trace["slowest"][0], f"오래 걸린 실행 행에 {key} 가 없다"

    # 패널을 여는 첫 가드가 실제로 통과해야 한다 - 통과 못 하면 패널 자체가 안 그려진다.
    assert trace["runs_total"] > 0

    # 생산자가 대상·포트를 실어야 '호스트별 소요' 와 진행 중 표가 채워진다. 안 실으면
    # 그 섹션은 오류 없이 **영원히 빈 채로** 남는다 - 실제로 그렇게 만들었다가 놓쳤다.
    meta_src = (pathlib_Path(__file__).resolve().parents[2]
                / "engine" / "scanops_engine" / "pipeline.py").read_text(encoding="utf-8")
    produced = meta_src.split("def _execution_meta")[1].split("def ")[0]
    for key in ("hosts", "label", "ports", "proto"):
        assert f'"{key}"' in produced, f"생산자가 {key} 를 안 싣는다"
    parser_src = (pathlib_Path(__file__).resolve().parents[2]
                  / "backend" / "scanops" / "scanning"
                  / "engine_runner.py").read_text(encoding="utf-8")
    started = parser_src.split('elif e == "command_start"')[1].split("elif e ==")[0]
    for key in ("hosts", "label", "ports", "proto"):
        assert f'"{key}"' in started, f"파서가 {key} 를 실행 기록에 안 담는다"
    assert trace["by_host"], "호스트별 소요가 비었다 - 그 섹션은 화면에 안 나온다"


def test_execution_metadata_records_only_the_real_targets(tmp_path):
    """실행 기록의 `hosts` 는 **호출부가 알려 준 타깃**이어야 한다.

    argv 에서 '옵션이 아닌 값' 을 골라내려 하면 재시도 수·묶음 크기·포트 스펙·스크립트
    상한이 전부 걸린다(실측: `2`·`64`·`100`·`2m` 이 호스트로 잡혔다). 그러면 한 대짜리
    실행이 '6대' 로 적히고, 호스트별 집계는 항목이 하나일 때만 세므로 그 표가 통째로 빈다 -
    어느 호스트가 끌고 있는지가 지연 진단의 핵심인데.
    """
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine.pipeline import Pipeline
    from scanops_engine.spec import JobSpec

    spec = JobSpec.from_dict({
        "job_id": 1, "targets": ["10.0.0.1"], "out_dir": str(tmp_path),
        "stages": {"discovery": {"mode": "pn"},
                   "tcp": {"enabled": True, "ports": "22,443"},
                   "udp": {"enabled": False, "ports": ""},
                   "service": {"enabled": True, "nse": ["ssl-cert"]}},
    })

    class _Sink:
        def emit(self, *_a, **_k):
            pass

    pipe = Pipeline(spec, _Sink(), "nmap")
    args = ["-sS", "-Pn", "-n", "--open", "-T4", "--reason",
            "--max-retries", "2", "--min-hostgroup", "64", "--max-parallelism", "100",
            "-p", "T:22,443", "--script", "ssl-cert", "--script-timeout", "2m", "10.0.0.1"]

    meta = pipe._execution_meta("service", args, tmp_path / "stage3-10_0_0_1-tcp",
                                targets=["10.0.0.1"])
    assert meta["hosts"] == ["10.0.0.1"], f"옵션 값이 호스트로 잡혔다: {meta['hosts']}"
    assert meta["label"] == "10.0.0.1", f"한 대짜리 실행인데 라벨이 {meta['label']}"
    assert meta["ports"] == "T:22,443"

    # 여러 대면 개수로 적고, 호스트는 그대로 담는다.
    many = pipe._execution_meta("tcp", args, tmp_path / "stage-tcp-b0",
                                targets=["10.0.0.1", "10.0.0.2"])
    assert many["hosts"] == ["10.0.0.1", "10.0.0.2"] and many["label"] == "2대"

    # 호출부가 안 알려 주면 지어내지 않는다 - 빈 목록이 정직하다.
    unknown = pipe._execution_meta("tcp", args, tmp_path / "stage-tcp-b0")
    assert unknown["hosts"] == []


def test_a_failed_udp_attempt_still_counts_toward_the_stage_time(tmp_path):
    """재시도한 UDP 식별의 단계 소요는 **두 시도의 합**이어야 한다.

    묶음/호스트별 두 경로 모두, 재시도 결과가 `r` 을 덮어쓴다. 반환값을 그대로 쓰면
    첫 시도에서 12분을 쓰고 재시도에서 3초 만에 끝난 실행이 '3초 걸린 단계' 로 남는다 -
    `_service_batch()` 가 이 값으로 영속 단계 소요를 만들기 때문에, 지연을 추적하려고
    보는 바로 그 숫자가 지연을 감춘다.
    """
    import sys
    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    for path, kind in ((tmp_path / "grouped", "grouped"), (tmp_path / "perhost", "perhost")):
        pipe, spec = _pipeline(path, {
            "job_id": kind, "targets": ["10.0.0.3"], "out_dir": str(path),
            "stages": {"service": {"nse": [], "udp_nse": []}},
        })
        calls = []

        def flaky(stage, args, base, fatal=True, targets=None):
            calls.append(str(base))
            first = len(calls) == 1
            if not first:
                # 재시도는 짧고, 읽을 수 있는 산출물을 남긴다(채택 조건).
                pathlib_Path(str(base) + ".xml").write_text(
                    "<nmaprun><runstats><finished exit=\"success\"/></runstats></nmaprun>",
                    encoding="utf-8")
            return {"rc": 1 if first else 0, "seconds": 720.0 if first else 3.0,
                    "cmd": args, "stopped": False}

        pipe._nmap = flaky
        if kind == "grouped":
            elapsed, _rows, ok = pipe._probe_batch_protocol(
                ["10.0.0.3"], "udp", [161], spec.service, 0, 0)
        else:
            elapsed, _rows, ok = pipe._probe_protocol(
                "10.0.0.3", "udp", [161], spec.service, confirm=False)

        assert ok, f"{kind}: 재시도가 채택되지 않아 시간 비교가 무의미하다"
        assert len(calls) == 2, f"{kind}: 재시도가 일어나지 않았다"
        assert calls[1] != calls[0], f"{kind}: 재시도가 첫 실행과 같은 base 를 썼다"
        assert elapsed == 723.0, (
            f"{kind}: 단계 소요가 {elapsed} 초 - 실패한 첫 시도(720초)가 사라졌다"
        )
        assert nmaprun.retry_base(pathlib_Path(calls[0])).name == pathlib_Path(calls[1]).name


def test_a_running_execution_reports_how_long_it_has_actually_been_running():
    """'지금 실행 중' 표의 경과는 시작 시각에서 재야 한다.

    도는 중인 실행에는 `seconds` 가 없다(command_done 이 아직 안 왔다). 그걸 그대로
    경과로 쓰면 표가 영원히 '0초 경과' 를 그리고, 오래 걸리는 실행을 굵게 짚어 주는
    임계값(ScanTrace.LONG_RUN_SECONDS)도 절대 안 걸린다 - 지연이 어디서 나는지 보려고
    만든 표가 정작 지연을 못 가리킨다.
    """
    import re
    from datetime import datetime, timezone
    from scanops.scanning import engine_runner

    now = 10_000.0
    trace = engine_runner.fold_trace([
        {"id": "a", "stage": "service", "status": "running", "seconds": None,
         "started_at": now - 725.0, "hosts": ["10.0.0.1"], "label": "10.0.0.1"},
        {"id": "b", "stage": "tcp", "status": "running", "seconds": None,
         "started_at": datetime.fromtimestamp(now - 30.0, timezone.utc),
         "hosts": ["10.0.0.2"], "label": "10.0.0.2"},
        {"id": "c", "stage": "tcp", "status": "running", "seconds": None,
         "started_at": None, "hosts": ["10.0.0.3"]},          # 시작 시각을 모르면 0
    ], now=now)
    elapsed = {run["id"]: run["elapsed_seconds"] for run in trace["running"]}
    assert elapsed["a"] == 725.0, "경과가 시작 시각에서 나오지 않는다"
    assert elapsed["b"] == 30.0, "영속 행(datetime)에서도 경과를 못 잰다"
    assert elapsed["c"] == 0.0, "모르는 값을 지어냈다"

    # 화면의 임계값이 실제로 걸리는가 - 이 값이 0 이면 굵게 짚어 주는 일이 영영 없다.
    source = (pathlib_Path(__file__).resolve().parents[2]
              / "frontend" / "src" / "ui" / "ScanTrace.jsx").read_text(encoding="utf-8")
    threshold = int(re.search(r"LONG_RUN_SECONDS\s*=\s*(\d+)", source).group(1))
    assert elapsed["a"] >= threshold, (
        f"12분째 도는 실행이 화면 임계값({threshold}초)에 안 걸린다"
    )


def test_the_staged_watchdog_does_not_fail_a_scan_that_finished_in_the_gap(tmp_path):
    """단계 엔진 워치독도 이미 끝난 프로세스에 발동하면 안 된다.

    루프 조건 `while proc.poll() is None` 과 상한 검사 사이에는 `stop_requested()` 가
    있고, 그건 파일을 읽는다. 그 사이에 nmap 이 정상 종료하면 예전에는 그대로 상한
    초과로 표시했고, 아래 강제 실패(rc 0 → -1)가 걸려 **완주한 스캔이 실패/부분으로**
    남았다. 멀쩡한 XML 도 워치독 복구본으로 격리된다.
    """
    import sys
    import time
    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import nmaprun

    polls = {"n": 0}
    checked_stop = {"n": 0}
    reached = {"deadline": False}

    class _ExitsInTheGap:
        """루프 조건에서는 살아 있고, 상한 검사 시점에는 이미 끝나 있다."""

        def __init__(self):
            self.stdout = iter([])
            self.terminated = False

        def poll(self):
            polls["n"] += 1
            return None if polls["n"] == 1 else 0     # 첫 확인 이후 종료

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            self.terminated = True

    process = _ExitsInTheGap()
    base = tmp_path / "stage"
    (tmp_path / "stage.xml").write_text(
        '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/>'
        '</runstats></nmaprun>', encoding="utf-8")

    def stop_requested():
        checked_stop["n"] += 1
        time.sleep(0.02)      # 파일을 읽는 자리 - 그 사이에 상한이 지나고 nmap 이 끝난다
        reached["deadline"] = True   # 이 뒤가 곧 상한 검사다
        return False

    original_popen = nmaprun.popen_owned
    original_terminate = nmaprun.terminate_owned
    original_close = nmaprun.close_kill_job
    nmaprun.popen_owned = lambda *a, **k: process
    nmaprun.terminate_owned = lambda proc: proc.terminate()
    nmaprun.close_kill_job = lambda proc: None
    try:
        result = nmaprun.run("nmap", ["-sS", "10.0.0.1"], base,
                             stop_requested=stop_requested,
                             poll_interval=0.01, watchdog_seconds=0.001)
    finally:
        nmaprun.popen_owned = original_popen
        nmaprun.terminate_owned = original_terminate
        nmaprun.close_kill_job = original_close

    assert checked_stop["n"] >= 1, "상한 검사 앞의 자리를 지나지 않았다 - 재현이 안 됐다"
    assert polls["n"] >= 2, "상한 지점에서 다시 확인하지 않았다 - 이 검사는 빈 검사다"
    assert reached["deadline"], "상한 검사에 아예 닿지 않았다 - 이 검사는 빈 검사다"
    assert result["rc"] == 0, f"완주한 스캔이 rc={result['rc']} 로 바뀌었다"
    assert result["timed_out_by_watchdog"] is False, "상한을 넘기지 않았는데 넘겼다고 한다"
    assert not process.terminated, "이미 끝난 프로세스를 종료하려 했다"
    # 멀쩡한 XML 은 그대로여야 한다 - 복구본으로 격리되면 닫힘 권한을 잃는다.
    assert "<finished" in (tmp_path / "stage.xml").read_text(encoding="utf-8")


def test_a_resumed_scan_reports_the_ports_it_found_before_the_stop(tmp_path):
    """이어가기로 끝난 스캔의 단계 총계는 **중지 전에 찾은 것까지** 세야 한다.

    이미 끝낸 배치는 건너뛰므로, 이 프로세스에서 훑은 것만 더하는 누산기를 쓰면 그
    포트가 총계에서 빠진다. 서비스 단계만 남기고 이어가면 총계가 0 으로 마감돼,
    타임라인과 영속 단계 요약이 그 스캔이 실제로 인입한 발견과 어긋난다.
    """
    spec_dict = {
        "job_id": "r", "targets": ["10.0.0.1", "10.0.0.2"], "out_dir": str(tmp_path),
        "batch_size": 1,
        "stages": {"tcp": {"enabled": True, "ports": "22"}, "service": {"nse": []}},
    }

    def emitted_tcp_total(sink_events):
        done = [e for e in sink_events
                if e[0] == "stage_done" and e[1].get("stage") == "tcp"]
        assert done, "tcp 단계가 마감되지 않았다 - 이 검사는 아무것도 안 보고 있다"
        return done[-1][1]["counts"]

    class _Recording:
        def __init__(self):
            self.events = []

        def emit(self, event, **fields):
            self.events.append((event, fields))

    def fake(stage, args, base, fatal=True, targets=None):
        pathlib_Path(str(base) + ".xml").write_bytes(_clean_xml(str(args[-1])))
        return {"rc": 0, "seconds": 0.0, "cmd": args, "stopped": False}

    # 1차: 두 배치를 다 돌아 기준값을 만든다.
    whole, _ = _pipeline(tmp_path / "whole", {**spec_dict, "out_dir": str(tmp_path / "whole")})
    whole.sink = _Recording()
    whole._nmap = fake
    whole._scan_batches(["10.0.0.1", "10.0.0.2"])
    expected = emitted_tcp_total(whole.sink.events)
    assert expected["open_ports"] >= 1 and expected["hosts"] == 2, expected

    # 2차: 한 번 다 돌린 뒤, 같은 out_dir 로 이어간다(모든 배치가 이미 done).
    resumed_dir = tmp_path / "resumed"
    first, _ = _pipeline(resumed_dir, {**spec_dict, "out_dir": str(resumed_dir)})
    first._nmap = fake
    first._scan_batches(["10.0.0.1", "10.0.0.2"])

    again, _ = _pipeline(resumed_dir, {**spec_dict, "out_dir": str(resumed_dir)})
    again.sink = _Recording()
    ran = []
    again._nmap = lambda *a, **k: ran.append(1) or fake(*a, **k)
    again._scan_batches(["10.0.0.1", "10.0.0.2"])
    assert not ran, "이어가기가 배치를 다시 돌았다 - 재현이 안 됐다"

    assert emitted_tcp_total(again.sink.events) == expected, (
        "이어가기가 중지 전에 찾은 포트를 총계에서 빠뜨렸다"
    )
    assert again.counts["open_tcp"] == whole.counts["open_tcp"], (
        "영속 요약도 같은 수를 말해야 한다"
    )
