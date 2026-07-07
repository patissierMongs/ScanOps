"""engine_runner 순수 로직 — 옵션→단계 매핑 + 이벤트→단계요약(스폰 없이 결정적)."""
import json
import shutil
import sys
from pathlib import Path

from scanops.config import get_settings
from scanops.db import SessionLocal
from scanops.models import Finding, FindingEvent, ScanRun
from scanops.scanning import engine_runner
from scanops.scanning.ingest import ingest


def _open_finding(db, scan_id, host_ip, port, proto="tcp"):
    ingest(db, scan_id, [{
        "host_ip": host_ip, "hostname": "", "port": port, "proto": proto, "state": "open",
        "service": "http", "product": "", "version": "", "banner": "", "cpe": "", "rtt": "",
        "identification": "확인", "nse_json": [], "remarks": "",
        "category": "", "usage": "", "risk_level": "info", "compliance_json": [],
    }], {host_ip})


def test_build_job_spec_maps_options_to_stages():
    spec = engine_runner.build_job_spec(
        7, ["10.0.0.0/24"], ["10.0.0.1"],
        options=["syn", "udp", "version_all", "t3"], ports="1-1000",
        nse=["http-headers", "ssl-cert"], out_dir="/tmp/x", batch_size=128, discovery="pn")
    assert spec["job_id"] == "scan_7"
    assert spec["targets"] == ["10.0.0.0/24"]
    assert spec["exclude"] == ["10.0.0.1"]
    assert spec["batch_size"] == 128
    st = spec["stages"]
    assert st["discovery"]["mode"] == "pn"
    assert st["tcp"]["ports"] == "1-1000"
    assert st["tcp"]["timing"] == "-T3"
    assert st["udp"]["enabled"] is True
    assert st["service"]["version_all"] is True
    assert st["service"]["nse"] == ["http-headers", "ssl-cert"]
    assert "targets_ports" not in spec


def test_build_job_spec_defaults_and_rescan():
    spec = engine_runner.build_job_spec(
        1, [], [], options=[], ports="", nse=[], out_dir="/tmp/x", batch_size=256,
        rescan_units=[{"ip": "10.0.0.5", "port": 6379, "proto": "tcp"},
                      {"ip": "10.0.0.5", "port": 22, "proto": "tcp"}])
    st = spec["stages"]
    assert st["tcp"]["ports"] == "1-65535"      # 기본 전포트
    assert st["tcp"]["timing"] == "-T4"          # 기본 T4
    assert st["udp"]["enabled"] is False
    assert "nse" not in st["service"]            # 비우면 엔진 기본 NSE 사용
    assert len(spec["rescan_units"]) == 2 and spec["rescan_units"][0]["port"] == 6379


def test_rescan_targets_units_per_finding():
    units, keys = engine_runner.rescan_targets([
        ("10.0.0.5", 6379, "tcp", "10.0.0.5|6379|tcp"),
        ("10.0.0.5", 22, "tcp", "10.0.0.5|22|tcp"),
        ("10.0.0.6", 80, "udp", "10.0.0.6|80|udp"),
        ("10.0.0.6", 80, "udp", "10.0.0.6|80|udp"),   # 중복 → 1건
    ])
    assert units == [
        {"ip": "10.0.0.5", "port": 6379, "proto": "tcp"},
        {"ip": "10.0.0.5", "port": 22, "proto": "tcp"},
        {"ip": "10.0.0.6", "port": 80, "proto": "udp"},
    ]
    assert keys == {"10.0.0.5|6379|tcp", "10.0.0.5|22|tcp", "10.0.0.6|80|udp"}


def test_build_job_spec_rescan_enables_confirm():
    spec = engine_runner.build_job_spec(1, [], [], [], "", [], "/tmp/x", 256,
                                        rescan_units=[{"ip": "10.0.0.5", "port": 22, "proto": "tcp"}])
    assert spec["stages"]["service"]["confirm"] is True
    assert spec["rescan_units"][0]["ip"] == "10.0.0.5"


def test_describe():
    spec = engine_runner.build_job_spec(1, ["10.0.0.0/24"], [], ["udp"], "", [], "/tmp/x", 256)
    d = engine_runner.describe(spec)
    assert "단계스캔" in d and "UDP" in d
    rspec = engine_runner.build_job_spec(1, [], [], [], "", [], "/tmp/x", 256,
                                         rescan_units=[{"ip": "10.0.0.5", "port": 22, "proto": "tcp"}])
    assert "재스캔" in engine_runner.describe(rspec)


def test_parse_events_folds_stages(tmp_path):
    lines = [
        {"event": "job_start"},
        {"event": "stage_start", "stage": "discovery"},
        {"event": "hosts_up", "stage": "discovery", "count": 3},
        {"event": "stage_done", "stage": "discovery", "seconds": 4.6, "counts": {"live": 3}},
        {"event": "stage_start", "stage": "tcp"},
        {"event": "ports_open", "stage": "tcp", "ip": "10.0.0.10", "ports": [80]},
        {"event": "stage_done", "stage": "tcp", "seconds": 2.7, "counts": {"open_ports": 1}},
        {"event": "stage_start", "stage": "service"},
        {"event": "stage_progress", "stage": "service", "percent": 50.0},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    res = engine_runner.parse_events(tmp_path)
    stages = {s["stage"]: s for s in res["stages"]}
    assert stages["discovery"]["status"] == "done"
    assert stages["discovery"]["counts"]["live"] == 3
    assert stages["tcp"]["status"] == "done"
    assert stages["service"]["status"] == "running"
    assert stages["service"]["percent"] == 50.0
    assert [s["stage"] for s in res["stages"]] == ["discovery", "tcp", "service"]
    assert res["overall"]["status"] == "running"


def test_parse_events_error_and_stopped(tmp_path):
    lines = [
        {"event": "stage_start", "stage": "udp"},
        {"event": "error", "stage": "udp", "rc": 1},
        {"event": "stage_done", "stage": "udp", "seconds": 1.0, "counts": {"stopped": True}},
        {"event": "job_done", "status": "stopped", "seconds": 9.0, "counts": {"services": 0}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    res = engine_runner.parse_events(tmp_path)
    udp = res["stages"][0]
    assert udp["status"] == "stopped"          # stage_done 의 stopped 가 error 보다 나중
    assert res["overall"]["status"] == "stopped"
    assert res["overall"]["percent"] == 100


def test_parse_events_missing_file(tmp_path):
    res = engine_runner.parse_events(tmp_path)
    assert res["stages"] == []
    assert res["overall"]["status"] == "running"


def test_ingest_results_closes_rescanned_port(client, tmp_path):
    """헤드라인 기능 회귀 — 발견별 재스캔(rescan_units)은 발견·찾기를 건너뛰어 엔진이 open_map/live
    를 안 남긴다. 그래도 scope_keys 로 스캔한 호스트를 보강해 닫힘 자동검증(정상처리)이 동작해야 한다.

    이전 버그: scanned_hosts 가 빈 집합 → ingest 의 닫힘 패스가 통째로 건너뛰어져 '조치 완료 자동
    확인'이 절대 발생하지 않았다(포트가 닫혔는데도 open/처리중 그대로).
    """
    db = SessionLocal()
    try:
        s1 = ScanRun(name="base", status="done"); db.add(s1); db.commit()
        _open_finding(db, s1.id, "10.9.9.9", 9999)
        f = db.query(Finding).filter_by(port=9999).first()
        f.status = "처리중"; db.commit()

        # 재스캔 결과: 포트 닫힘 → stage3 XML 없음, run-state 에 open_map/live 없음(재스캔 경로)
        s2 = ScanRun(name="rescan", status="running"); db.add(s2); db.commit()
        counts = engine_runner.ingest_results(db, s2, tmp_path, scope_keys={"10.9.9.9|9999|tcp"})
        assert counts["closed"] == 1
        f = db.query(Finding).filter_by(port=9999).first()
        assert f.state == "closed" and f.status == "정상처리"
        assert "CLOSED" in {e.type for e in db.query(FindingEvent).filter_by(finding_id=f.id)}
    finally:
        db.close()


def test_ingest_results_rescan_scope_does_not_touch_other_ports(client, tmp_path):
    """재스캔 닫힘 판정은 scope_keys(선택 발견)로만 한정 — 같은 호스트의 다른 열린 포트는 손대지 않음."""
    db = SessionLocal()
    try:
        s1 = ScanRun(name="base", status="done"); db.add(s1); db.commit()
        _open_finding(db, s1.id, "10.9.9.9", 9999)
        _open_finding(db, s1.id, "10.9.9.9", 22)   # 재스캔 대상 아님
        s2 = ScanRun(name="rescan", status="running"); db.add(s2); db.commit()
        engine_runner.ingest_results(db, s2, tmp_path, scope_keys={"10.9.9.9|9999|tcp"})
        assert db.query(Finding).filter_by(port=9999).first().state == "closed"
        assert db.query(Finding).filter_by(port=22).first().state == "open"   # 범위 밖 → 불변
    finally:
        db.close()


def test_rescan_close_records_basis(client, tmp_path):
    """닫힘 자동확정 시 근거를 CLOSED 이벤트에 구분 기록 — RST(확실 닫힘) vs 필터드/무응답(도달불가 추정).

    닫힘=부재 판정은 '열림 아니면 닫힘'이라 방화벽 드롭·오프라인도 정상처리로 확정된다. 재스캔은
    --open 없이 해당 포트를 직접 프로브하므로 실제 상태가 XML 에 남고, 그 근거를 감사 타임라인에 남긴다.
    """
    db = SessionLocal()
    try:
        s1 = ScanRun(name="base", status="done"); db.add(s1); db.commit()
        _open_finding(db, s1.id, "10.1.1.1", 80)    # 재스캔서 RST 로 확실히 닫힘
        _open_finding(db, s1.id, "10.2.2.2", 443)   # 재스캔서 filtered(무응답)
        (tmp_path / "stage3-10_1_1_1-tcp80.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port></ports>'
            '</host><runstats><finished/></runstats></nmaprun>', encoding="utf-8")
        (tmp_path / "stage3-10_2_2_2-tcp443.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.2.2.2" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/></port></ports>'
            '</host><runstats><finished/></runstats></nmaprun>', encoding="utf-8")
        s2 = ScanRun(name="rescan", status="running"); db.add(s2); db.commit()
        engine_runner.ingest_results(db, s2, tmp_path,
                                     scope_keys={"10.1.1.1|80|tcp", "10.2.2.2|443|tcp"})
        f_rst = db.query(Finding).filter_by(host_ip="10.1.1.1", port=80).first()
        f_flt = db.query(Finding).filter_by(host_ip="10.2.2.2", port=443).first()
        assert f_rst.state == "closed" and f_flt.state == "closed"   # 둘 다 자동 정상처리(워크플로우 유지)
        d_rst = db.query(FindingEvent).filter_by(finding_id=f_rst.id, type="CLOSED").first().detail
        d_flt = db.query(FindingEvent).filter_by(finding_id=f_flt.id, type="CLOSED").first().detail
        assert "RST" in d_rst and "도달불가" not in d_rst          # 확실히 닫힘
        assert "도달불가" in d_flt and "미도달" in d_flt            # 도달불가 추정 — 확인 요망 플래그
    finally:
        db.close()


def test_engine_cli_accepts_rescan_only_spec(tmp_path, monkeypatch):
    """엔진 CLI 가 rescan_units-only spec(targets 비어있음)을 '타겟 없음'으로 거부하지 않아야 한다.

    이전 버그: cli 의 타겟 존재 검사가 rescan_units 를 안 봐서 재스캔 스캔이 즉시 rc=2 로 죽고
    (엔진 로그 '타겟이 없습니다'), 워커가 scan 을 'failed' 로 표기 → 재스캔이 항상 실패했다.
    """
    engine_dir = str(get_settings().engine_dir)
    if engine_dir not in sys.path:
        sys.path.insert(0, engine_dir)
    from scanops_engine import cli, nmaprun, pipeline

    spec = {
        "job_id": "scan_1", "targets": [], "out_dir": str(tmp_path),
        "rescan_units": [{"ip": "10.0.0.5", "port": 22, "proto": "tcp"}],
        "stages": {"service": {"enabled": True, "confirm": True}},
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    monkeypatch.setattr(nmaprun, "find_nmap", lambda p="": "nmap")
    monkeypatch.setattr(pipeline.Pipeline, "run", lambda self: {"errors": 0})
    rc = cli.main(["--spec", str(spec_path), "--no-stdout"])
    assert rc == 0   # 이전엔 2 ("타겟이 없습니다")


def test_ingest_results_creates_findings(client, tmp_path):
    """엔진 산출(stage3 XML) → 기존 ingest()로 finding 생성되는 통합 경로. client=taxonomy 시드."""
    src = Path(__file__).parent / "fixtures" / "sample_scan.xml"
    shutil.copy(src, tmp_path / "stage3-host.xml")
    db = SessionLocal()
    try:
        scan = ScanRun(name="엔진 통합 테스트", status="running")
        db.add(scan)
        db.commit()
        before = db.query(Finding).count()
        counts = engine_runner.ingest_results(db, scan, tmp_path)
        assert counts["new"] >= 1
        assert db.query(Finding).count() > before
        assert scan.port_count >= 1
    finally:
        db.close()
