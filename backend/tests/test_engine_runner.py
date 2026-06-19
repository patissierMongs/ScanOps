"""engine_runner 순수 로직 — 옵션→단계 매핑 + 이벤트→단계요약(스폰 없이 결정적)."""
import json
import shutil
from pathlib import Path

from scanops.db import SessionLocal
from scanops.models import Finding, ScanRun
from scanops.scanning import engine_runner


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
        rescan_ports={"10.0.0.5": [6379, 22]})
    st = spec["stages"]
    assert st["tcp"]["ports"] == "1-65535"      # 기본 전포트
    assert st["tcp"]["timing"] == "-T4"          # 기본 T4
    assert st["udp"]["enabled"] is False
    assert "nse" not in st["service"]            # 비우면 엔진 기본 NSE 사용
    assert spec["targets_ports"] == {"10.0.0.5": [6379, 22]}


def test_describe():
    spec = engine_runner.build_job_spec(1, ["10.0.0.0/24"], [], ["udp"], "", [], "/tmp/x", 256)
    d = engine_runner.describe(spec)
    assert "단계스캔" in d and "UDP" in d
    rspec = engine_runner.build_job_spec(1, [], [], [], "", [], "/tmp/x", 256,
                                         rescan_ports={"10.0.0.5": [22]})
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
