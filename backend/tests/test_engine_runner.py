"""engine_runner 순수 로직 — 옵션→단계 매핑 + 이벤트→단계요약(스폰 없이 결정적)."""
import json
import shutil
from pathlib import Path

import pytest

from scanops.db import SessionLocal
from scanops.models import Finding, FindingEvent, ScanRun
from scanops.scanning import engine_runner


def test_build_job_spec_maps_options_to_stages():
    spec = engine_runner.build_job_spec(
        7, ["10.0.0.0/24"], ["10.0.0.1"],
        options=["syn", "udp", "version_all", "t3"], ports="T:1-1000,U:53",
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
    assert st["udp"]["ports"] == "53"
    assert st["service"]["version_all"] is True
    assert st["service"]["nse"] == ["http-headers", "ssl-cert"]
    assert "targets_ports" not in spec


@pytest.mark.parametrize(("ports", "options", "tcp", "tcp_ports", "udp", "udp_ports"), [
    ("T:80", ["udp"], True, "80", False, ""),
    ("U:53", ["udp"], False, "", True, "53"),
])
def test_build_job_spec_enables_only_protocols_with_explicit_ports(
    ports, options, tcp, tcp_ports, udp, udp_ports,
):
    spec = engine_runner.build_job_spec(
        1, ["127.0.0.1"], [], options=options, ports=ports, nse=[],
        out_dir="/tmp/x", batch_size=256, discovery="pn",
    )

    assert spec["stages"]["tcp"] == {
        "enabled": tcp,
        "ports": tcp_ports,
        "timing": "-T4",
        "min_rate": 1000,
        "max_retries": 2,
    }
    assert spec["stages"]["udp"] == {
        "enabled": udp,
        "ports": udp_ports,
        "timing": "-T3",
    }


def test_build_job_spec_defaults_and_rescan():
    spec = engine_runner.build_job_spec(
        1, [], [], options=[], ports="", nse=None, out_dir="/tmp/x", batch_size=256,
        rescan_units=[{"ip": "10.0.0.5", "port": 6379, "proto": "tcp"},
                      {"ip": "10.0.0.5", "port": 22, "proto": "tcp"}])
    st = spec["stages"]
    assert st["tcp"]["ports"] == "1-65535"      # 기본 전포트
    assert st["tcp"]["timing"] == "-T4"          # 기본 T4
    assert st["udp"]["enabled"] is False
    assert "nse" not in st["service"]            # 생략하면 엔진 기본 NSE 사용
    assert len(spec["rescan_units"]) == 2 and spec["rescan_units"][0]["port"] == 6379


def test_build_job_spec_preserves_explicit_empty_nse():
    spec = engine_runner.build_job_spec(
        1, ["127.0.0.1"], [], options=[], ports="", nse=[],
        out_dir="/tmp/x", batch_size=256,
    )

    assert spec["stages"]["service"]["nse"] == []


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
    spec = engine_runner.build_job_spec(1, [], [], [], "", None, "/tmp/x", 256,
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


def test_parse_events_ignores_non_object_json_records(tmp_path):
    (tmp_path / "events.ndjson").write_text(
        '[]\n"not-an-event"\n'
        '{"event":"stage_progress"}\n'
        '{"event":"stage_progress","stage":"service","percent":"half"}\n'
        '{"event":"stage_progress","stage":"service","percent":150}\n'
        '{"event":"stage_done","stage":"udp","counts":[]}\n'
        '{"event":"job_done","status":[],"seconds":"later","counts":[]}\n'
        '{"event":"stage_start","stage":"tcp"}\n',
        encoding="utf-8",
    )

    result = engine_runner.parse_events(tmp_path)

    assert [stage["stage"] for stage in result["stages"]] == ["service", "udp", "tcp"]
    assert result["stages"][0]["percent"] == 100
    assert result["stages"][1]["status"] == "done"
    assert result["stages"][2]["status"] == "running"
    assert result["overall"]["status"] == "running"


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


def test_ingest_results_stage3_only_closes_scoped_missing_port(client, tmp_path):
    db = SessionLocal()
    try:
        scan1 = ScanRun(name="initial", status="done")
        db.add(scan1)
        db.commit()
        row = Finding(
            finding_key="127.0.0.1|65530|tcp", host_ip="127.0.0.1", port=65530,
            proto="tcp", state="open", first_scan_id=scan1.id, last_scan_id=scan1.id,
        )
        db.add(row)
        scan2 = ScanRun(name="stage3 rescan", status="running")
        db.add(scan2)
        db.commit()

        counts = engine_runner.ingest_results(
            db, scan2, tmp_path, scope_keys={"127.0.0.1|65530|tcp"},
            force_scanned_hosts=True,
        )
        assert counts["closed"] == 1
        assert row.state == "closed"
    finally:
        db.close()


def test_full_staged_ingest_uses_protocol_sweeps_as_stage3_fallback(client, tmp_path):
    ip = "127.0.0.1"
    (tmp_path / "run-state.json").write_text(json.dumps({
        "open_map": {ip: {"tcp": [54842, 54844], "udp": [63848]}},
        "live": [ip],
    }), encoding="utf-8")
    (tmp_path / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="54842"><state state="open"/>'
        '<service name="unknown" method="table"/></port>'
        '<port protocol="tcp" portid="54844"><state state="open"/>'
        '<service name="http" method="table"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    (tmp_path / "stage-udp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="63848"><state state="open|filtered"/>'
        '<service name="unknown" method="table"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    # Mirrors the runtime failure: stage3 misses one proven-open TCP and UDP port, while
    # enriching the other TCP port. The sweep remains authoritative for open state.
    (tmp_path / "stage3-127_0_0_1-tcp.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="54842"><state state="filtered"/></port>'
        '<port protocol="tcp" portid="54844"><state state="open"/>'
        '<service name="https" product="Exact Server" method="probed"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    (tmp_path / "stage3-127_0_0_1-udp.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="63848"><state state="filtered"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )

    db = SessionLocal()
    try:
        scan = ScanRun(name="mixed protocol full staged", status="running")
        db.add(scan)
        db.commit()

        counts = engine_runner.ingest_results(db, scan, tmp_path)

        rows = {
            (row.proto, row.port): row
            for row in db.query(Finding).filter_by(host_ip=ip).all()
        }
        assert counts["new"] == 3 and set(rows) == {
            ("tcp", 54842), ("tcp", 54844), ("udp", 63848),
        }
        assert rows[("tcp", 54842)].state == "open"
        assert rows[("tcp", 54844)].service == "https"
        assert rows[("tcp", 54844)].product == "Exact Server"
        assert rows[("udp", 63848)].state == "open|filtered"
        assert scan.host_count == 1 and scan.port_count == 3
    finally:
        db.close()


def test_sweep_fallback_preserves_existing_identity_until_stage3_observes_it(client, tmp_path):
    ip, port = "127.0.0.1", 54842
    key = f"{ip}|{port}|tcp"
    (tmp_path / "run-state.json").write_text(json.dumps({
        "open_map": {ip: {"tcp": [port]}}, "live": [ip],
    }), encoding="utf-8")
    (tmp_path / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><times srtt="222"/><ports>'
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        '<service name="unknown" method="table"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    preserved = {
        "hostname": "api.internal",
        "service": "http",
        "product": "Uvicorn",
        "version": "0.30",
        "server": "uvicorn/0.30",
        "banner": "Uvicorn 0.30",
        "cpe": "cpe:/a:encode:uvicorn:0.30",
        "identification": "확인",
        "nse_json": [{"id": "http-server-header", "output": "uvicorn/0.30"}],
        "remarks": "server=uvicorn/0.30",
        "category": "기존 웹",
        "usage": "기존 API",
        "risk_level": "high",
        "compliance_json": [{"std": "legacy", "ref": "keep"}],
    }
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        row = Finding(
            finding_key=key, host_ip=ip, port=port, proto="tcp", state="open",
            first_scan_id=initial.id, last_scan_id=initial.id, **preserved,
        )
        fallback_scan = ScanRun(name="fallback", status="running")
        db.add_all([row, fallback_scan])
        db.commit()

        fallback_counts = engine_runner.ingest_results(
            db, fallback_scan, tmp_path, scope_keys={key},
        )

        for field, value in preserved.items():
            assert getattr(row, field) == value
        assert row.state == "open" and row.rtt == "222"
        assert fallback_counts["unchanged"] == 1
        assert fallback_counts["service_changed"] == 0
        assert fallback_counts["version_changed"] == 0
        assert fallback_counts["server_changed"] == 0
        fallback_events = {
            event.type for event in db.query(FindingEvent).filter_by(scan_id=fallback_scan.id)
        }
        assert not {"SERVICE_CHANGED", "VERSION_CHANGED", "SERVER_CHANGED"} & fallback_events

        (tmp_path / "stage3-127_0_0_1-tcp.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            f'<port protocol="tcp" portid="{port}"><state state="open"/>'
            '<service name="http" product="Uvicorn" version="0.31" method="probed"/>'
            '<script id="http-server-header" output="uvicorn/0.31"/>'
            '</port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        overlay_scan = ScanRun(name="stage3 overlay", status="running")
        db.add(overlay_scan)
        db.commit()

        overlay_counts = engine_runner.ingest_results(
            db, overlay_scan, tmp_path, scope_keys={key},
        )

        assert row.service == "http" and row.product == "Uvicorn"
        assert row.version == "0.31" and row.server == "uvicorn/0.31"
        assert overlay_counts["service_changed"] == 0
        assert overlay_counts["version_changed"] == 1
        assert overlay_counts["server_changed"] == 1
        overlay_events = {
            event.type for event in db.query(FindingEvent).filter_by(scan_id=overlay_scan.id)
        }
        assert {"VERSION_CHANGED", "SERVER_CHANGED"} <= overlay_events
    finally:
        db.close()


def test_rescan_ingest_does_not_use_full_scan_sweep_fallback(client, tmp_path):
    key = "127.0.0.1|54842|tcp"
    (tmp_path / "stage-tcp-b0.xml").write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="54842"><state state="open"/></port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        row = Finding(
            finding_key=key, host_ip="127.0.0.1", port=54842, proto="tcp",
            state="open", first_scan_id=initial.id, last_scan_id=initial.id,
        )
        rescan = ScanRun(name="rescan", status="running")
        db.add_all([row, rescan])
        db.commit()

        counts = engine_runner.ingest_results(
            db, rescan, tmp_path, scope_keys={key}, force_scanned_hosts=True,
        )

        assert counts["closed"] == 1 and row.state == "closed"
    finally:
        db.close()


def test_ingest_results_full_scan_does_not_close_unresponsive_scoped_host(client, tmp_path):
    """Full staged scans only close findings for hosts observed live by discovery/sweep."""
    db = SessionLocal()
    try:
        scan1 = ScanRun(name="initial", status="done")
        db.add(scan1)
        db.commit()
        row = Finding(
            finding_key="127.0.0.1|443|tcp", host_ip="127.0.0.1", port=443,
            proto="tcp", state="open", first_scan_id=scan1.id, last_scan_id=scan1.id,
        )
        db.add(row)
        scan2 = ScanRun(name="full staged", status="running")
        db.add(scan2)
        db.commit()

        counts = engine_runner.ingest_results(
            db, scan2, tmp_path, scope_keys={"127.0.0.1|443|tcp"},
        )

        assert counts["closed"] == 0
        assert row.state == "open"
    finally:
        db.close()


def test_stage3_rescan_open_close_and_reopen_lifecycle(client, tmp_path):
    key = "127.0.0.1|18443|tcp"
    scope_keys = {key}
    db = SessionLocal()
    try:
        initial = ScanRun(name="initial", status="done")
        db.add(initial)
        db.commit()
        row = Finding(
            finding_key=key, host_ip="127.0.0.1", port=18443, proto="tcp", state="open",
            service="https", status="처리중", manual_note="운영 메모",
            first_scan_id=initial.id, last_scan_id=initial.id,
        )
        db.add(row)
        still_open = ScanRun(name="open rescan", status="running")
        db.add(still_open)
        db.commit()

        (tmp_path / "stage3-open.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="18443"><state state="open"/>'
            '<service name="https" method="probed"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        counts = engine_runner.ingest_results(
            db, still_open, tmp_path, scope_keys=scope_keys, force_scanned_hosts=True,
        )
        assert counts["closed"] == 0 and row.state == "open"

        (tmp_path / "stage3-open.xml").unlink()
        closed_scan = ScanRun(name="closed rescan", status="running")
        db.add(closed_scan)
        db.commit()
        counts = engine_runner.ingest_results(
            db, closed_scan, tmp_path, scope_keys=scope_keys, force_scanned_hosts=True,
        )
        assert counts["closed"] == 1
        assert row.state == "closed" and row.status == "정상처리"

        (tmp_path / "stage3-reopen.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="18443"><state state="open"/>'
            '<service name="https" method="probed"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        reopened_scan = ScanRun(name="reopen rescan", status="running")
        db.add(reopened_scan)
        db.commit()
        counts = engine_runner.ingest_results(
            db, reopened_scan, tmp_path, scope_keys=scope_keys, force_scanned_hosts=True,
        )
        assert counts["reopened"] == 1
        assert row.state == "open" and row.reopened == 1 and row.status == "미조치"
        assert row.manual_note == "운영 메모"
        types = {event.type for event in db.query(FindingEvent).filter_by(finding_id=row.id)}
        assert {"CLOSED", "REOPENED"} <= types
    finally:
        db.close()


def test_engine_availability_error_is_actionable(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_runner._settings, "engine_dir", tmp_path)
    with pytest.raises(RuntimeError, match="배포 패키지") as exc:
        engine_runner.ensure_available()
    assert str(tmp_path) not in str(exc.value)
