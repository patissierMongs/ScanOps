"""engine_runner 순수 로직 — 옵션→단계 매핑 + 이벤트→단계요약(스폰 없이 결정적)."""
import json
import shutil
from pathlib import Path

import pytest

from scanops.db import SessionLocal
from scanops.models import Finding, FindingEvent, ScanRun
from pathlib import Path as pathlib_Path

from scanops.scanning import engine_runner, scan_options


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
    assert st["discovery"]["timing"] == "-T3"
    assert st["discovery"]["max_retries"] == 2
    assert st["tcp"]["ports"] == "1-1000"
    assert st["tcp"]["timing"] == "-T3"
    assert st["tcp"]["scan_type"] == "syn"
    assert st["tcp"]["min_rate"] == 0
    assert st["udp"]["enabled"] is True
    assert st["udp"]["ports"] == "53"
    assert st["udp"]["timing"] == "-T3"
    assert st["udp"]["max_retries"] == 4   # UDP 는 ICMP 율제한 때문에 더 넉넉히
    assert st["service"]["version_all"] is True
    assert st["service"]["timing"] == "-T3"
    assert st["service"]["max_retries"] == 2
    assert st["service"]["udp_max_retries"] == 4
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
        "scan_type": "syn",
        "min_rate": 0,
        "max_retries": scan_options.MAX_RETRIES_DEFAULT,
    }
    assert spec["stages"]["udp"] == {
        "enabled": udp,
        "ports": udp_ports,
        "timing": "-T4",
        # UDP 무응답은 '닫힘'이 아니라 '못 봄'이다 - TCP 보다 재전송을 넉넉히 준다.
        "max_retries": scan_options.UDP_MAX_RETRIES_DEFAULT,
    }


def test_build_job_spec_defaults_and_rescan():
    spec = engine_runner.build_job_spec(
        1, [], [], options=[], ports="", nse=None, out_dir="/tmp/x", batch_size=256,
        rescan_units=[{"ip": "10.0.0.5", "port": 6379, "proto": "tcp"},
                      {"ip": "10.0.0.5", "port": 22, "proto": "tcp"}])
    st = spec["stages"]
    assert st["tcp"]["ports"] == "1-65535"      # 기본 전포트
    assert st["tcp"]["timing"] == "-T4"          # 기본 T4
    assert st["discovery"]["timing"] == "-T4"
    assert st["discovery"]["max_retries"] == 2
    assert st["udp"]["enabled"] is False
    assert st["service"]["nse"] == engine_runner.scan_options.NSE_DEFAULT_KEYS
    assert st["service"]["version_all"] is True
    assert st["service"]["timing"] == "-T4"
    assert st["service"]["max_retries"] == 2
    assert st["service"]["workers"] == 16
    assert len(spec["rescan_units"]) == 2 and spec["rescan_units"][0]["port"] == 6379


def test_build_job_spec_preserves_explicit_empty_nse():
    spec = engine_runner.build_job_spec(
        1, ["127.0.0.1"], [], options=[], ports="", nse=[],
        out_dir="/tmp/x", batch_size=256,
    )

    assert spec["stages"]["service"]["nse"] == []


@pytest.mark.parametrize(("options", "version_all", "version_light"), [
    ([], True, False),
    (["syn"], False, False),
    (["syn", "version_all"], True, False),
    (["syn", "version_all", "version_light"], False, True),
])
def test_build_job_spec_preserves_default_and_explicit_version_choices(
    options, version_all, version_light,
):
    spec = engine_runner.build_job_spec(
        1, ["127.0.0.1"], [], options=options, ports="T:443", nse=None,
        out_dir="/tmp/x", batch_size=256,
    )
    service = spec["stages"]["service"]
    assert service["version_all"] is version_all
    assert service["version_light"] is version_light


def test_build_job_spec_maps_connect_and_rejects_incompatible_scan_types():
    spec = engine_runner.build_job_spec(
        1, ["127.0.0.1"], [], options=["connect"], ports="T:443", nse=[],
        out_dir="/tmp/x", batch_size=256,
    )
    assert spec["stages"]["tcp"]["scan_type"] == "connect"
    with pytest.raises(ValueError, match="SYN.*Connect"):
        engine_runner.build_job_spec(
            1, ["127.0.0.1"], [], options=["syn", "connect"], ports="T:443", nse=[],
            out_dir="/tmp/x", batch_size=256,
        )
    with pytest.raises(ValueError, match="Connect.*UDP"):
        engine_runner.build_job_spec(
            1, ["127.0.0.1"], [], options=["connect", "udp"], ports="T:443,U:53", nse=[],
            out_dir="/tmp/x", batch_size=256,
        )


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


def test_parse_events_exposes_five_stage_progress_and_current_hosts(tmp_path):
    lines = [
        {"event": "job_start"},
        {"event": "stage_plan", "stages": [
            "discovery", "tcp", "tcp_service", "udp", "udp_service",
        ]},
        {"event": "stage_done", "stage": "discovery", "seconds": 1,
         "counts": {"live": 4}},
        {"event": "stage_start", "stage": "tcp"},
        {"event": "stage_activity", "stage": "tcp", "percent": 25,
         "batch": 2, "batch_total": 4,
         "current_hosts": ["10.0.0.3", "10.0.0.4"], "current_host_count": 2},
        {"event": "stage_progress", "stage": "tcp", "percent": 50},
        {"event": "stage_start", "stage": "tcp_service"},
        {"event": "stage_activity", "stage": "tcp_service", "percent": 37.5,
         "batch": 2, "batch_total": 4, "current_hosts": ["10.0.0.3"],
         "current_host_count": 1, "completed_hosts": 1, "total_hosts": 2},
        # 병렬 호스트별 Nmap 퍼센트는 단계 전체 퍼센트를 덮어쓰면 안 된다.
        {"event": "stage_progress", "stage": "service", "percent": 99},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")

    result = engine_runner.parse_events(tmp_path)
    stages = {stage["stage"]: stage for stage in result["stages"]}

    assert list(stages) == ["discovery", "tcp", "tcp_service", "udp", "udp_service"]
    assert stages["tcp"]["percent"] == 37.5
    assert stages["tcp_service"]["percent"] == 37.5
    assert stages["udp"]["status"] == "pending"
    assert result["current"] == {
        "stage": "tcp_service", "hosts": ["10.0.0.3"],
        "batch": 2, "batch_total": 4, "current_host_count": 1,
        "completed_hosts": 1, "total_hosts": 2,
    }


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
    assert res["overall"]["percent"] == 0


def test_parse_events_exposes_timeout_reason_and_exact_grouped_commands(tmp_path):
    lines = [
        {"event": "stage_plan", "stages": ["tcp", "tcp_service", "udp"]},
        {"event": "stage_done", "stage": "tcp", "seconds": 2.0,
         "counts": {"open_ports": 2}},
        {"event": "stage_start", "stage": "tcp_service"},
        {"event": "command_start", "stage": "tcp_service", "execution_id": "x1",
         "group": "common", "reason": "TCP union", "artifact": "stage3-tcp-b0-g0",
         "argv": ["nmap.exe", "-sV", "-p", "T:22,443", "10.0.0.1", "10.0.0.2"],
         "ts": 10.0},
        {"event": "command_done", "stage": "tcp_service", "execution_id": "x1",
         "outcome": "timeout", "seconds": 20.5, "rc": 0,
         "timeout_count": 1, "timed_out": ["10.0.0.2"], "ts": 30.5},
        {"event": "hosts_gave_up", "stage": "service", "proto": "tcp", "count": 1,
         "hosts": ["10.0.0.2"]},
        {"event": "stage_done", "stage": "tcp_service", "seconds": 21.0,
         "counts": {"services": 1}},
        {"event": "job_done", "status": "stopped", "seconds": 23.0, "counts": {}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")

    result = engine_runner.parse_events(tmp_path)
    stages = {stage["stage"]: stage for stage in result["stages"]}
    assert stages["tcp_service"]["status"] == "warning"
    assert stages["tcp_service"]["percent"] == 100
    assert stages["tcp_service"]["issues"][0] == {
        "type": "host_timeout", "count": 1, "hosts": ["10.0.0.2"],
        "message": "호스트 1대가 제한 시간 안에 이 단계를 끝내지 못했습니다.",
    }
    assert result["overall"]["percent"] == pytest.approx(66.7)
    assert result["executions"] == [{
        "id": "x1", "stage": "tcp_service", "group": "common",
        "reason": "TCP union", "artifact": "stage3-tcp-b0-g0",
        "argv": ["nmap.exe", "-sV", "-p", "T:22,443", "10.0.0.1", "10.0.0.2"],
        "status": "timeout", "started_at": 10.0, "seconds": 20.5,
        "timeout_count": 1, "timed_out": ["10.0.0.2"], "rc": 0,
        "retransmission_cap_count": 0, "retransmission_cap_hosts": [],
        # 워치독이 끊은 실행에만 값이 실린다. 이 실행은 nmap 자신의 host-timeout 이므로 0.
        "watchdog_seconds": 0,
        "finished_at": 30.5,
    }]


def test_parse_events_separates_a_watchdog_kill_from_an_nmap_error(tmp_path):
    """워치독은 우리가 끊은 것이고 error 는 nmap 이 죽은 것이다.

    rc 만 보면 둘이 같아 보이는데 사용자가 할 일이 다르다 - 전자는 상한을 늘릴지 대상을
    줄일지 정하는 문제고, 후자는 원인을 조사할 문제다.
    """
    out = tmp_path / "scan_wd"
    out.mkdir()
    (out / "events.ndjson").write_text("\n".join(json.dumps(ev) for ev in [
        {"event": "job_start", "ts": 0.0},
        {"event": "command_start", "ts": 1.0, "execution_id": "w1", "stage": "tcp",
         "group": "common", "reason": "sweep", "artifact": "stage-tcp-b0",
         "argv": ["nmap.exe", "-sS", "10.0.0.1"]},
        {"event": "command_done", "ts": 601.0, "execution_id": "w1", "stage": "tcp",
         "group": "common", "reason": "sweep", "artifact": "stage-tcp-b0",
         "seconds": 600.0, "rc": -1, "outcome": "watchdog", "watchdog_seconds": 600,
         "timed_out": [], "timeout_count": 0,
         "retransmission_cap_hosts": [], "retransmission_cap_count": 0},
    ]), encoding="utf-8")

    execution = engine_runner.parse_events(out)["executions"][0]
    assert execution["status"] == "watchdog"
    assert execution["watchdog_seconds"] == 600
    # 상한에 걸린 호스트 목록과는 다른 개념이다 - 워치독은 프로세스를 통째로 끊는다.
    assert execution["timed_out"] == [] and execution["timeout_count"] == 0


def test_parse_events_exposes_retransmission_cap_as_a_stage_warning(tmp_path):
    lines = [
        {"event": "stage_plan", "stages": ["tcp"]},
        {"event": "stage_start", "stage": "tcp"},
        {"event": "retransmission_cap_hit", "stage": "tcp", "count": 1,
         "hosts": ["10.0.0.9"], "max_retries": 2},
        {"event": "stage_done", "stage": "tcp", "seconds": 3.0,
         "counts": {"open_ports": 0}},
        {"event": "job_done", "status": "done", "seconds": 3.0, "counts": {}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")

    stage = engine_runner.parse_events(tmp_path)["stages"][0]

    assert stage["status"] == "warning"
    assert stage["issues"] == [{
        "type": "retransmission_cap", "count": 1, "hosts": ["10.0.0.9"],
        "message": "호스트 1대에서 포트 재전송 한도(2회)에 도달했습니다.",
    }]


def test_parse_events_keeps_recovery_separate_from_durable_degradation(tmp_path):
    lines = [
        {"event": "stage_plan", "stages": ["udp_service"]},
        {"event": "stage_start", "stage": "udp_service"},
        {"event": "error", "stage": "service", "proto": "udp",
         "execution_id": "failed", "rc": 1, "fatal": False},
        {"event": "service_retry", "stage": "service", "proto": "udp",
         "hosts": ["10.0.0.7"], "ports": [53, 161], "port_spec": "U:53,161",
         "engine": "select", "reason": "udp_nsock_engine_fallback",
         "outcome": "recovered", "recovered": True, "seconds": 1.2, "rc": 0,
         "recovery_of_execution_id": "failed", "execution_id": "retry"},
        {"event": "service_split", "stage": "service", "proto": "udp",
         "ip": "10.0.0.8", "hosts": ["10.0.0.8"], "ports": [53, 161],
         "port_spec": "U:53,161", "units": 2, "recovered_units": 1,
         "failed_units": 1, "reason": "grouped_service_probe_failed",
         "outcome": "degraded", "recovered": False},
        {"event": "service_degraded", "stage": "service", "proto": "udp",
         "ip": "10.0.0.8", "hosts": ["10.0.0.8"], "ports": [53, 161],
         "failed_ports": [161], "port_spec": "U:53,161",
         "message": "서비스 프로브가 일부 또는 전부 완료되지 않았습니다."},
        {"event": "stage_done", "stage": "udp_service", "seconds": 4.0,
         "counts": {"services": 1}},
        {"event": "job_done", "status": "done", "seconds": 4.0, "counts": {}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")

    result = engine_runner.parse_events(tmp_path)

    assert [recovery["type"] for recovery in result["recoveries"]] == ["retry", "split"]
    assert result["recoveries"][0]["outcome"] == "recovered"
    assert result["recoveries"][0]["recovery_of_execution_id"] == "failed"
    assert result["recoveries"][1]["failed_units"] == 1
    assert result["stages"][0]["status"] == "warning"
    assert result["stages"][0]["issues"] == [{
        "type": "service_degraded", "count": 1, "hosts": ["10.0.0.8"],
        "proto": "udp", "ports": [161], "port_spec": "U:53,161",
        "message": "서비스 프로브가 일부 또는 전부 완료되지 않았습니다.",
    }]
    assert result["quality_issues"] == [{
        "kind": "service_degraded", "stage": "udp_service", "host_ip": "10.0.0.8",
        "proto": "udp", "port_spec": "U:53,161",
        "message": "서비스 프로브가 일부 또는 전부 완료되지 않았습니다.",
    }]


def test_fully_recovered_service_retry_does_not_leave_a_warning_issue(tmp_path):
    events = [
        {"event": "stage_plan", "stages": ["udp_service"]},
        {"event": "stage_start", "stage": "udp_service"},
        {"event": "error", "stage": "service", "proto": "udp",
         "execution_id": "failed", "rc": 1, "fatal": False},
        {"event": "service_retry", "stage": "service", "proto": "udp",
         "hosts": ["10.0.0.7"], "ports": [53], "port_spec": "U:53",
         "reason": "udp_nsock_engine_fallback", "outcome": "recovered",
         "recovered": True, "recovery_of_execution_id": "failed",
         "execution_id": "retry"},
        {"event": "stage_done", "stage": "udp_service", "seconds": 2,
         "counts": {"services": 1}},
        {"event": "job_done", "status": "done", "seconds": 2, "counts": {}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(event) for event in events), encoding="utf-8")

    result = engine_runner.parse_events(tmp_path)

    assert result["stages"][0]["status"] == "done"
    assert result["stages"][0]["issues"] == []
    assert result["quality_issues"] == []
    assert result["recoveries"][0]["outcome"] == "recovered"


def test_terminal_observability_projects_five_host_stages_and_exact_issues(tmp_path):
    events = [
        {"event": "stage_plan", "stages": [
            "discovery", "tcp", "tcp_service", "udp", "udp_service",
        ]},
        {"event": "stage_start", "stage": "discovery"},
        {"event": "hosts_up", "stage": "discovery", "hosts": ["10.0.0.1"], "count": 1},
        {"event": "stage_done", "stage": "discovery", "seconds": 1, "counts": {"live": 1}},
        {"event": "command_start", "stage": "tcp", "execution_id": "tcp-1",
         "group": "common", "role": "authority", "reason": "sweep",
         "artifact": "stage-tcp-b0", "argv": ["nmap", "10.0.0.1"], "ts": 10},
        {"event": "command_done", "stage": "tcp", "execution_id": "tcp-1",
         "outcome": "timeout", "seconds": 2, "rc": 0,
         "timed_out": ["10.0.0.2"], "timeout_count": 1,
         "retransmission_cap_hosts": [], "retransmission_cap_count": 0, "ts": 12},
        {"event": "service_degraded", "stage": "service", "proto": "udp",
         "hosts": ["10.0.0.1"], "ports": [161], "failed_ports": [161],
         "port_spec": "U:161", "message": "UDP 상세 실패"},
        {"event": "job_done", "status": "done", "seconds": 3, "counts": {}},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(event) for event in events), encoding="utf-8")
    (tmp_path / "run-state.json").write_text(json.dumps({
        "live": ["10.0.0.1"],
        "coverage": [
            {"artifact": "stage-tcp-b0.xml", "proto": "tcp", "role": "authority",
             "hosts": ["10.0.0.1", "10.0.0.2"], "ports": "T:1-65535", "finished": True},
            {"artifact": "stage3-10_0_0_1-udp.xml", "proto": "udp", "role": "enrichment",
             "hosts": ["10.0.0.1"], "ports": "U:161", "finished": False},
        ],
    }), encoding="utf-8")

    result = engine_runner.terminal_observability(
        tmp_path, {"targets": ["10.0.0.1", "10.0.0.2"]},
    )

    assert result["executions"][0]["role"] == "authority"
    issues = {(issue["kind"], issue["host_ip"], issue["stage"]) for issue in result["issues"]}
    assert issues == {
        ("host_timeout", "10.0.0.2", "tcp"),
        ("service_degraded", "10.0.0.1", "udp_service"),
    }
    hosts = {row["host_ip"]: row for row in result["hosts"]}
    assert hosts["10.0.0.1"] == {
        "host_ip": "10.0.0.1", "discovery_status": "done",
        "tcp_sweep_status": "done", "tcp_service_status": "unknown",
        "udp_sweep_status": "unknown", "udp_service_status": "degraded",
    }
    assert hosts["10.0.0.2"]["discovery_status"] == "not_responding"
    assert hosts["10.0.0.2"]["tcp_sweep_status"] == "timeout"


def test_parse_events_reports_elapsed_seconds_for_a_running_command(tmp_path, monkeypatch):
    lines = [
        {"event": "stage_start", "stage": "tcp_service"},
        {"event": "command_start", "stage": "tcp_service", "execution_id": "active",
         "group": "common", "reason": "TCP union", "artifact": "stage3-tcp-b0-g0",
         "argv": ["nmap.exe", "-sV", "10.0.0.1"], "ts": 100.0},
    ]
    (tmp_path / "events.ndjson").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    monkeypatch.setattr(engine_runner.time, "time", lambda: 112.4)

    execution = engine_runner.parse_events(tmp_path)["executions"][0]

    assert execution["status"] == "running"
    assert execution["seconds"] == pytest.approx(12.4)


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


def test_ingest_results_full_scan_closes_unobserved_host_in_explicit_effective_scope(client, tmp_path):
    """Completed structured scans treat explicit scope as authority, not discovery evidence."""
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

        assert counts["closed"] == 1
        assert row.state == "closed"
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


def test_a_target_expression_is_never_recorded_as_a_host(tmp_path):
    """저장된 spec 의 targets 는 **주소 표현**이지 호스트 목록이 아니다.

    기본 단계 스캔은 `-sn` 발견을 쓰므로 `10.0.0.0/24` 같은 문자열이 spec 에 그대로 남는다.
    그걸 호스트로 넣으면 그 토큰 자체가 가짜 관측 행이 되어 `not_responding` 으로 찍히고,
    정작 응답하지 않은 실제 주소들은 행이 없다 - 없는 호스트를 하나 만들고 있는 호스트들을
    빠뜨리는 셈이다. 이 행은 미관측 닫힘 판정이 읽는 데이터라 조용히 틀리면 안 된다.
    """
    import json

    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    out.mkdir()
    (out / "events.ndjson").write_text(
        json.dumps({"event": "stage_start", "stage": "discovery"}) + "\n"
        + json.dumps({"event": "stage_done", "stage": "discovery", "seconds": 1,
                      "counts": {"live": 1}}) + "\n", encoding="utf-8")
    (out / "run-state.json").write_text(
        json.dumps({"live": ["10.0.0.5"], "coverage": []}), encoding="utf-8")

    spec = {"targets": ["10.0.0.0/24", "10.0.0.1-50", "10.0.0.5"]}
    hosts = engine_runner.terminal_observability(out, spec)["hosts"]
    recorded = {row["host_ip"] for row in hosts}
    assert recorded == {"10.0.0.5"}, f"주소 표현이 호스트로 기록됐다: {sorted(recorded)}"

    # `--discovery pn` 경로는 실제 호스트 목록이 들어오므로 그쪽 미응답 기록은 남아야 한다.
    concrete = {"targets": ["10.0.0.5", "10.0.0.9"]}
    rows = {row["host_ip"]: row for row in
            engine_runner.terminal_observability(out, concrete)["hosts"]}
    assert set(rows) == {"10.0.0.5", "10.0.0.9"}
    assert rows["10.0.0.9"]["discovery_status"] == "not_responding"


def test_stages_that_never_ran_do_not_stay_pending_forever(tmp_path):
    """`-sn` 발견이 생존 0으로 끝나면 뒤 단계는 돌 것이 없다.

    계획에만 남겨 두면 잡은 `done` 으로 끝나는데 그 단계들은 영원히 '대기' 로 남아, 전체
    100% 옆에 시작도 안 한 칩이 붙는다. 끝났다는 사실을 남기되 `counts.skipped` 로
    '생략' 임을 밝힌다 - 돈 것과 돌 것이 없던 것은 다른 사실이다.
    """
    import json

    from scanops.scanning import engine_runner

    out = tmp_path / "scan_1"
    out.mkdir()
    events = [
        {"event": "job_start", "job_id": "scan_1", "targets": ["10.0.0.0/30"]},
        {"event": "stage_plan", "stages": ["discovery", "tcp", "tcp_service"]},
        {"event": "stage_start", "stage": "discovery"},
        {"event": "stage_done", "stage": "discovery", "seconds": 1, "counts": {"live": 0}},
        # 엔진이 남은 계획 단계를 닫는다.
        {"event": "stage_done", "stage": "tcp", "seconds": 0.0,
         "counts": {"skipped": True, "live": 0}},
        {"event": "stage_done", "stage": "tcp_service", "seconds": 0.0,
         "counts": {"skipped": True, "live": 0}},
        {"event": "job_done", "status": "done", "seconds": 1, "counts": {}},
    ]
    (out / "events.ndjson").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

    parsed = engine_runner.parse_events(out)
    stages = {s["stage"]: s for s in parsed["stages"]}
    assert set(stages) >= {"discovery", "tcp", "tcp_service"}
    for name in ("tcp", "tcp_service"):
        assert stages[name]["status"] != "pending", f"{name} 단계가 대기로 남았다"
        assert stages[name]["counts"].get("skipped") is True, f"{name} 이 생략으로 표시되지 않는다"
    assert parsed["overall"]["status"] == "done"


def test_the_engine_closes_the_plan_when_discovery_finds_nobody():
    """생산자 쪽 - 파이프라인이 실제로 그 이벤트를 낸다."""
    import sys

    sys.path.insert(0, str(pathlib_Path(__file__).resolve().parents[2] / "engine"))
    from scanops_engine import pipeline as pipeline_mod

    src = (pathlib_Path(__file__).resolve().parents[2]
           / "engine" / "scanops_engine" / "pipeline.py").read_text(encoding="utf-8")
    assert "_skip_remaining_stages" in src
    assert hasattr(pipeline_mod.Pipeline, "_skip_remaining_stages")

    body = src.split("def _skip_remaining_stages")[1].split("\n    def ")[0]
    assert '"skipped": True' in body, "생략 표식 없이 닫으면 훑고 온 단계와 구분되지 않는다"
    assert 'stage == "discovery"' in body, "발견 단계까지 다시 닫으면 실제 결과를 덮는다"


def _events(tmp_path, events):
    import json

    out = tmp_path / f"scan_{len(list(tmp_path.iterdir()))}"
    out.mkdir()
    (out / "events.ndjson").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return out


_FAILED_ATTEMPT = [
    {"event": "job_start"},
    {"event": "stage_plan", "stages": ["discovery", "tcp"]},
    {"event": "stage_start", "stage": "discovery"},
    {"event": "stage_done", "stage": "discovery", "seconds": 1, "counts": {"live": 1}},
    {"event": "stage_start", "stage": "tcp"},
    {"event": "error", "stage": "tcp", "execution_id": "e1", "fatal": True},
    {"event": "job_done", "status": "failed", "seconds": 2, "counts": {"errors": 1}},
]


def test_a_resumed_stage_does_not_keep_reporting_the_first_attempts_failure(tmp_path):
    """`events.ndjson` 은 append-only 라 재개해도 이전 시도의 오류가 그대로 남는다.

    `stage_start` 가 error 상태를 되돌리지 못하면 뒤따르는 `stage_done` 이 그 error 를
    보존하고, 옛 `command_error` 가 미해결 품질 이슈로 남는다. 스캔 행은 `done` 인데
    타임라인과 품질 상태는 실패로 보고하고, 재시도 안내가 영영 사라지지 않는다.
    """
    from scanops.scanning import engine_runner

    resumed = _FAILED_ATTEMPT + [
        {"event": "job_start"},
        {"event": "stage_start", "stage": "tcp"},
        {"event": "stage_done", "stage": "tcp", "seconds": 1, "counts": {"open_ports": 2}},
        {"event": "job_done", "status": "done", "seconds": 2, "counts": {}},
    ]
    parsed = engine_runner.parse_events(_events(tmp_path, resumed))
    tcp = next(s for s in parsed["stages"] if s["stage"] == "tcp")
    assert parsed["overall"]["status"] == "done"
    assert tcp["status"] == "done", "재개해서 성공했는데 단계가 실패로 남았다"
    assert not [i for i in tcp.get("issues", []) if i.get("type") == "command_error"]
    assert not [i for i in parsed.get("quality_issues", [])
                if i.get("kind") == "command_error"], "대체된 시도의 오류가 품질 이슈로 남았다"
    # 내부 추적 키가 응답으로 새면 안 된다.
    assert "_error_attempt" not in tcp
    assert all("_attempt" not in i for i in parsed.get("quality_issues", []))


def test_a_failure_that_was_never_retried_still_reports(tmp_path):
    """반대 경계 - 재개하지 않았으면 실패는 그대로 남아야 한다."""
    from scanops.scanning import engine_runner

    parsed = engine_runner.parse_events(_events(tmp_path, _FAILED_ATTEMPT))
    tcp = next(s for s in parsed["stages"] if s["stage"] == "tcp")
    assert parsed["overall"]["status"] == "failed"
    assert tcp["status"] == "error"
    assert [i for i in parsed.get("quality_issues", []) if i.get("kind") == "command_error"]


def test_a_batch_restart_inside_one_attempt_never_erases_the_failure(tmp_path):
    """배치마다 `stage_start` 가 다시 나온다(`_scan_batches`).

    회차를 보지 않고 지우면 배치 0 의 실패가 배치 1 시작에 조용히 사라진다 - 실패한 배치의
    호스트들이 훑지도 않은 채 정상 완료로 넘어간다.
    """
    from scanops.scanning import engine_runner

    same_attempt = _FAILED_ATTEMPT[:6] + [
        {"event": "stage_start", "stage": "tcp"},         # 다음 배치 - 같은 시도다
        {"event": "stage_done", "stage": "tcp", "seconds": 1, "counts": {}},
        {"event": "job_done", "status": "failed", "seconds": 2, "counts": {"errors": 1}},
    ]
    parsed = engine_runner.parse_events(_events(tmp_path, same_attempt))
    tcp = next(s for s in parsed["stages"] if s["stage"] == "tcp")
    assert tcp["status"] == "error", "같은 시도의 배치 재시작이 실패를 지웠다"
    assert [i for i in parsed.get("quality_issues", []) if i.get("kind") == "command_error"]


def test_a_resumed_service_stage_clears_the_normalized_error_slot(tmp_path):
    """실패 이벤트는 proto 에 따라 정규화되어 `stage_start` 와 슬롯 이름이 갈린다.

    `targets_ports`/`rescan_units` 생산자는 `stage_start(stage="service")` 를 내지만, 실패는
    `proto="tcp"` 때문에 `tcp_service` 슬롯으로 들어간다. 원시 이름만 보면 회차 비교가
    실행되지 않아 재개해서 성공해도 `tcp_service=error` 와 그 품질 이슈가 남는다.
    """
    from scanops.scanning import engine_runner

    failed = [
        {"event": "job_start"},
        {"event": "stage_plan", "stages": ["service"]},
        {"event": "stage_start", "stage": "service"},
        {"event": "error", "stage": "service", "proto": "tcp",
         "execution_id": "e1", "fatal": True},
        {"event": "job_done", "status": "failed", "seconds": 1, "counts": {"errors": 1}},
    ]
    resumed = failed + [
        {"event": "job_start"},
        {"event": "stage_start", "stage": "service"},
        {"event": "stage_done", "stage": "service", "seconds": 1, "counts": {"services": 2}},
        {"event": "job_done", "status": "done", "seconds": 1, "counts": {}},
    ]
    parsed = engine_runner.parse_events(_events(tmp_path, resumed))
    by_stage = {s["stage"]: s["status"] for s in parsed["stages"]}
    assert parsed["overall"]["status"] == "done"
    assert by_stage.get("tcp_service") != "error", "정규화된 슬롯의 옛 실패가 남았다"
    # 정규화 슬롯은 이번 시도의 stage_done 을 못 받는다 - running 으로 두면 끝난 스캔에
    # 영원히 도는 단계가 남는다.
    assert by_stage.get("tcp_service") != "running", "대체된 슬롯이 계속 도는 것으로 남았다"
    assert not [i for i in parsed.get("quality_issues", [])
                if i.get("kind") == "command_error"]

    # 같은 시도 안의 재시작은 여전히 실패를 지켜야 한다.
    same_attempt = failed[:4] + [
        {"event": "stage_start", "stage": "service"},
        {"event": "stage_done", "stage": "service", "seconds": 1, "counts": {}},
        {"event": "job_done", "status": "failed", "seconds": 1, "counts": {"errors": 1}},
    ]
    kept = engine_runner.parse_events(_events(tmp_path, same_attempt))
    assert {s["stage"]: s["status"] for s in kept["stages"]}.get("tcp_service") == "error"
    assert [i for i in kept.get("quality_issues", []) if i.get("kind") == "command_error"]
