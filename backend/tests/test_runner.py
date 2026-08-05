"""스캔 러너 — -oA 출력 + --resume 명령 생성 + 타겟 검증."""
from pathlib import Path
import subprocess

import pytest
from scanops.scanning import nmap_runner as r


def test_build_command_uses_oA():
    base = Path("/s/scan_1")
    cmd = r.build_command("nmap", "quick", ["127.0.0.1"], base)
    assert "-oA" in cmd and str(base) in cmd
    assert cmd[cmd.index("-oA") + 1] == str(base)
    assert "-oX" not in cmd  # XML 단독 아님 — 3형식 동시(.nmap/.xml/.gnmap)
    assert cmd[-1] == "127.0.0.1"


def test_build_command_includes_stats_every():
    # 진행률 가시성 — 두 빌더 모두 --stats-every 주입(타겟은 항상 마지막).
    base = Path("/s/scan_1")
    cmd = r.build_command("nmap", "quick", ["127.0.0.1"], base)
    assert cmd[cmd.index("--stats-every") + 1] == "10s"
    cmd2 = r.build_command_opts("nmap", ["connect"], "80", ["127.0.0.1"], base)
    assert "--stats-every" in cmd2 and cmd2[-1] == "127.0.0.1"


def test_connect_command_drops_syn_only_rst_ratelimit_flag():
    base = Path("/s/scan_connect")
    connect = r.build_command_opts(
        "nmap", ["connect", "defeat_rst"], "80", ["127.0.0.1"], base,
    )
    syn = r.build_command_opts(
        "nmap", ["syn", "defeat_rst"], "80", ["127.0.0.1"], base,
    )

    assert "-sT" in connect
    assert "--defeat-rst-ratelimit" not in connect
    assert "-sS" in syn
    assert "--defeat-rst-ratelimit" in syn


@pytest.mark.parametrize("preset", ["quick", "phase1"])
def test_explicit_ports_override_preset_port_selection(preset):
    cmd = r.build_command(
        "nmap", preset, ["127.0.0.1"], Path("/s/scan_ports"), ports="443",
    )

    assert cmd.count("-p") == 1
    assert cmd[cmd.index("-p") + 1] == "443"
    assert "--top-ports" not in cmd


@pytest.mark.parametrize("preset", ["quick", "phase1"])
def test_legacy_presets_collect_http_server_identity(preset):
    cmd = r.build_command("nmap", preset, ["127.0.0.1"], Path("/s/scan_server"))
    scripts = cmd[cmd.index("--script") + 1].split(",")
    assert "http-headers" in scripts
    assert "http-server-header" in scripts


def test_manual_nse_omitted_empty_and_selected_are_distinct():
    base = Path("/s/scan_nse")
    omitted = r.build_command("nmap", "quick", ["127.0.0.1"], base)
    disabled = r.build_command("nmap", "quick", ["127.0.0.1"], base, nse=[])
    selected = r.build_command(
        "nmap", "quick", ["127.0.0.1"], base, nse=["ssl-cert"],
    )
    custom_default = r.build_command_opts(
        "nmap", ["connect"], "443", ["127.0.0.1"], base,
    )
    custom_disabled = r.build_command_opts(
        "nmap", ["connect"], "443", ["127.0.0.1"], base, nse=[],
    )

    assert "--script" in omitted
    assert "--script" not in disabled
    assert selected[selected.index("--script") + 1] == "ssl-cert"
    assert "http-server-header" in custom_default[custom_default.index("--script") + 1]
    assert "--script" not in custom_disabled


def test_parse_progress_extracts_percent_and_elapsed(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(
        "Starting Nmap 7.94\n"
        "Stats: 0:01:03 elapsed; 12 hosts completed (3 up), 4 undergoing Service Scan\n"
        "Service scan Timing: About 42.86% done; ETC: 14:30 (0:00:30 remaining)\n",
        encoding="utf-8",
    )
    prog = r.parse_progress(log)
    assert prog["percent"] == 42.86
    assert prog["etc"] == "14:30" and prog["remaining"] == "0:00:30"
    assert prog["elapsed"] == "0:01:03" and prog["hosts_up"] == 3


def test_parse_progress_missing_log_is_safe(tmp_path):
    prog = r.parse_progress(tmp_path / "nope.log")
    assert prog["percent"] is None and "last_line" not in prog


def test_xml_and_log_paths():
    assert str(r.xml_of(Path("/s/scan_9"))).endswith("scan_9.xml")
    assert str(r.normal_log_of(Path("/s/scan_9"))).endswith("scan_9.nmap")


def test_resume_command_is_log_only():
    cmd = r.build_resume_command("nmap", Path("/s/scan_1"))
    # --resume 는 옵션 없이 normal 로그만
    assert cmd == ["nmap", "--resume", str(Path("/s/scan_1.nmap"))]


def test_unknown_preset_rejected():
    with pytest.raises(ValueError):
        r.build_command("nmap", "bogus", ["127.0.0.1"], Path("/s/x"))


@pytest.mark.parametrize("target", ["127.0.0.1; rm -rf /", "-oX/tmp/structured.xml"])
def test_target_validation_blocks_injection(target):
    with pytest.raises(ValueError):
        r.build_command("nmap", "quick", [target], Path("/s/x"))


def test_structured_target_validation_rejects_unsupported_ipv6():
    with pytest.raises(ValueError, match="IPv6"):
        r.build_command("nmap", "quick", ["2001:db8::1"], Path("/s/x"))


@pytest.mark.parametrize(
    "target",
    ["0-255.0-255.0-255.0-255", "10.0-255.0.1", "10-11.0.0.1"],
)
def test_structured_target_validation_rejects_composite_ipv4_range(target):
    with pytest.raises(ValueError, match="지원하지 않는 복합 IP 범위"):
        r.validate_targets([target])


@pytest.mark.parametrize(
    "target",
    ["scan-node.example.internal", "192.0.2.1", "192.0.2.0/24", "192.0.2.1-3"],
)
def test_structured_target_validation_preserves_supported_forms(target):
    assert r.validate_targets([target]) == [target]


@pytest.mark.parametrize("ports", ["99999", "443-22", "22,,80", "T:", "0"])
def test_structured_port_validation_rejects_invalid_semantics(ports):
    with pytest.raises(ValueError):
        r.build_command_opts("nmap", ["connect"], ports, ["127.0.0.1"], Path("/s/x"))


def test_build_with_nse_scripts():
    from pathlib import Path
    cmd = r.build_command_opts("nmap", ["version"], "443", ["10.0.0.1"], Path("/s/x"),
                               nse=["ssl-cert", "http-title"])
    assert "--script" in cmd
    i = cmd.index("--script")
    # 레지스트리 순서로 정렬·중복제거 (http-title 가 ssl-cert 보다 앞)
    assert cmd[i + 1] == "http-title,ssl-cert"


def test_build_rejects_unknown_nse():
    import pytest
    from pathlib import Path
    with pytest.raises(ValueError):
        r.build_command_opts("nmap", ["version"], "", ["10.0.0.1"], Path("/s/x"), nse=["evil-script"])


def test_auto_workflow_builds_staged_commands():
    base = Path("/s/scan_1.b0")
    discovery = r.build_auto_command("nmap", "tcp_discovery", ["127.0.0.1"], Path(str(base) + ".tcp_discovery"))
    identify = r.build_auto_command("nmap", "tcp_identify", ["127.0.0.1"], Path(str(base) + ".tcp_identify"), tcp_ports=[443, 22])
    udp = r.build_auto_command("nmap", "udp_identify", ["127.0.0.1"], Path(str(base) + ".udp_identify"), ports="U:53")

    assert discovery[discovery.index("-p") + 1] == "T:1-65535"
    assert identify[identify.index("-p") + 1] == "T:22,443"
    assert "--script" in identify and "http-title" in identify[identify.index("--script") + 1]
    assert udp[udp.index("-p") + 1] == "U:53"


def test_auto_workflow_can_disable_nse_scripts():
    cmd = r.build_auto_command("nmap", "tcp_identify", ["127.0.0.1"], Path("/s/x"), tcp_ports=[443], nse=[])
    assert "--script" not in cmd


def test_auto_workflow_udp_only_does_not_invent_tcp_ports():
    assert r.auto_tcp_port_spec("U:53") == ""
    assert r.auto_udp_port_spec("U:53") == "U:53"


def test_open_ports_from_xml_for_auto_discovery(tmp_path):
    xml = tmp_path / "d.xml"
    xml.write_text(
        """<nmaprun><host><ports>
        <port protocol="tcp" portid="22"><state state="open"/></port>
        <port protocol="tcp" portid="80"><state state="closed"/></port>
        <port protocol="udp" portid="53"><state state="open"/></port>
        </ports></host></nmaprun>""",
        encoding="utf-8",
    )
    assert r.open_ports_from_xml(xml, "tcp") == [22]
    assert r.open_ports_from_xml(xml, "udp") == [53]


def test_options_endpoint_exposes_nse(client=None):
    from scanops.scanning import scan_options as s
    assert len(s.NSE_SCRIPTS) >= 27
    assert "ssl-cert" in s.NSE_DEFAULT_KEYS
    # phase1 옵션 키가 레지스트리에 모두 존재
    keys = {o["key"] for o in s.SCAN_OPTIONS}
    for k in ["t0", "t1", "t2", "max_retries", "min_hostgroup", "max_parallel", "defeat_rst"]:
        assert k in keys
    assert s.flags_for(["max_retries"]) == ["--max-retries", "2"]


def test_popen_uses_backend_owned_tree_and_closes_parent_log(monkeypatch, tmp_path):
    process = object()
    captured = {}

    def owned_spawn(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["log"] = kwargs["stdout"]
        assert captured["log"].closed is False
        return process

    monkeypatch.setattr(r.process_control, "popen_owned", owned_spawn)

    assert r.popen(["nmap", "-sn", "127.0.0.1"], tmp_path / "nmap.log") is process
    assert captured["cmd"] == ["nmap", "-sn", "127.0.0.1"]
    assert captured["log"].closed is True


def test_wait_owned_preserves_returncode_and_releases_ownership(monkeypatch):
    closed = []

    class Process:
        @staticmethod
        def wait(timeout=None):
            assert timeout == 7
            return 9

    process = Process()
    monkeypatch.setattr(r.process_control, "close_owned", closed.append)

    assert r.wait_owned(process, timeout=7) == 9
    assert closed == [process]


def test_wait_owned_preserves_timeout_and_releases_ownership(monkeypatch):
    closed = []

    class Process:
        @staticmethod
        def wait(timeout=None):
            raise subprocess.TimeoutExpired("nmap", timeout)

    process = Process()
    monkeypatch.setattr(r.process_control, "close_owned", closed.append)

    with pytest.raises(subprocess.TimeoutExpired):
        r.wait_owned(process, timeout=1)
    assert closed == [process]
