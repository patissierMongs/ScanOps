"""스캔 러너 — -oA 출력 + --resume 명령 생성 + 타겟 검증."""
from pathlib import Path

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
    assert prog["percent"] is None and prog["last_line"] == ""


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


def test_slow_preset_is_gentle_full_port_syn():
    # 느린 프리셋: 전 65535 TCP 커버리지 + 저동시성(병렬 5)·참을성 RTT. 관리자 권한(-sS) 전제.
    cmd = r.build_command("nmap", "slow", ["10.0.0.0/24"], Path("/s/scan_1"), admin=True)
    assert "-sS" in cmd
    assert cmd[cmd.index("-p") + 1] == "T:1-65535"
    assert cmd[cmd.index("--max-parallelism") + 1] == "5"
    assert cmd[cmd.index("--max-rtt-timeout") + 1] == "1000ms"
    assert cmd[cmd.index("--max-retries") + 1] == "6"
    assert cmd[-1] == "10.0.0.0/24"


def test_apply_privilege_downgrades_syn_to_connect_and_strips_udp():
    # 비특권: -sS→-sT(중복 없이), -sU/-O 제거, -p 의 U: 포트도 제거(nmap fatal 방지).
    flags = r.apply_privilege(["-sS", "-sU", "-O", "-sV", "-p", "T:22,U:53"], admin=False)
    assert "-sT" in flags and "-sS" not in flags
    assert "-sU" not in flags and "-O" not in flags
    assert flags[flags.index("-p") + 1] == "T:22"       # U:53 제거, T:22 유지
    # 관리자면 원본 그대로.
    assert r.apply_privilege(["-sS", "-sU"], admin=True) == ["-sS", "-sU"]


def test_apply_privilege_drops_port_when_tcp_empty():
    # UDP 전용 포트만 있으면 비특권 강등 후 -p 를 통째로 제거(nmap 기본 TCP 로).
    flags = r.apply_privilege(["-sU", "-p", "U:53,161"], admin=False)
    assert "-p" not in flags and "U:53" not in " ".join(flags)


def test_build_command_opts_drops_version_all_with_udp():
    # udp + version_all 공존 → version_all 드롭(단일 실행 UDP 강도9 fatal 방지). WYSIWYG 대상.
    cmd = r.build_command_opts("nmap", ["syn", "udp", "version", "version_all"],
                               "T:1-65535,U:53", ["127.0.0.1"], Path("/s/x"), admin=True)
    assert "--version-all" not in cmd
    assert "-sV" in cmd and "-sU" in cmd and "-sS" in cmd


def test_build_command_opts_keeps_version_all_without_udp():
    cmd = r.build_command_opts("nmap", ["syn", "version", "version_all"],
                               "T:1-65535", ["127.0.0.1"], Path("/s/x"), admin=True)
    assert "--version-all" in cmd


def test_build_command_opts_unprivileged_connect_no_udp():
    # 비특권 단일 실행: -sT 강등, -sU 제거, U: 포트 스트립.
    cmd = r.build_command_opts("nmap", ["syn", "udp", "version"],
                               "T:1-65535,U:53", ["127.0.0.1"], Path("/s/x"), admin=False)
    assert "-sT" in cmd and "-sS" not in cmd and "-sU" not in cmd
    assert cmd[cmd.index("-p") + 1] == "T:1-65535"


def test_target_validation_blocks_injection():
    with pytest.raises(ValueError):
        r.build_command("nmap", "quick", ["127.0.0.1; rm -rf /"], Path("/s/x"))


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
