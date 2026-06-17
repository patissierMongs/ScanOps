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


def test_options_endpoint_exposes_nse(client=None):
    from scanops.scanning import scan_options as s
    assert len(s.NSE_SCRIPTS) >= 27
    assert "ssl-cert" in s.NSE_DEFAULT_KEYS
    # phase1 옵션 키가 레지스트리에 모두 존재
    keys = {o["key"] for o in s.SCAN_OPTIONS}
    for k in ["t0", "t1", "t2", "max_retries", "min_hostgroup", "max_parallel", "defeat_rst"]:
        assert k in keys
