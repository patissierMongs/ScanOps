"""직접 명령 입력 — 파싱/검증/출력플래그 강제 교체 + scope CIDR 판정."""
from pathlib import Path

import pytest

from scanops.scanning.nmap_runner import build_command_raw, parse_raw_command
from scanops.scanning.scope import check_scope


def test_parse_strips_leading_nmap():
    assert parse_raw_command("nmap -sV 10.0.0.1") == ["-sV", "10.0.0.1"]
    assert parse_raw_command("-sV 10.0.0.1") == ["-sV", "10.0.0.1"]


def test_build_injects_stats_and_oa():
    argv, ips = build_command_raw("nmap", "nmap -sV -p 22,80 10.0.0.0/24", Path("/s/scan_1"))
    assert argv[0] == "nmap"
    assert "--stats-every" in argv
    assert argv[-2] == "-oA" and argv[-1] == str(Path("/s/scan_1"))
    assert ips == ["10.0.0.0/24"]


def test_build_strips_user_output_flags():
    # 사용자가 준 -oX/-oN 등은 제거(경로 traversal·형식 충돌 방지)되고 -oA 만 남는다.
    argv, _ = build_command_raw("nmap", "-sS -oX /etc/passwd -oN out.txt 10.0.0.1", Path("/s/scan_2"))
    assert "/etc/passwd" not in argv and "out.txt" not in argv
    assert "-oX" not in argv and "-oN" not in argv
    assert argv.count("-oA") == 1


def test_build_rejects_shell_metachars():
    for bad in ["nmap 10.0.0.1; rm -rf /", "nmap 10.0.0.1 | nc x 1", "nmap `id`", "nmap $(whoami)"]:
        with pytest.raises(ValueError):
            build_command_raw("nmap", bad, Path("/s/x"))


def test_build_rejects_empty():
    with pytest.raises(ValueError):
        build_command_raw("nmap", "nmap", Path("/s/x"))


def test_does_not_double_inject_stats():
    argv, _ = build_command_raw("nmap", "-sV --stats-every 2s 10.0.0.1", Path("/s/scan_3"))
    assert argv.count("--stats-every") == 1


def test_scope_accepts_cidr_subnet():
    check_scope(["10.0.12.0/24"], spec="10.0.0.0/8")     # 서브넷 → 통과


def test_scope_rejects_cidr_outside():
    with pytest.raises(ValueError):
        check_scope(["172.16.0.0/16"], spec="10.0.0.0/8")
