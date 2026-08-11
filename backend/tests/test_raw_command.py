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


def test_build_records_only_scan_targets_not_inline_exclude_values():
    _argv, ips = build_command_raw(
        "nmap",
        "nmap -sV --exclude 203.0.113.9 10.0.0.1",
        Path("/s/scan_exclude"),
    )

    assert ips == ["10.0.0.1"]


def test_build_strips_user_output_flags():
    # 사용자가 준 -oX/-oN 등은 제거(경로 traversal·형식 충돌 방지)되고 -oA 만 남는다.
    argv, _ = build_command_raw("nmap", "-sS -oX /etc/passwd -oN out.txt 10.0.0.1", Path("/s/scan_2"))
    assert "/etc/passwd" not in argv and "out.txt" not in argv
    assert "-oX" not in argv and "-oN" not in argv
    assert argv.count("-oA") == 1


@pytest.mark.parametrize("flag", [
    "-oX/tmp/escaped.xml", "-oNout.txt", "-oG=out.gnmap", "-oSout.script", "-oAbase",
])
def test_build_strips_compact_user_output_flags(flag):
    argv, _ = build_command_raw("nmap", f"-sV {flag} --append-output 10.0.0.1", Path("/s/scan_2"))
    assert flag not in argv
    assert "--append-output" not in argv
    assert argv.count("-oA") == 1


@pytest.mark.parametrize("resume", ["--resume old.nmap", "--resume=old.nmap"])
def test_build_rejects_user_resume(resume):
    with pytest.raises(ValueError, match="--resume"):
        build_command_raw("nmap", f"{resume} 10.0.0.1", Path("/s/scan_2"))


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


def test_raw_command_merges_structured_and_inline_excludes_into_one_option():
    """직접 명령 모드에서도 구조화 제외가 적용되고, 인라인 --exclude 와 하나로 합쳐진다.

    Nmap 은 --exclude 를 반복하면 마지막 값만 쓰므로 두 개를 그대로 두면 한쪽이 조용히 사라진다.
    예전에는 이 경로가 구조화 제외를 아예 버려, 폼에 제외를 입력한 뒤 '명령 직접 입력'으로
    바꾸면 제외 없이 스캔이 나갔다."""
    from scanops.api.scans import _merge_raw_excludes

    argv = ["nmap", "--exclude", "10.0.0.5", "-sV", "-oA", "base"]
    merged = _merge_raw_excludes(argv, ["10.0.0.7", "10.0.0.20-30"])

    assert merged.count("--exclude") == 1
    values = merged[merged.index("--exclude") + 1].split(",")
    assert set(values) == {"10.0.0.5", "10.0.0.7", "10.0.0.20-30"}
    assert merged[-2:] == ["-oA", "base"]  # 서버가 강제한 출력 경로는 그대로 마지막에


def test_raw_command_merges_attached_exclude_form():
    from scanops.api.scans import _merge_raw_excludes

    merged = _merge_raw_excludes(
        ["nmap", "--exclude=10.0.0.5,10.0.0.6", "-sV", "-oA", "base"], ["10.0.0.7"])

    assert merged.count("--exclude") == 1
    assert not any(t.startswith("--exclude=") for t in merged)
    assert set(merged[merged.index("--exclude") + 1].split(",")) == {
        "10.0.0.5", "10.0.0.6", "10.0.0.7"}


def test_raw_command_without_any_exclude_is_unchanged():
    from scanops.api.scans import _merge_raw_excludes

    argv = ["nmap", "-sV", "-oA", "base", "10.0.0.1"]
    assert _merge_raw_excludes(argv, []) == argv
    assert _merge_raw_excludes(argv, None) == argv


def test_raw_command_rejects_invalid_structured_exclude():
    from scanops.api.scans import _merge_raw_excludes

    with pytest.raises(ValueError):
        _merge_raw_excludes(["nmap", "-sV", "-oA", "base"], ["not-an-ip"])


def test_nmap_exclusions_add_port_filter_once():
    """포트 제외는 -p 를 건드리지 않는 전역 필터라 명령 앞에 한 번만 붙는다."""
    from scanops.api.scans import _with_nmap_excludes

    argv = _with_nmap_excludes(
        ["nmap", "-sS", "-p", "T:1-65535", "-oA", "b", "10.0.0.0/24"],
        ["10.0.0.1-10"], "3030,3040")

    assert argv.count("--exclude-ports") == 1
    assert argv[argv.index("--exclude-ports") + 1] == "3030,3040"
    assert argv[argv.index("--exclude") + 1] == "10.0.0.1-10"
    # 포트 선택(-p)은 그대로 유지된다.
    assert argv[argv.index("-p") + 1] == "T:1-65535"
