"""스캔 허용 대역(scope) 게이트 — 범위 밖 타겟은 시작 전에 거절, 미설정 시 무제한."""
import pytest

from scanops.scanning.scope import check_scope, parse_scope


def test_no_scope_allows_everything():
    # spec 이 비면 어떤 타겟도 통과(하위호환)
    check_scope(["8.8.8.8", "1.2.3.4", "example.com"], spec="")


def test_in_scope_passes():
    check_scope(["10.0.12.5", "10.255.0.1"], spec="10.0.0.0/8")


def test_out_of_scope_rejected():
    with pytest.raises(ValueError) as e:
        check_scope(["10.0.0.1", "192.168.1.1"], spec="10.0.0.0/8")
    assert "192.168.1.1" in str(e.value)


def test_hostname_rejected_when_scope_set():
    # IP 가 아닌 토큰은 CIDR 검증 불가 → scope 모드에선 거절
    with pytest.raises(ValueError):
        check_scope(["scanme.example.com"], spec="10.0.0.0/8")


def test_parse_scope_skips_garbage():
    nets = parse_scope("10.0.0.0/8, not-an-ip 192.168.0.0/16")
    assert len(nets) == 2


def test_multiple_scope_ranges():
    check_scope(["10.0.0.1", "192.168.1.1"], spec="10.0.0.0/8 192.168.0.0/16")
