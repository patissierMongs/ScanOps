"""청킹 — 타겟 확장 / 배치 분할 / 사이드카 상태."""
from pathlib import Path

import pytest
from scanops.scanning import chunker as ch


def test_expand_cidr_includes_all_addresses():
    hosts = ch.expand_targets(["10.0.12.0/29"])  # /29 = 8 주소(.0~.7 전수)
    assert hosts == [f"10.0.12.{i}" for i in range(8)]


def test_expand_octet_range():
    assert ch.expand_targets(["10.0.12.5-8"]) == ["10.0.12.5", "10.0.12.6", "10.0.12.7", "10.0.12.8"]


@pytest.mark.parametrize(
    "target",
    ["0-255.0-255.0-255.0-255", "10.0-255.0.1", "10-11.0.0.1"],
)
def test_expand_composite_ipv4_range_fails_closed(target):
    with pytest.raises(ValueError, match="지원하지 않는 복합 IP 범위"):
        ch.expand_targets([target])


def test_expand_hyphenated_hostname_passthrough():
    assert ch.expand_targets(["scan-node.example.internal"]) == ["scan-node.example.internal"]


@pytest.mark.parametrize("target", ["10.999.12.5-8", "256.0.0.1-2", "10.0.0.9-3", "10.0.0.1-256"])
def test_expand_invalid_octet_range_fails_closed(target):
    with pytest.raises(ValueError, match="잘못된 IP 범위"):
        ch.expand_targets([target])


def test_expand_octet_range_checks_cap_before_materializing():
    with pytest.raises(ValueError, match="대상 호스트가 너무 많습니다"):
        ch.expand_targets(["10.0.0.1-10"], cap=5)


def test_expand_mixed_and_hostname_passthrough():
    hosts = ch.expand_targets(["10.0.0.0/30", "host.local", "10.0.1.1"])
    assert hosts == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "host.local", "10.0.1.1"]


def test_expand_cap_exceeded():
    with pytest.raises(ValueError):
        ch.expand_targets(["10.0.0.0/8"], cap=1000)


def test_expand_invalid_cidr_fails_closed():
    with pytest.raises(ValueError, match="잘못된 CIDR"):
        ch.expand_targets(["10.0.0.0/999"])


def test_make_batches():
    hosts = [f"10.0.0.{i}" for i in range(5)]
    assert ch.make_batches(hosts, 2) == [["10.0.0.0", "10.0.0.1"], ["10.0.0.2", "10.0.0.3"], ["10.0.0.4"]]


def test_sidecar_roundtrip(tmp_path):
    base = tmp_path / "scan_1"
    state = {"batches": [["a"], ["b"]], "cursor": 1, "stop": False, "options": ["connect"]}
    ch.write_state(base, state)
    assert ch.read_state(base) == state
    assert ch.read_state(tmp_path / "missing") is None


def test_stop_sentinel_survives_worker_stale_state_write_until_resume(tmp_path):
    base = tmp_path / "scan_2"
    ch.write_state(base, {"batches": [["a"], ["b"]], "cursor": 0, "stop": False})
    stale_worker_state = ch.read_state(base)

    ch.request_stop(base)
    stale_worker_state["cursor"] = 1
    stale_worker_state["stop"] = False
    ch.write_state(base, stale_worker_state)

    assert ch.stop_requested(base) is True
    ch.clear_stop(base)
    assert ch.stop_requested(base) is False
