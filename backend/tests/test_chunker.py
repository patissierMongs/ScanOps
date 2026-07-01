"""청킹 — 타겟 확장 / 배치 분할 / 사이드카 상태."""

import pytest

from scanops.scanning import chunker as ch


def test_expand_cidr_includes_all_addresses():
    hosts = ch.expand_targets(["10.0.12.0/29"])  # /29 = 8 주소(.0~.7 전수)
    assert hosts == [f"10.0.12.{i}" for i in range(8)]


def test_expand_octet_range():
    assert ch.expand_targets(["10.0.12.5-8"]) == ["10.0.12.5", "10.0.12.6", "10.0.12.7", "10.0.12.8"]


def test_expand_mixed_and_hostname_passthrough():
    hosts = ch.expand_targets(["10.0.0.0/30", "host.local", "10.0.1.1"])
    assert hosts == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "host.local", "10.0.1.1"]


def test_expand_cap_exceeded():
    with pytest.raises(ValueError):
        ch.expand_targets(["10.0.0.0/8"], cap=1000)


def test_make_batches():
    hosts = [f"10.0.0.{i}" for i in range(5)]
    assert ch.make_batches(hosts, 2) == [["10.0.0.0", "10.0.0.1"], ["10.0.0.2", "10.0.0.3"], ["10.0.0.4"]]


def test_sidecar_roundtrip(tmp_path):
    base = tmp_path / "scan_1"
    state = {"batches": [["a"], ["b"]], "cursor": 1, "stop": False, "options": ["connect"]}
    ch.write_state(base, state)
    assert ch.read_state(base) == state
    assert ch.read_state(tmp_path / "missing") is None
