"""대역 청킹 — 넓은 타겟을 호스트 배치로 쪼개 '배치 단위' 스캔/중지/이어가기.

native `nmap --resume` 가 Windows 에서 자기 로그 파싱에 실패해 못 쓰므로, 이어가기를
배치 단위로 직접 구현한다. 각 배치는 정상 nmap 실행 → 유효한 XML → 즉시 인입되고,
배치 진행상태(커서/중지요청/옵션)는 DB 마이그레이션 없이 사이드카 JSON 으로 영속한다.
중지하면 진행 중이던 배치 하나만 버리고(커서 유지) 이어가기 때 그 배치부터 재실행한다.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

# 마지막 옥텟 범위(예: 10.0.12.1-50) — 단순 케이스만 직접 확장, 나머지 nmap 문법은 단일 토큰.
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")


def expand_targets(targets: list[str], cap: int = 65536) -> list[str]:
    """타겟 스펙을 개별 호스트 문자열로 확장. CIDR·단순 옥텟범위는 펼치고,
    호스트명/복합 nmap 문법은 그대로 한 토큰으로 둔다(배치 1개). cap 초과 시 ValueError."""
    hosts: list[str] = []
    for raw in targets:
        t = raw.strip()
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                hosts.append(t)
            else:
                hosts.extend(str(ip) for ip in net)   # 네트워크/브로드캐스트 포함(대역 전수)
        elif (m := _RANGE_RE.match(t)):
            base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            if lo > hi or hi > 255:
                raise ValueError(f"잘못된 IP 범위: {t}")
            hosts.extend(f"{base}.{i}" for i in range(lo, hi + 1))
        else:
            hosts.append(t)
        if len(hosts) > cap:
            raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}). 대역을 줄여 주세요.")
    return hosts


def make_batches(hosts: list[str], size: int) -> list[list[str]]:
    size = max(1, size)
    return [hosts[i:i + size] for i in range(0, len(hosts), size)]


def sidecar_path(basename: Path) -> Path:
    return Path(str(basename) + ".chunks.json")


def write_state(basename: Path, state: dict) -> None:
    sidecar_path(basename).write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def read_state(basename: Path) -> dict | None:
    p = sidecar_path(basename)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
