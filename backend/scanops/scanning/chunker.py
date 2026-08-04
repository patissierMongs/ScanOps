"""대역 청킹 — 넓은 타겟을 호스트 배치로 쪼개 '배치 단위' 스캔/중지/이어가기.

native `nmap --resume` 가 Windows 에서 자기 로그 파싱에 실패해 못 쓰므로, 이어가기를
배치 단위로 직접 구현한다. 각 배치는 정상 nmap 실행 → 유효한 XML → 즉시 인입되고,
배치 진행상태(커서/중지요청/옵션)는 DB 마이그레이션 없이 사이드카 JSON 으로 영속한다.
중지하면 진행 중이던 배치 하나만 버리고(커서 유지) 이어가기 때 그 배치부터 재실행한다.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
from pathlib import Path

# 마지막 옥텟 범위(예: 10.0.12.1-50) — 이 단순 케이스만 안전하게 직접 확장한다.
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_IPV4_RANGE_TOKEN_RE = re.compile(r"^[\d-]+(?:\.[\d-]+){3}$")


def is_unsupported_composite_ipv4_range(target: str) -> bool:
    """숫자 옥텟의 Nmap 복합 범위 중 마지막 옥텟 단순 범위가 아닌 형식인지 반환."""
    return bool(
        "-" in target
        and _IPV4_RANGE_TOKEN_RE.fullmatch(target)
        and not _RANGE_RE.fullmatch(target)
    )


def expand_targets(targets: list[str], cap: int = 65536) -> list[str]:
    """타겟 스펙을 개별 호스트 문자열로 확장. CIDR·단순 옥텟범위는 펼치고,
    호스트명은 그대로 한 토큰으로 둔다(배치 1개). 복합 IPv4 범위와 cap 초과는 거부한다."""
    hosts: list[str] = []
    for raw in targets:
        t = raw.strip()
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError as exc:
                raise ValueError(f"잘못된 CIDR: {t}") from exc
            if len(hosts) + net.num_addresses > cap:
                raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}). 대역을 줄여 주세요.")
            hosts.extend(str(ip) for ip in net)   # 네트워크/브로드캐스트 포함(대역 전수)
        elif (m := _RANGE_RE.match(t)):
            base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            base_octets = [int(part) for part in base.split(".")]
            if any(part > 255 for part in base_octets) or lo > hi or hi > 255:
                raise ValueError(f"잘못된 IP 범위: {t}")
            if len(hosts) + (hi - lo + 1) > cap:
                raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}). 대역을 줄여 주세요.")
            hosts.extend(f"{base}.{i}" for i in range(lo, hi + 1))
        elif is_unsupported_composite_ipv4_range(t):
            raise ValueError(f"지원하지 않는 복합 IP 범위: {t}. 마지막 옥텟 범위만 사용할 수 있습니다.")
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


def stop_path(basename: Path) -> Path:
    return Path(str(basename) + ".stop-requested")


def write_state(basename: Path, state: dict) -> None:
    path = sidecar_path(basename)
    temp = Path(f"{path}.{os.getpid()}.{threading.get_ident()}.tmp")
    temp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


def request_stop(basename: Path) -> None:
    """중지 요청을 JSON과 분리한 단조 센티넬로 남긴다.

    worker가 오래된 state를 다시 저장해도 이 파일은 resume만 지우므로 중지가 유실되지 않는다.
    """
    path = stop_path(basename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def clear_stop(basename: Path) -> None:
    stop_path(basename).unlink(missing_ok=True)


def stop_requested(basename: Path) -> bool:
    if stop_path(basename).exists():
        return True
    # 구형 sidecar의 stop=true도 이어받는다.
    return bool((read_state(basename) or {}).get("stop"))


def read_state(basename: Path) -> dict | None:
    p = sidecar_path(basename)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
