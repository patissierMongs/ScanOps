"""스캔 허용 대역(scope) 게이트 — 설정된 CIDR/IP 범위 밖 타겟을 시작 전에 거절.

네트워크 스캐너는 그 자체로 민감 도구다. 오타 한 번(10.0 → 100.0)이나 잘못 붙여넣은
대역이 사외·타조직을 스캔하는 사고로 이어진다. scope 가 설정돼 있으면(설정 비면 무제한,
하위호환) 확장된 호스트 전부가 허용 대역 안에 드는지 검증하고, 하나라도 벗어나면
ValueError 로 막는다. IP 가 아닌 토큰(호스트명 등)은 CIDR 로 검증 불가하므로 거절한다.
"""
from __future__ import annotations

import ipaddress

from ..config import get_settings


def parse_scope(spec: str) -> list[ipaddress._BaseNetwork]:
    """콤마/공백 구분 CIDR·IP 목록을 네트워크 객체로. 잘못된 토큰은 조용히 건너뛴다."""
    nets: list[ipaddress._BaseNetwork] = []
    for raw in (spec or "").replace(",", " ").split():
        t = raw.strip()
        if not t:
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            continue
    return nets


def is_ip_token(token: str) -> bool:
    """토큰이 IP 또는 CIDR 인지. 호스트명/복합 nmap 문법은 False."""
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _in_scope(host: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    # 단일 IP 는 멤버십, CIDR 토큰은 허용망의 서브넷인지로 판정.
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(host, strict=False)
        return any(net.version == n.version and net.subnet_of(n) for n in nets)
    except ValueError:
        return False  # IP/CIDR 가 아니면(호스트명/복합문법) 범위 검증 불가 → scope 모드에선 불허


def check_scope(hosts: list[str], spec: str | None = None) -> None:
    """허용 대역이 설정돼 있으면 모든 host 가 그 안에 드는지 검증. 비면 무제한(통과).

    범위 밖 호스트가 있으면 ValueError(처음 몇 개를 메시지에 노출). 비-IP 토큰도 거절."""
    if spec is None:
        spec = get_settings().scan_scope
    nets = parse_scope(spec)
    if not nets:
        return  # scope 미설정 — 제한 없음
    bad = [h for h in hosts if not _in_scope(h, nets)]
    if bad:
        shown = ", ".join(bad[:5]) + (f" 외 {len(bad) - 5}건" if len(bad) > 5 else "")
        raise ValueError(f"허용된 스캔 대역(scope) 밖의 대상입니다: {shown}")


# 직접 명령에서 타겟이 아닌 파일/랜덤 입력 — scope 검증을 우회하므로 scope 설정 시 차단.
_UNSCOPED_TARGET_FLAGS = ("-iL", "-iR", "--excludefile", "--exclude-file")


def check_raw_scope(tokens: list[str], spec: str | None = None) -> None:
    """직접 입력 명령용 scope 게이트. spec 비면 통과(무제한).

    scope 설정 시: 파일/랜덤 타겟 플래그(-iL/-iR 등) 차단, IP/CIDR 타겟이 최소 1개 있어야 하고,
    IP/CIDR 타겟은 전부 허용 대역 안이어야 한다. (호스트명만 있는 명령은 검증 불가 → 거절)"""
    if spec is None:
        spec = get_settings().scan_scope
    nets = parse_scope(spec)
    if not nets:
        return  # scope 미설정 — 제한 없음
    if any(t in _UNSCOPED_TARGET_FLAGS for t in tokens):
        raise ValueError(
            "스캔 대역(scope)이 설정된 환경에서는 직접 명령에서 파일/랜덤 타겟(-iL/-iR 등)을 쓸 수 없습니다. "
            "IP/CIDR 로 직접 지정하세요.")
    ip_tokens = [t for t in tokens if is_ip_token(t)]
    if not ip_tokens:
        raise ValueError("스캔 대역(scope)이 설정된 환경에서는 직접 명령에 IP/CIDR 타겟을 명시해야 합니다.")
    check_scope(ip_tokens, spec)
