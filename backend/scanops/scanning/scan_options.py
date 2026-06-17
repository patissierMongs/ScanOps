"""스캔 옵션 화이트리스트 — 클라이언트는 옵션 '키'만 보내고 서버가 플래그로 변환.

임의 nmap 플래그를 받지 않는다(명령 주입/위험옵션 차단). UI 는 이 레지스트리를
받아 토글을 그리고 명령을 실시간 조립하며, 서버는 동일 레지스트리로 검증·조립한다.
"""
from __future__ import annotations

import re

# key, label(UI), flags(실제), group, default(기본선택), note
SCAN_OPTIONS = [
    {"key": "syn", "label": "TCP SYN 스캔 (-sS)", "flags": ["-sS"], "group": "스캔 기법", "default": False, "note": "관리자 권한 필요"},
    {"key": "connect", "label": "TCP Connect (-sT)", "flags": ["-sT"], "group": "스캔 기법", "default": False, "note": "권한 불필요"},
    {"key": "udp", "label": "UDP 스캔 (-sU)", "flags": ["-sU"], "group": "스캔 기법", "default": False, "note": "느림"},
    {"key": "version", "label": "서비스·버전 탐지 (-sV)", "flags": ["-sV"], "group": "탐지", "default": True, "note": "서비스 식별"},
    {"key": "scripts", "label": "기본 NSE 스크립트 (-sC)", "flags": ["-sC"], "group": "탐지", "default": False, "note": "배너·근거 보강"},
    {"key": "os", "label": "OS 탐지 (-O)", "flags": ["-O"], "group": "탐지", "default": False, "note": "관리자 권한 필요"},
    {"key": "noping", "label": "핑 생략 (-Pn)", "flags": ["-Pn"], "group": "제어", "default": True, "note": "방화벽 우회"},
    {"key": "fast", "label": "빠른 타이밍 (-T4)", "flags": ["-T4"], "group": "제어", "default": True, "note": "속도↑"},
]

_BY_KEY = {o["key"]: o for o in SCAN_OPTIONS}
DEFAULT_KEYS = [o["key"] for o in SCAN_OPTIONS if o["default"]]

# 포트 스펙: 숫자/범위/콤마 + T:/U: 프로토콜 접두만 허용
_PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]+$")


def validate_keys(keys: list[str]) -> list[str]:
    bad = [k for k in keys if k not in _BY_KEY]
    if bad:
        raise ValueError(f"알 수 없는 스캔 옵션: {bad}")
    return keys


def flags_for(keys: list[str]) -> list[str]:
    """레지스트리 순서대로 플래그 조립(결정적)."""
    out: list[str] = []
    sel = set(keys)
    for o in SCAN_OPTIONS:
        if o["key"] in sel:
            out.extend(o["flags"])
    return out


def validate_ports(ports: str) -> str:
    ports = (ports or "").strip()
    if not ports:
        return ""
    if not _PORTS_RE.match(ports):
        raise ValueError("허용되지 않는 포트 형식입니다. (예: 22,80,443 또는 1-1024)")
    return ports.replace(" ", "")
