"""스캔 옵션 화이트리스트 — 클라이언트는 옵션 '키'만 보내고 서버가 플래그로 변환.

임의 nmap 플래그를 받지 않는다(명령 주입/위험옵션 차단). UI 는 이 레지스트리를
받아 토글을 그리고 명령을 실시간 조립하며, 서버는 동일 레지스트리로 검증·조립한다.
"""
from __future__ import annotations

import re

# key, label(UI), flags(실제), group, default(기본선택), note(짧은 경고), desc(설명)
# nmap 명령어 생성기 — 토글 가능한 안전한 고정 플래그만(값 입력이 필요한 위험 옵션 제외).
# UI 는 desc 를 펼쳐 보여주고, 서버는 이 레지스트리로 키를 검증·조립한다.
SCAN_OPTIONS = [
    # ── 스캔 기법 (보통 하나, UDP 는 TCP 와 함께 가능) ──
    {"key": "syn", "label": "TCP SYN 스캔 (-sS)", "flags": ["-sS"], "group": "스캔 기법", "default": False,
     "note": "관리자 권한", "desc": "가장 일반적인 '반열림' 스캔. 연결을 끝까지 맺지 않아 빠르고 흔적이 적다. raw 소켓이 필요해 관리자 권한이 있어야 한다."},
    {"key": "connect", "label": "TCP Connect 스캔 (-sT)", "flags": ["-sT"], "group": "스캔 기법", "default": False,
     "desc": "OS 의 connect() 로 완전한 TCP 연결을 맺는다. 권한이 없을 때의 기본. 대상 로그에 연결 기록이 남는다."},
    {"key": "udp", "label": "UDP 스캔 (-sU)", "flags": ["-sU"], "group": "스캔 기법", "default": False,
     "note": "느림", "desc": "DNS·SNMP·DHCP 같은 UDP 서비스를 점검. 응답이 느려 시간이 오래 걸리니 포트를 좁혀 쓰는 게 좋다."},
    {"key": "ack", "label": "TCP ACK 스캔 (-sA)", "flags": ["-sA"], "group": "스캔 기법", "default": False,
     "desc": "포트 개폐가 아니라 방화벽 필터링 여부를 매핑한다. '어떤 포트가 방화벽에 막혀 있나'를 볼 때."},
    {"key": "fin", "label": "FIN 스캔 (-sF)", "flags": ["-sF"], "group": "스캔 기법", "default": False,
     "desc": "FIN 패킷만 보내는 스텔스 기법. 단순 패킷필터를 우회할 수 있으나 최신 Windows 에는 잘 안 통한다."},
    {"key": "null", "label": "NULL 스캔 (-sN)", "flags": ["-sN"], "group": "스캔 기법", "default": False,
     "desc": "플래그가 전혀 없는 패킷으로 점검하는 스텔스 기법. Windows 대상에는 부정확하다."},
    {"key": "xmas", "label": "Xmas 스캔 (-sX)", "flags": ["-sX"], "group": "스캔 기법", "default": False,
     "desc": "FIN·PSH·URG 를 동시에 켠 패킷. 방화벽/IDS 의 반응을 관찰하는 스텔스 기법."},

    # ── 호스트 발견 ──
    {"key": "noping", "label": "핑 생략 (-Pn)", "flags": ["-Pn"], "group": "호스트 발견", "default": True,
     "desc": "ICMP 를 막는 호스트도 살아있다고 보고 바로 포트 스캔. 사내 방화벽 환경에서 호스트 누락을 막는다."},
    {"key": "ping_only", "label": "호스트만 탐지 (-sn)", "flags": ["-sn"], "group": "호스트 발견", "default": False,
     "note": "포트스캔과 배타", "desc": "포트 스캔 없이 '어떤 IP 가 살아있나'만 빠르게(핑 스윕). 자산 인벤토리 점검용. 포트 스캔 옵션과 함께 쓰지 말 것."},
    {"key": "dns_no", "label": "역DNS 생략 (-n)", "flags": ["-n"], "group": "호스트 발견", "default": False,
     "desc": "IP→이름 역질의를 건너뛰어 속도를 높인다. 대량 대역 스캔에서 유용."},

    # ── 탐지 ──
    {"key": "version", "label": "서비스·버전 탐지 (-sV)", "flags": ["-sV"], "group": "탐지", "default": True,
     "desc": "열린 포트에 프로브를 보내 서비스 종류와 버전을 식별. ScanOps 분류·위험등급의 핵심 입력이다."},
    {"key": "version_light", "label": "버전 탐지·가볍게 (--version-light)", "flags": ["--version-light"], "group": "탐지", "default": False,
     "desc": "-sV 를 빠른 프로브만으로. 정확도는 조금 낮지만 시간을 크게 줄인다."},
    {"key": "version_all", "label": "버전 탐지·전수 (--version-all)", "flags": ["--version-all"], "group": "탐지", "default": False,
     "note": "느림", "desc": "모든 프로브를 시도해 최대한 정확하게. 그만큼 느리다."},
    {"key": "scripts", "label": "기본 NSE 스크립트 (-sC)", "flags": ["-sC"], "group": "탐지", "default": False,
     "desc": "안전한 기본 스크립트 묶음 실행(인증서·SMB·HTTP 헤더 등). ScanOps 의 NSE 추출(TLS_CN/SMB_OS 등)을 채운다."},
    {"key": "os", "label": "OS 탐지 (-O)", "flags": ["-O"], "group": "탐지", "default": False,
     "note": "관리자 권한", "desc": "TCP/IP 스택 지문으로 운영체제를 추정한다. raw 소켓 권한이 필요하다."},
    {"key": "traceroute", "label": "경로 추적 (--traceroute)", "flags": ["--traceroute"], "group": "탐지", "default": False,
     "desc": "대상까지의 네트워크 경로(홉)를 기록. 세그먼트·경계 파악에 도움."},
    {"key": "aggressive", "label": "종합 탐지 (-A)", "flags": ["-A"], "group": "탐지", "default": False,
     "note": "무겁다", "desc": "-O·-sV·-sC·--traceroute 를 한 번에. 가장 풍부하지만 가장 느리고 흔적이 많다."},

    # ── 결과 표시 ──
    {"key": "open_only", "label": "열린 포트만 (--open)", "flags": ["--open"], "group": "결과 표시", "default": False,
     "desc": "closed/filtered 는 빼고 열린 포트만 출력해 결과를 깔끔하게."},
    {"key": "reason", "label": "판단 근거 (--reason)", "flags": ["--reason"], "group": "결과 표시", "default": False,
     "desc": "각 포트 상태를 왜 그렇게 판정했는지(예: syn-ack)를 기록. 감사·디버깅용."},
    {"key": "verbose", "label": "상세 로그 (-v)", "flags": ["-v"], "group": "결과 표시", "default": False,
     "desc": "진행 로그를 더 자세히 출력. 큰 스캔의 진행 파악에 유용."},

    # ── 타이밍 (하나만 선택) ──
    {"key": "t3", "label": "표준 타이밍 (-T3)", "flags": ["-T3"], "group": "타이밍 (택1)", "default": False,
     "desc": "nmap 기본 속도. 안정적이고 무난하다."},
    {"key": "fast", "label": "빠른 타이밍 (-T4)", "flags": ["-T4"], "group": "타이밍 (택1)", "default": True,
     "desc": "사내망에 권장. 속도와 정확도의 균형."},
    {"key": "t5", "label": "매우 빠름 (-T5)", "flags": ["-T5"], "group": "타이밍 (택1)", "default": False,
     "note": "누락 위험", "desc": "최대 속도. 혼잡하거나 느린 망에서는 결과가 누락될 수 있다."},

    # ── 방화벽 진단 ──
    {"key": "fragment", "label": "패킷 분할 (-f)", "flags": ["-f"], "group": "방화벽 진단", "default": False,
     "desc": "패킷을 잘게 쪼개 단순 패킷필터의 차단/탐지를 시험한다. 방화벽·IDS 점검용."},
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
