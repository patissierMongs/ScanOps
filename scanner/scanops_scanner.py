#!/usr/bin/env python3
"""Standalone nmap runner that writes XML files ready for ScanOps import.

This file intentionally uses only the Python standard library. Copy this single
file to a scanner host that has Python 3.8+ and nmap installed, then run it
without starting the ScanOps web app.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

VERSION = "0.2.0"
IMPORT_CONTRACT_SCHEMA = 1
IMPORT_CONTRACT_MAX_HOSTS = 65536
STATS_EVERY_DEFAULT = "10s"
# 중단된 실행의 산출물을 모아 두는 하위 폴더 — 결과 폴더에는 온전한 결과만 남긴다.
INTERRUPTED_DIR_NAME = "interrupted"
# 중단본 파일명 표식. 폴더만으로는 파일 하나를 옮기는 순간 구분이 사라진다.
INTERRUPTED_MARK = ".interrupted"
# 정지 신호 후 nmap 이 진행분을 파일로 쓸 때까지 기다리는 시간. GUI 의 강제 종료 타이머보다
# 짧아야 부분 결과 저장과 state 기록이 끝난 뒤에 강제 종료가 온다.
NMAP_STOP_GRACE_SECONDS = 5.0
NMAP_KILL_GRACE_SECONDS = 3.0
# 기본 미적용. 전 포트 스캔은 필터링된 망에서 고정 시간 상한을 정상적으로 넘을 수 있고,
# nmap 은 timeout 된 호스트의 결과를 버린 채 성공 종료할 수 있다. 필요한 환경만 명시적으로 opt-in.
HOST_TIMEOUT_DEFAULT = "0"
UDP_DEFAULT_PORTS = "7,53,67,68,69,88,111,123,135,137,138,139,161,162,389,400,500,514,520,623,1900,2049,4500,5060,5353,5355,11211"
PRECISION_PORTS = f"T:1-65535,U:{UDP_DEFAULT_PORTS}"
# 용도 식별형 NSE만(취약점/노이즈/부작용 스크립트 제외) — 빠르고 부작용 적게 '무엇/왜' 파악.
# 제외: ssl-enum-ciphers·ntp-monlist·dns-recursion·vnc-title
# DB 찌르는 스크립트(oracle-tns-version·ms-sql-info 등)는 장애 위험(티베로 등 호환DB 다운)으로 기본 제외.
# fingerprint-strings: -sV 가 식별 못 한 포트의 원시 응답을 찍어 사람이 판단 → 미식별 포트 조사용.
# TCP 식별용(2단계): TCP portrule 스크립트만. UDP portrule(snmp/nbstat/ike 등)은 UDP_NSE_SCRIPTS 로 분리.
DEFAULT_NSE_SCRIPTS = (
    "http-headers,http-server-header,http-title,ssl-cert,"
    "tls-alpn,ssh-hostkey,smb-os-discovery,smb-protocols,"
    "rdp-ntlm-info,sip-methods,rpcinfo,banner,"
    "ftp-anon,ftp-syst,telnet-encryption,dns-nsid,vnc-info,fingerprint-strings"
)
# UDP 식별용(3단계): UDP 기본 포트(53·111·123·137·161·500·5060 등)에 실제 매칭되는 스크립트만.
# rpcinfo 는 UDP 111(포트맵퍼)에서 RPC/NFS(2049) 프로그램 매핑 → 정체 파악에 유효.
# 부작용 제외: dhcp-discover(리스 요청)·snmp-interfaces(장황·느림)·ntp-monlist(증폭).
UDP_NSE_SCRIPTS = (
    "snmp-info,snmp-sysdescr,nbstat,ike-version,dns-nsid,ntp-info,sip-methods,rpcinfo"
)
# 발견 단계 호스트 디스커버리: ICMP 막은 서버도 흔한 서비스 포트로 잡고, 죽은 IP 는 건너뛴다
# (-Pn 전수보다 듬성한 대역에서 빠르고 누락 적음). -sS 라 raw 소켓(관리자) 전제.
# probe 조합: -PE(ICMP echo) + -PS(SYN) + -PA(ACK). SYN엔 침묵해도 ICMP/ACK엔 답하는 호스트를
# up으로 포착 → discovery 종속 UDP 식별의 누락을 줄인다(가산적, 비용≈0).
DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080"
DISCOVERY_PA = "-PA80,443,3389"
# --open 은 discovery 에 쓰지 않는다: 열린 TCP 가 0개인 up 호스트(UDP 전용: DNS/SNMP/NTP 등)를
# nmap 이 XML 에서 통째로 빼버려 live_hosts 에서 누락 → 그 호스트가 UDP 식별을 못 받게 된다.
# 닫힌 포트는 어차피 <extraports> 로 요약되어 XML 이 커지지 않고, 열린 포트 추출에도 영향 없다.
AUTO_TCP_DISCOVERY_FLAGS = [
    "-sS", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", "-T4", "--reason",
    "--min-hostgroup", "64", "--max-retries", "2",
    "--defeat-rst-ratelimit", "--max-parallelism", "100",
    "-p", "T:1-65535",
]
# identify 단계는 discovery 에서 살아난 호스트만 타깃(execute_auto 가 live_hosts 주입)이라
# -Pn(전수 live 취급)이 안전. -n 제거 → 역DNS 켜서 호스트명 확보(용도 식별 근거).
# --version-all(intensity 9): rarity 높은 서비스(redis 등 rarity 8)까지 식별. 포트스캔에 죽는
# 서비스는 그 자체가 취약점 → 강도를 낮추기보다 정상 식별하고 조치를 압박한다.
AUTO_TCP_IDENTIFY_FLAGS = [
    "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason", "-T4",
    "--max-retries", "2", "--script", DEFAULT_NSE_SCRIPTS, "--script-timeout", "10s",
]
# UDP: --max-scan-delay 금지(닫힌 포트 ICMP rate-limit 백오프를 막아 open|filtered 오판).
# 역DNS 는 TCP identify 가 같은 호스트에서 이미 끝냄 → 중복 PTR 피하려 -n 유지.
# --version-all 미적용: 강도 9 는 수다스러운/증폭형 UDP 서비스(SNMP·SSDP·DNS 등)에서 거대·비정상
# 응답으로 nmap 을 fatal 종료시킬 위험이 크고 UDP 식별 이득은 미미 → 기본 -sV(강도 7)로 안전하게.
AUTO_UDP_IDENTIFY_FLAGS = [
    "-sU", "-Pn", "-n", "-sV", "--open", "--reason", "-T4",
    "--max-retries", "2", "-p", f"U:{UDP_DEFAULT_PORTS}",
    "--script", UDP_NSE_SCRIPTS, "--script-timeout", "10s",
]
AUTO_STAGES = [
    ("tcp_discovery", "TCP 전체 포트 발견"),
    ("tcp_identify", "발견된 TCP 포트 용도/서비스 식별"),
    ("udp_identify", "주요 UDP 서비스 식별"),
]
# 파일명 끝의 단계 접미사. 서버가 이 이름으로 단계를 읽으므로(STAGE_FILE_RE)
# 산출물 이름을 손댈 때는 접미사가 맨 뒤에 남아야 한다.
STAGE_IDS = frozenset(stage_id for stage_id, _ in AUTO_STAGES)

PRESETS: dict[str, list[str]] = {
    "basic": ["-Pn", "-sV", "-T4"],
    "quick": ["-sT", "-T4", "--top-ports", "1000", "-sV", "--reason"],
    "light": ["-sT", "-T4", "--top-ports", "100", "--reason"],
    # phase1 은 단일 nmap 실행으로 -sS+-sU 를 함께 돌린다. 한 번의 실행에선 --version-all 이
    # TCP·UDP 양쪽 버전탐지에 모두 걸리는데, 강도 9 는 수다/증폭형 UDP(SNMP·SSDP·DNS 등)에서
    # nmap 을 fatal 종료시킬 위험이 크다(자동 워크플로가 UDP 식별에서 --version-all 을 뺀 이유와 동일).
    # 그래서 phase1 도 기본 -sV(강도 7)로 안전하게 간다. 강도 9 TCP 식별이 필요하면 자동 워크플로 사용.
    "phase1": [
        "-sS", "-sU", "-Pn", "-n", "-sV", "--open", "--reason",
        "-T4", "--max-retries", "2", "--min-hostgroup", "64",
        "--max-parallelism", "100", "--defeat-rst-ratelimit",
        "-p", PRECISION_PORTS,
        "--script", DEFAULT_NSE_SCRIPTS + "," + UDP_NSE_SCRIPTS,
    ],
}

# ── 저장 프리셋(사용자 정의) ──
# 위의 PRESETS 는 코드에 박힌 내장 프로필이고, 이 아래는 사용자가 만들어 파일로 보관하며
# ScanOps 웹서버와 동기화하는 프리셋이다. 파일은 **이 스크립트와 같은 폴더**에 둔다.
PRESET_SCHEMA = 1
PRESET_FILE_NAME = "scanops_presets.json"
PRESET_MAX_NAME_LEN = 60
PRESET_MAX_DESC_LEN = 200
PRESET_MAX_COUNT = 200
PRESET_WORKFLOW_ALIASES = {"manual": "single", "single": "single", "auto": "auto"}
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
# 이름은 서버 API 의 URL 경로 조각(PUT /api/scan-presets/item/{name})으로도 쓰인다.
# 경로 구분자가 섞이면 어느 프리셋을 가리키는지 양쪽이 다르게 읽을 수 있다.
PRESET_NAME_FORBIDDEN = ("/", "\\")

# 웹 UI 의 스캔 옵션 레지스트리(backend/scanops/scanning/scan_options.py SCAN_OPTIONS) 사본.
# 프리셋은 nmap 플래그가 아니라 이 '키'로 오가므로, 양쪽이 같은 키→플래그 표를 가져야 한다.
# 표가 어긋나면 같은 프리셋이 서로 다른 스캔이 되므로 backend 테스트가 동일성을 강제한다.
OPTION_FLAGS: dict[str, list[str]] = {
    "syn": ["-sS"],
    "connect": ["-sT"],
    "udp": ["-sU"],
    "ack": ["-sA"],
    "fin": ["-sF"],
    "null": ["-sN"],
    "xmas": ["-sX"],
    "disc_ports": [DISCOVERY_PS],
    "noping": ["-Pn"],
    "ping_only": ["-sn"],
    "dns_no": ["-n"],
    "version": ["-sV"],
    "version_light": ["--version-light"],
    "version_all": ["--version-all"],
    "scripts": ["-sC"],
    "os": ["-O"],
    "traceroute": ["--traceroute"],
    "aggressive": ["-A"],
    "open_only": ["--open"],
    "reason": ["--reason"],
    "verbose": ["-v"],
    "t0": ["-T0"],
    "t1": ["-T1"],
    "t2": ["-T2"],
    "t3": ["-T3"],
    "fast": ["-T4"],
    "t5": ["-T5"],
    "max_retries": ["--max-retries", "2"],
    "min_hostgroup": ["--min-hostgroup", "64"],
    "max_parallel": ["--max-parallelism", "100"],
    "defeat_rst": ["--defeat-rst-ratelimit"],
    "max_scan_delay": ["--max-scan-delay", "5ms"],
    "fragment": ["-f"],
}
# 타이밍은 택1 — 프리셋에 여러 개가 들어와도 마지막 하나만 실제 플래그로 나간다.
OPTION_TIMING_KEYS = ("t0", "t1", "t2", "t3", "fast", "t5")
# NSE 화이트리스트(웹 NSE_SCRIPTS 사본) — key: 식별 단계 적용 프로토콜.
NSE_PROTO: dict[str, str] = {
    "http-headers": "tcp", "http-server-header": "tcp", "http-title": "tcp",
    "ssl-cert": "tcp", "ssl-enum-ciphers": "tcp", "tls-alpn": "tcp",
    "ssh-hostkey": "tcp", "ssh-auth-methods": "tcp", "ssh2-enum-algos": "tcp",
    "nbstat": "udp", "smb-os-discovery": "tcp", "smb-protocols": "tcp",
    "oracle-tns-version": "tcp", "ms-sql-info": "both", "ldap-rootdse": "tcp",
    "rdp-ntlm-info": "tcp", "snmp-info": "udp", "snmp-sysdescr": "udp",
    "ike-version": "udp", "sip-methods": "both", "ntp-info": "udp",
    "ntp-monlist": "udp", "rpcinfo": "both", "fingerprint-strings": "tcp",
    "banner": "tcp", "ftp-anon": "tcp", "ftp-syst": "tcp",
    "telnet-encryption": "tcp", "dns-recursion": "both", "dns-nsid": "both",
    "vnc-info": "tcp", "vnc-title": "tcp",
}
# 프리셋의 '기본 NSE' — 이 스캐너가 실제로 쓰는 TCP/UDP 기본 세트의 합집합에서 파생시킨다.
# 상수를 따로 적으면 기본값을 바꿀 때 조용히 어긋나므로 파생으로 묶어 둔다.
DEFAULT_PRESET_NSE = [
    key for key in NSE_PROTO
    if key in set(DEFAULT_NSE_SCRIPTS.split(",")) | set(UDP_NSE_SCRIPTS.split(","))
]

# 웹 UI 가 기본으로 켜 두는 옵션 집합(scan_options.DEFAULT_KEYS 사본). --workflow auto 를
# 프리셋으로 저장할 때의 본문이 되므로, 같은 프리셋이 웹에서도 같은 스캔이 된다.
DEFAULT_AUTO_PRESET_OPTIONS = [
    "syn", "udp", "disc_ports", "version", "version_all",
    "open_only", "reason", "fast", "max_retries", "min_hostgroup",
    "max_parallel", "defeat_rst",
]
# 내장 프로필 중 '옵션 키로 손실 없이 표현되는' 것만 프리셋으로 저장할 수 있다.
# quick/light 는 --top-ports 를 쓰는데 웹 옵션 레지스트리에 대응 키가 없어 제외한다.
PROFILE_PRESET_OPTIONS = {
    "basic": ["noping", "version", "fast"],
    "phase1": ["syn", "udp", "noping", "dns_no", "version", "open_only", "reason",
               "fast", "max_retries", "min_hostgroup", "max_parallel", "defeat_rst"],
}
PROFILE_PRESET_PORTS = {"phase1": PRECISION_PORTS}
PROFILE_PRESET_NSE = {"phase1"}
# 저강도(gentle) — 15년 전 도입한 백본처럼 control-plane 이 약한 장비를 상대할 때의 기본값.
# -T3(표준)을 기준으로 속도·병렬·재시도에 상한을 더 걸어 "-T3 보다 조금 더 느린" 강도를 만든다.
GENTLE_TIMING = "-T3"
FASTER_TIMING_FLAGS = {"-T4", "-T5"}
GENTLE_MAX_PARALLELISM = "10"
GENTLE_MIN_HOSTGROUP = "16"
GENTLE_MAX_RETRIES = "1"
GENTLE_MAX_RATE_DEFAULT = "150"   # packets/sec
GENTLE_HOST_TIMEOUT_DEFAULT = "30m"
# 허용 강도 — 파서 choices 와 state 재검증이 같은 목록을 쓴다.
INTENSITY_CHOICES = ("normal", "gentle")

# 타겟은 argv 맨 뒤에 와도 '-' 시작 시 Nmap 옵션으로 재해석된다.
TARGET_RE = re.compile(r"^(?!-)[A-Za-z0-9_.:/\-]+$")
PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]+$")
# 포트 본문(프로토콜 접두사 제거 후): 단일 포트·범위·열린 범위(1-, -1024) 허용.
PORT_BODY_RE = re.compile(r"^(\d{1,5}-\d{1,5}|\d{1,5}-|-\d{1,5}|\d{1,5})$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$")
STATS_RE = re.compile(r"^\d+[smh]?$")
NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
IPV4_RANGE_TOKEN_RE = re.compile(r"^[\d-]+(?:\.[\d-]+){3}$")
VALUE_FLAGS = {"-p", "--top-ports"}
SCAN_TYPE_FLAGS = {"-sS", "-sT"}
TIMING_FLAG_RE = re.compile(r"^-T[0-5]$")


def configure_pipe_encoding() -> None:
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


configure_pipe_encoding()


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_name(name: str | None) -> str:
    cleaned = NAME_RE.sub("_", (name or "").strip()).strip("._-")
    return cleaned or f"scan_{timestamp()}"


def target_label(targets: list[str]) -> str:
    labels = [NAME_RE.sub("_", t.strip()).strip("._-") for t in targets if t.strip()]
    labels = [label for label in labels if label]
    if not labels:
        return "target"
    label = labels[0][:80]
    if len(labels) > 1:
        label = f"{label}_plus{len(labels) - 1}"
    return label


def find_nmap(explicit: str = "") -> str | None:
    if explicit and Path(explicit).is_file():
        return explicit
    for candidate in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if Path(candidate).is_file():
            return candidate
    return shutil.which("nmap")


def split_targets(text: str) -> list[str]:
    tokens: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens.extend(t for t in re.split(r"[\s,]+", line) if t)
    return tokens


def collect_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.targets or [])
    if args.targets_file:
        targets.extend(split_targets(Path(args.targets_file).read_text(encoding="utf-8")))
    targets = [t.strip() for t in targets if t and t.strip()]
    if not targets:
        raise ValueError("target 이 없습니다. 예: 10.0.0.10 또는 --targets-file targets.txt")
    validate_targets(targets)
    return targets


def validate_targets(targets: list[str]) -> None:
    bad = [t for t in targets if not isinstance(t, str) or not TARGET_RE.fullmatch(t)]
    if bad:
        raise ValueError(f"허용되지 않는 target 형식: {bad}")
    # IPv6 는 자동 워크플로 플래그(-6 없음)와 호환되지 않아 nmap 이 실패하고, 실패하면
    # best-effort 라도 해당 대상은 결과가 0 → 혼란. 명시적으로 거절한다(QA-016).
    ipv6 = [t for t in targets if ":" in t]
    if ipv6:
        raise ValueError(f"IPv6 대상은 아직 지원하지 않습니다: {ipv6}. IPv4 주소/대역으로 지정하세요.")
    composite_ranges = [t for t in targets if is_unsupported_composite_ipv4_range(t)]
    if composite_ranges:
        raise ValueError(
            f"지원하지 않는 복합 IP 범위: {composite_ranges}. "
            "마지막 옥텟 범위만 사용할 수 있습니다."
        )


def is_unsupported_composite_ipv4_range(target: str) -> bool:
    """숫자 옥텟의 Nmap 복합 범위 중 마지막 옥텟 단순 범위가 아닌 형식인지 반환."""
    return bool(
        "-" in target
        and IPV4_RANGE_TOKEN_RE.fullmatch(target)
        and not RANGE_RE.fullmatch(target)
    )


def warn_ambiguous_ports(spec: str) -> None:
    """T:/U: 접두사는 다음 접두사 전까지 sticky(nmap 규칙). 접두사 뒤의 '접두사 없는' 포트는
    직전 프로토콜로 묶인다(예: T:80,U:53,443 → 443 은 UDP). 사용자 의도와 다를 수 있어 한 번 경고(QA-013).

    단, 한 프로토콜 접두사만 쓰인 스펙(예: 포트 제외 우회용 'T:1-3029,3031-65535')은 접두사 없는
    꼬리가 귀속될 프로토콜이 하나뿐이라 모호하지 않다 → 경고하지 않는다. T:와 U:가 함께 있을 때만
    실제로 오해가 발생하므로 그 경우로 한정한다."""
    if ":" not in spec:
        return
    segments = spec.replace(" ", "").split(",")
    prefixes = {seg.split(":", 1)[0].upper() for seg in segments if ":" in seg}
    if not {"T", "U"} <= prefixes:
        return
    current = ""
    for seg in segments:
        if ":" in seg:
            current = seg.split(":", 1)[0].upper()
        elif current:
            print(
                f"warning: 포트 '{seg}' 는 직전 '{current}:' 프로토콜로 처리됩니다(nmap 규칙). "
                f"의도와 다르면 포트마다 T:/U: 접두사를 붙이세요.",
                file=sys.stderr,
            )
            return


def parse_scope(spec: str) -> list:
    """콤마/공백 구분 CIDR·IP 목록. 토큰 하나라도 잘못되면 전체 설정을 거절한다."""
    nets = []
    for raw in (spec or "").replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(raw.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"잘못된 스캔 대역(scope) 설정입니다: {raw.strip()!r}") from exc
    return nets


def _in_scope(host: str, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(host, strict=False)
        return any(net.version == n.version and net.subnet_of(n) for n in nets)
    except ValueError:
        return False  # IP/CIDR 가 아니면(호스트명 등) scope 모드에선 검증 불가 → 불허


def check_scope(hosts: list[str], spec: str) -> None:
    """허용 대역(scope)이 설정돼 있으면 모든 host 가 그 안에 드는지 검증. 비면 무제한.
    오타·잘못 붙여넣은 사외 대역을 스캔 시작 전에 막는다(QA-020, 백엔드 scope 와 동일 의미)."""
    nets = parse_scope(spec)
    if not nets:
        return
    bad = [h for h in hosts if not _in_scope(h, nets)]
    if bad:
        shown = ", ".join(bad[:5]) + (f" 외 {len(bad) - 5}건" if len(bad) > 5 else "")
        raise ValueError(f"허용된 스캔 대역(scope) 밖의 대상입니다: {shown}")


def parse_excludes(values: list[str] | tuple[str, ...] | str | None) -> tuple[list[str], list[ipaddress.IPv4Network]]:
    """반복 --exclude 값을 IPv4 IP/CIDR/마지막 옥텟 범위 목록으로 검증·정규화한다.

    각 옵션 값 안의 쉼표와 모든 공백(CRLF 포함)을 구분자로 쓴다. 잘못된 토큰 하나라도 있으면
    전체 요청을 거절해 오타가 조용히 '제외 없음'으로 바뀌지 않게 한다.

    대상 입력(expand_targets)이 받는 '10.0.0.1-10' 형태를 제외에서는 거절해 '제외가 안 먹는다'로
    보이던 문법 비대칭을 없앤다. 범위 토큰은 nmap 이 --exclude 에서 그대로 받으므로 canonical 에는
    압축 표기를 유지하고, 파이썬 쪽 호스트 차감(apply_excludes)을 위해 /32 로 전개해 둔다.
    """
    if values is None:
        raw_values: list[str] = []
    elif isinstance(values, str):
        raw_values = [values]
    elif isinstance(values, (list, tuple)) and all(isinstance(v, str) for v in values):
        raw_values = list(values)
    else:
        raise ValueError("--exclude 값은 IPv4 주소 또는 CIDR 문자열이어야 합니다.")

    canonical: list[str] = []
    networks: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for raw in raw_values:
        tokens = raw.replace(",", " ").split()
        if not tokens:
            raise ValueError("--exclude 값이 비어 있습니다. 옵션을 빼거나 IPv4 IP/CIDR을 지정하세요.")
        for token in tokens:
            # 마지막 옥텟 범위(10.0.0.1-10): 대상 입력과 같은 문법을 제외에서도 받는다.
            if match := RANGE_RE.fullmatch(token):
                base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
                octets = [int(o) for o in base.split(".")]
                if any(o > 255 for o in octets) or lo > 255 or hi > 255 or lo > hi:
                    raise ValueError(f"잘못된 제외 IP 범위(--exclude)입니다: {token!r}. 예: 10.0.0.1-10")
                if token in seen:
                    continue
                seen.add(token)
                canonical.append(token)  # nmap --exclude 가 범위 표기를 그대로 받는다.
                networks.extend(ipaddress.ip_network(f"{base}.{i}/32") for i in range(lo, hi + 1))
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"잘못된 제외 대상(--exclude)입니다: {token!r}. IPv4 IP/CIDR/범위만 지원합니다."
                ) from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError(
                    f"잘못된 제외 대상(--exclude)입니다: {token!r}. IPv4 IP/CIDR/범위만 지원합니다."
                )
            key = network.with_prefixlen
            if key in seen:
                continue
            seen.add(key)
            # 단일 IP는 읽기 쉬운 IP로, CIDR은 host bits를 정리한 canonical network로 저장한다.
            canonical.append(
                str(network.network_address)
                if network.prefixlen == network.max_prefixlen
                else key
            )
            networks.append(network)
    return canonical, networks


def apply_excludes(hosts: list[str], networks: list[ipaddress.IPv4Network]) -> list[str]:
    """확장된 대상 중 exclude 네트워크에 속한 IPv4 호스트만 제거한다."""
    if not networks:
        return list(hosts)
    effective: list[str] = []
    for host in hosts:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            effective.append(host)  # hostname은 DNS로 추측하지 않는다.
            continue
        if not isinstance(ip, ipaddress.IPv4Address) or not any(ip in network for network in networks):
            effective.append(host)
    return effective


def effective_targets_fingerprint(hosts: list[str]) -> str:
    """순서까지 포함한 유효 대상 목록의 안정적인 SHA-256 지문을 만든다."""
    digest = hashlib.sha256()
    for host in hosts:
        encoded = host.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def concrete_scan_targets(
    plan: dict, batch_index: int, targets: list[str] | None = None,
) -> tuple[list[str], bool]:
    """Return the exact IPv4 hosts handed to one execution unit.

    Non-batch plans retain compact CIDR/range tokens for Nmap, so expand them here only for
    the import contract. Hostnames cannot prove an unobserved address and therefore make the
    unit observation-only.
    """
    max_hosts = min(int(plan.get("max_hosts", IMPORT_CONTRACT_MAX_HOSTS)), IMPORT_CONTRACT_MAX_HOSTS)
    if targets:
        source = targets
    elif int(plan.get("batch_size", 0)) > 0:
        source = plan["batches"][batch_index]
    else:
        source = plan.get("raw_targets") or plan["batches"][batch_index]
    try:
        expanded = expand_targets(source, max_hosts)
        _canonical_excludes, exclude_networks = parse_excludes(plan.get("exclude", []))
        effective = apply_excludes(expanded, exclude_networks)
    except (TypeError, ValueError):
        return [], False

    concrete: list[str] = []
    seen: set[str] = set()
    for host in effective:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return [], False
        if not isinstance(address, ipaddress.IPv4Address):
            return [], False
        value = str(address)
        if value not in seen:
            seen.add(value)
            concrete.append(value)
    return concrete, bool(concrete)


def validate_ports(ports: str) -> str:
    ports = (ports or "").strip()
    if not ports:
        return ""
    if not PORTS_RE.match(ports):
        raise ValueError("허용되지 않는 포트 형식입니다. 예: 22,80,443 또는 1-1024")
    ports = ports.replace(" ", "")
    # 문자집합 통과 뒤에도 'T:'(빈 본문)·빈 항목(',,')·잘못된 본문 같은 쓰레기가 nmap -p 로
    # 새지 않도록 항목 단위로 검증한다(QA-014).
    for seg in ports.split(","):
        if not seg:
            raise ValueError("포트 목록에 빈 항목이 있습니다(콤마 위치 확인). 예: 22,80,443")
        body = seg
        if ":" in seg:
            prefix, body = seg.split(":", 1)
            if prefix.upper() not in ("T", "U"):
                raise ValueError(f"알 수 없는 프로토콜 접두사: '{seg}' (T: 또는 U: 만 허용)")
        if not body:
            raise ValueError(f"프로토콜 접두사 뒤에 포트가 없습니다: '{seg}'")
        if not PORT_BODY_RE.match(body):
            raise ValueError(f"잘못된 포트/범위: '{seg}' (예: 80, 1-1024, 1-, -1024)")
        nums = re.findall(r"\d+", body)
        if any(not (1 <= int(n) <= 65535) for n in nums):
            raise ValueError(f"포트는 1-65535 범위여야 합니다: '{seg}'")
        # 거꾸로 된 범위(시작>끝)는 nmap 이 fatal 로 거절 → 빈 실패 스캔이 된다. IP 범위(expand_targets)와
        # 동일하게 여기서 정직하게 막는다(QA-035). 열린 범위('1-','-1024')는 끝점이 하나라 무관.
        if "-" in body and len(nums) == 2 and int(nums[0]) > int(nums[1]):
            raise ValueError(f"포트 범위가 거꾸로입니다(시작>끝): '{seg}'. 예: 22-443")
    return ports


def resumed_value(plan: dict, key: str, default, validate):
    """재개 시 저장값을 되살린다 — '키 부재'와 '명시된 값'을 반드시 구분한다.

    plan.get(key) 는 키가 없는 경우와 명시적 null 을 똑같이 None 으로 돌려준다. 안전 제어
    필드에서 그 둘을 뭉개면, state 에 `"intensity": null` 한 줄만 넣어도 -T3+속도상한이
    -T4+무제한으로 조용히 풀린다. 구버전 호환은 키가 '아예 없을 때'만 적용하고, 값이
    명시돼 있으면 그것이 null 이든 무엇이든 검증기를 통과해야 한다."""
    if key not in plan:
        return default          # 구형 state: 그 개념이 없던 시절 → 기본값
    return validate(plan[key])


def validate_intensity(value: object) -> str:
    """저장된 스캔 강도를 검증한다(fail-closed).

    강도는 노후 장비 보호용 '안전 제어'다. 알 수 없는 값(미래 버전이 쓴 값이나 손상된 값,
    명시적 null)을 조용히 normal 로 올리면 보호하려던 장비를 그대로 때리게 된다."""
    if isinstance(value, str) and value in INTENSITY_CHOICES:
        return value
    raise ValueError(
        f"state 파일의 intensity 값을 알 수 없습니다: {value!r}. "
        f"허용: {', '.join(INTENSITY_CHOICES)} (안전 제어라 임의로 낮추지 않고 거절합니다)"
    )


def validate_max_rate(value: object) -> str:
    """--max-rate(초당 패킷 상한) 검증. 같은 이유로 손상 값·명시적 null 은 거절한다."""
    if isinstance(value, str) and not value.strip():
        return ""               # 빈 문자열은 '지정 안 함'이라는 정상 저장값이다
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"--max-rate 는 1 이상의 정수여야 합니다: {value!r}")
    text = str(value).strip()
    if not text.isdecimal() or int(text) < 1:
        raise ValueError(f"--max-rate 는 1 이상의 정수여야 합니다: {value!r}")
    return text


def validate_exclude_list(value: object) -> list:
    """저장된 제외 대상 목록의 형태 검증. 명시적 null 로 제외가 사라지지 않게 한다."""
    if not isinstance(value, list):
        raise ValueError(f"state 파일의 exclude 는 목록이어야 합니다: {value!r}")
    return value


def validate_exclude_ports(spec: object) -> str:
    """--exclude-ports 값 검증. -p 와 같은 포트 문법을 쓰되 오류 문구만 옵션에 맞춘다.

    전역 포트 필터라서 warn_ambiguous_ports(=-p 의도 모호성 경고)는 적용하지 않는다.
    문자열이 아닌 값(명시적 null 등)은 거절한다 — 운영자가 뺀 포트가 조용히 되살아나면
    일부러 피한 취약 포트를 그대로 때리게 된다."""
    if not isinstance(spec, str):
        raise ValueError(f"허용되지 않는 --exclude-ports 형식입니다: {spec!r}")
    try:
        return validate_ports(spec)
    except ValueError as exc:
        raise ValueError(
            f"허용되지 않는 --exclude-ports 형식입니다: {exc} (예: 3030, 3030,3040, T:1-1024)"
        ) from exc


def validate_scripts(scripts: str) -> str:
    scripts = (scripts or "").replace(" ", "").strip(",")
    if not scripts:
        return ""
    if not SCRIPT_RE.match(scripts):
        raise ValueError("NSE script 는 이름만 콤마로 지정하세요. 예: ssl-cert,http-title")
    return scripts


def validate_stats_every(value: str) -> str:
    value = (value or STATS_EVERY_DEFAULT).strip()
    if not STATS_RE.match(value):
        raise ValueError("--stats-every 값은 10s, 1m 같은 nmap 시간 형식이어야 합니다.")
    return value


def validate_host_timeout(value: str) -> str:
    """호스트당 상한. 빈 값/0 이면 미적용. 그 외는 nmap 시간 형식(15m 등)."""
    value = (value if value is not None else "").strip()
    if value in ("", "0"):
        return ""
    if not STATS_RE.match(value):
        raise ValueError("--host-timeout 값은 15m, 30m 같은 nmap 시간 형식이어야 합니다(끄려면 0).")
    return value


def expand_targets(targets: list[str], cap: int) -> list[str]:
    # dict 로 누적해 '전개 도중'에도 중복/겹침을 제거한다(QA-018). 캡은 dedup 된 누적 개수로 검사하므로
    # 중복 대상이 캡을 헛되이 넘기지 않고(QA-053), 동시에 누적 폭발도 막는다(QA-015 유지).
    hosts: dict[str, None] = {}
    for raw in targets:
        t = raw.strip()
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError as exc:
                # 잘못된 CIDR 을 그대로 nmap 에 넘기면 거기서 깨진다 → 여기서 정직하게 거절(QA-019).
                raise ValueError(f"잘못된 CIDR: {t}") from exc
            # 전개 '전에' 단일 CIDR 크기를 확인한다. /8·IPv6 CIDR 을 통째로 materialize 하면 캡이 발동하기도
            # 전에 메모리/시간이 폭발한다(QA-015). 이 pre-check 는 절대 제거하지 말 것.
            if net.num_addresses > cap:
                raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}): {t}. --max-hosts 또는 범위를 조정하세요.")
            for ip in net:
                hosts[str(ip)] = None
        elif match := RANGE_RE.match(t):
            base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
            octets = [int(o) for o in base.split(".")]
            if any(o > 255 for o in octets) or lo > 255 or hi > 255 or lo > hi:
                raise ValueError(f"잘못된 IP 범위: {t}")
            for i in range(lo, hi + 1):
                hosts[f"{base}.{i}"] = None
        elif is_unsupported_composite_ipv4_range(t):
            raise ValueError(f"지원하지 않는 복합 IP 범위: {t}. 마지막 옥텟 범위만 사용할 수 있습니다.")
        else:
            hosts[t] = None
        if len(hosts) > cap:
            raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}). --max-hosts 또는 범위를 조정하세요.")
    return list(hosts)


def make_batches(targets: list[str], batch_size: int) -> list[list[str]]:
    if batch_size <= 0:
        return [targets]
    return [targets[i:i + batch_size] for i in range(0, len(targets), batch_size)]


def strip_value_flags(flags: list[str], names: set[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for token in flags:
        if skip:
            skip = False
            continue
        if token in names:
            skip = True
            continue
        out.append(token)
    return out


def strip_flags(flags: list[str], names: set[str], value_flags: set[str] | None = None) -> list[str]:
    out: list[str] = []
    skip = False
    value_flags = value_flags or set()
    for token in flags:
        if skip:
            skip = False
            continue
        if token in names:
            continue
        if token in value_flags:
            skip = True
            continue
        out.append(token)
    return out


def set_scan_type(flags: list[str], scan_type: str) -> list[str]:
    if not scan_type:
        return flags
    mapped = {"connect": "-sT", "syn": "-sS"}[scan_type]
    flags = [f for f in flags if f not in SCAN_TYPE_FLAGS]
    if scan_type == "connect":
        flags = [f for f in flags if f != "--defeat-rst-ratelimit"]
    return [mapped, *flags]


def tcp_only_ports(port_spec: str) -> str:
    # nmap sticky 규칙(T:/U: 는 다음 접두사 전까지 유효)을 존중해 TCP 부분만 남긴다. 접두사 없는 포트는
    # 직전 프로토콜에 귀속된다. 이전 구현은 첫 'U:' 에서 spec 을 통째로 잘라 그 뒤 T: 포트를 잃었고
    # (예: 'U:53,T:80,443' → '' ), 단순 항목 필터는 U: 뒤 sticky 포트(예: 'U:7,53' 의 53)를 TCP 로
    # 오인했다 — 둘 다 틀렸다(QA-037). T: 접두사는 보존한다(build_base_flags 가 그대로 -p 에 넣는다).
    current = ""
    parts: list[str] = []
    for raw in port_spec.split(","):
        item = raw.strip()
        if not item:
            continue
        if ":" in item:
            prefix, value = item.split(":", 1)
            up = prefix.upper()
            if up in ("T", "U"):
                current = up
                if up == "T" and value:
                    parts.append(f"T:{value}")
                continue
        # 접두사 없는 포트: 직전 프로토콜(없으면 TCP)에 귀속
        if current in ("", "T"):
            parts.append(item)
    return ",".join(parts)


def set_timing(flags: list[str], timing: str) -> list[str]:
    """타이밍 플래그 교체 — 프리셋이 -T2 를 요구하면 단계 기본 -T4 를 대체한다(택1).
    자리를 그대로 두고 값만 바꿔 명령 미리보기가 불필요하게 흔들리지 않게 한다."""
    if not timing:
        return flags
    out: list[str] = []
    replaced = False
    for flag in flags:
        if TIMING_FLAG_RE.fullmatch(flag):
            if not replaced:
                out.append(timing)
                replaced = True
            continue
        out.append(flag)
    if not replaced:
        out.append(timing)
    return out


def build_base_flags(args: argparse.Namespace) -> list[str]:
    # 저장 프리셋을 쓰면 내장 프로필 대신 프리셋의 옵션 키에서 플래그를 만든다(웹과 같은 어휘).
    preset_options = getattr(args, "preset_options", None)
    flags = option_flags(preset_options) if preset_options is not None else list(PRESETS[args.profile])
    flags = set_scan_type(flags, args.scan_type)

    if getattr(args, "tcp_only", False):
        flags = strip_flags(flags, {"-sU"})
        if "-p" in flags:
            idx = flags.index("-p")
            if idx + 1 < len(flags):
                flags[idx + 1] = tcp_only_ports(flags[idx + 1])
    elif args.udp and "-sU" not in flags:
        flags.insert(1 if flags and flags[0] in SCAN_TYPE_FLAGS else 0, "-sU")

    # TCP Connect(권한 불필요) 모드에선 -sU(raw 소켓, 관리자 권한 필요)를 쓸 수 없다 → 제거(QA-010).
    if args.scan_type == "connect":
        flags = strip_flags(flags, {"-sU"})

    ports = "T:1-65535" if args.all_ports else validate_ports(args.ports)
    if ports:
        flags = strip_value_flags(flags, VALUE_FLAGS)
        flags.extend(["-p", ports])

    # TCP 전용(tcp_only)·connect(권한 불필요, UDP 불가) 모드에선 '최종' -p 의 U: 포트도 제거한다.
    # 위 tcp_only 분기는 프리셋 -p 만 처리하므로, 사용자 --ports override 의 U: 포트가 그대로 새어
    # -sU 없이 nmap 에 전달되면 nmap 이 fatal 종료한다(QA-048). 제거 후 TCP 포트가 없으면 정직하게 거절.
    if (getattr(args, "tcp_only", False) or args.scan_type == "connect") and "-p" in flags:
        idx = flags.index("-p")
        stripped = tcp_only_ports(flags[idx + 1])
        if not stripped:
            raise ValueError("TCP 전용(또는 connect) 모드인데 지정한 포트에 TCP 포트가 없습니다. 예: --ports 22,443")
        flags[idx + 1] = stripped

    scripts = validate_scripts(args.scripts)
    if getattr(args, "no_scripts", False):
        flags = strip_flags(flags, set(), {"--script"})
        flags = strip_flags(flags, set(), {"--script-timeout"})
    elif args.nse_default or scripts:
        flags = strip_value_flags(flags, {"--script"})
        flags.extend(["--script", scripts or DEFAULT_NSE_SCRIPTS])

    if getattr(args, "include_closed", False):
        flags = strip_flags(flags, {"--open"})
    if args.open_only and "--open" not in flags:
        flags.append("--open")

    # 저강도는 마지막에 적용한다: -p/-sU/스크립트 처리가 모두 끝난 뒤 타이밍·속도만 낮춰
    # QA-037(sticky 포트)·QA-048(U: 누출) 같은 포트 계약을 건드리지 않게 한다.
    if getattr(args, "intensity", "normal") == "gentle":
        flags = apply_gentle_intensity(flags, getattr(args, "max_rate", "") or "")

    return flags


def replace_value_flag(flags: list[str], name: str, value: str) -> list[str]:
    flags = strip_value_flags(flags, {name})
    return [*flags, name, value]


def set_value_if_present(flags: list[str], name: str, value: str) -> list[str]:
    """이미 있는 value flag 의 값만 바꾼다(없으면 추가하지 않는다)."""
    if name not in flags:
        return flags
    return replace_value_flag(flags, name, value)


def apply_gentle_intensity(flags: list[str], max_rate: str = "") -> list[str]:
    """노후 백본 장비 안전용 저강도 변환.

    가장 중요한 건 --defeat-rst-ratelimit 제거다. 이 플래그는 장비가 스스로 거는 RST rate-limit
    보호를 무력화해, 오래된 control-plane 을 가장 확실하게 괴롭힌다. 타이밍은 -T3 로 낮추고
    속도/병렬/재시도에 상한을 걸어 '-T3 보다 조금 더 느린' 강도를 만든다.

    --max-parallelism/--min-hostgroup 은 '있을 때만' 축소한다(프리셋이 안 쓰면 굳이 만들지 않음).
    --max-retries/--max-rate 는 없으면 추가해, 어떤 프리셋에서도 완화가 실제로 걸리게 한다."""
    flags = [GENTLE_TIMING if f in FASTER_TIMING_FLAGS else f for f in flags]
    flags = strip_flags(flags, {"--defeat-rst-ratelimit"})
    flags = set_value_if_present(flags, "--max-parallelism", GENTLE_MAX_PARALLELISM)
    flags = set_value_if_present(flags, "--min-hostgroup", GENTLE_MIN_HOSTGROUP)
    flags = replace_value_flag(flags, "--max-retries", GENTLE_MAX_RETRIES)
    flags = replace_value_flag(flags, "--max-rate", max_rate or GENTLE_MAX_RATE_DEFAULT)
    return flags


def protocol_ports(port_spec: str, protocol: str) -> list[str]:
    protocol = protocol.upper()
    current = ""
    ports: list[str] = []
    for raw in (port_spec or "").replace(" ", "").split(","):
        item = raw.strip()
        if not item:
            continue
        if ":" in item:
            prefix, value = item.split(":", 1)
            if prefix.upper() in {"T", "U"}:
                current = prefix.upper()
                item = value
        if not item:
            continue
        if not current:
            if protocol == "T":
                ports.append(item)
        elif current == protocol:
            ports.append(item)
    return ports


def auto_tcp_discovery_ports(plan: dict) -> str:
    if plan.get("all_ports"):
        return "T:1-65535"
    override = plan.get("ports_override", "")
    if not override:
        return "T:1-65535"
    ports = protocol_ports(override, "T")
    return ",".join(ports)


def auto_udp_ports(plan: dict) -> str:
    # --all-ports 는 '전부 스캔' 의도 → auto_tcp_discovery_ports 가 override 를 무시하고 전체를 잡는 것과
    # 대칭으로, UDP 도 기본 UDP 포트셋을 쓴다. (이전엔 all_ports 를 무시해, TCP만 담긴 --ports 가 남아 있으면
    # UDP 단계가 통째로 건너뛰어졌다 — QA-036.) tcp_only 는 execute_auto 가 더 앞에서 처리.
    if plan.get("all_ports"):
        return f"U:{UDP_DEFAULT_PORTS}"
    override = plan.get("ports_override", "")
    if override:
        ports = protocol_ports(override, "U")
        return f"U:{','.join(ports)}" if ports else ""
    return f"U:{UDP_DEFAULT_PORTS}"


def stage_scripts(scripts: str, stage_id: str) -> str:
    """단계에 실제로 걸리는 NSE 만 남긴다.

    - 발견(tcp_discovery)에는 NSE 를 붙이지 않는다. 이 단계의 목적은 '열린 포트를 빨리 좁히는 것'이라
      스크립트를 얹으면 이득 없이 느려진다(웹 자동 스캔의 발견 단계도 동일).
    - 식별 단계는 portrule 이 맞는 프로토콜만: TCP 식별에 snmp/nbstat, UDP 식별에 http-* 를 보내도
      매칭되지 않아 시간만 쓴다. 화이트리스트에 없는 이름은 사용자가 명시한 것이므로 그대로 통과시킨다.
    """
    if stage_id == "tcp_discovery":
        return ""
    protocol = "udp" if stage_id == "udp_identify" else "tcp"
    keep = [s for s in (scripts or "").split(",")
            if s and NSE_PROTO.get(s, "both") in (protocol, "both")]
    return ",".join(keep)


def apply_auto_modifiers(flags: list[str], plan: dict, stage_id: str = "") -> list[str]:
    # UDP 식별 단계에는 TCP 스캔 기법을 절대 얹지 않는다. -sS 가 섞이면 그 한 번의 실행이
    # TCP+UDP 동시 스캔이 되어 UDP 단계의 포트 범위/시간 계산이 통째로 어긋난다.
    if stage_id != "udp_identify":
        flags = set_scan_type(list(flags), plan.get("scan_type", ""))
    else:
        flags = list(flags)
    # 프리셋이 타이밍을 지정하면 단계 기본 -T4 를 대체한다(느린 망/민감 장비용 프리셋이
    # 자동 워크플로에서 조용히 무시되지 않게).
    flags = set_timing(flags, plan.get("timing", ""))
    scripts = plan.get("scripts", "")
    if plan.get("no_scripts"):
        flags = strip_flags(flags, set(), {"--script"})
        flags = strip_flags(flags, set(), {"--script-timeout"})
    elif scripts:
        selected = stage_scripts(scripts, stage_id)
        if selected:
            flags = replace_value_flag(flags, "--script", selected)
        else:
            flags = strip_flags(flags, set(), {"--script"})
            flags = strip_flags(flags, set(), {"--script-timeout"})
    if plan.get("include_closed"):
        flags = strip_flags(flags, {"--open"})
    # discovery 단계엔 --open 을 절대 추가하지 않는다: 열린 TCP 0개인 up 호스트(UDP 전용)가 XML 에서
    # 통째로 빠져 live_hosts 에서 누락되고 UDP 식별을 못 받는다(상단 불변식, QA-031).
    # open_only 는 identify 단계(이미 --open 보유)에만 의미가 있으므로 discovery 는 제외한다.
    if plan.get("open_only") and "--open" not in flags and stage_id != "tcp_discovery":
        flags.append("--open")
    # 저강도: auto 3단계 전부가 이 깔때기를 지나므로 여기 한 곳이면 충분하고,
    # plan 을 읽으므로 --resume 으로 이어할 때도 같은 강도가 유지된다.
    if plan.get("intensity") == "gentle":
        flags = apply_gentle_intensity(flags, plan.get("max_rate", ""))
    return flags


def build_auto_flags(plan: dict, stage_id: str, tcp_ports: list[int] | None = None) -> list[str]:
    if stage_id == "tcp_discovery":
        port_spec = auto_tcp_discovery_ports(plan)
        if not port_spec:
            raise ValueError("tcp_discovery stage has no TCP ports to scan.")
        flags = replace_value_flag(AUTO_TCP_DISCOVERY_FLAGS, "-p", port_spec)
    elif stage_id == "tcp_identify":
        if not tcp_ports:
            raise ValueError("tcp_identify stage requires discovered TCP ports.")
        port_spec = "T:" + ",".join(str(p) for p in tcp_ports)
        flags = [*AUTO_TCP_IDENTIFY_FLAGS, "-p", port_spec]
    elif stage_id == "udp_identify":
        udp_ports = auto_udp_ports(plan)
        if not udp_ports:
            raise ValueError("udp_identify stage has no UDP ports to scan.")
        flags = replace_value_flag(AUTO_UDP_IDENTIFY_FLAGS, "-p", udp_ports)
    else:
        raise ValueError(f"unknown auto stage: {stage_id}")
    return apply_auto_modifiers(flags, plan, stage_id)


def output_base(plan: dict, index: int, stage_id: str = "") -> Path:
    out_dir = Path(plan["output_dir"])
    name = plan["name"]
    target = target_label(plan["batches"][index])
    suffix = f".{stage_id}" if stage_id else ""
    if len(plan["batches"]) == 1:
        return out_dir / f"{name}.{target}{suffix}"
    return out_dir / f"{name}.{target}.b{index:04d}{suffix}"


def build_command(plan: dict, index: int, stage_id: str = "", tcp_ports: list[int] | None = None,
                  targets: list[str] | None = None) -> list[str]:
    base = output_base(plan, index, stage_id)
    flags = build_auto_flags(plan, stage_id, tcp_ports) if stage_id else plan["base_flags"]
    # identify 단계는 discovery 생존 호스트(targets)로 좁힌다. 없으면 원본 배치 전체.
    scan_targets = targets if targets else plan["batches"][index]
    host_timeout = plan.get("host_timeout", "")
    # --host-timeout: 한 호스트가 무한정 멈추는 걸 막는다(nmap 이 해당 호스트만 포기, 0으로 정상 종료).
    timeout_flags = ["--host-timeout", host_timeout] if host_timeout else []
    excludes = plan.get("exclude") or []
    # Nmap 7.99는 --exclude를 반복하면 누적하지 않고 마지막 값만 쓴다. CLI에서는 반복 입력을
    # 받되 실제 Nmap에는 검증·정규화된 전체 값을 쉼표로 합쳐 정확히 한 번만 전달한다.
    exclude_flags = ["--exclude", ",".join(excludes)] if excludes else []
    # 포트 제외는 -p 를 건드리지 않는 전역 필터다. nmap 이 선택된 포트집합(-p / --top-ports)에서
    # 사후 차감하므로 auto 각 단계와 single 프리셋 모두에 그대로 얹을 수 있다.
    exclude_ports = plan.get("exclude_ports") or ""
    exclude_ports_flags = ["--exclude-ports", exclude_ports] if exclude_ports else []
    return [
        plan["nmap"],
        "--unique",
        "--stats-every", plan["stats_every"],
        *timeout_flags,
        *exclude_flags,
        *exclude_ports_flags,
        *flags,
        "-oA", str(base),
        *scan_targets,
    ]


def display_command(cmd: list[str]) -> str:
    return shlex.join(cmd)


def existing_outputs(base: Path) -> list[str]:
    files = []
    for suffix in (".xml", ".nmap", ".gnmap"):
        p = Path(str(base) + suffix)
        if p.exists():
            files.append(str(p))
    return files


def interrupted_dir(base: Path) -> Path:
    """중단 산출물을 모으는 하위 폴더 — 결과 폴더 안의 `interrupted/`.

    파일명 표식만으로는 결과 폴더가 온전한 결과와 부분 결과로 뒤섞인다. 폴더를 나누면
    (1) 가져올 것과 아닌 것이 눈으로 바로 갈리고, (2) `폴더째 가져오기`가 온전한 결과만
    집어가며, (3) 중단본만 따로 보관·삭제·검토하기 쉽다.
    """
    return Path(base).parent / INTERRUPTED_DIR_NAME


def interrupted_name(stem: str) -> str:
    """중단본 파일명 — 이름 자체에 표식을 박는다.

    중단된 스캔은 **인입하지 않는다.** 열린 포트를 다 못 봤는데 관측으로 받으면 미탐이
    되고, 재시도가 끊긴 자리의 filtered 를 그대로 믿으면 오탐이 된다. 그런데 '안 넣는다'를
    폴더 위치로만 지키면 파일 하나를 손으로 끌어다 놓는 순간 뚫린다. 그래서 폴더와
    파일명 두 곳에 표식을 남기고, 스캐너·브라우저·서버 세 곳에서 각각 막는다.

    표식은 맨 뒤에 붙어 단계 접미사(.tcp_discovery.xml)를 깨뜨린다 — 의도한 것이다.
    중단본은 어떤 경로로도 '단계 계약을 갖춘 온전한 결과'로 읽히면 안 된다.
    """
    return f"{stem}{INTERRUPTED_MARK}"


def is_interrupted_output(path: str | Path) -> bool:
    """중단본인가 — 파일명 표식 또는 `interrupted/` 폴더 안."""
    normalized = str(path).replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1].lower()
    if f"{INTERRUPTED_MARK}." in name or name.endswith(INTERRUPTED_MARK):
        return True
    return f"/{INTERRUPTED_DIR_NAME}/" in f"/{normalized.lower()}"


def numbered_stage_name(stem: str, index: int) -> str:
    """반복 중단 번호를 붙인 이름 — 단계 접미사는 **맨 뒤에 그대로 남긴다**.

    `...tcp_discovery-2.xml` 처럼 뒤에 붙이면 서버가 파일명에서 단계를 못 읽는다
    (STAGE_FILE_RE 는 `.<stage>.xml` 로 끝나야 매칭). 그러면 발견 단계 sweep 이
    '식별까지 관측한 스캔'으로 취급돼, -sV 를 돌리지도 않은 포트 표 추측이 앞서
    관측한 진짜 식별(OpenSSH 8.9 …)을 덮어쓴다. 번호는 단계 앞에 넣는다.
    """
    head, sep, stage = stem.rpartition(".")
    if sep and stage in STAGE_IDS:
        return f"{head}-{index}.{stage}"
    return f"{stem}-{index}"


def interrupted_base(base: Path) -> Path:
    """중단 산출물의 목적지 basename(하위 폴더 안). 같은 단계를 여러 번 중단하면 번호를 올려
    이전 중단본을 덮어쓰지 않는다(부분 결과 보존)."""
    stem = Path(base).name
    candidate = interrupted_dir(base) / interrupted_name(stem)
    index = 2
    while existing_outputs(candidate):
        candidate = interrupted_dir(base) / interrupted_name(numbered_stage_name(stem, index))
        index += 1
    return candidate


def mark_interrupted_outputs(base: Path) -> list[str]:
    """중단된 실행의 산출물을 `interrupted/` 하위 폴더로 옮긴다.

    이렇게 해야 (1) 결과 폴더에는 온전한 결과만 남고, (2) `--resume` 이 같은 basename 으로
    다시 돌 때 온전한 결과가 부분 결과를 덮어쓰지 않는다. state/manifest 파일명과 위치는
    `--resume` 경로가 깨지지 않도록 그대로 둔다.
    """
    sources = existing_outputs(base)
    if not sources:
        return []
    target = interrupted_base(base)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return sources           # 폴더를 못 만들어도 부분 결과 자체는 계속 기록한다
    renamed: list[str] = []
    for source in sources:
        destination = Path(str(target) + Path(source).suffix)
        try:
            os.replace(source, destination)
        except OSError:
            renamed.append(source)
            continue
        renamed.append(str(destination))
    return renamed


def run_nmap_process(cmd: list[str]) -> int:
    """nmap 한 번 실행. 정지 신호를 받으면 곧바로 죽이지 않고 잠깐 기다린다.

    터미널 Ctrl+C 와 GUI [중지]는 프로세스 그룹 전체에 신호를 보내므로 nmap 도 같은 신호를
    이미 받은 상태다. nmap 은 그때 진행분을 -oA 파일로 마저 쓰고 종료하는데, 여기서 바로
    kill 하면 그 부분 결과가 통째로 사라진다. 유예 후에도 살아 있으면 단계적으로 종료한다.
    """
    proc = subprocess.Popen(cmd, shell=False)
    try:
        return proc.wait()
    except KeyboardInterrupt:
        try:
            proc.wait(timeout=NMAP_STOP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=NMAP_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        raise


def open_ports_from_xml(path: Path, protocol: str = "tcp") -> list[int]:
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    protocol = protocol.lower()
    ports: set[int] = set()
    for port in root.findall(".//port"):
        if (port.get("protocol") or "").lower() != protocol:
            continue
        state = port.find("state")
        if state is None or not (state.get("state") or "").lower().startswith("open"):
            continue
        try:
            ports.add(int(port.get("portid") or ""))
        except ValueError:
            continue
    return sorted(ports)


def open_host_ports_from_xml(path: Path, protocol: str = "tcp") -> list[tuple[str, int]]:
    """열린 (호스트, 포트) 쌍 목록. 서로 다른 호스트의 같은 포트번호를 구분해 노출 규모를 정확히 센다(QA-039).
    포트번호만 세면 50개 호스트가 443 을 열어도 1 로 집계돼 공격면을 크게 과소보고한다."""
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    protocol = protocol.lower()
    pairs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for host in root.findall(".//host"):
        ip = ""
        for addr in host.findall("address"):
            if (addr.get("addrtype") or "").lower() == "mac":
                continue
            if addr.get("addr"):
                ip = addr.get("addr") or ""
                break
        if not ip:
            # 사용 가능한(비-MAC) 주소가 없으면 건너뛴다 — live_hosts_from_xml / hosts_with_open_ports_from_xml
            # 의 가드와 일관되게 ('', port) 유령 쌍이 open_tcp 를 부풀려 live=0 인데 open>0 이 되는 모순 방지(QA-050).
            continue
        for port in host.findall(".//port"):
            if (port.get("protocol") or "").lower() != protocol:
                continue
            state = port.find("state")
            if state is None or not (state.get("state") or "").lower().startswith("open"):
                continue
            try:
                pid = int(port.get("portid") or "")
            except ValueError:
                continue
            key = (ip, pid)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def live_hosts_from_xml(path: Path) -> list[str]:
    """discovery XML 에서 status=up 인 호스트 주소만 추출(identify 타깃 좁히기)."""
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for host in root.findall(".//host"):
        status = host.find("status")
        if status is None or (status.get("state") or "").lower() != "up":
            continue
        for addr in host.findall("address"):
            # MAC(addrtype="mac")은 TARGET_RE 에 매치되지만 nmap 타깃이 될 수 없어 제외.
            if (addr.get("addrtype") or "").lower() == "mac":
                continue
            ip = addr.get("addr") or ""
            # nmap 자체 출력이지만 argv 주입 전 한 번 더 검증.
            if ip and ip not in seen and TARGET_RE.fullmatch(ip):
                seen.add(ip)
                hosts.append(ip)
    return hosts


def hosts_with_open_ports_from_xml(path: Path) -> list[str]:
    """열린 포트가 1개 이상인 호스트 주소만 추출(status 무관). 열린 포트가 있으면 그 호스트는 확실히
    살아있다 → discovery 가 없는 단일 워크플로나 UDP 전용 호스트의 live 집계 보정용(QA-030).
    -Pn 이 죽은 호스트를 up 으로 표시해도 '열린 포트' 조건이라 과집계되지 않는다."""
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for host in root.findall(".//host"):
        has_open = any(
            (state := port.find("state")) is not None
            and (state.get("state") or "").lower().startswith("open")
            for port in host.findall(".//port")
        )
        if not has_open:
            continue
        for addr in host.findall("address"):
            if (addr.get("addrtype") or "").lower() == "mac":
                continue
            ip = addr.get("addr") or ""
            if ip and ip not in seen and TARGET_RE.fullmatch(ip):
                seen.add(ip)
                hosts.append(ip)
    return hosts


def xml_parse_ok(path: Path) -> bool:
    """XML 이 존재하고 파싱 가능한지. discovery 결과가 손상(잘린 XML 등)됐는지 판단용."""
    if not path.exists():
        return False
    try:
        ET.parse(path)
    except ET.ParseError:
        return False
    return True


def xml_run_completed(path: Path, target_count: int) -> bool:
    """Validate the Nmap completion counters required for absent-result closure authority."""
    if target_count < 1 or not path.exists():
        return False
    try:
        root = ET.parse(path).getroot()
        finished = root.findall("./runstats/finished")
        hosts = root.findall("./runstats/hosts")
        if len(finished) != 1 or len(hosts) != 1 or finished[0].get("exit") != "success":
            return False
        up = int(hosts[0].get("up", ""))
        down = int(hosts[0].get("down", ""))
        total = int(hosts[0].get("total", ""))
    except (ET.ParseError, TypeError, ValueError):
        return False
    return up >= 0 and down >= 0 and up + down == total == target_count


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def xml_has_hosts(path: Path) -> bool:
    """파싱 가능하고 host 항목이 하나라도 있는지. rc≠0 단계의 부분 XML 도 쓸만하면 manifest 에 포함하기 위함."""
    if not path.exists():
        return False
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return False
    return root.find(".//host") is not None


def xml_has_usable_host(path: Path) -> bool:
    """import 가치가 있는 host 가 있는지: status=up 호스트가 있거나 열린 포트를 가진 호스트가 있는지.
    단순 <host> 엘리먼트 존재(xml_has_hosts)보다 엄격하다 — MAC-only/유령 호스트나 status=down + 전부
    필터/닫힘인 '빈' 식별 XML 이 importable 로 잘못 잡혀 discovery 구제 fallback 을 막는 것을 방지(QA-056).
    QA-050 의 집계 헬퍼와 동일한 '쓸만한 host' 기준을 쓴다."""
    return bool(live_hosts_from_xml(path) or hosts_with_open_ports_from_xml(path))


def run_stage_name(stage_id: str) -> str:
    return dict(AUTO_STAGES).get(stage_id, stage_id)


def stage_succeeded(plan: dict, batch_index: int, stage_id: str) -> bool:
    for run in plan.get("runs", []):
        run_batch = run.get("batch_index", run.get("index"))
        if run_batch == batch_index and run.get("stage_id", "") == stage_id and run.get("returncode") == 0 and not run.get("skipped"):
            # 성공으로 기록됐어도 '.xml 산출물'이 사라졌으면 재스캔되도록 성공으로 보지 않는다(QA-041).
            # manifest 가 광고하는 것은 .xml 이므로, .nmap/.gnmap 형제가 남아있어도 .xml 이 없으면 vanished 로
            # 본다 — 그렇지 않으면 .xml 만 지워졌을 때 재실행이 안 돼 importable 결과가 영구 손실된다(QA-051).
            xmls = [f for f in run.get("files", []) if str(f).lower().endswith(".xml")]
            if xmls and not any(Path(f).exists() for f in xmls):
                continue
            return True
    return False


def stage_recorded(plan: dict, batch_index: int, stage_id: str) -> bool:
    for run in plan.get("runs", []):
        run_batch = run.get("batch_index", run.get("index"))
        if run_batch == batch_index and run.get("stage_id", "") == stage_id:
            return True
    return False


def append_skipped_stage(plan: dict, batch_index: int, stage_id: str, reason: str) -> None:
    if stage_recorded(plan, batch_index, stage_id):
        return
    base = output_base(plan, batch_index, stage_id)
    plan["runs"].append({
        "index": batch_index,
        "batch_index": batch_index,
        "stage_id": stage_id,
        "stage_name": run_stage_name(stage_id),
        "started_at": now_iso(),
        "finished_at": now_iso(),
        "returncode": 0,
        "skipped": True,
        "skip_reason": reason,
        "command": [],
        "output_base": str(base),
        "files": [],
    })


def write_json(path: Path, data: dict) -> None:
    # 원자적 쓰기: 임시파일에 쓴 뒤 os.replace 로 교체한다. 중간에 실패해도 기존 state 파일이
    # 손상되거나 절반만 쓰인 채 남지 않는다(QA-043).
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ── 사용자 정의 프리셋: 파일 저장 · 서버 도킹 동기화 ──
# 파일 형식은 ScanOps 웹서버(backend/scanops/scanning/preset_store.py)와 동일하다.
# 같은 내용의 파일이 스캐너 폴더와 서버 data/ 양쪽에 존재하며 --sync 로 합집합을 맞춘다.

def default_preset_path() -> Path:
    """프리셋 파일 기본 위치 — 이 스크립트와 같은 폴더(단독 스캐너 폴더에 따로 보관)."""
    return Path(__file__).resolve().with_name(PRESET_FILE_NAME)


def preset_name_key(name: str) -> str:
    """충돌 판정용 이름 키 — 앞뒤/연속 공백과 대소문자 차이는 같은 이름으로 본다."""
    return " ".join(str(name or "").split()).casefold()


def normalize_preset_workflow(value: str) -> str:
    workflow = PRESET_WORKFLOW_ALIASES.get(str(value or "single").strip().lower())
    if workflow is None:
        raise ValueError(f"프리셋 workflow 는 auto 또는 single 이어야 합니다: {value!r}")
    return workflow


def _preset_text(value, label: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if CONTROL_CHAR_RE.search(text):
        raise ValueError(f"프리셋 {label}에 사용할 수 없는 문자가 있습니다.")
    if len(text) > limit:
        raise ValueError(f"프리셋 {label}은 {limit}자 이내여야 합니다.")
    return text


def _preset_keys(values, label: str, allowed: dict) -> list[str]:
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise ValueError(f"프리셋 {label}은 문자열 목록이어야 합니다.")
    selected = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"프리셋 {label}은 문자열 목록이어야 합니다.")
        if value not in allowed:
            raise ValueError(f"알 수 없는 프리셋 {label} 항목: {value!r}")
        if value not in selected:
            selected.append(value)
    # 레지스트리 순서로 고정 → 선택 순서가 달라도 같은 프리셋은 같은 지문을 갖는다.
    return [key for key in allowed if key in set(selected)]


def normalize_preset(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("프리셋 항목이 객체가 아닙니다.")
    name = _preset_text(raw.get("name"), "이름", PRESET_MAX_NAME_LEN)
    if not name:
        raise ValueError("프리셋 이름이 비어 있습니다.")
    if any(token in name for token in PRESET_NAME_FORBIDDEN):
        raise ValueError("프리셋 이름에 / 또는 \\ 를 쓸 수 없습니다.")
    return {
        "name": name,
        "description": _preset_text(raw.get("description"), "설명", PRESET_MAX_DESC_LEN),
        "workflow": normalize_preset_workflow(raw.get("workflow")),
        "options": _preset_keys(raw.get("options") or [], "options", OPTION_FLAGS),
        "ports": validate_ports(str(raw.get("ports") or "")),
        "nse": _preset_keys(raw.get("nse") or [], "nse", NSE_PROTO),
        "updated_at": _preset_text(raw.get("updated_at"), "updated_at", 40) or now_iso(),
    }


def normalize_presets(raw_presets) -> list[dict]:
    if isinstance(raw_presets, dict):
        raw_presets = raw_presets.get("presets")
    if raw_presets is None:
        return []
    if not isinstance(raw_presets, (list, tuple)):
        raise ValueError("presets 는 목록이어야 합니다.")
    if len(raw_presets) > PRESET_MAX_COUNT:
        raise ValueError(f"프리셋은 최대 {PRESET_MAX_COUNT}개까지 저장할 수 있습니다.")
    out: list[dict] = []
    seen: set = set()
    for raw in raw_presets:
        preset = normalize_preset(raw)
        key = preset_name_key(preset["name"])
        if key in seen:
            raise ValueError(f"프리셋 이름이 중복됩니다: {preset['name']}")
        seen.add(key)
        out.append(preset)
    return sorted(out, key=lambda p: preset_name_key(p["name"]))


def preset_fingerprint(preset: dict) -> str:
    """내용 지문 — 설명/시각 같은 메타는 빼고 '실제 스캔 동작'만 비교한다.
    설명만 다른 두 프리셋까지 충돌로 보면 동기화가 계속 사람 손을 요구하게 된다."""
    body = {
        "workflow": preset["workflow"],
        "options": sorted(preset["options"]),
        "ports": preset["ports"],
        "nse": sorted(preset["nse"]),
    }
    blob = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def diff_presets(local: list[dict], remote: list[dict]) -> dict:
    """같은 이름 + 다른 내용 = 충돌. 하나라도 있으면 어느 쪽도 바꾸지 않는다."""
    local_by = {preset_name_key(p["name"]): p for p in local}
    remote_by = {preset_name_key(p["name"]): p for p in remote}
    conflicts = [
        {"name": local_by[key]["name"], "remote_name": remote_by[key]["name"]}
        for key in sorted(set(local_by) & set(remote_by))
        if preset_fingerprint(local_by[key]) != preset_fingerprint(remote_by[key])
    ]
    # 같은 스캔인데 설명/이름 표기만 다른 항목. 충돌은 아니지만(그렇게 보면 동기화가 계속
    # 사람 손을 요구한다) 병합이 서버 값으로 맞추므로, 로컬 표기가 바뀐다는 사실은 보고한다.
    metadata_changed = [
        {"name": local_by[key]["name"], "remote_name": remote_by[key]["name"]}
        for key in sorted(set(local_by) & set(remote_by))
        if preset_fingerprint(local_by[key]) == preset_fingerprint(remote_by[key])
        and (local_by[key]["description"] != remote_by[key]["description"]
             or local_by[key]["name"] != remote_by[key]["name"])
    ]
    return {
        "conflicts": conflicts,
        "metadata_changed": metadata_changed,
        "only_local": [local_by[key] for key in sorted(set(local_by) - set(remote_by))],
        "only_remote": [remote_by[key] for key in sorted(set(remote_by) - set(local_by))],
    }


def merge_presets(local: list[dict], remote: list[dict]) -> list[dict]:
    merged = {preset_name_key(p["name"]): p for p in local}
    merged.update({preset_name_key(p["name"]): p for p in remote})
    return sorted(merged.values(), key=lambda p: preset_name_key(p["name"]))


def load_presets(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"프리셋 파일을 해석할 수 없습니다: {path} ({exc})")
    if not isinstance(data, dict):
        raise ValueError(f"프리셋 파일 형식이 올바르지 않습니다: {path}")
    schema = data.get("schema", PRESET_SCHEMA)
    if not isinstance(schema, int) or schema > PRESET_SCHEMA:
        raise ValueError(
            f"프리셋 파일 스키마({schema})가 이 버전보다 새것입니다. 스캐너를 업데이트하세요: {path}"
        )
    return normalize_presets(data.get("presets"))


def save_presets(path: Path, presets: list[dict]) -> list[dict]:
    path = Path(path)
    normalized = normalize_presets(presets)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, {"schema": PRESET_SCHEMA, "updated_at": now_iso(), "presets": normalized})
    return normalized


def find_preset(presets: list[dict], name: str) -> dict | None:
    key = preset_name_key(name)
    return next((p for p in presets if preset_name_key(p["name"]) == key), None)


def option_flags(options: list[str]) -> list[str]:
    """옵션 키 → nmap 플래그(레지스트리 순서, 결정적). 타이밍은 마지막 하나만 남긴다."""
    selected = set(options)
    timing = [key for key in OPTION_TIMING_KEYS if key in selected]
    if len(timing) > 1:
        selected -= set(timing[:-1])
    flags: list[str] = []
    for key, values in OPTION_FLAGS.items():
        if key in selected:
            flags.extend(values)
    return flags


def preset_summary(preset: dict) -> str:
    ports = preset["ports"] or "(프로필 기본)"
    nse = f"{len(preset['nse'])}종" if preset["nse"] else "없음"
    return (f"{preset['name']}  [{preset['workflow']}] ports={ports} "
            f"options={len(preset['options'])}개 nse={nse}")


def preset_from_args(args: argparse.Namespace, name: str) -> dict:
    """현재 CLI 구성을 프리셋 한 건으로 만든다.

    프리셋 본문은 옵션 키로만 표현된다. --profile quick/light 는 `--top-ports` 를 쓰는데
    이 값은 웹 옵션 레지스트리에 없어 키로 표현할 수 없으므로 정직하게 거절하고
    --options/--ports 로 다시 표현하도록 안내한다.
    """
    options = parse_option_keys(getattr(args, "options", ""))
    workflow = normalize_preset_workflow(args.workflow)
    if not options:
        if workflow == "auto":
            options = list(DEFAULT_AUTO_PRESET_OPTIONS)
            # 'TCP만'은 옵션 키가 아니라 별도 스위치다. 프리셋 본문에서는 udp 를 빼는 것으로 표현해야
            # 이 프리셋을 다시 불렀을 때도 UDP 단계가 꺼진다(웹의 자동 스캔과 같은 규칙).
            if getattr(args, "tcp_only", False):
                options = [key for key in options if key != "udp"]
        elif args.profile in PROFILE_PRESET_OPTIONS:
            options = list(PROFILE_PRESET_OPTIONS[args.profile])
        else:
            raise ValueError(
                f"--profile {args.profile} 는 --top-ports 를 사용해 옵션 키로 표현할 수 없습니다. "
                "--options 와 --ports 로 구성을 지정한 뒤 저장하세요."
            )
    ports = validate_ports(args.ports)
    if not ports:
        if args.all_ports:
            ports = "T:1-65535"
        elif not getattr(args, "options", "") and workflow == "single":
            ports = PROFILE_PRESET_PORTS.get(args.profile, "")
    if getattr(args, "no_scripts", False):
        nse: list[str] = []
    else:
        nse = parse_nse_keys(args.scripts)
        if not nse and (args.nse_default or workflow == "auto"
                        or args.profile in PROFILE_PRESET_NSE):
            nse = list(DEFAULT_PRESET_NSE)
    return normalize_preset({
        "name": name,
        "description": getattr(args, "preset_description", "") or "",
        "workflow": workflow,
        "options": options,
        "ports": ports,
        "nse": nse,
    })


def parse_option_keys(value: str) -> list[str]:
    keys = [token for token in re.split(r"[,\s]+", str(value or "").strip()) if token]
    unknown = [key for key in keys if key not in OPTION_FLAGS]
    if unknown:
        raise ValueError(
            f"알 수 없는 스캔 옵션 키: {unknown}. 사용 가능: {', '.join(OPTION_FLAGS)}"
        )
    return keys


def parse_nse_keys(value: str) -> list[str]:
    keys = [token for token in re.split(r"[,\s]+", str(value or "").strip()) if token]
    unknown = [key for key in keys if key not in NSE_PROTO]
    if unknown:
        raise ValueError(f"알 수 없는 NSE 스크립트: {unknown}")
    return keys


def apply_preset_to_args(args: argparse.Namespace, preset: dict) -> None:
    """프리셋 → CLI args. 명령줄에서 직접 준 --ports 는 프리셋보다 우선한다.

    자동 워크플로는 단계별 고정 플래그를 쓰므로 프리셋에서 반영되는 것은 스캔 방식(-sS/-sT),
    타이밍(-T*), 포트, NSE, 열린 포트 표시, UDP 단계 사용 여부다. 나머지 상세 옵션은
    단일 실행(single)에서만 그대로 나간다 — README 에 같은 내용을 적어 두었다.
    """
    options = list(preset["options"])
    args.workflow = "auto" if preset["workflow"] == "auto" else "single"
    args.preset_options = options
    if not args.ports and preset["ports"]:
        args.ports = preset["ports"]
    if "connect" in options:
        args.scan_type = "connect"
    elif "syn" in options:
        args.scan_type = "syn"
    args.udp = "udp" in options
    if args.workflow == "auto" and "udp" not in options:
        # 웹의 자동 스캔도 udp 옵션이 없으면 UDP 단계를 끈다 — 같은 프리셋이 같은 단계를 돌게 맞춘다.
        args.tcp_only = True
    if "open_only" in options:
        args.open_only = True
    args.preset_timing = next(
        (OPTION_FLAGS[key][0] for key in OPTION_TIMING_KEYS if key in options), "",
    )
    if preset["nse"]:
        args.scripts = ",".join(preset["nse"])
        args.no_scripts = False
    else:
        args.no_scripts = True
        args.scripts = ""


# ── 서버 도킹(동기화) ──

def _sync_request(url: str, token: str, payload: dict | None, timeout: float) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    request.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
        except Exception:
            pass
        raise ValueError(f"서버 응답 오류 {exc.code}: {detail or exc.reason}")
    except urllib.error.URLError as exc:
        raise ValueError(f"서버에 연결할 수 없습니다: {url} ({exc.reason})")
    except (ValueError, TimeoutError) as exc:
        raise ValueError(f"서버 응답을 해석할 수 없습니다: {exc}")


def server_login(base_url: str, username: str, password: str, timeout: float) -> str:
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    request = urllib.request.Request(f"{base_url}/api/auth/login", data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))["token"]
    except urllib.error.HTTPError as exc:
        raise ValueError(f"서버 로그인 실패({exc.code}). 계정/비밀번호를 확인하세요.")
    except urllib.error.URLError as exc:
        raise ValueError(f"서버에 연결할 수 없습니다: {base_url} ({exc.reason})")
    except (KeyError, ValueError) as exc:
        raise ValueError(f"서버 로그인 응답을 해석할 수 없습니다: {exc}")


def dock(args: argparse.Namespace, preset_path: Path) -> int:
    """도킹 — 프리셋 동기화 + 스캔 결과 업로드를 한 번에.

    프리셋 충돌은 결과 업로드를 막지 않는다(둘은 독립적인 데이터다). 다만 충돌이 있었으면
    사람이 볼 수 있도록 종료 코드로 남긴다.
    """
    base_url, token = _dock_endpoint(args)
    what = getattr(args, "sync_only", "") or "all"
    preset_rc = 0
    if what in ("all", "presets"):
        preset_rc = sync_presets(args, preset_path, base_url=base_url, token=token)
    result_failures = 0
    if what in ("all", "results"):
        result_failures = sync_results(
            base_url, token, Path(args.output_dir), args.sync_timeout,
            resend=getattr(args, "resend_results", False),
        )
    if result_failures:
        return 1
    return preset_rc


def _dock_endpoint(args: argparse.Namespace) -> tuple[str, str]:
    """--server/--token(또는 로그인)에서 도킹 대상과 토큰을 확정한다."""
    base_url = (args.server or "").strip().rstrip("/")
    if not base_url:
        raise ValueError("--server 로 ScanOps 웹 주소를 지정하세요. 예: --server http://10.0.0.5:8770")
    if not base_url.lower().startswith(("http://", "https://")):
        raise ValueError(f"--server 는 http:// 또는 https:// 로 시작해야 합니다: {base_url}")
    token = (args.token or os.environ.get("SCANOPS_TOKEN", "")).strip()
    if token:
        return base_url, token
    # 비밀번호는 환경변수로도 받는다 — argv 는 같은 호스트의 다른 사용자에게 보인다.
    password = args.password or os.environ.get("SCANOPS_PASSWORD", "")
    if not (args.username and password):
        raise ValueError(
            "--token 또는 --username/--password 로 인증하세요"
            "(환경변수 SCANOPS_TOKEN·SCANOPS_PASSWORD 도 가능). "
            "도킹은 auditor 이상 권한이 필요합니다."
        )
    return base_url, server_login(base_url, args.username, password, args.sync_timeout)


def sync_presets(args: argparse.Namespace, preset_path: Path,
                 base_url: str = "", token: str = "") -> int:
    """단독 스캐너 프리셋 ↔ 웹 서버 프리셋 동기화(도킹).

    1) 서버 목록을 읽어 이름 충돌(같은 이름·다른 내용)이 있는지 먼저 확인한다.
    2) 충돌이 하나라도 있으면 **양쪽 모두 그대로 두고** 충돌 목록만 보고한다(코드 3).
    3) 충돌이 없으면 서버가 합집합을 저장하고, 그 최종 목록을 로컬 파일에도 그대로 쓴다.
    """
    if not (base_url and token):
        base_url, token = _dock_endpoint(args)

    local = load_presets(preset_path)
    remote_doc = _sync_request(f"{base_url}/api/scan-presets", token, None, args.sync_timeout)
    remote = normalize_presets(remote_doc.get("presets"))
    delta = diff_presets(local, remote)
    print(f"local={len(local)}건 server={len(remote)}건 "
          f"서버로 보낼 것={len(delta['only_local'])}건 서버에서 받을 것={len(delta['only_remote'])}건")
    if delta["conflicts"]:
        print("error: 같은 이름인데 내용이 다른 프리셋이 있어 동기화를 중단했습니다(양쪽 모두 변경 없음).",
              file=sys.stderr)
        for conflict in delta["conflicts"]:
            print(f"  conflict: {conflict['name']}", file=sys.stderr)
        print("한쪽 이름을 바꾸거나 내용을 같게 맞춘 뒤 다시 실행하세요.", file=sys.stderr)
        return 3

    result = _sync_request(f"{base_url}/api/scan-presets/sync", token,
                           {"presets": local}, args.sync_timeout)
    if result.get("status") == "conflict":
        # 확인과 병합 사이에 서버가 바뀐 경우(다른 사용자가 저장). 로컬도 건드리지 않는다.
        print("error: 동기화 직전에 서버 프리셋이 변경되어 충돌이 발생했습니다(양쪽 모두 변경 없음).",
              file=sys.stderr)
        for conflict in result.get("conflicts", []):
            print(f"  conflict: {conflict.get('name')}", file=sys.stderr)
        return 3
    merged = normalize_presets(result.get("presets"))
    save_presets(preset_path, merged)
    print(f"synced: {len(merged)}건 → {preset_path}")
    # 안내는 **실제로 쓴 결과**(merged)와 시작 시점의 로컬을 비교해 만든다. 위쪽 확인용 delta 는
    # 첫 GET 기준이라, 그 뒤 다른 사용자가 서버 설명을 바꿔 병합 응답에 실려 오면 로컬 파일은
    # 덮이는데 안내는 비어 있게 된다(GET→POST 사이 TOCTOU).
    for changed in diff_presets(local, merged)["metadata_changed"]:
        # 스캔 동작은 같아 충돌이 아니지만 로컬 설명/표기가 서버 값으로 바뀐다 — 조용히 넘기지 않는다.
        print(f"note: '{changed['name']}' 의 설명/이름 표기를 서버 값('{changed['remote_name']}')으로 맞췄습니다.")
    print(f"서버에 추가됨: {', '.join(result.get('added_to_server') or []) or '없음'}")
    print(f"스캐너에 추가됨: {', '.join(result.get('added_to_client') or []) or '없음'}")
    return 0


# ── 스캔 결과 도킹(업로드) ──

def result_fingerprint(xml_payloads: list[bytes]) -> str:
    """가져온 결과 단위의 내용 지문 — 서버 scans.result_fingerprint 와 같은 규칙.

    파일 내용만으로 계산하므로 폴더를 복사해 다른 경로에서 도킹해도 같은 결과로 인식된다.
    """
    parts = sorted(hashlib.sha256(payload).hexdigest() for payload in xml_payloads)
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def stage_of(name: str) -> str:
    for stage_id, _label in AUTO_STAGES:
        if name.lower().endswith(f".{stage_id}.xml"):
            return stage_id
    return ""


def collect_result_units(output_dir: Path) -> list[dict]:
    """업로드할 결과 단위 목록 — **온전히 끝난 실행만**.

    manifest 가 있는 실행의 XML 만 한 단위로 묶는다(닫힘 계약 유지).

    중단본(`interrupted/`)은 올리지 않는다. 중간에 끊긴 스캔은 열린 포트를 다 보지 못한
    상태라 그대로 받으면 **미탐**이 되고, 재시도가 잘린 자리의 filtered 를 관측으로 믿으면
    **오탐**이 된다. 발견 관리에서 그 둘은 되돌리기 가장 어려운 오류이므로, 부분 결과는
    사람이 파일을 보고 판단할 재료로만 남기고 자동 인입 경로에서는 뺀다.
    """
    output_dir = Path(output_dir)
    units: list[dict] = []
    claimed: set[Path] = set()
    for manifest_path in sorted(output_dir.glob("*.manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(manifest, dict) or manifest.get("tool") != "scanops_scanner":
            continue
        xml_paths = []
        for value in manifest.get("import_xml_files") or []:
            path = Path(value)
            if not path.is_absolute():
                path = output_dir / path.name
            if path.exists():
                xml_paths.append(path)
        if not xml_paths:
            continue
        claimed.update(xml_paths)
        units.append({
            "kind": "manifest",
            "name": manifest_path.stem.replace(".manifest", ""),
            "status": manifest.get("status", ""),
            "manifest": manifest_path,
            "xml": xml_paths,
        })

    return units


def interrupted_outputs(output_dir: Path) -> list[Path]:
    """올리지 않고 남겨 둔 중단본. 개수를 사람에게 알려 주려고만 쓴다."""
    folder = Path(output_dir) / INTERRUPTED_DIR_NAME
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.glob("*.xml") if is_interrupted_output(p))


def _multipart_body(files: list[tuple[str, str, bytes]]) -> tuple[bytes, str]:
    """multipart/form-data 본문을 표준 라이브러리만으로 조립(스캐너는 의존성이 없다)."""
    boundary = "----scanops" + hashlib.sha256(
        b"".join(payload for _f, _n, payload in files) + str(len(files)).encode()
    ).hexdigest()[:24]
    out = bytearray()
    for field, filename, payload in files:
        out += f"--{boundary}\r\n".encode()
        out += (f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        out += payload
        out += b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def _upload_unit(base_url: str, token: str, unit: dict, timeout: float,
                 skip_known: bool = True) -> dict:
    files: list[tuple[str, str, bytes]] = [
        ("files", path.name, path.read_bytes()) for path in unit["xml"]
    ]
    if unit["manifest"] is not None:
        files.append(("files", unit["manifest"].name, unit["manifest"].read_bytes()))
    body, content_type = _multipart_body(files)
    # 중복 판정은 서버가 한다 — import 단위를 나누는 것도 서버이므로, 여기서 자체 지문으로
    # 걸러내면 배치 스캔처럼 단위가 갈라지는 순간 판정이 어긋나 같은 결과가 다시 인입된다.
    url = f"{base_url}/api/scans/import-bundle" + ("?skip_known=true" if skip_known else "")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
        except Exception:
            pass
        raise ValueError(f"업로드 실패 {exc.code}: {detail or exc.reason}")
    except urllib.error.URLError as exc:
        raise ValueError(f"서버에 연결할 수 없습니다: {base_url} ({exc.reason})")


def sync_results(base_url: str, token: str, output_dir: Path, timeout: float,
                 resend: bool = False) -> int:
    """결과 폴더의 스캔 결과를 서버로 올린다(자동 인입).

    서버에 이미 있는 지문은 빼고 새 결과만 보낸다 — 그러지 않으면 도킹할 때마다 같은 결과로
    스캔 이력이 불어나고 닫힘 판정이 다시 돈다.
    """
    units = collect_result_units(output_dir)
    held = interrupted_outputs(output_dir)
    if held:
        # 조용히 빼면 '올렸겠거니' 하고 넘어간다. 몇 건을 왜 안 올렸는지 말해 준다.
        print(f"results: 중단본 {len(held)}건은 올리지 않습니다 "
              f"({INTERRUPTED_DIR_NAME}/ — 부분 결과라 오탐·미탐을 만듭니다)")
    if not units:
        print(f"results: 올릴 결과가 없습니다 ({output_dir})")
        return 0
    print(f"results: {len(units)}건 전송 (이미 가져온 것은 서버가 건너뜁니다)")

    failures = 0
    for unit in units:
        label = f"{unit['name']} [{unit['status'] or unit['kind']}]"
        try:
            result = _upload_unit(base_url, token, unit, timeout, skip_known=not resend)
        except ValueError as exc:
            print(f"  error: {label} — {exc}", file=sys.stderr)
            failures += 1
            continue
        counts = result.get("counts") or {}
        imported, skipped = result.get("imported", 0), result.get("skipped", 0)
        if imported == 0 and skipped:
            print(f"  skipped: {label} — 이미 가져온 결과 {skipped}건")
            continue
        mode = result.get("closure_mode", "")
        extra = f" · 건너뜀 {skipped}" if skipped else ""
        print(f"  uploaded: {label} → 신규 {counts.get('new', 0)} / 갱신 {counts.get('updated', 0)}"
              f" · {mode}{extra}")
    return failures


def run_preset_command(args: argparse.Namespace) -> int | None:
    """프리셋 관리 하위 명령. 스캔을 실행하지 않고 끝나면 종료 코드를, 아니면 None 을 준다."""
    preset_path = Path(args.preset_file) if args.preset_file else default_preset_path()
    if args.list_presets:
        presets = load_presets(preset_path)
        print(f"preset file: {preset_path}")
        if not presets:
            print("(저장된 프리셋 없음)")
        for preset in presets:
            print("  " + preset_summary(preset))
        return 0
    if args.delete_preset:
        presets = load_presets(preset_path)
        target = find_preset(presets, args.delete_preset)
        if target is None:
            raise ValueError(f"삭제할 프리셋이 없습니다: {args.delete_preset}")
        save_presets(preset_path, [p for p in presets if p is not target])
        print(f"deleted: {target['name']} → {preset_path}")
        return 0
    if args.save_preset:
        presets = load_presets(preset_path)
        preset = preset_from_args(args, args.save_preset)
        existing = find_preset(presets, preset["name"])
        if existing is not None and not args.overwrite_preset:
            raise ValueError(
                f"같은 이름의 프리셋이 이미 있습니다: {existing['name']}. "
                "덮어쓰려면 --overwrite-preset 을 함께 쓰세요."
            )
        presets = [p for p in presets if p is not existing] + [preset]
        save_presets(preset_path, presets)
        print(f"saved: {preset_summary(preset)} → {preset_path}")
        return 0
    if args.sync:
        return dock(args, preset_path)
    return None


def create_plan(args: argparse.Namespace) -> dict:
    nmap = find_nmap(args.nmap)
    if not nmap:
        if args.dry_run:
            nmap = args.nmap or "nmap"
        else:
            raise ValueError("nmap 을 찾을 수 없습니다. PATH 에 추가하거나 --nmap 경로를 지정하세요.")

    raw_targets = collect_targets(args)
    # --max-hosts 캡은 배치 여부와 무관하게 항상 검증(초과 시 expand_targets 가 ValueError).
    # 비배치 모드는 원본 스펙(CIDR 등)을 그대로 nmap 에 넘기되, 캡 검사만 수행.
    expanded = expand_targets(raw_targets, args.max_hosts)
    # scope 게이트: 설정 시 전개된 모든 호스트가 허용 대역 안인지 검증(밖이면 시작 전 거절).
    scope_spec = getattr(args, "scan_scope", "") or os.environ.get("SCANOPS_SCAN_SCOPE", "")
    check_scope(expanded, scope_spec)
    excludes, exclude_networks = parse_excludes(getattr(args, "exclude", []))
    effective = apply_excludes(expanded, exclude_networks)
    if not effective:
        raise ValueError("제외 대상(--exclude)을 적용하니 스캔할 호스트가 남지 않았습니다.")
    # 배치는 실제 스캔할 호스트만 저장한다. 비배치는 Windows argv 폭발을 피하려 CIDR/범위 원문을
    # 유지하고, build_command가 모든 Nmap 단계에 canonical --exclude를 적용한다.
    run_targets = effective if args.batch_size > 0 else raw_targets
    batches = make_batches(run_targets, args.batch_size)
    out_dir = Path(args.output_dir).resolve()
    name = safe_name(args.name)
    ports_override = validate_ports(args.ports)
    if ports_override:
        warn_ambiguous_ports(ports_override)
    if args.workflow == "auto" and args.tcp_only and ports_override and not protocol_ports(ports_override, "T"):
        raise ValueError("TCP만 옵션을 사용할 때는 TCP 포트를 지정해야 합니다. 예: --ports 22,443")
    intensity = validate_intensity(getattr(args, "intensity", "normal"))
    # --host-timeout 은 None 센티널로 '사용자가 지정하지 않음'을 구분한다. 지정이 없으면 저강도에서만
    # 30m 을 기본으로 켜고(느린 스캔이 한 호스트에 무한정 묶이지 않게), 기본 강도는 종전대로 꺼둔다(QA-007).
    host_timeout_raw = getattr(args, "host_timeout", None)
    if host_timeout_raw is None:
        host_timeout_raw = GENTLE_HOST_TIMEOUT_DEFAULT if intensity == "gentle" else HOST_TIMEOUT_DEFAULT
    return {
        "tool": "scanops_scanner",
        "version": VERSION,
        "status": "planned",
        "created_at": now_iso(),
        "finished_at": "",
        "nmap": nmap,
        "name": name,
        "output_dir": str(out_dir),
        "state_path": str(out_dir / f"{name}.state.json"),
        "manifest_path": str(out_dir / f"{name}.manifest.json"),
        "workflow": args.workflow,
        "profile": args.profile,
        "preset": getattr(args, "preset", "") or "",
        "preset_options": getattr(args, "preset_options", None),
        "timing": getattr(args, "preset_timing", "") or "",
        "stats_every": validate_stats_every(args.stats_every),
        "host_timeout": validate_host_timeout(host_timeout_raw),
        "base_flags": build_base_flags(args),
        "scan_type": args.scan_type,
        "ports_override": ports_override,
        "all_ports": args.all_ports,
        "tcp_only": args.tcp_only,
        "udp_all_targets": args.udp_all_targets,
        "no_scripts": args.no_scripts,
        "nse_default": args.nse_default,
        "scripts": validate_scripts(args.scripts),
        "open_only": args.open_only,
        "include_closed": args.include_closed,
        "raw_targets": raw_targets,
        "exclude": excludes,
        "exclude_ports": validate_exclude_ports(getattr(args, "exclude_ports", "")),
        "intensity": intensity,
        "max_rate": validate_max_rate(getattr(args, "max_rate", "")),
        "scan_scope": scope_spec,
        "max_hosts": args.max_hosts,
        "requested_host_count": len(expanded),
        "effective_host_count": len(effective),
        "effective_targets_sha256": effective_targets_fingerprint(effective),
        "batch_size": args.batch_size,
        "batches": batches,
        "cursor": 0,
        "runs": [],
    }


REQUIRED_STATE_KEYS = ("workflow", "output_dir", "name", "manifest_path", "batches", "cursor", "runs")


def load_plan(path: str, nmap_override: str = "", dry_run: bool = False,
              scan_scope_override: str = "") -> dict:
    p = Path(path)
    plan = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(plan, dict) or plan.get("tool") != "scanops_scanner":
        raise ValueError("scanops_scanner state 파일이 아닙니다.")
    # 손상/구버전 state 가 나중에 KeyError 트레이스백으로 터지지 않도록 필수 키를 미리 검증(QA-017).
    missing = [k for k in REQUIRED_STATE_KEYS if k not in plan]
    if missing:
        raise ValueError(f"state 파일에 필수 항목이 없습니다(손상되었거나 호환되지 않음): {missing}")

    batches = plan.get("batches")
    if not isinstance(batches, list) or not batches or any(not isinstance(batch, list) for batch in batches):
        raise ValueError("state 파일의 batches가 올바른 목록이 아닙니다.")
    saved_batch_targets = [host for batch in batches for host in batch]
    if not all(isinstance(host, str) for host in saved_batch_targets):
        raise ValueError("state 파일의 target 형식이 올바르지 않습니다.")
    validate_targets(saved_batch_targets)

    # 안전 제어 필드는 '키 부재'(구형 state)와 '명시된 값'을 구분해 되살린다.
    # plan.get() 으로 뭉개면 `"intensity": null` 한 줄로 보호가 조용히 풀린다(resumed_value 주석 참고).
    excludes, exclude_networks = parse_excludes(resumed_value(plan, "exclude", [], validate_exclude_list))
    plan["exclude"] = excludes  # 구형 state는 빈 목록으로 호환, 새 state는 canonical 형태로 재검증.
    plan["exclude_ports"] = resumed_value(plan, "exclude_ports", "", validate_exclude_ports)
    plan["intensity"] = resumed_value(plan, "intensity", "normal", validate_intensity)
    plan["max_rate"] = resumed_value(plan, "max_rate", "", validate_max_rate)
    raw_targets = plan.get("raw_targets")
    if raw_targets is None:
        raw_targets = saved_batch_targets
    if not isinstance(raw_targets, list) or not all(isinstance(host, str) for host in raw_targets):
        raise ValueError("state 파일의 raw_targets 형식이 올바르지 않습니다.")
    validate_targets(raw_targets)
    try:
        max_hosts = int(plan.get("max_hosts", 65536))
    except (TypeError, ValueError) as exc:
        raise ValueError("state 파일의 max_hosts가 올바른 정수가 아닙니다.") from exc
    if max_hosts < 1:
        raise ValueError("state 파일의 max_hosts는 1 이상이어야 합니다.")
    expanded = expand_targets(raw_targets, max_hosts)
    stored_scope = plan.get("scan_scope", "")
    if not isinstance(stored_scope, str):
        raise ValueError("state 파일의 scan_scope 형식이 올바르지 않습니다.")
    # 저장 당시 경계는 resume에서 절대 완화하지 않는다. 현재 CLI/환경 scope가 있으면 그것도
    # 추가로 통과해야 하므로 실제 허용 범위는 stored ∩ current가 된다.
    if stored_scope:
        check_scope(expanded, stored_scope)
    current_scope = scan_scope_override or os.environ.get("SCANOPS_SCAN_SCOPE", "")
    if current_scope:
        check_scope(expanded, current_scope)
    effective = apply_excludes(expanded, exclude_networks)
    if not effective:
        raise ValueError("저장된 제외 대상(--exclude)을 적용하니 재개할 호스트가 남지 않았습니다.")
    if "requested_host_count" in plan and plan["requested_host_count"] != len(expanded):
        raise ValueError("state 파일의 요청 호스트 수가 저장된 target과 일치하지 않습니다.")
    if "effective_host_count" in plan and plan["effective_host_count"] != len(effective):
        raise ValueError("state 파일의 유효 호스트 수가 저장된 exclude와 일치하지 않습니다.")
    effective_fingerprint = effective_targets_fingerprint(effective)
    if ("effective_targets_sha256" in plan
            and plan["effective_targets_sha256"] != effective_fingerprint):
        raise ValueError("state 파일의 유효 호스트 지문이 저장된 target/exclude 계획과 일치하지 않습니다.")
    batch_size = int(plan.get("batch_size", 0))
    expected_batches = make_batches(effective, batch_size) if batch_size > 0 else make_batches(raw_targets, 0)
    if batches != expected_batches:
        raise ValueError("state 파일의 batches가 저장된 target/exclude 계획과 일치하지 않습니다.")
    plan["raw_targets"] = raw_targets
    plan["max_hosts"] = max_hosts
    plan["requested_host_count"] = len(expanded)
    plan["effective_host_count"] = len(effective)
    plan["effective_targets_sha256"] = effective_fingerprint
    if plan.get("status") == "running":
        print("warning: 이 state 는 'running' 상태입니다(중단되었거나 다른 스캔이 진행 중일 수 있음). "
              "동일 state 로 동시에 두 스캔을 돌리지 마세요.", file=sys.stderr)
    nmap = find_nmap(nmap_override) if nmap_override else find_nmap(plan.get("nmap", ""))
    if not nmap and dry_run:
        nmap = nmap_override or plan.get("nmap", "") or "nmap"
    if not nmap:
        raise ValueError("nmap 을 찾을 수 없습니다. PATH 에 추가하거나 --nmap 경로를 지정하세요.")
    plan["nmap"] = nmap
    plan["state_path"] = str(p.resolve())
    return plan


def print_plan(plan: dict) -> None:
    print(f"output: {plan['output_dir']}")
    print(f"batches: {len(plan['batches'])}")
    for idx in range(plan["cursor"], len(plan["batches"])):
        if plan.get("workflow", "single") == "auto":
            if auto_tcp_discovery_ports(plan):
                print(f"# {idx + 1}/{len(plan['batches'])} {run_stage_name('tcp_discovery')}")
                print(display_command(build_command(plan, idx, "tcp_discovery")))
                print(f"# {idx + 1}/{len(plan['batches'])} {run_stage_name('tcp_identify')}")
                print(display_command(build_command(plan, idx, "tcp_identify", [0])).replace("T:0", "T:<open TCP ports from previous step>"))
            else:
                print(f"# {idx + 1}/{len(plan['batches'])} TCP 포트가 지정되지 않아 TCP 단계는 건너뜁니다.")
            # 미리보기는 실제 실행과 일치해야 한다: connect(권한 불필요) 모드는 execute_auto 가 UDP 단계를
            # 건너뛰므로(QA-010) 미리보기에도 띄우지 않는다. 안 그러면 절대 안 도는 -sT+-sU(무효 조합)를
            # 광고하게 된다(QA-059).
            if not plan.get("tcp_only") and plan.get("scan_type") != "connect" and auto_udp_ports(plan):
                print(f"# {idx + 1}/{len(plan['batches'])} {run_stage_name('udp_identify')}")
                print(display_command(build_command(plan, idx, "udp_identify")))
            elif plan.get("scan_type") == "connect" and not plan.get("tcp_only"):
                print(f"# {idx + 1}/{len(plan['batches'])} UDP 단계는 connect(권한 불필요) 모드에서 건너뜁니다.")
        else:
            print(display_command(build_command(plan, idx)))


def manifest_xml_files(run: dict) -> list[str]:
    """이 run 에서 import 할 XML 목록. rc==0 은 그대로, rc≠0(부분 실패) 은 파싱되고 host 가 있는 XML 만 포함.
    nmap 이 일부 호스트를 스캔하고도 비정상 종료(host down/NSE 오류 등)한 경우 그 부분 결과를 살린다(QA-005)."""
    if run.get("skipped"):
        return []
    xmls = [p for p in run.get("files", []) if str(p).lower().endswith(".xml")]
    if run.get("returncode") == 0:
        # 기록 당시 존재했어도 이후 삭제/유실됐을 수 있으므로 실제 존재하는 것만 광고한다(QA-041).
        return [p for p in xmls if Path(p).exists()]
    return [p for p in xmls if xml_has_hosts(Path(p))]


def import_contract_unit(plan: dict, run: dict, xml_path: Path) -> dict:
    stage_id = run.get("stage_id", "") or "single"
    targets = run.get("scan_targets")
    targets_complete = run.get("scan_targets_complete") is True
    if not isinstance(targets, list) or not all(isinstance(host, str) for host in targets):
        targets, targets_complete = [], False  # old state: preserve import, but never infer absence
    authoritative = bool(
        run.get("returncode") == 0
        and not run.get("skipped")
        and not plan.get("host_timeout")
        and stage_id in {"single", "tcp_discovery", "udp_identify"}
        and targets_complete
        and xml_run_completed(xml_path, len(targets))
    )
    return {
        "batch_index": run_batch(run),
        "stage_id": stage_id,
        "authoritative": authoritative,
        "closure_targets": targets if authoritative else [],
        "xml_basename": xml_path.name,
        "xml_size": xml_path.stat().st_size,
        "xml_sha256": file_sha256(xml_path),
    }


def build_import_contract(plan: dict, import_xml_files: list[str] | None = None) -> dict | None:
    """Build the allowlisted, versioned sidecar contract consumed by ScanOps web import.

    The surrounding manifest intentionally remains human-friendly and may contain absolute
    paths/commands. Only this object is closure authority, and every unit is bound to the
    original Nmap XML bytes.
    """
    max_hosts = min(int(plan.get("max_hosts", IMPORT_CONTRACT_MAX_HOSTS)), IMPORT_CONTRACT_MAX_HOSTS)
    raw_targets = list(plan.get("raw_targets") or [host for batch in plan["batches"] for host in batch])
    try:
        expanded = expand_targets(raw_targets, max_hosts)
    except ValueError:
        # The standalone scanner can intentionally raise --max-hosts above the web import
        # authority cap. Keep producing its legacy manifest instead of failing after Nmap;
        # such oversized runs remain observation-only when imported.
        return None
    excludes, exclude_networks = parse_excludes(plan.get("exclude", []))
    effective = apply_excludes(expanded, exclude_networks)
    # A hostname is resolved by Nmap only at execution time, so the sidecar cannot prove
    # which IPv4 address produced the XML. Preserve that valid workflow with legacy
    # observed-host semantics instead of emitting a strong contract the web importer must
    # (and should) reject as unbound.
    for host in effective:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None
        if not isinstance(address, ipaddress.IPv4Address) or str(address) != host:
            return None
    selected_xml = set(
        import_xml_files
        if import_xml_files is not None
        else importable_xml(plan, include_discovery_fallback=True)
    )
    units = []
    for run in latest_runs(plan):
        for value in manifest_xml_files(run):
            if value in selected_xml:
                units.append(import_contract_unit(plan, run, Path(value)))
    return {
        "schema": IMPORT_CONTRACT_SCHEMA,
        "raw_targets": raw_targets,
        "exclude": excludes,
        "max_hosts": max_hosts,
        "requested_host_count": len(expanded),
        "effective_host_count": len(effective),
        "effective_targets_sha256": effective_targets_fingerprint(effective),
        "batch_size": min(max(0, int(plan.get("batch_size", 0))), max_hosts),
        "host_timeout": plan.get("host_timeout", ""),
        "units": units,
    }


def write_manifest(plan: dict, zip_path: str = "") -> None:
    manifest = dict(plan)
    manifest["state_path"] = plan.get("state_path", "")
    manifest["zip_path"] = zip_path
    runs = latest_runs(plan)
    manifest["all_xml_files"] = list(dict.fromkeys(
        p for run in runs for p in manifest_xml_files(run)
    ))
    # The strong contract and the recommended upload list are one exact set. Diagnostic or
    # unusable XML may remain in all_xml_files/on disk, but cannot invalidate completed units.
    import_xml_files = importable_xml(plan, include_discovery_fallback=True)
    # Very old/minimal state files can still be summarized, but they cannot prove the original
    # requested target plan. Keep them on observed-host import semantics instead of inventing it.
    if isinstance(plan.get("batches"), list) and plan.get("batches"):
        contract = build_import_contract(plan, import_xml_files)
        if contract is not None:
            manifest["import_contract"] = contract
        else:
            manifest.pop("import_contract", None)
    else:
        manifest.pop("import_contract", None)
    # identify 산출물이 하나도 없으면 성공한 discovery XML 을 구제 fallback 으로 추천한다(QA-038).
    manifest["import_xml_files"] = import_xml_files
    write_json(Path(plan["manifest_path"]), manifest)


def create_zip(plan: dict) -> str:
    out_dir = Path(plan["output_dir"])
    zip_path = out_dir / f"{plan['name']}.scanops.zip"
    wanted = {Path(plan["manifest_path"]), Path(plan["state_path"])}
    for run in plan["runs"]:
        wanted.update(Path(p) for p in run.get("files", []))
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(wanted):
            if path.exists():
                zf.write(path, arcname=path.name)
    return str(zip_path)


def run_batch(run: dict) -> int:
    return run.get("batch_index", run.get("index"))


def latest_runs(plan: dict) -> list[dict]:
    """(batch, stage) 별 마지막 실행만 남긴다. --resume 으로 재시도해 성공한 단계가
    예전 실패 기록에 가려지지 않도록(상태/요약/manifest 일관성)."""
    by_key: dict[tuple, dict] = {}
    for run in plan.get("runs", []):
        by_key[(run_batch(run), run.get("stage_id", ""))] = run
    return list(by_key.values())


def failed_runs(plan: dict) -> list[dict]:
    """비정상 종료(rc≠0)했고 건너뛰지 않은 단계들(각 단계의 최신 시도 기준). best-effort 실패 집계용."""
    return [r for r in latest_runs(plan) if not r.get("skipped") and r.get("returncode") not in (0, None)]


def importable_xml(plan: dict, include_discovery_fallback: bool = False) -> list[str]:
    """Importable XML, including completed authoritative units with zero observed hosts.

    Observation-only identify/partial output still needs a usable host. Completed discovery,
    UDP, and single units are retained because their manifest contract can close an included
    but unobserved target. Old states without unit target evidence keep the legacy fallback.
    """
    seen: dict[str, None] = {}
    for run in latest_runs(plan):
        for p in manifest_xml_files(run):
            path = Path(p)
            if import_contract_unit(plan, run, path)["authoritative"]:
                seen[p] = None
                continue
            if run.get("stage_id", "") == "tcp_discovery":
                # New states know the concrete unit targets, so a usable failed/partial
                # discovery can be imported safely as observation-only beside later stages.
                # Old states retain the legacy discovery-only fallback below.
                if run.get("scan_targets_complete") is True and xml_has_usable_host(path):
                    seen[p] = None
                continue
            # '쓸만한 host'(status=up 또는 열린 포트)가 든 식별 XML 만 importable 로 센다. host 없는 빈 XML
            # (QA-049)이나 MAC-only/유령·down-전부필터 host(QA-056)가 seen 을 차지하면 discovery 구제
            # fallback 이 막혀 실데이터가 든 discovery XML 이 누락된다.
            if xml_has_usable_host(path):
                seen[p] = None
    if seen or not include_discovery_fallback:
        return list(seen)
    # fallback 은 host 가 실제로 든 성공 discovery XML 만 구제한다. host 0 인 빈 discovery(살아있는 호스트
    # 없음)까지 살리면 '빈 스캔'이 import 가능한 것처럼 잘못 보고된다(QA-038 ↔ QA-012 경계).
    for run in latest_runs(plan):
        if run.get("stage_id", "") != "tcp_discovery":
            continue
        for p in manifest_xml_files(run):
            if xml_has_usable_host(Path(p)):
                seen[p] = None
    return list(seen)


def scan_findings(plan: dict) -> dict:
    """결과 요약 집계: 살아있는 호스트 수, 열린 TCP/UDP (호스트,포트) 수, import XML 개수."""
    live: set[str] = set()
    tcp: set[tuple[str, int]] = set()
    udp: set[tuple[str, int]] = set()
    for run in latest_runs(plan):
        if run.get("skipped"):
            continue
        for p in run.get("files", []):
            if not str(p).lower().endswith(".xml"):
                continue
            path = Path(p)
            stage = run.get("stage_id", "")
            if stage == "tcp_discovery":
                live.update(live_hosts_from_xml(path))
                # discovery 가 찾은 열린 TCP 를 floor 로 집계: identify 가 건너뛰거나 실패해도 open_tcp 가
                # 0 으로 떨어지지 않는다(QA-040). set 이라 identify 재관측분과 중복되지 않는다.
                tcp.update(open_host_ports_from_xml(path, "tcp"))
            elif stage == "udp_identify":
                udp.update(open_host_ports_from_xml(path, "udp"))
                # discovery 가 없거나 UDP 전용으로 살아난 호스트도 live 로 집계(QA-030).
                live.update(hosts_with_open_ports_from_xml(path))
            else:  # tcp_identify or single
                tcp.update(open_host_ports_from_xml(path, "tcp"))
                udp.update(open_host_ports_from_xml(path, "udp"))
                # 단일 워크플로(discovery 없음)는 여기서만 호스트를 보므로 열린 포트 호스트를 live 로 센다(QA-030).
                live.update(hosts_with_open_ports_from_xml(path))
    return {
        "live_hosts": len(live),
        "open_tcp": len(tcp),
        "open_udp": len(udp),
        "importable": len(importable_xml(plan, include_discovery_fallback=True)),
    }


def finalize_plan(plan: dict, state_path: Path, zip_outputs: bool) -> int:
    """단계별 best-effort 결과를 모아 플랜을 마감한다.
    - done:    실패한 단계 없음(빈 결과여도 정직하게 done + 경고).
    - partial: 일부 단계 실패했지만 import 가능한 결과가 남음 → 사용 가능. exit 0.
    - failed:  실패가 있고 import 가능한 결과가 0 → 진짜 실패. exit 1.
    이 구조가 'UDP 한 단계 실패가 전체 스캔을 죽이던' ISSUE-001/QA-002~006 을 해소한다."""
    failed = failed_runs(plan)
    # discovery 만 성공한 경우(identify 산출물 0)에도 성공한 discovery XML 을 구제 fallback 으로 인정한다.
    # 살아있는 호스트와 열린 포트를 찾고도 'failed'(exit 1, "모든 단계 실패")로 버려지던 문제를 막는다(QA-038).
    importable = importable_xml(plan, include_discovery_fallback=True)
    if importable:
        status = "partial" if failed else "done"
    else:
        status = "failed" if failed else "done"
    plan["status"] = status
    plan["finished_at"] = now_iso()
    # --resume 이 실패한 단계를 다시 시도할 수 있도록 cursor 를 '아직 실패가 남은 가장 앞 배치'로 되돌린다.
    # (성공한 단계는 stage_succeeded 가 막아 재실행되지 않으므로, 실패 단계만 재시도된다.)
    failed_batches = [b for b in (run_batch(r) for r in failed) if b is not None]
    if failed_batches:
        plan["cursor"] = min(failed_batches)
    write_json(state_path, plan)
    zip_path = str(Path(plan["output_dir"]) / f"{plan['name']}.scanops.zip") if zip_outputs else ""
    write_manifest(plan, zip_path)
    if zip_outputs:
        create_zip(plan)
    print_scan_summary(plan, failed, status)
    print(f"{status}: {plan['manifest_path']}")
    if zip_path:
        print(f"zip: {zip_path}")
    if status != "done":
        print("resume with: --resume " + str(state_path), file=sys.stderr)
    return 0 if status in ("done", "partial") else 1


def print_scan_summary(plan: dict, failed: list[dict], status: str) -> None:
    f = scan_findings(plan)
    print(
        f"summary: live_hosts={f['live_hosts']} open_tcp={f['open_tcp']} "
        f"open_udp={f['open_udp']} import_xml={f['importable']}"
    )
    for run in failed:
        print(
            f"warning: {run.get('stage_name') or run.get('stage_id') or 'scan'} "
            f"실패(rc={run.get('returncode')}) — 부분 결과만 반영됩니다.",
            file=sys.stderr,
        )
    if not failed and f["live_hosts"] == 0 and f["open_tcp"] == 0 and f["open_udp"] == 0:
        if f["importable"]:
            print(
                "warning: 살아있는 호스트/열린 포트 관측은 없습니다. "
                "성공한 완료 범위 XML+manifest는 가져오기 시 미관측 닫힘 판정에 사용됩니다.",
                file=sys.stderr,
            )
        else:
            print(
                "warning: 가져올 결과가 없습니다(열린 포트/살아있는 호스트 0). 대상·네트워크 도달성을 확인하세요.",
                file=sys.stderr,
            )
    elif f["importable"] == 0 and not failed:
        print(
            "warning: 가져올 결과가 없습니다(열린 포트/살아있는 호스트 0). 대상·네트워크 도달성을 확인하세요.",
            file=sys.stderr,
        )
    elif status == "failed":
        print("error: 사용할 수 있는 스캔 결과가 없습니다(모든 단계 실패).", file=sys.stderr)


def run_nmap_stage(plan: dict, idx: int, state_path: Path, stage_id: str = "", tcp_ports: list[int] | None = None,
                   targets: list[str] | None = None) -> int:
    cmd = build_command(plan, idx, stage_id, tcp_ports, targets)
    scan_targets, targets_complete = concrete_scan_targets(plan, idx, targets)
    base = output_base(plan, idx, stage_id)
    started = now_iso()
    stage_label = f" {run_stage_name(stage_id)}" if stage_id else ""
    print(f"[{idx + 1}/{len(plan['batches'])}]{stage_label} {display_command(cmd)}", flush=True)
    interrupted = False
    try:
        rc = run_nmap_process(cmd)
    except KeyboardInterrupt:
        # 중단도 '일어난 일'이라 기록한다. 기록하지 않으면 중간까지 스캔한 부분 결과가
        # state 에 없는 유령 파일로 남고, 재개 후 온전한 결과에 덮어써진다.
        interrupted, rc = True, 130
    files = mark_interrupted_outputs(base) if interrupted else existing_outputs(base)
    run = {
        "index": idx,
        "batch_index": idx,
        "stage_id": stage_id,
        "stage_name": run_stage_name(stage_id) if stage_id else "",
        "started_at": started,
        "finished_at": now_iso(),
        "returncode": rc,
        "interrupted": interrupted,
        "command": cmd,
        "scan_targets": scan_targets,
        "scan_targets_complete": targets_complete,
        "output_base": str(base),
        "files": files,
    }
    plan["runs"].append(run)
    write_json(state_path, plan)
    if interrupted:
        if files:
            print("\ninterrupted outputs: " + ", ".join(Path(f).name for f in files), file=sys.stderr)
        raise KeyboardInterrupt()
    return rc


def execute_single(plan: dict, state_path: Path, zip_outputs: bool) -> int:
    # best-effort: 한 배치가 실패해도 나머지 배치는 계속 진행. 마감에서 부분/실패를 판정한다.
    # --resume 시 cursor 가 '실패한 가장 앞 배치'로 되감기므로, 이미 성공한 배치는 stage_succeeded 로
    # 건너뛴다(성공 배치 재스캔/덮어쓰기 방지 — auto 워크플로와 동일한 증분 재개).
    for idx in range(int(plan["cursor"]), len(plan["batches"])):
        if not stage_succeeded(plan, idx, ""):
            run_nmap_stage(plan, idx, state_path)
        plan["cursor"] = idx + 1
        write_json(state_path, plan)
    return finalize_plan(plan, state_path, zip_outputs)


def execute_auto(plan: dict, state_path: Path, zip_outputs: bool) -> int:
    # 핵심 설계: 각 단계는 best-effort. 한 단계(특히 UDP)의 rc≠0 이 전체 플랜을 죽이지 않는다.
    # 실패한 단계는 plan["runs"] 에 rc 와 함께 기록되어 마감에서 partial/failed 로 정직하게 집계되고,
    # --resume 시 stage_succeeded(rc==0) 가 False 이므로 자동으로 재시도된다.
    for idx in range(int(plan["cursor"]), len(plan["batches"])):
        live_hosts: list[str] | None = None
        if auto_tcp_discovery_ports(plan):
            if not stage_succeeded(plan, idx, "tcp_discovery"):
                run_nmap_stage(plan, idx, state_path, "tcp_discovery")

            discovery_xml = Path(str(output_base(plan, idx, "tcp_discovery")) + ".xml")
            # 손상/누락 XML 을 '열린 포트 0' 과 구분(QA-008): 파싱 실패면 식별 대상을 알 수 없다.
            parse_ok = xml_parse_ok(discovery_xml)
            tcp_ports = open_ports_from_xml(discovery_xml, "tcp") if parse_ok else []
            # identify 는 발견된 살아있는 호스트만 타깃(죽은 IP 재스캔 방지).
            live_hosts = (live_hosts_from_xml(discovery_xml) if parse_ok else []) or None
            if not parse_ok:
                append_skipped_stage(plan, idx, "tcp_identify",
                                     "tcp_discovery 결과 XML 이 없거나 손상되어 식별 대상을 알 수 없습니다.")
                write_json(state_path, plan)
            elif tcp_ports:
                if not stage_succeeded(plan, idx, "tcp_identify"):
                    run_nmap_stage(plan, idx, state_path, "tcp_identify", tcp_ports, live_hosts)
            else:
                append_skipped_stage(plan, idx, "tcp_identify", "tcp_discovery 에서 열린 TCP 포트를 찾지 못했습니다.")
                write_json(state_path, plan)
        else:
            append_skipped_stage(plan, idx, "tcp_discovery", "사용자가 지정한 포트에 TCP 포트가 없습니다.")
            append_skipped_stage(plan, idx, "tcp_identify", "사용자가 지정한 포트에 TCP 포트가 없습니다.")
            write_json(state_path, plan)

        if plan.get("tcp_only"):
            append_skipped_stage(plan, idx, "udp_identify", "TCP만 옵션이 선택되었습니다.")
            write_json(state_path, plan)
        elif plan.get("scan_type") == "connect":
            # TCP Connect(권한 불필요) 모드에선 -sU 를 쓸 수 없다(관리자 권한 필요) → UDP 단계는 깨끗이 건너뛴다(QA-010).
            append_skipped_stage(plan, idx, "udp_identify",
                                 "TCP Connect 모드(권한 불필요)에서는 UDP 스캔(-sU, 관리자 권한 필요)을 건너뜁니다.")
            write_json(state_path, plan)
        elif not auto_udp_ports(plan):
            append_skipped_stage(plan, idx, "udp_identify", "사용자가 지정한 포트에 UDP 포트가 없습니다.")
            write_json(state_path, plan)
        elif plan.get("udp_all_targets"):
            # 완전 커버리지(opt-in): discovery 결과 무관하게 원본 배치 전체로 UDP 식별
            # (TCP/ICMP/ACK에 다 침묵하지만 UDP만 여는 호스트·부분 누락까지 보장, 죽은 IP 비용 감수).
            if not stage_succeeded(plan, idx, "udp_identify"):
                run_nmap_stage(plan, idx, state_path, "udp_identify")
        elif auto_tcp_discovery_ports(plan):
            # discovery 를 돌렸으면 생존 호스트로만 UDP 식별(죽은 IP 재스캔 방지).
            if not live_hosts:
                append_skipped_stage(plan, idx, "udp_identify",
                                     "tcp_discovery 에서 살아있는 호스트를 찾지 못했습니다(숨은 UDP 전용 호스트는 --udp-all-targets 로 확인).")
                write_json(state_path, plan)
            elif not stage_succeeded(plan, idx, "udp_identify"):
                run_nmap_stage(plan, idx, state_path, "udp_identify", targets=live_hosts)
        elif not stage_succeeded(plan, idx, "udp_identify"):
            # discovery 를 안 돌렸으면 생존 정보가 없으므로 원본 배치 전체로 UDP 식별.
            run_nmap_stage(plan, idx, state_path, "udp_identify")

        plan["cursor"] = idx + 1
        write_json(state_path, plan)

    return finalize_plan(plan, state_path, zip_outputs)


def _raise_keyboard_interrupt(signum, frame):  # noqa: ANN001
    raise KeyboardInterrupt()


def install_stop_handlers() -> None:
    """GUI/외부에서 보낸 정지 신호를 KeyboardInterrupt 로 바꿔 interrupted 정리(상태 저장+재개 힌트)가
    실행되게 한다. Windows 의 CTRL_BREAK 는 SIGBREAK 로 오는데 파이썬은 기본적으로 이를
    KeyboardInterrupt 로 바꾸지 않으므로 직접 핸들러를 단다(QA-009). 메인 스레드에서만 가능."""
    for name in ("SIGBREAK", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _raise_keyboard_interrupt)
        except (ValueError, OSError):
            pass  # 비메인 스레드 등에서는 등록 불가 — 무시


def rewind_cursor_for_vanished_outputs(plan: dict) -> None:
    """resume 시, 성공(rc=0)으로 기록됐지만 출력 파일이 전부 사라진 단계가 있으면 그 단계가 속한 가장 앞
    배치로 cursor 를 되감아 재스캔되게 한다(QA-041). 완료(done) 플랜은 cursor 가 끝이라 그냥 두면 아무
    단계도 재실행되지 않는다. stage_succeeded 가 사라진 단계를 성공으로 보지 않으므로, 되감긴 배치에서 그
    단계만 다시 돌고 산출물이 멀쩡한 단계는 그대로 건너뛴다(fresh 플랜은 runs 가 없어 무영향)."""
    missing_batches: list[int] = []
    for run in plan.get("runs", []):
        if run.get("skipped") or run.get("returncode") != 0:
            continue
        # manifest 가 광고하는 .xml 기준으로 vanished 판정(.nmap/.gnmap 형제만 남아도 .xml 이 없으면 재실행, QA-051).
        xmls = [f for f in run.get("files", []) if str(f).lower().endswith(".xml")]
        if xmls and not any(Path(f).exists() for f in xmls):
            b = run.get("batch_index", run.get("index"))
            if b is not None:
                missing_batches.append(int(b))
    if missing_batches:
        plan["cursor"] = min(int(plan.get("cursor", 0)), min(missing_batches))


def execute(plan: dict, dry_run: bool = False, zip_outputs: bool = False) -> int:
    if dry_run:
        print_plan(plan)
        return 0

    out_dir = Path(plan["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = Path(plan["state_path"])
    install_stop_handlers()
    # resume: 성공 기록이지만 산출물이 사라진 단계가 있으면 그 배치로 cursor 를 되감아 재스캔되게 한다(QA-041).
    rewind_cursor_for_vanished_outputs(plan)
    plan["status"] = "running"
    write_json(state_path, plan)

    try:
        if plan.get("workflow", "single") == "auto":
            return execute_auto(plan, state_path, zip_outputs)
        return execute_single(plan, state_path, zip_outputs)
    except KeyboardInterrupt:
        # finalize 가 이미 최종 상태(done/partial/failed)를 디스크에 기록한 뒤의 늦은 인터럽트(예: zip 생성 중)는
        # 그 최종 상태를 덮어쓰지 않는다(QA-042). 완료된 스캔이 'interrupted' 로 둔갑하는 것을 막는다.
        if plan.get("status") in ("done", "partial", "failed"):
            return 0 if plan["status"] in ("done", "partial") else 1
        plan["status"] = "interrupted"
        plan["finished_at"] = now_iso()
        try:
            write_json(state_path, plan)
        except OSError:
            pass
        print("\ninterrupted. Resume with: --resume " + str(state_path), file=sys.stderr)
        return 130
    except OSError as exc:
        # 루프 도중 상태 저장 실패(디스크풀/읽기전용 등)로 finalize 에 도달 못 하면 status 가 'running' 으로
        # 영구히 남는다(QA-043). 가능하면 interrupted 로 낮추고 재개 힌트를 남긴다.
        if plan.get("status") not in ("done", "partial", "failed"):
            plan["status"] = "interrupted"
            plan["finished_at"] = now_iso()
            try:
                write_json(state_path, plan)
            except OSError:
                pass
        print(f"\nerror: 입출력 오류로 스캔이 중단되었습니다: {exc}\nresume with: --resume {state_path}", file=sys.stderr)
        return 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run nmap standalone and write ScanOps-importable XML.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IP/CIDR/range/hostname targets. Example: 10.0.0.1 10.0.0.20-30")
    p.add_argument("--targets-file", help="File containing targets separated by whitespace, comma, or newlines.")
    p.add_argument("--output-dir", "-o", default="scanops_scans", help="Directory for .xml/.nmap/.gnmap outputs.")
    p.add_argument("--name", "-n", help="Portable output basename. Defaults to scan_YYYYMMDD_HHMMSS.")
    p.add_argument("--nmap", default="", help="Path to nmap executable. Empty means auto-detect.")
    p.add_argument(
        "--workflow",
        choices=["auto", "single"],
        default="auto",
        help="auto runs discovery -> TCP identification -> UDP identification. single runs one profile.",
    )
    p.add_argument("--profile", choices=sorted(PRESETS), default="basic", help="Built-in scan profile for --workflow single.")
    p.add_argument("--options", default="",
                   help="Comma-separated ScanOps option keys (same vocabulary as the web UI), e.g. "
                        "syn,udp,version,version_all,fast. Replaces the built-in profile flags.")

    presets = p.add_argument_group(
        "saved presets",
        "Presets are stored next to this script in scanops_presets.json and can be synced with a "
        "ScanOps web server so both sides hold the same file.",
    )
    presets.add_argument("--preset", default="", help="Run a saved preset by name.")
    presets.add_argument("--preset-file", default="",
                         help="Preset file path. Defaults to scanops_presets.json beside this script.")
    presets.add_argument("--list-presets", action="store_true", help="List saved presets and exit.")
    presets.add_argument("--save-preset", metavar="NAME", default="",
                         help="Save the current --workflow/--options/--ports/--scripts configuration as a preset and exit.")
    presets.add_argument("--preset-description", default="", help="Description stored with --save-preset.")
    presets.add_argument("--overwrite-preset", action="store_true", help="Allow --save-preset to replace an existing name.")
    presets.add_argument("--delete-preset", metavar="NAME", default="", help="Delete a saved preset and exit.")
    presets.add_argument("--sync", action="store_true",
                         help="Dock to a ScanOps web server: sync presets and upload scan results (auto-ingested). Exits without scanning.")
    presets.add_argument("--sync-only", choices=["all", "presets", "results"], default="all",
                         help="Limit what --sync does. Default all (presets + scan results).")
    presets.add_argument("--resend-results", action="store_true",
                         help="Upload every scan result again, even ones the server already imported.")
    presets.add_argument("--server", default="", help="ScanOps web base URL for --sync. Example: http://10.0.0.5:8770")
    presets.add_argument("--token", default="", help="ScanOps API token for --sync. Falls back to the SCANOPS_TOKEN env var.")
    presets.add_argument("--username", default="", help="ScanOps account for --sync when no token is given.")
    presets.add_argument("--password", default="",
                         help="ScanOps password for --sync. Prefer the SCANOPS_PASSWORD env var: a command line is visible to other users on the same host.")
    presets.add_argument("--sync-timeout", type=float, default=15.0, help="Per-request timeout for --sync, in seconds.")
    p.add_argument("--ports", "-p", default="", help="Port spec. Overrides profile ports/top-ports.")
    p.add_argument("--all-ports", action="store_true", help="Shortcut for -p T:1-65535.")
    p.add_argument("--scan-type", choices=["connect", "syn"], default="", help="Override TCP scan type.")
    p.add_argument("--udp", action="store_true", help="Add UDP scan (-sU). Keep ports narrow when using this.")
    p.add_argument("--tcp-only", action="store_true", help="Remove UDP scan and U: ports from the selected profile.")
    p.add_argument("--udp-all-targets", action="store_true",
                   help="Auto workflow: run UDP identify against the original batch targets (-Pn) instead of limiting to TCP-discovery live hosts. Catches UDP-only hosts that don't answer TCP discovery, at the cost of probing dead IPs.")
    p.add_argument("--nse-default", action="store_true", help="Run the built-in NSE script set.")
    p.add_argument("--scripts", default="", help="Comma-separated NSE script names. Overrides --nse-default script list.")
    p.add_argument("--no-scripts", action="store_true", help="Disable NSE scripts for profiles that include them.")
    p.add_argument("--open-only", action="store_true", help="Add --open. Faster/smaller, but closed ports are omitted from heatmap XML.")
    p.add_argument("--include-closed", action="store_true", help="Remove --open so closed/filtered ports remain in XML.")
    p.add_argument("--stats-every", default=STATS_EVERY_DEFAULT, help="nmap --stats-every value.")
    p.add_argument("--host-timeout", default=None,
                   help="Per-host nmap --host-timeout. Off by default (0); --intensity gentle defaults to 30m. "
                        "Set e.g. 30m to opt in, or 0 to force off.")
    p.add_argument("--intensity", choices=list(INTENSITY_CHOICES), default="normal",
                   help="gentle: safer for old/fragile gear (-T3, no --defeat-rst-ratelimit, capped rate/"
                        "parallelism/retries, 30m host timeout).")
    p.add_argument("--max-rate", default="", metavar="PPS",
                   help="nmap --max-rate packets/sec cap. Applied automatically by --intensity gentle "
                        f"(default {GENTLE_MAX_RATE_DEFAULT}) when unset.")
    p.add_argument("--scan-scope", default="",
                   help="Allowed scan range(s): comma/space CIDR or IP. Targets outside are rejected before scanning. "
                        "Falls back to the SCANOPS_SCAN_SCOPE env var. Empty means unrestricted.")
    p.add_argument("--exclude", action="append", default=[], metavar="IP_OR_CIDR",
                   help="Exclude IPv4 IP/CIDR/last-octet range (10.0.0.1-10) values. Repeatable; each value may use "
                        "comma/space/newline separators.")
    p.add_argument("--exclude-ports", default="", metavar="PORT_SPEC",
                   help="Exclude these ports from every nmap stage (nmap --exclude-ports). Same grammar as --ports: "
                        "3030, 3030,3040, 1-1024, T:/U: prefixes.")
    p.add_argument("--batch-size", type=int, default=0, help="Expand targets and run batches of this size. 0 means one nmap run.")
    p.add_argument("--max-hosts", type=int, default=65536, help="Safety cap when expanding CIDR/ranges for batching.")
    p.add_argument("--resume", help="Resume from a previous *.state.json.")
    p.add_argument("--zip", action="store_true", help="Create a zip containing manifest/state and nmap outputs.")
    p.add_argument("--dry-run", action="store_true", help="Print nmap command(s) without running.")
    return p


def apply_cli_options(args: argparse.Namespace) -> None:
    """--preset / --options 를 args 에 반영. 둘 다 없으면 기존 --profile 동작 그대로."""
    args.preset_options = None
    args.preset_timing = ""
    preset_path = Path(args.preset_file) if args.preset_file else default_preset_path()
    if args.preset:
        # 프리셋이 소유하는 항목을 명령줄에서 같이 주면 어느 쪽이 이겼는지 알 수 없다 → 정직하게 거절.
        # --ports/--tcp-only/--open-only/--include-closed 는 프리셋 위에 얹는 보정이라 허용한다.
        owned = [
            name for name, value, default in (
                ("--options", args.options, ""),
                ("--profile", args.profile, "basic"),
                ("--scan-type", args.scan_type, ""),
                ("--udp", args.udp, False),
                ("--scripts", args.scripts, ""),
                ("--nse-default", args.nse_default, False),
                ("--no-scripts", args.no_scripts, False),
            ) if value != default
        ]
        if owned:
            raise ValueError(
                f"--preset 이 결정하는 항목을 명령줄에서 같이 지정했습니다: {', '.join(owned)}. "
                "프리셋을 수정하거나 --preset 없이 실행하세요."
            )
        preset = find_preset(load_presets(preset_path), args.preset)
        if preset is None:
            raise ValueError(
                f"저장된 프리셋이 없습니다: {args.preset} (--list-presets 로 확인, 파일: {preset_path})"
            )
        apply_preset_to_args(args, preset)
    elif args.options:
        # --options 는 '이름 없는 프리셋'이다. 저장 후 --preset 으로 부른 것과 한 글자도 다르지 않게
        # 같은 경로로 처리한다(스캔 기법·UDP 단계 사용 여부·NSE 유도 규칙이 갈라지지 않도록).
        apply_preset_to_args(args, preset_from_args(args, "(--options)"))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        done = run_preset_command(args)
        if done is not None:
            return done
        if args.resume and args.exclude:
            raise ValueError("--resume에서는 --exclude를 변경할 수 없습니다. state에 저장된 제외 대상을 사용합니다.")
        if args.resume and (args.preset or args.options):
            raise ValueError("--resume 은 저장된 state 의 구성을 그대로 이어갑니다. --preset/--options 를 함께 쓸 수 없습니다.")
        apply_cli_options(args)
        if args.resume and (args.exclude or args.exclude_ports):
            raise ValueError(
                "--resume에서는 --exclude/--exclude-ports를 변경할 수 없습니다. state에 저장된 제외 설정을 사용합니다."
            )
        plan = (load_plan(args.resume, args.nmap, args.dry_run, args.scan_scope)
                if args.resume else create_plan(args))
        return execute(plan, dry_run=args.dry_run, zip_outputs=args.zip)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyError, TypeError) as exc:
        # 손상/구버전 state 등으로 인한 예기치 못한 형태 → 트레이스백 대신 정직한 에러로(QA-017).
        print(f"error: 손상되었거나 호환되지 않는 state/입력입니다: {exc!r}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
