#!/usr/bin/env python3
"""Standalone nmap runner that writes XML files ready for ScanOps import.

This file intentionally uses only the Python standard library. Copy this single
file to a scanner host that has Python 3.8+ and nmap installed, then run it
without starting the ScanOps web app.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

VERSION = "0.2.0"
STATS_EVERY_DEFAULT = "10s"
# 호스트당 상한. nmap 은 이 시간을 넘긴 호스트를 포기하고 다음으로 넘어가며 0으로 정상 종료(부분 결과 유지).
# 한 호스트가 스캔 전체를 무한정 멈추는 사고(QA-007)를 막는다. 비우면("") 미적용.
HOST_TIMEOUT_DEFAULT = "15m"
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

TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")
PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]+$")
# 포트 본문(프로토콜 접두사 제거 후): 단일 포트·범위·열린 범위(1-, -1024) 허용.
PORT_BODY_RE = re.compile(r"^(\d{1,5}-\d{1,5}|\d{1,5}-|-\d{1,5}|\d{1,5})$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$")
STATS_RE = re.compile(r"^\d+[smh]?$")
NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
VALUE_FLAGS = {"-p", "--top-ports"}
SCAN_TYPE_FLAGS = {"-sS", "-sT"}


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
    bad = [t for t in targets if not TARGET_RE.match(t)]
    if bad:
        raise ValueError(f"허용되지 않는 target 형식: {bad}")
    # IPv6 는 자동 워크플로 플래그(-6 없음)와 호환되지 않아 nmap 이 실패하고, 실패하면
    # best-effort 라도 해당 대상은 결과가 0 → 혼란. 명시적으로 거절한다(QA-016).
    ipv6 = [t for t in targets if ":" in t]
    if ipv6:
        raise ValueError(f"IPv6 대상은 아직 지원하지 않습니다: {ipv6}. IPv4 주소/대역으로 지정하세요.")


def warn_ambiguous_ports(spec: str) -> None:
    """T:/U: 접두사는 다음 접두사 전까지 sticky(nmap 규칙). 접두사 뒤의 '접두사 없는' 포트는
    직전 프로토콜로 묶인다(예: T:80,U:53,443 → 443 은 UDP). 사용자 의도와 다를 수 있어 한 번 경고(QA-013)."""
    if ":" not in spec:
        return
    current = ""
    for seg in spec.replace(" ", "").split(","):
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
    """콤마/공백 구분 CIDR·IP 목록 → 네트워크 객체. 잘못된 토큰은 건너뛴다."""
    nets = []
    for raw in (spec or "").replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(raw.strip(), strict=False))
        except ValueError:
            continue
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


def build_base_flags(args: argparse.Namespace) -> list[str]:
    flags = list(PRESETS[args.profile])
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

    return flags


def replace_value_flag(flags: list[str], name: str, value: str) -> list[str]:
    flags = strip_value_flags(flags, {name})
    return [*flags, name, value]


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


def apply_auto_modifiers(flags: list[str], plan: dict, stage_id: str = "") -> list[str]:
    flags = set_scan_type(list(flags), plan.get("scan_type", ""))
    scripts = plan.get("scripts", "")
    if plan.get("no_scripts"):
        flags = strip_flags(flags, set(), {"--script"})
        flags = strip_flags(flags, set(), {"--script-timeout"})
    elif scripts:
        flags = replace_value_flag(flags, "--script", scripts)
    if plan.get("include_closed"):
        flags = strip_flags(flags, {"--open"})
    # discovery 단계엔 --open 을 절대 추가하지 않는다: 열린 TCP 0개인 up 호스트(UDP 전용)가 XML 에서
    # 통째로 빠져 live_hosts 에서 누락되고 UDP 식별을 못 받는다(상단 불변식, QA-031).
    # open_only 는 identify 단계(이미 --open 보유)에만 의미가 있으므로 discovery 는 제외한다.
    if plan.get("open_only") and "--open" not in flags and stage_id != "tcp_discovery":
        flags.append("--open")
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
    return [
        plan["nmap"],
        "--stats-every", plan["stats_every"],
        *timeout_flags,
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
        if state is None or (state.get("state") or "").lower() != "open":
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
            if state is None or (state.get("state") or "").lower() != "open":
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
            if ip and ip not in seen and TARGET_RE.match(ip):
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
            (state := port.find("state")) is not None and (state.get("state") or "").lower() == "open"
            for port in host.findall(".//port")
        )
        if not has_open:
            continue
        for addr in host.findall("address"):
            if (addr.get("addrtype") or "").lower() == "mac":
                continue
            ip = addr.get("addr") or ""
            if ip and ip not in seen and TARGET_RE.match(ip):
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


def xml_has_hosts(path: Path) -> bool:
    """파싱 가능하고 host 항목이 하나라도 있는지. rc≠0 단계의 부분 XML 도 쓸만하면 manifest 에 포함하기 위함."""
    if not path.exists():
        return False
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return False
    return root.find(".//host") is not None


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
    check_scope(expanded, getattr(args, "scan_scope", "") or os.environ.get("SCANOPS_SCAN_SCOPE", ""))
    run_targets = expanded if args.batch_size > 0 else raw_targets
    batches = make_batches(run_targets, args.batch_size)
    out_dir = Path(args.output_dir).resolve()
    name = safe_name(args.name)
    ports_override = validate_ports(args.ports)
    if ports_override:
        warn_ambiguous_ports(ports_override)
    if args.workflow == "auto" and args.tcp_only and ports_override and not protocol_ports(ports_override, "T"):
        raise ValueError("TCP만 옵션을 사용할 때는 TCP 포트를 지정해야 합니다. 예: --ports 22,443")
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
        "stats_every": validate_stats_every(args.stats_every),
        "host_timeout": validate_host_timeout(getattr(args, "host_timeout", HOST_TIMEOUT_DEFAULT)),
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
        "batch_size": args.batch_size,
        "batches": batches,
        "cursor": 0,
        "runs": [],
    }


REQUIRED_STATE_KEYS = ("workflow", "output_dir", "name", "manifest_path", "batches", "cursor", "runs")


def load_plan(path: str, nmap_override: str = "", dry_run: bool = False) -> dict:
    p = Path(path)
    plan = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(plan, dict) or plan.get("tool") != "scanops_scanner":
        raise ValueError("scanops_scanner state 파일이 아닙니다.")
    # 손상/구버전 state 가 나중에 KeyError 트레이스백으로 터지지 않도록 필수 키를 미리 검증(QA-017).
    missing = [k for k in REQUIRED_STATE_KEYS if k not in plan]
    if missing:
        raise ValueError(f"state 파일에 필수 항목이 없습니다(손상되었거나 호환되지 않음): {missing}")
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
            if not plan.get("tcp_only") and auto_udp_ports(plan):
                print(f"# {idx + 1}/{len(plan['batches'])} {run_stage_name('udp_identify')}")
                print(display_command(build_command(plan, idx, "udp_identify")))
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


def write_manifest(plan: dict, zip_path: str = "") -> None:
    manifest = dict(plan)
    manifest["state_path"] = plan.get("state_path", "")
    manifest["zip_path"] = zip_path
    runs = latest_runs(plan)
    manifest["all_xml_files"] = list(dict.fromkeys(
        p for run in runs for p in manifest_xml_files(run)
    ))
    # identify 산출물이 하나도 없으면 성공한 discovery XML 을 구제 fallback 으로 추천한다(QA-038).
    manifest["import_xml_files"] = importable_xml(plan, include_discovery_fallback=True)
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
    """import 가능한 XML(파싱+host, discovery 제외). 부분 실패 단계의 XML 도 쓸만하면 포함.
    include_discovery_fallback=True 면, identify 산출물이 하나도 없을 때 성공한 discovery XML 을 구제
    fallback 으로 포함한다(QA-038: discovery 만 성공한 스캔이 'failed' 로 버려지지 않게)."""
    seen: dict[str, None] = {}
    for run in latest_runs(plan):
        if run.get("stage_id", "") == "tcp_discovery":
            continue
        for p in manifest_xml_files(run):
            # host 가 실제로 든 식별 XML 만 importable 로 센다. rc=0 이지만 host 없는 빈 식별 XML 이
            # seen 을 차지하면 discovery 구제 fallback 이 막혀, 실데이터가 든 discovery XML 이 누락된다(QA-049).
            if xml_has_hosts(Path(p)):
                seen[p] = None
    if seen or not include_discovery_fallback:
        return list(seen)
    # fallback 은 host 가 실제로 든 성공 discovery XML 만 구제한다. host 0 인 빈 discovery(살아있는 호스트
    # 없음)까지 살리면 '빈 스캔'이 import 가능한 것처럼 잘못 보고된다(QA-038 ↔ QA-012 경계).
    for run in latest_runs(plan):
        if run.get("stage_id", "") != "tcp_discovery":
            continue
        for p in manifest_xml_files(run):
            if xml_has_hosts(Path(p)):
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
    if f["importable"] == 0 and not failed:
        print(
            "warning: 가져올 결과가 없습니다(열린 포트/살아있는 호스트 0). 대상·네트워크 도달성을 확인하세요.",
            file=sys.stderr,
        )
    elif status == "failed":
        print("error: 사용할 수 있는 스캔 결과가 없습니다(모든 단계 실패).", file=sys.stderr)


def run_nmap_stage(plan: dict, idx: int, state_path: Path, stage_id: str = "", tcp_ports: list[int] | None = None,
                   targets: list[str] | None = None) -> int:
    cmd = build_command(plan, idx, stage_id, tcp_ports, targets)
    base = output_base(plan, idx, stage_id)
    started = now_iso()
    stage_label = f" {run_stage_name(stage_id)}" if stage_id else ""
    print(f"[{idx + 1}/{len(plan['batches'])}]{stage_label} {display_command(cmd)}", flush=True)
    rc = subprocess.call(cmd, shell=False)
    run = {
        "index": idx,
        "batch_index": idx,
        "stage_id": stage_id,
        "stage_name": run_stage_name(stage_id) if stage_id else "",
        "started_at": started,
        "finished_at": now_iso(),
        "returncode": rc,
        "command": cmd,
        "output_base": str(base),
        "files": existing_outputs(base),
    }
    plan["runs"].append(run)
    write_json(state_path, plan)
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
    p.add_argument("--host-timeout", default=HOST_TIMEOUT_DEFAULT,
                   help="Per-host nmap --host-timeout so one host cannot hang the whole scan. 0 disables.")
    p.add_argument("--scan-scope", default="",
                   help="Allowed scan range(s): comma/space CIDR or IP. Targets outside are rejected before scanning. "
                        "Falls back to the SCANOPS_SCAN_SCOPE env var. Empty means unrestricted.")
    p.add_argument("--batch-size", type=int, default=0, help="Expand targets and run batches of this size. 0 means one nmap run.")
    p.add_argument("--max-hosts", type=int, default=65536, help="Safety cap when expanding CIDR/ranges for batching.")
    p.add_argument("--resume", help="Resume from a previous *.state.json.")
    p.add_argument("--zip", action="store_true", help="Create a zip containing manifest/state and nmap outputs.")
    p.add_argument("--dry-run", action="store_true", help="Print nmap command(s) without running.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        plan = load_plan(args.resume, args.nmap, args.dry_run) if args.resume else create_plan(args)
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
