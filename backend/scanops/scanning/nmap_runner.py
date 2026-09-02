"""nmap 실행 — subprocess(shell=False)로 명령 주입 차단. XML 산출."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from . import chunker, process_control, scan_options
from .presets import PRESETS

# 타겟 화이트리스트: IPv4/CIDR/호스트명/범위. shell 미사용이라도 입력은 검증.
# Nmap 인자 끝에 붙이더라도 '-' 로 시작하면 타겟이 아니라 옵션으로 재해석된다.
_TARGET_RE = re.compile(r"^(?!-)[A-Za-z0-9_.:/\-]+$")

# 직접 명령 입력에서 거절할 셸 메타문자 — shell=False 라 해석은 안 되지만, 의도치 않은
# 토큰이 nmap 인자로 새는 걸 막고 명확히 거절한다.
_SHELL_META = set(";|&`$<>\n\r")
# 사용자가 준 출력 플래그는 무시(경로 traversal·형식 충돌 방지) — ScanOps 가 -oA 를 강제 주입.
_OUT_FLAGS = {"-oX", "-oN", "-oG", "-oS", "-oA"}
_RAW_FORBIDDEN_FLAGS = {"--resume"}

# 주기적 진행 보고 — nmap 이 stdout 에 "About X% done; ETC ..." 를 10초마다 출력.
# --resume 은 원본 명령을 그대로 이어받으므로 이 플래그도 자동 승계된다(가시성 유지).
STATS_FLAGS = ["--stats-every", "10s"]
# 발견: -PE(ICMP echo)+-PS(SYN)+-PA(ACK) 조합으로 살아있는 호스트만 추린다(-Pn 전수 아님).
# -Pn 이면 죽은 IP 도 status=up(user-set)로 박혀 live-host 제한이 무력화됨 → 실제 호스트 발견 사용.
# SYN엔 침묵해도 ICMP/ACK엔 답하는 호스트를 up으로 포착해 UDP 식별 누락을 줄인다.
DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080"
DISCOVERY_PA = "-PA80,443,3389"
# --open 제외: 열린 TCP 0개인 up 호스트(UDP 전용)를 nmap 이 XML 에서 빼버려 up_hosts 가 놓치고,
# 그 호스트가 UDP 식별 대상에서 누락된다. 닫힌 포트는 <extraports> 로 요약돼 영향 없음.
# 처리량 정책 — 모든 자동 단계가 같은 값을 지도록 한 곳에서 정한다.
#
# **가속 옵션이 아니다.** --max-parallelism 은 동시 프로브의 상한이고(하한이 아니다),
# --min-hostgroup 은 포트/버전 스캔 묶음 크기의 하한이다. 여기 있는 이유는 스캔 서버와 대상
# 장비의 부하를 예측 가능하게 묶어 두려는 것이다. 자동 워크플로의 세 단계는 모두 포트/버전
# 스캔이라(-sS 발견 포함) --min-hostgroup 이 실제로 묶을 대상이 있다 - 엔진의 -sn 발견
# 단계와 다른 점이다(그쪽은 nmap 문서상 효과가 없어 싣지 않는다).
#
# --defeat-rst-ratelimit 는 **SYN 스캔 전용**이라(nmap 은 -sT/-sU/-sn 과 함께 주면 fatal 로
# 끝난다) 여기 넣지 않고, SYN 단계에만 따로 얹는다. 이 플래그는 대상이 스스로 거는 보호를
# 무시하므로 부하를 올리는 쪽이다.
THROUGHPUT_FLAGS = ["--min-hostgroup", "64", "--max-parallelism", "100"]
DEFEAT_RST_FLAG = "--defeat-rst-ratelimit"
MAX_RETRIES = str(scan_options.MAX_RETRIES_DEFAULT)
# UDP 는 대상 OS 의 ICMP port-unreachable 율제한 때문에 응답이 늦게·드물게 온다. TCP 와 같은
# 재전송 상한을 쓰면 '닫혔다'가 아니라 '못 봤다'(open|filtered)가 그만큼 늘어난다.
UDP_MAX_RETRIES = str(scan_options.UDP_MAX_RETRIES_DEFAULT)
AUTO_TCP_DISCOVERY_FLAGS = [
    "-sS", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", "-T4", "--reason",
    "--max-retries", MAX_RETRIES, DEFEAT_RST_FLAG, *THROUGHPUT_FLAGS,
]
# 식별은 발견된 생존 호스트만 대상(scans.py 가 discovery_live 주입)이라 -Pn 안전, -n 제거 → 역DNS 로
# 호스트명 확보(용도 식별 근거). --version-all(intensity 9)로 rarity 높은 서비스(redis 등)까지 식별.
AUTO_TCP_IDENTIFY_FLAGS = [
    "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason",
    "-T4", "--max-retries", MAX_RETRIES, DEFEAT_RST_FLAG, *THROUGHPUT_FLAGS,
    "--script-timeout", "2m",
]
# UDP: --max-scan-delay 금지(닫힌 포트 ICMP rate-limit 적응형 백오프를 막아 open|filtered 오판).
# --version-all 미적용: 강도 9 는 수다스러운/증폭형 UDP 서비스(SNMP·SSDP·DNS 등)에서 거대·비정상
# 응답으로 nmap 을 fatal 종료시킬 위험이 크고 UDP 식별 이득은 미미 → 기본 -sV(강도 7)로 안전하게.
AUTO_UDP_IDENTIFY_FLAGS = [
    "-sU", "-Pn", "-n", "-sV", "--open", "--reason",
    "-T4", "--max-retries", UDP_MAX_RETRIES, *THROUGHPUT_FLAGS,
    "--script-timeout", "3m",
]


def find_nmap(explicit: str = "") -> str | None:
    if explicit and os.path.isfile(explicit):
        return explicit
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.isfile(c):
            return c
    # PATH 상의 nmap
    from shutil import which
    return which("nmap")


_DOTTED_QUAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def validate_targets(targets: list[str]) -> list[str]:
    bad = [t for t in targets if not isinstance(t, str) or not _TARGET_RE.fullmatch(t)]
    if bad:
        raise ValueError(f"허용되지 않는 타겟 형식: {bad}")
    invalid_ipv4 = [t for t in targets
                    if _DOTTED_QUAD_RE.fullmatch(t) and any(int(o) > 255 for o in t.split("."))]
    if invalid_ipv4:
        raise ValueError(f"잘못된 IPv4 주소: {invalid_ipv4}. 각 옥텟은 0-255 여야 합니다.")
    ipv6 = [t for t in targets if ":" in t]
    if ipv6:
        raise ValueError(f"IPv6 대상은 아직 지원하지 않습니다: {ipv6}. IPv4 주소/대역으로 지정하세요.")
    composite_ranges = [t for t in targets if chunker.is_unsupported_composite_ipv4_range(t)]
    if composite_ranges:
        raise ValueError(
            f"지원하지 않는 복합 IP 범위: {composite_ranges}. "
            "마지막 옥텟 범위만 사용할 수 있습니다."
        )
    return targets


def _protocol_ports(port_spec: str, protocol: str) -> list[str]:
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


def auto_tcp_port_spec(ports: str) -> str:
    port_spec = scan_options.validate_ports(ports)
    if not port_spec:
        return "T:1-65535"
    return ",".join(_protocol_ports(port_spec, "T"))


def auto_udp_port_spec(ports: str) -> str:
    port_spec = scan_options.validate_ports(ports)
    if not port_spec:
        return f"U:{scan_options.UDP_DEFAULT_PORTS}"
    udp_ports = _protocol_ports(port_spec, "U")
    return f"U:{','.join(udp_ports)}" if udp_ports else ""


def _script_args(nse: list[str] | None, proto: str) -> list[str]:
    keys = scan_options.NSE_DEFAULT_KEYS if nse is None else nse
    return scan_options.script_flag(scan_options.filter_nse_proto(keys, proto))


def xml_of(basename: Path) -> Path:
    return Path(str(basename) + ".xml")


def normal_log_of(basename: Path) -> Path:
    return Path(str(basename) + ".nmap")


def repair_truncated_xml(path: Path) -> bool:
    """중간에 끊긴 nmap XML 을 **파싱 가능한 데까지만** 남기고 닫는다.

    워치독이 프로세스를 끝내면 nmap 은 ``</nmaprun>`` 을 쓰지 못한다. 그 파일은 표준 파서가
    통째로 거절하므로 이미 끝난 호스트의 관측까지 같이 버려진다 - 몇 시간짜리 스캔에서는
    워치독을 둔 이유를 스스로 지우는 일이다(실측: 587바이트, ParseError).

    마지막 완결 ``</host>`` 뒤를 잘라내고 루트만 닫는다. **``runstats`` 는 만들지 않는다** -
    그것이 있어야 산출물 완결성 검사가 통과하므로, 없는 채로 두면 이 실행은 관측만 제공하고
    미관측 닫힘 권한은 얻지 못한다. 그 성질이 이 함수의 존재 이유다.

    단계 엔진(``scanops_engine.nmaprun``)과 단독 스캐너에도 같은 함수가 있다. 엔진은 따로
    설치되는 패키지라 백엔드가 그것을 import 할 수 없어(``ensure_available``) 세 경로가 각자
    들고 있고, 계약 테스트가 같은 입력에 같은 결과를 내는지 검사한다.

    반환: 손봤으면 True. 이미 온전하거나 살릴 호스트가 없으면 손대지 않고 False.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not raw.strip():
        return False
    try:
        ET.fromstring(raw)
        return False                      # 이미 온전하다 - 건드리지 않는다
    except ET.ParseError:
        pass
    cut = raw.rfind("</host>")
    if cut == -1:
        return False                      # 살릴 호스트가 없다 - 빈 파일로 두는 편이 정직하다
    repaired = raw[:cut + len("</host>")] + "\n</nmaprun>\n"
    try:
        ET.fromstring(repaired)
    except ET.ParseError:
        return False
    try:
        path.write_text(repaired, encoding="utf-8")
    except OSError:
        return False
    return True


def build_command(nmap: str, preset: str, targets: list[str], out_basename: Path,
                  ports: str = "", nse: list[str] | None = None) -> list[str]:
    if preset not in PRESETS:
        raise ValueError(f"알 수 없는 프리셋: {preset}")
    validate_targets(targets)
    port_spec = scan_options.validate_ports(ports)
    flags = list(PRESETS[preset])
    if port_spec:
        # 명시 포트가 프리셋의 -p/--top-ports 와 함께 나가면 Nmap 해석이 모호해진다.
        # 프리셋의 포트 선택만 제거하고 나머지 스캔 의미는 그대로 유지한다.
        filtered: list[str] = []
        skip_value = False
        for flag in flags:
            if skip_value:
                skip_value = False
                continue
            if flag in {"-p", "--top-ports"}:
                skip_value = True
                continue
            if flag == "-F" or flag.startswith("--top-ports="):
                continue
            filtered.append(flag)
        flags = [*filtered, "-p", port_spec]
    if nse is not None:
        scan_options.validate_nse(nse)
        filtered = []
        skip_value = False
        for flag in flags:
            if skip_value:
                skip_value = False
                continue
            if flag == "--script":
                skip_value = True
                continue
            if flag.startswith("--script="):
                continue
            filtered.append(flag)
        flags = [*filtered, *scan_options.script_flag(nse)]
    # -oA : .nmap(normal)/.xml/.gnmap 동시 출력. .nmap 이 있어야 --resume 가능,
    # .xml 은 ScanOps 파싱용. 중단 후 --resume 시 nmap 이 세 파일을 모두 이어 쓴다.
    return [nmap, *STATS_FLAGS, *flags, "-oA", str(out_basename), *targets]


def build_command_opts(nmap: str, option_keys: list[str], ports: str,
                       targets: list[str], out_basename: Path,
                       nse: list[str] | None = None) -> list[str]:
    """옵션 키 화이트리스트 + 포트 + (선택)NSE 스크립트 + 타겟 → 검증된 nmap argv (-oA 강제)."""
    scan_options.validate_keys(option_keys)
    flags = scan_options.flags_for(option_keys)
    if "connect" in option_keys:
        # Nmap rejects this SYN-only acceleration flag with -sT. Keep API callers safe even
        # if an older UI/preset submits the stale combination.
        flags = [flag for flag in flags if flag != "--defeat-rst-ratelimit"]
    port_spec = scan_options.validate_ports(ports)
    scripts = scan_options.NSE_DEFAULT_KEYS if nse is None else nse
    script_flags = scan_options.script_flag(scripts)
    validate_targets(targets)
    argv = [nmap, *STATS_FLAGS, *flags]
    if port_spec:
        argv += ["-p", port_spec]
    argv += script_flags
    argv += ["-oA", str(out_basename), *targets]
    return argv


def build_auto_command(nmap: str, stage: str, targets: list[str], out_basename: Path,
                       ports: str = "", tcp_ports: list[int] | None = None,
                       nse: list[str] | None = None) -> list[str]:
    """자동 워크플로 단계 명령.

    tcp_discovery: 전체/지정 TCP에서 열린 포트 발견
    tcp_identify: 발견된 TCP 포트에 서비스/버전/NSE 단서 부착(--version-all 기본)
    udp_identify: 주요/지정 UDP 포트 식별
    """
    validate_targets(targets)
    if stage == "tcp_discovery":
        port_spec = auto_tcp_port_spec(ports)
        if not port_spec:
            raise ValueError("자동 스캔 TCP 단계에 사용할 TCP 포트가 없습니다.")
        flags = [*AUTO_TCP_DISCOVERY_FLAGS, "-p", port_spec]
    elif stage == "tcp_identify":
        if not tcp_ports:
            raise ValueError("TCP 식별 단계에 사용할 열린 TCP 포트가 없습니다.")
        flags = [
            *AUTO_TCP_IDENTIFY_FLAGS,
            *_script_args(nse, "tcp"),
            "-p", "T:" + ",".join(str(p) for p in sorted(set(tcp_ports))),
        ]
    elif stage == "udp_identify":
        port_spec = auto_udp_port_spec(ports)
        if not port_spec:
            raise ValueError("자동 스캔 UDP 단계에 사용할 UDP 포트가 없습니다.")
        # UDP 식별 단계에는 NSE 를 붙이지 않는다(단독 스캐너의 AUTO_UDP_IDENTIFY_FLAGS 와 동일 규칙):
        # 발견에 반영되는 NSE 가 전부 TCP 스크립트라 얻는 게 없는데, 출발지 포트를 bind 하는 UDP
        # 스크립트가 스캔 호스트의 서비스와 충돌하면(ike-version↔IKEEXT 의 UDP 500) NSE 가 정리되지
        # 못한 채 끝나 단계 전체가 닫힘 권한을 잃는다. 포트 상태·서비스 식별은 -sV 가 담당한다.
        flags = [*AUTO_UDP_IDENTIFY_FLAGS, "-p", port_spec]
    else:
        raise ValueError(f"알 수 없는 자동 스캔 단계: {stage}")
    return [nmap, *STATS_FLAGS, *flags, "-oA", str(out_basename), *targets]


def open_ports_from_xml(path: Path, proto: str = "tcp") -> list[int]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    found: set[int] = set()
    for port in root.findall(".//port"):
        if (port.get("protocol") or "").lower() != proto:
            continue
        state = port.find("state")
        if state is None or (state.get("state") or "").lower() != "open":
            continue
        try:
            found.add(int(port.get("portid") or ""))
        except ValueError:
            continue
    return sorted(found)


def run_opts(nmap: str, option_keys: list[str], ports: str, targets: list[str],
             out_basename: Path, log_path: Path | None = None, timeout: int = 3600) -> int:
    return _spawn(build_command_opts(nmap, option_keys, ports, targets, out_basename), log_path, timeout)


def _is_ip_like(token: str) -> bool:
    from .scope import is_ip_token  # 단일 진실원천(scope) 재사용 — 중복 판별 로직 방지
    return is_ip_token(token)


def parse_raw_command(command: str) -> list[str]:
    """사용자 직접 입력 명령 → 토큰 리스트. 셸 메타문자 거절, 선두 nmap 토큰 제거."""
    if any(c in command for c in _SHELL_META):
        raise ValueError("명령에 허용되지 않는 문자가 있습니다 (; | & $ ` < > 등).")
    try:
        toks = shlex.split(command, posix=True)
    except ValueError as e:
        raise ValueError(f"명령을 해석할 수 없습니다: {e}")
    if not toks:
        raise ValueError("빈 명령입니다.")
    if Path(toks[0]).name.lower() in ("nmap", "nmap.exe"):
        toks = toks[1:]
    if not toks:
        raise ValueError("스캔 인자가 없습니다.")
    if any(t in _RAW_FORBIDDEN_FLAGS or any(t.startswith(f"{flag}=") for flag in _RAW_FORBIDDEN_FLAGS)
           for t in toks):
        raise ValueError("직접 명령에서 --resume 옵션은 사용할 수 없습니다.")
    return toks


def build_command_raw(nmap: str, command: str, out_basename: Path) -> tuple[list[str], list[str]]:
    """직접 입력 명령 → 검증된 argv. 출력 플래그 제거 후 -oA 강제, stats 주입.

    반환: (argv, ip_유사_타겟토큰들). 타겟 토큰은 scope 검사에 쓴다."""
    toks = parse_raw_command(command)
    cleaned: list[str] = []
    skip = False
    for t in toks:
        if skip:               # 직전이 출력 플래그 → 그 값(경로)도 버림
            skip = False
            continue
        if t in _OUT_FLAGS:
            skip = True
            continue
        if any(t.startswith(flag) and len(t) > len(flag) for flag in _OUT_FLAGS):
            # -oX/tmp/out.xml, -oA=base 같은 붙임 형태도 사용자 경로와 함께 제거.
            continue
        if t == "--append-output":
            continue
        cleaned.append(t)
    argv = [nmap]
    if not any(t == "--stats-every" for t in cleaned):
        argv += STATS_FLAGS
    argv += cleaned
    argv += ["-oA", str(out_basename)]
    from .scope import raw_target_tokens
    ip_tokens = [t for t in raw_target_tokens(cleaned) if _is_ip_like(t)]
    return argv, ip_tokens


def build_resume_command(nmap: str, out_basename: Path) -> list[str]:
    # --resume 는 다른 옵션 없이 로그만 — 원본 명령/출력형식을 그대로 이어받는다.
    return [nmap, "--resume", str(normal_log_of(out_basename))]


def _spawn(cmd: list[str], log_path: Path | None, timeout: int) -> int:
    with open(log_path, "wb") if log_path else open(os.devnull, "wb") as logf:
        proc = process_control.popen_owned(
            cmd, stdout=logf, stderr=subprocess.STDOUT, shell=False,
        )
        return wait_owned(proc, timeout=timeout)


def popen(cmd: list[str], log_path: Path) -> subprocess.Popen:
    """비차단 실행 — backend-owned process tree를 즉시 반환한다."""
    with open(log_path, "wb") as logf:
        return process_control.popen_owned(
            cmd, stdout=logf, stderr=subprocess.STDOUT, shell=False,
        )


def wait_owned(process: subprocess.Popen, timeout: float | None = None) -> int:
    """Preserve Popen.wait semantics while always releasing tree ownership."""
    try:
        return process.wait(timeout=timeout)
    finally:
        process_control.close_owned(process)


# nmap stats 라인 파서 (예):
#   "Stats: 0:01:03 elapsed; 12 hosts completed (3 up), 4 undergoing Service Scan"
#   "Service scan Timing: About 42.86% done; ETC: 14:30 (0:00:30 remaining)"
_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_ETC_RE = re.compile(r"ETC:\s*(\S+)\s*\(([\d:]+)\s+remaining\)")
_ELAPSED_RE = re.compile(r"Stats:\s*([\d:]+)\s+elapsed;\s*(\d+)\s+hosts completed\s*\((\d+)\s+up\)")


def parse_progress(log_path: Path) -> dict:
    """진행 로그 tail 에서 최신 진행률/ETC/경과를 추출. 없으면 None 값."""
    out: dict = {"percent": None, "etc": None, "remaining": None,
                 "elapsed": None, "hosts_up": None}
    try:
        data = log_path.read_bytes()[-8192:].decode("utf-8", "replace")
    except OSError:
        return out
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if out["percent"] is None and (m := _PCT_RE.search(ln)):
            out["percent"] = float(m.group(1))
            if e := _ETC_RE.search(ln):
                out["etc"], out["remaining"] = e.group(1), e.group(2)
        if out["elapsed"] is None and (m := _ELAPSED_RE.search(ln)):
            out["elapsed"], out["hosts_up"] = m.group(1), int(m.group(3))
        if out["percent"] is not None and out["elapsed"] is not None:
            break
    return out


def run(nmap: str, preset: str, targets: list[str], out_basename: Path,
        log_path: Path | None = None, timeout: int = 3600) -> int:
    return _spawn(build_command(nmap, preset, targets, out_basename), log_path, timeout)
