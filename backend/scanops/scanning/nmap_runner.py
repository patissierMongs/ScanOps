"""nmap 실행 — subprocess(shell=False)로 명령 주입 차단. XML 산출."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

from . import scan_options
from .presets import PRESETS

# 타겟 화이트리스트: IPv4/CIDR/호스트명/범위. shell 미사용이라도 입력은 검증.
_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")

# 직접 명령 입력에서 거절할 셸 메타문자 — shell=False 라 해석은 안 되지만, 의도치 않은
# 토큰이 nmap 인자로 새는 걸 막고 명확히 거절한다.
_SHELL_META = set(";|&`$<>\n\r")
# 사용자가 준 출력 플래그는 무시(경로 traversal·형식 충돌 방지) — ScanOps 가 -oA 를 강제 주입.
_OUT_FLAGS = {"-oX", "-oN", "-oG", "-oS", "-oA"}

# 주기적 진행 보고 — nmap 이 stdout 에 "About X% done; ETC ..." 를 10초마다 출력.
# --resume 은 원본 명령을 그대로 이어받으므로 이 플래그도 자동 승계된다(가시성 유지).
STATS_FLAGS = ["--stats-every", "10s"]


def find_nmap(explicit: str = "") -> str | None:
    if explicit and os.path.isfile(explicit):
        return explicit
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.isfile(c):
            return c
    # PATH 상의 nmap
    from shutil import which
    return which("nmap")


def validate_targets(targets: list[str]) -> list[str]:
    bad = [t for t in targets if not _TARGET_RE.match(t)]
    if bad:
        raise ValueError(f"허용되지 않는 타겟 형식: {bad}")
    return targets


def xml_of(basename: Path) -> Path:
    return Path(str(basename) + ".xml")


def normal_log_of(basename: Path) -> Path:
    return Path(str(basename) + ".nmap")


def build_command(nmap: str, preset: str, targets: list[str], out_basename: Path) -> list[str]:
    if preset not in PRESETS:
        raise ValueError(f"알 수 없는 프리셋: {preset}")
    validate_targets(targets)
    # -oA : .nmap(normal)/.xml/.gnmap 동시 출력. .nmap 이 있어야 --resume 가능,
    # .xml 은 ScanOps 파싱용. 중단 후 --resume 시 nmap 이 세 파일을 모두 이어 쓴다.
    return [nmap, *STATS_FLAGS, *PRESETS[preset], "-oA", str(out_basename), *targets]


def build_command_opts(nmap: str, option_keys: list[str], ports: str,
                       targets: list[str], out_basename: Path,
                       nse: list[str] | None = None) -> list[str]:
    """옵션 키 화이트리스트 + 포트 + (선택)NSE 스크립트 + 타겟 → 검증된 nmap argv (-oA 강제)."""
    scan_options.validate_keys(option_keys)
    flags = scan_options.flags_for(option_keys)
    port_spec = scan_options.validate_ports(ports)
    script_flags = scan_options.script_flag(nse or [])
    validate_targets(targets)
    argv = [nmap, *STATS_FLAGS, *flags]
    if port_spec:
        argv += ["-p", port_spec]
    argv += script_flags
    argv += ["-oA", str(out_basename), *targets]
    return argv


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
        cleaned.append(t)
    argv = [nmap]
    if not any(t == "--stats-every" for t in cleaned):
        argv += STATS_FLAGS
    argv += cleaned
    argv += ["-oA", str(out_basename)]
    ip_tokens = [t for t in cleaned if _is_ip_like(t)]
    return argv, ip_tokens


def build_resume_command(nmap: str, out_basename: Path) -> list[str]:
    # --resume 는 다른 옵션 없이 로그만 — 원본 명령/출력형식을 그대로 이어받는다.
    return [nmap, "--resume", str(normal_log_of(out_basename))]


def _spawn(cmd: list[str], log_path: Path | None, timeout: int) -> int:
    with open(log_path, "wb") if log_path else open(os.devnull, "wb") as logf:
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, shell=False)
        return proc.wait(timeout=timeout)


def popen(cmd: list[str], log_path: Path) -> subprocess.Popen:
    """비차단 실행 — Popen 을 즉시 반환(백그라운드 워커가 wait/terminate). 로그는 파일로.

    로그 파일 핸들은 프로세스가 쥐고 있어야 하므로 닫지 않는다(프로세스 종료 시 OS 가 회수).
    """
    logf = open(log_path, "wb")
    return subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, shell=False)


# nmap stats 라인 파서 (예):
#   "Stats: 0:01:03 elapsed; 12 hosts completed (3 up), 4 undergoing Service Scan"
#   "Service scan Timing: About 42.86% done; ETC: 14:30 (0:00:30 remaining)"
_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_ETC_RE = re.compile(r"ETC:\s*(\S+)\s*\(([\d:]+)\s+remaining\)")
_ELAPSED_RE = re.compile(r"Stats:\s*([\d:]+)\s+elapsed;\s*(\d+)\s+hosts completed\s*\((\d+)\s+up\)")


def parse_progress(log_path: Path) -> dict:
    """진행 로그 tail 에서 최신 진행률/ETC/경과를 추출. 없으면 None 값."""
    out: dict = {"percent": None, "etc": None, "remaining": None,
                 "elapsed": None, "hosts_up": None, "last_line": ""}
    try:
        data = log_path.read_bytes()[-8192:].decode("utf-8", "replace")
    except OSError:
        return out
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    if lines:
        out["last_line"] = lines[-1]
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
