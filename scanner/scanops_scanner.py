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
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

VERSION = "0.1.0"
STATS_EVERY_DEFAULT = "10s"
UDP_DEFAULT_PORTS = "7,53,67,68,69,88,123,135,137,138,139,161,162,389,400,500,514,520,623,1900,2049,4500,5060,5353,5355,11211"
PRECISION_PORTS = f"T:1-65535,U:{UDP_DEFAULT_PORTS}"
# 용도 식별형 NSE만(취약점/노이즈/부작용 스크립트 제외) — 빠르고 부작용 적게 '무엇/왜' 파악.
# 제외: ssl-enum-ciphers·ntp-info·ntp-monlist·fingerprint-strings·dns-recursion·vnc-title
# DB 찌르는 스크립트(oracle-tns-version·ms-sql-info 등)는 장애 위험(티베로 등 호환DB 다운)으로 기본 제외.
DEFAULT_NSE_SCRIPTS = (
    "http-headers,http-server-header,http-title,ssl-cert,"
    "tls-alpn,ssh-hostkey,nbstat,smb-os-discovery,smb-protocols,"
    "rdp-ntlm-info,snmp-info,ike-version,sip-methods,"
    "rpcinfo,banner,ftp-anon,ftp-syst,telnet-encryption,dns-nsid,vnc-info"
)
# 발견 단계 호스트 디스커버리: ICMP 막은 서버도 흔한 서비스 포트로 잡고, 죽은 IP 는 건너뛴다
# (-Pn 전수보다 듬성한 대역에서 빠르고 누락 적음). -sS 라 raw 소켓(관리자) 전제.
DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080"
AUTO_TCP_DISCOVERY_FLAGS = [
    "-sS", DISCOVERY_PS, "-n", "-T4", "--open", "--reason",
    "--min-hostgroup", "64", "--max-retries", "1",
    "--defeat-rst-ratelimit", "--max-parallelism", "100",
    "--max-scan-delay", "5ms", "-p", "T:1-65535",
]
AUTO_TCP_IDENTIFY_FLAGS = [
    "-sS", "-Pn", "-n", "-sV", "--version-all", "--open", "--reason", "-T4",
    "--max-retries", "2", "--script", DEFAULT_NSE_SCRIPTS, "--script-timeout", "10s",
]
AUTO_UDP_IDENTIFY_FLAGS = [
    "-sU", "-Pn", "-n", "-sV", "--version-all", "--open", "--reason", "-T4",
    "--max-retries", "1", "--max-scan-delay", "5ms", "-p", f"U:{UDP_DEFAULT_PORTS}",
    "--script", DEFAULT_NSE_SCRIPTS, "--script-timeout", "10s",
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
    "phase1": [
        "-sS", "-sU", "-Pn", "-n", "-sV", "--version-all", "--open", "--reason",
        "-T4", "--max-retries", "2", "--min-hostgroup", "64",
        "--max-parallelism", "100", "--defeat-rst-ratelimit",
        "-p", PRECISION_PORTS,
        "--script", DEFAULT_NSE_SCRIPTS,
    ],
}

TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")
PORTS_RE = re.compile(r"^[0-9TUtu:,\-\s]+$")
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


def validate_ports(ports: str) -> str:
    ports = (ports or "").strip()
    if not ports:
        return ""
    if not PORTS_RE.match(ports):
        raise ValueError("허용되지 않는 포트 형식입니다. 예: 22,80,443 또는 1-1024")
    return ports.replace(" ", "")


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


def expand_targets(targets: list[str], cap: int) -> list[str]:
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
                hosts.extend(str(ip) for ip in net)
        elif match := RANGE_RE.match(t):
            base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
            if lo > hi or hi > 255:
                raise ValueError(f"잘못된 IP 범위: {t}")
            hosts.extend(f"{base}.{i}" for i in range(lo, hi + 1))
        else:
            hosts.append(t)
        if len(hosts) > cap:
            raise ValueError(f"대상 호스트가 너무 많습니다(>{cap}). --max-hosts 또는 범위를 조정하세요.")
    return hosts


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
    u_idx = port_spec.upper().find("U:")
    if u_idx >= 0:
        port_spec = port_spec[:u_idx].rstrip(",")
    parts = []
    for part in port_spec.split(","):
        item = part.strip()
        if not item or item.upper().startswith("U:"):
            continue
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

    ports = "T:1-65535" if args.all_ports else validate_ports(args.ports)
    if ports:
        flags = strip_value_flags(flags, VALUE_FLAGS)
        flags.extend(["-p", ports])

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
    override = plan.get("ports_override", "")
    if override:
        ports = protocol_ports(override, "U")
        return f"U:{','.join(ports)}" if ports else ""
    return f"U:{UDP_DEFAULT_PORTS}"


def apply_auto_modifiers(flags: list[str], plan: dict) -> list[str]:
    flags = set_scan_type(list(flags), plan.get("scan_type", ""))
    scripts = plan.get("scripts", "")
    if plan.get("no_scripts"):
        flags = strip_flags(flags, set(), {"--script"})
        flags = strip_flags(flags, set(), {"--script-timeout"})
    elif scripts:
        flags = replace_value_flag(flags, "--script", scripts)
    if plan.get("include_closed"):
        flags = strip_flags(flags, {"--open"})
    if plan.get("open_only") and "--open" not in flags:
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
    return apply_auto_modifiers(flags, plan)


def output_base(plan: dict, index: int, stage_id: str = "") -> Path:
    out_dir = Path(plan["output_dir"])
    name = plan["name"]
    suffix = f".{stage_id}" if stage_id else ""
    if len(plan["batches"]) == 1:
        return out_dir / f"{name}{suffix}"
    return out_dir / f"{name}.b{index:04d}{suffix}"


def build_command(plan: dict, index: int, stage_id: str = "", tcp_ports: list[int] | None = None) -> list[str]:
    base = output_base(plan, index, stage_id)
    flags = build_auto_flags(plan, stage_id, tcp_ports) if stage_id else plan["base_flags"]
    return [
        plan["nmap"],
        "--stats-every", plan["stats_every"],
        *flags,
        "-oA", str(base),
        *plan["batches"][index],
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


def run_stage_name(stage_id: str) -> str:
    return dict(AUTO_STAGES).get(stage_id, stage_id)


def stage_succeeded(plan: dict, batch_index: int, stage_id: str) -> bool:
    for run in plan.get("runs", []):
        run_batch = run.get("batch_index", run.get("index"))
        if run_batch == batch_index and run.get("stage_id", "") == stage_id and run.get("returncode") == 0 and not run.get("skipped"):
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
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


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
    run_targets = expanded if args.batch_size > 0 else raw_targets
    batches = make_batches(run_targets, args.batch_size)
    out_dir = Path(args.output_dir).resolve()
    name = safe_name(args.name)
    ports_override = validate_ports(args.ports)
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
        "base_flags": build_base_flags(args),
        "scan_type": args.scan_type,
        "ports_override": ports_override,
        "all_ports": args.all_ports,
        "tcp_only": args.tcp_only,
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


def load_plan(path: str, nmap_override: str = "", dry_run: bool = False) -> dict:
    p = Path(path)
    plan = json.loads(p.read_text(encoding="utf-8"))
    if plan.get("tool") != "scanops_scanner":
        raise ValueError("scanops_scanner state 파일이 아닙니다.")
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


def write_manifest(plan: dict, zip_path: str = "") -> None:
    manifest = dict(plan)
    manifest["state_path"] = plan.get("state_path", "")
    manifest["zip_path"] = zip_path
    manifest["all_xml_files"] = [
        p
        for run in plan.get("runs", [])
        if run.get("returncode") == 0 and not run.get("skipped")
        for p in run.get("files", [])
        if str(p).lower().endswith(".xml")
    ]
    manifest["import_xml_files"] = [
        p
        for run in plan.get("runs", [])
        if run.get("returncode") == 0 and not run.get("skipped") and run.get("stage_id", "") != "tcp_discovery"
        for p in run.get("files", [])
        if str(p).lower().endswith(".xml")
    ]
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


def finish_plan(plan: dict, state_path: Path, zip_outputs: bool) -> None:
    plan["status"] = "done"
    plan["finished_at"] = now_iso()
    write_json(state_path, plan)
    zip_path = str(Path(plan["output_dir"]) / f"{plan['name']}.scanops.zip") if zip_outputs else ""
    write_manifest(plan, zip_path)
    if zip_outputs:
        create_zip(plan)
    print(f"done: {plan['manifest_path']}")
    if zip_path:
        print(f"zip: {zip_path}")


def run_nmap_stage(plan: dict, idx: int, state_path: Path, stage_id: str = "", tcp_ports: list[int] | None = None) -> int:
    cmd = build_command(plan, idx, stage_id, tcp_ports)
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


def fail_plan(plan: dict, state_path: Path, rc: int) -> int:
    plan["status"] = "failed"
    plan["finished_at"] = now_iso()
    write_json(state_path, plan)
    write_manifest(plan)
    return rc


def execute_single(plan: dict, state_path: Path, zip_outputs: bool) -> int:
    for idx in range(int(plan["cursor"]), len(plan["batches"])):
        rc = run_nmap_stage(plan, idx, state_path)
        if rc != 0:
            return fail_plan(plan, state_path, rc)
        plan["cursor"] = idx + 1
        write_json(state_path, plan)
    finish_plan(plan, state_path, zip_outputs)
    return 0


def execute_auto(plan: dict, state_path: Path, zip_outputs: bool) -> int:
    for idx in range(int(plan["cursor"]), len(plan["batches"])):
        if auto_tcp_discovery_ports(plan):
            if not stage_succeeded(plan, idx, "tcp_discovery"):
                rc = run_nmap_stage(plan, idx, state_path, "tcp_discovery")
                if rc != 0:
                    return fail_plan(plan, state_path, rc)

            discovery_xml = Path(str(output_base(plan, idx, "tcp_discovery")) + ".xml")
            tcp_ports = open_ports_from_xml(discovery_xml, "tcp")
            if tcp_ports:
                if not stage_succeeded(plan, idx, "tcp_identify"):
                    rc = run_nmap_stage(plan, idx, state_path, "tcp_identify", tcp_ports)
                    if rc != 0:
                        return fail_plan(plan, state_path, rc)
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
        elif auto_udp_ports(plan):
            if not stage_succeeded(plan, idx, "udp_identify"):
                rc = run_nmap_stage(plan, idx, state_path, "udp_identify")
                if rc != 0:
                    return fail_plan(plan, state_path, rc)
        else:
            append_skipped_stage(plan, idx, "udp_identify", "사용자가 지정한 포트에 UDP 포트가 없습니다.")
            write_json(state_path, plan)

        plan["cursor"] = idx + 1
        write_json(state_path, plan)

    finish_plan(plan, state_path, zip_outputs)
    return 0


def execute(plan: dict, dry_run: bool = False, zip_outputs: bool = False) -> int:
    if dry_run:
        print_plan(plan)
        return 0

    out_dir = Path(plan["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = Path(plan["state_path"])
    plan["status"] = "running"
    write_json(state_path, plan)

    try:
        if plan.get("workflow", "single") == "auto":
            return execute_auto(plan, state_path, zip_outputs)
        return execute_single(plan, state_path, zip_outputs)
    except KeyboardInterrupt:
        plan["status"] = "interrupted"
        plan["finished_at"] = now_iso()
        write_json(state_path, plan)
        print("\ninterrupted. Resume with: --resume " + str(state_path), file=sys.stderr)
        return 130


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
    p.add_argument("--nse-default", action="store_true", help="Run the built-in NSE script set.")
    p.add_argument("--scripts", default="", help="Comma-separated NSE script names. Overrides --nse-default script list.")
    p.add_argument("--no-scripts", action="store_true", help="Disable NSE scripts for profiles that include them.")
    p.add_argument("--open-only", action="store_true", help="Add --open. Faster/smaller, but closed ports are omitted from heatmap XML.")
    p.add_argument("--include-closed", action="store_true", help="Remove --open so closed/filtered ports remain in XML.")
    p.add_argument("--stats-every", default=STATS_EVERY_DEFAULT, help="nmap --stats-every value.")
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


if __name__ == "__main__":
    raise SystemExit(main())
