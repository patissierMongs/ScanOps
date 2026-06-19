"""nmap 래퍼 — 단계별 실행(라이브 진행 스트리밍) + XML 파싱.

엔진의 유일한 외부 명령 실행 지점. shell=False, -oA 서버 강제로 명령 주입 차단.
nmap stdout 의 'About X% done' 을 파싱해 stage_progress 콜백으로 흘린다.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done")


def find_nmap(explicit: str = "") -> str | None:
    if explicit and os.path.isfile(explicit):
        return explicit
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.isfile(c):
            return c
    return shutil.which("nmap")


def _need_sudo(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    # auto: POSIX 비root → sudo (Windows+Npcap 은 불필요)
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0


def run(nmap, args, out_base, sudo_mode="auto", progress=None, stats="5s") -> dict:
    """nmap 한 패스 — -oA out_base 강제 + --stats-every. stdout 스트리밍하며 progress(pct).

    반환: {"rc", "seconds", "cmd"}.
    """
    out_base = Path(out_base)
    cmd = (["sudo"] if _need_sudo(sudo_mode) else []) + \
        [nmap, "--stats-every", stats, *args, "-oA", str(out_base)]
    t0 = time.time()
    with open(str(out_base) + ".stdout.log", "w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        for line in proc.stdout:
            log.write(line)
            if progress and (m := _PCT_RE.search(line)):
                try:
                    progress(float(m.group(1)))
                except Exception:
                    pass
        rc = proc.wait()
    return {"rc": rc, "seconds": round(time.time() - t0, 2), "cmd": cmd}


# ── XML 파싱 ──

def _ipkey(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (ip,)


def _hosts(xml_path):
    try:
        return ET.parse(str(xml_path)).getroot().findall("host")
    except (ET.ParseError, FileNotFoundError, OSError):
        return []


def _ipv4(h):
    a = h.find("address[@addrtype='ipv4']")
    return a.get("addr") if a is not None else None


def hosts_up(xml_path) -> list[str]:
    ups = [ip for h in _hosts(xml_path)
           if (st := h.find("status")) is not None and st.get("state") == "up"
           and (ip := _ipv4(h))]
    return sorted(ups, key=_ipkey)


def open_ports(xml_path, proto=None) -> dict[str, list[int]]:
    """{ip: [열린 포트]} — proto 지정 시 그 프로토콜만."""
    out: dict[str, list[int]] = {}
    for h in _hosts(xml_path):
        ip = _ipv4(h)
        if not ip:
            continue
        ports = [int(p.get("portid")) for p in h.findall("ports/port")
                 if (not proto or p.get("protocol") == proto)
                 and (s := p.find("state")) is not None and s.get("state") == "open"]
        if ports:
            out[ip] = sorted(ports)
    return out


def services(xml_path) -> list[dict]:
    rows = []
    for h in _hosts(xml_path):
        ip = _ipv4(h)
        if not ip:
            continue
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") != "open":
                continue
            svc = p.find("service")
            scripts = {sc.get("id"): (sc.get("output") or "").strip()[:300]
                       for sc in p.findall("script")}
            rows.append({
                "ip": ip, "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "scripts": scripts,
            })
    return rows
