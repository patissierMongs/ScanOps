"""nmap 래퍼 — 단계별 실행(라이브 진행 스트리밍) + XML 파싱.

엔진의 유일한 외부 명령 실행 지점. shell=False, -oA 서버 강제로 명령 주입 차단.
nmap stdout 의 'About X% done' 을 파싱해 stage_progress 콜백으로 흘린다.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .process_control import close_kill_job, popen_owned, terminate_owned

_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_RETRANSMISSION_CAP_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\s+giving up on port because "
    r"retransmission cap hit\b",
    re.IGNORECASE,
)


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


def _stream_output(stream, log, progress, retransmission_cap_hosts) -> None:
    for line in stream:
        log.write(line)
        log.flush()
        if m := _RETRANSMISSION_CAP_RE.search(line):
            retransmission_cap_hosts.add(m.group(1))
        if progress and (m := _PCT_RE.search(line)):
            try:
                progress(float(m.group(1)))
            except Exception:
                pass


def build_command(nmap, args, out_base, sudo_mode="auto", stats="5s") -> list[str]:
    """Return the exact argv used by :func:`run` for history/UI evidence."""
    return (['sudo'] if _need_sudo(sudo_mode) else []) + [
        str(nmap), "--stats-every", str(stats), *[str(arg) for arg in args],
        "-oA", str(Path(out_base)),
    ]


def run(nmap, args, out_base, sudo_mode="auto", progress=None, stats="5s",
        stop_requested=None, poll_interval=0.1, watchdog_seconds=0) -> dict:
    """nmap 한 패스 — -oA out_base 강제 + --stats-every. stdout 스트리밍하며 progress(pct).

    stdout 유무와 무관하게 stop_requested 를 짧게 poll하고, 중지 시 이 호출이 소유한
    프로세스 트리만 종료한다.
    반환: {"rc", "seconds", "cmd", "stopped", "timed_out_by_watchdog", ...}.

    ``watchdog_seconds`` 는 **프로세스 단위** 상한이다(0 = 끔). ``--host-timeout`` 과는
    성격이 다르다:

    * ``--host-timeout`` 은 nmap 이 상한을 넘긴 호스트의 **포트 표를 아예 쓰지 않고**
      실행은 ``exit="success"`` 로 끝낸다. 그래서 그 호스트가 '살아 있는데 열린 포트가
      없다'로 읽혀 기존 발견이 전부 닫힌다 - 관측을 버리면서 그 사실을 숨긴다.
    * 워치독은 nmap 을 **밖에서** 끝낸다. ``-oA`` 는 증분 기록이라 그때까지 쓰인 XML 은
      디스크에 그대로 남고, 실행은 비정상 종료로 표시되어 닫힘 권한을 얻지 못한다
      (산출물 완결성 검사가 ``<finished exit="success">`` 를 요구한다).

    즉 워치독은 '못 본 것을 봤다고 말하는' 사고를 만들지 않는다. 그래서 상한을 되살리는
    대신 이쪽을 둔다.
    """
    out_base = Path(out_base)
    cmd = build_command(nmap, args, out_base, sudo_mode=sudo_mode, stats=stats)
    t0 = time.time()
    with open(str(out_base) + ".stdout.log", "w", encoding="utf-8") as log:
        proc = popen_owned(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, bufsize=1)
        retransmission_cap_hosts = set()
        reader = threading.Thread(
            target=_stream_output,
            args=(proc.stdout, log, progress, retransmission_cap_hosts), daemon=True,
        )
        reader.start()
        stopped = False
        watchdog_fired = False
        deadline = t0 + watchdog_seconds if watchdog_seconds and watchdog_seconds > 0 else None
        try:
            while proc.poll() is None:
                if stop_requested is not None and stop_requested():
                    stopped = True
                    terminate_owned(proc)
                    break
                if deadline is not None and time.time() >= deadline:
                    watchdog_fired = True
                    terminate_owned(proc)
                    break
                time.sleep(poll_interval)
            rc = proc.wait()
        except BaseException:
            if proc.poll() is None:
                terminate_owned(proc)
            raise
        finally:
            # Closing the Windows Job Object also removes a descendant that outlived its
            # parent and still owns the stdout pipe. POSIX stop uses the private process group.
            close_kill_job(proc)
            reader.join(timeout=2)
            if reader.is_alive() and proc.stdout is not None:
                proc.stdout.close()
                reader.join(timeout=0.5)
    # 워치독이 끊은 실행은 rc 가 0 이어서는 안 된다. 종료 신호를 받은 nmap 이 0 으로 끝낼
    # 수 있는데, 그대로 두면 '정상 완료'로 읽혀 미관측 닫힘 권한을 얻는다 - 워치독을 둔
    # 이유가 통째로 뒤집힌다. 여기서 실패로 못박는다.
    if watchdog_fired and rc == 0:
        rc = -1
    return {
        "rc": rc,
        "seconds": round(time.time() - t0, 2),
        "cmd": cmd,
        "stopped": stopped,
        "timed_out_by_watchdog": watchdog_fired,
        "retransmission_cap_hosts": sorted(retransmission_cap_hosts, key=_ipkey),
    }


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


def timed_out(xml_path) -> list[str]:
    """``--host-timeout`` 으로 nmap 이 포기한 호스트.

    nmap 은 상한을 넘긴 호스트를 건너뛰고 포트 표를 아예 쓰지 않으며, `<host>` 에
    ``timedout="true"`` 만 남긴 뒤 실행 자체는 ``exit="success"`` 로 끝낸다. 그래서 이
    표식을 안 읽으면 '살아 있는데 열린 포트가 없다'로 보인다 - 그 호스트의 기존 발견이
    전부 닫힘 처리되는 자리다.
    """
    return sorted({ip for h in _hosts(xml_path)
                   if h.get("timedout") == "true" and (ip := _ipv4(h))}, key=_ipkey)


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
                 and (s := p.find("state")) is not None
                 and (s.get("state") or "").startswith("open")]
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
            if s is None or not (s.get("state") or "").startswith("open"):
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
