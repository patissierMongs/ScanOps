#!/usr/bin/env python3
"""ScanOps 샘플 스캔 하니스 — '단계 분리' 스캔의 미니 프로토타입(=엔진 설계 미리보기).

one-liner 대신 내부를 단계로 쪼갠다:
  Stage 0  호스트 발견   대역 → 살아있는 호스트            (-sn)
  Stage 1  TCP 포트 찾기  live → 열린 TCP 포트(버전/NSE 없이) (-sS -p- --open, 빠르고 느슨)
  Stage 3  서비스 probe   '각 호스트의 열린 포트에만' -sV+NSE  (좁혀서 정밀하게)

각 단계 산출(XML/gnmap/stdout) + 통합 summary.json 을 samples/<ts>/ 에 적재.
핵심: Stage 3 은 Stage 1 이 찾은 '그 호스트의 그 포트'에만 붙는다(닫힌 포트에 -sV 낭비 0).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

NMAP = os.environ.get("NMAP", "nmap")
ROOT = Path(__file__).resolve().parent
SUDO = [] if os.geteuid() == 0 else ["sudo"]   # -sS 는 root 필요(WSL). passwordless sudo 가정.

# Stage 3 NSE — 서비스별 적합 스크립트. portrule 안 맞으면 자동 skip 되니 묶어 줘도 안전.
# 원본 one-liner 의 20종 전수 대신 '타겟 NSE' 로 줄인 게 개선 포인트(+ --version-all 제거).
NSE = "banner,http-headers,http-title,http-server-header,ssl-cert,ssh-hostkey,ftp-anon,redis-info"


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def run_nmap(args: list[str], out_base: Path) -> dict:
    """nmap 한 패스 실행 → -oA 산출 + stdout 로그. 메타(소요시간/명령/rc) 반환."""
    cmd = SUDO + [NMAP, "--stats-every", "5s", *args, "-oA", str(out_base)]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    dt = round(time.time() - t0, 2)
    (out_base.parent / f"{out_base.name}.stdout.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    return {"cmd": cmd, "seconds": dt, "rc": proc.returncode}


def _hosts(xml_path: Path):
    return ET.parse(xml_path).getroot().findall("host")


def hosts_up(xml_path: Path) -> list[str]:
    ups = []
    for h in _hosts(xml_path):
        st = h.find("status")
        a = h.find("address[@addrtype='ipv4']")
        if st is not None and st.get("state") == "up" and a is not None:
            ups.append(a.get("addr"))
    return sorted(ups, key=lambda ip: tuple(int(o) for o in ip.split(".")))


def open_ports(xml_path: Path) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for h in _hosts(xml_path):
        a = h.find("address[@addrtype='ipv4']")
        if a is None:
            continue
        ports = [int(p.get("portid")) for p in h.findall("ports/port")
                 if (s := p.find("state")) is not None and s.get("state") == "open"]
        if ports:
            out[a.get("addr")] = sorted(ports)
    return out


def services(xml_path: Path) -> list[dict]:
    rows = []
    for h in _hosts(xml_path):
        a = h.find("address[@addrtype='ipv4']")
        if a is None:
            continue
        ip = a.get("addr")
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") != "open":
                continue
            svc = p.find("service")
            scripts = {sc.get("id"): (sc.get("output") or "").strip()[:200]
                       for sc in p.findall("script")}
            rows.append({
                "ip": ip,
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "scripts": scripts,
            })
    return rows


def main() -> int:
    subnet = sys.argv[1] if len(sys.argv) > 1 else "172.30.0.0/24"
    exclude = sys.argv[2] if len(sys.argv) > 2 else "172.30.0.1"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = ROOT / "samples" / ts
    out.mkdir(parents=True, exist_ok=True)
    summary: dict = {"subnet": subnet, "exclude": exclude, "started": ts, "stages": []}
    log(f"대상 {subnet} (제외 {exclude})  →  {out}")

    # ── Stage 0: 호스트 발견 ──
    log(f"Stage 0  호스트 발견 (-sn)")
    m = run_nmap(["-sn", "-n", "--exclude", exclude, subnet], out / "stage0-discovery")
    live = hosts_up(out / "stage0-discovery.xml")
    log(f"  live {len(live)}대  {m['seconds']}s  → {', '.join(live) or '없음'}")
    summary["stages"].append({"stage": 0, "name": "discovery", **m, "live_hosts": live})
    if not live:
        log("live 호스트 없음 — 종료.")
        (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0

    # ── Stage 1: TCP 전포트 '찾기' (버전/NSE 없이) ──
    log(f"Stage 1  TCP 전포트 찾기 (-sS -p- --open)  {len(live)}대")
    m = run_nmap(["-sS", "-Pn", "-n", "-p-", "--open", "--max-retries", "2", "--min-rate", "1000", *live],
                 out / "stage1-tcp")
    op = open_ports(out / "stage1-tcp.xml")
    nports = sum(len(v) for v in op.values())
    log(f"  열린 TCP {nports}개 / {len(op)}대  {m['seconds']}s")
    for ip in sorted(op, key=lambda i: tuple(int(o) for o in i.split("."))):
        log(f"    {ip}: {','.join(map(str, op[ip]))}")
    summary["stages"].append({"stage": 1, "name": "tcp-sweep", **m, "open_ports": op})
    if not op:
        log("열린 포트 없음 — 서비스 probe 생략.")
        (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0

    # ── Stage 3: 서비스 probe (각 호스트의 열린 포트에만, 호스트별 1패스) ──
    log(f"Stage 3  서비스 probe (-sV + 타겟 NSE)  — 호스트별 열린 포트에만")
    svc_rows: list[dict] = []
    s3_total = 0.0
    for ip in sorted(op, key=lambda i: tuple(int(o) for o in i.split("."))):
        pspec = ",".join(map(str, op[ip]))
        mm = run_nmap(["-sV", "-Pn", "-n", "--reason", "-p", pspec, "--script", NSE, ip],
                      out / f"stage3-{ip.replace('.', '_')}")
        s3_total += mm["seconds"]
        rows = services(out / f"stage3-{ip.replace('.', '_')}.xml")
        svc_rows += rows
        for r in rows:
            ident = " ".join(x for x in (r["product"], r["version"]) if x) or "?"
            log(f"    {r['ip']}:{r['port']}  {r['service']}  [{ident}]")
    summary["stages"].append({"stage": 3, "name": "service-probe",
                              "seconds": round(s3_total, 2), "services": svc_rows})

    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"완료 → {out}  (services {len(svc_rows)}건)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
