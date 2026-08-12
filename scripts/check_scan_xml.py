#!/usr/bin/env python3
"""이미 돌린 스캔 XML 이 믿을 만한지 판정한다 — 버릴지 다시 돌릴지 정하는 데 쓴다.

이 스크립트가 답하는 질문은 하나다: **이 XML 의 포트 상태를 믿어도 되는가.**

UDP NSE 실패(UDP 500 bind 등)는 포트 스캔이 끝난 뒤 스크립트 단계에서 일어난다. 그래서
포트 상태(open/closed/open|filtered)는 멀쩡한데 스크립트 결과만 비는 경우가 대부분이다.
그 둘을 갈라서 보여준다.

사용:
    python scripts/check_scan_xml.py scanops_scans
    python scripts/check_scan_xml.py scanops_scans/weekly.10_0_0_0.udp_identify.xml
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# NSE 가 붙는 UDP 포트 — 여기에 스크립트 결과가 하나도 없으면 스크립트 단계가 날아갔을 수 있다.
_NSE_UDP_PORTS = {53, 111, 123, 137, 161, 500, 5060}


def inspect(path: Path) -> dict:
    out = {"path": path, "parse": True, "finished": False, "exit": "",
           "hosts": 0, "open_ports": 0, "hosts_with_scripts": 0,
           "nse_candidates": 0, "truncated": False, "protocols": set(),
           "stage": ""}
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        out["parse"] = False
        out["truncated"] = True          # 중간에 끊긴 XML 은 파싱부터 실패한다
        return out
    finished = root.findall("./runstats/finished")
    if finished:
        out["finished"] = True
        out["exit"] = finished[0].get("exit") or ""
    out["stage"] = next(
        (name for name in ("tcp_discovery", "tcp_identify", "udp_identify")
         if path.name.lower().endswith(f".{name}.xml")), "")
    out["protocols"] = {
        (info.get("protocol") or "").lower() for info in root.findall("./scaninfo")
    }
    hosts = root.findall("host")
    out["hosts"] = len(hosts)
    for host in hosts:
        has_script = False
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and (state.get("state") or "").startswith("open"):
                out["open_ports"] += 1
            try:
                number = int(port.get("portid") or 0)
            except ValueError:
                number = 0
            if number in _NSE_UDP_PORTS:
                out["nse_candidates"] += 1
            if port.find("script") is not None:
                has_script = True
        if host.find("./hostscript") is not None:
            has_script = True
        if has_script:
            out["hosts_with_scripts"] += 1
    return out


def verdict(info: dict) -> tuple[str, str]:
    """(판정, 이유). 판정은 '버림' / '재실행 권장' / '사용 가능' 셋뿐이다."""
    if info["truncated"]:
        return "버림", "XML 이 중간에 끊겨 파싱되지 않습니다 — 다시 스캔하세요."
    if not info["finished"]:
        return "버림", "<finished> 가 없습니다 — nmap 이 결과를 마무리하지 못했습니다."
    if info["exit"] != "success":
        return "버림", f'nmap 이 exit="{info["exit"]}" 로 끝났습니다.'
    # 서버는 닫힘 권한을 주기 전에 '단계가 광고한 프로토콜'과 XML 이 실제로 스캔한 프로토콜이
    # 같은지 본다. UDP 식별 XML 에 TCP scaninfo 가 섞여 있으면 가져오기가 거절된다.
    # (스캔 기법이 UDP 단계로 새던 옛 버전으로 만든 XML 의 지문이다.)
    if info["stage"] == "udp_identify" and info["protocols"] - {"udp"}:
        mixed = ",".join(sorted(info["protocols"]))
        return ("가져오기 거절",
                f"UDP 식별 XML 인데 scaninfo 에 {mixed} 가 섞여 있습니다 — 서버가 "
                "'UDP 식별 manifest와 XML protocol이 일치하지 않습니다' 로 거절합니다. "
                "옛 버전에서 스캔 기법이 UDP 단계로 새어 만들어진 XML 입니다. 다시 스캔하세요.")
    if info["nse_candidates"] and not info["hosts_with_scripts"]:
        return ("재실행 권장",
                "포트 상태는 온전하지만 NSE 스크립트 결과가 하나도 없습니다 "
                "— 스크립트 단계가 정리되지 못했을 수 있습니다(서비스 상세만 손실).")
    return "사용 가능", "포트 상태와 스크립트 결과가 모두 기록돼 있습니다."


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    root = Path(argv[1])
    files = sorted(root.rglob("*.xml")) if root.is_dir() else [root]
    if not files:
        print(f"XML 을 찾지 못했습니다: {root}")
        return 1
    worst = 0
    for path in files:
        info = inspect(path)
        mark, why = verdict(info)
        worst = max(worst, {"사용 가능": 0, "재실행 권장": 1,
                            "가져오기 거절": 2, "버림": 2}[mark])
        print(f"[{mark}] {path.name}")
        print(f"          호스트 {info['hosts']} · 열린 포트 {info['open_ports']} · "
              f"스크립트 있는 호스트 {info['hosts_with_scripts']}")
        print(f"          {why}")
    return 0 if worst == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
