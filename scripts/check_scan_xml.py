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
           "stage": "", "hosts_up": 0, "hosts_total": 0, "reasons": {}}
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
    # 끝맺힌 실행이라도 '몇 대를 봤는가'는 따로 봐야 한다. 서버는 이 XML 에 up 으로 잡힌
    # 호스트에 대해서만 닫힘을 진행하므로(_auto_scope_keys), 커버리지가 곧 닫힘 범위다.
    stats_hosts = root.find("./runstats/hosts")
    if stats_hosts is not None:
        for key, attr in (("hosts_up", "up"), ("hosts_total", "total")):
            try:
                out[key] = int(stats_hosts.get(attr) or 0)
            except ValueError:
                out[key] = 0
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
                # 같은 open 이라도 syn-ack(응답을 받아 확인)과 no-response(못 받고 추정)는
                # 증거 강도가 다르다. --reason 은 이미 모든 단계에 붙어 있으므로 옛 XML 에도
                # 대개 들어 있다. 없으면 '미기록'으로 세고 추정으로 넘겨짚지 않는다.
                why = (state.get("reason") or "").strip() or "미기록"
                out["reasons"][why] = out["reasons"].get(why, 0) + 1
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
        # nmap 이 XML 을 끝맺지 못한 채 죽은 경우다. 완료된 호스트만 살리려면 파일 끝에
        # </nmaprun> 을 붙여 복구할 수도 있지만, 그건 nmap 이 쓰지 않은 문서를 우리가
        # 만들어 내는 일이라 자동으로 하지 않는다 — 하려면 사람이 관측 전용으로 판단해서.
        return "버림", ("XML 이 중간에서 끊겨 파싱되지 않습니다(nmap 이 끝맺지 못함). "
                       "완료된 호스트가 하나도 없으면 건질 것이 없습니다 — 다시 스캔하세요.")
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
    # 끝맺혔더라도 대상의 일부만 봤다면, 못 본 호스트에 대해 이 XML 은 아무 말도 하지 않는다.
    # 서버는 up 으로 잡힌 호스트에 대해서만 닫힘을 진행하므로 미탐으로 이어지지는 않지만,
    # '이 스캔으로 전 대역을 확인했다'고 읽으면 안 된다는 것은 알려야 한다.
    if info["hosts_total"] and info["hosts_up"] < info["hosts_total"]:
        down = info["hosts_total"] - info["hosts_up"]
        coverage = (f"대상 {info['hosts_total']}대 중 {info['hosts_up']}대만 응답했습니다"
                    f"(나머지 {down}대는 이 XML 이 아무 말도 하지 않습니다 — 닫힘 범위 밖).")
    else:
        coverage = ""

    if info["nse_candidates"] and not info["hosts_with_scripts"]:
        return ("재실행 권장",
                "포트 상태는 온전하지만 NSE 스크립트 결과가 하나도 없습니다 "
                "— 스크립트 단계가 정리되지 못했을 수 있습니다(서비스 상세만 손실). " + coverage)

    # 응답 없이 추정된 열린 포트가 섞여 있으면 그 사실을 말해 준다. UDP 는 open|filtered 가
    # 예외가 아니라 다수라, 이걸 '확인된 열림'으로 읽으면 실제보다 노출을 크게 본다.
    inferred = info["reasons"].get("no-response", 0)
    note = ""
    if inferred:
        note = (f" 열린 포트 {info['open_ports']}건 중 {inferred}건은 응답 없이 추정된 것입니다"
                "(재확인 대상).")
    return "사용 가능", ("포트 상태와 스크립트 결과가 모두 기록돼 있습니다." + note
                     + (" " + coverage if coverage else ""))


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
    buckets: dict[str, list[str]] = {}
    open_total = inferred_total = 0
    for path in files:
        info = inspect(path)
        mark, why = verdict(info)
        worst = max(worst, {"사용 가능": 0, "재실행 권장": 1,
                            "가져오기 거절": 2, "버림": 2}[mark])
        buckets.setdefault(mark, []).append(path.name)
        open_total += info["open_ports"]
        inferred_total += info["reasons"].get("no-response", 0)
        print(f"[{mark}] {path.name}")
        print(f"          호스트 {info['hosts']} · 열린 포트 {info['open_ports']} · "
              f"스크립트 있는 호스트 {info['hosts_with_scripts']}")
        if info["reasons"]:
            spread = " · ".join(f"{why_}={n}" for why_, n in sorted(info["reasons"].items()))
            print(f"          관측 근거: {spread}")
        print(f"          {why}")

    # 살릴 수 있는 것과 아닌 것을 마지막에 한 번 더 갈라 준다 — 파일이 수십 개면 위 목록만
    # 보고는 '무엇을 올려도 되는지'가 눈에 안 들어온다.
    print()
    print("=" * 60)
    usable = buckets.get("사용 가능", []) + buckets.get("재실행 권장", [])
    if usable:
        print(f"올려도 되는 XML {len(usable)}건:")
        for name in usable:
            print(f"  - {name}")
    else:
        print("올릴 수 있는 XML 이 없습니다.")
    for mark in ("재실행 권장", "가져오기 거절", "버림"):
        if buckets.get(mark):
            print(f"{mark} {len(buckets[mark])}건: {', '.join(buckets[mark])}")
    if inferred_total:
        print(f"열린 포트 {open_total}건 중 {inferred_total}건은 응답 없이 추정된 것입니다 "
              "— 올린 뒤 '재확인 필요'로 표시됩니다.")
    print("주의: 여기서 '사용 가능'은 그 XML 이 스캔한 호스트에 한정된 판정입니다. "
          "대상 대역 전체를 확인했다는 뜻이 아닙니다.")
    return 0 if worst == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
