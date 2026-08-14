"""가져온 XML 이 믿을 만한지 판정한다 — 단독 스캐너 도구(check_scan_xml.py)와 같은 규칙.

가져오기는 파일을 받는 순간 끝나는 일이 아니다. nmap 이 중간에 죽어 XML 을 끝맺지 못했거나,
포트 상태는 멀쩡한데 스크립트 단계만 날아갔거나, 응답한 호스트가 대상의 일부뿐일 수 있다.
그 사실을 사용자가 따로 도구를 돌려야만 알 수 있다면 대부분은 모른 채 지나간다 — 그래서
서버가 가져오기마다 자동으로 같은 판정을 붙인다.

판정은 닫힘 권한을 바꾸지 않는다. 그건 이미 산출물 완결성 계약이 따로 판단한다. 여기서 하는
일은 **사람에게 사실을 알리는 것**뿐이다.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

# NSE 가 붙는 UDP 포트 — 여기에 스크립트 결과가 하나도 없으면 스크립트 단계가 날아갔을 수 있다.
_NSE_UDP_PORTS = frozenset({53, 111, 123, 137, 161, 500, 5060})

USABLE = "사용 가능"
RESCAN = "재실행 권장"
REJECT = "가져오기 거절"
DISCARD = "버림"


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def inspect(xml_bytes: bytes, filename: str = "", stage: str = "") -> dict:
    """XML 한 건의 관측 사실. 파싱 실패도 '사실'이라 예외로 던지지 않는다."""
    out = {
        "parse": True, "finished": False, "exit": "", "hosts": 0, "open_ports": 0,
        "hosts_with_scripts": 0, "nse_candidates": 0, "protocols": set(),
        "hosts_up": 0, "hosts_total": 0, "inferred_open": 0, "stage": stage,
    }
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        out["parse"] = False
        return out
    finished = root.findall("./runstats/finished")
    if finished:
        out["finished"] = True
        out["exit"] = finished[0].get("exit") or ""
    stats = root.find("./runstats/hosts")
    if stats is not None:
        out["hosts_up"] = _int(stats.get("up"))
        out["hosts_total"] = _int(stats.get("total"))
    out["protocols"] = {
        (info.get("protocol") or "").lower() for info in root.findall("./scaninfo")
    }
    hosts = root.findall("host")
    out["hosts"] = len(hosts)
    for host in hosts:
        has_script = host.find("./hostscript") is not None
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and (state.get("state") or "").startswith("open"):
                out["open_ports"] += 1
                # 같은 open 이라도 syn-ack(응답 확인)과 no-response(무응답 추정)는 증거 강도가
                # 다르다. 기록이 없으면 '미관측'이지 '무응답'이 아니므로 세지 않는다.
                if (state.get("reason") or "").strip() == "no-response":
                    out["inferred_open"] += 1
            if _int(port.get("portid")) in _NSE_UDP_PORTS:
                out["nse_candidates"] += 1
            if port.find("script") is not None:
                has_script = True
        if has_script:
            out["hosts_with_scripts"] += 1
    return out


def verdict(info: dict) -> tuple[str, str]:
    """(판정, 이유). check_scan_xml.py 와 같은 순서·같은 근거로 판단한다."""
    if not info["parse"]:
        return DISCARD, ("XML 이 중간에서 끊겨 파싱되지 않습니다(nmap 이 끝맺지 못함).")
    if not info["finished"]:
        return DISCARD, "<finished> 가 없습니다 - nmap 이 결과를 마무리하지 못했습니다."
    if info["exit"] != "success":
        return DISCARD, f'nmap 이 exit="{info["exit"]}" 로 끝났습니다.'
    if info["stage"] == "udp_identify" and info["protocols"] - {"udp"}:
        mixed = ",".join(sorted(p for p in info["protocols"] if p))
        return REJECT, (f"UDP 식별 XML 인데 scaninfo 에 {mixed} 가 섞여 있습니다 - "
                        "스캔 기법이 UDP 단계로 새던 옛 버전의 산출물입니다.")

    notes = []
    if info["hosts_total"] and info["hosts_up"] < info["hosts_total"]:
        down = info["hosts_total"] - info["hosts_up"]
        notes.append(f"대상 {info['hosts_total']}대 중 {info['hosts_up']}대만 응답했습니다"
                     f"(나머지 {down}대는 이 XML 이 아무 말도 하지 않습니다).")
    if info["inferred_open"]:
        notes.append(f"열린 포트 {info['open_ports']}건 중 {info['inferred_open']}건은 "
                     "응답 없이 추정된 것입니다(재확인 대상).")

    if info["nse_candidates"] and not info["hosts_with_scripts"]:
        return RESCAN, " ".join(
            ["포트 상태는 온전하지만 NSE 스크립트 결과가 하나도 없습니다 "
             "- 스크립트 단계가 정리되지 못했을 수 있습니다(서비스 상세만 손실)."] + notes)
    return USABLE, " ".join(["포트 상태와 스크립트 결과가 모두 기록돼 있습니다."] + notes)


def review(xml_bytes: bytes, filename: str = "", stage: str = "") -> dict:
    """가져오기 1건의 자동 검증 결과 — {mark, why, usable}."""
    mark, why = verdict(inspect(xml_bytes, filename, stage))
    return {"file": filename, "mark": mark, "why": why, "usable": mark == USABLE}


def worst(reviews: list[dict]) -> dict | None:
    """묶음 전체에서 가장 나쁜 판정 하나. 없으면 None."""
    order = {USABLE: 0, RESCAN: 1, REJECT: 2, DISCARD: 2}
    ranked = sorted(reviews, key=lambda r: -order.get(r["mark"], 0))
    return ranked[0] if ranked else None


def scan_scope(xml_bytes: bytes) -> tuple[str, str]:
    """XML 이 스스로 밝힌 스캔 범위 -> (TCP 포트 표기, UDP 포트 표기).

    가져온 스캔의 '스캔 범위'는 추측할 필요가 없다. nmap 이 `<scaninfo services=>` 에 정확히
    적어 둔다. 이걸 읽지 않으면 이력 요약이 명령이 없다는 이유로 nmap 기본값(상위 1000개
    TCP)을 가정해, UDP 만 스캔한 XML 도 TCP 스캔으로 표시된다.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return "", ""
    found = {"tcp": [], "udp": []}
    for info in root.findall("./scaninfo"):
        proto = (info.get("protocol") or "").lower()
        services = (info.get("services") or "").strip()
        if proto in found and services:
            found[proto].append(services)
    return ",".join(found["tcp"]), ",".join(found["udp"])
