"""nmap XML → finding dict 파싱.

식별 품질(확인/추측/tcpwrapped/미확인)·NSE 핵심줄 추출·비고 조립은
nmapParser 의 검증된 로직을 포팅한 것.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# (script_id 부분일치, 라벨, 정규식) — NSE 출력에서 한 줄 핵심 추출
_REMARK_PATTERNS = [
    ("ssl-cert", "CN", re.compile(r"commonName=([^\n,/]+)")),
    ("smb-os-discovery", "OS", re.compile(r"OS:\s*([^\n]+)")),
    ("smb-os-discovery", "host", re.compile(r"Computer name:\s*([^\n]+)")),
    ("rdp-ntlm-info", "DNS_Computer_Name", re.compile(r"DNS_Computer_Name:\s*([^\n]+)")),
    ("rdp-ntlm-info", "Target_Name", re.compile(r"Target_Name:\s*([^\n]+)")),
    ("nbstat", "host", re.compile(r"Computer name:\s*([^\n]+)")),
    ("http-title", "title", re.compile(r"\A\s*([^\n]+)")),
]


def _identification(svc) -> str:
    if svc is None:
        return "미확인"
    name = (svc.get("name") or "").strip()
    method = (svc.get("method") or "").strip()
    if not name or name == "unknown":
        return "미확인"
    if name == "tcpwrapped":
        return "tcpwrapped"
    if method == "probed":
        return "확인"
    if method == "table":
        return "추측"
    return "미확인"


def _extract_key_line(script_id: str, output: str) -> str:
    if not output:
        return ""
    sid = (script_id or "").lower()
    for sid_match, label, regex in _REMARK_PATTERNS:
        if sid_match in sid:
            m = regex.search(output)
            if m:
                val = m.group(1).strip(" \t,")
                if not val or "doesn't have a title" in val.lower():
                    continue
                if len(val) > 80:
                    val = val[:77] + "..."
                return f"{label}={val}"
    return ""


def _remarks(detail: str, nse: list[dict]) -> str:
    parts = [detail] if detail else []
    for s in nse:
        key = _extract_key_line(s["id"], s["output"])
        if key and key not in parts:
            parts.append(key)
            if len(parts) >= 2:
                break
    return ", ".join(parts)


def _detail(svc) -> str:
    if svc is None:
        return ""
    bits = [svc.get("product"), svc.get("version"), svc.get("extrainfo"), svc.get("ostype")]
    return " ".join(b for b in bits if b)


def _root_of(source):
    if isinstance(source, bytes):
        return ET.fromstring(source)
    if isinstance(source, str):
        if source.lstrip().startswith("<"):
            return ET.fromstring(source)
        return ET.parse(source).getroot()  # 파일 경로
    return ET.parse(source).getroot()  # 파일 객체


def scan_start(source) -> datetime | None:
    """nmap XML 의 실제 스캔 시작 시각(<nmaprun start="epoch">) → UTC datetime. 없으면 None.
    가져온 XML 의 '스캔 날짜'를 인입 시각이 아니라 실제 실행일로 잡는 데 쓴다."""
    root = _root_of(source)
    start = root.get("start")
    if not start:
        return None
    try:
        return datetime.fromtimestamp(int(start), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def up_hosts(source) -> set[str]:
    """이번 스캔에서 살아있던(up) 호스트 IP 집합 — 닫힘 판정 범위에 사용."""
    root = _root_of(source)
    ips: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is not None:
            ips.add(addr_el.get("addr"))
    return ips


def parse_xml(source) -> list[dict]:
    """XML 경로/바이트/문자열 → finding dict 목록(상태 포함 모든 포트)."""
    root = _root_of(source)

    findings: list[dict] = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else ""
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else ""
        times = host.find("times")
        rtt = times.get("srtt") if times is not None else ""

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            st = port.find("state")
            state = st.get("state") if st is not None else "open"
            # 발견 = 열린 포트만. 닫힘/필터는 인입하지 않는다(닫힘은 '부재'로 판정).
            # nmap 을 --open 없이 돌려 닫힌 포트가 XML 에 섞여도 안전.
            if not state.startswith("open"):
                continue
            svc = port.find("service")
            nse = [{"id": s.get("id") or "", "output": s.get("output") or ""}
                   for s in port.findall("script")]
            cpe = ";".join(c.text or "" for c in (svc.findall("cpe") if svc is not None else []))
            detail = _detail(svc)
            findings.append({
                "host_ip": host_ip,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "proto": port.get("protocol") or "tcp",
                "state": state,
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "banner": detail,
                "cpe": cpe,
                "rtt": rtt or "",
                "identification": _identification(svc),
                "nse_json": nse,
                "remarks": _remarks(detail, nse),
            })
    return findings
