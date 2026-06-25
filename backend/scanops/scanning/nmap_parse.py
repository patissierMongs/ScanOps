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
    # http-server-header 출력은 Server 값 그 자체(예: "uvicorn")
    ("http-server-header", "server", re.compile(r"\A\s*([^\r\n]+)")),
    # -sV 가 식별 못 한 포트: fingerprint-strings 원시 응답에서 Server 헤더를 건진다(소문자 server: 포함).
    ("fingerprint-strings", "server", re.compile(r"(?i)server:[ \t]*([^\r\n]+)")),
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


def pretty_fingerprint(raw: str) -> str:
    """fingerprint-strings 원시 응답을 사람이 읽기 좋게 정리.

    probe 그룹별로 들여쓰기를 정돈하고, 여러 probe 가 같은 응답을 낸 경우 합친다.
    프론트 columns.js prettyFingerprint 와 동일 로직(표=내보내기 동일).
    """
    if not raw:
        return ""
    blocks: list[dict] = []
    cur: dict | None = None
    for ln in str(raw).replace("\r", "").split("\n"):
        if not ln.strip():
            continue
        m = re.match(r"^\s{1,3}(\S.*?):\s*$", ln)   # probe 그룹 헤더
        if m:
            cur = {"probes": m.group(1), "body": []}
            blocks.append(cur)
        elif cur is not None:
            cur["body"].append(ln.strip())
        else:
            cur = {"probes": "", "body": [ln.strip()]}
            blocks.append(cur)
    seen: set[str] = set()
    out: list[str] = []
    for b in blocks:
        key = "\n".join(b["body"])
        if key in seen:
            continue
        seen.add(key)
        head = f"[{b['probes']}]\n" if b["probes"] else ""
        out.append(head + "\n".join(b["body"]))
    return "\n\n".join(out)


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
        # IP 만 — MAC(addrtype="mac")이 타깃/스코프로 새지 않게 ipv4 우선, 없으면 첫 비-MAC 주소.
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            for a in host.findall("address"):
                if (a.get("addrtype") or "").lower() != "mac":
                    addr_el = a
                    break
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
