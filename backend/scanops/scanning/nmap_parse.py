"""nmap XML → finding dict 파싱.

식별 품질(확인/추측/tcpwrapped/미확인)·NSE 핵심줄 추출·비고 조립은
nmapParser 의 검증된 로직을 포팅한 것.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from . import fingerprints

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
    ("http-server-header", "server", re.compile(r"(?i)\A\s*(?:server:[ \t]*)?([^\r\n]+)")),
    ("http-headers", "server", re.compile(r"(?im)^\s*server:[ \t]*([^\r\n]+)")),
    # -sV 가 식별 못 한 포트: fingerprint-strings 원시 응답에서 Server 헤더를 건진다(소문자 server: 포함).
    ("fingerprint-strings", "server", re.compile(r"(?im)^[ \t]*server:[ \t]*([^\r\n]+)")),
]

_SERVER_SOURCES = (
    ("http-server-header", re.compile(r"(?im)^[ \t]*(?:server:[ \t]*)?([^\r\n]+)")),
    ("http-headers", re.compile(r"(?im)^\s*server:[ \t]*([^\r\n]+)")),
    ("fingerprint-strings", re.compile(r"(?im)^[ \t]*server:[ \t]*([^\r\n]+)")),
)

_NSE_FAILURE_RE = re.compile(r"(?i)^\s*ERROR:\s*(?:Script execution failed|Header request failed)\b")


def _nse_failed(output: object) -> bool:
    """Nmap이 NSE 실패로 표준화한 출력은 관측값으로 취급하지 않는다."""
    return bool(_NSE_FAILURE_RE.match(str(output or "")))


def extract_server(nse: list[dict] | None) -> str:
    """NSE 원문에서 HTTP Server 자기신고 값을 우선순위대로 구조화한다.

    정규화된 Nmap ``service``는 taxonomy 키로 유지하고 이 값은 별도 관측 근거로 쓴다.
    """
    scripts = [s for s in (nse or []) if isinstance(s, dict)]
    for wanted, regex in _SERVER_SOURCES:
        for script in scripts:
            if wanted not in str(script.get("id") or "").lower():
                continue
            output = script.get("output")
            if _nse_failed(output):
                continue
            for match in regex.finditer(str(output or "")):
                value = " ".join(match.group(1).strip(" \t,").split())
                if value.lower() == "<empty>":
                    continue
                if value and "doesn't have" not in value.lower():
                    return value[:256]
    return ""


def server_observed(nse: list[dict] | None) -> bool:
    """Server 값을 확인할 수 있는 NSE 출처가 이번 스캔 결과에 있었는지."""
    fingerprint_scripts: list[dict] = []
    for script in nse or []:
        if not isinstance(script, dict):
            continue
        script_id = str(script.get("id") or "").lower()
        if _nse_failed(script.get("output")):
            continue
        if "http-server-header" in script_id or "http-headers" in script_id:
            # A successful direct header probe is authoritative even when the header is absent.
            return True
        if "fingerprint-strings" in script_id:
            # Fingerprints contain many unrelated successful responses. They only establish a
            # Server observation when an actual header line can be extracted.
            fingerprint_scripts.append(script)
    return bool(extract_server(fingerprint_scripts))


def _fingerprint_of(nse: list[dict] | None) -> str:
    """NSE 목록에서 fingerprint-strings 원시 응답만 뽑는다(모델의 동명 속성과 같은 계약)."""
    for script in nse or []:
        if isinstance(script, dict) and "fingerprint-strings" in str(script.get("id") or "").lower():
            return str(script.get("output") or "")
    return ""


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
    # 블록 파싱은 시그니처 대조와 같은 로직이라 fingerprints 에 한 벌만 둔다.
    blocks = fingerprints.fingerprint_blocks(raw)
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
    if not output or _nse_failed(output):
        return ""
    sid = (script_id or "").lower()
    for sid_match, label, regex in _REMARK_PATTERNS:
        if sid_match in sid:
            m = regex.search(output)
            if m:
                val = m.group(1).strip(" \t,")
                if label == "server" and val.lower() == "<empty>":
                    continue
                if not val or "doesn't have a title" in val.lower():
                    continue
                if len(val) > 80:
                    val = val[:77] + "..."
                return f"{label}={val}"
    return ""


def _remarks(detail: str, nse: list[dict]) -> str:
    parts = [detail] if detail else []
    server = extract_server(nse)
    if server:
        parts.append(f"server={server}")
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
            service = (svc.get("name") if svc is not None else "") or ""
            product = (svc.get("product") if svc is not None else "") or ""
            remarks = _remarks(detail, nse)
            # -sV 가 아무것도 못 알아낸 포트만 시그니처 표로 한 번 더 시도한다.
            # 관측된 service/product 가 있으면 절대 덮어쓰지 않는다.
            if not product and service.lower() in fingerprints.UNIDENTIFIED_SERVICES:
                hit = fingerprints.identify(_fingerprint_of(nse))
                if hit:
                    product = hit["product"]
                    evidence = f"fingerprint={hit['id']}"
                    remarks = f"{remarks} · {evidence}" if remarks else evidence
            findings.append({
                "host_ip": host_ip,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "proto": port.get("protocol") or "tcp",
                "state": state,
                "service": service,
                "product": product,
                "version": (svc.get("version") if svc is not None else "") or "",
                "server": extract_server(nse),
                # 세 상태 계약: 미관측(False) / 관측했으나 없음(True+"") / 값 있음(True+value).
                "server_observed": server_observed(nse),
                "banner": detail,
                "cpe": cpe,
                "rtt": rtt or "",
                "identification": _identification(svc),
                "nse_json": nse,
                "remarks": remarks,
            })
    return findings
