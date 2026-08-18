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

# ── 노출 신호 ────────────────────────────────────────────────────────────────
# 이미 돌리고 있는 NSE 가 '이 포트가 왜 위험한가' 를 이미 말하고 있는데, 여태 remarks 문자열
# 한 줄로만 남아 등급에도 필터에도 쓰이지 못했다. 익명 FTP 와 잠긴 FTP 가 같은 발견이었다.
#
# 여기서는 **관측된 사실만** 뽑는다. 등급을 정하는 것은 taxonomy 의 일이다(관측과 판단을
# 섞지 않는다). 스크립트가 실패로 끝났으면 아무 말도 하지 않는다 - nse_failed 가 거른다.
_SMB_V1_RE = re.compile(r"(?i)\bSMBv1\b")
# nmap 은 `Not valid after: 2026-08-18T23:59:59` 처럼 **시각까지** 낸다. 날짜만 잘라 읽고
# 자정으로 되돌리면 오늘 만료되는 인증서가 하루 내내 이미 만료된 것으로 잡힌다.
_CERT_EXPIRY_RE = re.compile(r"(?i)Not valid after:\s*(\S+)")
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CERT_SUBJECT_RE = re.compile(r"(?i)^Subject:\s*(.+)$", re.M)
_CERT_ISSUER_RE = re.compile(r"(?i)^Issuer:\s*(.+)$", re.M)
_CERT_BITS_RE = re.compile(r"(?i)Public Key bits:\s*(\d+)")
_CERT_KEYTYPE_RE = re.compile(r"(?i)Public Key type:\s*(\S+)")
# 알고리즘별 최소 키 길이. 같은 비트수가 알고리즘마다 전혀 다른 강도를 뜻하므로
# 하나의 임계값을 전부에 들이대면 안 된다 - NIST SP 800-57 Part 1 Rev.5 가 요구하는
# 112비트 보안 강도 기준으로, RSA/DSA/DH 는 2048, ECC 는 224 다. EC 256(P-256)은
# 128비트 강도로 RSA 3072 급이라 약한 키가 아니다.
_KEY_MIN_BITS = {"rsa": 2048, "dsa": 2048, "dh": 2048, "ec": 224, "ecdsa": 224}
_VNC_TYPES_RE = re.compile(r"(?i)^\s*Security types:\s*(.*)$")


def _vnc_accepts_no_auth(output: str) -> bool:
    """vnc-info 가 인증 없음을 보고했는가.

    nmap 은 목록을 라벨 **다음 줄들**에 들여써서 낸다::

        Security types:
          None (1)

    그래서 한 줄짜리 정규식으로는 잡히지 않는다(실측으로 확인). 라벨 뒤에 이어지는
    더 들여쓴 블록만 훑어서, 다른 곳의 'None' 을 잘못 집지 않게 한다.
    """
    lines = output.splitlines()
    for index, line in enumerate(lines):
        match = _VNC_TYPES_RE.match(line)
        if not match:
            continue
        if re.search(r"(?i)\bNone\b", match.group(1)):
            return True
        indent = len(line) - len(line.lstrip())
        for follower in lines[index + 1:]:
            if not follower.strip():
                continue
            if len(follower) - len(follower.lstrip()) <= indent:
                break          # 블록이 끝났다
            if re.search(r"(?i)\bNone\b", follower):
                return True
    return False


def _cert_deadline(text: str) -> datetime | None:
    """ssl-cert 의 유효기간 끝 시각. 읽지 못하면 None - 그때는 만료를 주장하지 않는다.

    nmap 은 초 단위까지 낸다(`2026-08-18T23:59:59`). 빌드에 따라 `Z` 나 오프셋이 붙을 수
    있어 ISO 8601 로 읽고, 시간대가 없으면 nmap 의 출력대로 UTC 로 본다.

    날짜만 있는 경우에는 **그날 끝**으로 본다. 자정으로 읽으면 그날 하루가 통째로 '이미
    만료' 가 되는데, 만료는 등급을 올리는 신호라 모르는 쪽으로 기울여야 한다.
    """
    stamp = (text or "").strip()
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if _DATE_ONLY_RE.match(stamp):
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cert_signals(output: str) -> list[dict]:
    """ssl-cert 출력에서 만료·자체발급·약한 키를 뽑는다. CN 만 쓰고 나머지를 버리던 자리다."""
    out: list[dict] = []
    if match := _CERT_EXPIRY_RE.search(output):
        expiry = match.group(1)
        deadline = _cert_deadline(expiry)
        if deadline is not None and deadline < datetime.now(timezone.utc):
            out.append({"kind": "cert_expired", "detail": f"인증서 만료됨 (유효기간 {expiry} 까지)"})
    subject = _CERT_SUBJECT_RE.search(output)
    issuer = _CERT_ISSUER_RE.search(output)
    if subject and issuer and subject.group(1).strip() == issuer.group(1).strip():
        # RFC 5280 3.2 는 issuer=subject 를 **self-issued** 로 정의하고, 그 인증서 안의
        # 공개키로 서명이 검증될 때만 self-signed 라고 구분한다. ssl-cert 문자열에는 서명
        # 검증 결과가 없으므로 '자가서명'은 관측보다 강한 결론이다 - 같은 DN 을 쓰는 사설
        # CA 가 발급한 인증서도 여기 걸린다(실측으로 openssl verify 통과가 확인됐다).
        out.append({"kind": "self_issued",
                    "detail": "발급자와 주체가 같음(자체 발급) - 서명 검증은 이 출력으로 확인 불가"})
    # 키 길이는 **알고리즘과 함께** 읽어야 뜻이 생긴다. nmap 은 두 줄을 나란히 내는데
    # type 을 읽지 않고 2048 을 전부에 적용하면, 흔한 P-256 인증서가 전부 약한 키가 된다
    # (EC 384 조차 그랬다 - RSA 2048 보다 강한 키다).
    keytype = match.group(1).strip().lower() if (match := _CERT_KEYTYPE_RE.search(output)) else ""
    floor = _KEY_MIN_BITS.get(keytype)
    if floor and (bits := _CERT_BITS_RE.search(output)):
        try:
            size = int(bits.group(1))
        except ValueError:
            size = 0
        if 0 < size < floor:
            out.append({"kind": "weak_key",
                        "detail": f"약한 공개키 {keytype.upper()} {size}bit ({floor} 미만)"})
    # 모르는 알고리즘(Ed25519 등)은 판정하지 않는다. 그 곡선들은 256bit 로 128비트 강도를
    # 내므로, 비트수만 보고 약하다고 하면 정확히 거꾸로 말하게 된다.
    return out


def exposure_signals(nse: list[dict] | None) -> list[dict]:
    """NSE 출력 -> 구조화된 노출 사실 목록. 판단이 아니라 관측만 담는다.

    `[{"kind": ..., "detail": "사람이 읽는 근거"}]`. kind 는 taxonomy 가 등급을 올릴 때
    쓰는 기계 판독용 키이고, detail 은 화면·내보내기에 그대로 실린다.
    """
    signals: list[dict] = []
    for script in (nse or []):
        if not isinstance(script, dict):
            continue
        sid = str(script.get("id") or "").lower()
        output = str(script.get("output") or "")
        if not output or nse_failed(output):
            continue
        if sid == "ftp-anon" and "anonymous ftp login allowed" in output.lower():
            signals.append({"kind": "anon_access", "detail": "익명 FTP 로그인 허용"})
        elif sid == "telnet-encryption" and "does not support encryption" in output.lower():
            signals.append({"kind": "plaintext", "detail": "Telnet 암호화 미지원(평문 전송)"})
        elif sid == "smb-protocols" and _SMB_V1_RE.search(output):
            signals.append({"kind": "legacy_protocol", "detail": "SMBv1 지원(레거시 프로토콜)"})
        elif sid == "vnc-info" and _vnc_accepts_no_auth(output):
            signals.append({"kind": "no_auth", "detail": "VNC 인증 없음(Security type None)"})
        elif sid == "ssl-cert":
            signals.extend(_cert_signals(output))
    # 같은 사실이 여러 스크립트에서 겹쳐 나올 수 있다.
    seen: set[str] = set()
    unique: list[dict] = []
    for signal in signals:
        if signal["kind"] in seen:
            continue
        seen.add(signal["kind"])
        unique.append(signal)
    return unique


_NSE_FAILURE_RE = re.compile(r"(?i)^\s*ERROR:\s*(?:Script execution failed|Header request failed)\b")


def nse_failed(output: object) -> bool:
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
            if nse_failed(output):
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
        if nse_failed(script.get("output")):
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
    if not output or nse_failed(output):
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


def scan_finished(source) -> datetime | None:
    """이 XML 이 관측을 **끝낸** 시각(<runstats><finished time="epoch">) → UTC. 없으면 None.

    시작 시각과 완료 시각은 다른 사실이다. /24 스캔은 몇 시간을 돌기도 하므로, 시작 시각을
    관측 시각으로 쓰면 그 사이에 다른 스캔이 남긴 결과가 이 스캔보다 '새것'으로 판정된다.
    반대로 이 스캔이 실제로는 더 나중에 확인한 열린 포트가 '오래된 관측'으로 버려진다 -
    노출을 숨기는 미탐이다. 그래서 최신성 판단에는 완료 시각을 쓴다.
    """
    root = _root_of(source)
    for finished in root.findall("./runstats/finished"):
        raw = finished.get("time")
        if not raw:
            continue
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    return None


def observed_at(source) -> datetime | None:
    """이 XML 의 관측 시각 — 완료 시각이 있으면 그것, 없으면 시작 시각."""
    try:
        return scan_finished(source) or scan_start(source)
    except ET.ParseError:
        return None


def probed_identity(source) -> bool | None:
    """이 XML 이 '서비스 식별까지 관측한 실행'인가. 판단 불가면 None.

    포트 열림만 본 sweep(`-sS` 만)도 nmap 은 포트 표(nmap-services)의 이름을 `service
    name=` 에 채워 넣는다. 그걸 관측으로 받아들이면, 앞서 `-sV` 로 확인한 진짜 식별
    (OpenSSH 8.9)이 포트 번호 관례(ssh)로 덮인다. 파일명(단계 접미사)만으로 판정하면
    이름이 조금만 달라져도 — 중단본 번호, 사용자가 손으로 바꾼 이름 — 조용히 뚫린다.
    그래서 XML 이 스스로 들고 있는 실행 인자로도 본다.

    `args` 가 없는 XML(수기 생성 등)은 판단하지 않고 None 을 돌려준다 — 여기서 함부로
    '식별 아님'으로 몰면 정상적인 식별 인입이 갱신을 멈춘다.
    """
    root = _root_of(source)
    args = (root.get("args") or "").strip()
    if not args:
        return None
    return any(_enables_version_detection(token) for token in args.split())


def _enables_version_detection(token: str) -> bool:
    """이 nmap 인자 하나가 버전 탐지를 켜는가.

    `-s` 뒤의 스캔 타입 문자는 붙여 쓸 수 있다(`-sSV`, `-sSUV`). 그래서 `-sV` 만 정확히
    비교하면 `nmap -sSV` 로 돌린 XML 이 'sweep' 으로 잘못 분류되고, 진짜 식별 결과가
    관측으로 반영되지 않는다. `-sSU`(버전 탐지 없음)와는 V 유무로 갈린다.
    """
    if token == "-A" or token.startswith("--version"):
        return True
    return token.startswith("-s") and not token.startswith("--") and "V" in token[2:]


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
            # nmap 이 이 상태를 무엇을 보고 정했는지(syn-ack·conn-refused·no-response…).
            # 모든 단계가 --reason 을 이미 싣고 있어 XML 에 늘 있는데 여태 버리고 있었다.
            # 'open' 안에서도 syn-ack(응답을 받음)과 no-response(안 받고 추정)는 증거 강도가
            # 다르다 — 이 구분이 open|filtered 를 정직하게 표시하기 위한 최소 재료다.
            reason = (st.get("reason") if st is not None else "") or ""
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
                "reason": reason,
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
                # 이미 돌린 NSE 가 말한 노출 사실. 관측만 담고 등급은 taxonomy 가 정한다.
                "exposure_json": exposure_signals(nse),
                "remarks": remarks,
            })
    return findings
