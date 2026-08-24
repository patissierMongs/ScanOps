"""스캔 이력 요약 — 실행된 nmap 명령을 사람이 읽는 한 줄로 줄인다.

이력 표에 명령줄을 통째로 뿌리면 정작 알고 싶은 것(어디를·어떤 포트를·TCP 인지 UDP 인지)이
플래그 더미에 묻힌다. 요약은 **명령 자체에서** 뽑는다 — 요청 본문이 아니라 실제로 실행된
argv 를 근거로 삼아야 이력이 실행과 어긋나지 않는다.

포트는 숫자 나열 대신 규모를 말한다: 전체 65535 개를 '1-65535' 로 적으면 읽는 사람이
그게 전체인지 매번 계산해야 한다. 일부를 뺐다면 그 사실이 개수보다 중요하므로 따로 적는다.
"""
from __future__ import annotations

import ipaddress
import re

from . import chunker, scope

FULL_TCP = "1-65535"
# 값을 뒤 토큰으로 받는 옵션 — 그 값을 타겟으로 오인하지 않기 위해 건너뛴다.
_VALUE_OPTIONS = frozenset({
    "-p", "--top-ports", "--exclude", "--exclude-ports", "--script", "--script-args",
    "--script-timeout", "--max-retries", "--min-hostgroup", "--max-hostgroup",
    "--max-parallelism", "--min-parallelism", "--max-rate", "--min-rate",
    "--host-timeout", "--scan-delay", "--max-scan-delay", "--stats-every",
    "-oA", "-oN", "-oX", "-oG", "-oS", "--datadir", "-e", "-S", "-g", "--source-port",
    "-D", "-b", "-sI", "--proxies", "--dns-servers", "--data-length", "--ttl", "--mtu",
    "--version-intensity", "--initial-rtt-timeout", "--max-rtt-timeout", "--min-rtt-timeout",
})


def _split(argv) -> list[str]:
    if isinstance(argv, str):
        return argv.split()
    return [str(t) for t in (argv or [])]


def _value_of(tokens: list[str], option: str) -> str:
    """`-p 22` 와 `--exclude-ports=22` 두 표기를 모두 읽는다."""
    for index, token in enumerate(tokens):
        if token == option and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith(f"{option}="):
            return token.split("=", 1)[1]
    return ""


def _port_body(spec: str, prefix: str) -> str:
    """`T:1-65535,U:53,161` 에서 한 프로토콜의 본문만 뽑는다(접두사 없으면 통째로).

    접두사 없는 항목은 **직전 접두사에 이어지는 값**이다(`U:53,161` 의 161 은 UDP). 그것을
    무조건 요청한 프로토콜에 붙이면 UDP 포트가 TCP 목록에 섞여 이력이 스캔하지 않은 TCP
    포트를 봤다고 말한다.
    """
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not any(p[:2].upper() in ("T:", "U:") for p in parts):
        return spec.strip()
    want, current, body = prefix.upper(), "", []
    for part in parts:
        head = part[:2].upper()
        if head in ("T:", "U:"):
            current, part = head[0], part[2:]
        if current == want and part:
            body.append(part)
    return ",".join(body)


def _describe_ports(spec: str, top_ports: str, excluded: str) -> str:
    if top_ports:
        label = f"상위 {top_ports}개"
    elif not spec:
        label = "기본 1000개"        # nmap 기본(포트 지정 없음)
    else:
        # 한쪽만 보여 주면 'TCP·UDP' 뱃지 옆에 TCP 범위만 붙어, UDP 도 그 범위로 스캔한 것처럼
        # 읽힌다. `-p T:1-100,U:53` 은 UDP 를 두 포트만 본 스캔이다. 단 접두사가 없는
        # `-p 1-65535` 는 두 프로토콜이 같은 범위라 나눠 적을 것이 없다.
        label = _proto_split_label(spec) or _one_proto_label(spec)
    return f"{label} (일부 제외)" if excluded else label


def _has_proto_prefix(spec: str) -> bool:
    return any(part.strip()[:2].upper() in ("T:", "U:") for part in spec.split(",") if part.strip())


def _proto_split_label(spec: str) -> str:
    """접두사로 나뉜 TCP/UDP 범위를 둘 다 적는다. 나눌 게 없으면 빈 문자열."""
    if not _has_proto_prefix(spec):
        return ""
    tcp, udp = _port_body(spec, "T"), _port_body(spec, "U")
    if tcp and udp:
        return f"TCP {_one_proto_label(tcp)} · UDP {_one_proto_label(udp)}"
    return _one_proto_label(tcp or udp)


# ── 명령 표기가 argv 가 아닐 때의 범위 꼬리표 ────────────────────────────────
# 엔진 스캔·자동 스캔·가져오기는 실행된 argv 가 아니라 사람이 읽는 설명을 command 에 남긴다.
# 그 설명을 nmap argv 로 착각해 파싱하면 `-p` 가 없다는 이유로 '기본 1000개 · TCP' 가 되어,
# 전 포트 TCP+UDP 스캔이 이력에서 상위 1000개 TCP 스캔으로 보인다. 관측하지 않은 것을 관측했다고
# 말하는 것과 같은 종류의 오류다 - 그래서 만든 쪽이 범위를 정규 형식으로 함께 적고, 읽는 쪽은
# 그것만 근거로 삼는다. 꼬리표가 없고 argv 도 아니면 '알 수 없음'이라고 말한다.
SCOPE_MARK = "범위:"
UNKNOWN_PORTS = "알 수 없음"


def scope_note(tcp: str = "", udp: str = "") -> str:
    """`범위: T:1-65535 U:53,161` — 명령 표기 뒤에 붙이는 기계 판독용 범위.

    비활성 프로토콜은 아예 적지 않는다(빈 문자열과 '스캔 안 함'을 같게 두면 다시 넘겨짚게 된다).
    """
    parts = []
    for prefix, value in (("T", tcp), ("U", udp)):
        body = _port_body(str(value or "").strip(), prefix) or str(value or "").strip()
        # 호출자마다 "1-65535" 로도, 이미 "T:1-65535" 로도 넘긴다. 접두사가 두 번 붙으면
        # 읽는 쪽이 통째로 흘려버려 다시 '알 수 없음'이 된다.
        if body:
            parts.append(f"{prefix}:{body}")
    return f"{SCOPE_MARK} {' '.join(parts)}" if parts else f"{SCOPE_MARK} 없음"


def _read_scope_note(command: str) -> dict | None:
    """command 꼬리표에서 프로토콜·포트를 읽는다. 꼬리표가 없으면 None."""
    index = command.rfind(SCOPE_MARK)
    if index < 0:
        return None
    body = command[index + len(SCOPE_MARK):].strip()
    protocols, specs = [], []
    for token in body.split():
        head, _, ports = token.partition(":")
        if head.upper() == "T" and ports:
            protocols.append("TCP")
            specs.append(f"T:{ports}")
        elif head.upper() == "U" and ports:
            protocols.append("UDP")
            specs.append(f"U:{ports}")
    return {"protocols": protocols, "spec": ",".join(specs)}


def _one_proto_label(body: str) -> str:
    return "전체" if body.strip() == FULL_TCP else body.strip()


def _describe_noted_ports(noted: dict, excluded: str) -> str:
    """꼬리표 범위의 표시 문구. 두 프로토콜을 스캔했으면 둘 다 적는다.

    한쪽만 보여 주면 'TCP·UDP' 뱃지 옆에 TCP 범위만 붙어, UDP 를 그 범위로 스캔한 것처럼
    읽힌다(실제로는 53,161 몇 개뿐이다).
    """
    spec = noted["spec"]
    if not spec:
        return "없음"
    label = _proto_split_label(spec)
    return f"{label} (일부 제외)" if excluded else label


def _looks_like_nmap_argv(tokens: list[str]) -> bool:
    """첫 토큰이 nmap 실행 파일인가 — 그래야 '포트 플래그 없음 = 기본 1000개'가 참이다."""
    if not tokens:
        return False
    head = tokens[0].strip('"').replace("\\", "/").rsplit("/", 1)[-1].lower()
    return head.startswith("nmap")


# 이력 표가 대상 칸에 쓰는 것은 **경계와 개수**뿐이다. 그걸 얻자고 대역을 통째로
# 펼치면 /16 하나가 65,536 개의 문자열을 만들고 정렬까지 한다 - 목록의 **행마다**,
# 화면을 열 때마다. CIDR 자체가 이미 그 답을 갖고 있으므로 정수 구간으로 센다.
# 읽을 수 없는 토큰이 하나라도 있으면 손대지 않고 원래 경로로 넘긴다(같은 답, 같은 오류).
_HOST_CAP = 65536
# 확장 경로(chunker._RANGE_RE)와 같은 모양이어야 한다 - 여기서만 받아주는 표기가 있으면
# 두 경로가 다른 답을 낸다.
_LAST_OCTET_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")


def _token_interval(token: str) -> tuple[int, int, int] | None:
    """토큰 하나 → (주소 버전, 시작, 끝). 정수 구간으로 못 읽으면 None."""
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None
        # 확장 규칙과 같다 - 네트워크/브로드캐스트까지 전수.
        return (net.version, int(net.network_address), int(net.broadcast_address))
    if match := _LAST_OCTET_RANGE_RE.match(token):
        base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        octets = [int(part) for part in base.split(".")]
        if any(part > 255 for part in octets) or lo > hi or hi > 255:
            return None
        try:
            start = ipaddress.ip_address(f"{base}.{lo}")
            end = ipaddress.ip_address(f"{base}.{hi}")
        except ValueError:
            return None
        return (start.version, int(start), int(end))
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    return (address.version, int(address), int(address))


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _subtract(spans: list[tuple[int, int]], cuts: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = list(spans)
    for cut_start, cut_end in cuts:
        nxt: list[tuple[int, int]] = []
        for start, end in out:
            if cut_end < start or cut_start > end:
                nxt.append((start, end))
                continue
            if start < cut_start:
                nxt.append((start, cut_start - 1))
            if cut_end < end:
                nxt.append((cut_end + 1, end))
        out = nxt
    return out


def _target_bounds(tokens: list[str], excluded: list[str]) -> tuple[int, str, str] | None:
    """(호스트 수, 첫 대상, 마지막 대상). 펼치지 않고 센다. 못 세면 None."""
    spans: dict[int, list[tuple[int, int]]] = {}
    names: set[str] = set()
    for token in tokens:
        interval = _token_interval(token)
        if interval is None:
            if "/" in token or _LAST_OCTET_RANGE_RE.match(token) \
                    or chunker.is_unsupported_composite_ipv4_range(token):
                return None            # 확장 경로가 오류로 처리할 토큰 - 그쪽에 맡긴다.
            names.add(token)           # 호스트명은 그대로 한 대다.
            continue
        version, start, end = interval
        spans.setdefault(version, []).append((start, end))
    cuts: list[tuple[int, int]] = []
    for token in excluded:
        interval = _token_interval(token)
        if interval is None or interval[0] != 4:
            return None                # 제외 규칙을 못 읽으면 개수를 말하지 않는다.
        cuts.append((interval[1], interval[2]))
    for version in list(spans):
        merged = _merge(spans[version])
        spans[version] = _subtract(merged, cuts) if version == 4 and cuts else merged

    total = sum(end - start + 1 for version_spans in spans.values()
                for start, end in version_spans) + len(names)
    if total == 0:
        return (0, "", "")
    if total > _HOST_CAP:
        return None                    # 확장 경로가 거절하는 크기 - 표기도 그때와 같아야 한다.

    def render(version: int, value: int) -> str:
        return str(ipaddress.ip_address(value) if version == 4
                   else ipaddress.IPv6Address(value))

    ordered_versions = sorted(v for v, rows in spans.items() if rows)
    first = last = ""
    if ordered_versions:
        low = ordered_versions[0]
        high = ordered_versions[-1]
        first = render(low, min(start for start, _ in spans[low]))
        last = render(high, max(end for _, end in spans[high]))
    if names:
        # 호스트명은 IP 뒤에 온다(_describe_targets 의 정렬 규칙과 같다).
        last = sorted(names, key=str.casefold)[-1]
        if not first:
            first = sorted(names, key=str.casefold)[0]
    return (total, first, last)


def _describe_targets(targets: str, excluded_hosts: str) -> str:
    tokens = [t for t in (targets or "").replace(",", " ").split() if t]
    if not tokens:
        return "—"
    excluded_tokens = [t for t in excluded_hosts.replace(",", " ").split() if t]
    bounds = _target_bounds(tokens, excluded_tokens)
    if bounds is not None:
        count, first, last = bounds
        if not count:
            return "대상 0대"
        return f"{first if first == last else f'{first} – {last}'} · 대상 {count}대"
    try:
        hosts = chunker.expand_targets(tokens)
        excluded = [t for t in excluded_hosts.replace(",", " ").split() if t]
        hosts = scope.apply_excludes(hosts, excluded)
    except ValueError:
        # 오래된 직접 명령에는 Nmap 전용 복합 범위가 남아 있을 수 있다. 실제 호스트 수를
        # 확정할 수 없는 이력은 그럴듯한 숫자를 만들지 않고 기존 축약 표기로 되돌린다.
        head = tokens[0] if len(tokens) == 1 else f"{tokens[0]} 외 {len(tokens) - 1}건"
        return f"{head} (일부 제외)" if excluded_hosts else head

    def order(host: str) -> tuple:
        try:
            address = ipaddress.ip_address(host)
            return (0, address.version, int(address))
        except ValueError:
            return (1, 0, host.casefold())

    ordered = sorted(hosts, key=order)
    if not ordered:
        return "대상 0대"
    bounds = ordered[0] if len(ordered) == 1 else f"{ordered[0]} – {ordered[-1]}"
    return f"{bounds} · 대상 {len(ordered)}대"


def summarize_command(command, targets: str = "") -> dict:
    """실행된 nmap 명령 → {targets, ports, protocols, excluded} 요약.

    protocols 는 스캔 기법 플래그로만 판단한다(-sU 없으면 UDP 를 스캔한 게 아니다).
    """
    text = command if isinstance(command, str) else " ".join(_split(command))
    tokens = _split(command)
    excluded_ports = _value_of(tokens, "--exclude-ports")
    excluded_hosts = _value_of(tokens, "--exclude")

    noted = _read_scope_note(text)
    if noted is not None:
        # 만든 쪽이 적어 준 범위가 가장 정확하다 - argv 파싱보다 먼저 본다.
        return {
            "targets": _describe_targets(targets, excluded_hosts),
            "ports": _describe_noted_ports(noted, excluded_ports),
            "protocols": noted["protocols"],
            "excluded_ports": excluded_ports,
            "excluded_hosts": excluded_hosts,
        }

    if not _looks_like_nmap_argv(tokens):
        # 실행된 argv 가 아니다(설명 문구이거나 비어 있다). 여기서 nmap 기본값을 가정하면
        # 스캔하지도 않은 범위를 이력이 단언하게 된다 - 모른다고 말한다.
        return {
            "targets": _describe_targets(targets, excluded_hosts),
            "ports": UNKNOWN_PORTS,
            "protocols": [],
            "excluded_ports": excluded_ports,
            "excluded_hosts": excluded_hosts,
        }

    protocols: list[str] = []
    if any(t.startswith("-s") and not t.startswith("--")
           and any(c in t[2:] for c in "STAWMNFX") for t in tokens):
        protocols.append("TCP")
    if any(t.startswith("-s") and not t.startswith("--") and "U" in t[2:] for t in tokens):
        protocols.append("UDP")
    port_spec = _value_of(tokens, "-p")
    if not protocols and port_spec:
        # 기법 플래그가 없으면 nmap 기본은 TCP 다. 포트 접두사로 UDP 여부만 보정한다.
        protocols = ["TCP"]
        if "U:" in port_spec.upper():
            protocols.append("UDP")
    return {
        "targets": _describe_targets(targets, excluded_hosts),
        "ports": _describe_ports(port_spec, _value_of(tokens, "--top-ports"), excluded_ports),
        "protocols": protocols or ["TCP"],
        "excluded_ports": excluded_ports,
        "excluded_hosts": excluded_hosts,
    }
