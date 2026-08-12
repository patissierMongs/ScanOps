"""스캔 이력 요약 — 실행된 nmap 명령을 사람이 읽는 한 줄로 줄인다.

이력 표에 명령줄을 통째로 뿌리면 정작 알고 싶은 것(어디를·어떤 포트를·TCP 인지 UDP 인지)이
플래그 더미에 묻힌다. 요약은 **명령 자체에서** 뽑는다 — 요청 본문이 아니라 실제로 실행된
argv 를 근거로 삼아야 이력이 실행과 어긋나지 않는다.

포트는 숫자 나열 대신 규모를 말한다: 전체 65535 개를 '1-65535' 로 적으면 읽는 사람이
그게 전체인지 매번 계산해야 한다. 일부를 뺐다면 그 사실이 개수보다 중요하므로 따로 적는다.
"""
from __future__ import annotations

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
    """`T:1-65535,U:53` 에서 한 프로토콜의 본문만 뽑는다(접두사 없으면 통째로)."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not any(p[:2].upper() in ("T:", "U:") for p in parts):
        return spec.strip()
    body = []
    for part in parts:
        if part[:2].upper() == f"{prefix}:":
            body.append(part[2:])
        elif body and part[:2].upper() not in ("T:", "U:"):
            body.append(part)          # `T:1-100,200` 처럼 접두사가 이어지는 형태
    return ",".join(body)


def _describe_ports(spec: str, top_ports: str, excluded: str) -> str:
    if top_ports:
        label = f"상위 {top_ports}개"
    elif not spec:
        label = "기본 1000개"        # nmap 기본(포트 지정 없음)
    else:
        tcp, udp = _port_body(spec, "T"), _port_body(spec, "U")
        shown = tcp or udp or spec
        label = "전체" if shown.strip() == FULL_TCP else shown.strip()
    return f"{label} (일부 제외)" if excluded else label


def _describe_targets(targets: str, excluded_hosts: str) -> str:
    tokens = [t for t in (targets or "").replace(",", " ").split() if t]
    if not tokens:
        head = "—"
    elif len(tokens) == 1:
        head = tokens[0]
    else:
        head = f"{tokens[0]} 외 {len(tokens) - 1}건"
    return f"{head} (일부 제외)" if excluded_hosts else head


def summarize_command(command, targets: str = "") -> dict:
    """실행된 nmap 명령 → {targets, ports, protocols, excluded} 요약.

    protocols 는 스캔 기법 플래그로만 판단한다(-sU 없으면 UDP 를 스캔한 게 아니다).
    """
    tokens = _split(command)
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
    excluded_ports = _value_of(tokens, "--exclude-ports")
    excluded_hosts = _value_of(tokens, "--exclude")
    return {
        "targets": _describe_targets(targets, excluded_hosts),
        "ports": _describe_ports(port_spec, _value_of(tokens, "--top-ports"), excluded_ports),
        "protocols": protocols or ["TCP"],
        "excluded_ports": excluded_ports,
        "excluded_hosts": excluded_hosts,
    }
