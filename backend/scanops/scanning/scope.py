"""스캔 허용 대역(scope) 게이트 — 설정된 CIDR/IP 범위 밖 타겟을 시작 전에 거절.

네트워크 스캐너는 그 자체로 민감 도구다. 오타 한 번(10.0 → 100.0)이나 잘못 붙여넣은
대역이 사외·타조직을 스캔하는 사고로 이어진다. scope 가 설정돼 있으면(설정 비면 무제한,
하위호환) 확장된 호스트 전부가 허용 대역 안에 드는지 검증하고, 하나라도 벗어나면
ValueError 로 막는다. IP 가 아닌 토큰(호스트명 등)은 CIDR 로 검증 불가하므로 거절한다.
"""
from __future__ import annotations

import ipaddress

from ..config import get_settings
from .scan_options import NSE_SCRIPTS


def parse_scope(spec: str) -> list[ipaddress._BaseNetwork]:
    """콤마/공백 구분 CIDR·IP 목록. 설정 토큰 하나라도 잘못되면 전체를 거절한다."""
    nets: list[ipaddress._BaseNetwork] = []
    for raw in (spec or "").replace(",", " ").split():
        t = raw.strip()
        if not t:
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError as exc:
            raise ValueError(f"잘못된 스캔 대역(scope) 설정입니다: {t!r}") from exc
    return nets


def parse_excludes(tokens: list[str] | None) -> list[str]:
    """제외 IPv4/IP-CIDR 토큰을 검증·정규화하고 입력 순서로 중복 제거한다.

    제외는 안전 경계이므로 토큰 하나라도 잘못되면 전체 요청을 거절한다. 단일 IP는
    IP 표기를 유지하고, CIDR은 host bit를 정규화하되 개별 주소로 확장하지 않는다.
    """
    if tokens is None:
        return []
    if not isinstance(tokens, list):
        raise ValueError("제외 대상은 IPv4 주소/CIDR 목록이어야 합니다.")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in tokens:
        if not isinstance(raw, str) or not (token := raw.strip()):
            raise ValueError("제외 대상에 빈 토큰을 사용할 수 없습니다.")
        try:
            address = ipaddress.ip_address(token)
            if address.version != 4:
                raise ValueError
            value = str(address)
        except ValueError:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"잘못된 제외 대상 IPv4/CIDR입니다: {token!r}") from exc
            if network.version != 4:
                raise ValueError(f"IPv6 제외 대상은 아직 지원하지 않습니다: {token!r}")
            value = (str(network.network_address)
                     if network.prefixlen == network.max_prefixlen else str(network))
        if value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized


def apply_excludes(hosts: list[str], tokens: list[str] | None) -> list[str]:
    """확장·중복 제거된 host 목록에서 검증된 IPv4/IP-CIDR 제외 범위를 뺀다."""
    normalized = parse_excludes(tokens)
    if not normalized:
        return list(hosts)
    networks = [ipaddress.ip_network(token, strict=False) for token in normalized]
    kept: list[str] = []
    for host in hosts:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            kept.append(host)  # hostname은 IPv4/CIDR 제외와 일치할 수 없다.
            continue
        if address.version != 4 or not any(address in network for network in networks):
            kept.append(host)
    return kept


def is_ip_token(token: str) -> bool:
    """토큰이 IP 또는 CIDR 인지. 호스트명/복합 nmap 문법은 False."""
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _in_scope(host: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    # 단일 IP 는 멤버십, CIDR 토큰은 허용망의 서브넷인지로 판정.
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(host, strict=False)
        return any(net.version == n.version and net.subnet_of(n) for n in nets)
    except ValueError:
        return False  # IP/CIDR 가 아니면(호스트명/복합문법) 범위 검증 불가 → scope 모드에선 불허


def check_scope(hosts: list[str], spec: str | None = None) -> None:
    """허용 대역이 설정돼 있으면 모든 host 가 그 안에 드는지 검증. 비면 무제한(통과).

    범위 밖 호스트가 있으면 ValueError(처음 몇 개를 메시지에 노출). 비-IP 토큰도 거절."""
    if spec is None:
        spec = get_settings().scan_scope
    nets = parse_scope(spec)
    if not nets:
        return  # scope 미설정 — 제한 없음
    bad = [h for h in hosts if not _in_scope(h, nets)]
    if bad:
        shown = ", ".join(bad[:5]) + (f" 외 {len(bad) - 5}건" if len(bad) > 5 else "")
        raise ValueError(f"허용된 스캔 대역(scope) 밖의 대상입니다: {shown}")


# 직접 명령에서 타겟이 아닌 파일/랜덤 입력 — scope 검증을 우회하므로 scope 설정 시 차단.
# 붙여 쓴 형태(-iR10, -iL=hosts.txt)도 같은 옵션이다.
_UNSCOPED_TARGET_OPTIONS = ("-iL", "-iR", "--excludefile", "--exclude-file", "--resume")

# nmap 옵션 중 다음 토큰을 값으로 소비하는 항목. 이 값을 타겟으로 오인하면
# `-p 22`, `--script http-title` 같은 정상 명령을 막게 된다. 알 수 없는 옵션의
# 다음 값은 안전하게 위치 타겟으로 다룬다(비-IP면 거절되므로 fail-closed).
_RAW_OPTIONS_WITH_VALUE = frozenset({
    "-b", "-D", "-e", "-g", "-oA", "-oG", "-oN", "-oS", "-oX", "-p", "-S", "-sI",
    "--data", "--data-length", "--data-string", "--datadir", "--dns-servers",
    "--exclude", "--exclude-ports", "--host-timeout", "--initial-rtt-timeout", "--ip-options",
    "--max-hostgroup", "--max-os-tries", "--max-parallelism", "--max-rate",
    "--max-retries", "--max-rtt-timeout", "--max-scan-delay", "--min-hostgroup",
    "--min-parallelism", "--min-rate", "--min-rtt-timeout", "--mtu", "--port-ratio",
    "--proxies", "--scan-delay", "--scanflags", "--script", "--script-args",
    "--script-args-file", "--script-help", "--script-timeout", "--source-port",
    "--spoof-mac", "--stats-every", "--stylesheet", "--top-ports", "--ttl",
    "--version-intensity",
})

# A scoped raw command may use the same named NSE scripts as the structured scanner, but it
# must not enable Nmap's dynamic target queue.  ``newtargets`` can make an NSE pre/host-rule
# add addresses that never appeared in the positional target list, so no post-token scope check
# can make arbitrary script arguments safe.  Script-argument files are equally opaque here.
_SCOPED_NSE_KEYS = frozenset(script["key"] for script in NSE_SCRIPTS)
# These options actively contact a user-selected intermediary outside the positional targets.
# Their host syntaxes (relay ports, proxy URLs, comma-separated resolvers) cannot be reduced to
# the same IP/CIDR membership check, so a configured scope must reject them fail-closed.
_SCOPED_UNSAFE_NETWORK_OPTIONS = ("-b", "-sI", "--proxies", "--dns-servers")


def _matches_option(token: str, option: str) -> bool:
    """정확한 옵션, --long=value, 또는 -iLfile 같은 짧은 붙임 형태 판별."""
    if token == option or token.startswith(f"{option}="):
        return True
    return option in {"-iL", "-iR"} and token.startswith(option) and len(token) > len(option)


def _raw_target_tokens(tokens: list[str]) -> list[str]:
    """직접 nmap argv의 위치 타겟만 추출한다. 옵션 값과 타겟을 구분하는 최소 렉서."""
    targets: list[str] = []
    consume_value = False
    positional_only = False
    for token in tokens:
        if consume_value:
            consume_value = False
            continue
        if positional_only:
            targets.append(token)
            continue
        if token == "--":
            positional_only = True
            continue
        if token in _RAW_OPTIONS_WITH_VALUE:
            consume_value = True
            continue
        if token.startswith("-"):
            # --opt=value와 -p80 같은 붙임 옵션은 현재 토큰 안에서 완결된다.
            continue
        targets.append(token)
    return targets


def raw_target_tokens(tokens: list[str]) -> list[str]:
    """Return positional raw-command targets, excluding all recognized option values."""
    return _raw_target_tokens(tokens)


def _validate_scoped_nse(tokens: list[str]) -> None:
    """Keep scoped raw NSE execution inside ScanOps' managed, non-expanding contract."""
    for index, token in enumerate(tokens):
        option_name = token.split("=", 1)[0]
        # Current Nmap rejects these as ambiguous, but accepting an abbreviation in another
        # release must not silently bypass the exact --script whitelist.
        if len(option_name) > 2 and option_name.startswith("--") \
                and "--script".startswith(option_name) \
                and option_name != "--script":
            raise ValueError(
                "스캔 대역(scope)이 설정된 환경에서는 NSE 옵션 축약형을 사용할 수 없습니다."
            )
        # Reject every script-args/script-help variant and abbreviation. Only the exact
        # selector (validated below) and a value-only timeout option are safe here.
        if option_name.startswith("--script") \
                and option_name not in {"--script", "--script-timeout"}:
            raise ValueError(
                "스캔 대역(scope)이 설정된 환경에서는 NSE script-args/newtargets를 사용할 수 없습니다."
            )
        if token == "--script":
            selector = tokens[index + 1] if index + 1 < len(tokens) else ""
        elif token.startswith("--script="):
            selector = token.split("=", 1)[1]
        else:
            continue
        scripts = [item.strip().lower() for item in selector.split(",") if item.strip()]
        if not scripts or any(script not in _SCOPED_NSE_KEYS for script in scripts):
            raise ValueError(
                "스캔 대역(scope)이 설정된 환경에서는 관리되는 NSE 스크립트만 사용할 수 있습니다."
            )


def _validate_scoped_excludes(tokens: list[str]) -> None:
    """Allow one inline IPv4/CIDR comma-list while keeping file/dynamic forms blocked."""
    values: list[str] = []
    for index, token in enumerate(tokens):
        option_name = token.split("=", 1)[0]
        if len(option_name) > 2 and option_name.startswith("--") \
                and option_name != "--exclude" \
                and any(option.startswith(option_name) for option in (
                    "--exclude", "--excludefile", "--exclude-file",
                )):
            raise ValueError(
                "스캔 대역(scope)이 설정된 환경에서는 --exclude 옵션 축약형을 사용할 수 없습니다."
            )
        if token == "--exclude":
            if index + 1 >= len(tokens):
                raise ValueError("--exclude 뒤에 IPv4 주소/CIDR 목록을 지정해야 합니다.")
            values.append(tokens[index + 1])
        elif token.startswith("--exclude="):
            values.append(token.split("=", 1)[1])
    if len(values) > 1:
        raise ValueError("--exclude 옵션은 한 번만 사용하고 값을 쉼표로 구분해야 합니다.")
    if values:
        parse_excludes(values[0].split(","))


def _uses_scoped_unsafe_network_option(token: str) -> bool:
    option_name = token.split("=", 1)[0]
    for option in _SCOPED_UNSAFE_NETWORK_OPTIONS:
        if option.startswith("--"):
            # Reject valid/possibly-valid GNU long-option abbreviations as well as exact forms.
            if len(option_name) > 2 and option_name.startswith("--") \
                    and option.startswith(option_name):
                return True
        elif token == option or token.startswith(option):
            return True
    return False


def check_raw_scope(tokens: list[str], spec: str | None = None) -> None:
    """직접 입력 명령용 scope 게이트. spec 비면 통과(무제한).

    scope 설정 시: 파일/랜덤 타겟 플래그(-iL/-iR 등) 차단, IP/CIDR 타겟이 최소 1개 있어야 하고,
    IP/CIDR 타겟은 전부 허용 대역 안이어야 한다. (호스트명만 있는 명령은 검증 불가 → 거절)"""
    if spec is None:
        spec = get_settings().scan_scope
    nets = parse_scope(spec)
    if not nets:
        return  # scope 미설정 — 제한 없음
    if any(_matches_option(token, option) for token in tokens for option in _UNSCOPED_TARGET_OPTIONS):
        raise ValueError(
            "스캔 대역(scope)이 설정된 환경에서는 직접 명령에서 파일/랜덤/이어하기 타겟을 쓸 수 없습니다. "
            "IP/CIDR 로 직접 지정하세요.")
    if any(_uses_scoped_unsafe_network_option(token) for token in tokens):
        raise ValueError(
            "스캔 대역(scope)이 설정된 환경에서는 외부 릴레이/프록시/DNS 대상을 지정할 수 없습니다."
        )
    _validate_scoped_excludes(tokens)
    _validate_scoped_nse(tokens)
    targets = _raw_target_tokens(tokens)
    if not targets:
        raise ValueError("스캔 대역(scope)이 설정된 환경에서는 직접 명령에 IP/CIDR 타겟을 명시해야 합니다.")
    check_scope(targets, spec)
