"""스캔 프리셋 — 토큰 목록. 출력(-oX)·타겟은 러너가 강제하므로 여기엔 없음."""

PRESETS: dict[str, list[str]] = {
    # 일반 점검: TCP 상위 1000 포트 + 서비스 버전/경량 HTTP Server 증거. 비특권으로도 동작(-sT).
    "quick": [
        "-sT", "-T4", "--top-ports", "1000", "-sV", "--open", "--reason",
        "--script", "http-headers,http-server-header",
    ],
    # 저강도(gentle): 오래된 백본/방화벽처럼 control-plane 이 약한 장비용. -T3 를 기준으로
    # 속도·재시도에 상한을 걸고, 장비의 RST 율제한 보호를 무력화하는 --defeat-rst-ratelimit 은 쓰지 않는다.
    # 단독 스캐너의 --intensity gentle 과 같은 의도이며 값도 맞춰 둔다.
    "gentle": [
        "-sT", "-T3", "--top-ports", "1000", "-sV", "--open", "--reason",
        "--max-retries", "1", "--max-rate", "150",
        "--max-parallelism", "10", "--min-hostgroup", "16",
        "--script", "http-headers,http-server-header",
    ],
    # 표준 점검(phase1): 전 TCP 포트 SYN + 강한 버전식별 + 핵심 NSE. 관리자 권한 필요(-sS).
    "phase1": [
        "-sS", "-T4", "-p", "T:1-65535", "-sV", "--version-all",
        "--max-retries", "2", "--open", "--reason", "--defeat-rst-ratelimit",
        "--script", (
            "ssl-cert,ssh-hostkey,http-headers,http-server-header,http-title,"
            "smb-os-discovery,nbstat,rdp-ntlm-info"
        ),
    ],
}

DEFAULT_PRESET = "quick"
