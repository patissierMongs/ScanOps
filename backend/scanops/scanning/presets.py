"""스캔 프리셋 — 토큰 목록. 출력(-oX)·타겟은 러너가 강제하므로 여기엔 없음."""

PRESETS: dict[str, list[str]] = {
    # 일반 점검: TCP 상위 1000 포트 + 서비스 버전. 비특권으로도 동작(-sT).
    "quick": ["-sT", "-T4", "--top-ports", "1000", "-sV", "--open", "--reason"],
    # 표준 점검(phase1): 전 TCP 포트 SYN + 강한 버전식별 + 핵심 NSE. 관리자 권한 필요(-sS).
    "phase1": [
        "-sS", "-T4", "-p", "T:1-65535", "-sV", "--version-all",
        "--max-retries", "2", "--open", "--reason", "--defeat-rst-ratelimit",
        "--script", "ssl-cert,ssh-hostkey,http-title,smb-os-discovery,nbstat,rdp-ntlm-info",
    ],
}

DEFAULT_PRESET = "quick"
