"""스캔 프리셋 — 토큰 목록. 출력(-oX)·타겟은 러너가 강제하므로 여기엔 없음."""

from .scan_options import UDP_DEFAULT_PORTS

PRESETS: dict[str, list[str]] = {
    # 일반 점검: TCP 상위 1000 포트 + 서비스 버전. 비특권으로도 동작(-sT).
    "quick": ["-sT", "-T4", "--top-ports", "1000", "-sV", "--open", "--reason"],
    # 표준 점검(phase1): 전 TCP 포트 SYN + 강한 버전식별 + 핵심 NSE. 관리자 권한 필요(-sS).
    "phase1": [
        "-sS", "-T4", "-p", "T:1-65535", "-sV", "--version-all",
        "--max-retries", "2", "--open", "--reason", "--defeat-rst-ratelimit",
        "--script", "ssl-cert,ssh-hostkey,http-title,smb-os-discovery,nbstat,rdp-ntlm-info",
    ],
    # 느린(젠틀) 점검(slow): 전 TCP 포트 SYN + 주요 UDP + 서비스 버전. 검증된 원본 '느린 스캔'을 이식.
    # 강도를 낮추는 축은 '동시성'이다 — --max-parallelism 5(호스트그룹 전역 상한)로 회선·장비
    # 부하를 크게 줄이고, --max-rtt-timeout 1000ms 로 느린 레거시 장비까지 참을성 있게 포착한다
    # (정확도는 오히려 유리). 관리자 권한 필요(-sS·-sU). 방화벽 예외(포트 응답) 환경 기준으로
    # 병렬 5 가 처리량 병목이라 전 포트 대역은 시간이 오래 걸린다(TCP≈1.5~3.5h + UDP 추가분).
    # 커버리지: TCP 전 65535 + UDP 주요 포트셋(빠른/자동 스캔과 동일 UDP 집합). 부하만 낮춘 '조용한' 프로파일.
    # UDP 는 --version-all 미적용(-sV 강도 7): 강도 9 는 증폭형 UDP 에서 nmap fatal 위험 → 안전하게.
    # 역DNS 는 켠다(-n 없음): 호스트명(PTR)이 발견의 식별 근거로 유용하고, 젠틀 단일 스캔이라
    # PTR 조회 비용은 미미(수 초~수십 초). 순수 속도가 필요하면 '역DNS 생략(-n)' 토글로 끌 수 있다.
    "slow": [
        "-sS", "-sU", "-T4", "-p", f"T:1-65535,U:{UDP_DEFAULT_PORTS}", "-sV", "--open", "--reason",
        "--min-hostgroup", "16", "--max-parallelism", "5",
        "--max-rtt-timeout", "1000ms", "--initial-rtt-timeout", "300ms",
        "--max-retries", "6",
    ],
}

DEFAULT_PRESET = "quick"
