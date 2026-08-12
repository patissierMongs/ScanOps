"""사람에게 보여 줄 서비스 식별자의 공통 우선순위."""
from __future__ import annotations

# Nmap 이 프로브로 확인하지 못하면 포트번호 관례표(nmap-services)의 이름을 그대로 내놓는다.
# 예: 8770 → "apple-iphoto"(실제로는 uvicorn). 이건 관측이 아니라 '그 포트는 보통 이거였다'는
# 관례이므로 관측값과 같은 무게로 보여주면 안 된다. parse 단계의 identification 이 '추측'이다.
GUESSED = "추측"
GUESS_SUFFIX = " (포트 추측)"


def observed_identity(*, server: str = "", product: str = "", version: str = "") -> str:
    """실제로 관측된 식별자만 — Server 자기신고 또는 -sV 가 매칭한 제품/버전."""
    server = (server or "").strip()
    if server:
        return server
    return " ".join(
        value.strip() for value in (product or "", version or "") if value.strip()
    )


def display_identity(*, server: str = "", product: str = "", version: str = "",
                     service: str = "", identification: str = "") -> str:
    """Server 자기신고 → 제품/버전 → Nmap 서비스명 순.

    서비스명까지 내려왔는데 그게 포트 관례 추측이면 그 사실을 표기한다. 표시·검색·내보내기가
    모두 이 한 함수를 쓰므로 '추측을 관측처럼 보여주는' 경로가 한 곳에서 닫힌다.
    """
    observed = observed_identity(server=server, product=product, version=version)
    if observed:
        return observed
    service = (service or "").strip()
    if service and identification == GUESSED:
        return service + GUESS_SUFFIX
    return service
