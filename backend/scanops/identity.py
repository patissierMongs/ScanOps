"""사람에게 보여 줄 서비스 식별자의 공통 우선순위."""
from __future__ import annotations


def display_identity(*, server: str = "", product: str = "", version: str = "",
                     service: str = "") -> str:
    """Server 자기신고를 우선하고, 제품/버전과 Nmap 서비스명을 차례로 사용한다."""
    server = (server or "").strip()
    if server:
        return server
    product_version = " ".join(
        value.strip() for value in (product or "", version or "") if value.strip()
    )
    return product_version or (service or "").strip()
