"""스프레드시트 셀 안전화 — CSV/XLSX 수식 인젝션(formula injection) 차단.

배너·서비스·버전처럼 스캔 대상 호스트가 제어하는 문자열이 ``= + - @``(또는
탭/CR)로 시작하면 Excel·LibreOffice 가 이를 수식으로 실행할 수 있다. 셀 앞에
작은따옴표를 붙여 텍스트로 강제한다. (OWASP CSV Injection 권고)
"""
from __future__ import annotations

_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value):
    """문자열이 위험 문자로 시작하면 작은따옴표 프리픽스. 그 외(숫자 등)는 그대로."""
    if isinstance(value, str) and value and value[0] in _DANGEROUS:
        return "'" + value
    return value
