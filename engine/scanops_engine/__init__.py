"""ScanOps 단계분리 스캔 엔진 — nmap을 단계로 오케스트레이션, 이벤트·XML 산출.

ScanOps 본체와 분리된 별도 패키지. 계약:
  입력  job spec(JSON)  →  출력  이벤트(NDJSON) + 단계별 nmap XML
엔진은 ScanOps DB/taxonomy/finding 을 모른다(결과 생산만 담당).
단독 실행:  python -m scanops_engine --target 10.0.0.0/24
"""
from . import nmaprun
from .events import EventSink
from .pipeline import Pipeline
from .spec import JobSpec

__version__ = "0.1.0"
__all__ = ["JobSpec", "EventSink", "Pipeline", "nmaprun", "__version__"]
