"""포트 상태를 '무엇을 보고' 정했는지 — nmap ``--reason`` 값의 공통 해석.

같은 ``open`` 이라도 근거가 다르다. ``syn-ack`` 은 응답 패킷을 실제로 받아 확인한 것이고,
``no-response`` 는 아무것도 못 받아 추정한 것이다. 둘을 같은 '열림'으로 보여주면 관측하지
않은 것을 관측한 것처럼 말하게 된다 — UDP 는 응답 없는 포트가 예외가 아니라 다수라서
이 구분이 특히 중요하다.

표시·내보내기·재확인 대상 선정이 모두 이 한 모듈을 쓰므로 '추정을 확인처럼 보여주는'
경로가 한 곳에서 닫힌다(identity.display_identity 와 같은 이유).

근거 문자열은 nmap 원전 ``portreasons.cc`` 의 reason_map 에서 가져왔다.
"""
from __future__ import annotations

CONFIRMED = "응답 확인"
INFERRED = "무응답 추정"
DECLARED = "관측 아님"
UNOBSERVED = "미관측"
OTHER = "기타 응답"
ABSENT = "부재로 판정"

# 개방을 응답 패킷으로 확인한 근거들.
_OPEN_CONFIRMING = frozenset({
    "syn-ack", "split-handshake-syn", "udp-response", "proto-response",
    "tcp-response", "localhost-response", "init-ack", "unknown-response",
})
# 닫힘을 응답 패킷으로 확인한 근거들(능동 관측 — 부재 판정과 구분된다).
_CLOSED_CONFIRMING = frozenset({"conn-refused", "reset", "port-unreach", "proto-unreach"})
# 아무 응답도 못 받아 추정한 것. open|filtered 가 여기 해당한다.
_SILENT = frozenset({"no-response"})
# 네트워크 관측이 아니라 사용자/스크립트가 그렇게 정해 준 것.
_DECLARED = frozenset({"user-set", "script-set"})


def state_evidence(state: str | None, reason: str | None) -> str:
    """**현재 상태**를 무엇을 보고 정했는지.

    reason 은 마지막 *관측*의 근거이고 state 는 그 뒤에도 바뀔 수 있다. 부재 기반 닫힘은
    ``state`` 만 ``closed`` 로 바꾸고 reason 은 열려 있던 시절의 ``syn-ack`` 을 그대로 두므로,
    reason 만 보고 판정하면 **닫힘을 응답으로 확인했다고 말하게 된다.** 그래서 state 를 함께
    받아, 근거가 현재 상태를 실제로 뒷받침할 때만 '확인'이라고 한다.

    모르는 값을 확인/추정 어느 쪽으로도 넘겨짚지 않는다. nmap 의 reason 목록은 버전에 따라
    늘어나므로, 목록에 없으면 OTHER 로 두고 원문(reason)을 그대로 보여 준다.
    """
    value = (reason or "").strip()
    current = (state or "").strip()

    if current.startswith("closed"):
        # 닫힘을 응답으로 확인한 경우에만 '확인'. 그 밖에는 전부 부재 판정이다 —
        # 열려 있던 시절의 근거를 현재 닫힘의 근거로 재활용하지 않는다.
        return CONFIRMED if value in _CLOSED_CONFIRMING else ABSENT

    if not value:
        # reason 컬럼 이전에 인입된 행. '응답이 없었다'와는 전혀 다른 뜻이다.
        return UNOBSERVED
    if value in _OPEN_CONFIRMING:
        return CONFIRMED
    if value in _SILENT:
        return INFERRED
    if value in _DECLARED:
        return DECLARED
    return OTHER


def current_reason(state: str | None, reason: str | None) -> str:
    """**현재 상태를 뒷받침하는** 근거 원문만. 아니면 빈 값.

    행에는 마지막 관측의 reason 이 provenance 로 남지만, 그것을 '근거 원문'이라는 이름으로
    현재 상태 옆에 그대로 보여 주면 읽는 사람은 둘을 잇는다 — closed 옆의 syn-ack 이
    그렇다. 해석(state_evidence)만 고치고 원문을 그대로 두면 화면·내보내기에서 같은 오독이
    남으므로, 표시 경로는 이 함수를 거친다.
    """
    if state_evidence(state, reason) in (ABSENT, UNOBSERVED):
        return ""
    return (reason or "").strip()


def is_confirmed_open(state: str | None, reason: str | None) -> bool:
    """이 포트가 열려 있다는 것을 응답으로 확인했는가.

    ``open|filtered`` 는 정의상 확인이 아니다 — nmap 이 열림과 필터를 가르지 못한 상태다.
    """
    if (state or "").strip() != "open":
        return False
    return state_evidence(state, reason) == CONFIRMED


def needs_confirmation(state: str | None, reason: str | None) -> bool:
    """재확인해야 열림 여부를 말할 수 있는 건인가.

    '미관측'(reason 이 없는 과거 행)은 여기 넣지 않는다. 값이 없다는 것은 근거가 약하다는
    뜻이 아니라 우리가 기록하지 않았다는 뜻이라, 그것으로 재스캔을 요구하면 과거 데이터
    전체가 재확인 대상이 된다.

    닫힌 건도 넣지 않는다. 부재로 닫힌 건이 정말 닫혔는지는 별개의 큰 문제(#50)이고,
    여기서 다루면 '열려 있다는데 확인이 안 된 것'이라는 이 신호의 뜻이 흐려진다.
    """
    current = (state or "").strip()
    if not current.startswith("open"):
        return False
    return state_evidence(state, reason) == INFERRED or current == "open|filtered"
