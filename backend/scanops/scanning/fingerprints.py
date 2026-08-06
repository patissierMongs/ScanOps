"""핑거프린트 시그니처 — `-sV` 가 식별하지 못한 포트의 원시 응답에서 제품을 알아낸다.

nmap 의 서비스 DB(`nmap-service-probes`)는 서구 소프트웨어 중심이라 Tibero 처럼 국내
엔터프라이즈 제품은 match 줄이 없어 `unknown` 으로 남는다. 그런데 fingerprint-strings 가
남긴 원시 응답에는 제품명이 그대로 들어 있는 경우가 많다(Tibero 는 프로토콜을 가리지 않고
제품명만 답한다). 그 응답을 시그니처 표와 대조해 제품을 되돌린다.

**시그니처 표는 코드가 아니라 데이터다** — `seed/fingerprint_signatures.json` 을 고치고
서버를 재시작하면 반영된다. DB 시드(categories.json)와 달리 파일을 매번 읽으므로 기존
설치에도 그대로 적용된다.

시그니처 항목:
  id         고유 식별자(관측근거 문구에 남는다)
  product    되돌릴 제품명
  pattern    probe 응답 본문에 적용할 정규식(re 문법). 오탐을 막으려면 앵커를 쓴다
  min_probes 같은 응답을 낸 probe 가 최소 몇 개여야 하는지(생략 시 1)
             — 'Tibero' 처럼 그 자체로 고유한 토큰은 1 이면 충분하고, 흔한 토큰을
               쓰는 시그니처를 나중에 추가할 때 오탐을 막는 안전장치다
  note       왜 이렇게 판정하는지(운영자가 검증할 수 있게 근거로 남는다)

안전 원칙: 관측된 값을 절대 덮어쓰지 않는다. service 가 unknown/빈 값이고 product 도
비어 있을 때만 채운다. 판정에 쓰인 시그니처는 근거로 남긴다.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_SIGNATURES = Path(__file__).resolve().parent.parent / "seed" / "fingerprint_signatures.json"

# -sV 가 식별에 실패했다고 보는 service 값.
UNIDENTIFIED_SERVICES = frozenset({"", "unknown"})

# fingerprint-strings 의 probe 그룹 머리글: '  GetRequest, NULL: ' 형태(들여쓰기 1~3칸).
_PROBE_HEADER_RE = re.compile(r"^\s{1,3}(\S.*?):\s*$")


def fingerprint_blocks(raw: str) -> list[dict]:
    """fingerprint-strings 원시 응답을 [{probes, body}] 로 쪼갠다.

    probe 이름은 응답이 아니라 nmap-service-probes 에서 온다(= '어떤 probe 에 답했는가'이지
    서비스 정체가 아니다). 본문만 시그니처 대조에 쓴다.
    """
    blocks: list[dict] = []
    cur: dict | None = None
    for line in str(raw or "").replace("\r", "").split("\n"):
        if not line.strip():
            continue
        header = _PROBE_HEADER_RE.match(line)
        if header:
            cur = {"probes": header.group(1), "body": []}
            blocks.append(cur)
        elif cur is not None:
            cur["body"].append(line.strip())
        else:
            cur = {"probes": "", "body": [line.strip()]}
            blocks.append(cur)
    return blocks


def _probe_count(probes: str) -> int:
    return len([p for p in (probes or "").split(",") if p.strip()]) or 1


@lru_cache(maxsize=1)
def load_signatures() -> tuple[dict, ...]:
    """시그니처 표를 읽어 컴파일한다. 파일이 없거나 깨져도 스캔 인입을 막지 않는다."""
    try:
        raw = json.loads(_SIGNATURES.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    out: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        product, pattern = (item.get("product") or "").strip(), item.get("pattern") or ""
        if not product or not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue  # 잘못된 정규식 하나가 표 전체를 못 쓰게 만들지 않는다.
        out.append({
            "id": (item.get("id") or product).strip(),
            "product": product,
            "regex": compiled,
            "min_probes": max(1, int(item.get("min_probes") or 1)),
            "note": (item.get("note") or "").strip(),
        })
    return tuple(out)


def identify(fingerprint: str) -> dict | None:
    """핑거프린트 본문에서 제품을 알아낸다. 못 찾으면 None.

    같은 응답을 낸 probe 수가 시그니처의 min_probes 이상일 때만 인정한다.
    """
    if not fingerprint:
        return None
    signatures = load_signatures()
    if not signatures:
        return None
    for block in fingerprint_blocks(fingerprint):
        body = "\n".join(block["body"]).strip()
        if not body:
            continue
        probes = _probe_count(block["probes"])
        for sig in signatures:
            if probes >= sig["min_probes"] and sig["regex"].search(body):
                return {"id": sig["id"], "product": sig["product"], "note": sig["note"],
                        "probe_count": probes}
    return None
