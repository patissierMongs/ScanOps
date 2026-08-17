"""서비스 분류 적용 — 시드 taxonomy + 조직 위험규칙으로 finding 을 분류.

finding dict 에 category/usage/risk_level/compliance_json 를 채운다.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Category, RiskRule
from .nmap_parse import nse_failed

_SEED = Path(__file__).resolve().parent.parent / "seed" / "categories.json"


def seed_categories(db: Session) -> None:
    data = json.loads(_SEED.read_text(encoding="utf-8"))
    if db.query(Category).count() > 0:
        _backfill_service_traits(db, data)
        return
    for c in data:
        db.add(Category(
            service_name=c["service_name"], category=c["category"], usage=c["usage"],
            risk_level=c["risk_level"], compliance_json=c["compliance"], desc=c["desc"],
            encryption=c.get("encryption", ""), auth=c.get("auth", ""),
            exposure=c.get("exposure", ""),
        ))
    db.commit()


def _backfill_service_traits(db: Session, data: list[dict]) -> None:
    """이미 시드된 DB 에 서비스 특성만 채운다.

    이 세 컬럼은 만들어만 두고 값이 한 번도 들어간 적이 없었다(0/105). 시드는 '비어 있을
    때만' 돌기 때문에 운영 중인 DB 는 영영 채워지지 않는다. 등급·분류 같은 사람이 손댔을
    수 있는 값은 건드리지 않고, 비어 있는 특성 칸만 메운다.
    """
    traits = {c["service_name"]: c for c in data}
    changed = 0
    for row in db.query(Category).all():
        source = traits.get(row.service_name)
        if source is None:
            continue
        for field in ("encryption", "auth", "exposure"):
            if not getattr(row, field, "") and source.get(field):
                setattr(row, field, source[field])
                changed = 1
    if changed:
        db.commit()


def build_lookup(db: Session) -> dict[str, dict]:
    return {
        c.service_name: {
            "category": c.category, "usage": c.usage,
            "risk_level": c.risk_level, "compliance": c.compliance_json or [],
            # 서비스 고유 특성(기대값) - 그 인스턴스에서 관측한 사실(exposure_json)과 다른 축이다.
            "encryption": c.encryption or "", "auth": c.auth or "",
            "exposure": c.exposure or "",
        }
        for c in db.query(Category).all()
    }


# TLS 를 관측했다고 말할 수 있는 스크립트. 둘 다 실제로 핸드셰이크가 성립해야 출력이 나온다.
_TLS_SCRIPT_IDS = frozenset({"ssl-cert", "tls-alpn"})


def _tls_evidence(finding: dict) -> bool:
    """이 포트가 TLS 위에서 말하는지에 대한 관측 증거.

    ``nse_json`` 은 파서(nmap_parse)와 모델(Finding.nse_json) 양쪽에서 ``[{"id":..,"output":..}]``
    리스트다. 이전 구현은 dict 로 받아 **런타임 값을 전부 탈락**시켰다 — service 에 "ssl" 이
    들어가지 않는 TLS 포트는 ssl-cert 를 갖고도 http 로 분류됐고, 단위 테스트가 dict 를 주입해
    그 미탐을 가렸다. 형제 소비자(extract_server·server_observed·Finding.fingerprint)와 같은
    계약으로 맞춘다.

    실패로 끝난 스크립트는 증거가 아니다 — nmap 이 표준화한 실패 출력은 "확인해 봤지만 못 봤다"
    이므로, 그것으로 https 를 주장하면 관측하지 않은 것을 관측했다고 말하는 셈이다.
    """
    if "ssl" in (finding.get("service") or "").lower():
        return True
    nse = finding.get("nse_json") or []
    if isinstance(nse, str):
        try:
            nse = json.loads(nse)
        except (ValueError, TypeError):
            return False
    if not isinstance(nse, list):
        return False
    return any(
        isinstance(script, dict)
        and str(script.get("id") or "") in _TLS_SCRIPT_IDS
        and not nse_failed(script.get("output"))
        for script in nse
    )


def fallback_service_key(finding: dict) -> str:
    """service 로 분류가 안 될 때 쓸 보조 분류 키를 관측 증거에서 끌어낸다.

    nmap 의 service 는 종종 저신뢰 추측이다(uniconv·apple-iphoto 처럼). 반면 Server 헤더는
    http-server-header/http-headers 가 실제로 HTTP 응답을 받아냈다는 뜻이라, 값이 무엇이든
    '이 포트는 HTTP 로 말한다'는 사실 자체가 service 추측보다 강한 증거다. taxonomy 는
    제품명(nginx)이 아니라 서비스명(http)으로 키가 잡혀 있으므로 그 사실만 키로 되돌린다.
    """
    if not (finding.get("server") or "").strip():
        return ""
    return "https" if _tls_evidence(finding) else "http"


# 관측된 노출 사실이 보장하는 **최소** 등급. 올리기만 하고 내리지 않는다 - taxonomy 가 이미
# 더 높게 본 서비스를 노출 신호가 끌어내리면 안 된다.
#
# 익명 FTP 와 잠긴 FTP 가 같은 등급이던 것이 문제의 출발점이었다. 등급을 올리는 것은 운영자의
# 우선순위를 바꾸는 일이라, **왜 올랐는지**를 컴플라이언스 근거에 함께 남긴다(발견 상세에서
# 바로 읽힌다). 근거 없이 등급만 바뀌면 사람이 판단을 검증할 수 없다.
_EXPOSURE_FLOOR = {
    "anon_access": ("high", "인증 없이 접근 가능한 서비스"),
    "no_auth": ("high", "인증을 요구하지 않는 원격 접근"),
    "plaintext": ("high", "자격증명이 평문으로 오가는 서비스"),
    "legacy_protocol": ("high", "알려진 취약 레거시 프로토콜 지원"),
    "cert_expired": ("medium", "만료된 인증서"),
    "weak_key": ("medium", "권고 미만 키 길이"),
    "self_signed": ("low", "신뢰 체인 없는 자가서명 인증서"),
}
# 낮은 쪽 -> 높은 쪽. banned 는 조직이 명시 금지한 것이라 노출 신호로 도달하지 않는다.
_RISK_ORDER = ["info", "low", "medium", "high", "banned"]


def _raise_to(current: str, floor: str) -> str:
    try:
        return floor if _RISK_ORDER.index(floor) > _RISK_ORDER.index(current) else current
    except ValueError:
        return current


def apply_exposure(finding: dict) -> None:
    """관측된 노출 사실로 위험 등급의 하한을 올리고 근거를 남긴다.

    조직 규칙보다 **먼저** 적용한다 - 조직이 명시적으로 '허용'으로 정했다면 그 판단이
    이겨야 하기 때문이다(규칙 루프가 뒤에서 덮어쓴다).
    """
    for signal in (finding.get("exposure_json") or []):
        if not isinstance(signal, dict):
            continue
        floor = _EXPOSURE_FLOOR.get(str(signal.get("kind") or ""))
        if floor is None:
            continue
        level, why = floor
        finding["risk_level"] = _raise_to(finding.get("risk_level", "info"), level)
        finding["compliance_json"].append({
            "std": "노출관측",
            "ref": f"{signal.get('detail') or signal.get('kind')} - {why}",
        })


def classify(finding: dict, lookup: dict[str, dict], rules: list[RiskRule]) -> dict:
    """finding 에 분류 필드를 채워 반환(같은 dict 수정)."""
    svc = (finding.get("service") or "").lower()
    info = lookup.get(svc, {})
    # 보조 키: service 로 분류가 전혀 안 될 때만 관측 증거(Server 배너)로 한 번 더 시도한다.
    # service 로 이미 분류된 건은 건드리지 않아 기존 위험등급이 흔들리지 않는다.
    fallback_used = ""
    if not info:
        fallback = fallback_service_key(finding)
        if fallback and fallback in lookup:
            info = lookup[fallback]
            fallback_used = fallback
    finding["category"] = info.get("category", "")
    finding["usage"] = info.get("usage", "")
    finding["risk_level"] = info.get("risk_level", "info")
    finding["compliance_json"] = list(info.get("compliance", []))
    # '조직이 허용하기로 정했다'와 '아직 아무 규칙도 걸리지 않았다'는 둘 다 risk_level=info 로
    # 끝난다. 등급만 보면 구분할 수 없어서, 허용 규칙에 걸린 사실을 따로 기록한다 - 이게
    # 없으면 미분류 발견까지 '허용'으로 숨겨져 정작 봐야 할 것이 사라진다.
    finding["allowed"] = False
    if fallback_used:
        # 왜 이렇게 분류됐는지 남긴다. nmap 이 뭐라 했든 Server 헤더가 나왔다는 사실로
        # 분류한 것이므로 근거를 보여줘야 운영자가 판단을 검증할 수 있다.
        finding["compliance_json"].append({
            "std": "관측근거",
            "ref": (f"nmap service '{svc or '미상'}' 로는 분류되지 않아 Server 배너"
                    f"({finding.get('server', '').strip()}) 기준 {fallback_used} 로 분류"),
        })

    # 서비스 고유 특성 - '이 프로토콜은 원래 평문이다' 같은 명세상의 사실. 관측이 아니라
    # 기대값이라 등급을 바꾸지 않는다(시드 등급이 이미 그 사실을 반영해 매겨져 있다).
    # 다만 왜 이 등급인지를 사람이 검증할 수 있어야 하므로 근거로는 남긴다.
    traits = [
        ("전송 구간", info.get("encryption", "")),
        ("인증", info.get("auth", "")),
        ("노출 범위", info.get("exposure", "")),
    ]
    for label, value in traits:
        if value:
            finding["compliance_json"].append({"std": "서비스특성", "ref": f"{label}: {value}"})

    # NSE 가 관측한 노출 사실로 하한을 올린다. 조직 규칙보다 먼저 적용해야, 조직이 명시적으로
    # 허용한 포트를 관측 신호가 다시 끌어올리지 않는다.
    apply_exposure(finding)

    # 조직 규칙은 taxonomy 기본값을 직접 덮어쓴다. risk_level=info 는 허용/정보 처리다.
    # banned_service 는 기존 호환용 이름이며 항상 금지(banned)로 적용한다.
    product = (finding.get("product") or "").lower()
    cpe = (finding.get("cpe") or "").lower()
    for r in rules:
        if r.kind == "banned_service" and r.service and r.service.lower() == svc:
            finding["risk_level"] = "banned"
        elif r.kind == "service_rule" and r.service and r.service.lower() == svc:
            finding["risk_level"] = r.risk_level
        elif (r.kind == "port_rule" and r.port == finding.get("port")
              and (not r.service or r.service.lower() == svc)):
            finding["risk_level"] = r.risk_level
        # 제품/CPE 규칙은 부분일치다. nmap product 는 'Samba smbd' 처럼 서술 접미사가 붙고,
        # CPE 는 여러 개가 ';' 로 이어져 저장되므로 정확일치로는 실무에서 쓸 수 없다.
        elif r.kind == "product_rule" and getattr(r, "product", "") and product:
            if r.product.lower() not in product:
                continue
            finding["risk_level"] = r.risk_level
        elif r.kind == "cpe_rule" and getattr(r, "cpe", "") and cpe:
            if r.cpe.lower() not in cpe:
                continue
            finding["risk_level"] = r.risk_level
        else:
            continue
        # 마지막에 걸린 규칙이 이긴다(위에서 계속 덮어쓴다). 허용 여부도 같은 규칙을 따라야
        # 나중 규칙이 허용을 취소했을 때 숨김이 풀린다.
        finding["allowed"] = r.risk_level == "info"
        if r.note:
            finding["compliance_json"].append({"std": "조직규칙", "ref": r.note})
    return finding


def reclassify_all(db: Session) -> int:
    """현재 taxonomy + 위험규칙으로 모든 발견의 분류/위험/근거를 재계산.

    규칙 추가·삭제 시 호출 — 파생 필드만 갱신하고 운영 필드(상태/담당/마감)는 보존.
    """
    from ..models import Finding
    lookup = build_lookup(db)
    rules = db.query(RiskRule).order_by(RiskRule.created_at, RiskRule.id).all()
    n = 0
    for f in db.query(Finding).all():
        # Server 배너 보조 분류와 제품/CPE 규칙이 재계산에서도 동일하게 걸리도록 관측 증거를 함께 넘긴다.
        d = {"service": f.service, "port": f.port, "server": f.server, "nse_json": f.nse_json,
             "product": f.product, "cpe": f.cpe,
             # 노출 신호는 관측값이므로 재분류에서도 그대로 다시 반영돼야 한다.
             "exposure_json": f.exposure_json}
        classify(d, lookup, rules)
        if f.risk_level != d["risk_level"]:
            n += 1
        f.category = d["category"]
        f.usage = d["usage"]
        f.risk_level = d["risk_level"]
        f.allowed = 1 if d.get("allowed") else 0
        f.compliance_json = d["compliance_json"]
    db.commit()
    return n


def enrich_all(db: Session, findings: list[dict]) -> list[dict]:
    lookup = build_lookup(db)
    rules = db.query(RiskRule).order_by(RiskRule.created_at, RiskRule.id).all()
    for f in findings:
        classify(f, lookup, rules)
    return findings
