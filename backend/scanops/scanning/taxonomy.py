"""서비스 분류 적용 — 시드 taxonomy + 조직 위험규칙으로 finding 을 분류.

finding dict 에 category/usage/risk_level/compliance_json 를 채운다.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Category, RiskRule

_SEED = Path(__file__).resolve().parent.parent / "seed" / "categories.json"


def seed_categories(db: Session) -> None:
    if db.query(Category).count() > 0:
        return
    data = json.loads(_SEED.read_text(encoding="utf-8"))
    for c in data:
        db.add(Category(
            service_name=c["service_name"], category=c["category"], usage=c["usage"],
            risk_level=c["risk_level"], compliance_json=c["compliance"], desc=c["desc"],
        ))
    db.commit()


def build_lookup(db: Session) -> dict[str, dict]:
    return {
        c.service_name: {
            "category": c.category, "usage": c.usage,
            "risk_level": c.risk_level, "compliance": c.compliance_json or [],
        }
        for c in db.query(Category).all()
    }


def _tls_evidence(finding: dict) -> bool:
    """이 포트가 TLS 위에서 말하는지에 대한 관측 증거."""
    if "ssl" in (finding.get("service") or "").lower():
        return True
    nse = finding.get("nse_json") or {}
    if isinstance(nse, str):
        try:
            nse = json.loads(nse)
        except (ValueError, TypeError):
            return False
    if not isinstance(nse, dict):
        return False
    return any(key in nse for key in ("ssl-cert", "tls-alpn"))


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
    if fallback_used:
        # 왜 이렇게 분류됐는지 남긴다. nmap 이 뭐라 했든 Server 헤더가 나왔다는 사실로
        # 분류한 것이므로 근거를 보여줘야 운영자가 판단을 검증할 수 있다.
        finding["compliance_json"].append({
            "std": "관측근거",
            "ref": (f"nmap service '{svc or '미상'}' 로는 분류되지 않아 Server 배너"
                    f"({finding.get('server', '').strip()}) 기준 {fallback_used} 로 분류"),
        })

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
             "product": f.product, "cpe": f.cpe}
        classify(d, lookup, rules)
        if f.risk_level != d["risk_level"]:
            n += 1
        f.category = d["category"]
        f.usage = d["usage"]
        f.risk_level = d["risk_level"]
        f.compliance_json = d["compliance_json"]
    db.commit()
    return n


def enrich_all(db: Session, findings: list[dict]) -> list[dict]:
    lookup = build_lookup(db)
    rules = db.query(RiskRule).order_by(RiskRule.created_at, RiskRule.id).all()
    for f in findings:
        classify(f, lookup, rules)
    return findings
