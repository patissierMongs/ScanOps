"""서비스 분류 적용 — 시드 taxonomy + 조직 위험규칙으로 finding 을 분류.

finding dict 에 category/usage/risk_level/compliance_json 를 채운다.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Category, RiskRule

_SEED = Path(__file__).resolve().parent.parent / "seed" / "categories.json"
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "banned": 4}


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


def _max_risk(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def classify(finding: dict, lookup: dict[str, dict], rules: list[RiskRule]) -> dict:
    """finding 에 분류 필드를 채워 반환(같은 dict 수정)."""
    svc = (finding.get("service") or "").lower()
    info = lookup.get(svc, {})
    finding["category"] = info.get("category", "")
    finding["usage"] = info.get("usage", "")
    finding["risk_level"] = info.get("risk_level", "info")
    finding["compliance_json"] = list(info.get("compliance", []))

    # 조직 위험규칙으로 등급 상향(최대치 채택).
    # 금지 서비스(banned_service) 매칭은 최고 등급 '금지(banned)'로 승격.
    # 기본포트 사용 금지(port_rule) = 서비스+포트 조합 일치 시 규칙 등급 적용(예: ssh/22).
    for r in rules:
        if r.kind == "banned_service" and r.service and r.service.lower() == svc:
            finding["risk_level"] = _max_risk(finding["risk_level"], "banned")
        elif (r.kind == "port_rule" and r.port == finding.get("port")
              and (not r.service or r.service.lower() == svc)):
            finding["risk_level"] = _max_risk(finding["risk_level"], r.risk_level)
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
    rules = db.query(RiskRule).all()
    n = 0
    for f in db.query(Finding).all():
        d = {"service": f.service, "port": f.port}
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
    rules = db.query(RiskRule).all()
    for f in findings:
        classify(f, lookup, rules)
    return findings
