"""서비스/포트 규칙 라우터 — 조직 커스텀 규칙 CRUD + 규칙별 매칭 발견 수.

taxonomy(seed) 위에 얹는 service_rule/port_rule. 매칭 카운트는 현재 열린(open)
발견 중 규칙에 걸리는 수를 즉시 집계해 UI 가 "이 규칙이 몇 건을 잡는가"를 보여준다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import RISK_LEVELS, Finding, RiskRule, User
from ..scanning import taxonomy
from ..schemas import RuleIn, RuleOut
from .audit import record
from .deps import current_user, require_role

router = APIRouter()

_KINDS = ("service_rule", "banned_service", "port_rule")


def _match_count(db: Session, rule: RiskRule) -> int:
    """규칙이 잡는 현재 열린 발견 수."""
    q = db.query(func.count(Finding.id)).filter(Finding.state == "open")
    if rule.kind in ("service_rule", "banned_service"):
        if not rule.service:
            return 0
        return q.filter(func.lower(Finding.service) == rule.service.lower()).scalar() or 0
    if rule.kind == "port_rule":
        if rule.port is None:
            return 0
        q = q.filter(Finding.port == rule.port)
        if rule.service:  # 기본포트 사용 금지 = 서비스+포트 조합
            q = q.filter(func.lower(Finding.service) == rule.service.lower())
        return q.scalar() or 0
    return 0


def _out(db: Session, rule: RiskRule) -> RuleOut:
    o = RuleOut.model_validate(rule)
    o.match_count = _match_count(db, rule)
    return o


def _validate_rule(body: RuleIn) -> None:
    if body.kind not in _KINDS:
        raise HTTPException(status_code=400, detail=f"kind 는 {_KINDS} 중 하나여야 합니다.")
    if body.risk_level not in RISK_LEVELS:
        raise HTTPException(status_code=400, detail=f"risk_level 은 {RISK_LEVELS} 중 하나여야 합니다.")
    if body.kind in ("service_rule", "banned_service") and not body.service.strip():
        raise HTTPException(status_code=400, detail="서비스 규칙은 service 가 필요합니다.")
    if body.kind == "port_rule" and body.port is None:
        raise HTTPException(status_code=400, detail="포트 규칙은 port 가 필요합니다.")


@router.get("", response_model=list[RuleOut])
def list_rules(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return [_out(db, r) for r in db.query(RiskRule).order_by(RiskRule.created_at).all()]


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    body: RuleIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    _validate_rule(body)
    rule = RiskRule(
        kind=body.kind, service=body.service.strip(), port=body.port,
        risk_level="banned" if body.kind == "banned_service" else body.risk_level,
        note=body.note, created_by=user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    taxonomy.reclassify_all(db)  # 기존 발견에 즉시 반영(금지 승격 등)
    record(db, user, "RULE_CREATE", target=f"{rule.kind}:{rule.service or rule.port}",
           detail=f"#{rule.id} → {rule.risk_level}")
    return _out(db, rule)


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    body: RuleIn,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    rule = db.get(RiskRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="규칙을 찾을 수 없습니다.")
    _validate_rule(body)
    old = f"{rule.kind}:{rule.service or rule.port} → {rule.risk_level}"
    rule.kind = body.kind
    rule.service = body.service.strip()
    rule.port = body.port
    rule.risk_level = "banned" if body.kind == "banned_service" else body.risk_level
    rule.note = body.note
    db.commit()
    db.refresh(rule)
    taxonomy.reclassify_all(db)
    record(db, user, "RULE_UPDATE", target=f"{rule.kind}:{rule.service or rule.port}",
           detail=f"#{rule.id} {old} -> {rule.risk_level}")
    return _out(db, rule)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    rule = db.get(RiskRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="규칙을 찾을 수 없습니다.")
    label = f"{rule.kind}:{rule.service or rule.port}"
    db.delete(rule)
    db.commit()
    taxonomy.reclassify_all(db)  # 규칙 제거 후 등급 원복
    record(db, user, "RULE_DELETE", target=label, detail=f"#{rule_id}")
