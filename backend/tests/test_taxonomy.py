"""Phase D 검증 — taxonomy 분류 + 위험등급 + 컴플라이언스 + 위험규칙 상향."""
from scanops.db import SessionLocal, init_db
from scanops.models import RiskRule
from scanops.scanning.taxonomy import build_lookup, classify, seed_categories
from tests.conftest import make_user, token_for


def _seeded_db():
    init_db()
    db = SessionLocal()
    seed_categories(db)
    return db


def test_seed_and_classify_known_service():
    db = _seeded_db()
    try:
        lookup = build_lookup(db)
        f = classify({"service": "ssh", "port": 22}, lookup, [])
        assert f["category"] == "원격접속" and f["usage"] == "관리"
        assert f["risk_level"] == "high"
        assert any(c["std"] == "KISA" for c in f["compliance_json"])
    finally:
        db.close()


def test_plaintext_service_forced_high():
    db = _seeded_db()
    try:
        f = classify({"service": "telnet", "port": 23}, build_lookup(db), [])
        assert f["risk_level"] == "high"
    finally:
        db.close()


def test_unknown_service_defaults_info():
    db = _seeded_db()
    try:
        f = classify({"service": "weird-thing", "port": 9999}, build_lookup(db), [])
        assert f["category"] == "" and f["risk_level"] == "info"
    finally:
        db.close()


def test_risk_rule_escalates():
    db = _seeded_db()
    try:
        rule = RiskRule(kind="port_rule", port=8080, risk_level="high", note="사내 금지 포트")
        # dns 는 기본 low → 포트규칙으로 high 승격
        f = classify({"service": "domain", "port": 8080}, build_lookup(db), [rule])
        assert f["risk_level"] == "high"
        assert any(c["std"] == "조직규칙" for c in f["compliance_json"])
    finally:
        db.close()


def test_service_rule_can_override_to_info():
    db = _seeded_db()
    try:
        rule = RiskRule(kind="service_rule", service="ssh", risk_level="info", note="업무용 허용")
        f = classify({"service": "ssh", "port": 22}, build_lookup(db), [rule])
        assert f["risk_level"] == "info"
        assert any(c["std"] == "조직규칙" for c in f["compliance_json"])
    finally:
        db.close()


def test_import_populates_risk(client):
    make_user("op", "pw", role="auditor")
    h = {"Authorization": f"Bearer {token_for(client, 'op', 'pw')}"}
    with open("tests/fixtures/sample_scan.xml", "rb") as fp:
        client.post("/api/scans/import", headers=h, files={"file": ("s.xml", fp, "text/xml")})
    rows = client.get("/api/findings", headers=h).json()
    ssh = next(r for r in rows if r["port"] == 22)
    assert ssh["category"] == "원격접속" and ssh["risk_level"] == "high"
    # 위험등급이 비어있지 않은 발견이 다수
    assert sum(1 for r in rows if r["risk_level"] in ("high", "medium")) >= 3
