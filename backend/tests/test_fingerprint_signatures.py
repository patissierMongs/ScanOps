"""핑거프린트 시그니처 — nmap 이 unknown 으로 남긴 포트의 제품 식별."""
from __future__ import annotations

import json

from scanops.scanning import fingerprints
from scanops.scanning.nmap_parse import parse_xml

# 실제 Tibero 포트에서 나오는 형태: 프로토콜을 가리지 않고 제품명만 응답한다.
TIBERO_FP = ("  DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, "
             "HTTPOptions, Hello, Help, NULL, RPCCheck, RTSPRequest, SSLSessionReq: \n"
             "    Tibero\n")


def _xml(port: int, service: str, fp: str, product: str = "") -> bytes:
    product_attr = f' product="{product}"' if product else ""
    return f"""<?xml version="1.0"?>
<nmaprun start="1893456000"><host><status state="up"/>
<address addr="10.0.0.50" addrtype="ipv4"/><ports>
  <port protocol="tcp" portid="{port}"><state state="open"/>
    <service name="{service}" method="table" conf="3"{product_attr}/>
    <script id="fingerprint-strings" output="{fp.replace(chr(10), '&#10;')}"/>
  </port>
</ports></host></nmaprun>""".encode()


def test_identify_returns_product_for_known_signature():
    hit = fingerprints.identify(TIBERO_FP)

    assert hit is not None
    assert hit["product"] == "Tibero"
    assert hit["id"] == "tmax-tibero"
    assert hit["probe_count"] == 11        # 여러 probe 가 같은 응답 → 제품 배너라는 신호


def test_identify_ignores_unknown_payloads():
    assert fingerprints.identify("  NULL: \n    SomeRandomBanner\n") is None
    assert fingerprints.identify("") is None


def test_unidentified_port_gets_product_from_signature():
    findings = parse_xml(_xml(8629, "unknown", TIBERO_FP))

    assert len(findings) == 1
    assert findings[0]["product"] == "Tibero"
    assert findings[0]["service"] == "unknown"          # 관측값은 그대로 둔다
    assert "fingerprint=tmax-tibero" in findings[0]["remarks"]   # 판정 근거를 남긴다


def test_signature_never_overwrites_an_identified_service():
    """이미 -sV 가 식별한 포트는 핑거프린트에 다른 제품명이 있어도 건드리지 않는다."""
    findings = parse_xml(_xml(22, "ssh", TIBERO_FP, product="OpenSSH"))

    assert findings[0]["product"] == "OpenSSH"
    assert "fingerprint=" not in findings[0]["remarks"]


def test_signature_display_identity_and_search_surface_the_product(client):
    """제품이 채워지면 표시 식별자·검색이 함께 살아난다(둘 다 product 를 본다)."""
    from tests.conftest import make_user, token_for
    make_user("fp-op", "pw", role="auditor")
    h = {"Authorization": f"Bearer {token_for(client, 'fp-op', 'pw')}"}
    r = client.post("/api/scans/import", headers=h,
                    files={"file": ("t.xml", _xml(8629, "unknown", TIBERO_FP), "text/xml")})
    assert r.status_code == 200, r.text

    row = next(f for f in client.get("/api/findings", headers=h).json() if f["port"] == 8629)
    assert row["product"] == "Tibero"
    assert row["display_identity"] == "Tibero"     # server 없음 → product 로 표시

    found = client.get("/api/findings", headers=h, params={"q": "Tibero"}).json()
    assert [f["port"] for f in found] == [8629]


def test_signature_table_is_data_not_code():
    """시그니처는 seed JSON 으로 관리한다 — 파일만 고치고 재시작하면 반영된다."""
    path = fingerprints._SIGNATURES
    assert path.exists(), path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data
    tibero = next(s for s in data if s["id"] == "tmax-tibero")
    assert tibero["product"] == "Tibero" and tibero["pattern"] and tibero["note"]


def test_broken_signature_file_does_not_break_ingest(tmp_path, monkeypatch):
    """표가 깨져도 스캔 인입은 계속돼야 한다(시그니처는 보조 수단이다)."""
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json", encoding="utf-8")
    monkeypatch.setattr(fingerprints, "_SIGNATURES", bad)
    fingerprints.load_signatures.cache_clear()
    try:
        assert fingerprints.load_signatures() == ()
        assert fingerprints.identify(TIBERO_FP) is None
        assert parse_xml(_xml(8629, "unknown", TIBERO_FP))[0]["product"] == ""
    finally:
        fingerprints.load_signatures.cache_clear()


def test_invalid_regex_entry_is_skipped_not_fatal(tmp_path, monkeypatch):
    table = tmp_path / "sig.json"
    table.write_text(json.dumps([
        {"id": "broken", "product": "X", "pattern": "([unclosed"},
        {"id": "good", "product": "Tibero", "pattern": "(?im)^\\s*Tibero\\s*$"},
    ]), encoding="utf-8")
    monkeypatch.setattr(fingerprints, "_SIGNATURES", table)
    fingerprints.load_signatures.cache_clear()
    try:
        assert [s["id"] for s in fingerprints.load_signatures()] == ["good"]
        assert fingerprints.identify(TIBERO_FP)["product"] == "Tibero"
    finally:
        fingerprints.load_signatures.cache_clear()
