"""서비스 분류 적용 — 시드 taxonomy + 조직 위험규칙으로 finding 을 분류.

finding dict 에 category/usage/risk_level/compliance_json 를 채운다.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Category, RiskRule
from .nmap_parse import nse_failed

logger = logging.getLogger(__name__)

_SEED = Path(__file__).resolve().parent.parent / "seed" / "categories.json"
_EOL_SEED = Path(__file__).resolve().parent.parent / "seed" / "eol_products.json"


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
}

# 등급은 건드리지 않고 **근거로만** 남기는 관측. '볼 값어치가 있다'와 '위험 하한을 올린다'는
# 별개다. 표·필터에는 그대로 나오고(exposure_json 을 직접 읽는다) 왜 눈에 띄었는지도 남지만,
# 이 사실 하나로 우선순위를 올리지는 않는다.
#
# self_issued 가 그렇다. RFC 5280 3.2 는 자체 발급 인증서를 CA 의 키 교체·정책 변경을 받치는
# **정상 메커니즘**으로 설명한다. 발급자와 주체가 같다는 것만으로는 체인 검증 실패도 취약성도
# 증명되지 않는다 - 실측에서 같은 DN 을 쓰는 사설 CA 가 발급한 인증서가 openssl verify 를
# 통과했다. 서명·체인 검증 실패라는 증거가 따로 잡히면 그때 하한을 논할 자리다.
_EXPOSURE_NOTE = {
    "self_issued": "정상 운영에서도 쓰는 형태여서 등급은 올리지 않는다",
}
# 낮은 쪽 -> 높은 쪽. banned 는 조직이 명시 금지한 것이라 노출 신호로 도달하지 않는다.
_RISK_ORDER = ["info", "low", "medium", "high", "banned"]


def _raise_to(current: str, floor: str) -> str:
    try:
        return floor if _RISK_ORDER.index(floor) > _RISK_ORDER.index(current) else current
    except ValueError:
        return current


def apply_exposure(finding: dict) -> None:
    """관측된 노출 사실을 근거로 남기고, 그럴 만한 것만 위험 등급의 하한을 올린다.

    두 갈래다 - 하한을 주는 관측(_EXPOSURE_FLOOR)과 근거로만 남기는 관측(_EXPOSURE_NOTE).
    관측했다는 사실과 그것이 더 위험하다는 판단은 다른 층이라, 코드에서도 갈라 둔다.

    하한은 조직 규칙보다 **먼저** 적용한다 - 조직이 명시적으로 '허용'으로 정했다면 그 판단이
    이겨야 하기 때문이다(규칙 루프가 뒤에서 덮어쓴다).
    """
    for signal in (finding.get("exposure_json") or []):
        if not isinstance(signal, dict):
            continue
        kind = str(signal.get("kind") or "")
        detail = signal.get("detail") or kind
        if floor := _EXPOSURE_FLOOR.get(kind):
            level, why = floor
            finding["risk_level"] = _raise_to(finding.get("risk_level", "info"), level)
            finding["compliance_json"].append({"std": "노출관측", "ref": f"{detail} - {why}"})
        elif note := _EXPOSURE_NOTE.get(kind):
            finding["compliance_json"].append({"std": "노출관측", "ref": f"{detail} - {note}"})


def _version_tuple(text: str) -> tuple[int, ...]:
    """'2.2.15' -> (2, 2, 15). 읽을 수 없으면 빈 튜플이라 어떤 비교에도 걸리지 않는다.

    자리마다 앞의 숫자만 쓴다 - '1.0.2k' 의 k 는 버린다(OpenSSL 의 문자 접미사).

    다만 **글자만 있는 자리**가 나오면 통째로 포기한다. 그 자리는 이 문자열이 버전 하나가
    아니라는 뜻이고, 실측에서 세 가지가 전부 여기 걸린다.

      '5.5.5-10.3.34-MariaDB'  MariaDB 가 MySQL 프로토콜 호환으로 붙이는 '5.5.5-' 표식.
                               앞을 읽으면 지원 중인 MariaDB 가 EOL MySQL 로 잡힌다.
      '3.X - 4.X'              nmap 이 정확한 버전을 못 좁혔을 때 내는 범위. 3 으로 읽으면
                               '모른다'가 '오래됐다'로 바뀐다.
      '4.15.13-Ubuntu'         배포판 패키지. 업스트림이 끝났어도 배포판이 백포트로 계속
                               고쳐 주므로, 업스트림 EOL 표를 그대로 들이대면 틀린다.

    셋 다 '읽지 못했다'로 두는 편이 맞다. 놓치는 쪽은 등급이 안 오를 뿐이지만, 잘못 잡는
    쪽은 근거 없이 운영자의 우선순위를 흔든다.
    """
    parts: list[int] = []
    for chunk in re.split(r"[.\-_]", str(text or "").strip()):
        match = re.match(r"^(\d+)", chunk)
        if not match:
            return ()
        parts.append(int(match.group(1)))
    return tuple(parts)


def _is_below(current: tuple[int, ...], limit: tuple[int, ...]) -> bool:
    """관측 버전이 기준 **미만**임이 분명한가. 판단할 수 없으면 False.

    튜플 비교를 그대로 쓰면 자리수가 기준보다 짧을 때 틀린다 - MySQL 을 '8' 로만 보고한
    배너는 (8,) < (8,0) 이 되어 지원 종료로 잡히지만, 실제로는 8.0.x 일 수도 있어 알 수
    없는 값이다. 겹치는 자리까지만 비교하고, 거기서 같으면 짧은 쪽은 판단을 포기한다.
    """
    depth = min(len(current), len(limit))
    if current[:depth] != limit[:depth]:
        return current[:depth] < limit[:depth]
    return False  # 겹치는 자리가 같다 - 기준 이상이거나(2.4.58 vs 2.4) 알 수 없다(8 vs 8.0)


def _load_eol() -> dict:
    try:
        return json.loads(_EOL_SEED.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("EOL 표를 읽지 못했습니다 - 버전 기반 판정을 건너뜁니다", exc_info=True)
        return {"as_of": "", "products": []}


_EOL = _load_eol()


def eol_finding(product: str, version: str) -> dict | None:
    """이 제품·버전이 지원 종료인가. 아니거나 판단할 수 없으면 None.

    제품명은 nmap 이 'Apache httpd', 'Samba smbd' 처럼 서술 접미사를 붙여 내므로 부분일치로
    본다. 버전을 읽을 수 없으면 아무 말도 하지 않는다 - 모르는 것을 오래됐다고 하지 않는다.
    """
    name = str(product or "").lower()
    current = _version_tuple(version)
    if not name or not current:
        return None
    for entry in _EOL.get("products", []):
        wanted = str(entry.get("product") or "").lower()
        if not wanted or wanted not in name:
            continue
        limit = _version_tuple(entry.get("eol_below", ""))
        if not limit or not _is_below(current, limit):
            continue
        return {**entry, "as_of": _EOL.get("as_of", "")}
    return None


def apply_version_age(finding: dict) -> None:
    """지원 종료 버전이면 위험 하한을 올리고, 판단 근거와 표의 기준일을 남긴다.

    노출 신호와 같은 규칙이다 - 올리기만 하고 내리지 않으며, 조직 규칙보다 먼저 적용해
    '허용' 판단이 이기게 한다. 표는 에어갭에서 자동 갱신될 수 없으므로 기준일을 함께
    적어, 읽는 사람이 얼마나 오래된 판단인지 알 수 있게 한다.
    """
    hit = eol_finding(finding.get("product", ""), finding.get("version", ""))
    if hit is None:
        return
    finding["risk_level"] = _raise_to(finding.get("risk_level", "info"), "high")
    stamp = f", 표 기준일 {hit['as_of']}" if hit.get("as_of") else ""
    finding["compliance_json"].append({
        "std": "지원종료",
        "ref": (f"{hit.get('note') or hit.get('product')} "
                f"(관측 {finding.get('product', '')} {finding.get('version', '')}"
                f" · EOL {hit.get('eol_date', '미상')}{stamp})"),
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

    # 지원 종료 버전도 관측된 사실이다. -sV 가 이미 버전을 읽어 VERSION_CHANGED 이력까지
    # 남기면서 위험에는 반영되지 않던 자리다.
    apply_version_age(finding)

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
             # product 만 넘기고 version 을 빠뜨리면 EOL 판정이 재분류에서 조용히 사라진다.
             # 이 dict 는 classify() 가 읽는 관측 입력의 전부이므로, 하나라도 빠지면 그 판정만
             # 규칙 편집 때마다 없어진다.
             "product": f.product, "version": f.version, "cpe": f.cpe,
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
