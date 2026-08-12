"""스캔 프리셋 저장소 — 웹 서버와 단독 스캐너가 공유하는 파일 형식.

두 곳(서버 `data/scan_presets.json`, 스캐너 폴더 `scanops_presets.json`)에 같은 내용의
파일이 존재하고, 단독 스캐너가 서버에 도킹해 동기화한다. 동기화는 **이름 충돌이 하나도
없을 때만** 양쪽을 합집합으로 맞춘다(같은 이름 + 다른 내용 = 충돌 → 아무것도 안 바꿈).

프리셋 본문은 nmap 플래그가 아니라 **옵션 키**(scan_options.SCAN_OPTIONS)로 저장한다.
그래야 웹 UI 토글과 단독 스캐너가 같은 값을 서로 해석할 수 있고, 임의 플래그 주입도 막힌다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import scan_options

PRESET_SCHEMA = 1
# 이름은 파일/로그/드롭다운에 그대로 노출되므로 제어문자·과도한 길이를 미리 거절한다.
MAX_NAME_LEN = 60
MAX_DESC_LEN = 200
MAX_PRESETS = 200
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# 이름은 URL 경로 조각(PUT /api/scan-presets/item/{name})과 파일 목록에 그대로 실린다.
# 경로 구분자가 섞이면 어느 프리셋을 가리키는지 서버·프록시·클라이언트가 다르게 읽을 수 있다.
_NAME_FORBIDDEN = ("/", "\\")

# 파일 안의 workflow 는 단독 스캐너 어휘(single)를 정본으로 쓴다. 웹 UI 의 'manual' 은 같은 뜻.
_WORKFLOW_ALIASES = {"manual": "single", "single": "single", "auto": "auto"}
WORKFLOWS = ("auto", "single")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def name_key(name: str) -> str:
    """충돌 판정용 이름 키 — 앞뒤 공백/대소문자/연속 공백 차이는 같은 이름으로 본다."""
    return " ".join(str(name or "").split()).casefold()


def normalize_workflow(value: str) -> str:
    workflow = _WORKFLOW_ALIASES.get(str(value or "single").strip().lower())
    if workflow is None:
        raise ValueError(f"프리셋 workflow 는 auto 또는 single 이어야 합니다: {value!r}")
    return workflow


def _clean_text(value, label: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if _CONTROL_RE.search(text):
        raise ValueError(f"프리셋 {label}에 사용할 수 없는 문자가 있습니다.")
    if len(text) > limit:
        raise ValueError(f"프리셋 {label}은 {limit}자 이내여야 합니다.")
    return text


def validate_name(value) -> str:
    name = _clean_text(value, "이름", MAX_NAME_LEN)
    if not name:
        raise ValueError("프리셋 이름이 비어 있습니다.")
    if any(token in name for token in _NAME_FORBIDDEN):
        raise ValueError("프리셋 이름에 / 또는 \\ 를 쓸 수 없습니다.")
    return name


def _ordered_unique(values, label: str) -> list[str]:
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise ValueError(f"프리셋 {label}은 문자열 목록이어야 합니다.")
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"프리셋 {label}은 문자열 목록이어야 합니다.")
        if value not in out:
            out.append(value)
    return out


def normalize_preset(raw: dict) -> dict:
    """단일 프리셋 검증·정규화. 화이트리스트 밖 옵션/NSE/포트는 여기서 거절된다."""
    if not isinstance(raw, dict):
        raise ValueError("프리셋 항목이 객체가 아닙니다.")
    name = validate_name(raw.get("name"))
    options = _ordered_unique(raw.get("options") or [], "options")
    scan_options.validate_keys(options)
    nse = _ordered_unique(raw.get("nse") or [], "nse")
    scan_options.validate_nse(nse)
    ports = scan_options.validate_ports(str(raw.get("ports") or ""))
    updated_at = _clean_text(raw.get("updated_at"), "updated_at", 40)
    return {
        "name": name,
        "description": _clean_text(raw.get("description"), "설명", MAX_DESC_LEN),
        "workflow": normalize_workflow(raw.get("workflow")),
        # 레지스트리 순서로 고정 → 선택 순서가 달라도 같은 프리셋은 같은 지문을 갖는다.
        "options": [o["key"] for o in scan_options.SCAN_OPTIONS if o["key"] in set(options)],
        "ports": ports,
        "nse": [s["key"] for s in scan_options.NSE_SCRIPTS if s["key"] in set(nse)],
        "updated_at": updated_at or now_iso(),
    }


def normalize_presets(raw_presets) -> list[dict]:
    """목록 전체 정규화. 같은 이름이 두 번 오면(대소문자/공백 차이 포함) 거절한다."""
    if isinstance(raw_presets, dict):
        raw_presets = raw_presets.get("presets")
    if raw_presets is None:
        return []
    if not isinstance(raw_presets, (list, tuple)):
        raise ValueError("presets 는 목록이어야 합니다.")
    if len(raw_presets) > MAX_PRESETS:
        raise ValueError(f"프리셋은 최대 {MAX_PRESETS}개까지 저장할 수 있습니다.")
    out: list[dict] = []
    seen: set[str] = set()
    for raw in raw_presets:
        preset = normalize_preset(raw)
        key = name_key(preset["name"])
        if key in seen:
            raise ValueError(f"프리셋 이름이 중복됩니다: {preset['name']}")
        seen.add(key)
        out.append(preset)
    return sorted(out, key=lambda p: name_key(p["name"]))


def fingerprint(preset: dict) -> str:
    """내용 지문 — updated_at/설명 같은 메타는 빼고 '실제 스캔 동작'만 비교한다.

    설명만 다른 두 프리셋을 충돌로 보면 동기화가 사람 손을 계속 요구하게 된다.
    실행 결과가 같으면 같은 프리셋으로 본다.
    """
    body = {
        "workflow": preset["workflow"],
        "options": sorted(preset["options"]),
        "ports": preset["ports"],
        "nse": sorted(preset["nse"]),
    }
    blob = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def document_revision(presets: list[dict]) -> str:
    """저장 문서 전체의 지문 — 전체 교체 쓰기의 optimistic-concurrency 토큰.

    **`fingerprint()` 를 재사용하면 안 된다.** fingerprint 는 '같은 스캔인가'를 묻는 값이라
    description·updated_at·이름 표기를 일부러 뺀다. 그 값으로 revision 을 만들면 설명만 바꾼
    수정이 revision 을 움직이지 못해, 낡은 목록을 든 전체 교체가 409 없이 통과하며 그 수정을
    조용히 되돌린다. revision 은 '이 쓰기가 파괴할 수 있는 모든 것'을 덮어야 하므로
    정규화된 저장 문서를 통째로 해시한다(normalize_presets 가 순서까지 고정한다).
    """
    normalized = normalize_presets(presets)
    blob = json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def upsert(presets: list[dict], preset: dict) -> list[dict]:
    """이름 하나만 추가/교체한다. 나머지 항목은 그대로 — 이 경로엔 lost update 가 없다."""
    key = name_key(preset["name"])
    return normalize_presets([p for p in presets if name_key(p["name"]) != key] + [preset])


def remove(presets: list[dict], name: str) -> tuple[list[dict], bool]:
    """이름 하나만 제거. 두 번째 값은 실제로 지운 것이 있었는지."""
    key = name_key(name)
    kept = [p for p in presets if name_key(p["name"]) != key]
    return kept, len(kept) != len(presets)


def diff(local: list[dict], remote: list[dict]) -> dict:
    """양쪽 목록 비교 → 충돌/한쪽에만 있는 항목.

    conflicts: 같은 이름인데 내용(지문)이 다른 것 → 하나라도 있으면 동기화하지 않는다.
    """
    local_by = {name_key(p["name"]): p for p in local}
    remote_by = {name_key(p["name"]): p for p in remote}
    conflicts = [
        {
            "name": local_by[key]["name"],
            "local_fingerprint": fingerprint(local_by[key]),
            "remote_name": remote_by[key]["name"],
            "remote_fingerprint": fingerprint(remote_by[key]),
        }
        for key in sorted(local_by.keys() & remote_by.keys())
        if fingerprint(local_by[key]) != fingerprint(remote_by[key])
    ]
    return {
        "conflicts": conflicts,
        "only_local": [local_by[key] for key in sorted(local_by.keys() - remote_by.keys())],
        "only_remote": [remote_by[key] for key in sorted(remote_by.keys() - local_by.keys())],
        "same": [local_by[key] for key in sorted(local_by.keys() & remote_by.keys())
                 if fingerprint(local_by[key]) == fingerprint(remote_by[key])],
    }


def merge(local: list[dict], remote: list[dict]) -> list[dict]:
    """충돌이 없다는 전제에서의 합집합. 같은 이름은 원격 표기를 유지(서버가 이름 표기 기준)."""
    merged = {name_key(p["name"]): p for p in local}
    merged.update({name_key(p["name"]): p for p in remote})
    return sorted(merged.values(), key=lambda p: name_key(p["name"]))


# ── 파일 입출력 ──

def load(path: Path) -> list[dict]:
    """프리셋 파일 읽기. 없으면 빈 목록. 손상 파일은 정직하게 ValueError."""
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"프리셋 파일을 해석할 수 없습니다: {path} ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"프리셋 파일 형식이 올바르지 않습니다: {path}")
    schema = data.get("schema", PRESET_SCHEMA)
    if not isinstance(schema, int) or schema > PRESET_SCHEMA:
        raise ValueError(
            f"프리셋 파일 스키마({schema})가 이 버전보다 새것입니다. 도구를 업데이트하세요: {path}"
        )
    return normalize_presets(data.get("presets"))


def save(path: Path, presets: list[dict]) -> list[dict]:
    """원자적 쓰기 — 임시파일 후 os.replace. 중간 실패로 반쪽 파일이 남지 않는다."""
    path = Path(path)
    normalized = normalize_presets(presets)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": PRESET_SCHEMA, "updated_at": now_iso(), "presets": normalized}
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return normalized
