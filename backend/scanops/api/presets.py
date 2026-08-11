"""스캔 프리셋 라우터 — 웹 UI 저장소이자 단독 스캐너의 도킹 지점.

`GET`                       : 현재 프리셋 목록 + revision(열람 권한)
`PUT /item/{name}`          : 프리셋 하나만 추가/교체(auditor 이상)
`DELETE /item/{name}`       : 프리셋 하나만 삭제(auditor 이상)
`PUT` (목록 전체 교체)      : revision 일치를 요구하는 조건부 교체(auditor 이상)
`POST /sync`                : 단독 스캐너 도킹 — 먼저 충돌을 확인하고, 없을 때만 합집합으로 맞춘다.

**동시 쓰기 규칙.** 프리셋은 파일 하나에 모여 있으므로 read-modify-write 가 겹치면 한쪽
저장이 통째로 사라진다. 그래서 쓰기 경로를 두 종류로 나눴다.
- 이름 하나만 건드리는 쓰기(`/item/...`)는 나머지 항목을 읽지도 않고 보존하므로 안전하다.
  웹 UI 의 저장/삭제는 실제로 이 의미이며, 이 경로를 쓴다.
- 목록 전체 교체는 본질적으로 "내가 읽은 것이 전부였다"는 주장이므로 revision 을 요구한다.
  읽은 뒤 다른 클라이언트가 무언가 추가했으면 409 로 거절한다.

동기화도 같은 원칙이다. 충돌이 하나라도 있으면 **서버 파일을 전혀 건드리지 않고**
충돌 목록만 돌려준다(부분 병합 없음).
"""
from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User
from ..schemas import ScanPresetItem, ScanPresetReplace, ScanPresetSync
from ..scanning import preset_store
from .audit import record
from .deps import current_user, require_role

router = APIRouter()
_settings = get_settings()
logger = logging.getLogger(__name__)

# 프리셋 파일은 단일 파일이라 read-modify-write 가 겹치면 한쪽 저장이 통째로 사라진다.
# 스캐너 동기화와 웹 저장이 동시에 들어올 수 있으므로 쓰기 구간을 직렬화한다.
_WRITE_LOCK = threading.Lock()


def _path():
    return _settings.preset_file


def _load() -> list[dict]:
    try:
        return preset_store.load(_path())
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except OSError:
        logger.exception("scan preset file is unreadable: %s", _path())
        raise HTTPException(status_code=500, detail="프리셋 파일을 읽지 못했습니다.")


def _save(presets: list[dict]) -> list[dict]:
    try:
        return preset_store.save(_path(), presets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError:
        logger.exception("scan preset file is not writable: %s", _path())
        raise HTTPException(status_code=500, detail="프리셋 파일을 저장하지 못했습니다.")


def _document(presets: list[dict]) -> dict:
    """응답 본문. 각 항목에 서버가 쓰는 **정규화된 이름 키**를 실어 보낸다.

    클라이언트가 '같은 이름인가'를 스스로 계산하면(예: trim().toLowerCase()) 서버의
    규칙(연속 공백 접기 + casefold)과 어긋나 'Weekly  Full' 과 'weekly full' 을 다른
    것으로 보내고 서버는 중복이라 거절하는 불일치가 생긴다. 판정 기준을 서버가 준다.
    """
    return {
        "schema": preset_store.PRESET_SCHEMA,
        "revision": preset_store.document_revision(presets),
        "presets": [{**p, "name_key": preset_store.name_key(p["name"])} for p in presets],
    }


def _normalized_name(name: str) -> str:
    try:
        return preset_store.validate_name(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("")
def list_presets(_: User = Depends(current_user)) -> dict:
    return _document(_load())


@router.put("/item/{name}")
def upsert_preset(
    body: ScanPresetItem,
    name: str = Path(..., description="프리셋 이름"),
    create_only: bool = False,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    """프리셋 하나만 추가/교체한다. 다른 항목은 읽지도 않고 그대로 둔다.

    create_only=true 는 '없을 때만 만들기' — 이미 있으면 409. 웹 UI 가 예전 localStorage
    프리셋을 이관할 때 서버의 동명 프리셋을 덮어쓰지 않기 위해 쓴다.
    """
    target = _normalized_name(name)
    payload = body.model_dump()
    body_name = (payload.get("name") or "").strip()
    if body_name and preset_store.name_key(body_name) != preset_store.name_key(target):
        # 이름 변경은 삭제+생성으로만. 경로와 본문이 다른 이름을 가리키면 어느 쪽이 대상인지 모호하다.
        raise HTTPException(status_code=400, detail="경로의 이름과 본문의 이름이 다릅니다. 이름 변경은 삭제 후 새로 저장하세요.")
    payload["name"] = target
    try:
        preset = preset_store.normalize_preset(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with _WRITE_LOCK:
        current = _load()
        exists = any(preset_store.name_key(p["name"]) == preset_store.name_key(target) for p in current)
        if exists and create_only:
            raise HTTPException(status_code=409, detail=f"같은 이름의 프리셋이 이미 있습니다: {target}")
        try:
            saved = _save(preset_store.upsert(current, preset))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    record(db, user, "SCAN_PRESET_SAVE", target=target, detail="교체" if exists else "추가")
    # 서버가 정규화한 이름을 돌려준다 — 클라이언트가 이름 규칙을 다시 구현하지 않아도 되게.
    return {**_document(saved), "name": preset["name"]}


@router.delete("/item/{name}")
def delete_preset(
    name: str = Path(..., description="프리셋 이름"),
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    target = _normalized_name(name)
    with _WRITE_LOCK:
        current = _load()
        kept, removed = preset_store.remove(current, target)
        if not removed:
            raise HTTPException(status_code=404, detail=f"프리셋이 없습니다: {target}")
        saved = _save(kept)
    record(db, user, "SCAN_PRESET_DELETE", target=target)
    return {**_document(saved), "name": target}


@router.put("")
def replace_presets(
    body: ScanPresetReplace,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    """목록 전체 교체 — 읽은 시점의 revision 과 일치할 때만 허용한다.

    revision 없이 통째로 덮어쓰게 두면, 목록을 읽은 뒤 다른 클라이언트가 추가한 프리셋이
    아무 오류 없이 사라진다(두 요청 모두 200). 낱개 편집은 /item/{name} 을 쓰면 되므로
    이 경로는 조건부로만 남긴다.
    """
    try:
        incoming = preset_store.normalize_presets([p.model_dump() for p in body.presets])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with _WRITE_LOCK:
        current = _load()
        expected = preset_store.document_revision(current)
        if body.revision != expected:
            record(db, user, "SCAN_PRESET_SAVE", target="scan_presets",
                   detail="revision 불일치 — 교체 취소", ok=False)
            raise HTTPException(
                status_code=409,
                detail="다른 곳에서 프리셋이 변경되었습니다. 목록을 다시 불러온 뒤 저장하세요.",
            )
        saved = _save(incoming)
    record(db, user, "SCAN_PRESET_SAVE", target="scan_presets", detail=f"전체 교체 {len(saved)}건")
    return _document(saved)


@router.post("/sync")
def sync_presets(
    body: ScanPresetSync,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    """단독 스캐너 도킹 — 충돌 없으면 합집합 동기화, 있으면 아무것도 바꾸지 않는다.

    응답의 `status` 가 계약이다. `conflict` 면 서버는 그대로이며 클라이언트도 자기 파일을
    바꾸면 안 된다. `synced` 면 `presets` 가 양쪽이 가져야 할 최종 목록이다.
    """
    try:
        incoming = preset_store.normalize_presets([p.model_dump() for p in body.presets])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with _WRITE_LOCK:
        server = _load()
        delta = preset_store.diff(incoming, server)
        if delta["conflicts"]:
            record(db, user, "SCAN_PRESET_SYNC", target="scan_presets",
                   detail=f"충돌 {len(delta['conflicts'])}건 — 동기화 취소", ok=False)
            return {
                "status": "conflict",
                "schema": preset_store.PRESET_SCHEMA,
                "conflicts": [
                    {"name": c["name"], "remote_name": c["remote_name"]}
                    for c in delta["conflicts"]
                ],
                "presets": server,
            }
        merged = preset_store.merge(incoming, server)
        # 서버에 새로 들어온 것이 없으면 파일을 다시 쓰지 않는다(불필요한 mtime 변경 방지).
        saved = _save(merged) if delta["only_local"] else server
    record(db, user, "SCAN_PRESET_SYNC", target="scan_presets",
           detail=f"서버 추가 {len(delta['only_local'])}건 · 스캐너 추가 {len(delta['only_remote'])}건")
    return {
        "status": "synced",
        "schema": preset_store.PRESET_SCHEMA,
        "conflicts": [],
        "added_to_server": [p["name"] for p in delta["only_local"]],
        "added_to_client": [p["name"] for p in delta["only_remote"]],
        "presets": saved,
    }
