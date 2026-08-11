"""스캔 프리셋 라우터 — 웹 UI 저장소이자 단독 스캐너의 도킹 지점.

`GET`  : 현재 서버 프리셋 목록(열람 권한)
`PUT`  : 웹 UI 의 저장/삭제(전체 교체, auditor 이상)
`POST /sync` : 단독 스캐너 도킹 — 먼저 충돌을 확인하고, 없을 때만 양쪽을 합집합으로 맞춘다.

동기화는 '충돌 확인 → 없으면 병합' 두 단계를 한 요청에서 처리하지만, 충돌이 하나라도
있으면 **서버 파일을 전혀 건드리지 않고** 충돌 목록만 돌려준다(부분 병합 없음).
"""
from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User
from ..schemas import ScanPresetSync
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
    return {"schema": preset_store.PRESET_SCHEMA, "presets": presets}


@router.get("")
def list_presets(_: User = Depends(current_user)) -> dict:
    return _document(_load())


@router.put("")
def replace_presets(
    body: ScanPresetSync,
    user: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
) -> dict:
    """웹 UI 의 프리셋 저장/삭제 — 목록 전체를 교체한다."""
    try:
        incoming = preset_store.normalize_presets([p.model_dump() for p in body.presets])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with _WRITE_LOCK:
        saved = _save(incoming)
    record(db, user, "SCAN_PRESET_SAVE", target="scan_presets", detail=f"{len(saved)}건")
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
