"""최초 부팅 시드 — 기본 admin 계정. (taxonomy 시드는 D 단계에서 추가)"""
from __future__ import annotations

import secrets

from ..config import get_settings
from ..db import SessionLocal
from ..models import User
from ..scanning.taxonomy import seed_categories
from ..security import hash_password


def run_bootstrap() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        seed_categories(db)
        if db.query(User).count() > 0:
            return
        # 에어갭 첫 부팅: 랜덤 비밀번호 생성 후 파일로 1회 안내.
        pw = secrets.token_urlsafe(12)
        db.add(User(
            username="admin",
            password_hash=hash_password(pw),
            role="admin",
            display_name="관리자",
        ))
        db.commit()
        cred = settings.data_dir / "INITIAL_ADMIN.txt"
        cred.write_text(
            f"ScanOps 최초 관리자 계정\n  아이디: admin\n  비밀번호: {pw}\n"
            f"\n로그인 후 비밀번호를 변경하고 이 파일을 삭제하세요.\n",
            encoding="utf-8",
        )
    finally:
        db.close()
