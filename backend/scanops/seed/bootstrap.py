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
            # 이 비밀번호는 평문으로 파일에 남는다. 바꾸기 전까지는 로그인해도 아무것도
            # 하지 못하게 막고, 바꾸는 순간 파일을 지운다 - '나중에 하세요'로 두면 남는다.
            must_change_password=1,
        ))
        db.commit()
        cred = settings.data_dir / "INITIAL_ADMIN.txt"
        cred.write_text(
            f"ScanOps 최초 관리자 계정\n  아이디: admin\n  비밀번호: {pw}\n"
            f"\n첫 로그인 때 비밀번호 변경을 요구합니다. 변경하면 이 파일은 자동으로 삭제됩니다.\n",
            encoding="utf-8",
        )
    finally:
        db.close()
