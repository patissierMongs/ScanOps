"""최초 부팅 시드 — 기본 admin 계정. (taxonomy 시드는 D 단계에서 추가)"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from ..config import get_settings
from ..db import SessionLocal
from ..models import User
from ..scanning.taxonomy import seed_categories
from ..security import hash_password, verify_password


_PASSWORD_LINE = re.compile(r"(?m)^\s*비밀번호:\s*(\S+)\s*$")


def _credential_password(path: Path) -> str:
    try:
        match = _PASSWORD_LINE.search(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return ""
    return match.group(1) if match else ""


def _write_credentials(path: Path, password: str) -> None:
    """안내 파일을 완성한 뒤 교체해, 읽는 순간 빈 파일이 보이지 않게 한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        temp.write_text(
            f"ScanOps 최초 관리자 계정\n  아이디: admin\n  비밀번호: {password}\n"
            f"\n첫 로그인 때 비밀번호 변경을 요구합니다. 변경하면 이 파일은 자동으로 삭제됩니다.\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def _save_initial_password(db, user: User, path: Path, password: str) -> None:
    """파일과 해시가 서로 다른 상태로 남지 않게 실패 시 둘 다 되돌린다."""
    _write_credentials(path, password)
    try:
        db.commit()
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise


def run_bootstrap() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        seed_categories(db)
        cred = settings.data_dir / "INITIAL_ADMIN.txt"
        admin = db.query(User).filter(User.username == "admin").first()
        if admin is not None:
            # 최초 비밀번호 변경 전인데 안내 파일이 비었거나 손상된 경우, 기존 해시는
            # 역산할 수 없다. 새 임시 비밀번호로 재발급해야 설치가 영구 잠기지 않는다.
            if admin.must_change_password:
                recorded = _credential_password(cred)
                if not recorded or not verify_password(recorded, admin.password_hash):
                    pw = secrets.token_urlsafe(12)
                    admin.password_hash = hash_password(pw)
                    admin.auth_version = (admin.auth_version or 0) + 1
                    _save_initial_password(db, admin, cred, pw)
            return
        if db.query(User).count() > 0:
            return
        # 에어갭 첫 부팅: 랜덤 비밀번호 생성 후 파일로 1회 안내.
        pw = secrets.token_urlsafe(12)
        admin = User(
            username="admin",
            password_hash=hash_password(pw),
            role="admin",
            display_name="관리자",
            # 이 비밀번호는 평문으로 파일에 남는다. 바꾸기 전까지는 로그인해도 아무것도
            # 하지 못하게 막고, 바꾸는 순간 파일을 지운다 - '나중에 하세요'로 두면 남는다.
            must_change_password=1,
        )
        db.add(admin)
        _save_initial_password(db, admin, cred, pw)
    finally:
        db.close()
