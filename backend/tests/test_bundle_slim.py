"""올인원 번들 슬림화가 '완전 오프라인 구동'을 깨지 않는지 고정한다.

번들은 에어갭 타깃에서 처음 실행된다. 거기서 ModuleNotFoundError 가 나면 고칠
방법이 없으므로, 슬림화가 지운 표준 라이브러리를 앱이나 의존성이 실제로 쓰는지는
빌드 이전에 — CI 에서 — 판정돼야 한다.

여기서는 두 각도로 본다:
  1) 정적: 지운 이름을 import 하는 소스가 있는가(빌더와 같은 함수를 그대로 쓴다).
  2) 동적: 지운 이름을 전부 막은 인터프리터에서 서버가 실제 요청을 처리하는가.
동적 검사는 lazy import(첫 요청에서야 걸리는 것)를 잡으려는 것이라 별도 프로세스에서
돈다 — 이미 import 가 끝난 테스트 프로세스 안에서는 차단이 의미가 없다.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _builder():
    path = ROOT / "packaging" / "build_allinone.py"
    spec = importlib.util.spec_from_file_location("scanops_build_allinone", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dropped_names() -> set[str]:
    build = _builder()
    return set(build.STDLIB_DROP_PACKAGES) | set(build.STDLIB_DROP_MODULES)


# 지우면 번들이 부팅조차 못 하거나 기능이 사라지는 이름들. 슬림화 목록이 커질 때
# 사람이 무심코 넣는 사고를 막는 안전핀이다(각각의 이유는 아래 주석 참고).
FATAL_TO_DROP = {
    "encodings",     # 인터프리터 부팅
    "runpy",         # START.bat 의 python -m uvicorn
    "asyncio", "selectors", "socket",   # uvicorn
    "email", "http", "urllib", "json",  # HTTP 처리
    "sqlite3",       # 유일한 DB 방언
    "hashlib", "hmac", "secrets",       # 로그인/토큰
    "ssl",           # 스캐너 --sync https
    "ctypes",        # colorama(Windows 콘솔)
    "zipfile", "csv", "datetime", "logging", "typing", "re",
}


def test_slim_list_never_touches_a_name_the_bundle_cannot_boot_without():
    assert not (_dropped_names() & FATAL_TO_DROP)


def test_sqlite_dialect_survives_the_dialect_trim():
    build = _builder()
    assert "sqlite" not in build.SQLALCHEMY_DROP_DIALECTS


def test_no_trimmed_stdlib_name_is_imported_by_shipped_source():
    """앱·엔진·CLI 스캐너 소스가 지운 이름을 import 하지 않는다.

    (의존성까지 합친 같은 검사는 빌드 시점에 staged 번들 전체를 대고 한 번 더 돈다 —
    packaging/build_allinone.py 의 verify_stdlib_drop.)"""
    build = _builder()
    dropped = _dropped_names()
    offenders: dict[str, list[str]] = {}
    sources = [
        *(ROOT / "backend" / "scanops").rglob("*.py"),
        *(ROOT / "engine").rglob("*.py"),
        ROOT / "scanner" / "scanops_scanner.py",
    ]
    for path in sources:
        used = build._top_level_imports(path.read_text(encoding="utf-8"))
        for name in sorted(used & dropped):
            offenders.setdefault(name, []).append(path.name)
    assert not offenders, f"슬림화 목록과 충돌하는 import: {offenders}"


# 별도 프로세스에서 돌 본문. 차단기를 먼저 심고 나서야 scanops 를 import 한다.
_BLOCKED_RUN = """
import importlib.abc, importlib.util, os, sys, tempfile
sys.path.insert(0, {backend!r})
os.environ["SCANOPS_DATA_DIR"] = tempfile.mkdtemp(prefix="scanops_slim_")

spec = importlib.util.spec_from_file_location("b", {builder!r})
build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
blocked = set(build.STDLIB_DROP_PACKAGES) | set(build.STDLIB_DROP_MODULES)

class _Trimmed(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in blocked:
            raise ImportError("removed by bundle slim: " + name)
        return None

sys.meta_path.insert(0, _Trimmed())

from fastapi.testclient import TestClient
from scanops.db import SessionLocal, init_db
from scanops.main import app
from scanops.models import User
from scanops.security import hash_password

init_db()
db = SessionLocal()
db.add(User(username="slim", password_hash=hash_password("slim-pass-1234"),
            role="admin", display_name="slim"))
db.commit(); db.close()

with TestClient(app) as c:
    r = c.post("/api/auth/login",
               json={{"username": "slim", "password": "slim-pass-1234"}})
    assert r.status_code == 200, r.text          # pbkdf2 (_hashlib) 경로
    h = {{"Authorization": "Bearer " + r.json()["token"]}}
    assert c.get("/api/findings", headers=h).status_code == 200
    x = c.get("/api/findings/export?fmt=xlsx", headers=h)   # openpyxl 지연 import
    assert x.status_code == 200, x.status_code
print("SLIM-OK")
"""


def test_server_answers_requests_with_every_trimmed_module_blocked(tmp_path):
    code = _BLOCKED_RUN.format(
        backend=str(ROOT / "backend"),
        builder=str(ROOT / "packaging" / "build_allinone.py"),
    )
    script = tmp_path / "slim_boot.py"
    script.write_text(code, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SLIM-OK" in proc.stdout
