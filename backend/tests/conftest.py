"""테스트 공통 — 임시 데이터 디렉터리로 격리(실데이터/실 DB 안 건드림)."""
import os
import tempfile

# scanops 를 import 하기 전에 데이터 경로를 임시로 돌린다.
_TMP = tempfile.mkdtemp(prefix="scanops_test_")
os.environ["SCANOPS_DATA_DIR"] = _TMP

import pytest
from fastapi.testclient import TestClient

from scanops.db import Base, SessionLocal, get_engine, init_db
from scanops.main import app
from scanops.models import User
from scanops.security import hash_password


@pytest.fixture(autouse=True)
def _clean_db():
    """테스트마다 깨끗한 스키마로 시작(공유 임시 DB 격리)."""
    init_db()
    eng = get_engine()
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:  # lifespan: init_db + bootstrap
        yield c


def make_user(username: str, password: str, role: str = "viewer") -> None:
    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            return
        db.add(User(username=username, password_hash=hash_password(password),
                    role=role, display_name=username))
        db.commit()
    finally:
        db.close()


def token_for(client: TestClient, username: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]
