"""SQLAlchemy 엔진/세션 — SQLite(WAL, 단일 진실원천)."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_engine = create_engine(
    f"sqlite:///{_settings.db_path}",
    connect_args={"check_same_thread": False},
    future=True,
)


@event.listens_for(_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")      # 동시 읽기 + 쓰기 내구성
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_engine():
    return _engine


def init_db() -> None:
    """모델 메타데이터로 테이블 생성(idempotent) + 경량 마이그레이션."""
    from . import models  # noqa: F401  (모델 등록)
    Base.metadata.create_all(_engine)
    _migrate()


def _migrate() -> None:
    """create_all 이 못 하는 기존 DB 보강(SQLite). idempotent."""
    with _engine.begin() as conn:
        cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()}
        if "owner" not in cols:  # 자산대장 담당자명 전파용 컬럼
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN owner VARCHAR(128) DEFAULT ''")
        # 예외승인 폐지 → 정상처리로 통합
        conn.exec_driver_sql("UPDATE findings SET status='정상처리' WHERE status='예외승인'")


def get_db() -> Iterator[Session]:
    """FastAPI 의존성."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
