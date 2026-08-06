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
        user_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()}
        if "auth_version" not in user_cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN auth_version INTEGER DEFAULT 0")
        rule_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(risk_rules)").fetchall()}
        if rule_cols and "product" not in rule_cols:  # 제품/CPE 기반 조직 규칙
            conn.exec_driver_sql("ALTER TABLE risk_rules ADD COLUMN product VARCHAR(128) DEFAULT ''")
        if rule_cols and "cpe" not in rule_cols:
            conn.exec_driver_sql("ALTER TABLE risk_rules ADD COLUMN cpe VARCHAR(128) DEFAULT ''")
        cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()}
        if "owner" not in cols:  # 자산대장 담당자명 전파용 컬럼
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN owner VARCHAR(128) DEFAULT ''")
        if "reopened" not in cols:  # 재발 태그 컬럼
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN reopened INTEGER DEFAULT 0")
        server_added = "server" not in cols
        if server_added:  # NSE HTTP Server 구조화 값
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN server VARCHAR(256) DEFAULT ''")
            import json
            from .scanning.nmap_parse import extract_server

            for finding_id, raw_nse in conn.exec_driver_sql(
                "SELECT id, nse_json FROM findings WHERE nse_json IS NOT NULL"
            ).fetchall():
                try:
                    nse = json.loads(raw_nse) if isinstance(raw_nse, str) else raw_nse
                except (TypeError, ValueError):
                    continue
                if server := extract_server(nse):
                    conn.exec_driver_sql(
                        "UPDATE findings SET server=? WHERE id=?", (server, finding_id)
                    )
        # 예외승인 폐지 → 정상처리로 통합
        conn.exec_driver_sql("UPDATE findings SET status='정상처리' WHERE status='예외승인'")
        # 재발 상태 폐지 → 미조치 + reopened 태그로 전환
        conn.exec_driver_sql("UPDATE findings SET reopened=1, status='미조치' WHERE status='재발'")
        # 단계분리 엔진 스캔의 단계 요약 컬럼(기존 DB 보강)
        sc_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(scan_runs)").fetchall()}
        if "stages_json" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN stages_json JSON")
        if "failure_code" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN failure_code VARCHAR(64) DEFAULT ''")
        if "failure_message" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN failure_message VARCHAR(256) DEFAULT ''")


def get_db() -> Iterator[Session]:
    """FastAPI 의존성."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
