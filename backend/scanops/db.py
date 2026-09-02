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
    _ensure_monotonic_ids()


MONOTONIC_ID_TABLES = ("scan_runs", "findings", "finding_events", "notifications", "audit_logs")


def _table_lacks_autoincrement(cur, table: str) -> bool:
    row = cur.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return bool(row) and "AUTOINCREMENT" not in (row[0] or "").upper()


def _ensure_monotonic_ids() -> None:
    raw = _engine.raw_connection()
    try:
        cur = raw.cursor()
        pending = [t for t in MONOTONIC_ID_TABLES if _table_lacks_autoincrement(cur, t)]
        if not pending:
            return
        cur.execute("PRAGMA foreign_keys=OFF")
        cur.execute("BEGIN")
        try:
            for table in pending:
                _rebuild_with_autoincrement(cur, table)
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.execute("PRAGMA foreign_keys=ON")
    finally:
        raw.close()


def _fill_literal(column) -> str:
    default = column.default.arg if column.default is not None and column.default.is_scalar else None
    if default is None:
        if column.nullable:
            return "NULL"
        default = 0 if column.type.python_type in (int, float, bool) else ""
    if isinstance(default, bool):
        return "1" if default else "0"
    if isinstance(default, (int, float)):
        return repr(default)
    return "'" + str(default).replace("'", "''") + "'"


def _rebuild_with_autoincrement(cur, table: str) -> None:
    ddl = Base.metadata.tables[table]
    from sqlalchemy.schema import CreateTable, CreateIndex

    create_sql = str(CreateTable(ddl).compile(_engine)).strip()
    tmp = f"{table}__autoinc"
    create_tmp = create_sql.replace(f"CREATE TABLE {table} ", f"CREATE TABLE {tmp} ", 1)
    assert create_tmp != create_sql
    assert "AUTOINCREMENT" in create_tmp.upper()
    existing = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
    targets, sources = [], []
    for column in ddl.columns:
        targets.append(column.name)
        sources.append(column.name if column.name in existing else _fill_literal(column))
    max_id = cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
    cur.execute(create_tmp)
    cur.execute(
        f"INSERT INTO {tmp} ({', '.join(targets)}) SELECT {', '.join(sources)} FROM {table}"
    )
    cur.execute(f"DROP TABLE {table}")
    cur.execute(f"ALTER TABLE {tmp} RENAME TO {table}")
    for index in ddl.indexes:
        cur.execute(str(CreateIndex(index).compile(_engine)).strip())
    if max_id:
        cur.execute("DELETE FROM sqlite_sequence WHERE name=?", (table,))
        cur.execute("INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)", (table, max_id))


def _migrate() -> None:
    """create_all 이 못 하는 기존 DB 보강(SQLite). idempotent."""
    with _engine.begin() as conn:
        user_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()}
        if "auth_version" not in user_cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN auth_version INTEGER DEFAULT 0")
        if user_cols and "must_change_password" not in user_cols:
            # 기존 DB 의 계정은 이미 각자 비밀번호를 쓰고 있다고 본다. 소급해서 전원을 잠그면
            # 운영 중인 시스템이 통째로 멈춘다 - 새로 발급되는 계정부터 적용한다.
            conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0"
            )
        rule_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(risk_rules)").fetchall()}
        if rule_cols and "product" not in rule_cols:  # 제품/CPE 기반 조직 규칙
            conn.exec_driver_sql("ALTER TABLE risk_rules ADD COLUMN product VARCHAR(128) DEFAULT ''")
        if rule_cols and "cpe" not in rule_cols:
            conn.exec_driver_sql("ALTER TABLE risk_rules ADD COLUMN cpe VARCHAR(128) DEFAULT ''")
        exec_cols = {r[1] for r in
                     conn.exec_driver_sql("PRAGMA table_info(scan_executions)").fetchall()}
        if exec_cols and "diagnostics_json" not in exec_cols:
            # 소급 backfill 은 하지 않는다 - 옛 행에는 그 값이 애초에 없었다. None 이면
            # 화면이 기본값으로 그리고, 다음 스캔부터 채워진다.
            conn.exec_driver_sql("ALTER TABLE scan_executions ADD COLUMN diagnostics_json JSON")
        issue_cols = {r[1] for r in
                      conn.exec_driver_sql("PRAGMA table_info(scan_quality_issues)").fetchall()}
        for column, ddl in (("proto", "VARCHAR(8) DEFAULT ''"),
                            ("port_spec", "VARCHAR(256) DEFAULT ''")):
            # 서비스 저하가 어느 프로토콜·어느 포트에서 났는지. 옛 행은 그 값이 애초에
            # 없었으므로 소급하지 않는다 - 빈 문자열이면 화면이 그 줄을 그리지 않는다.
            if issue_cols and column not in issue_cols:
                conn.exec_driver_sql(
                    f"ALTER TABLE scan_quality_issues ADD COLUMN {column} {ddl}"
                )
        cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()}
        if "owner" not in cols:  # 자산대장 담당자명 전파용 컬럼
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN owner VARCHAR(128) DEFAULT ''")
        if "reopened" not in cols:  # 재발 태그 컬럼
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN reopened INTEGER DEFAULT 0")
        if cols and "reason" not in cols:  # nmap --reason 근거(syn-ack/no-response…)
            # 소급 backfill 은 불가능하다 — 이 값은 여태 저장한 적이 없다. 기본 '' 는
            # '미관측'이며, 다음 스캔이 관측할 때 채워진다. no-response 로 넘겨짚지 않는다.
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN reason VARCHAR(32) DEFAULT ''")
        if cols and "exposure_json" not in cols:
            # 소급 계산은 nse_json 으로 가능하지만 조용히 등급을 바꾸게 되므로 하지 않는다.
            # 다음 스캔이 채우고, 그때 등급 변화가 이력에 남는다.
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN exposure_json JSON")
        if cols and "allowed" not in cols:
            # 소급 계산은 하지 않는다 - 규칙이 바뀔 때 reclassify_all 이 전부 다시 채운다.
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN allowed INTEGER DEFAULT 0")
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
        for column in ("batch_total", "batch_size"):
            if sc_cols and column not in sc_cols:
                # 소급 계산은 하지 않는다 - 과거 실행의 배치 구성은 어디에도 남아 있지 않다.
                conn.exec_driver_sql(
                    f"ALTER TABLE scan_runs ADD COLUMN {column} INTEGER DEFAULT 0")
        if "stages_json" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN stages_json JSON")
        if "failure_code" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN failure_code VARCHAR(64) DEFAULT ''")
        if "failure_message" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN failure_message VARCHAR(256) DEFAULT ''")
        # 도킹 중복 인입 방지용 원본 지문(기존 DB 보강)
        if "source_fingerprint" not in sc_cols:
            conn.exec_driver_sql("ALTER TABLE scan_runs ADD COLUMN source_fingerprint VARCHAR(64) DEFAULT ''")
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_scan_runs_source_fingerprint "
                "ON scan_runs (source_fingerprint)"
            )


def get_db() -> Iterator[Session]:
    """FastAPI 의존성."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
