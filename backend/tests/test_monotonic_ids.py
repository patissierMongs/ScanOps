import sqlite3

from scanops.db import SessionLocal, get_engine, init_db
from scanops.models import ScanRun


def test_scan_ids_are_not_reused_after_deleting_the_newest_scan(client):
    db = SessionLocal()
    try:
        first = ScanRun(name="first", targets="10.0.0.1", status="done")
        second = ScanRun(name="second", targets="10.0.0.2", status="done")
        db.add_all([first, second])
        db.commit()
        deleted_id = second.id
        db.delete(second)
        db.commit()
        third = ScanRun(name="third", targets="10.0.0.3", status="done")
        db.add(third)
        db.commit()
        assert third.id > deleted_id
    finally:
        db.close()


def test_legacy_tables_are_rebuilt_with_autoincrement_and_keep_rows_and_sequence():
    engine = get_engine()
    with engine.begin() as conn:
        for table in ("finding_events", "findings", "scan_runs"):
            conn.exec_driver_sql(f"DROP TABLE IF EXISTS {table}")
        conn.exec_driver_sql(
            "CREATE TABLE scan_runs (id INTEGER NOT NULL, name VARCHAR(128) NOT NULL, "
            "targets TEXT NOT NULL, status VARCHAR(16) NOT NULL, PRIMARY KEY (id))"
        )
        conn.exec_driver_sql(
            "INSERT INTO scan_runs (id, name, targets, status) VALUES "
            "(1, 'a', '10.0.0.1', 'done'), (7, 'g', '10.0.0.7', 'done')"
        )

    init_db()

    raw = sqlite3.connect(str(engine.url.database))
    try:
        sql = raw.execute(
            "SELECT sql FROM sqlite_master WHERE name='scan_runs'").fetchone()[0]
        assert "AUTOINCREMENT" in sql.upper()
        assert raw.execute("SELECT id, name FROM scan_runs ORDER BY id").fetchall() == [
            (1, "a"), (7, "g")]
        assert raw.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='scan_runs'").fetchone()[0] == 7
        raw.execute("DELETE FROM scan_runs WHERE id=7")
        raw.commit()
    finally:
        raw.close()
    db = SessionLocal()
    try:
        added = ScanRun(name="h", targets="10.0.0.8", status="done")
        db.add(added)
        db.commit()
        assert added.id == 8
    finally:
        db.close()
    init_db()
