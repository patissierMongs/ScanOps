"""재시작 시 고아 실행 정리 — running/canceling 을 interrupted 로(자동 복구 안 함)."""
from scanops.api.scans import reconcile_orphans
from scanops.db import SessionLocal
from scanops.models import ScanRun


def _mk(status):
    db = SessionLocal()
    try:
        s = ScanRun(name="t", status=status)
        db.add(s)
        db.commit()
        db.refresh(s)
        return s.id
    finally:
        db.close()


def _status(sid):
    db = SessionLocal()
    try:
        return db.get(ScanRun, sid).status
    finally:
        db.close()


def test_orphans_marked_interrupted(client):
    running = _mk("running")
    canceling = _mk("canceling")
    done = _mk("done")

    n = reconcile_orphans()
    assert n == 2
    assert _status(running) == "interrupted"
    assert _status(canceling) == "interrupted"
    assert _status(done) == "done"   # 완료된 건 안 건드림


def test_reconcile_idempotent(client):
    _mk("running")
    assert reconcile_orphans() == 1
    assert reconcile_orphans() == 0   # 두 번째는 정리할 게 없음
