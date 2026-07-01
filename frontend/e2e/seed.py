"""E2E 시드 — 알려진 admin 계정 + 샘플 발견(픽스처 XML)으로 DB 를 채운다.

Playwright webServer(serve.sh)가 uvicorn 을 띄우기 전에 1회 실행한다. serve.sh 가 export 한
SCANOPS_DATA_DIR 을 uvicorn 과 공유하므로, 여기서 만든 계정/발견을 그대로 서버가 서빙한다.
운영 부트스트랩(랜덤 admin 비밀번호)과 달리 E2E 는 고정 비밀번호가 필요해서 계정을 직접 만든다.
"""
from __future__ import annotations

import os
from pathlib import Path

# scanops 를 import 하기 전에 데이터 경로가 잡혀 있어야 한다. serve.sh 가 export 하지만
# 단독 실행(디버그) 대비 기본값도 둔다.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
os.environ.setdefault("SCANOPS_DATA_DIR", str(_BACKEND / ".e2e-data"))

from scanops.db import SessionLocal, init_db  # noqa: E402
from scanops.models import ScanRun, User  # noqa: E402
from scanops.scanning import taxonomy  # noqa: E402
from scanops.scanning.ingest import ingest  # noqa: E402
from scanops.scanning.nmap_parse import parse_xml, up_hosts  # noqa: E402
from scanops.security import hash_password  # noqa: E402

USERNAME = "admin"
PASSWORD = os.environ.get("SCANOPS_E2E_PASSWORD", "scanops-e2e")
FIXTURE = _BACKEND / "tests" / "fixtures" / "sample_scan.xml"


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        taxonomy.seed_categories(db)  # 위험도 enrich 가 참조하는 분류 시드
        if not db.query(User).filter(User.username == USERNAME).first():
            db.add(User(username=USERNAME, password_hash=hash_password(PASSWORD),
                        role="admin", display_name="E2E 관리자"))
            db.commit()
        if db.query(ScanRun).count() == 0:
            xml = FIXTURE.read_bytes()
            scan = ScanRun(name="E2E 시드 스캔", status="done")
            db.add(scan)
            db.commit()
            findings = taxonomy.enrich_all(db, parse_xml(xml))
            counts = ingest(db, scan.id, findings, up_hosts(xml))
            db.commit()
            print(f"[e2e-seed] findings: {counts}")
    finally:
        db.close()
    print(f"[e2e-seed] ready — user={USERNAME}")


if __name__ == "__main__":
    main()
