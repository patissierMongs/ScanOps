"""FastAPI 앱 — API + 프론트 정적 dist 를 한 포트로 서빙(공용 서버 1대)."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import get_settings
from .db import init_db

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    # 시드(기본 admin·taxonomy)는 B/D 단계에서 seed 모듈이 채운다.
    try:
        from .seed.bootstrap import run_bootstrap
        run_bootstrap()
    except Exception:
        # 시드 모듈이 아직 없거나 실패해도 앱 부팅은 막지 않는다(개발 단계).
        pass
    # 재시작으로 고아가 된 실행을 interrupted 로 정직하게 표기(자동 복구 안 함, 좀비 방지).
    try:
        from .api.scans import reconcile_orphans
        reconcile_orphans()
    except Exception:
        pass
    yield


app = FastAPI(title="ScanOps", version=__version__, lifespan=lifespan)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "scanops", "version": __version__}


def _mount_routers() -> None:
    """라우터는 생성되는 대로 여기서 등록(아직 일부만)."""
    from .api import assets as assets_api
    from .api import audit as audit_api
    from .api import auth as auth_api
    from .api import dashboard as dashboard_api
    from .api import events as events_api
    from .api import findings as findings_api
    from .api import heatmap as heatmap_api
    from .api import notifications as notify_api
    from .api import reports as reports_api
    from .api import rules as rules_api
    from .api import scans as scans_api
    from .api import users as users_api
    app.include_router(auth_api.router, prefix="/api/auth", tags=["auth"])
    app.include_router(users_api.router, prefix="/api/users", tags=["users"])
    app.include_router(scans_api.router, prefix="/api/scans", tags=["scans"])
    app.include_router(findings_api.router, prefix="/api/findings", tags=["findings"])
    app.include_router(heatmap_api.router, prefix="/api/heatmap", tags=["heatmap"])
    app.include_router(assets_api.router, prefix="/api/assets", tags=["assets"])
    app.include_router(notify_api.router, prefix="/api/notifications", tags=["notifications"])
    app.include_router(dashboard_api.router, prefix="/api/dashboard", tags=["dashboard"])
    app.include_router(reports_api.router, prefix="/api/reports", tags=["reports"])
    app.include_router(rules_api.router, prefix="/api/rules", tags=["rules"])
    app.include_router(events_api.router, prefix="/api/events", tags=["events"])
    app.include_router(audit_api.router, prefix="/api/audit", tags=["audit"])


_mount_routers()


# 프론트 dist 가 있으면 SPA 로 서빙(없으면 API 전용으로 동작).
if settings.frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(settings.frontend_dist), html=True), name="spa")
else:
    @app.get("/")
    def _root() -> JSONResponse:
        return JSONResponse(
            {"ok": True, "msg": "ScanOps API 동작 중. 프론트 dist 미빌드 — /api/health 확인.",
             "docs": "/docs"}
        )
