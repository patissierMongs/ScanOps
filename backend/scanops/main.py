"""FastAPI 앱 — API + 프론트 정적 dist 를 한 포트로 서빙(공용 서버 1대)."""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import get_settings
from .db import init_db
from .uploads import UploadBodyLimitMiddleware

settings = get_settings()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from .scanning.scope import parse_scope

    _app.state.ready = False
    _app.state.readiness_errors = []
    # A malformed non-empty scope must never turn into unrestricted scanning.
    try:
        parse_scope(settings.scan_scope)
    except ValueError:
        logger.exception("invalid scan scope configuration")
        _app.state.readiness_errors.append("invalid scan scope configuration")
    init_db()
    from .seed.bootstrap import run_bootstrap
    try:
        run_bootstrap()
    except Exception:
        # 계정/taxonomy가 준비되지 않은 서버를 정상으로 띄우지 않는다.
        logger.exception("required bootstrap failed")
        raise
    # 재시작으로 고아가 된 실행을 interrupted 로 정직하게 표기(자동 복구 안 함, 좀비 방지).
    try:
        from .api.scans import reconcile_orphans
        reconcile_orphans()
    except Exception as exc:
        logger.exception("scan orphan reconciliation failed")
        _app.state.readiness_errors.append(f"scan reconciliation failed: {type(exc).__name__}")
    _app.state.ready = not _app.state.readiness_errors
    yield


app = FastAPI(title="ScanOps", version=__version__, lifespan=lifespan)
app.add_middleware(UploadBodyLimitMiddleware)


@app.get("/api/health")
def health() -> JSONResponse:
    ready = bool(getattr(app.state, "ready", False))
    errors = list(getattr(app.state, "readiness_errors", []))
    return JSONResponse(
        {"ok": ready, "ready": ready, "service": "scanops", "version": __version__,
         "errors": errors},
        status_code=200 if ready else 503,
    )


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
