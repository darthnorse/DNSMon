"""
DNSMon API - Main FastAPI application
"""
import os
import logging
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_db, init_db
from .config import get_settings, get_settings_sync
from .service import get_service
from .routes import (
    auth_router,
    users_router,
    oidc_providers_router,
    queries_router,
    stats_router,
    alerts_router,
    settings_router,
    sync_router,
    domains_router,
    blocking_router,
    notifications_router,
    api_keys_router,
)

logger = logging.getLogger(__name__)


class DynamicCORSMiddleware:
    """CORS middleware that loads allowed origins from the database.

    Rebuilds the inner CORSMiddleware whenever the configured origins change
    (e.g. after an admin updates cors_origins via the Settings page).
    Uses get_settings_sync() which reads the in-memory singleton — no DB hit
    per request. Before settings are loaded (during startup), requests pass
    through without CORS headers and retry on the next request.
    """

    def __init__(self, app: ASGIApp):
        self.app = app
        self._inner: ASGIApp | None = None
        self._current_origins: list[str] | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            settings = get_settings_sync()
            origins = settings.cors_origins
        except RuntimeError:
            # Settings not loaded yet (startup still in progress) — pass through
            await self.app(scope, receive, send)
            return

        if origins != self._current_origins:
            self._inner = CORSMiddleware(
                app=self.app,
                allow_origins=origins,
                allow_credentials=True,
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_headers=["Content-Type", "Authorization"],
            )
            self._current_origins = origins
            logger.info(f"CORS origins configured: {origins}")

        inner = self._inner
        if inner is None:
            await self.app(scope, receive, send)
            return
        await inner(scope, receive, send)


app = FastAPI(title="DNSMon", description="DNS Ad-Blocker Monitor - Pi-hole & AdGuard Home")

app.add_middleware(DynamicCORSMiddleware)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(oidc_providers_router)
app.include_router(queries_router)
app.include_router(stats_router)
app.include_router(alerts_router)
app.include_router(settings_router)
app.include_router(sync_router)
app.include_router(domains_router)
app.include_router(blocking_router)
app.include_router(notifications_router)
app.include_router(api_keys_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and services on startup"""
    logger.info("Initializing database...")
    await init_db()

    logger.info("Loading settings from database...")
    settings = await get_settings()
    logger.info(f"Settings loaded: poll_interval={settings.poll_interval_seconds}s")

    logger.info("Starting background services...")
    service = get_service()
    await service.startup()
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown services"""
    service = get_service()
    await service.shutdown()


@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint with database connectivity verification"""
    try:
        await db.execute(select(1))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail="Database unavailable")


if os.path.exists("/app/frontend/build"):
    app.mount("/assets", StaticFiles(directory="/app/frontend/build/assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        """Serve React app for all non-API routes with path traversal protection"""
        if "." in full_path.split("/")[-1]:
            base_path = Path("/app/frontend/build").resolve()
            requested_path = (base_path / full_path).resolve()

            try:
                requested_path.relative_to(base_path)
            except ValueError:
                raise HTTPException(status_code=404, detail="File not found")

            if requested_path.exists() and requested_path.is_file():
                return FileResponse(str(requested_path))

        return FileResponse("/app/frontend/build/index.html", headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
