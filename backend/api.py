"""
DNSMon API - Main FastAPI application
"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os
import logging

from .database import get_db, init_db
from .config import get_settings
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
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="DNSMon", description="DNS Ad-Blocker Monitor - Pi-hole & AdGuard Home")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Include routers
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
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Database unavailable")


# Serve React frontend in production
if os.path.exists("/app/frontend/build"):
    app.mount("/assets", StaticFiles(directory="/app/frontend/build/assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        """Serve React app for all non-API routes with path traversal protection"""
        from pathlib import Path
        from fastapi import HTTPException

        if "." in full_path.split("/")[-1]:
            base_path = Path("/app/frontend/build").resolve()
            requested_path = (base_path / full_path).resolve()

            try:
                requested_path.relative_to(base_path)
            except ValueError:
                raise HTTPException(status_code=404, detail="File not found")

            if requested_path.exists() and requested_path.is_file():
                return FileResponse(str(requested_path))

        return FileResponse("/app/frontend/build/index.html")
