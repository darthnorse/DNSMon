"""
Blocking control routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import logging

from ..database import get_db
from ..models import User, PiholeServerModel, BlockingOverride
from ..schemas import BlockingSetRequest
from ..auth import get_current_user, require_admin
from ..utils import create_client_from_server

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/blocking", tags=["blocking"])


@router.get("/status")
async def get_blocking_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get blocking status for all enabled DNS servers"""
    stmt = select(PiholeServerModel).where(
        PiholeServerModel.enabled == True
    ).order_by(PiholeServerModel.display_order)
    result = await db.execute(stmt)
    servers = result.scalars().all()

    if not servers:
        return {"servers": []}

    override_stmt = select(BlockingOverride).where(
        BlockingOverride.enabled_at.is_(None)
    )
    override_result = await db.execute(override_stmt)
    overrides = {o.server_id: o for o in override_result.scalars()}

    statuses = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    blocking = await client.get_blocking_status()
                    override = overrides.get(server.id)
                    statuses.append({
                        "id": server.id,
                        "name": server.name,
                        "blocking": blocking,
                        "auto_enable_at": override.auto_enable_at.isoformat() if override and override.auto_enable_at else None
                    })
                else:
                    statuses.append({
                        "id": server.id,
                        "name": server.name,
                        "blocking": None,
                        "auto_enable_at": None,
                        "error": "Authentication failed"
                    })
        except Exception as e:
            logger.error(f"Error getting blocking status from {server.name}: {e}", exc_info=True)
            statuses.append({
                "id": server.id,
                "name": server.name,
                "blocking": None,
                "auto_enable_at": None,
                "error": f"Failed to get blocking status from {server.name}"
            })

    return {"servers": statuses}


@router.post("/all")
async def set_blocking_for_all(
    data: BlockingSetRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Enable or disable blocking for all enabled DNS servers"""
    stmt = select(PiholeServerModel).where(
        PiholeServerModel.enabled == True
    ).order_by(PiholeServerModel.display_order)
    result = await db.execute(stmt)
    servers = result.scalars().all()

    if not servers:
        return {"success": True, "results": []}

    timer_seconds = data.duration_minutes * 60 if data.duration_minutes and not data.enabled else None
    auto_enable_at = None
    if data.duration_minutes and not data.enabled:
        auto_enable_at = datetime.now(timezone.utc) + timedelta(minutes=data.duration_minutes)

    results = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if not await client.authenticate():
                    results.append({
                        "server_id": server.id,
                        "name": server.name,
                        "success": False,
                        "error": "Authentication failed"
                    })
                    continue

                success = await client.set_blocking(data.enabled, timer_seconds)

                if success:
                    if not data.enabled:
                        existing_stmt = select(BlockingOverride).where(
                            BlockingOverride.server_id == server.id,
                            BlockingOverride.enabled_at.is_(None)
                        )
                        existing_result = await db.execute(existing_stmt)
                        for existing in existing_result.scalars():
                            existing.enabled_at = datetime.now(timezone.utc)

                        override = BlockingOverride(
                            server_id=server.id,
                            auto_enable_at=auto_enable_at,
                            disabled_by='user'
                        )
                        db.add(override)
                    else:
                        existing_stmt = select(BlockingOverride).where(
                            BlockingOverride.server_id == server.id,
                            BlockingOverride.enabled_at.is_(None)
                        )
                        existing_result = await db.execute(existing_stmt)
                        for existing in existing_result.scalars():
                            existing.enabled_at = datetime.now(timezone.utc)

                results.append({
                    "server_id": server.id,
                    "name": server.name,
                    "success": success,
                    "blocking": data.enabled if success else None
                })

        except Exception as e:
            logger.error(f"Error setting blocking for {server.name}: {e}", exc_info=True)
            results.append({
                "server_id": server.id,
                "name": server.name,
                "success": False,
                "error": f"Failed to set blocking on {server.name}"
            })

    await db.commit()

    return {
        "success": all(r["success"] for r in results),
        "results": results,
        "auto_enable_at": auto_enable_at.isoformat() if auto_enable_at else None
    }


@router.post("/{server_id}")
async def set_blocking_for_server(
    server_id: int,
    data: BlockingSetRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Enable or disable blocking for a specific DNS server"""
    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    if not server.enabled:
        raise HTTPException(status_code=400, detail="Server is disabled")

    timer_seconds = data.duration_minutes * 60 if data.duration_minutes and not data.enabled else None

    try:
        async with create_client_from_server(server) as client:
            if not await client.authenticate():
                raise HTTPException(status_code=500, detail=f"Failed to authenticate with {server.name}")

            success = await client.set_blocking(data.enabled, timer_seconds)
            if not success:
                raise HTTPException(status_code=500, detail=f"Failed to set blocking on {server.name}")

            if not data.enabled:
                existing_stmt = select(BlockingOverride).where(
                    BlockingOverride.server_id == server_id,
                    BlockingOverride.enabled_at.is_(None)
                )
                existing_result = await db.execute(existing_stmt)
                for existing in existing_result.scalars():
                    existing.enabled_at = datetime.now(timezone.utc)

                auto_enable_at = None
                if data.duration_minutes:
                    auto_enable_at = datetime.now(timezone.utc) + timedelta(minutes=data.duration_minutes)

                override = BlockingOverride(
                    server_id=server_id,
                    auto_enable_at=auto_enable_at,
                    disabled_by='user'
                )
                db.add(override)
                await db.commit()

                return {
                    "success": True,
                    "server_id": server_id,
                    "blocking": False,
                    "auto_enable_at": auto_enable_at.isoformat() if auto_enable_at else None
                }
            else:
                existing_stmt = select(BlockingOverride).where(
                    BlockingOverride.server_id == server_id,
                    BlockingOverride.enabled_at.is_(None)
                )
                existing_result = await db.execute(existing_stmt)
                for existing in existing_result.scalars():
                    existing.enabled_at = datetime.now(timezone.utc)
                await db.commit()

                return {
                    "success": True,
                    "server_id": server_id,
                    "blocking": True,
                    "auto_enable_at": None
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting blocking for {server.name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to set blocking on server {server.name}")
