"""
Settings routes - app settings, Pi-hole servers, restart
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime, timezone
import os
import asyncio
import signal
import json
import logging

from ..database import get_db
from ..models import User, AppSetting, PiholeServerModel, SettingsChangelog
from ..schemas import (
    AppSettingUpdate, PiholeServerCreate, PiholeServerUpdate, SettingsResponse
)
from ..auth import get_current_user, require_admin
from ..config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

# Rate limiting for restart endpoint
_last_restart_time: Optional[float] = None
_restart_cooldown_seconds = 30


@router.get("", response_model=SettingsResponse)
async def get_all_settings(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get all application settings and Pi-hole servers"""
    stmt = select(AppSetting)
    result = await db.execute(stmt)
    app_settings = {row.key: row.to_dict() for row in result.scalars()}

    stmt = select(PiholeServerModel).order_by(PiholeServerModel.display_order, PiholeServerModel.id)
    result = await db.execute(stmt)
    servers = [server.to_dict() for server in result.scalars()]

    return SettingsResponse(
        app_settings=app_settings,
        servers=servers
    )


@router.put("/{key}")
async def update_app_setting(
    key: str,
    update: AppSettingUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Update a single app setting"""
    stmt = select(AppSetting).where(AppSetting.key == key)
    result = await db.execute(stmt)
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")

    try:
        if setting.value_type == 'int':
            int(update.value)
        elif setting.value_type == 'json':
            json.loads(update.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid value for type {setting.value_type}: {e}")

    old_value = setting.value
    changelog = SettingsChangelog(
        setting_key=key,
        old_value=old_value,
        new_value=update.value,
        change_type='app_setting',
        requires_restart=setting.requires_restart
    )
    db.add(changelog)

    setting.value = update.value
    setting.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(setting)

    await get_settings(force_reload=True)

    return {
        "message": "Setting updated successfully",
        "setting": setting.to_dict(),
        "requires_restart": setting.requires_restart
    }



@router.get("/pihole-servers")
async def get_servers(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get all Pi-hole servers"""
    stmt = select(PiholeServerModel).order_by(PiholeServerModel.display_order, PiholeServerModel.id)
    result = await db.execute(stmt)
    servers = [server.to_dict() for server in result.scalars()]

    return {"servers": servers}


@router.post("/pihole-servers")
async def create_server(
    server_data: PiholeServerCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Create a new Pi-hole server"""
    stmt = select(PiholeServerModel).where(PiholeServerModel.name == server_data.name)
    existing = await db.execute(stmt)
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Server with this name already exists")

    stmt = (
        select(PiholeServerModel.display_order)
        .order_by(PiholeServerModel.display_order.desc())
        .limit(1)
        .with_for_update()
    )
    result = await db.execute(stmt)
    last_server = result.scalar_one_or_none()
    max_order = last_server if last_server is not None else 0

    # If setting as source, unset existing source of the SAME server type
    # This allows one source per server type (e.g., one Pi-hole source + one AdGuard source)
    server_type = server_data.server_type or 'pihole'
    if server_data.is_source:
        stmt = (
            select(PiholeServerModel)
            .where(
                PiholeServerModel.is_source == True,
                PiholeServerModel.server_type == server_type
            )
            .with_for_update()
        )
        result = await db.execute(stmt)
        for existing_source in result.scalars():
            existing_source.is_source = False

    server = PiholeServerModel(
        name=server_data.name,
        url=server_data.url,
        password=server_data.password,
        username=server_data.username,
        server_type=server_data.server_type,
        skip_ssl_verify=server_data.skip_ssl_verify,
        enabled=server_data.enabled,
        is_source=server_data.is_source,
        sync_enabled=server_data.sync_enabled,
        display_order=max_order + 1
    )
    db.add(server)

    changelog = SettingsChangelog(
        setting_key=f"server.{server_data.name}",
        new_value=server_data.url,
        change_type='server',
        requires_restart=False
    )
    db.add(changelog)

    await db.commit()
    await db.refresh(server)

    await get_settings(force_reload=True)

    return {"message": "Server created", "server": server.to_dict()}


@router.put("/pihole-servers/{server_id}")
async def update_server(
    server_id: int,
    server_data: PiholeServerUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Update Pi-hole server"""
    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    update_data = server_data.model_dump(exclude_unset=True)

    # Don't update password if empty or masked
    if 'password' in update_data and (not update_data['password'] or update_data['password'] == '********'):
        del update_data['password']

    # If setting as source, unset existing source of the SAME server type
    # This allows one source per server type (e.g., one Pi-hole source + one AdGuard source)
    if update_data.get('is_source'):
        # Use the new server_type if being updated, otherwise use existing
        target_type = update_data.get('server_type', server.server_type) or 'pihole'
        stmt = (
            select(PiholeServerModel)
            .where(
                PiholeServerModel.is_source == True,
                PiholeServerModel.id != server_id,
                PiholeServerModel.server_type == target_type
            )
            .with_for_update()
        )
        result = await db.execute(stmt)
        for existing_source in result.scalars():
            existing_source.is_source = False

    for key, value in update_data.items():
        setattr(server, key, value)

    server.updated_at = datetime.now(timezone.utc)

    changelog = SettingsChangelog(
        setting_key=f"server.{server.name}",
        change_type='server',
        requires_restart=False
    )
    db.add(changelog)

    await db.commit()
    await db.refresh(server)

    await get_settings(force_reload=True)

    return {"message": "Server updated", "server": server.to_dict()}


@router.delete("/pihole-servers/{server_id}")
async def delete_server(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Delete Pi-hole server"""
    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    server_name = server.name

    changelog = SettingsChangelog(
        setting_key=f"server.{server_name}",
        old_value=server.url,
        change_type='server',
        requires_restart=False
    )
    db.add(changelog)

    await db.delete(server)
    await db.commit()

    await get_settings(force_reload=True)

    return {"message": "Server deleted"}


@router.post("/pihole-servers/test")
async def test_pihole_connection(
    server_data: PiholeServerCreate,
    _: User = Depends(require_admin)
):
    """Test connection to a DNS ad-blocker server (Pi-hole or AdGuard Home)"""
    from ..dns_client_factory import create_dns_client

    server_type = server_data.server_type or 'pihole'
    server_type_display = "AdGuard Home" if server_type == 'adguard' else "Pi-hole"

    try:
        client = create_dns_client(
            server_type=server_type,
            url=server_data.url,
            password=server_data.password,
            server_name=server_data.name,
            username=server_data.username,
            skip_ssl_verify=server_data.skip_ssl_verify
        )
        async with client:
            auth_success = await client.authenticate()
            if auth_success:
                return {
                    "success": True,
                    "message": f"Successfully connected to {server_type_display} at {server_data.url}"
                }
            else:
                return {
                    "success": False,
                    "message": "Authentication failed. Please check your credentials."
                }
    except Exception as e:
        logger.error(f"{server_type_display} connection test failed for {server_data.url}: {e}", exc_info=True)

        error_msg = str(e).lower()
        if "authentication" in error_msg or "401" in error_msg:
            return {
                "success": False,
                "message": "Authentication failed. Please check your password."
            }
        elif "connect" in error_msg or "refused" in error_msg or "timeout" in error_msg:
            return {
                "success": False,
                "message": "Cannot connect to the server. Please check the URL and network connectivity."
            }
        else:
            return {
                "success": False,
                "message": "Connection test failed. Please check your configuration and try again."
            }


@router.post("/restart")
async def trigger_restart(_: User = Depends(require_admin)):
    """Trigger container restart with rate limiting to prevent DoS"""
    import time

    global _last_restart_time

    current_time = time.time()
    if _last_restart_time and (current_time - _last_restart_time) < _restart_cooldown_seconds:
        remaining = int(_restart_cooldown_seconds - (current_time - _last_restart_time))
        raise HTTPException(
            status_code=429,
            detail=f"Restart rate limited. Please wait {remaining} seconds before restarting again."
        )

    _last_restart_time = current_time
    logger.info("Restart requested via API - sending SIGTERM to self")

    async def delayed_restart():
        await asyncio.sleep(1)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(delayed_restart())

    return {
        "message": "Container restart initiated",
        "note": "Application will restart in 1 second"
    }
