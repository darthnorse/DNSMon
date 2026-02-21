"""
Domain management routes - whitelist, blacklist, regex lists
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
import logging

from ..models import User, PiholeServerModel
from ..schemas import DomainRequest
from ..auth import get_current_user, require_admin
from ..database import async_session_maker
from ..utils import create_client_from_server

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/domains", tags=["domains"])


async def get_source_server():
    """Helper to get source DNS server model from database"""
    async with async_session_maker() as session:
        stmt = select(PiholeServerModel).where(
            PiholeServerModel.is_source == True,
            PiholeServerModel.enabled == True
        )
        result = await session.execute(stmt)
        source = result.scalar_one_or_none()

        if not source:
            raise HTTPException(status_code=400, detail="No source DNS server configured")

        return source


async def get_all_enabled_servers():
    """Helper to get all enabled DNS servers"""
    async with async_session_maker() as session:
        stmt = select(PiholeServerModel).where(
            PiholeServerModel.enabled == True
        ).order_by(PiholeServerModel.display_order)
        result = await session.execute(stmt)
        servers = result.scalars().all()

        if not servers:
            raise HTTPException(status_code=400, detail="No DNS servers configured")

        return servers


@router.get("/whitelist")
async def get_whitelist(_: User = Depends(get_current_user)):
    """Get whitelist entries from source DNS server"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        domains = await client.get_whitelist()
        return {"domains": domains}


@router.post("/whitelist")
async def add_to_whitelist(
    data: DomainRequest,
    _: User = Depends(require_admin)
):
    """Add a domain to whitelist on all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    results = []

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    success = await client.add_to_whitelist(data.domain)
                    results.append({"server": server.name, "success": success})
                else:
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
        except Exception as e:
            logger.error(f"Error adding to whitelist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to add domain to whitelist on any server")

    return {"message": f"Added {data.domain} to whitelist on {successful}/{len(results)} servers", "results": results}


@router.delete("/whitelist/{domain:path}")
async def remove_from_whitelist(
    domain: str,
    _: User = Depends(require_admin)
):
    """Remove a domain from whitelist on all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    results = []

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    success = await client.remove_from_whitelist(domain)
                    results.append({"server": server.name, "success": success})
                else:
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
        except Exception as e:
            logger.error(f"Error removing from whitelist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to remove domain from whitelist on any server")

    return {"message": f"Removed {domain} from whitelist on {successful}/{len(results)} servers", "results": results}


@router.get("/blacklist")
async def get_blacklist(_: User = Depends(get_current_user)):
    """Get blacklist entries from source DNS server"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        domains = await client.get_blacklist()
        return {"domains": domains}


@router.post("/blacklist")
async def add_to_blacklist(
    data: DomainRequest,
    _: User = Depends(require_admin)
):
    """Add a domain to blacklist on all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    results = []

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    success = await client.add_to_blacklist(data.domain)
                    results.append({"server": server.name, "success": success})
                else:
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
        except Exception as e:
            logger.error(f"Error adding to blacklist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to add domain to blacklist on any server")

    return {"message": f"Added {data.domain} to blacklist on {successful}/{len(results)} servers", "results": results}


@router.delete("/blacklist/{domain:path}")
async def remove_from_blacklist(
    domain: str,
    _: User = Depends(require_admin)
):
    """Remove a domain from blacklist on all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    results = []

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    success = await client.remove_from_blacklist(domain)
                    results.append({"server": server.name, "success": success})
                else:
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
        except Exception as e:
            logger.error(f"Error removing from blacklist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to remove domain from blacklist on any server")

    return {"message": f"Removed {domain} from blacklist on {successful}/{len(results)} servers", "results": results}


@router.get("/regex-whitelist")
async def get_regex_whitelist(_: User = Depends(get_current_user)):
    """Get all regex whitelist entries from source DNS server (Pi-hole only)"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not client.supports_regex_lists:
            return {"domains": [], "message": "Regex lists not supported by this server type"}
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        domains = await client.get_regex_whitelist()
        return {"domains": domains}


@router.post("/regex-whitelist")
async def add_to_regex_whitelist(
    request: DomainRequest,
    _: User = Depends(require_admin)
):
    """Add a regex pattern to whitelist on all servers"""
    servers = await get_all_enabled_servers()
    if not servers:
        raise HTTPException(status_code=400, detail="No enabled servers configured")

    results = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if not client.supports_regex_lists:
                    results.append({"server": server.name, "success": False, "error": "Regex not supported"})
                    continue
                if not await client.authenticate():
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
                    continue
                success = await client.add_to_regex_whitelist(request.domain)
                results.append({"server": server.name, "success": success})
        except Exception as e:
            logger.error(f"Error adding regex whitelist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get("success"))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to add regex to whitelist on any server")

    return {"message": f"Added regex to whitelist on {successful}/{len(results)} servers", "results": results}


@router.delete("/regex-whitelist/{pattern:path}")
async def remove_from_regex_whitelist(
    pattern: str,
    _: User = Depends(require_admin)
):
    """Remove a pattern from regex whitelist on all servers"""
    servers = await get_all_enabled_servers()
    if not servers:
        raise HTTPException(status_code=400, detail="No enabled servers configured")

    results = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if not client.supports_regex_lists:
                    results.append({"server": server.name, "success": False, "error": "Regex not supported"})
                    continue
                if not await client.authenticate():
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
                    continue
                success = await client.remove_from_regex_whitelist(pattern)
                results.append({"server": server.name, "success": success})
        except Exception as e:
            logger.error(f"Error removing regex whitelist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get("success"))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to remove regex from whitelist on any server")

    return {"message": f"Removed regex from whitelist on {successful}/{len(results)} servers", "results": results}


@router.get("/regex-blacklist")
async def get_regex_blacklist(_: User = Depends(get_current_user)):
    """Get all regex blacklist entries from source DNS server (Pi-hole only)"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not client.supports_regex_lists:
            return {"domains": [], "message": "Regex lists not supported by this server type"}
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        domains = await client.get_regex_blacklist()
        return {"domains": domains}


@router.post("/regex-blacklist")
async def add_to_regex_blacklist(
    request: DomainRequest,
    _: User = Depends(require_admin)
):
    """Add a regex pattern to blacklist on all servers"""
    servers = await get_all_enabled_servers()
    if not servers:
        raise HTTPException(status_code=400, detail="No enabled servers configured")

    results = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if not client.supports_regex_lists:
                    results.append({"server": server.name, "success": False, "error": "Regex not supported"})
                    continue
                if not await client.authenticate():
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
                    continue
                success = await client.add_to_regex_blacklist(request.domain)
                results.append({"server": server.name, "success": success})
        except Exception as e:
            logger.error(f"Error adding regex blacklist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get("success"))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to add regex to blacklist on any server")

    return {"message": f"Added regex to blacklist on {successful}/{len(results)} servers", "results": results}


@router.delete("/regex-blacklist/{pattern:path}")
async def remove_from_regex_blacklist(
    pattern: str,
    _: User = Depends(require_admin)
):
    """Remove a pattern from regex blacklist on all servers"""
    servers = await get_all_enabled_servers()
    if not servers:
        raise HTTPException(status_code=400, detail="No enabled servers configured")

    results = []
    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if not client.supports_regex_lists:
                    results.append({"server": server.name, "success": False, "error": "Regex not supported"})
                    continue
                if not await client.authenticate():
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
                    continue
                success = await client.remove_from_regex_blacklist(pattern)
                results.append({"server": server.name, "success": success})
        except Exception as e:
            logger.error(f"Error removing regex blacklist on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get("success"))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to remove regex from blacklist on any server")

    return {"message": f"Removed regex from blacklist on {successful}/{len(results)} servers", "results": results}
