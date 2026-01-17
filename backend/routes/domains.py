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
    """Get combined whitelist entries from all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    all_domains = {}

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    domains = await client.get_whitelist()
                    for d in domains:
                        domain_name = d.get('domain', '')
                        if domain_name and domain_name not in all_domains:
                            all_domains[domain_name] = d
        except Exception as e:
            logger.warning(f"Failed to get whitelist from {server.name}: {e}")

    return {"domains": list(all_domains.values())}


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
            results.append({"server": server.name, "success": False, "error": str(e)})

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
            results.append({"server": server.name, "success": False, "error": str(e)})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        raise HTTPException(status_code=500, detail="Failed to remove domain from whitelist on any server")

    return {"message": f"Removed {domain} from whitelist on {successful}/{len(results)} servers", "results": results}


@router.get("/blacklist")
async def get_blacklist(_: User = Depends(get_current_user)):
    """Get combined blacklist entries from all enabled DNS servers"""
    servers = await get_all_enabled_servers()
    all_domains = {}

    for server in servers:
        try:
            async with create_client_from_server(server) as client:
                if await client.authenticate():
                    domains = await client.get_blacklist()
                    for d in domains:
                        domain_name = d.get('domain', '')
                        if domain_name and domain_name not in all_domains:
                            all_domains[domain_name] = d
        except Exception as e:
            logger.warning(f"Failed to get blacklist from {server.name}: {e}")

    return {"domains": list(all_domains.values())}


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
            results.append({"server": server.name, "success": False, "error": str(e)})

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
            results.append({"server": server.name, "success": False, "error": str(e)})

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


@router.delete("/regex-whitelist/{pattern_id}")
async def remove_from_regex_whitelist(
    pattern_id: int,
    _: User = Depends(require_admin)
):
    """Remove a pattern from regex whitelist on source DNS server (Pi-hole only)"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not client.supports_regex_lists:
            raise HTTPException(status_code=400, detail="Regex lists not supported by this server type")
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        success = await client.remove_from_regex_whitelist(pattern_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove pattern from regex whitelist")
        return {"message": f"Removed pattern {pattern_id} from regex whitelist"}


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


@router.delete("/regex-blacklist/{pattern_id}")
async def remove_from_regex_blacklist(
    pattern_id: int,
    _: User = Depends(require_admin)
):
    """Remove a pattern from regex blacklist on source DNS server (Pi-hole only)"""
    source = await get_source_server()
    async with create_client_from_server(source) as client:
        if not client.supports_regex_lists:
            raise HTTPException(status_code=400, detail="Regex lists not supported by this server type")
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source server")
        success = await client.remove_from_regex_blacklist(pattern_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove pattern from regex blacklist")
        return {"message": f"Removed pattern {pattern_id} from regex blacklist"}
