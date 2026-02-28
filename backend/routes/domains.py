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

_REGEX_CAPABLE_TYPES = {'pihole'}


async def get_source_servers():
    """Helper to get all enabled source DNS servers from database"""
    async with async_session_maker() as session:
        stmt = select(PiholeServerModel).where(
            PiholeServerModel.is_source == True,
            PiholeServerModel.enabled == True
        ).order_by(PiholeServerModel.display_order)
        result = await session.execute(stmt)
        sources = result.scalars().all()

        if not sources:
            raise HTTPException(status_code=400, detail="No source DNS server configured")

        return sources


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


async def _fetch_domains(fetch_method: str, list_name: str, regex_only: bool = False) -> dict:
    """Fetch and deduplicate domains from all source servers. Prefers enabled=True on conflicts."""
    sources = await get_source_servers()
    seen: dict[str, dict] = {}
    reachable = 0
    for source in sources:
        if regex_only and source.server_type not in _REGEX_CAPABLE_TYPES:
            continue
        try:
            async with create_client_from_server(source) as client:
                if not await client.authenticate():
                    continue
                reachable += 1
                for d in await getattr(client, fetch_method)():
                    key = d.get('domain', '')
                    if not key:
                        continue
                    if key not in seen or (d.get('enabled') and not seen[key].get('enabled')):
                        seen[key] = d
        except Exception as e:
            logger.error(f"Error fetching {list_name} from {source.name}: {e}")
    if reachable == 0:
        raise HTTPException(status_code=502, detail="Failed to reach any source server")
    return {"domains": list(seen.values())}


async def _write_to_servers(
    domain: str,
    method_name: str,
    list_name: str,
    action: str,
    regex_only: bool = False,
) -> dict:
    """Execute a write operation on all enabled servers. Raises 500 if all fail."""
    domain = domain.strip()
    if not domain or len(domain) > 255:
        raise HTTPException(status_code=400, detail="Invalid domain")
    servers = await get_all_enabled_servers()
    results = []
    for server in servers:
        if regex_only and server.server_type not in _REGEX_CAPABLE_TYPES:
            continue
        try:
            async with create_client_from_server(server) as client:
                if not await client.authenticate():
                    results.append({"server": server.name, "success": False, "error": "Auth failed"})
                    continue
                success = await getattr(client, method_name)(domain)
                results.append({"server": server.name, "success": success})
        except Exception as e:
            verb = "adding to" if action == "add" else "removing from"
            logger.error(f"Error {verb} {list_name} on {server.name}: {e}", exc_info=True)
            results.append({"server": server.name, "success": False, "error": f"Failed on {server.name}"})

    successful = sum(1 for r in results if r.get('success'))
    if successful == 0:
        prep = "to" if action == "add" else "from"
        raise HTTPException(status_code=500, detail=f"Failed to {action} domain {prep} {list_name} on any server")

    past = "Added" if action == "add" else "Removed"
    prep = "to" if action == "add" else "from"
    return {
        "message": f"{past} {domain} {prep} {list_name} on {successful}/{len(results)} servers",
        "results": results,
    }


# --- Whitelist ---

@router.get("/whitelist")
async def get_whitelist(_: User = Depends(get_current_user)):
    return await _fetch_domains('get_whitelist', 'whitelist')


@router.post("/whitelist")
async def add_to_whitelist(data: DomainRequest, _: User = Depends(require_admin)):
    return await _write_to_servers(data.domain, 'add_to_whitelist', 'whitelist', 'add')


@router.delete("/whitelist/{domain:path}")
async def remove_from_whitelist(domain: str, _: User = Depends(require_admin)):
    return await _write_to_servers(domain, 'remove_from_whitelist', 'whitelist', 'remove')


# --- Blacklist ---

@router.get("/blacklist")
async def get_blacklist(_: User = Depends(get_current_user)):
    return await _fetch_domains('get_blacklist', 'blacklist')


@router.post("/blacklist")
async def add_to_blacklist(data: DomainRequest, _: User = Depends(require_admin)):
    return await _write_to_servers(data.domain, 'add_to_blacklist', 'blacklist', 'add')


@router.delete("/blacklist/{domain:path}")
async def remove_from_blacklist(domain: str, _: User = Depends(require_admin)):
    return await _write_to_servers(domain, 'remove_from_blacklist', 'blacklist', 'remove')


# --- Regex Whitelist ---

@router.get("/regex-whitelist")
async def get_regex_whitelist(_: User = Depends(get_current_user)):
    return await _fetch_domains('get_regex_whitelist', 'regex whitelist', regex_only=True)


@router.post("/regex-whitelist")
async def add_to_regex_whitelist(data: DomainRequest, _: User = Depends(require_admin)):
    return await _write_to_servers(data.domain, 'add_to_regex_whitelist', 'regex whitelist', 'add', regex_only=True)


@router.delete("/regex-whitelist/{pattern:path}")
async def remove_from_regex_whitelist(pattern: str, _: User = Depends(require_admin)):
    return await _write_to_servers(pattern, 'remove_from_regex_whitelist', 'regex whitelist', 'remove', regex_only=True)


# --- Regex Blacklist ---

@router.get("/regex-blacklist")
async def get_regex_blacklist(_: User = Depends(get_current_user)):
    return await _fetch_domains('get_regex_blacklist', 'regex blacklist', regex_only=True)


@router.post("/regex-blacklist")
async def add_to_regex_blacklist(data: DomainRequest, _: User = Depends(require_admin)):
    return await _write_to_servers(data.domain, 'add_to_regex_blacklist', 'regex blacklist', 'add', regex_only=True)


@router.delete("/regex-blacklist/{pattern:path}")
async def remove_from_regex_blacklist(pattern: str, _: User = Depends(require_admin)):
    return await _write_to_servers(pattern, 'remove_from_regex_blacklist', 'regex blacklist', 'remove', regex_only=True)
