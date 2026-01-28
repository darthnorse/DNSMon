"""
Query search routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query as QueryParam
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
from datetime import datetime

from ..database import get_db
from ..models import Query, User
from ..schemas import QueryResponse
from ..auth import get_current_user
from ..utils import ensure_utc


def escape_sql_like(value: str) -> str:
    """Escape SQL LIKE wildcards to prevent unintended pattern matching"""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


router = APIRouter(prefix="/api", tags=["queries"])


@router.get("/queries", response_model=List[QueryResponse])
async def search_queries(
    search: Optional[str] = QueryParam(None, max_length=255),
    domain: Optional[str] = QueryParam(None, max_length=255),
    client_ip: Optional[str] = QueryParam(None, max_length=45),
    client_hostname: Optional[str] = QueryParam(None, max_length=255),
    server: Optional[str] = QueryParam(None, max_length=100),
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = QueryParam(100, le=1000, ge=1),
    offset: int = QueryParam(0, ge=0, le=1000000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """
    Search DNS queries with flexible filtering.
    - search: searches across domain, client_ip, and client_hostname (OR)
    - domain/client_ip/client_hostname: specific field filters (AND)
    """
    stmt = select(Query)
    conditions = []

    # General search across multiple fields (OR)
    if search:
        escaped_search = escape_sql_like(search)
        search_pattern = f"%{escaped_search}%"
        conditions.append(or_(
            Query.domain.ilike(search_pattern, escape='\\'),
            Query.client_ip.ilike(search_pattern, escape='\\'),
            Query.client_hostname.ilike(search_pattern, escape='\\')
        ))

    # Specific field filters (AND)
    if domain:
        escaped_domain = escape_sql_like(domain)
        conditions.append(Query.domain.ilike(f"%{escaped_domain}%", escape='\\'))

    if client_ip:
        conditions.append(Query.client_ip == client_ip)

    if client_hostname:
        escaped_hostname = escape_sql_like(client_hostname)
        conditions.append(Query.client_hostname.ilike(f"%{escaped_hostname}%", escape='\\'))

    if server:
        escaped_server = escape_sql_like(server)
        conditions.append(Query.server.ilike(f"%{escaped_server}%", escape='\\'))

    from_dt = None
    to_dt = None

    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            conditions.append(Query.timestamp >= from_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format")

    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            conditions.append(Query.timestamp <= to_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format")

    if from_dt and to_dt and from_dt > to_dt:
        raise HTTPException(status_code=400, detail="from_date must be before or equal to to_date")

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.order_by(Query.timestamp.desc())
    stmt = stmt.limit(limit).offset(offset)

    result = await db.execute(stmt)
    queries = result.scalars().all()

    return [QueryResponse(
        id=q.id,
        timestamp=ensure_utc(q.timestamp),
        domain=q.domain,
        client_ip=q.client_ip,
        client_hostname=q.client_hostname,
        query_type=q.query_type,
        status=q.status,
        server=q.server
    ) for q in queries]


@router.get("/queries/count")
async def count_queries(
    domain: Optional[str] = None,
    client_ip: Optional[str] = None,
    client_hostname: Optional[str] = None,
    server: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get count of queries matching search criteria"""
    stmt = select(func.count(Query.id))
    conditions = []

    if domain:
        escaped_domain = escape_sql_like(domain)
        conditions.append(Query.domain.ilike(f"%{escaped_domain}%", escape='\\'))
    if client_ip:
        conditions.append(Query.client_ip == client_ip)
    if client_hostname:
        escaped_hostname = escape_sql_like(client_hostname)
        conditions.append(Query.client_hostname.ilike(f"%{escaped_hostname}%", escape='\\'))
    if server:
        escaped_server = escape_sql_like(server)
        conditions.append(Query.server.ilike(f"%{escaped_server}%", escape='\\'))

    from_dt = None
    to_dt = None

    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            conditions.append(Query.timestamp >= from_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format")

    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            conditions.append(Query.timestamp <= to_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format")

    if from_dt and to_dt and from_dt > to_dt:
        raise HTTPException(status_code=400, detail="from_date must be before or equal to to_date")

    if conditions:
        stmt = stmt.where(and_(*conditions))

    result = await db.execute(stmt)
    count = result.scalar()

    return {"count": count}
