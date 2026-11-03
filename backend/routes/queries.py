"""
Query search routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query as QueryParam
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Literal, Optional, List
from datetime import datetime, timedelta

from ..database import get_db
from ..models import Query, User, DomainLabel
from ..schemas import QueryContextResponse, QueryResponse
from ..auth import get_current_user
from ..utils import ensure_utc, split_csv
from .stats import _parse_iso_date


def escape_sql_like(value: str) -> str:
    """Escape SQL LIKE wildcards to prevent unintended pattern matching"""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


router = APIRouter(prefix="/api", tags=["queries"])

# Per side of the anchor, so a busy window trims both directions evenly and the
# lookups right next to the anchor are always kept.
CONTEXT_SIDE_LIMIT = 500
CONTEXT_WINDOWS = (1, 2, 5, 15)


def _labelled_queries():
    return select(Query, DomainLabel.app_name, DomainLabel.category,
                  DomainLabel.threat_type).outerjoin(DomainLabel, Query.domain == DomainLabel.domain)


def _to_response(row) -> QueryResponse:
    q, app_name, category, threat_type = row
    return QueryResponse(
        id=q.id,
        timestamp=ensure_utc(q.timestamp),
        domain=q.domain,
        client_ip=q.client_ip,
        client_hostname=q.client_hostname,
        query_type=q.query_type,
        status=q.status,
        server=q.server,
        app_name=app_name,
        category=category,
        threat_type=threat_type,
    )


@router.get("/queries", response_model=List[QueryResponse])
async def search_queries(
    search: Optional[str] = QueryParam(None, max_length=255),
    domain: Optional[str] = QueryParam(None, max_length=255),
    client_ip: Optional[str] = QueryParam(None, max_length=45),
    client_hostname: Optional[str] = QueryParam(None, max_length=255),
    server: Optional[str] = QueryParam(None, max_length=100),
    servers: Optional[str] = QueryParam(None, max_length=1000),
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
    - server: substring match; servers: comma-separated exact names, as /api/statistics takes them
    """
    stmt = _labelled_queries()
    conditions = []

    if search:
        escaped_search = escape_sql_like(search)
        search_pattern = f"%{escaped_search}%"
        conditions.append(or_(
            Query.domain.ilike(search_pattern, escape='\\'),
            Query.client_ip.ilike(search_pattern, escape='\\'),
            Query.client_hostname.ilike(search_pattern, escape='\\')
        ))

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

    server_list = split_csv(servers)
    if server_list:
        conditions.append(Query.server.in_(server_list))

    from_dt = None
    to_dt = None

    if from_date:
        from_dt = _parse_iso_date(from_date, "from_date")
        conditions.append(Query.timestamp >= from_dt)

    if to_date:
        to_dt = _parse_iso_date(to_date, "to_date")
        conditions.append(Query.timestamp <= to_dt)

    if from_dt and to_dt and from_dt > to_dt:
        raise HTTPException(status_code=400, detail="from_date must be before or equal to to_date")

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.order_by(Query.timestamp.desc())
    stmt = stmt.limit(limit).offset(offset)

    result = await db.execute(stmt)
    return [_to_response(row) for row in result.all()]


@router.get("/queries/context", response_model=QueryContextResponse)
async def query_context(
    query_id: Optional[int] = QueryParam(None, ge=1, le=2**63 - 1),
    client_ip: Optional[str] = QueryParam(None, max_length=45),
    at: Optional[str] = QueryParam(None, max_length=64),
    domain: Optional[str] = QueryParam(None, max_length=255),
    window: int = 5,
    scope: Literal['device', 'all'] = 'device',
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """
    Lookups within ±window minutes of an anchor, oldest first on each side.
    - query_id: anchor on that query (its client and time).
    - client_ip + at (+ domain): anchor on that client's lookup nearest `at` (matching `domain`
      when given); with none in the window, centre on `at` with no anchor. This is the form
      external dashboards use, since they know an IP and a time but not a query id.
    - scope: 'device' limits both sides to the anchor's client; 'all' includes every client.
    """
    if window not in CONTEXT_WINDOWS:
        raise HTTPException(status_code=422, detail=f"window must be one of {', '.join(map(str, CONTEXT_WINDOWS))}")
    span = timedelta(minutes=window)
    anchor_row = None

    def window_bounds(moment: datetime) -> tuple[datetime, datetime]:
        try:
            return moment - span, moment + span
        except OverflowError:
            raise HTTPException(status_code=400, detail="at is outside the supported date range")

    if query_id is not None:
        anchor_row = (await db.execute(_labelled_queries().where(Query.id == query_id))).first()
        if anchor_row is None:
            raise HTTPException(status_code=404, detail="Query not found")
        center = anchor_row[0].timestamp
        client_ip = anchor_row[0].client_ip
    elif client_ip and at:
        center = _parse_iso_date(at, "at")
        lo, hi = window_bounds(center)
        nearest = _labelled_queries().where(
            Query.client_ip == client_ip,
            Query.timestamp.between(lo, hi),
        )
        if domain:
            nearest = nearest.where(func.lower(Query.domain) == domain.strip().lower())
        distance = func.abs(func.extract('epoch', Query.timestamp - center))
        anchor_row = (await db.execute(nearest.order_by(distance, Query.id).limit(1))).first()
        if anchor_row is not None:
            center = anchor_row[0].timestamp
    else:
        raise HTTPException(status_code=400, detail="Provide query_id, or client_ip and at")

    lo, hi = window_bounds(center)
    scope_conditions = [Query.client_ip == client_ip] if scope == 'device' else []
    if anchor_row is not None:
        anchor_id = anchor_row[0].id
        is_before = or_(Query.timestamp < center, and_(Query.timestamp == center, Query.id < anchor_id))
        is_after = or_(Query.timestamp > center, and_(Query.timestamp == center, Query.id > anchor_id))
    else:
        is_before = Query.timestamp < center
        is_after = Query.timestamp >= center

    before_rows = (await db.execute(
        _labelled_queries()
        .where(*scope_conditions, is_before, Query.timestamp >= lo)
        .order_by(Query.timestamp.desc(), Query.id.desc())
        .limit(CONTEXT_SIDE_LIMIT + 1)
    )).all()
    after_rows = (await db.execute(
        _labelled_queries()
        .where(*scope_conditions, is_after, Query.timestamp <= hi)
        .order_by(Query.timestamp.asc(), Query.id.asc())
        .limit(CONTEXT_SIDE_LIMIT + 1)
    )).all()

    return QueryContextResponse(
        anchor=_to_response(anchor_row) if anchor_row is not None else None,
        center=ensure_utc(center),
        client_ip=client_ip,
        scope=scope,
        window=window,
        before=[_to_response(row) for row in reversed(before_rows[:CONTEXT_SIDE_LIMIT])],
        after=[_to_response(row) for row in after_rows[:CONTEXT_SIDE_LIMIT]],
        truncated_before=len(before_rows) > CONTEXT_SIDE_LIMIT,
        truncated_after=len(after_rows) > CONTEXT_SIDE_LIMIT,
    )


@router.get("/queries/count")
async def count_queries(
    domain: Optional[str] = None,
    client_ip: Optional[str] = None,
    client_hostname: Optional[str] = None,
    server: Optional[str] = None,
    servers: Optional[str] = QueryParam(None, max_length=1000),
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
    server_list = split_csv(servers)
    if server_list:
        conditions.append(Query.server.in_(server_list))

    from_dt = None
    to_dt = None

    if from_date:
        from_dt = _parse_iso_date(from_date, "from_date")
        conditions.append(Query.timestamp >= from_dt)

    if to_date:
        to_dt = _parse_iso_date(to_date, "to_date")
        conditions.append(Query.timestamp <= to_dt)

    if from_dt and to_dt and from_dt > to_dt:
        raise HTTPException(status_code=400, detail="from_date must be before or equal to to_date")

    if conditions:
        stmt = stmt.where(and_(*conditions))

    result = await db.execute(stmt)
    count = result.scalar()

    return {"count": count}
