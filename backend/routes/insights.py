from typing import Optional, List

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, DomainLabel, DomainStatsHourly, Query
from ..schemas import AppUsage, CategoryUsage, DomainUsage
from ..auth import get_current_user
from ..constants import BLOCKED_STATUSES, UNCATEGORIZED_LABEL
from .stats import _resolve_period

router = APIRouter(prefix="/api/insights", tags=["insights"])


def _server_list(servers: Optional[str]) -> list[str]:
    return [s.strip() for s in servers.split(',') if s.strip()] if servers else []


@router.get("/apps", response_model=List[AppUsage])
async def get_app_usage(
    period: str = "24h", servers: Optional[str] = None, clients: Optional[str] = None,
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    """Top apps by query volume. Uses the domain_stats_hourly rollup, or raw
    queries when a client filter is supplied (the rollup lacks client_ip)."""
    start, end = _resolve_period(period, from_date, to_date)
    server_list = _server_list(servers)
    client_list = _server_list(clients)

    if client_list:
        stmt = (
            select(DomainLabel.app_name, func.max(DomainLabel.category).label('category'),
                   func.count(Query.id).label('total'),
                   func.count(Query.id).filter(Query.status.in_(BLOCKED_STATUSES)).label('blocked'))
            .join(DomainLabel, DomainLabel.domain == Query.domain)
            .where(Query.timestamp >= start, DomainLabel.app_name.isnot(None))
            .group_by(DomainLabel.app_name).order_by(func.count(Query.id).desc()).limit(50)
        )
        if end:
            stmt = stmt.where(Query.timestamp <= end)
        if server_list:
            stmt = stmt.where(Query.server.in_(server_list))
        stmt = stmt.where(Query.client_ip.in_(client_list))
    else:
        T = DomainStatsHourly
        stmt = (
            select(DomainLabel.app_name, func.max(DomainLabel.category).label('category'),
                   func.sum(T.total).label('total'), func.sum(T.blocked).label('blocked'))
            .join(DomainLabel, DomainLabel.domain == T.domain)
            .where(T.hour >= start, DomainLabel.app_name.isnot(None))
            .group_by(DomainLabel.app_name).order_by(func.sum(T.total).desc()).limit(50)
        )
        if end:
            stmt = stmt.where(T.hour <= end)
        if server_list:
            stmt = stmt.where(T.server.in_(server_list))

    rows = await db.execute(stmt)
    return [AppUsage(app_name=r[0], category=r[1], total=int(r[2] or 0), blocked=int(r[3] or 0))
            for r in rows]


@router.get("/categories", response_model=List[CategoryUsage])
async def get_category_usage(
    period: str = "24h", servers: Optional[str] = None, clients: Optional[str] = None,
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    start, end = _resolve_period(period, from_date, to_date)
    server_list = _server_list(servers)
    client_list = _server_list(clients)
    cat = func.coalesce(DomainLabel.category, UNCATEGORIZED_LABEL).label('category')

    if client_list:
        stmt = (
            select(cat, func.count(Query.id).label('total'),
                   func.count(Query.id).filter(Query.status.in_(BLOCKED_STATUSES)).label('blocked'))
            .join(DomainLabel, DomainLabel.domain == Query.domain, isouter=True)
            .where(Query.timestamp >= start)
            .group_by(cat).order_by(func.count(Query.id).desc())
        )
        if end:
            stmt = stmt.where(Query.timestamp <= end)
        if server_list:
            stmt = stmt.where(Query.server.in_(server_list))
        stmt = stmt.where(Query.client_ip.in_(client_list))
    else:
        T = DomainStatsHourly
        stmt = (
            select(cat, func.sum(T.total).label('total'), func.sum(T.blocked).label('blocked'))
            .join(DomainLabel, DomainLabel.domain == T.domain, isouter=True)
            .where(T.hour >= start)
            .group_by(cat).order_by(func.sum(T.total).desc())
        )
        if end:
            stmt = stmt.where(T.hour <= end)
        if server_list:
            stmt = stmt.where(T.server.in_(server_list))

    rows = await db.execute(stmt)
    return [CategoryUsage(category=r[0], total=int(r[1] or 0), blocked=int(r[2] or 0)) for r in rows]


@router.get("/apps/domains", response_model=List[DomainUsage])
async def get_app_domains(
    app_name: str, period: str = "24h", servers: Optional[str] = None,
    from_date: Optional[str] = None, to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    """Drill-down: the matched domains behind one app, with counts."""
    start, end = _resolve_period(period, from_date, to_date)
    server_list = _server_list(servers)
    T = DomainStatsHourly
    stmt = (
        select(T.domain, func.sum(T.total).label('total'), func.sum(T.blocked).label('blocked'))
        .join(DomainLabel, DomainLabel.domain == T.domain)
        .where(T.hour >= start, DomainLabel.app_name == app_name)
        .group_by(T.domain).order_by(func.sum(T.total).desc()).limit(100)
    )
    if end:
        stmt = stmt.where(T.hour <= end)
    if server_list:
        stmt = stmt.where(T.server.in_(server_list))
    rows = await db.execute(stmt)
    return [DomainUsage(domain=r[0], total=int(r[1] or 0), blocked=int(r[2] or 0)) for r in rows]


@router.get("/uncategorized-domains", response_model=List[DomainUsage])
async def get_uncategorized_domains(
    period: str = "24h", servers: Optional[str] = None,
    from_date: Optional[str] = None, to_date: Optional[str] = None, limit: int = 50,
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user),
):
    """Top domains with no resolved category, by query volume — the coverage backlog."""
    start, end = _resolve_period(period, from_date, to_date)
    T = DomainStatsHourly
    stmt = (
        select(T.domain, func.sum(T.total).label('total'), func.sum(T.blocked).label('blocked'))
        .join(DomainLabel, DomainLabel.domain == T.domain, isouter=True)
        .where(T.hour >= start, DomainLabel.category.is_(None))
        .group_by(T.domain).order_by(func.sum(T.total).desc()).limit(limit)
    )
    server_list = _server_list(servers)
    if server_list:
        stmt = stmt.where(T.server.in_(server_list))
    rows = (await db.execute(stmt)).all()
    return [DomainUsage(domain=r[0], total=int(r[1] or 0), blocked=int(r[2] or 0)) for r in rows]
