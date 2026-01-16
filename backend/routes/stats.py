"""
Statistics routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional
from datetime import datetime, timedelta, timezone

from ..database import get_db
from ..models import Query, User
from ..schemas import StatsResponse, StatisticsResponse
from ..auth import get_current_user

# Blocked status values from Pi-hole v6
BLOCKED_STATUSES = ['GRAVITY', 'GRAVITY_CNAME', 'REGEX', 'REGEX_CNAME',
                    'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
                    'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA']

CACHE_STATUSES = ['CACHE', 'CACHE_STALE']

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get dashboard statistics"""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Total queries
    total_stmt = select(func.count(Query.id))
    total_result = await db.execute(total_stmt)
    total_queries = total_result.scalar()

    # Queries last 24h
    last_24h_stmt = select(func.count(Query.id)).where(Query.timestamp >= last_24h)
    last_24h_result = await db.execute(last_24h_stmt)
    queries_last_24h = last_24h_result.scalar()

    # Blocked queries last 24h
    blocks_24h_stmt = select(func.count(Query.id)).where(
        and_(
            Query.timestamp >= last_24h,
            Query.status.in_(['GRAVITY', 'GRAVITY_CNAME', 'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST'])
        )
    )
    blocks_24h_result = await db.execute(blocks_24h_stmt)
    blocks_last_24h = blocks_24h_result.scalar()

    # Queries last 7d
    last_7d_stmt = select(func.count(Query.id)).where(Query.timestamp >= last_7d)
    last_7d_result = await db.execute(last_7d_stmt)
    queries_last_7d = last_7d_result.scalar()

    # Top domains (last 7 days)
    top_domains_stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(Query.timestamp >= last_7d)
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    top_domains_result = await db.execute(top_domains_stmt)
    top_domains = [{"domain": row[0], "count": row[1]} for row in top_domains_result]

    # Top clients (last 7 days)
    top_clients_stmt = (
        select(Query.client_ip, Query.client_hostname, func.count(Query.id).label('count'))
        .where(Query.timestamp >= last_7d)
        .group_by(Query.client_ip, Query.client_hostname)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    top_clients_result = await db.execute(top_clients_stmt)
    top_clients = [
        {"client_ip": row[0], "client_hostname": row[1], "count": row[2]}
        for row in top_clients_result
    ]

    # Queries by server (last 7 days)
    by_server_stmt = (
        select(Query.pihole_server, func.count(Query.id).label('count'))
        .where(Query.timestamp >= last_7d)
        .group_by(Query.pihole_server)
        .order_by(func.count(Query.id).desc())
    )
    by_server_result = await db.execute(by_server_stmt)
    queries_by_server = [{"server": row[0], "count": row[1]} for row in by_server_result]

    return StatsResponse(
        total_queries=total_queries or 0,
        queries_last_24h=queries_last_24h or 0,
        blocks_last_24h=blocks_last_24h or 0,
        queries_last_7d=queries_last_7d or 0,
        top_domains=top_domains,
        top_clients=top_clients,
        queries_by_server=queries_by_server
    )


@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(
    period: str = "24h",
    servers: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get comprehensive statistics for the Statistics page.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
    """
    if period not in ("24h", "7d", "30d"):
        raise HTTPException(status_code=400, detail="Invalid period. Must be '24h', '7d', or '30d'")

    now = datetime.now(timezone.utc)

    if period == "24h":
        period_start = now - timedelta(hours=24)
        time_granularity = 'hour'
    elif period == "7d":
        period_start = now - timedelta(days=7)
        time_granularity = 'day'
    else:  # 30d
        period_start = now - timedelta(days=30)
        time_granularity = 'day'

    server_list = None
    if servers:
        server_list = [s.strip() for s in servers.split(',') if s.strip()]
        if not server_list:
            server_list = None

    def add_server_filter(stmt):
        if server_list:
            return stmt.where(Query.pihole_server.in_(server_list))
        return stmt

    period_filter = Query.timestamp >= period_start

    # Query counts
    period_stmt = select(func.count(Query.id)).where(period_filter)
    period_stmt = add_server_filter(period_stmt)
    period_result = await db.execute(period_stmt)
    queries_period = period_result.scalar() or 0

    today_start = now - timedelta(hours=24)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    today_stmt = add_server_filter(select(func.count(Query.id)).where(Query.timestamp >= today_start))
    today_result = await db.execute(today_stmt)
    queries_today = today_result.scalar() or 0

    week_stmt = add_server_filter(select(func.count(Query.id)).where(Query.timestamp >= week_start))
    week_result = await db.execute(week_stmt)
    queries_week = week_result.scalar() or 0

    month_stmt = add_server_filter(select(func.count(Query.id)).where(Query.timestamp >= month_start))
    month_result = await db.execute(month_stmt)
    queries_month = month_result.scalar() or 0

    total_stmt = add_server_filter(select(func.count(Query.id)))
    total_result = await db.execute(total_stmt)
    queries_total = total_result.scalar() or 0

    # Blocked stats
    blocked_stmt = select(func.count(Query.id)).where(
        and_(period_filter, Query.status.in_(BLOCKED_STATUSES))
    )
    blocked_stmt = add_server_filter(blocked_stmt)
    blocked_result = await db.execute(blocked_stmt)
    blocked_today = blocked_result.scalar() or 0

    blocked_percentage = (blocked_today / queries_period * 100) if queries_period > 0 else 0.0

    # Time Series
    if time_granularity == 'hour':
        time_col = func.date_trunc('hour', Query.timestamp).label('time_bucket')
        time_stmt = (
            select(
                time_col,
                func.count(Query.id).label('queries'),
                func.count(Query.id).filter(Query.status.in_(BLOCKED_STATUSES)).label('blocked')
            )
            .where(period_filter)
            .group_by(time_col)
            .order_by(time_col)
        )
        time_stmt = add_server_filter(time_stmt)
        time_result = await db.execute(time_stmt)
        queries_hourly = [
            {"hour": row[0].strftime('%Y-%m-%dT%H:%M:%SZ') if row[0] else "", "queries": row[1], "blocked": row[2]}
            for row in time_result
        ]
        queries_daily = []
    else:
        time_col = func.date_trunc('day', Query.timestamp).label('time_bucket')
        time_stmt = (
            select(
                time_col,
                func.count(Query.id).label('queries'),
                func.count(Query.id).filter(Query.status.in_(BLOCKED_STATUSES)).label('blocked')
            )
            .where(period_filter)
            .group_by(time_col)
            .order_by(time_col)
        )
        time_stmt = add_server_filter(time_stmt)
        time_result = await db.execute(time_stmt)
        queries_daily = [
            {"date": row[0].strftime('%Y-%m-%d') if row[0] else "", "queries": row[1], "blocked": row[2]}
            for row in time_result
        ]
        queries_hourly = []

    # Top domains
    top_domains_stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(period_filter)
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    top_domains_stmt = add_server_filter(top_domains_stmt)
    top_domains_result = await db.execute(top_domains_stmt)
    top_domains = [{"domain": row[0], "count": row[1]} for row in top_domains_result]

    # Top blocked domains
    top_blocked_stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(and_(period_filter, Query.status.in_(BLOCKED_STATUSES)))
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    top_blocked_stmt = add_server_filter(top_blocked_stmt)
    top_blocked_result = await db.execute(top_blocked_stmt)
    top_blocked_domains = [{"domain": row[0], "count": row[1]} for row in top_blocked_result]

    # Top clients
    top_clients_stmt = (
        select(Query.client_ip, Query.client_hostname, func.count(Query.id).label('count'))
        .where(period_filter)
        .group_by(Query.client_ip, Query.client_hostname)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    top_clients_stmt = add_server_filter(top_clients_stmt)
    top_clients_result = await db.execute(top_clients_stmt)
    top_clients = [
        {"client_ip": row[0], "client_hostname": row[1], "count": row[2]}
        for row in top_clients_result
    ]

    # Per Server Stats
    server_stats_stmt = (
        select(
            Query.pihole_server,
            func.count(Query.id).label('queries'),
            func.count(Query.id).filter(Query.status.in_(BLOCKED_STATUSES)).label('blocked'),
            func.count(Query.id).filter(Query.status.in_(CACHE_STATUSES)).label('cached')
        )
        .where(period_filter)
        .group_by(Query.pihole_server)
        .order_by(func.count(Query.id).desc())
    )
    server_stats_stmt = add_server_filter(server_stats_stmt)
    server_stats_result = await db.execute(server_stats_stmt)
    queries_by_server = [
        {"server": row[0], "queries": row[1], "blocked": row[2], "cached": row[3]}
        for row in server_stats_result
    ]

    # Client Insights
    unique_clients_stmt = select(func.count(func.distinct(Query.client_ip))).where(period_filter)
    unique_clients_stmt = add_server_filter(unique_clients_stmt)
    unique_clients_result = await db.execute(unique_clients_stmt)
    unique_clients = unique_clients_result.scalar() or 0

    most_active_client = top_clients[0] if top_clients else None

    first_seen_base = select(Query.client_ip, func.min(Query.timestamp).label('first_seen'))
    first_seen_base = add_server_filter(first_seen_base)
    first_seen_subq = first_seen_base.group_by(Query.client_ip).subquery()

    new_clients_stmt = select(func.count()).select_from(first_seen_subq).where(
        first_seen_subq.c.first_seen >= period_start
    )
    new_clients_result = await db.execute(new_clients_stmt)
    new_clients_24h = new_clients_result.scalar() or 0

    return StatisticsResponse(
        queries_today=queries_today,
        queries_week=queries_week,
        queries_month=queries_month,
        queries_total=queries_total,
        blocked_today=blocked_today,
        blocked_percentage=round(blocked_percentage, 2),
        queries_hourly=queries_hourly,
        queries_daily=queries_daily,
        top_domains=top_domains,
        top_blocked_domains=top_blocked_domains,
        top_clients=top_clients,
        queries_by_server=queries_by_server,
        unique_clients=unique_clients,
        most_active_client=most_active_client,
        new_clients_24h=new_clients_24h
    )
