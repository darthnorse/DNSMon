"""
Statistics routes
"""
import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional
from datetime import datetime, timedelta, timezone

from ..database import get_db, async_session_maker
from ..models import Query, User, QueryStatsHourly, ClientStatsHourly, DomainStatsHourly
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
            Query.status.in_(BLOCKED_STATUSES)
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
        select(Query.server, func.count(Query.id).label('count'))
        .where(Query.timestamp >= last_7d)
        .group_by(Query.server)
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


@router.get("/statistics/clients")
async def get_statistics_clients(
    period: str = "24h",
    servers: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get unique clients for the filter dropdown.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
    """
    if period not in ("24h", "7d", "30d"):
        raise HTTPException(status_code=400, detail="Invalid period. Must be '24h', '7d', or '30d'")

    now = datetime.now(timezone.utc)
    if period == "24h":
        period_start = now - timedelta(hours=24)
    elif period == "7d":
        period_start = now - timedelta(days=7)
    else:
        period_start = now - timedelta(days=30)

    server_list = None
    if servers:
        server_list = [s.strip() for s in servers.split(',') if s.strip()]

    # Get unique clients with query counts
    stmt = (
        select(
            Query.client_ip,
            Query.client_hostname,
            func.count(Query.id).label('count')
        )
        .where(Query.timestamp >= period_start)
        .group_by(Query.client_ip, Query.client_hostname)
        .order_by(func.count(Query.id).desc())
        .limit(500)  # Limit to top 500 clients
    )

    if server_list:
        stmt = stmt.where(Query.server.in_(server_list))

    result = await db.execute(stmt)
    clients = [
        {
            "client_ip": row[0],
            "client_hostname": row[1],
            "count": row[2]
        }
        for row in result
    ]

    return clients


@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(
    period: str = "24h",
    servers: Optional[str] = None,
    clients: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get comprehensive statistics using pre-aggregated hourly tables.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
        clients: Comma-separated list of client IPs to include (default: all clients)
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

    client_list = None
    if clients:
        client_list = [c.strip() for c in clients.split(',') if c.strip()]
        if not client_list:
            client_list = None

    today_start = now - timedelta(hours=24)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    has_client_filter = client_list is not None

    # --- Helper to add server filters to aggregated table queries ---
    def add_server_filter(stmt, table):
        if server_list:
            stmt = stmt.where(table.server.in_(server_list))
        return stmt

    def add_client_filter(stmt, table):
        if client_list:
            stmt = stmt.where(table.client_ip.in_(client_list))
        return stmt

    # --- Queries using pre-aggregated tables (fast path) ---

    async def run_counts():
        """Counts from QueryStatsHourly or ClientStatsHourly depending on client filter"""
        async with async_session_maker() as s:
            if has_client_filter:
                T = ClientStatsHourly
                base_filter = lambda stmt: add_client_filter(add_server_filter(stmt, T), T)
            else:
                T = QueryStatsHourly
                base_filter = lambda stmt: add_server_filter(stmt, T)

            stmt = select(
                func.sum(T.total).label('total_all'),
                func.sum(T.total).filter(T.hour >= month_start).label('month'),
                func.sum(T.total).filter(T.hour >= week_start).label('week'),
                func.sum(T.total).filter(T.hour >= today_start).label('today'),
                func.sum(T.total).filter(T.hour >= period_start).label('period'),
                func.sum(T.blocked).filter(T.hour >= period_start).label('blocked'),
            )
            stmt = base_filter(stmt)
            result = await s.execute(stmt)
            return result.one()

    async def run_time_series():
        async with async_session_maker() as s:
            if has_client_filter:
                T = ClientStatsHourly
                base_filter = lambda stmt: add_client_filter(add_server_filter(stmt, T), T)
            else:
                T = QueryStatsHourly
                base_filter = lambda stmt: add_server_filter(stmt, T)

            hour_filter = T.hour >= period_start

            if time_granularity == 'hour':
                stmt = (
                    select(
                        T.hour,
                        func.sum(T.total).label('queries'),
                        func.sum(T.blocked).label('blocked')
                    )
                    .where(hour_filter)
                    .group_by(T.hour)
                    .order_by(T.hour)
                )
            else:
                day_col = func.date_trunc('day', T.hour).label('day')
                stmt = (
                    select(
                        day_col,
                        func.sum(T.total).label('queries'),
                        func.sum(T.blocked).label('blocked')
                    )
                    .where(hour_filter)
                    .group_by(day_col)
                    .order_by(day_col)
                )
            stmt = base_filter(stmt)
            result = await s.execute(stmt)
            return list(result)

    async def run_top_domains():
        async with async_session_maker() as s:
            # Domain stats table doesn't have client_ip, fall back to raw table
            if has_client_filter:
                return await _run_top_domains_raw(s, period_start, server_list, client_list)
            T = DomainStatsHourly
            stmt = (
                select(T.domain, func.sum(T.total).label('count'))
                .where(T.hour >= period_start)
                .group_by(T.domain)
                .order_by(func.sum(T.total).desc())
                .limit(10)
            )
            stmt = add_server_filter(stmt, T)
            result = await s.execute(stmt)
            return [{"domain": row[0], "count": row[1]} for row in result]

    async def run_top_blocked():
        async with async_session_maker() as s:
            if has_client_filter:
                return await _run_top_blocked_raw(s, period_start, server_list, client_list)
            T = DomainStatsHourly
            stmt = (
                select(T.domain, func.sum(T.blocked).label('count'))
                .where(and_(T.hour >= period_start, T.blocked > 0))
                .group_by(T.domain)
                .order_by(func.sum(T.blocked).desc())
                .limit(10)
            )
            stmt = add_server_filter(stmt, T)
            result = await s.execute(stmt)
            return [{"domain": row[0], "count": row[1]} for row in result]

    async def run_top_clients():
        async with async_session_maker() as s:
            T = ClientStatsHourly
            stmt = (
                select(T.client_ip, func.max(T.client_hostname).label('hostname'),
                       func.sum(T.total).label('count'))
                .where(T.hour >= period_start)
                .group_by(T.client_ip)
                .order_by(func.sum(T.total).desc())
                .limit(10)
            )
            stmt = add_server_filter(stmt, T)
            if client_list:
                stmt = add_client_filter(stmt, T)
            result = await s.execute(stmt)
            return [
                {"client_ip": row[0], "client_hostname": row[1], "count": row[2]}
                for row in result
            ]

    async def run_server_stats():
        async with async_session_maker() as s:
            if has_client_filter:
                T = ClientStatsHourly
                stmt = (
                    select(
                        T.server,
                        func.sum(T.total).label('queries'),
                        func.sum(T.blocked).label('blocked'),
                    )
                    .where(T.hour >= period_start)
                    .group_by(T.server)
                    .order_by(func.sum(T.total).desc())
                )
                stmt = add_client_filter(add_server_filter(stmt, T), T)
                result = await s.execute(stmt)
                # ClientStatsHourly doesn't track cached, use 0
                return [
                    {"server": row[0], "queries": row[1], "blocked": row[2], "cached": 0}
                    for row in result
                ]
            else:
                T = QueryStatsHourly
                stmt = (
                    select(
                        T.server,
                        func.sum(T.total).label('queries'),
                        func.sum(T.blocked).label('blocked'),
                        func.sum(T.cached).label('cached')
                    )
                    .where(T.hour >= period_start)
                    .group_by(T.server)
                    .order_by(func.sum(T.total).desc())
                )
                stmt = add_server_filter(stmt, T)
                result = await s.execute(stmt)
                return [
                    {"server": row[0], "queries": row[1], "blocked": row[2], "cached": row[3]}
                    for row in result
                ]

    async def run_unique_clients():
        async with async_session_maker() as s:
            T = ClientStatsHourly
            stmt = select(func.count(func.distinct(T.client_ip))).where(T.hour >= period_start)
            stmt = add_server_filter(stmt, T)
            if client_list:
                stmt = add_client_filter(stmt, T)
            result = await s.execute(stmt)
            return result.scalar() or 0

    async def run_new_clients():
        async with async_session_maker() as s:
            T = ClientStatsHourly
            lookback = period_start - timedelta(days=30)
            in_period = select(func.distinct(T.client_ip)).where(T.hour >= period_start)
            in_period = add_server_filter(in_period, T)
            if client_list:
                in_period = add_client_filter(in_period, T)
            before = select(func.distinct(T.client_ip)).where(and_(T.hour >= lookback, T.hour < period_start))
            before = add_server_filter(before, T)
            if client_list:
                before = add_client_filter(before, T)
            stmt = select(func.count()).select_from(
                in_period.except_(before).subquery()
            )
            result = await s.execute(stmt)
            return result.scalar() or 0

    # Execute all queries concurrently
    (counts_row, time_rows, top_domains, top_blocked_domains,
     top_clients, queries_by_server, unique_clients, new_clients_24h) = await asyncio.gather(
        run_counts(),
        run_time_series(),
        run_top_domains(),
        run_top_blocked(),
        run_top_clients(),
        run_server_stats(),
        run_unique_clients(),
        run_new_clients(),
    )

    # Process counts
    queries_total = int(counts_row.total_all or 0)
    queries_month = int(counts_row.month or 0)
    queries_week = int(counts_row.week or 0)
    queries_today = int(counts_row.today or 0)
    queries_period = int(counts_row.period or 0)
    blocked_today = int(counts_row.blocked or 0)
    blocked_percentage = (blocked_today / queries_period * 100) if queries_period > 0 else 0.0

    # Process time series
    if time_granularity == 'hour':
        queries_hourly = [
            {"hour": row[0].strftime('%Y-%m-%dT%H:%M:%SZ') if row[0] else "", "queries": int(row[1]), "blocked": int(row[2])}
            for row in time_rows
        ]
        queries_daily = []
    else:
        queries_daily = [
            {"date": row[0].strftime('%Y-%m-%d') if row[0] else "", "queries": int(row[1]), "blocked": int(row[2])}
            for row in time_rows
        ]
        queries_hourly = []

    most_active_client = top_clients[0] if top_clients else None

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


async def _run_top_domains_raw(s, period_start, server_list, client_list):
    """Fallback to raw query table when client filter is applied (domain stats don't have client_ip)"""
    stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(Query.timestamp >= period_start)
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    if server_list:
        stmt = stmt.where(Query.server.in_(server_list))
    if client_list:
        stmt = stmt.where(Query.client_ip.in_(client_list))
    result = await s.execute(stmt)
    return [{"domain": row[0], "count": row[1]} for row in result]


async def _run_top_blocked_raw(s, period_start, server_list, client_list):
    """Fallback to raw query table for top blocked with client filter"""
    stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(and_(Query.timestamp >= period_start, Query.status.in_(BLOCKED_STATUSES)))
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    if server_list:
        stmt = stmt.where(Query.server.in_(server_list))
    if client_list:
        stmt = stmt.where(Query.client_ip.in_(client_list))
    result = await s.execute(stmt)
    return [{"domain": row[0], "count": row[1]} for row in result]
