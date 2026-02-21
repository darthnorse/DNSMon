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
from ..config import get_settings_sync

BLOCKED_STATUSES = ['GRAVITY', 'GRAVITY_CNAME', 'REGEX', 'REGEX_CNAME',
                    'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
                    'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA',
                    'BLOCKED']

CACHE_STATUSES = ['CACHE', 'CACHE_STALE', 'CACHED']

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


def _parse_iso_date(value: str, field_name: str) -> datetime:
    """Parse an ISO 8601 date string into a timezone-aware datetime."""
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name} format. Use ISO 8601 (e.g. 2026-02-18T00:00:00Z)"
        )


def _parse_custom_range(from_date: str, to_date: str) -> tuple[datetime, datetime]:
    """Parse and validate custom date range parameters.

    Returns (period_start, period_end) as timezone-aware datetimes.
    Raises HTTPException on validation failure.
    """
    start = _parse_iso_date(from_date, "from_date")
    end = _parse_iso_date(to_date, "to_date")

    if start >= end:
        raise HTTPException(status_code=400, detail="from_date must be before to_date")

    now = datetime.now(timezone.utc)
    if end > now + timedelta(minutes=5):
        raise HTTPException(status_code=400, detail="to_date cannot be in the future")

    try:
        settings = get_settings_sync()
        max_days = settings.retention_days
    except RuntimeError:
        max_days = 60

    if (end - start).total_seconds() > max_days * 86400:
        raise HTTPException(status_code=400, detail=f"Custom range cannot exceed {max_days} days (retention_days setting)")

    oldest_allowed = now - timedelta(days=max_days)
    if start < oldest_allowed:
        raise HTTPException(status_code=400, detail=f"from_date cannot be more than {max_days} days in the past (retention_days setting)")

    return start, end


_PERIOD_DELTAS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


def _resolve_period(
    period: str,
    from_date: Optional[str],
    to_date: Optional[str],
) -> tuple[datetime, Optional[datetime]]:
    """Resolve period params into (period_start, period_end).

    When from_date and to_date are both provided, uses the custom range.
    Otherwise uses the preset period. Returns period_end=None for presets.
    """
    if from_date and to_date:
        return _parse_custom_range(from_date, to_date)

    if period not in _PERIOD_DELTAS:
        raise HTTPException(status_code=400, detail="Invalid period. Must be '24h', '7d', or '30d'")
    return datetime.now(timezone.utc) - _PERIOD_DELTAS[period], None


@router.get("/statistics/clients")
async def get_statistics_clients(
    period: str = "24h",
    servers: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get unique clients for the filter dropdown.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
        from_date: Custom range start (ISO 8601). When both from_date and to_date are provided, period is ignored.
        to_date: Custom range end (ISO 8601).
    """
    period_start, period_end = _resolve_period(period, from_date, to_date)

    server_list = None
    if servers:
        server_list = [s.strip() for s in servers.split(',') if s.strip()]

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

    if period_end:
        stmt = stmt.where(Query.timestamp <= period_end)
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
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get comprehensive statistics using pre-aggregated hourly tables.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
        clients: Comma-separated list of client IPs to include (default: all clients)
        from_date: Custom range start (ISO 8601). When both from_date and to_date are provided, period is ignored.
        to_date: Custom range end (ISO 8601).
    """
    now = datetime.now(timezone.utc)
    period_start, period_end = _resolve_period(period, from_date, to_date)

    # Custom ranges and 24h use hourly granularity; 7d/30d use daily
    if period_end or period == "24h":
        time_granularity = 'hour'
    else:
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

    def add_server_filter(stmt, table):
        if server_list:
            stmt = stmt.where(table.server.in_(server_list))
        return stmt

    def add_client_filter(stmt, table):
        if client_list:
            stmt = stmt.where(table.client_ip.in_(client_list))
        return stmt

    def add_end_filter(stmt, table):
        if period_end:
            stmt = stmt.where(table.hour <= period_end)
        return stmt

    async def run_counts():
        """Counts from QueryStatsHourly or ClientStatsHourly depending on client filter.

        total_all is the all-time grand total (no date bounds) so users always see
        the full scope regardless of the selected period or custom range.
        The other columns are scoped to their respective windows, with period_end
        applied only when a custom range is active.
        """
        async with async_session_maker() as s:
            if has_client_filter:
                T = ClientStatsHourly
                base_filter = lambda stmt: add_client_filter(add_server_filter(stmt, T), T)
            else:
                T = QueryStatsHourly
                base_filter = lambda stmt: add_server_filter(stmt, T)

            def _time_window(start):
                """Build a FILTER condition for a time window, respecting period_end."""
                if period_end:
                    return and_(T.hour >= start, T.hour <= period_end)
                return T.hour >= start

            stmt = select(
                func.sum(T.total).label('total_all'),
                func.sum(T.total).filter(_time_window(month_start)).label('month'),
                func.sum(T.total).filter(_time_window(week_start)).label('week'),
                func.sum(T.total).filter(_time_window(today_start)).label('today'),
                func.sum(T.total).filter(_time_window(period_start)).label('period'),
                func.sum(T.blocked).filter(_time_window(period_start)).label('blocked'),
            )
            stmt = base_filter(stmt)
            result = await s.execute(stmt)
            return result.one()

    async def run_time_series():
        async with async_session_maker() as s:
            if has_client_filter:
                T = ClientStatsHourly
                base_filter = lambda stmt: add_end_filter(add_client_filter(add_server_filter(stmt, T), T), T)
            else:
                T = QueryStatsHourly
                base_filter = lambda stmt: add_end_filter(add_server_filter(stmt, T), T)

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
                return await _run_top_domains_raw(s, period_start, server_list, client_list, period_end)
            T = DomainStatsHourly
            stmt = (
                select(T.domain, func.sum(T.total).label('count'))
                .where(T.hour >= period_start)
                .group_by(T.domain)
                .order_by(func.sum(T.total).desc())
                .limit(10)
            )
            stmt = add_end_filter(add_server_filter(stmt, T), T)
            result = await s.execute(stmt)
            return [{"domain": row[0], "count": row[1]} for row in result]

    async def run_top_blocked():
        async with async_session_maker() as s:
            if has_client_filter:
                return await _run_top_domains_raw(s, period_start, server_list, client_list, period_end, blocked_only=True)
            T = DomainStatsHourly
            stmt = (
                select(T.domain, func.sum(T.blocked).label('count'))
                .where(and_(T.hour >= period_start, T.blocked > 0))
                .group_by(T.domain)
                .order_by(func.sum(T.blocked).desc())
                .limit(10)
            )
            stmt = add_end_filter(add_server_filter(stmt, T), T)
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
            stmt = add_end_filter(add_server_filter(stmt, T), T)
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
                stmt = add_end_filter(add_client_filter(add_server_filter(stmt, T), T), T)
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
                stmt = add_end_filter(add_server_filter(stmt, T), T)
                result = await s.execute(stmt)
                return [
                    {"server": row[0], "queries": row[1], "blocked": row[2], "cached": row[3]}
                    for row in result
                ]

    async def run_unique_clients():
        async with async_session_maker() as s:
            T = ClientStatsHourly
            stmt = select(func.count(func.distinct(T.client_ip))).where(T.hour >= period_start)
            stmt = add_end_filter(add_server_filter(stmt, T), T)
            if client_list:
                stmt = add_client_filter(stmt, T)
            result = await s.execute(stmt)
            return result.scalar() or 0

    async def run_new_clients():
        async with async_session_maker() as s:
            T = ClientStatsHourly
            lookback = period_start - timedelta(days=30)
            in_period = select(func.distinct(T.client_ip)).where(T.hour >= period_start)
            in_period = add_end_filter(add_server_filter(in_period, T), T)
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

    queries_total = int(counts_row.total_all or 0)
    queries_month = int(counts_row.month or 0)
    queries_week = int(counts_row.week or 0)
    queries_today = int(counts_row.today or 0)
    queries_period = int(counts_row.period or 0)
    blocked_period = int(counts_row.blocked or 0)
    blocked_percentage = (blocked_period / queries_period * 100) if queries_period > 0 else 0.0

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
        queries_period=queries_period,
        blocked_period=blocked_period,
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


async def _run_top_domains_raw(s, period_start, server_list, client_list,
                               period_end=None, blocked_only=False):
    """Fallback to raw query table when client filter is applied (domain stats don't have client_ip).

    When blocked_only=True, only counts queries with blocked statuses.
    """
    stmt = (
        select(Query.domain, func.count(Query.id).label('count'))
        .where(Query.timestamp >= period_start)
        .group_by(Query.domain)
        .order_by(func.count(Query.id).desc())
        .limit(10)
    )
    if blocked_only:
        stmt = stmt.where(Query.status.in_(BLOCKED_STATUSES))
    if period_end:
        stmt = stmt.where(Query.timestamp <= period_end)
    if server_list:
        stmt = stmt.where(Query.server.in_(server_list))
    if client_list:
        stmt = stmt.where(Query.client_ip.in_(client_list))
    result = await s.execute(stmt)
    return [{"domain": row[0], "count": row[1]} for row in result]
