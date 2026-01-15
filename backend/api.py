from fastapi import FastAPI, Depends, HTTPException, Query as QueryParam
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field as PydanticField, field_validator
import os
import logging

from .database import get_db, init_db
from .models import Query, AlertRule, AlertHistory
from .config import get_settings
from .service import get_service

logger = logging.getLogger(__name__)


def ensure_utc(dt: Optional[datetime]) -> Optional[str]:
    """Ensure datetime is timezone-aware (UTC) and return ISO format"""
    if dt is None:
        return None
    # If naive, assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def escape_sql_like(value: str) -> str:
    """Escape SQL LIKE wildcards to prevent unintended pattern matching"""
    # Escape % and _ which are SQL LIKE wildcards
    # Also escape the escape character itself (\)
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

# Pydantic models for API
class QueryResponse(BaseModel):
    id: int
    timestamp: str
    domain: str
    client_ip: str
    client_hostname: Optional[str]
    query_type: Optional[str]
    status: Optional[str]
    pihole_server: str

    class Config:
        from_attributes = True


class QuerySearchParams(BaseModel):
    domain: Optional[str] = None
    client_ip: Optional[str] = None
    client_hostname: Optional[str] = None
    pihole_server: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


class AlertRuleCreate(BaseModel):
    name: str = PydanticField(max_length=100)
    description: Optional[str] = PydanticField(default=None, max_length=500)
    domain_pattern: Optional[str] = PydanticField(default=None, max_length=5000)
    client_ip_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    client_hostname_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    exclude_domains: Optional[str] = PydanticField(default=None, max_length=5000)
    notify_telegram: bool = True
    telegram_chat_id: Optional[str] = PydanticField(default=None, max_length=100)
    cooldown_minutes: int = PydanticField(default=5, ge=0, le=10080)  # 0 to 7 days
    enabled: bool = True

    @field_validator('telegram_chat_id')
    @classmethod
    def validate_telegram_chat_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate that telegram_chat_id is numeric if provided"""
        if v is None or v == '':
            return v
        v = v.strip()
        # Validate numeric (can be negative for groups)
        try:
            int(v)
        except ValueError:
            raise ValueError("telegram_chat_id must be numeric")
        return v


class AlertRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    domain_pattern: Optional[str]
    client_ip_pattern: Optional[str]
    client_hostname_pattern: Optional[str]
    exclude_domains: Optional[str]
    notify_telegram: bool
    telegram_chat_id: Optional[str]
    cooldown_minutes: int
    enabled: bool
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_queries: int
    queries_last_24h: int
    blocks_last_24h: int
    queries_last_7d: int
    top_domains: List[dict]
    top_clients: List[dict]
    queries_by_server: List[dict]


class StatisticsResponse(BaseModel):
    """Comprehensive statistics response"""
    # Query Overview
    queries_today: int
    queries_week: int
    queries_month: int
    queries_total: int
    blocked_today: int
    blocked_percentage: float

    # Time Series
    queries_hourly: List[dict]  # [{"hour": str, "queries": int, "blocked": int}]
    queries_daily: List[dict]   # [{"date": str, "queries": int, "blocked": int}]

    # Top Lists
    top_domains: List[dict]          # [{"domain": str, "count": int}]
    top_blocked_domains: List[dict]  # [{"domain": str, "count": int}]
    top_clients: List[dict]          # [{"client_ip": str, "client_hostname": str|null, "count": int}]

    # Per Server
    queries_by_server: List[dict]    # [{"server": str, "queries": int, "blocked": int, "cached": int}]

    # Client Insights
    unique_clients: int
    most_active_client: Optional[dict]  # {"client_ip": str, "client_hostname": str|null, "count": int}
    new_clients_24h: int


# Blocked status values from Pi-hole v6
BLOCKED_STATUSES = ['GRAVITY', 'GRAVITY_CNAME', 'REGEX', 'REGEX_CNAME',
                    'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
                    'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA']

CACHE_STATUSES = ['CACHE', 'CACHE_STALE']


# Create FastAPI app
app = FastAPI(title="DNSMon", description="DNS Ad-Blocker Monitor - Pi-hole & AdGuard Home")

# CORS middleware - use defaults initially
# Will use database settings after bootstrap (restart required to change)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Restrict to needed methods only
    allow_headers=["Content-Type", "Authorization"],  # Restrict to standard headers
)


@app.on_event("startup")
async def startup_event():
    """Initialize database and services on startup"""
    # Initialize database (creates tables if they don't exist)
    logger.info("Initializing database...")
    await init_db()

    # Load settings from database (bootstraps with defaults if empty)
    logger.info("Loading settings from database...")
    settings = await get_settings()
    logger.info(f"Settings loaded: poll_interval={settings.poll_interval_seconds}s")

    # Start background service
    logger.info("Starting background services...")
    service = get_service()
    await service.startup()
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown services"""
    service = get_service()
    await service.shutdown()


# Query endpoints
@app.get("/api/queries", response_model=List[QueryResponse])
async def search_queries(
    domain: Optional[str] = QueryParam(None, max_length=255),
    client_ip: Optional[str] = QueryParam(None, max_length=45),
    client_hostname: Optional[str] = QueryParam(None, max_length=255),
    pihole_server: Optional[str] = QueryParam(None, max_length=100),
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = QueryParam(100, le=1000, ge=1),
    offset: int = QueryParam(0, ge=0, le=1000000),  # Max 1 million offset to prevent abuse
    db: AsyncSession = Depends(get_db)
):
    """
    Search DNS queries with flexible filtering.
    Supports partial matching on domain, client_ip, and client_hostname.
    """
    # Build query
    stmt = select(Query)
    conditions = []

    # Domain filter (partial match)
    if domain:
        escaped_domain = escape_sql_like(domain)
        conditions.append(Query.domain.ilike(f"%{escaped_domain}%", escape='\\'))

    # Client IP filter (partial match)
    if client_ip:
        escaped_ip = escape_sql_like(client_ip)
        conditions.append(Query.client_ip.ilike(f"%{escaped_ip}%", escape='\\'))

    # Client hostname filter (partial match)
    if client_hostname:
        escaped_hostname = escape_sql_like(client_hostname)
        conditions.append(Query.client_hostname.ilike(f"%{escaped_hostname}%", escape='\\'))

    # Pihole server filter
    if pihole_server:
        conditions.append(Query.pihole_server == pihole_server)

    # Date range filters
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

    # Validate date range
    if from_dt and to_dt and from_dt > to_dt:
        raise HTTPException(status_code=400, detail="from_date must be before or equal to to_date")

    # Apply conditions
    if conditions:
        stmt = stmt.where(and_(*conditions))

    # Order by timestamp descending
    stmt = stmt.order_by(Query.timestamp.desc())

    # Apply pagination
    stmt = stmt.limit(limit).offset(offset)

    # Execute query
    result = await db.execute(stmt)
    queries = result.scalars().all()

    # Convert to response model
    return [QueryResponse(
        id=q.id,
        timestamp=ensure_utc(q.timestamp),
        domain=q.domain,
        client_ip=q.client_ip,
        client_hostname=q.client_hostname,
        query_type=q.query_type,
        status=q.status,
        pihole_server=q.pihole_server
    ) for q in queries]


@app.get("/api/queries/count")
async def count_queries(
    domain: Optional[str] = None,
    client_ip: Optional[str] = None,
    client_hostname: Optional[str] = None,
    pihole_server: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get count of queries matching search criteria"""
    stmt = select(func.count(Query.id))
    conditions = []

    if domain:
        escaped_domain = escape_sql_like(domain)
        conditions.append(Query.domain.ilike(f"%{escaped_domain}%", escape='\\'))
    if client_ip:
        escaped_ip = escape_sql_like(client_ip)
        conditions.append(Query.client_ip.ilike(f"%{escaped_ip}%", escape='\\'))
    if client_hostname:
        escaped_hostname = escape_sql_like(client_hostname)
        conditions.append(Query.client_hostname.ilike(f"%{escaped_hostname}%", escape='\\'))
    if pihole_server:
        conditions.append(Query.pihole_server == pihole_server)

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

    if conditions:
        stmt = stmt.where(and_(*conditions))

    result = await db.execute(stmt)
    count = result.scalar()

    return {"count": count}


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)):
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

    # Blocked queries last 24h (Pi-hole v6 uses GRAVITY and GRAVITY_CNAME for blocked)
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


@app.get("/api/statistics", response_model=StatisticsResponse)
async def get_statistics(
    period: str = "24h",
    servers: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get comprehensive statistics for the Statistics page.

    Args:
        period: Time period filter - "24h", "7d", or "30d" (default: "24h")
        servers: Comma-separated list of server names to include (default: all servers)
    """
    # Validate period parameter
    if period not in ("24h", "7d", "30d"):
        raise HTTPException(status_code=400, detail="Invalid period. Must be '24h', '7d', or '30d'")

    now = datetime.now(timezone.utc)

    # Calculate period-specific time range
    if period == "24h":
        period_start = now - timedelta(hours=24)
        time_granularity = 'hour'
    elif period == "7d":
        period_start = now - timedelta(days=7)
        time_granularity = 'day'
    else:  # 30d
        period_start = now - timedelta(days=30)
        time_granularity = 'day'

    # Parse server filter
    server_list = None
    if servers:
        server_list = [s.strip() for s in servers.split(',') if s.strip()]
        if not server_list:
            server_list = None

    # Helper function to add server filter to queries
    def add_server_filter(stmt):
        if server_list:
            return stmt.where(Query.pihole_server.in_(server_list))
        return stmt

    # Base filter for period (used in most queries)
    period_filter = Query.timestamp >= period_start

    # === Query Overview (for selected servers, different time periods) ===
    # Queries in period
    period_stmt = select(func.count(Query.id)).where(period_filter)
    period_stmt = add_server_filter(period_stmt)
    period_result = await db.execute(period_stmt)
    queries_period = period_result.scalar() or 0

    # For overview cards, show period-appropriate values
    # Today = 24h period queries, Week = 7d queries, Month = 30d queries
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

    # === Blocked stats (period-specific) ===
    blocked_stmt = select(func.count(Query.id)).where(
        and_(period_filter, Query.status.in_(BLOCKED_STATUSES))
    )
    blocked_stmt = add_server_filter(blocked_stmt)
    blocked_result = await db.execute(blocked_stmt)
    blocked_today = blocked_result.scalar() or 0

    # Blocked percentage (for selected period)
    blocked_percentage = (blocked_today / queries_period * 100) if queries_period > 0 else 0.0

    # === Time Series (period-specific granularity) ===
    if time_granularity == 'hour':
        # Hourly data for 24h period
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
            {"hour": (row[0].isoformat() + 'Z') if row[0] else "", "queries": row[1], "blocked": row[2]}
            for row in time_result
        ]
        queries_daily = []  # Empty for 24h view
    else:
        # Daily data for 7d/30d periods
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
        queries_hourly = []  # Empty for 7d/30d view

    # === Top Lists (period-specific) ===
    # Top 10 domains
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

    # Top 10 blocked domains
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

    # Top 10 clients
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

    # === Per Server Stats (period-specific) ===
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

    # === Client Insights (period-specific) ===
    # Unique clients in period
    unique_clients_stmt = select(func.count(func.distinct(Query.client_ip))).where(period_filter)
    unique_clients_stmt = add_server_filter(unique_clients_stmt)
    unique_clients_result = await db.execute(unique_clients_stmt)
    unique_clients = unique_clients_result.scalar() or 0

    # Most active client (from top_clients, already calculated)
    most_active_client = top_clients[0] if top_clients else None

    # New clients in period (clients whose first query was in period)
    # Subquery to get first seen timestamp for each client (within selected servers)
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


# Alert rule endpoints
@app.get("/api/alert-rules", response_model=List[AlertRuleResponse])
async def get_alert_rules(db: AsyncSession = Depends(get_db)):
    """Get all alert rules"""
    stmt = select(AlertRule).order_by(AlertRule.created_at.desc())
    result = await db.execute(stmt)
    rules = result.scalars().all()

    return [AlertRuleResponse(
        id=r.id,
        name=r.name,
        description=r.description,
        domain_pattern=r.domain_pattern,
        client_ip_pattern=r.client_ip_pattern,
        client_hostname_pattern=r.client_hostname_pattern,
        exclude_domains=r.exclude_domains,
        notify_telegram=r.notify_telegram,
        telegram_chat_id=r.telegram_chat_id,
        cooldown_minutes=r.cooldown_minutes,
        enabled=r.enabled,
        created_at=ensure_utc(r.created_at),
        updated_at=ensure_utc(r.updated_at)
    ) for r in rules]


@app.post("/api/alert-rules", response_model=AlertRuleResponse)
async def create_alert_rule(rule: AlertRuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new alert rule"""
    db_rule = AlertRule(**rule.model_dump())
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)

    # Invalidate pattern cache for new rule
    service = get_service()
    await service.alert_engine.invalidate_cache(db_rule.id)

    return AlertRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        domain_pattern=db_rule.domain_pattern,
        client_ip_pattern=db_rule.client_ip_pattern,
        client_hostname_pattern=db_rule.client_hostname_pattern,
        exclude_domains=db_rule.exclude_domains,
        notify_telegram=db_rule.notify_telegram,
        telegram_chat_id=db_rule.telegram_chat_id,
        cooldown_minutes=db_rule.cooldown_minutes,
        enabled=db_rule.enabled,
        created_at=ensure_utc(db_rule.created_at),
        updated_at=ensure_utc(db_rule.updated_at)
    )


@app.put("/api/alert-rules/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: int,
    rule_update: AlertRuleCreate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing alert rule"""
    stmt = select(AlertRule).where(AlertRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()

    if not db_rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    # Update fields (explicitly exclude fields that shouldn't be user-modifiable)
    update_data = rule_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if key not in ('id', 'created_at', 'updated_at'):  # Exclude system fields
            setattr(db_rule, key, value)

    db_rule.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(db_rule)

    # Invalidate pattern cache for updated rule
    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return AlertRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        domain_pattern=db_rule.domain_pattern,
        client_ip_pattern=db_rule.client_ip_pattern,
        client_hostname_pattern=db_rule.client_hostname_pattern,
        exclude_domains=db_rule.exclude_domains,
        notify_telegram=db_rule.notify_telegram,
        telegram_chat_id=db_rule.telegram_chat_id,
        cooldown_minutes=db_rule.cooldown_minutes,
        enabled=db_rule.enabled,
        created_at=ensure_utc(db_rule.created_at),
        updated_at=ensure_utc(db_rule.updated_at)
    )


@app.delete("/api/alert-rules/{rule_id}")
async def delete_alert_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an alert rule"""
    stmt = select(AlertRule).where(AlertRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()

    if not db_rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    await db.delete(db_rule)
    await db.commit()

    # Invalidate pattern cache for deleted rule
    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return {"message": "Alert rule deleted"}


# Settings API models
class AppSettingUpdate(BaseModel):
    value: str


class PiholeServerCreate(BaseModel):
    name: str
    url: str
    password: str
    server_type: str = 'pihole'  # 'pihole' or 'adguard'
    enabled: bool = True
    is_source: bool = False
    sync_enabled: bool = False

    @field_validator('server_type')
    @classmethod
    def validate_server_type(cls, v: str) -> str:
        valid_types = ['pihole', 'adguard']
        if v not in valid_types:
            raise ValueError(f"server_type must be one of: {', '.join(valid_types)}")
        return v

    @field_validator('name', 'url', 'password')
    @classmethod
    def validate_not_empty(cls, v: str, info) -> str:
        """Validate that string fields are not empty"""
        if not v or not v.strip():
            raise ValueError(f"{info.field_name} cannot be empty")
        return v.strip()

    @field_validator('url')
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Validate URL format"""
        v = v.strip()
        if not v.startswith('http://') and not v.startswith('https://'):
            raise ValueError("URL must start with http:// or https://")
        return v


class PiholeServerUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    password: Optional[str] = None
    server_type: Optional[str] = None
    enabled: Optional[bool] = None
    is_source: Optional[bool] = None
    sync_enabled: Optional[bool] = None

    @field_validator('server_type')
    @classmethod
    def validate_server_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            valid_types = ['pihole', 'adguard']
            if v not in valid_types:
                raise ValueError(f"server_type must be one of: {', '.join(valid_types)}")
        return v


class TelegramTestData(BaseModel):
    bot_token: str
    chat_id: str

    @field_validator('bot_token')
    @classmethod
    def validate_bot_token(cls, v: str) -> str:
        """Validate that bot token is not empty"""
        if not v or not v.strip():
            raise ValueError("bot_token cannot be empty")
        return v.strip()

    @field_validator('chat_id')
    @classmethod
    def validate_chat_id(cls, v: str) -> str:
        """Validate that chat_id is not empty and is numeric"""
        if not v or not v.strip():
            raise ValueError("chat_id cannot be empty")
        v = v.strip()
        # Validate that chat_id is numeric (can be negative for groups)
        try:
            int(v)
        except ValueError:
            raise ValueError("chat_id must be numeric")
        return v


class SettingsResponse(BaseModel):
    app_settings: dict
    pihole_servers: List[dict]


# Settings endpoints
@app.get("/api/settings", response_model=SettingsResponse)
async def get_all_settings(db: AsyncSession = Depends(get_db)):
    """Get all application settings and Pi-hole servers"""
    from .models import AppSetting, PiholeServerModel

    # Get app settings
    stmt = select(AppSetting)
    result = await db.execute(stmt)
    app_settings = {row.key: row.to_dict() for row in result.scalars()}

    # Get Pi-hole servers
    stmt = select(PiholeServerModel).order_by(PiholeServerModel.display_order, PiholeServerModel.id)
    result = await db.execute(stmt)
    pihole_servers = [server.to_dict() for server in result.scalars()]

    return SettingsResponse(
        app_settings=app_settings,
        pihole_servers=pihole_servers
    )


@app.put("/api/settings/{key}")
async def update_app_setting(
    key: str,
    update: AppSettingUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update a single app setting"""
    from .models import AppSetting, SettingsChangelog
    from .config import get_settings
    import json

    # Get existing setting
    stmt = select(AppSetting).where(AppSetting.key == key)
    result = await db.execute(stmt)
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")

    # Validate value based on type
    try:
        if setting.value_type == 'int':
            int(update.value)
        elif setting.value_type == 'json':
            json.loads(update.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid value for type {setting.value_type}: {e}")

    # Log change
    old_value = setting.value
    changelog = SettingsChangelog(
        setting_key=key,
        old_value=old_value,
        new_value=update.value,
        change_type='app_setting',
        requires_restart=setting.requires_restart
    )
    db.add(changelog)

    # Update setting
    setting.value = update.value
    setting.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(setting)

    # Reload settings cache
    await get_settings(force_reload=True)

    return {
        "message": "Setting updated successfully",
        "setting": setting.to_dict(),
        "requires_restart": setting.requires_restart
    }


# Pi-hole server endpoints
@app.get("/api/settings/pihole-servers")
async def get_pihole_servers(db: AsyncSession = Depends(get_db)):
    """Get all Pi-hole servers"""
    from .models import PiholeServerModel

    stmt = select(PiholeServerModel).order_by(PiholeServerModel.display_order, PiholeServerModel.id)
    result = await db.execute(stmt)
    servers = [server.to_dict() for server in result.scalars()]

    return {"servers": servers}


@app.post("/api/settings/pihole-servers")
async def create_pihole_server(
    server_data: PiholeServerCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new Pi-hole server"""
    from .models import PiholeServerModel, SettingsChangelog
    from .config import get_settings

    # Check for duplicate name
    stmt = select(PiholeServerModel).where(PiholeServerModel.name == server_data.name)
    existing = await db.execute(stmt)
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Server with this name already exists")

    # Get max display order with row lock to prevent race condition
    stmt = (
        select(PiholeServerModel.display_order)
        .order_by(PiholeServerModel.display_order.desc())
        .limit(1)
        .with_for_update()
    )
    result = await db.execute(stmt)
    last_server = result.scalar_one_or_none()
    max_order = last_server if last_server is not None else 0

    # If setting this as source, unset any existing source (with row lock to prevent race condition)
    if server_data.is_source:
        stmt = (
            select(PiholeServerModel)
            .where(PiholeServerModel.is_source == True)
            .with_for_update()  # Row-level lock
        )
        result = await db.execute(stmt)
        for existing_source in result.scalars():
            existing_source.is_source = False

    # Create server
    server = PiholeServerModel(
        name=server_data.name,
        url=server_data.url,
        password=server_data.password,
        server_type=server_data.server_type,
        enabled=server_data.enabled,
        is_source=server_data.is_source,
        sync_enabled=server_data.sync_enabled,
        display_order=max_order + 1
    )
    db.add(server)

    # Log change
    changelog = SettingsChangelog(
        setting_key=f"pihole_server.{server_data.name}",
        new_value=server_data.url,
        change_type='pihole_server',
        requires_restart=False
    )
    db.add(changelog)

    await db.commit()
    await db.refresh(server)

    # Reload settings
    await get_settings(force_reload=True)

    return {"message": "Server created", "server": server.to_dict()}


@app.put("/api/settings/pihole-servers/{server_id}")
async def update_pihole_server(
    server_id: int,
    server_data: PiholeServerUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update Pi-hole server"""
    from .models import PiholeServerModel, SettingsChangelog
    from .config import get_settings

    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    # Update fields
    update_data = server_data.model_dump(exclude_unset=True)

    # Don't update password if it's empty or masked (security: password never sent to frontend)
    if 'password' in update_data and (not update_data['password'] or update_data['password'] == '********'):
        del update_data['password']

    # If setting this as source, unset any existing source (with row lock to prevent race condition)
    if update_data.get('is_source'):
        stmt = (
            select(PiholeServerModel)
            .where(
                PiholeServerModel.is_source == True,
                PiholeServerModel.id != server_id
            )
            .with_for_update()  # Row-level lock
        )
        result = await db.execute(stmt)
        for existing_source in result.scalars():
            existing_source.is_source = False

    for key, value in update_data.items():
        setattr(server, key, value)

    server.updated_at = datetime.now(timezone.utc)

    # Log change
    changelog = SettingsChangelog(
        setting_key=f"pihole_server.{server.name}",
        change_type='pihole_server',
        requires_restart=False
    )
    db.add(changelog)

    await db.commit()
    await db.refresh(server)

    # Reload settings
    await get_settings(force_reload=True)

    return {"message": "Server updated", "server": server.to_dict()}


@app.delete("/api/settings/pihole-servers/{server_id}")
async def delete_pihole_server(
    server_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete Pi-hole server"""
    from .models import PiholeServerModel, SettingsChangelog
    from .config import get_settings

    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    server_name = server.name

    # Log deletion
    changelog = SettingsChangelog(
        setting_key=f"pihole_server.{server_name}",
        old_value=server.url,
        change_type='pihole_server',
        requires_restart=False
    )
    db.add(changelog)

    await db.delete(server)
    await db.commit()

    # Reload settings
    await get_settings(force_reload=True)

    return {"message": "Server deleted"}


@app.post("/api/settings/pihole-servers/test")
async def test_pihole_connection(server_data: PiholeServerCreate):
    """Test connection to a Pi-hole server"""
    from .pihole_client import PiholeClient
    import logging

    logger = logging.getLogger(__name__)

    try:
        # Use context manager for proper resource cleanup
        async with PiholeClient(
            url=server_data.url,
            password=server_data.password,
            server_name=server_data.name
        ) as client:
            # Try to authenticate - this will verify the connection and credentials work
            auth_success = await client.authenticate()
            if auth_success:
                return {
                    "success": True,
                    "message": f"Successfully connected to Pi-hole at {server_data.url}"
                }
            else:
                return {
                    "success": False,
                    "message": "Authentication failed. Please check your password."
                }
    except Exception as e:
        # Log detailed error server-side for debugging
        logger.error(f"Pi-hole connection test failed for {server_data.url}: {e}", exc_info=True)

        # Return sanitized error messages to client
        error_msg = str(e).lower()
        if "authentication" in error_msg or "401" in error_msg:
            return {
                "success": False,
                "message": "Authentication failed. Please check your password."
            }
        elif "connect" in error_msg or "refused" in error_msg or "timeout" in error_msg:
            return {
                "success": False,
                "message": "Cannot connect to the Pi-hole server. Please check the URL and network connectivity."
            }
        else:
            return {
                "success": False,
                "message": "Connection test failed. Please check your configuration and try again."
            }


@app.post("/api/settings/telegram/test")
async def test_telegram_connection(data: TelegramTestData):
    """Test Telegram bot connection"""
    from telegram import Bot
    from telegram.error import TelegramError

    # Pydantic validation handles empty checks
    bot_token = data.bot_token
    chat_id = data.chat_id

    bot = None
    try:
        bot = Bot(token=bot_token)
        # Convert chat_id to integer (Telegram API requires int)
        chat_id_int = int(chat_id)
        # Try to send a test message
        await bot.send_message(
            chat_id=chat_id_int,
            text="✓ DNSMon test connection successful! Your Telegram notifications are configured correctly.",
            parse_mode='HTML'
        )
        return {
            "success": True,
            "message": f"Successfully sent test message to chat {chat_id}"
        }
    except TelegramError as e:
        error_msg = str(e)
        if "Unauthorized" in error_msg or "token" in error_msg.lower():
            return {
                "success": False,
                "message": "Invalid bot token. Please check your token."
            }
        elif "chat not found" in error_msg.lower() or "CHAT_ID_INVALID" in error_msg:
            return {
                "success": False,
                "message": "Invalid chat ID. Please check your chat ID."
            }
        else:
            # Log detailed error server-side, return generic message
            logger.error(f"Telegram test failed with error: {error_msg}", exc_info=True)
            return {
                "success": False,
                "message": "Telegram connection test failed. Please verify your bot token and chat ID."
            }
    except Exception as e:
        # Log detailed error server-side
        logger.error(f"Telegram test failed with exception: {e}", exc_info=True)
        return {
            "success": False,
            "message": "Connection test failed. Please check your configuration and try again."
        }
    finally:
        # Clean up bot resources
        if bot:
            try:
                await bot.shutdown()
            except Exception:
                pass  # Ignore cleanup errors


# Rate limiting for restart endpoint to prevent abuse
_last_restart_time: Optional[float] = None
_restart_cooldown_seconds = 30


@app.post("/api/settings/restart")
async def trigger_restart():
    """Trigger container restart with rate limiting to prevent DoS"""
    import signal
    import asyncio
    import time

    global _last_restart_time

    # Rate limiting: only allow restart once every 30 seconds
    current_time = time.time()
    if _last_restart_time and (current_time - _last_restart_time) < _restart_cooldown_seconds:
        remaining = int(_restart_cooldown_seconds - (current_time - _last_restart_time))
        raise HTTPException(
            status_code=429,
            detail=f"Restart rate limited. Please wait {remaining} seconds before restarting again."
        )

    _last_restart_time = current_time
    logger.info("Restart requested via API - sending SIGTERM to self")

    # Schedule restart after response is sent
    async def delayed_restart():
        await asyncio.sleep(1)  # Give time for response to be sent
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(delayed_restart())

    return {
        "message": "Container restart initiated",
        "note": "Application will restart in 1 second"
    }


# ========== Pi-hole Sync Endpoints ==========

@app.get("/api/sync/preview")
async def get_sync_preview():
    """Preview what would be synced from source to targets"""
    from .sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    preview = await sync_service.get_sync_preview()

    if not preview:
        raise HTTPException(
            status_code=400,
            detail="No source server configured or unable to fetch configuration"
        )

    return preview


@app.post("/api/sync/execute")
async def execute_sync():
    """Execute configuration sync from source to targets"""
    from .sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    sync_history_id = await sync_service.execute_sync(sync_type='manual')

    if not sync_history_id:
        raise HTTPException(
            status_code=400,
            detail="Sync failed. Check logs for details."
        )

    return {
        "message": "Sync completed",
        "sync_history_id": sync_history_id
    }


@app.get("/api/sync/history")
async def get_sync_history(limit: int = QueryParam(20, ge=1, le=100)):
    """Get recent sync history"""
    from .sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    history = await sync_service.get_sync_history(limit=limit)

    return {"history": history}


# ========== Domain Management Endpoints ==========

class DomainRequest(BaseModel):
    domain: str = PydanticField(min_length=1, max_length=255)

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain is not empty and strip whitespace"""
        v = v.strip()
        if not v:
            raise ValueError("Domain cannot be empty")
        return v


async def get_source_client():
    """Helper to get authenticated client for source Pi-hole"""
    from .database import async_session_maker
    from .models import PiholeServerModel

    async with async_session_maker() as session:
        stmt = select(PiholeServerModel).where(
            PiholeServerModel.is_source == True,
            PiholeServerModel.enabled == True
        )
        result = await session.execute(stmt)
        source = result.scalar_one_or_none()

        if not source:
            raise HTTPException(status_code=400, detail="No source Pi-hole server configured")

        return source.url, source.password, source.name


@app.get("/api/domains/whitelist")
async def get_whitelist():
    """Get all whitelist entries from source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        domains = await client.get_whitelist()
        return {"domains": domains}


@app.post("/api/domains/whitelist")
async def add_to_whitelist(data: DomainRequest):
    """Add a domain to whitelist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.add_to_whitelist(data.domain)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add domain to whitelist")
        return {"message": f"Added {data.domain} to whitelist"}


@app.delete("/api/domains/whitelist/{domain:path}")
async def remove_from_whitelist(domain: str):
    """Remove a domain from whitelist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.remove_from_whitelist(domain)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove domain from whitelist")
        return {"message": f"Removed {domain} from whitelist"}


@app.get("/api/domains/blacklist")
async def get_blacklist():
    """Get all blacklist entries from source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        domains = await client.get_blacklist()
        return {"domains": domains}


@app.post("/api/domains/blacklist")
async def add_to_blacklist(data: DomainRequest):
    """Add a domain to blacklist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.add_to_blacklist(data.domain)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add domain to blacklist")
        return {"message": f"Added {data.domain} to blacklist"}


@app.delete("/api/domains/blacklist/{domain:path}")
async def remove_from_blacklist(domain: str):
    """Remove a domain from blacklist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.remove_from_blacklist(domain)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove domain from blacklist")
        return {"message": f"Removed {domain} from blacklist"}


@app.get("/api/domains/regex-whitelist")
async def get_regex_whitelist():
    """Get all regex whitelist entries from source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        domains = await client.get_regex_whitelist()
        return {"domains": domains}


@app.delete("/api/domains/regex-whitelist/{pattern_id}")
async def remove_from_regex_whitelist(pattern_id: int):
    """Remove a pattern from regex whitelist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.remove_from_regex_whitelist(pattern_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove pattern from regex whitelist")
        return {"message": f"Removed pattern {pattern_id} from regex whitelist"}


@app.get("/api/domains/regex-blacklist")
async def get_regex_blacklist():
    """Get all regex blacklist entries from source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        domains = await client.get_regex_blacklist()
        return {"domains": domains}


@app.delete("/api/domains/regex-blacklist/{pattern_id}")
async def remove_from_regex_blacklist(pattern_id: int):
    """Remove a pattern from regex blacklist on source Pi-hole"""
    from .pihole_client import PiholeClient

    url, password, name = await get_source_client()
    async with PiholeClient(url, password, name) as client:
        if not await client.authenticate():
            raise HTTPException(status_code=500, detail="Failed to authenticate with source Pi-hole")
        success = await client.remove_from_regex_blacklist(pattern_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove pattern from regex blacklist")
        return {"message": f"Removed pattern {pattern_id} from regex blacklist"}


# ========== Blocking Control Endpoints ==========

class BlockingSetRequest(BaseModel):
    enabled: bool
    duration_minutes: Optional[int] = PydanticField(default=None, ge=1, le=1440)  # 1 min to 24 hours


@app.get("/api/blocking/status")
async def get_blocking_status(db: AsyncSession = Depends(get_db)):
    """Get blocking status for all enabled Pi-hole servers"""
    from .models import PiholeServerModel, BlockingOverride
    from .pihole_client import PiholeClient

    # Get all enabled servers
    stmt = select(PiholeServerModel).where(
        PiholeServerModel.enabled == True
    ).order_by(PiholeServerModel.display_order)
    result = await db.execute(stmt)
    servers = result.scalars().all()

    if not servers:
        return {"servers": []}

    # Get pending blocking overrides (auto_enable_at set, enabled_at is null)
    override_stmt = select(BlockingOverride).where(
        BlockingOverride.enabled_at.is_(None)
    )
    override_result = await db.execute(override_stmt)
    overrides = {o.server_id: o for o in override_result.scalars()}

    statuses = []
    for server in servers:
        try:
            async with PiholeClient(server.url, server.password, server.name) as client:
                if await client.authenticate():
                    blocking = await client.get_blocking_status()
                    override = overrides.get(server.id)
                    statuses.append({
                        "id": server.id,
                        "name": server.name,
                        "blocking": blocking,
                        "auto_enable_at": override.auto_enable_at.isoformat() if override and override.auto_enable_at else None
                    })
                else:
                    statuses.append({
                        "id": server.id,
                        "name": server.name,
                        "blocking": None,
                        "auto_enable_at": None,
                        "error": "Authentication failed"
                    })
        except Exception as e:
            logger.error(f"Error getting blocking status from {server.name}: {e}")
            statuses.append({
                "id": server.id,
                "name": server.name,
                "blocking": None,
                "auto_enable_at": None,
                "error": str(e)
            })

    return {"servers": statuses}


@app.post("/api/blocking/{server_id}")
async def set_blocking_for_server(server_id: int, data: BlockingSetRequest, db: AsyncSession = Depends(get_db)):
    """Enable or disable blocking for a specific Pi-hole server"""
    from .models import PiholeServerModel, BlockingOverride
    from .pihole_client import PiholeClient

    # Get server
    stmt = select(PiholeServerModel).where(PiholeServerModel.id == server_id)
    result = await db.execute(stmt)
    server = result.scalar_one_or_none()

    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    if not server.enabled:
        raise HTTPException(status_code=400, detail="Server is disabled")

    # Calculate timer in seconds if duration provided
    timer_seconds = data.duration_minutes * 60 if data.duration_minutes and not data.enabled else None

    try:
        async with PiholeClient(server.url, server.password, server.name) as client:
            if not await client.authenticate():
                raise HTTPException(status_code=500, detail=f"Failed to authenticate with {server.name}")

            success = await client.set_blocking(data.enabled, timer_seconds)
            if not success:
                raise HTTPException(status_code=500, detail=f"Failed to set blocking on {server.name}")

            # Track blocking override in database
            if not data.enabled:
                # Clear any existing pending overrides for this server
                existing_stmt = select(BlockingOverride).where(
                    BlockingOverride.server_id == server_id,
                    BlockingOverride.enabled_at.is_(None)
                )
                existing_result = await db.execute(existing_stmt)
                for existing in existing_result.scalars():
                    existing.enabled_at = datetime.now(timezone.utc)

                # Create new override record
                auto_enable_at = None
                if data.duration_minutes:
                    auto_enable_at = datetime.now(timezone.utc) + timedelta(minutes=data.duration_minutes)

                override = BlockingOverride(
                    server_id=server_id,
                    auto_enable_at=auto_enable_at,
                    disabled_by='user'
                )
                db.add(override)
                await db.commit()

                return {
                    "success": True,
                    "server_id": server_id,
                    "blocking": False,
                    "auto_enable_at": auto_enable_at.isoformat() if auto_enable_at else None
                }
            else:
                # Mark any pending overrides as completed
                existing_stmt = select(BlockingOverride).where(
                    BlockingOverride.server_id == server_id,
                    BlockingOverride.enabled_at.is_(None)
                )
                existing_result = await db.execute(existing_stmt)
                for existing in existing_result.scalars():
                    existing.enabled_at = datetime.now(timezone.utc)
                await db.commit()

                return {
                    "success": True,
                    "server_id": server_id,
                    "blocking": True,
                    "auto_enable_at": None
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting blocking for {server.name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/blocking/all")
async def set_blocking_for_all(data: BlockingSetRequest, db: AsyncSession = Depends(get_db)):
    """Enable or disable blocking for all enabled Pi-hole servers"""
    from .models import PiholeServerModel, BlockingOverride
    from .pihole_client import PiholeClient

    # Get all enabled servers
    stmt = select(PiholeServerModel).where(
        PiholeServerModel.enabled == True
    ).order_by(PiholeServerModel.display_order)
    result = await db.execute(stmt)
    servers = result.scalars().all()

    if not servers:
        return {"success": True, "results": []}

    timer_seconds = data.duration_minutes * 60 if data.duration_minutes and not data.enabled else None
    auto_enable_at = None
    if data.duration_minutes and not data.enabled:
        auto_enable_at = datetime.now(timezone.utc) + timedelta(minutes=data.duration_minutes)

    results = []
    for server in servers:
        try:
            async with PiholeClient(server.url, server.password, server.name) as client:
                if not await client.authenticate():
                    results.append({
                        "server_id": server.id,
                        "name": server.name,
                        "success": False,
                        "error": "Authentication failed"
                    })
                    continue

                success = await client.set_blocking(data.enabled, timer_seconds)

                if success:
                    # Track blocking override
                    if not data.enabled:
                        # Clear existing pending overrides
                        existing_stmt = select(BlockingOverride).where(
                            BlockingOverride.server_id == server.id,
                            BlockingOverride.enabled_at.is_(None)
                        )
                        existing_result = await db.execute(existing_stmt)
                        for existing in existing_result.scalars():
                            existing.enabled_at = datetime.now(timezone.utc)

                        # Create new override
                        override = BlockingOverride(
                            server_id=server.id,
                            auto_enable_at=auto_enable_at,
                            disabled_by='user'
                        )
                        db.add(override)
                    else:
                        # Mark pending overrides as completed
                        existing_stmt = select(BlockingOverride).where(
                            BlockingOverride.server_id == server.id,
                            BlockingOverride.enabled_at.is_(None)
                        )
                        existing_result = await db.execute(existing_stmt)
                        for existing in existing_result.scalars():
                            existing.enabled_at = datetime.now(timezone.utc)

                results.append({
                    "server_id": server.id,
                    "name": server.name,
                    "success": success,
                    "blocking": data.enabled if success else None
                })

        except Exception as e:
            logger.error(f"Error setting blocking for {server.name}: {e}")
            results.append({
                "server_id": server.id,
                "name": server.name,
                "success": False,
                "error": str(e)
            })

    await db.commit()

    return {
        "success": all(r["success"] for r in results),
        "results": results,
        "auto_enable_at": auto_enable_at.isoformat() if auto_enable_at else None
    }


@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint with database connectivity verification"""
    try:
        # Verify database connectivity
        await db.execute(select(1))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail="Database unavailable")


# Serve React frontend in production
if os.path.exists("/app/frontend/build"):
    # Mount static files (JS, CSS, etc.)
    app.mount("/assets", StaticFiles(directory="/app/frontend/build/assets"), name="assets")

    # Catch-all route for React Router - must be last
    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        """Serve React app for all non-API routes with path traversal protection"""
        from pathlib import Path

        # If it's a file request (has extension), try to serve it
        if "." in full_path.split("/")[-1]:
            # Prevent path traversal attacks
            base_path = Path("/app/frontend/build").resolve()
            requested_path = (base_path / full_path).resolve()

            # Ensure the resolved path is within the base directory
            try:
                requested_path.relative_to(base_path)
            except ValueError:
                # Path is outside base directory - potential attack
                raise HTTPException(status_code=404, detail="File not found")

            if requested_path.exists() and requested_path.is_file():
                return FileResponse(str(requested_path))

        # Otherwise, serve index.html for React Router
        return FileResponse("/app/frontend/build/index.html")
