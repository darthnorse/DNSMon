"""
Passive DNS lookups: which domains resolved to an IP and which devices looked them up,
and which IPs and CNAMEs a domain resolved to, from the answers stored on queries.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Query, User
from ..schemas import (
    PdnsClientRow, PdnsCnameRow, PdnsDomainResponse, PdnsDomainRow, PdnsIpResponse, PdnsIpRow,
    PdnsResolveRequest, PdnsResolveResponse, PdnsResolveResult,
)
from ..utils import ensure_utc, normalize_ip
from .stats import _parse_iso_date

router = APIRouter(prefix="/api/pdns", tags=["pdns"])

PDNS_ROW_LIMIT = 500
# netdash and DNSMon may run on different hosts; a slightly-ahead clock is not an error.
RESOLVE_CLOCK_SKEW = timedelta(minutes=5)


def _time_conditions(from_date: Optional[str], to_date: Optional[str]) -> List:
    conditions = []
    if from_date:
        conditions.append(Query.timestamp >= _parse_iso_date(from_date, "from_date"))
    if to_date:
        conditions.append(Query.timestamp <= _parse_iso_date(to_date, "to_date"))
    return conditions


def _parse_ip(value: str) -> str:
    ip = normalize_ip(value)
    if ip is None:
        raise HTTPException(status_code=400, detail=f"Not an IP address: {value[:64]}")
    return ip


def _parse_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 255:
        raise HTTPException(status_code=400, detail="Domain must be 1-255 characters")
    return domain


@router.get("/ip/{ip}", response_model=PdnsIpResponse)
async def lookup_ip(
    ip: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    ip = _parse_ip(ip)
    where = [Query.answer_ips.contains([ip]), *_time_conditions(from_date, to_date)]
    last_seen = func.max(Query.timestamp)

    # Grouping by (domain, server) first keeps the aggregate parallel-safe, which
    # array_agg(DISTINCT server) is not: 0.9 s vs 1.25 s for an IP in 500k rows
    # (scripts/bench-pdns.sql).
    per_server = (select(Query.domain, Query.server, func.min(Query.timestamp).label("first_seen"),
                         func.max(Query.timestamp).label("last_seen"), func.count().label("n"))
                  .where(*where).group_by(Query.domain, Query.server).subquery())
    domain_last_seen = func.max(per_server.c.last_seen)
    domains = (await db.execute(
        select(per_server.c.domain, func.min(per_server.c.first_seen), domain_last_seen,
               func.sum(per_server.c.n), func.array_agg(per_server.c.server))
        .group_by(per_server.c.domain).order_by(domain_last_seen.desc()).limit(PDNS_ROW_LIMIT)
    )).all()
    clients = (await db.execute(
        select(Query.client_ip, func.max(Query.client_hostname), func.count(), last_seen)
        .where(*where).group_by(Query.client_ip).order_by(last_seen.desc()).limit(PDNS_ROW_LIMIT)
    )).all()

    return PdnsIpResponse(
        ip=ip,
        domains=[PdnsDomainRow(domain=d, first_seen=ensure_utc(first), last_seen=ensure_utc(last),
                               count=int(n), servers=sorted(servers)) for d, first, last, n, servers in domains],
        clients=[PdnsClientRow(client_ip=c, client_hostname=host, count=n, last_seen=ensure_utc(last))
                 for c, host, n, last in clients],
    )


@router.get("/domain/{domain}", response_model=PdnsDomainResponse)
async def lookup_domain(
    domain: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    domain = _parse_domain(domain)
    where = [Query.domain == domain, Query.answer_ips.is_not(None), *_time_conditions(from_date, to_date)]

    async def grouped(column) -> list:
        answers = select(func.unnest(column).label("value"), Query.timestamp).where(*where).subquery()
        last_seen = func.max(answers.c.timestamp)
        return (await db.execute(
            select(answers.c.value, func.min(answers.c.timestamp), last_seen, func.count())
            .group_by(answers.c.value).order_by(last_seen.desc(), func.count().desc()).limit(PDNS_ROW_LIMIT)
        )).all()

    ips = await grouped(Query.answer_ips)
    cnames = await grouped(Query.answer_cnames)
    has_answer_data = bool(ips or cnames) or (await db.execute(
        select(Query.id).where(*where).limit(1))).first() is not None

    return PdnsDomainResponse(
        domain=domain,
        ips=[PdnsIpRow(ip=str(ip), first_seen=ensure_utc(first), last_seen=ensure_utc(last), count=n)
             for ip, first, last, n in ips],
        cnames=[PdnsCnameRow(cname=c, first_seen=ensure_utc(first), last_seen=ensure_utc(last), count=n)
                for c, first, last, n in cnames],
        has_answer_data=has_answer_data,
    )


def _resolve_at(at: Optional[datetime]) -> datetime:
    now = datetime.now(timezone.utc)
    if at is None:
        return now
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    if at > now + RESOLVE_CLOCK_SKEW:
        raise HTTPException(status_code=400, detail="'at' is in the future")
    return at


async def _resolve(db: AsyncSession, client: Optional[str], ip: str, at: datetime) -> PdnsResolveResult:
    """The newest lookup at or before `at` whose answer contained `ip`: the client's own if it has
    one, else any device's. No lower time bound: a long-lived connection can be days old, and the
    lookup that opened it is still its best explanation; age_seconds lets the caller judge."""
    newest = (select(Query.domain, Query.timestamp, Query.server, Query.client_ip, Query.answer_cnames)
              .where(Query.answer_ips.contains([ip]), Query.timestamp <= at)
              .order_by(Query.timestamp.desc()).limit(1))
    candidates = ([("client", newest.where(Query.client_ip == client))] if client else []) + [("any", newest)]
    for match, stmt in candidates:
        row = (await db.execute(stmt)).first()
        if row is not None:
            domain, ts, server, client_ip, cnames = row
            return PdnsResolveResult(
                match=match, domain=domain, query_time=ensure_utc(ts), age_seconds=int((at - ts).total_seconds()),
                server=server, client_ip=client_ip, cname_chain=cnames or [])
    return PdnsResolveResult(match="none")


@router.get("/resolve", response_model=PdnsResolveResult)
async def resolve_connection(
    ip: str,
    client: Optional[str] = None,
    at: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Name a connection: which domain did `client` look up that resolved to `ip`, as of `at`."""
    when = _resolve_at(_parse_iso_date(at, "at") if at else None)
    return await _resolve(db, _parse_ip(client) if client else None, _parse_ip(ip), when)


@router.post("/resolve", response_model=PdnsResolveResponse)
async def resolve_connections(
    request: PdnsResolveRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return PdnsResolveResponse(results=[
        await _resolve(db, item.client, item.ip, _resolve_at(item.at)) for item in request.items])
