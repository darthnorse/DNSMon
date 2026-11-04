"""
Passive DNS lookups: which domains resolved to an IP and which devices looked them up,
and which IPs and CNAMEs a domain resolved to, from the answers stored on queries.
"""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Row, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..geoip import get_geoip
from ..models import Query, User
from ..schemas import (
    PdnsClientRow, PdnsCnameRow, PdnsDomainResponse, PdnsDomainRow, PdnsIpResponse, PdnsIpRow,
    PdnsResolveRequest, PdnsResolveResponse, PdnsResolveResult, require_resolvable_time,
)
from ..utils import ensure_utc, normalize_domain, require_ip
from .stats import _parse_iso_date, time_range_conditions

router = APIRouter(prefix="/api/pdns", tags=["pdns"])

PDNS_ROW_LIMIT = 500
RESOLVE_CONCURRENT_BATCHES = 4
_batch_slots = asyncio.Semaphore(RESOLVE_CONCURRENT_BATCHES)
LOOKUP_VIEW_CONCURRENCY = 4
_lookup_view_slots = asyncio.Semaphore(LOOKUP_VIEW_CONCURRENCY)


@asynccontextmanager
async def _limited(db: AsyncSession, slots: asyncio.Semaphore):
    """Auth's read left this request's session holding a pooled connection. Queued requests must
    give it back first, or the queue itself exhausts the pool the limit exists to protect."""
    await db.commit()
    async with slots:
        yield


def _parse_ip(value: str) -> str:
    try:
        return require_ip(value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def parse_domain(value: str) -> str:
    domain = normalize_domain(value)
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
    where = [Query.answer_ips.contains([ip]), *time_range_conditions(Query.timestamp, from_date, to_date)]
    async with _limited(db, _lookup_view_slots):
        return await _ip_view(db, ip, where)


async def _ip_view(db: AsyncSession, ip: str, where: List) -> PdnsIpResponse:
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
        select(Query.client_ip, func.count(), last_seen)
        .where(*where).group_by(Query.client_ip).order_by(last_seen.desc()).limit(PDNS_ROW_LIMIT)
    )).all()
    hostnames = dict((await db.execute(
        select(Query.client_ip, Query.client_hostname)
        .where(*where, Query.client_hostname != "", Query.client_ip.in_([c for c, _, _ in clients]))
        .distinct(Query.client_ip).order_by(Query.client_ip, Query.timestamp.desc())
    )).all())

    return PdnsIpResponse(
        ip=ip,
        domains=[PdnsDomainRow(domain=d, first_seen=ensure_utc(first), last_seen=ensure_utc(last),
                               count=int(n), servers=sorted(servers)) for d, first, last, n, servers in domains],
        clients=[PdnsClientRow(client_ip=c, client_hostname=hostnames.get(c), count=n, last_seen=ensure_utc(last))
                 for c, n, last in clients],
        geo=get_geoip().lookup(ip),
    )


@router.get("/domain/{domain}", response_model=PdnsDomainResponse)
async def lookup_domain(
    domain: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    domain = parse_domain(domain)
    where = [Query.domain == domain, Query.answer_ips.is_not(None),
             *time_range_conditions(Query.timestamp, from_date, to_date)]

    async def grouped(column) -> list:
        answers = select(func.unnest(column).label("value"), Query.timestamp).where(*where).subquery()
        last_seen = func.max(answers.c.timestamp)
        return (await db.execute(
            select(answers.c.value, func.min(answers.c.timestamp), last_seen, func.count())
            .group_by(answers.c.value).order_by(last_seen.desc(), func.count().desc()).limit(PDNS_ROW_LIMIT)
        )).all()

    async with _limited(db, _lookup_view_slots):
        ips = await grouped(Query.answer_ips)
        cnames = await grouped(Query.answer_cnames)
        has_answer_data = bool(ips or cnames) or (await db.execute(
            select(Query.id).where(*where).limit(1))).first() is not None

    geo = get_geoip()
    return PdnsDomainResponse(
        domain=domain,
        ips=[PdnsIpRow(ip=str(ip), first_seen=ensure_utc(first), last_seen=ensure_utc(last), count=n,
                    geo=geo.lookup(str(ip)))
             for ip, first, last, n in ips],
        cnames=[PdnsCnameRow(cname=c, first_seen=ensure_utc(first), last_seen=ensure_utc(last), count=n)
                for c, first, last, n in cnames],
        has_answer_data=has_answer_data,
    )


class _NewestLookups:
    """The newest lookup at or before a time whose answer contained an IP. A row found as of time T
    also answers every earlier time back to its own timestamp, so connections to one IP share a
    query, which a batch only benefits from when served newest `at` first."""

    def __init__(self, db: AsyncSession):
        self._db = db
        self._known: dict[tuple[str, Optional[str]], tuple[datetime, Optional[Row]]] = {}

    async def get(self, ip: str, client: Optional[str], at: datetime) -> Optional[Row]:
        known = self._known.get((ip, client))
        if known:
            as_of, row = known
            if at <= as_of and (row is None or at >= row.timestamp):
                return row
        stmt = (select(Query.domain, Query.timestamp, Query.server, Query.client_ip, Query.answer_cnames)
                .where(Query.answer_ips.contains([ip]), Query.timestamp <= at)
                .order_by(Query.timestamp.desc()).limit(1))
        if client:
            stmt = stmt.where(Query.client_ip == client)
        row = (await self._db.execute(stmt)).first()
        self._known[(ip, client)] = (at, row)
        return row


async def _resolve(lookups: _NewestLookups, client: Optional[str], ip: str, at: datetime) -> PdnsResolveResult:
    """The newest lookup at or before `at` whose answer contained `ip`: the client's own if it has
    one, else any device's. No lower time bound: a long-lived connection can be days old, and the
    lookup that opened it is still its best explanation; age_seconds lets the caller judge."""
    geo = get_geoip().lookup(ip)
    for match, scope in ([("client", client)] if client else []) + [("any", None)]:
        row = await lookups.get(ip, scope, at)
        if row is not None:
            domain, ts, server, client_ip, cnames = row
            return PdnsResolveResult(
                match=match, domain=domain, query_time=ensure_utc(ts), age_seconds=int((at - ts).total_seconds()),
                server=server, client_ip=client_ip, cname_chain=cnames or [], geo=geo)
    return PdnsResolveResult(match="none", geo=geo)


@router.get("/resolve", response_model=PdnsResolveResult)
async def resolve_connection(
    ip: str,
    client: Optional[str] = None,
    at: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Name a connection: which domain did `client` look up that resolved to `ip`, as of `at`."""
    try:
        when = require_resolvable_time(_parse_iso_date(at, "at")) if at else datetime.now(timezone.utc)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    client, ip = _parse_ip(client) if client else None, _parse_ip(ip)
    async with _limited(db, _lookup_view_slots):
        return await _resolve(_NewestLookups(db), client, ip, when)


@router.post("/resolve", response_model=PdnsResolveResponse)
async def resolve_connections(
    request: PdnsResolveRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    async with _limited(db, _batch_slots):
        now = datetime.now(timezone.utc)
        whens = [item.at or now for item in request.items]
        lookups = _NewestLookups(db)
        results: List[Optional[PdnsResolveResult]] = [None] * len(whens)
        for i in sorted(range(len(whens)), key=whens.__getitem__, reverse=True):
            results[i] = await _resolve(lookups, request.items[i].client, request.items[i].ip, whens[i])
    return PdnsResolveResponse(results=results)
