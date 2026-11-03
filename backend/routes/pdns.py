"""
Passive DNS lookups: which domains resolved to an IP and which devices looked them up,
and which IPs and CNAMEs a domain resolved to, from the answers stored on queries.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Query, User
from ..schemas import (
    PdnsClientRow, PdnsCnameRow, PdnsDomainResponse, PdnsDomainRow, PdnsIpResponse, PdnsIpRow,
)
from ..utils import ensure_utc, normalize_ip
from .stats import _parse_iso_date

router = APIRouter(prefix="/api/pdns", tags=["pdns"])

PDNS_ROW_LIMIT = 500


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

    domains = (await db.execute(
        select(Query.domain, func.min(Query.timestamp), last_seen, func.count(),
               func.array_agg(distinct(Query.server)))
        .where(*where).group_by(Query.domain).order_by(last_seen.desc()).limit(PDNS_ROW_LIMIT)
    )).all()
    clients = (await db.execute(
        select(Query.client_ip, func.max(Query.client_hostname), func.count(), last_seen)
        .where(*where).group_by(Query.client_ip).order_by(last_seen.desc()).limit(PDNS_ROW_LIMIT)
    )).all()

    return PdnsIpResponse(
        ip=ip,
        domains=[PdnsDomainRow(domain=d, first_seen=ensure_utc(first), last_seen=ensure_utc(last),
                               count=n, servers=sorted(servers)) for d, first, last, n, servers in domains],
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
