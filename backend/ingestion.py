import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict

from sqlalchemy import select, func, text, update, BigInteger
from sqlalchemy.dialects.postgresql import insert

from .models import Query, QueryStatsHourly, ClientStatsHourly, DomainStatsHourly, PiholeServerModel
from .database import async_session_maker, cleanup_old_queries
from .utils import create_client_from_server, normalize_domain
from .config import get_settings_sync, PiholeServer
from .dns_client import QueryFetchError, QueryRangeTruncated
from .geoip import get_geoip
from .constants import BLOCKED_STATUSES, CACHE_STATUSES, BLOCKED_SQL_IN, CACHE_SQL_IN

logger = logging.getLogger(__name__)


# Re-read this much before the resume point: a query can land in the server's log
# after a poll whose range already covered its timestamp. Duplicates are dropped
# by the queries unique key.
RESUME_OVERLAP_SECONDS = 5

SERVER_CHECK_SECONDS = 900
# Well inside the default max_catchup_seconds (300 s), past which a server's queries count
# as backlog and stop alerting.
CLOCK_DRIFT_WARNING_SECONDS = 60

POSTGRES_MAX_BIND_PARAMS = 32767


@dataclass
class IngestedQuery:
    """Lightweight query object for alert checking (avoids DB round-trip)"""
    id: int
    domain: str
    client_ip: str
    client_hostname: str | None
    timestamp: datetime
    query_type: str
    status: str
    server: str
    answer_ips: Optional[List[str]] = None
    answer_countries: Optional[List[str]] = None


class QueryIngestionService:
    """Service for ingesting DNS queries from Pi-hole servers"""

    def __init__(self):
        self.settings = get_settings_sync()
        self._server_checked_at: dict[str, float] = {}
        self._in_flight: dict[str, asyncio.Task[Tuple[int, List[IngestedQuery]]]] = {}
        # From the interval the scheduler started with: a changed setting waits for a restart
        # there, and following it here could hold the job for far longer than a tick.
        self._poll_wait_seconds = self.settings.poll_interval_seconds / 2
        self._long_walk_until: dict[str, int] = {}

    def _catchup_floor(self, now: int) -> int:
        return now - self.settings.max_catchup_seconds

    def _alert_floor(self, server_name: str, now: int) -> int:
        """Queries older than this are backlog. A walk that outlasted the catch-up window froze its
        range when it started, so what clients did during it is live traffic, not outage backlog.
        Only the next poll gets the wider floor, so an outage after that still can't burst."""
        floor = self._catchup_floor(now)
        walk_until = self._long_walk_until.pop(server_name, None)
        return floor if walk_until is None else min(floor, walk_until - RESUME_OVERLAP_SECONDS)

    async def _resume_point(self, server: PiholeServer, supports_gap_recovery: bool, now: int) -> int:
        """Where the next fetch starts: the cursor, else the newest stored query, else the lookback window."""
        async with async_session_maker() as session:
            cursor = None
            if server.id is not None:
                cursor = (await session.execute(
                    select(PiholeServerModel.ingested_until).where(PiholeServerModel.id == server.id)
                )).scalar_one_or_none()
            if cursor is not None:
                start = int(cursor.timestamp())
            else:
                newest = (await session.execute(
                    select(func.floor(func.extract('epoch', func.max(Query.timestamp))).cast(BigInteger))
                    .where(Query.server == server.name)
                )).scalar()
                start = int(newest) if newest else now - self.settings.query_lookback_seconds

        start -= RESUME_OVERLAP_SECONDS
        floor = self._catchup_floor(now)
        if not supports_gap_recovery and start < floor:
            logger.warning(
                f"Last ingest for {server.name} was {now - start}s ago, capping lookback to "
                f"{self.settings.max_catchup_seconds}s (some queries may be missed)")
            return floor
        return start

    async def _advance_cursor(self, server: PiholeServer, to: datetime, only_if_unset: bool = False) -> None:
        """Move the cursor forward to `to`, never back. With only_if_unset, pin a starting point
        before the first page is stored, so a failed first fetch can't fall back to that page's
        newest row and skip everything older."""
        if server.id is None:
            return
        # Naming updated_at stops its onupdate firing: it records config changes, not polls.
        stmt = update(PiholeServerModel).where(PiholeServerModel.id == server.id).values(
            updated_at=PiholeServerModel.updated_at)
        if only_if_unset:
            stmt = stmt.where(PiholeServerModel.ingested_until.is_(None)).values(ingested_until=to)
        else:
            stmt = stmt.values(ingested_until=func.greatest(PiholeServerModel.ingested_until, to))
        async with async_session_maker() as session:
            await session.execute(stmt)
            await session.commit()

    async def _check_server(self, client, server_name: str, now: int) -> None:
        if now - self._server_checked_at.get(server_name, 0) < SERVER_CHECK_SECONDS:
            return
        self._server_checked_at[server_name] = now
        warning = await client.query_log_warning()
        if warning:
            logger.warning(f"{server_name}: {warning}")
        drift = await client.clock_drift_seconds()
        if drift is not None and abs(drift) >= CLOCK_DRIFT_WARNING_SECONDS:
            direction = "behind" if drift < 0 else "ahead of"
            logger.warning(f"{server_name}: clock is {abs(drift)}s {direction} DNSMon's, which can stop "
                           f"alerts and lose queries; check NTP on both")

    async def ingest_from_server(self, server: PiholeServer) -> Tuple[int, List[IngestedQuery]]:
        """Ingest one server's queries since its resume point.

        Returns (stored count, the stored queries recent enough to alert on). Older
        backlog recovered after an outage is stored and counted in the hourly stats
        but never alerted on, so an outage doesn't end in a burst of stale alerts.
        Queries made during a long recovery walk aren't backlog, and do alert.

        The cursor follows the newest query the server returned, in the server's own
        clock, so clock skew between DNSMon and the server can't open a gap.
        """
        if not server.enabled:
            logger.debug(f"Server {server.name} is disabled, skipping")
            return 0, []

        total = 0
        alertable: List[IngestedQuery] = []
        now = int(time.time())
        try:
            alert_floor = datetime.fromtimestamp(self._alert_floor(server.name, now), tz=timezone.utc)
            backlog = 0
            newest_seen: Optional[datetime] = None

            client = create_client_from_server(server)
            async with client:
                if not await client.authenticate():
                    logger.error(f"Failed to authenticate with {server.name}")
                    return 0, []

                await self._check_server(client, server.name, now)
                from_timestamp = await self._resume_point(server, client.supports_gap_recovery, now)
                await self._advance_cursor(
                    server, datetime.fromtimestamp(from_timestamp + RESUME_OVERLAP_SECONDS, tz=timezone.utc),
                    only_if_unset=True)
                logger.info(f"Ingesting queries from {server.name} (from {from_timestamp} to {now})")

                try:
                    async for page in client.iter_query_pages(from_timestamp, now):
                        count, stored = await self._store_queries(page, server.name)
                        total += count
                        await self.update_hourly_stats(stored)
                        recent = [q for q in stored if q.timestamp >= alert_floor]
                        backlog += len(stored) - len(recent)
                        alertable.extend(recent)
                        times = [q["timestamp"] for q in page if isinstance(q.get("timestamp"), datetime)]
                        if times:
                            newest_seen = max([newest_seen, *times] if newest_seen else times)
                            # Otherwise a failure repeating partway through would re-walk the same
                            # pages every poll and never reach newer rows, which come last.
                            if client.pages_oldest_first:
                                await self._advance_cursor(server, newest_seen)
                except QueryRangeTruncated as e:
                    logger.warning(str(e))
                except QueryFetchError as e:
                    logger.error(f"Ingesting {server.name} stopped mid-range ({e}); retrying the range next poll")
                    return total, alertable

            if newest_seen is not None:
                await self._advance_cursor(server, newest_seen)
            if backlog:
                logger.warning(
                    f"Recovered {backlog} queries for {server.name} from a {now - from_timestamp}s gap; "
                    f"alerts not sent for them")
            logger.info(f"Ingested {total} queries from {server.name}")
            return total, alertable

        except Exception as e:
            # Stored rows re-read next poll hit ON CONFLICT and never come back as alertable.
            logger.error(f"Error ingesting from {server.name}: {e}", exc_info=True)
            return total, alertable

        finally:
            if time.time() - now > self.settings.max_catchup_seconds:
                self._long_walk_until[server.name] = now

    async def _store_queries(self, queries: List[dict], server_name: str) -> Tuple[int, List[IngestedQuery]]:
        """Store queries in database with duplicate handling using bulk insert.
        Returns (count, list of IngestedQuery objects for alert checking).
        """
        if not queries:
            return 0, []

        geoip = get_geoip()
        async with async_session_maker() as session:
            # One row per unique key within this batch; an A and an HTTPS lookup can
            # still share a microsecond, and the one carrying addresses is worth keeping.
            # Across batches ON CONFLICT DO NOTHING keeps whichever arrived first.
            by_key: dict[tuple, tuple[dict, IngestedQuery]] = {}
            skipped_untimed = 0
            skipped_unstorable = 0

            for query_data in queries:
                client_data = query_data.get("client", {})
                if isinstance(client_data, dict):
                    client_ip = client_data.get("ip") or "unknown"
                    client_hostname = client_data.get("name") or ""
                    if client_hostname == client_ip:
                        client_hostname = None
                else:
                    client_ip = str(client_data)
                    client_hostname = None

                timestamp = query_data.get("timestamp")
                if not isinstance(timestamp, datetime):
                    # Stamping "now" instead hid for months that Pi-hole rows never carried their real time.
                    skipped_untimed += 1
                    continue

                # Validate and truncate field lengths to prevent database constraint violations
                raw_domain = query_data.get("domain") or ""
                # The root zone's only spelling is its dot, which normalizing would blank.
                domain = normalize_domain(raw_domain) or raw_domain.strip()
                if len(domain) > 255:
                    domain = domain[:255]

                query_type = query_data.get("type") or ""
                if len(query_type) > 10:
                    query_type = query_type[:10]

                status = query_data.get("status") or ""
                if len(status) > 50:
                    status = status[:50]

                if client_ip and len(client_ip) > 45:
                    client_ip = client_ip[:45]

                if client_hostname and len(client_hostname) > 255:
                    client_hostname = client_hostname[:255]

                # A multi-row insert fails whole, and a retried range would hit the same row
                # every poll, so only this row is dropped. Only data errors are safe to skip:
                # dropping a page on a database outage would lose the range.
                if any("\x00" in text for text in (domain, client_ip, client_hostname or "", query_type, status)):
                    skipped_unstorable += 1
                    continue

                answer_ips = query_data.get("answer_ips")
                answer_cnames = query_data.get("answer_cnames")
                answer_countries = geoip.countries(answer_ips) if geoip.has_countries and answer_ips else None
                key = (timestamp, domain, client_ip, server_name)
                if key in by_key and not answer_ips:
                    continue
                by_key[key] = ({
                    'timestamp': timestamp,
                    'domain': domain,
                    'client_ip': client_ip,
                    'client_hostname': client_hostname,
                    'query_type': query_type,
                    'status': status,
                    'server': server_name,
                    'created_at': datetime.now(timezone.utc),
                    'answer_ips': answer_ips,
                    'answer_cnames': answer_cnames,
                    'answer_countries': answer_countries,
                }, IngestedQuery(
                    id=0,
                    domain=domain,
                    client_ip=client_ip,
                    client_hostname=client_hostname,
                    timestamp=timestamp,
                    query_type=query_type,
                    status=status,
                    server=server_name,
                    answer_ips=answer_ips,
                    answer_countries=answer_countries,
                ))

            if skipped_untimed:
                logger.warning(f"Skipped {skipped_untimed} queries from {server_name} with no usable time")
            if skipped_unstorable:
                logger.warning(f"Skipped {skipped_unstorable} queries from {server_name} with a NUL byte in a text field")

            values_list = [values for values, _ in by_key.values()]
            ingested_queries = [ingested for _, ingested in by_key.values()]

            if not values_list:
                return 0, []

            batch_size = POSTGRES_MAX_BIND_PARAMS // len(values_list[0])
            total_inserted = 0
            inserted_keys: set = set()

            for i in range(0, len(values_list), batch_size):
                batch = values_list[i:i + batch_size]

                stmt = insert(Query).values(batch)
                stmt = stmt.on_conflict_do_nothing(
                    index_elements=['timestamp', 'domain', 'client_ip', 'server']
                ).returning(Query.timestamp, Query.domain, Query.client_ip, Query.server)

                result = await session.execute(stmt)
                rows = result.fetchall()
                total_inserted += len(rows)
                for row in rows:
                    inserted_keys.add((row[0], row[1], row[2], row[3]))

            await session.commit()

            skipped = len(values_list) - total_inserted
            logger.debug(f"Bulk inserted {total_inserted} queries in {(len(values_list) + batch_size - 1) // batch_size} batches, skipped {skipped} duplicates")

            if skipped > 0:
                ingested_queries = [
                    q for q in ingested_queries
                    if (q.timestamp, q.domain, q.client_ip, q.server) in inserted_keys
                ]

            return total_inserted, ingested_queries

    async def update_hourly_stats(self, ingested_queries: List[IngestedQuery]) -> None:
        """Update pre-aggregated hourly stats tables from ingested queries."""
        if not ingested_queries:
            return

        server_agg: dict[tuple, dict] = defaultdict(lambda: {'total': 0, 'blocked': 0, 'cached': 0})
        # Key: (hour, server, client_ip)
        client_agg: dict[tuple, dict] = defaultdict(lambda: {'hostname': None, 'total': 0, 'blocked': 0})
        # Key: (hour, server, domain)
        domain_agg: dict[tuple, dict] = defaultdict(lambda: {'total': 0, 'blocked': 0})

        for q in ingested_queries:
            hour = q.timestamp.replace(minute=0, second=0, microsecond=0)
            is_blocked = q.status in BLOCKED_STATUSES
            is_cached = q.status in CACHE_STATUSES

            sk = (hour, q.server)
            server_agg[sk]['total'] += 1
            if is_blocked:
                server_agg[sk]['blocked'] += 1
            if is_cached:
                server_agg[sk]['cached'] += 1

            ck = (hour, q.server, q.client_ip)
            client_agg[ck]['total'] += 1
            client_agg[ck]['hostname'] = q.client_hostname
            if is_blocked:
                client_agg[ck]['blocked'] += 1

            dk = (hour, q.server, q.domain)
            domain_agg[dk]['total'] += 1
            if is_blocked:
                domain_agg[dk]['blocked'] += 1

        try:
            async with async_session_maker() as session:
                if server_agg:
                    values = [
                        {'hour': k[0], 'server': k[1], 'total': v['total'], 'blocked': v['blocked'], 'cached': v['cached']}
                        for k, v in server_agg.items()
                    ]
                    stmt = insert(QueryStatsHourly).values(values)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=['hour', 'server'],
                        set_={'total': QueryStatsHourly.total + stmt.excluded.total,
                              'blocked': QueryStatsHourly.blocked + stmt.excluded.blocked,
                              'cached': QueryStatsHourly.cached + stmt.excluded.cached}
                    )
                    await session.execute(stmt)

                if client_agg:
                    values = [
                        {'hour': k[0], 'server': k[1], 'client_ip': k[2],
                         'client_hostname': v['hostname'], 'total': v['total'], 'blocked': v['blocked']}
                        for k, v in client_agg.items()
                    ]
                    # Batch to avoid parameter limits
                    for i in range(0, len(values), 2000):
                        batch = values[i:i + 2000]
                        stmt = insert(ClientStatsHourly).values(batch)
                        stmt = stmt.on_conflict_do_update(
                            index_elements=['hour', 'server', 'client_ip'],
                            set_={'total': ClientStatsHourly.total + stmt.excluded.total,
                                  'blocked': ClientStatsHourly.blocked + stmt.excluded.blocked,
                                  'client_hostname': stmt.excluded.client_hostname}
                        )
                        await session.execute(stmt)

                if domain_agg:
                    values = [
                        {'hour': k[0], 'server': k[1], 'domain': k[2],
                         'total': v['total'], 'blocked': v['blocked']}
                        for k, v in domain_agg.items()
                    ]
                    for i in range(0, len(values), 2000):
                        batch = values[i:i + 2000]
                        stmt = insert(DomainStatsHourly).values(batch)
                        stmt = stmt.on_conflict_do_update(
                            index_elements=['hour', 'server', 'domain'],
                            set_={'total': DomainStatsHourly.total + stmt.excluded.total,
                                  'blocked': DomainStatsHourly.blocked + stmt.excluded.blocked}
                        )
                        await session.execute(stmt)

                await session.commit()
                logger.debug(f"Updated hourly stats: {len(server_agg)} server buckets, {len(client_agg)} client buckets, {len(domain_agg)} domain buckets")

        except Exception as e:
            logger.error(f"Error updating hourly stats: {e}", exc_info=True)

    async def backfill_hourly_stats(self) -> None:
        """Backfill hourly stats tables from existing query data."""
        logger.info("Starting hourly stats backfill...")
        try:
            async with async_session_maker() as session:
                result = await session.execute(select(func.count()).select_from(QueryStatsHourly))
                if (result.scalar() or 0) > 0:
                    logger.info("Hourly stats already populated, skipping backfill")
                    return

                await session.execute(text(f"""
                    INSERT INTO query_stats_hourly (hour, server, total, blocked, cached)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ({BLOCKED_SQL_IN})) AS blocked,
                           COUNT(*) FILTER (WHERE status IN ({CACHE_SQL_IN})) AS cached
                    FROM queries
                    GROUP BY hour, server
                    ON CONFLICT (hour, server) DO NOTHING
                """))

                await session.execute(text(f"""
                    INSERT INTO client_stats_hourly (hour, server, client_ip, client_hostname, total, blocked)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           client_ip,
                           MAX(client_hostname) AS client_hostname,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ({BLOCKED_SQL_IN})) AS blocked
                    FROM queries
                    GROUP BY hour, server, client_ip
                    ON CONFLICT (hour, server, client_ip) DO NOTHING
                """))

                await session.execute(text(f"""
                    INSERT INTO domain_stats_hourly (hour, server, domain, total, blocked)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           domain,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ({BLOCKED_SQL_IN})) AS blocked
                    FROM queries
                    GROUP BY hour, server, domain
                    ON CONFLICT (hour, server, domain) DO NOTHING
                """))

                await session.commit()
                logger.info("Hourly stats backfill completed")

        except Exception as e:
            logger.error(f"Error backfilling hourly stats: {e}", exc_info=True)

    async def ingest_from_all_servers(self) -> Tuple[int, List[IngestedQuery]]:
        """Poll every configured server at once and return what has finished as
        (total_count, all_ingested_queries). A server still walking a backlog keeps running
        and is collected by a later call, which won't start a second poll of it.
        """
        # Reload settings to pick up any newly added servers
        from .config import get_settings
        self.settings = await get_settings()

        total_count, all_queries = self._collect_finished_polls()
        for server in self.settings.servers:
            if server.name not in self._in_flight:
                self._in_flight[server.name] = asyncio.create_task(self.ingest_from_server(server))

        # Waiting for every server would be no better than polling in turn: the scheduler runs
        # one instance of this job, so a long recovery would still stop the others being polled
        # until they pass max_catchup_seconds and lose queries. Half an interval leaves the next
        # tick free. Servers never share rows here, since every key these writes touch has `server`.
        if self._in_flight:
            await asyncio.wait(self._in_flight.values(), timeout=self._poll_wait_seconds)

        count, queries = self._collect_finished_polls()
        for name in self._in_flight:
            logger.info(f"Still ingesting from {name}; collecting it on a later poll")
        return total_count + count, all_queries + queries

    def _collect_finished_polls(self) -> Tuple[int, List[IngestedQuery]]:
        total_count = 0
        all_queries: List[IngestedQuery] = []
        for name, task in list(self._in_flight.items()):
            if not task.done():
                continue
            del self._in_flight[name]
            if task.cancelled():
                continue
            count, queries = task.result()
            total_count += count
            all_queries.extend(queries)
        return total_count, all_queries

    async def stop(self) -> None:
        """Cancel running polls. A newest-first walk's cursor only moves once it finishes, so the next
        start re-reads the range, but rows already stored don't come back as alertable, and neither
        do the results of polls that finished since the last tick."""
        tasks = list(self._in_flight.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._in_flight.clear()

    async def cleanup_old_data(self):
        """Remove queries older than retention period"""
        try:
            deleted_count = await cleanup_old_queries(self.settings.retention_days)
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old queries")
            return deleted_count
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}", exc_info=True)
            return 0
