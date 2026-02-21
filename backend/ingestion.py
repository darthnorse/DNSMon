import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Tuple
from dataclasses import dataclass
from collections import defaultdict

from sqlalchemy import select, func, text, BigInteger
from sqlalchemy.dialects.postgresql import insert

from .models import Query, QueryStatsHourly, ClientStatsHourly, DomainStatsHourly
from .database import async_session_maker, cleanup_old_queries
from .utils import create_client_from_server
from .config import get_settings_sync, PiholeServer

logger = logging.getLogger(__name__)


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


class QueryIngestionService:
    """Service for ingesting DNS queries from Pi-hole servers"""

    def __init__(self):
        self.settings = get_settings_sync()

    async def _get_last_query_timestamp(self, server_name: str) -> int:
        """Get the timestamp of the last query for a server from the database.

        Caps the lookback to max_catchup_seconds to prevent fetching huge amounts
        of data after extended downtime.
        """
        now = int(time.time())
        max_lookback = self.settings.max_catchup_seconds
        min_allowed_timestamp = now - max_lookback

        async with async_session_maker() as session:
            stmt = (
                select(func.extract('epoch', func.max(Query.timestamp)).cast(BigInteger))
                .where(Query.server == server_name)
            )
            result = await session.execute(stmt)
            epoch_timestamp = result.scalar()

            if epoch_timestamp:
                last_timestamp = int(epoch_timestamp)
                # Cap lookback to max_catchup_seconds
                if last_timestamp < min_allowed_timestamp:
                    logger.warning(
                        f"Last query for {server_name} was {now - last_timestamp}s ago, "
                        f"capping lookback to {max_lookback}s (some queries may be missed)"
                    )
                    return min_allowed_timestamp
                return last_timestamp
            else:
                # No queries yet, use lookback period
                return now - self.settings.query_lookback_seconds

    async def ingest_from_server(self, server: PiholeServer) -> Tuple[int, List[IngestedQuery]]:
        """Ingest queries from a single Pi-hole server.
        Returns (count, list of IngestedQuery objects).
        """
        if not server.enabled:
            logger.debug(f"Server {server.name} is disabled, skipping")
            return 0, []

        try:
            now = int(time.time())
            last_poll = await self._get_last_query_timestamp(server.name)
            from_timestamp = last_poll
            until_timestamp = now

            logger.info(f"Ingesting queries from {server.name} (from {from_timestamp} to {until_timestamp})")

            client = create_client_from_server(server)
            async with client:
                if not await client.authenticate():
                    logger.error(f"Failed to authenticate with {server.name}")
                    return 0, []

                queries = await client.get_queries(from_timestamp, until_timestamp)

                if queries is None:
                    logger.error(f"Failed to retrieve queries from {server.name}")
                    return 0, []

                if not queries:
                    logger.info(f"No new queries from {server.name}")
                    return 0, []

                query_count, ingested = await self._store_queries(queries, server.name)

                logger.info(f"Ingested {query_count} queries from {server.name}")
                return query_count, ingested

        except Exception as e:
            logger.error(f"Error ingesting from {server.name}: {e}", exc_info=True)
            return 0, []

    async def _store_queries(self, queries: List[dict], server_name: str) -> Tuple[int, List[IngestedQuery]]:
        """Store queries in database with duplicate handling using bulk insert.
        Returns (count, list of IngestedQuery objects for alert checking).
        """
        if not queries:
            return 0, []

        try:
            async with async_session_maker() as session:
                # Prepare bulk insert data
                values_list = []
                ingested_queries = []  # For alert checking

                for query_data in queries:
                    # Extract client information
                    client_data = query_data.get("client", {})
                    if isinstance(client_data, dict):
                        client_ip = client_data.get("ip", "unknown")
                        client_hostname = client_data.get("name", "")
                        # Don't store hostname if it's the same as IP
                        if client_hostname == client_ip:
                            client_hostname = None
                    else:
                        client_ip = str(client_data)
                        client_hostname = None

                    # Pi-hole provides Unix timestamps which are UTC by definition
                    timestamp = query_data.get("timestamp")
                    if timestamp:
                        if isinstance(timestamp, int):
                            # Unix timestamp - convert to UTC timezone-aware datetime
                            timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                        else:
                            # ISO format string
                            timestamp = datetime.fromisoformat(str(timestamp))
                            # Ensure it's timezone-aware (assume UTC if naive)
                            if timestamp.tzinfo is None:
                                timestamp = timestamp.replace(tzinfo=timezone.utc)
                    else:
                        # Fallback to current UTC time
                        timestamp = datetime.now(timezone.utc)

                    # Validate and truncate field lengths to prevent database constraint violations
                    domain = query_data.get("domain", "")
                    if len(domain) > 255:
                        domain = domain[:255]

                    query_type = query_data.get("type", "")
                    if len(query_type) > 10:
                        query_type = query_type[:10]

                    status = query_data.get("status", "")
                    if len(status) > 50:
                        status = status[:50]

                    if client_ip and len(client_ip) > 45:
                        client_ip = client_ip[:45]

                    if client_hostname and len(client_hostname) > 255:
                        client_hostname = client_hostname[:255]

                    values_list.append({
                        'timestamp': timestamp,
                        'domain': domain,
                        'client_ip': client_ip,
                        'client_hostname': client_hostname,
                        'query_type': query_type,
                        'status': status,
                        'server': server_name,
                        'created_at': datetime.now(timezone.utc),
                    })

                    # Create lightweight query object for alert checking
                    # ID is 0 placeholder - will be looked up if needed for alert history
                    ingested_queries.append(IngestedQuery(
                        id=0,
                        domain=domain,
                        client_ip=client_ip,
                        client_hostname=client_hostname,
                        timestamp=timestamp,
                        query_type=query_type,
                        status=status,
                        server=server_name,
                    ))

                if not values_list:
                    return 0, []

                # Use PostgreSQL INSERT ... ON CONFLICT DO NOTHING for efficient duplicate handling
                # Batch insert in chunks to avoid PostgreSQL parameter limit (32767)
                # Each query has 8 columns, so max ~4000 queries per batch
                batch_size = 4000
                total_inserted = 0

                for i in range(0, len(values_list), batch_size):
                    batch = values_list[i:i + batch_size]

                    stmt = insert(Query).values(batch)
                    stmt = stmt.on_conflict_do_nothing(
                        index_elements=['timestamp', 'domain', 'client_ip', 'server']
                    )

                    result = await session.execute(stmt)
                    total_inserted += result.rowcount

                await session.commit()

                logger.debug(f"Bulk inserted {total_inserted} queries in {(len(values_list) + batch_size - 1) // batch_size} batches, skipped {len(values_list) - total_inserted} duplicates")

                return total_inserted, ingested_queries

        except Exception as e:
            logger.error(f"Error storing queries: {e}", exc_info=True)
            return 0, []

    async def update_hourly_stats(self, ingested_queries: List[IngestedQuery]) -> None:
        """Update pre-aggregated hourly stats tables from ingested queries."""
        if not ingested_queries:
            return

        blocked_statuses = {'GRAVITY', 'GRAVITY_CNAME', 'REGEX', 'REGEX_CNAME',
                            'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
                            'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA',
                            'BLOCKED'}
        cache_statuses = {'CACHE', 'CACHE_STALE', 'CACHED'}

        # Aggregate in memory
        # Key: (hour, server)
        server_agg: dict[tuple, dict] = defaultdict(lambda: {'total': 0, 'blocked': 0, 'cached': 0})
        # Key: (hour, server, client_ip)
        client_agg: dict[tuple, dict] = defaultdict(lambda: {'hostname': None, 'total': 0, 'blocked': 0})
        # Key: (hour, server, domain)
        domain_agg: dict[tuple, dict] = defaultdict(lambda: {'total': 0, 'blocked': 0})

        for q in ingested_queries:
            hour = q.timestamp.replace(minute=0, second=0, microsecond=0)
            is_blocked = q.status in blocked_statuses
            is_cached = q.status in cache_statuses

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
                # Upsert query_stats_hourly
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

                # Upsert client_stats_hourly
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

                # Upsert domain_stats_hourly
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
                # Check if already backfilled
                result = await session.execute(select(func.count()).select_from(QueryStatsHourly))
                if (result.scalar() or 0) > 0:
                    logger.info("Hourly stats already populated, skipping backfill")
                    return

                # Backfill query_stats_hourly
                await session.execute(text("""
                    INSERT INTO query_stats_hourly (hour, server, total, blocked, cached)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ('GRAVITY','GRAVITY_CNAME','REGEX','REGEX_CNAME','BLACKLIST','BLACKLIST_CNAME','REGEX_BLACKLIST','EXTERNAL_BLOCKED_IP','EXTERNAL_BLOCKED_NULL','EXTERNAL_BLOCKED_NXRA','BLOCKED')) AS blocked,
                           COUNT(*) FILTER (WHERE status IN ('CACHE','CACHE_STALE','CACHED')) AS cached
                    FROM queries
                    GROUP BY hour, server
                    ON CONFLICT (hour, server) DO NOTHING
                """))

                # Backfill client_stats_hourly
                await session.execute(text("""
                    INSERT INTO client_stats_hourly (hour, server, client_ip, client_hostname, total, blocked)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           client_ip,
                           MAX(client_hostname) AS client_hostname,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ('GRAVITY','GRAVITY_CNAME','REGEX','REGEX_CNAME','BLACKLIST','BLACKLIST_CNAME','REGEX_BLACKLIST','EXTERNAL_BLOCKED_IP','EXTERNAL_BLOCKED_NULL','EXTERNAL_BLOCKED_NXRA','BLOCKED')) AS blocked
                    FROM queries
                    GROUP BY hour, server, client_ip
                    ON CONFLICT (hour, server, client_ip) DO NOTHING
                """))

                # Backfill domain_stats_hourly
                await session.execute(text("""
                    INSERT INTO domain_stats_hourly (hour, server, domain, total, blocked)
                    SELECT date_trunc('hour', timestamp) AS hour,
                           server,
                           domain,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status IN ('GRAVITY','GRAVITY_CNAME','REGEX','REGEX_CNAME','BLACKLIST','BLACKLIST_CNAME','REGEX_BLACKLIST','EXTERNAL_BLOCKED_IP','EXTERNAL_BLOCKED_NULL','EXTERNAL_BLOCKED_NXRA','BLOCKED')) AS blocked
                    FROM queries
                    GROUP BY hour, server, domain
                    ON CONFLICT (hour, server, domain) DO NOTHING
                """))

                await session.commit()
                logger.info("Hourly stats backfill completed")

        except Exception as e:
            logger.error(f"Error backfilling hourly stats: {e}", exc_info=True)

    async def ingest_from_all_servers(self) -> Tuple[int, List[IngestedQuery]]:
        """Ingest queries from all configured Pi-hole servers.
        Returns (total_count, all_ingested_queries).
        """
        # Reload settings to pick up any newly added servers
        from .config import get_settings
        self.settings = await get_settings()

        total_count = 0
        all_queries: List[IngestedQuery] = []

        for server in self.settings.servers:
            count, queries = await self.ingest_from_server(server)
            total_count += count
            all_queries.extend(queries)

        # Update pre-aggregated hourly stats only if new queries were inserted.
        # Note: ingested_queries includes all parsed queries, not just inserted ones
        # (ON CONFLICT DO NOTHING doesn't tell us which). In practice the duplicate
        # rate is near-zero since we fetch from the last known timestamp.
        if total_count > 0:
            await self.update_hourly_stats(all_queries)

        return total_count, all_queries

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
