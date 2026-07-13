import logging
import os
from typing import NamedTuple, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text
from .models import Base

logger = logging.getLogger(__name__)


class Migration(NamedTuple):
    """A hardcoded ALTER TABLE ADD COLUMN migration.

    On PostgreSQL 11+, `ADD COLUMN ... DEFAULT <constant> NOT NULL` is a
    metadata-only change (no table rewrite) when the default is a non-volatile
    constant. The project pins PG16 so this is always fast in production.
    """
    table: str
    column: str
    col_type: str
    default: Optional[str]
    nullable: bool

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dnsmon:changeme@localhost:5432/dnsmon")

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

if os.getenv("DNSMON_TEST"):
    # Tests use NullPool so each session gets a fresh asyncpg connection.
    # The default pool causes cross-event-loop hangs with FastAPI TestClient + pytest-asyncio.
    _engine_kwargs = {"poolclass": NullPool}
else:
    _engine_kwargs = {
        "pool_size": 20,
        "max_overflow": 30,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "pool_timeout": 30,
    }

engine = create_async_engine(DATABASE_URL, echo=False, **_engine_kwargs)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """Dependency for FastAPI to get database session"""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def _run_pre_create_migrations(conn):
    """Table renames that must run BEFORE create_all (else create_all makes a new
    empty table and orphans the old one). Each step is guarded + idempotent."""
    old = await conn.execute(text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'blocklist_sources'"))
    new = await conn.execute(text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'insight_sources'"))
    if old.scalar() and not new.scalar():
        await conn.execute(text("ALTER TABLE blocklist_sources RENAME TO insight_sources"))
        await conn.execute(text(
            "ALTER INDEX IF EXISTS idx_blocklist_sources_url RENAME TO idx_insight_sources_url"))
        logger.info("Migration: renamed blocklist_sources -> insight_sources")

    # The legacy blocklist_sources.category was NOT NULL; the generalized model
    # makes it nullable (adguard/dnsmon rows carry no category). create_all never
    # relaxes existing columns, so an upgraded table would still reject the seed.
    # DROP NOT NULL is idempotent (no-op once already nullable).
    insight = await conn.execute(text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'insight_sources'"))
    if insight.scalar():
        await conn.execute(text(
            "ALTER TABLE insight_sources ALTER COLUMN category DROP NOT NULL"))


async def _run_migrations(conn):
    """Add missing columns to existing tables.

    SQLAlchemy's create_all only creates new tables; it won't alter existing
    ones.  This function bridges that gap for schema changes so that existing
    installs upgrade automatically on restart.
    """
    # SECURITY: every field on each Migration MUST be a hardcoded literal.
    # NEVER source these values from user input or configuration.
    migrations = [
        Migration(table='servers', column='extra_config',
                  col_type='JSON', default=None, nullable=True),
        Migration(table='alert_rules', column='match_status',
                  col_type='VARCHAR(20)', default="'any'", nullable=False),
        Migration(table='app_definitions', column='is_category_only',
                  col_type='BOOLEAN', default='false', nullable=False),
        Migration(table='insight_sources', column='kind',
                  col_type='VARCHAR(20)', default="'hosts'", nullable=False),
        Migration(table='alert_rules', column='exclude_client_ips',
                  col_type='TEXT', default=None, nullable=True),
    ]
    for m in migrations:
        result = await conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ), {'table': m.table, 'column': m.column})
        if not result.scalar():
            default_clause = f" DEFAULT {m.default}" if m.default is not None else ""
            null_clause = "" if m.nullable else " NOT NULL"
            await conn.execute(text(
                f'ALTER TABLE {m.table} ADD COLUMN {m.column} {m.col_type}{default_clause}{null_clause}'
            ))
            logger.info(f"Migration: added {m.table}.{m.column} ({m.col_type})")

    # Backfill the flag for the pre-existing blocklist tier. `AND is_category_only
    # = false` keeps this idempotent + cheap (touches only un-backfilled rows).
    await conn.execute(text(
        "UPDATE app_definitions SET is_category_only = true "
        "WHERE source = 'blocklist' AND is_category_only = false"
    ))

    # Drop redundant indexes that are covered by composite indexes
    redundant_indexes = [
        'idx_queries_client_ip_timestamp',  # covered by idx_queries_timestamp_client
        'idx_queries_domain_client',        # no query uses this combination
        'ix_queries_timestamp',             # covered by 4 composites starting with timestamp
        'ix_queries_pihole_server',         # covered by idx_queries_pihole_timestamp
    ]
    for index_name in redundant_indexes:
        await conn.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))
        # No log on every startup; DROP IF EXISTS is a no-op when already gone


async def ensure_insight_sources() -> int:
    """Ensure each default insight source exists. Returns rows added.

    Kinds in SINGLETON_SOURCE_KINDS (adguard/dnsmon/v2fly) are singletons keyed
    on `kind` (only one row of each is meaningful); keying on url would risk a
    duplicate row if a singleton's url ever diverges from the default. `hosts`
    rows may be many, so they key on `url`. On upgrade, AdGuard/DNSMon inherit
    the legacy classification_* settings so an admin's prior toggle/URL is
    preserved.

    Owns its own session (matches cleanup_old_queries)."""
    from sqlalchemy import select
    from .models import InsightSource, AppSetting
    from .constants import DEFAULT_INSIGHT_SOURCES, SINGLETON_SOURCE_KINDS

    added = 0
    async with async_session_maker() as db:
        existing = (await db.execute(select(InsightSource.kind, InsightSource.url))).all()
        existing_kinds = {kind for kind, _ in existing}
        existing_urls = {url for _, url in existing}
        settings = {row.key: row.get_typed_value()
                    for row in (await db.execute(select(AppSetting))).scalars()}
        # Legacy migration read: classification_feed_*/classification_supplement_enabled
        # were dropped from bootstrap defaults in v1.2. On UPGRADE these AppSetting rows
        # still exist and seed the AdGuard/DNSMon rows so prior toggle/URL is preserved;
        # on FRESH install they're absent and .get() falls back to the defaults below.
        for src in DEFAULT_INSIGHT_SOURCES:
            row = dict(src)
            if row['kind'] == 'adguard':
                row['url'] = settings.get('classification_feed_url', row['url'])
                row['enabled'] = bool(settings.get('classification_feed_enabled', True))
            elif row['kind'] == 'dnsmon':
                row['enabled'] = bool(settings.get('classification_supplement_enabled', True))

            if row['kind'] in SINGLETON_SOURCE_KINDS:
                if row['kind'] in existing_kinds:
                    continue
            elif row['url'] in existing_urls:
                continue

            db.add(InsightSource(**row))
            existing_kinds.add(row['kind'])
            existing_urls.add(row['url'])
            added += 1
        if added:
            await db.commit()
    if added:  # don't log on every boot once seeded
        logger.info(f"Ensured insight sources ({added} added)")
    return added


async def init_db():
    """Initialize database tables and run migrations"""
    async with engine.begin() as conn:
        await _run_pre_create_migrations(conn)
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)
    await ensure_insight_sources()


async def cleanup_old_queries(days: int = 60):
    """Delete queries older than specified days from raw and aggregated tables"""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import delete
    from .models import Query, QueryStatsHourly, ClientStatsHourly, DomainStatsHourly

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

    async with async_session_maker() as session:
        stmt = delete(Query).where(Query.timestamp < cutoff_date)
        result = await session.execute(stmt)
        raw_deleted = result.rowcount

        await session.execute(delete(QueryStatsHourly).where(QueryStatsHourly.hour < cutoff_date))
        await session.execute(delete(ClientStatsHourly).where(ClientStatsHourly.hour < cutoff_date))
        await session.execute(delete(DomainStatsHourly).where(DomainStatsHourly.hour < cutoff_date))

        await session.commit()
        return raw_deleted
