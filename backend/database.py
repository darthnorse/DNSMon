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


async def seed_blocklist_sources() -> int:
    """Insert default blocklist sources iff the table is empty. Returns rows added.

    Owns its own session (matches cleanup_old_queries) so callers never have a
    session committed out from under them."""
    from sqlalchemy import select, func
    from .models import BlocklistSource
    from .constants import DEFAULT_BLOCKLIST_SOURCES

    async with async_session_maker() as db:
        count = await db.scalar(select(func.count()).select_from(BlocklistSource)) or 0
        if count > 0:
            logger.debug("Blocklist sources already seeded; skipping")
            return 0
        for src in DEFAULT_BLOCKLIST_SOURCES:
            db.add(BlocklistSource(**src))
        await db.commit()
    logger.info(f"Seeded {len(DEFAULT_BLOCKLIST_SOURCES)} default blocklist source(s)")
    return len(DEFAULT_BLOCKLIST_SOURCES)


async def init_db():
    """Initialize database tables and run migrations"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)
    await seed_blocklist_sources()


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
