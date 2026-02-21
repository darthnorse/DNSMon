import logging
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text
from .models import Base

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dnsmon:changeme@localhost:5432/dnsmon")

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,  # Max 20 connections in the pool (increased from 10)
    max_overflow=30,  # Allow up to 30 additional connections when pool is exhausted (increased from 20)
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=1800,  # Recycle connections after 30 minutes (reduced from 1 hour)
    pool_timeout=30,  # Timeout waiting for connection from pool (prevents indefinite hangs)
)

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
    # SECURITY: table, column, col_type, and default MUST be hardcoded string
    # literals. NEVER source these values from user input or configuration.
    migrations = [
        # (table, column, SQL type, default)
        ('servers', 'extra_config', 'JSON', None),
    ]
    for table, column, col_type, default in migrations:
        result = await conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ), {'table': table, 'column': column})
        if not result.scalar():
            default_clause = f" DEFAULT {default}" if default is not None else ""
            await conn.execute(text(
                f'ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}'
            ))
            logger.info(f"Migration: added {table}.{column} ({col_type})")


async def init_db():
    """Initialize database tables and run migrations"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)


async def cleanup_old_queries(days: int = 60):
    """Delete queries older than specified days from raw and aggregated tables"""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import delete
    from .models import Query, QueryStatsHourly, ClientStatsHourly, DomainStatsHourly

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

    async with async_session_maker() as session:
        # Clean raw queries
        stmt = delete(Query).where(Query.timestamp < cutoff_date)
        result = await session.execute(stmt)
        raw_deleted = result.rowcount

        # Clean aggregated tables
        await session.execute(delete(QueryStatsHourly).where(QueryStatsHourly.hour < cutoff_date))
        await session.execute(delete(ClientStatsHourly).where(ClientStatsHourly.hour < cutoff_date))
        await session.execute(delete(DomainStatsHourly).where(DomainStatsHourly.hour < cutoff_date))

        await session.commit()
        return raw_deleted
