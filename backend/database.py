from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from .models import Base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dnsmon:changeme@localhost:5432/dnsmon")

# Convert to async URL if needed
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Create async engine with proper connection pooling
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,  # Max 20 connections in the pool (increased from 10)
    max_overflow=30,  # Allow up to 30 additional connections when pool is exhausted (increased from 20)
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=1800,  # Recycle connections after 30 minutes (reduced from 1 hour)
    pool_timeout=30,  # Timeout waiting for connection from pool (prevents indefinite hangs)
)

# Create async session factory
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


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Run migrations
    await migrate_telegram_to_channels()


async def migrate_telegram_to_channels():
    """Migrate existing Telegram settings to notification_channels table"""
    import logging
    from sqlalchemy import select
    from .models import AppSetting, NotificationChannel

    logger = logging.getLogger(__name__)

    async with async_session_maker() as session:
        # Get existing Telegram settings
        stmt = select(AppSetting).where(AppSetting.key.in_([
            'telegram_bot_token', 'telegram_chat_id'
        ]))
        result = await session.execute(stmt)
        settings = {s.key: s.value for s in result.scalars()}

        bot_token = settings.get('telegram_bot_token')
        chat_id = settings.get('telegram_chat_id')

        if bot_token and chat_id:
            # Check if already migrated
            existing = await session.execute(
                select(NotificationChannel).where(
                    NotificationChannel.channel_type == 'telegram',
                    NotificationChannel.name == 'Telegram (migrated)'
                )
            )
            if not existing.scalar_one_or_none():
                # Create channel from existing settings
                channel = NotificationChannel(
                    name="Telegram (migrated)",
                    channel_type="telegram",
                    config={"bot_token": bot_token, "chat_id": chat_id},
                    enabled=True,
                )
                session.add(channel)
                await session.commit()
                logger.info("Migrated Telegram settings to notification_channels")


async def cleanup_old_queries(days: int = 60):
    """Delete queries older than specified days"""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import delete
    from .models import Query

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

    async with async_session_maker() as session:
        stmt = delete(Query).where(Query.timestamp < cutoff_date)
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount
