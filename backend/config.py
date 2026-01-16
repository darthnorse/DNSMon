from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os
import json
import logging
import asyncio
import threading

logger = logging.getLogger(__name__)


class PiholeServer(BaseModel):
    """Configuration for a single DNS ad-blocker server (Pi-hole or AdGuard Home)"""
    id: Optional[int] = None
    name: str
    url: str
    password: str
    username: Optional[str] = None  # For AdGuard Home (default: 'admin')
    server_type: str = 'pihole'  # 'pihole' or 'adguard'
    skip_ssl_verify: bool = False  # Skip SSL certificate verification for self-signed certs
    enabled: bool = True
    display_order: int = 0

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format with thorough checks"""
        from urllib.parse import urlparse

        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError("URL must start with http:// or https://")

        # Parse and validate URL structure
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("URL must include a hostname")
            if parsed.netloc.startswith(':'):
                raise ValueError("URL must include a hostname before port")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

        return v

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate name is not empty"""
        v = v.strip()
        if not v:
            raise ValueError("Server name cannot be empty")
        return v


class Settings(BaseModel):
    """Application settings loaded from database"""
    # Always from environment
    database_url: str

    # From database
    poll_interval_seconds: int = Field(default=60, ge=10, le=3600)
    query_lookback_seconds: int = Field(default=65, ge=10, le=3600)
    sync_interval_seconds: int = Field(default=900, ge=60, le=86400)  # 15 min default, 1 min to 24 hours
    retention_days: int = Field(default=60, ge=1, le=365)
    max_catchup_seconds: int = Field(default=300, ge=60, le=3600)  # 5 min default, max lookback after downtime
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    pihole_servers: List[PiholeServer] = Field(default_factory=list)

    model_config = {'arbitrary_types_allowed': True}


async def bootstrap_settings_if_needed(db: AsyncSession):
    """Ensure settings tables exist and have default values"""
    from .models import AppSetting, PiholeServerModel

    # Check if app_settings has any data
    stmt = select(AppSetting).limit(1)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if not existing:
        logger.info("Bootstrapping default settings...")

        # Insert default app settings
        # Note: telegram_bot_token and telegram_chat_id were removed - use NotificationChannel instead
        defaults = [
            AppSetting(
                key='poll_interval_seconds',
                value='60',
                value_type='int',
                description='How often to poll Pi-hole servers (10-3600 seconds)',
                requires_restart=True
            ),
            AppSetting(
                key='query_lookback_seconds',
                value='65',
                value_type='int',
                description='How far back to look for queries (10-3600 seconds)',
                requires_restart=True
            ),
            AppSetting(
                key='sync_interval_seconds',
                value='900',
                value_type='int',
                description='How often to sync Pi-hole configurations (60-86400 seconds, 15 min default)',
                requires_restart=True
            ),
            AppSetting(
                key='retention_days',
                value='60',
                value_type='int',
                description='Days to retain query data (1-365)',
                requires_restart=False
            ),
            AppSetting(
                key='max_catchup_seconds',
                value='300',
                value_type='int',
                description='Maximum lookback window when catching up after downtime (60-3600 seconds)',
                requires_restart=False
            ),
            AppSetting(
                key='cors_origins',
                value='["http://localhost:3000", "http://localhost:8000"]',
                value_type='json',
                description='Allowed CORS origins',
                requires_restart=True
            ),
        ]

        for setting in defaults:
            db.add(setting)

        await db.commit()
        logger.info("Default settings bootstrapped successfully")


async def load_settings_from_db(db: AsyncSession) -> Settings:
    """Load all settings from database"""
    from .models import AppSetting, PiholeServerModel

    # Get DATABASE_URL from environment (only setting not in DB)
    database_url = os.getenv("DATABASE_URL", "postgresql://dnsmon:changeme@localhost:5432/dnsmon")

    # Ensure bootstrap
    await bootstrap_settings_if_needed(db)

    # Load app settings
    stmt = select(AppSetting)
    result = await db.execute(stmt)
    app_settings = {row.key: row.get_typed_value() for row in result.scalars()}

    # Load Pi-hole servers
    stmt = select(PiholeServerModel).where(PiholeServerModel.enabled == True).order_by(
        PiholeServerModel.display_order,
        PiholeServerModel.id
    )
    result = await db.execute(stmt)
    pihole_servers = [
        PiholeServer(
            id=server.id,
            name=server.name,
            url=server.url,
            password=server.password,
            username=server.username,
            server_type=server.server_type or 'pihole',
            skip_ssl_verify=server.skip_ssl_verify or False,
            enabled=server.enabled,
            display_order=server.display_order
        )
        for server in result.scalars()
    ]

    # Build Settings object with validation
    try:
        settings = Settings(
            database_url=database_url,
            poll_interval_seconds=app_settings.get('poll_interval_seconds', 60),
            query_lookback_seconds=app_settings.get('query_lookback_seconds', 65),
            sync_interval_seconds=app_settings.get('sync_interval_seconds', 900),
            retention_days=app_settings.get('retention_days', 60),
            max_catchup_seconds=app_settings.get('max_catchup_seconds', 300),
            cors_origins=app_settings.get('cors_origins', ["http://localhost:3000"]),
            pihole_servers=pihole_servers
        )
    except Exception as e:
        logger.error(f"Invalid settings loaded from database: {e}", exc_info=True)
        raise ValueError(f"Settings validation failed: {e}") from e

    if not settings.pihole_servers:
        logger.warning("No Pi-hole servers configured in database. Add servers via Settings page.")

    return settings


# Singleton pattern with both async and sync locks
_settings: Optional[Settings] = None
_settings_async_lock = asyncio.Lock()  # For async access
_settings_sync_lock = threading.Lock()  # For sync access


async def get_settings(force_reload: bool = False) -> Settings:
    """Get or load settings singleton (async version)"""
    from .database import async_session_maker

    global _settings

    async with _settings_async_lock:
        if _settings is None or force_reload:
            async with async_session_maker() as db:
                _settings = await load_settings_from_db(db)
                if force_reload:
                    logger.info("Settings reloaded from database")

        return _settings


def get_settings_sync() -> Settings:
    """Synchronous getter for settings (requires settings to be loaded first)"""
    global _settings

    with _settings_sync_lock:
        if _settings is None:
            raise RuntimeError("Settings not loaded. Call async get_settings() first during startup.")
        return _settings
