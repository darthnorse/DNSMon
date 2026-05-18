"""
Pytest fixtures for the DNSMon test suite.

Test database strategy:
- A single `dnsmon_test` database (in the same Postgres instance the app uses).
- Dropped + recreated at session start, dropped again at session end.
- Each test gets a function-scoped `db_session` that truncates all tables on
  teardown so tests don't pollute one another.
- `DATABASE_URL` is derived from the existing environment by swapping the
  database name to `dnsmon_test` BEFORE backend modules are imported, so
  production code paths using `async_session_maker()` directly also hit the
  test DB. Credentials (user/password/host/port) are reused as-is, so
  non-default POSTGRES_PASSWORD setups Just Work.
"""

import os
from urllib.parse import urlparse, urlunparse


def _build_test_urls():
    """Return (test_db_url, admin_url) derived from $DATABASE_URL.

    test_db_url points at the test database; admin_url at the default
    `postgres` database for issuing DROP/CREATE DATABASE statements.
    """
    original = os.environ.get(
        "DATABASE_URL",
        "postgresql://dnsmon:changeme@localhost:5432/dnsmon",
    )
    parsed = urlparse(original)
    test_db_url = urlunparse(parsed._replace(path="/dnsmon_test"))
    # Admin URL must use asyncpg driver scheme. The async engine adds the
    # +asyncpg suffix itself in backend.database, but here we construct a
    # separate engine for DDL so we add it explicitly.
    scheme = parsed.scheme
    if scheme == "postgresql":
        scheme = "postgresql+asyncpg"
    admin_url = urlunparse(parsed._replace(scheme=scheme, path="/postgres"))
    return test_db_url, admin_url


_TEST_DB_URL, _ADMIN_URL = _build_test_urls()

# Must run before any `from backend.*` import.
os.environ["DATABASE_URL"] = _TEST_DB_URL
# Switch backend.database to a NullPool engine. The production pool causes
# cross-event-loop hangs when pytest-asyncio + httpx.AsyncClient share sessions.
os.environ["DNSMON_TEST"] = "1"

from typing import AsyncGenerator, Generator
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from backend.auth import generate_session_token, hash_password
from backend.config import get_settings
from backend.database import (
    async_session_maker,
    engine as production_engine,
    init_db,
)
from backend.models import Base, Session as DBSession, User, utcnow


async def _drop_test_database():
    """Disconnect any holders and drop dnsmon_test. Connects to the default
    `postgres` DB with AUTOCOMMIT because DROP DATABASE can't run inside a tx."""
    admin_engine = create_async_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = 'dnsmon_test' AND pid <> pg_backend_pid()"
            ))
            await conn.execute(text("DROP DATABASE IF EXISTS dnsmon_test"))
    finally:
        await admin_engine.dispose()


async def _create_test_database():
    admin_engine = create_async_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text("CREATE DATABASE dnsmon_test"))
    finally:
        await admin_engine.dispose()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db() -> AsyncGenerator[None, None]:
    """Drop + recreate dnsmon_test, then run create_all + migrations."""
    await _drop_test_database()
    await _create_test_database()

    # Create schema + run migrations (mirrors production startup).
    await init_db()
    # Preload settings singleton (mirrors @app.on_event("startup")) so endpoints
    # that synchronously read settings via get_settings_sync() don't raise.
    await get_settings()

    yield

    await production_engine.dispose()
    await _drop_test_database()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Per-test session. Truncates all tables on teardown."""
    async with async_session_maker() as session:
        yield session

    # Truncate everything between tests. CASCADE handles FK order.
    async with production_engine.begin() as conn:
        table_names = ", ".join(t.name for t in Base.metadata.sorted_tables)
        if table_names:
            await conn.execute(text(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    user = User(
        username="admin_test",
        email="admin@test.local",
        password_hash=hash_password("admin-password"),
        is_active=True,
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def readonly_user(db_session: AsyncSession) -> User:
    user = User(
        username="readonly_test",
        email="readonly@test.local",
        password_hash=hash_password("readonly-password"),
        is_active=True,
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_session(db_session: AsyncSession, admin_user: User) -> DBSession:
    session = DBSession(
        id=generate_session_token(),
        user_id=admin_user.id,
        expires_at=utcnow() + timedelta(hours=1),
    )
    db_session.add(session)
    await db_session.commit()
    await db_session.refresh(session)
    return session


# ---------------------------------------------------------------------------
# API client fixtures (async httpx.AsyncClient + ASGITransport)
#
# The sync starlette TestClient creates a fresh event loop per request which
# conflicts with our async DB engine and hangs tests. Always use these async
# clients for endpoint tests.
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Bare client with no auth overrides. Endpoints will return 401."""
    from backend.api import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def async_admin_client(admin_user: User) -> AsyncGenerator[AsyncClient, None]:
    """Client with get_current_user + require_admin overridden to admin_user."""
    from backend.api import app
    from backend.auth import get_current_user, require_admin

    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[require_admin] = lambda: admin_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_readonly_client(readonly_user: User) -> AsyncGenerator[AsyncClient, None]:
    """Client with get_current_user overridden to readonly_user. require_admin
    runs normally — admin endpoints return 403."""
    from backend.api import app
    from backend.auth import get_current_user

    app.dependency_overrides[get_current_user] = lambda: readonly_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()
