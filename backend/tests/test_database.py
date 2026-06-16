"""Tests for backend.database — migration runner and cleanup helpers."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import (
    _run_migrations,
    cleanup_old_queries,
    engine as production_engine,
)
from backend.models import BlocklistSource, Query


async def test_run_migrations_is_idempotent():
    """Running migrations twice must not error or duplicate columns."""
    async with production_engine.begin() as conn:
        await _run_migrations(conn)
    async with production_engine.begin() as conn:
        await _run_migrations(conn)


async def test_run_migrations_actually_adds_missing_column():
    """Drop the migrated column, run the migration, verify it comes back
    with the documented NOT NULL + DEFAULT.

    This is the only test that exercises the migration's add-column branch.
    create_all() builds the table from models.py with `default='any'` (a
    Python-side INSERT-time default, NOT a SQL DEFAULT clause), so we can't
    rely on the fresh test DB to prove the migration sets the server default.
    """
    async with production_engine.begin() as conn:
        # Drop and re-add to simulate an older DB that predates the migration.
        await conn.execute(text("ALTER TABLE alert_rules DROP COLUMN match_status"))

        # Sanity: column is really gone before the migration runs.
        result = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'alert_rules' AND column_name = 'match_status'"
        ))
        assert result.fetchone() is None

        await _run_migrations(conn)

        result = await conn.execute(text(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'alert_rules' AND column_name = 'match_status'"
        ))
        row = result.fetchone()
        assert row is not None, "_run_migrations did not add match_status back"
        is_nullable, default = row
        assert is_nullable == "NO", "migration must set NOT NULL"
        assert "'any'" in (default or ""), f"migration must set DEFAULT 'any', got {default!r}"


async def test_cleanup_old_queries_deletes_old_preserves_recent(db_session: AsyncSession):
    now = datetime.now(timezone.utc)
    old = Query(
        timestamp=now - timedelta(days=90),
        domain="old.example.com", client_ip="1.1.1.1", server="s", status="OK",
    )
    recent = Query(
        timestamp=now - timedelta(days=5),
        domain="recent.example.com", client_ip="2.2.2.2", server="s", status="OK",
    )
    db_session.add_all([old, recent])
    await db_session.commit()

    deleted = await cleanup_old_queries(days=60)
    assert deleted == 1

    # Verify recent row survived
    from sqlalchemy import select
    remaining = (await db_session.execute(select(Query.domain))).scalars().all()
    assert "recent.example.com" in remaining
    assert "old.example.com" not in remaining


async def test_cleanup_old_queries_zero_when_all_recent(db_session: AsyncSession):
    db_session.add(Query(
        timestamp=datetime.now(timezone.utc),
        domain="x", client_ip="1.1.1.1", server="s", status="OK",
    ))
    await db_session.commit()
    assert await cleanup_old_queries(days=60) == 0


async def test_cleanup_old_queries_empty_table():
    assert await cleanup_old_queries(days=60) == 0


async def test_blocklist_source_to_dict(db_session):
    src = BlocklistSource(
        name="L", url="https://e.com/l.txt", category="Ads & Tracking",
        format="domains", license="GPL-3.0", enabled=True,
    )
    db_session.add(src)
    await db_session.commit()
    await db_session.refresh(src)
    d = src.to_dict()
    assert d["name"] == "L"
    assert d["category"] == "Ads & Tracking"
    assert d["format"] == "domains"
    assert d["enabled"] is True
    assert d["last_fetched_at"] is None
    assert d["domain_count"] is None
    assert d["created_at"] is not None and d["updated_at"] is not None
