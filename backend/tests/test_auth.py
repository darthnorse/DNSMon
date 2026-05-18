"""Tests for backend.auth — password hashing, sessions, and dependencies."""

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import (
    create_session,
    delete_session,
    generate_session_token,
    get_current_user,
    get_session_user,
    hash_password,
    require_admin,
    verify_password,
)
from backend.models import Session as DBSession, User, utcnow


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def test_hash_password_produces_bcrypt_hash():
    h = hash_password("hunter2")
    assert h != "hunter2"  # never plaintext
    assert h.startswith("$2")  # bcrypt prefix
    assert len(h) > 50


def test_verify_password_roundtrip():
    h = hash_password("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_verify_password_with_garbage_hash():
    # Must not raise on malformed input, must return False.
    assert not verify_password("hunter2", "not-a-real-hash")


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------

def test_generate_session_token_is_random_and_long():
    a = generate_session_token()
    b = generate_session_token()
    assert a != b
    # secrets.token_hex(32) → 64 hex chars
    assert len(a) >= 32
    assert all(c in "0123456789abcdef" for c in a)


# ---------------------------------------------------------------------------
# Session lifecycle (DB-bound)
# ---------------------------------------------------------------------------

async def test_create_session_persists_and_links_user(db_session: AsyncSession, admin_user: User):
    request = MagicMock()
    request.client.host = "192.168.1.10"
    request.headers = {"user-agent": "test"}

    session = await create_session(db_session, admin_user, request, hours=1)
    assert session.id
    assert session.user_id == admin_user.id
    assert session.expires_at > utcnow()
    assert session.ip_address == "192.168.1.10"


async def test_get_session_user_returns_user(db_session: AsyncSession, admin_session: DBSession,
                                              admin_user: User):
    user = await get_session_user(db_session, admin_session.id)
    assert user is not None
    assert user.id == admin_user.id


async def test_get_session_user_returns_none_for_unknown_token(db_session: AsyncSession):
    user = await get_session_user(db_session, "nonexistent-token")
    assert user is None


async def test_get_session_user_returns_none_for_expired_session(db_session: AsyncSession,
                                                                  admin_user: User):
    expired = DBSession(
        id=generate_session_token(),
        user_id=admin_user.id,
        expires_at=utcnow() - timedelta(hours=1),  # already expired
    )
    db_session.add(expired)
    await db_session.commit()

    user = await get_session_user(db_session, expired.id)
    assert user is None


async def test_delete_session_removes_row(db_session: AsyncSession, admin_session: DBSession):
    assert await delete_session(db_session, admin_session.id) is True
    # Second call returns False — already deleted.
    assert await delete_session(db_session, admin_session.id) is False


# ---------------------------------------------------------------------------
# require_admin dependency
# ---------------------------------------------------------------------------

async def test_require_admin_allows_admin_user(admin_user: User):
    # Despite being a "Depends" function it can be called directly with the
    # user already resolved (FastAPI just chains dependencies).
    result = await require_admin(user=admin_user)
    assert result is admin_user


async def test_require_admin_rejects_readonly_user(readonly_user: User):
    with pytest.raises(HTTPException) as exc:
        await require_admin(user=readonly_user)
    assert exc.value.status_code == 403
