"""
Authentication service for DNSMon.
Handles password hashing, session management, and auth dependencies.
"""

import os
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Request, Response, HTTPException, Depends
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from .database import get_db
from .models import User, Session, utcnow

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session settings
SESSION_TOKEN_BYTES = 32  # 64 hex characters
DEFAULT_SESSION_HOURS = 24
SESSION_COOKIE_NAME = "dnsmon_session"

# Secret key for cookie signing (should be set via environment variable)
SECRET_KEY = os.getenv("PIDASH_SECRET_KEY", secrets.token_hex(32))
COOKIE_SECURE = os.getenv("PIDASH_COOKIE_SECURE", "true").lower() == "true"


# ============================================================================
# Password Hashing
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


# ============================================================================
# Session Management
# ============================================================================

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_hex(SESSION_TOKEN_BYTES)


async def create_session(
    db: AsyncSession,
    user: User,
    request: Request,
    hours: int = DEFAULT_SESSION_HOURS
) -> Session:
    """Create a new session for a user."""
    session = Session(
        id=generate_session_token(),
        user_id=user.id,
        expires_at=utcnow() + timedelta(hours=hours),
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:500],
    )
    db.add(session)

    # Update user's last login
    user.last_login_at = utcnow()

    await db.commit()
    await db.refresh(session)

    logger.info(f"Created session for user {user.username} (ID: {user.id})")
    return session


async def get_session(db: AsyncSession, session_id: str) -> Optional[Session]:
    """Get a session by ID if it exists and hasn't expired."""
    stmt = select(Session).where(
        Session.id == session_id,
        Session.expires_at > utcnow()
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_session_user(db: AsyncSession, session_id: str) -> Optional[User]:
    """Get the user associated with a session."""
    session = await get_session(db, session_id)
    if not session:
        return None

    # Update last activity
    session.last_activity_at = utcnow()
    await db.commit()

    # Get user
    stmt = select(User).where(User.id == session.user_id, User.is_active == True)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def delete_session(db: AsyncSession, session_id: str) -> bool:
    """Delete a session (logout)."""
    stmt = delete(Session).where(Session.id == session_id)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount > 0


async def delete_user_sessions(db: AsyncSession, user_id: int) -> int:
    """Delete all sessions for a user."""
    stmt = delete(Session).where(Session.user_id == user_id)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount


async def cleanup_expired_sessions(db: AsyncSession) -> int:
    """Delete all expired sessions. Returns count of deleted sessions."""
    stmt = delete(Session).where(Session.expires_at < utcnow())
    result = await db.execute(stmt)
    await db.commit()
    deleted = result.rowcount
    if deleted > 0:
        logger.info(f"Cleaned up {deleted} expired sessions")
    return deleted


# ============================================================================
# Cookie Management
# ============================================================================

def set_session_cookie(response: Response, session: Session) -> None:
    """Set the session cookie on a response."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=int((session.expires_at - utcnow()).total_seconds()),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Clear the session cookie."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )


def get_session_id_from_request(request: Request) -> Optional[str]:
    """Extract session ID from request cookie."""
    return request.cookies.get(SESSION_COOKIE_NAME)


# ============================================================================
# Utility Functions
# ============================================================================

def get_client_ip(request: Request) -> str:
    """Get client IP from request, checking X-Forwarded-For header."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_user_count(db: AsyncSession) -> int:
    """Get total number of users."""
    from sqlalchemy import func
    stmt = select(func.count()).select_from(User)
    result = await db.execute(stmt)
    return result.scalar() or 0


async def is_setup_complete(db: AsyncSession) -> bool:
    """Check if initial setup is complete (at least one user exists)."""
    return await get_user_count(db) > 0


# ============================================================================
# FastAPI Dependencies
# ============================================================================

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    FastAPI dependency to get the current authenticated user.
    Raises 401 if not authenticated.
    """
    session_id = get_session_id_from_request(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await get_session_user(db, session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    return user


async def get_current_user_optional(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    FastAPI dependency to get the current user if authenticated.
    Returns None instead of raising if not authenticated.
    """
    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


async def require_admin(
    user: User = Depends(get_current_user)
) -> User:
    """
    FastAPI dependency that requires admin privileges.
    Raises 403 if user is not admin.
    """
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def require_setup_incomplete(
    db: AsyncSession = Depends(get_db)
) -> None:
    """
    FastAPI dependency that requires setup to be incomplete.
    Used for the initial setup endpoint.
    """
    if await is_setup_complete(db):
        raise HTTPException(status_code=400, detail="Setup already complete")
