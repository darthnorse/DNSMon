"""
Authentication service for DNSMon.
Handles password hashing, session management, OIDC, and auth dependencies.
"""

import os
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from fastapi import Request, Response, HTTPException, Depends
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from .database import get_db
from .models import User, Session, OIDCProvider, utcnow

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session settings
SESSION_TOKEN_BYTES = 32  # 64 hex characters
DEFAULT_SESSION_HOURS = 24
SESSION_COOKIE_NAME = "dnsmon_session"

# Secret key for cookie signing (should be set via environment variable)
SECRET_KEY = os.getenv("PIDASH_SECRET_KEY", secrets.token_hex(32))
COOKIE_SECURE = os.getenv("PIDASH_COOKIE_SECURE", "false").lower() == "true"


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
    return result.rowcount


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


# ============================================================================
# OIDC Support
# ============================================================================

# In-memory state storage (simple approach - cleared on restart)
# For production with multiple instances, use Redis or database
_oidc_states: Dict[str, Dict[str, Any]] = {}

OIDC_STATE_EXPIRY_MINUTES = 10


# ============================================================================
# Rate Limiting (Login)
# ============================================================================

# In-memory rate limit tracking (cleared on restart)
# For production with multiple instances, use Redis
_login_attempts: Dict[str, list] = {}

LOGIN_RATE_LIMIT_ATTEMPTS = 5  # Max attempts
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60  # Window in seconds


def check_login_rate_limit(ip_address: str) -> bool:
    """
    Check if IP address is rate limited.
    Returns True if allowed, False if rate limited.
    """
    now = utcnow()
    cutoff = now - timedelta(seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS)

    # Get attempts for this IP
    attempts = _login_attempts.get(ip_address, [])

    # Filter to only recent attempts
    recent_attempts = [t for t in attempts if t > cutoff]

    # Update stored attempts
    _login_attempts[ip_address] = recent_attempts

    # Check if under limit
    return len(recent_attempts) < LOGIN_RATE_LIMIT_ATTEMPTS


def record_login_attempt(ip_address: str) -> None:
    """Record a login attempt for rate limiting."""
    now = utcnow()
    if ip_address not in _login_attempts:
        _login_attempts[ip_address] = []
    _login_attempts[ip_address].append(now)

    # Cleanup old entries periodically (every 100th call)
    if len(_login_attempts) > 100:
        cleanup_login_attempts()


def cleanup_login_attempts() -> None:
    """Remove expired login attempt records."""
    cutoff = utcnow() - timedelta(seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS * 2)
    expired_ips = []
    for ip, attempts in _login_attempts.items():
        recent = [t for t in attempts if t > cutoff]
        if not recent:
            expired_ips.append(ip)
        else:
            _login_attempts[ip] = recent
    for ip in expired_ips:
        _login_attempts.pop(ip, None)


def generate_oidc_state() -> str:
    """Generate a cryptographically secure state parameter for OIDC."""
    return secrets.token_urlsafe(32)


def store_oidc_state(state: str, provider_name: str, redirect_uri: str) -> None:
    """Store OIDC state for validation during callback."""
    _oidc_states[state] = {
        'provider_name': provider_name,
        'redirect_uri': redirect_uri,
        'created_at': utcnow(),
    }
    # Clean up old states
    cleanup_oidc_states()


def get_oidc_state(state: str) -> Optional[Dict[str, Any]]:
    """Retrieve and remove OIDC state (one-time use)."""
    data = _oidc_states.pop(state, None)
    if not data:
        return None
    # Check expiry
    if utcnow() - data['created_at'] > timedelta(minutes=OIDC_STATE_EXPIRY_MINUTES):
        return None
    return data


def cleanup_oidc_states() -> None:
    """Remove expired OIDC states."""
    cutoff = utcnow() - timedelta(minutes=OIDC_STATE_EXPIRY_MINUTES)
    expired = [k for k, v in _oidc_states.items() if v['created_at'] < cutoff]
    for k in expired:
        _oidc_states.pop(k, None)


async def get_oidc_provider(db: AsyncSession, name: str) -> Optional[OIDCProvider]:
    """Get an enabled OIDC provider by name."""
    stmt = select(OIDCProvider).where(
        OIDCProvider.name == name,
        OIDCProvider.enabled == True
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def discover_oidc_config(issuer_url: str) -> Dict[str, Any]:
    """Fetch OIDC discovery document from issuer."""
    discovery_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url, timeout=10.0)
        response.raise_for_status()
        return response.json()


async def create_oidc_authorization_url(
    provider: OIDCProvider,
    redirect_uri: str,
    state: str
) -> str:
    """Create the authorization URL for OIDC redirect."""
    try:
        config = await discover_oidc_config(provider.issuer_url)
        auth_endpoint = config['authorization_endpoint']
    except Exception as e:
        logger.error(f"Failed to discover OIDC config for {provider.name}: {e}")
        raise HTTPException(status_code=502, detail="Failed to contact identity provider")

    params = {
        'client_id': provider.client_id,
        'response_type': 'code',
        'scope': provider.scopes,
        'redirect_uri': redirect_uri,
        'state': state,
    }

    return f"{auth_endpoint}?{urlencode(params)}"


async def exchange_oidc_code(
    provider: OIDCProvider,
    code: str,
    redirect_uri: str
) -> Dict[str, Any]:
    """Exchange authorization code for tokens and user info."""
    try:
        config = await discover_oidc_config(provider.issuer_url)
    except Exception as e:
        logger.error(f"Failed to discover OIDC config for {provider.name}: {e}")
        raise HTTPException(status_code=502, detail="Failed to contact identity provider")

    token_endpoint = config['token_endpoint']
    userinfo_endpoint = config.get('userinfo_endpoint')

    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            token_endpoint,
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': provider.client_id,
                'client_secret': provider.client_secret,
            },
            timeout=10.0
        )
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            raise HTTPException(status_code=401, detail="Authentication failed")

        tokens = token_response.json()

        # Get user info (prefer userinfo endpoint, fall back to ID token claims)
        user_info = {}
        if userinfo_endpoint and 'access_token' in tokens:
            try:
                userinfo_response = await client.get(
                    userinfo_endpoint,
                    headers={'Authorization': f"Bearer {tokens['access_token']}"},
                    timeout=10.0
                )
                if userinfo_response.status_code == 200:
                    user_info = userinfo_response.json()
            except Exception as e:
                logger.warning(f"Failed to fetch userinfo: {e}")

        # If no userinfo, try to decode ID token (basic decode, not full validation)
        if not user_info and 'id_token' in tokens:
            try:
                import base64
                import json
                # Simple JWT decode (payload is second segment)
                payload = tokens['id_token'].split('.')[1]
                # Add padding if needed
                payload += '=' * (4 - len(payload) % 4)
                user_info = json.loads(base64.urlsafe_b64decode(payload))
            except Exception as e:
                logger.warning(f"Failed to decode id_token: {e}")

        return {
            'tokens': tokens,
            'user_info': user_info,
        }


def extract_oidc_claims(provider: OIDCProvider, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Extract user claims from OIDC user info based on provider configuration."""
    username = user_info.get(provider.username_claim) or user_info.get('sub')
    email = user_info.get(provider.email_claim)
    display_name = user_info.get(provider.display_name_claim)
    groups = user_info.get(provider.groups_claim, []) if provider.groups_claim else []

    # Determine if user should be admin based on group membership
    is_admin = False
    if provider.admin_group and groups:
        if isinstance(groups, list):
            is_admin = provider.admin_group in groups
        elif isinstance(groups, str):
            is_admin = provider.admin_group == groups

    return {
        'username': username,
        'email': email,
        'display_name': display_name,
        'groups': groups,
        'is_admin': is_admin,
        'sub': user_info.get('sub'),
    }


async def find_or_create_oidc_user(
    db: AsyncSession,
    provider: OIDCProvider,
    claims: Dict[str, Any]
) -> User:
    """Find existing user or create new one from OIDC claims."""
    sub = claims.get('sub')
    if not sub:
        raise HTTPException(status_code=400, detail="Missing 'sub' claim from identity provider")

    # First, try to find user by OIDC subject
    stmt = select(User).where(
        User.oidc_provider == provider.name,
        User.oidc_subject == sub
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        # Update user info from latest claims
        if claims.get('email'):
            user.email = claims['email'].lower()
        if claims.get('display_name'):
            user.display_name = claims['display_name']
        # Update admin status if group-based admin is configured
        if provider.admin_group:
            user.is_admin = claims.get('is_admin', False)
        user.last_login_at = utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    # Try to find by username (for linking existing local accounts)
    username = claims.get('username')
    if username:
        stmt = select(User).where(User.username == username.lower())
        result = await db.execute(stmt)
        existing_user = result.scalar_one_or_none()
        if existing_user:
            # Link OIDC to existing account
            existing_user.oidc_provider = provider.name
            existing_user.oidc_subject = sub
            if claims.get('email') and not existing_user.email:
                existing_user.email = claims['email'].lower()
            if claims.get('display_name') and not existing_user.display_name:
                existing_user.display_name = claims['display_name']
            existing_user.last_login_at = utcnow()
            await db.commit()
            await db.refresh(existing_user)
            logger.info(f"Linked OIDC {provider.name} to existing user {existing_user.username}")
            return existing_user

    # Create new user
    # Generate unique username if needed
    base_username = (username or sub).lower()
    # Remove invalid characters
    import re
    base_username = re.sub(r'[^a-z0-9_-]', '', base_username)[:50]
    if not base_username:
        base_username = 'user'

    final_username = base_username
    counter = 1
    while True:
        stmt = select(User).where(User.username == final_username)
        result = await db.execute(stmt)
        if not result.scalar_one_or_none():
            break
        final_username = f"{base_username}{counter}"
        counter += 1

    new_user = User(
        username=final_username,
        email=claims.get('email', '').lower() if claims.get('email') else None,
        display_name=claims.get('display_name'),
        oidc_provider=provider.name,
        oidc_subject=sub,
        is_admin=claims.get('is_admin', False),
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    logger.info(f"Created new user {new_user.username} from OIDC {provider.name}")
    return new_user
