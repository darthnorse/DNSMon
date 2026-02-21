"""
Authentication service for DNSMon.
Handles password hashing, session management, OIDC, and auth dependencies.
"""

import os
import re
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
from .models import User, Session, OIDCProvider, ApiKey, utcnow
from .utils import validate_url_safety, async_validate_url_safety

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_HOURS = 24
SESSION_COOKIE_NAME = "dnsmon_session"

COOKIE_SECURE = (os.getenv("DNSMON_COOKIE_SECURE") or os.getenv("PIDASH_COOKIE_SECURE", "false")).lower() == "true"


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

    session.last_activity_at = utcnow()
    await db.commit()

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
    """Get client IP from request.

    Uses request.client.host directly. For deployments behind a reverse proxy,
    configure uvicorn's --proxy-headers --forwarded-allow-ips flags instead of
    trusting X-Forwarded-For here (which is client-spoofable).
    """
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

API_KEY_USER_SENTINEL_ID = -1


async def _get_user_from_api_key(token: str, db: AsyncSession, client_ip: str) -> User:
    """
    Validate a Bearer token against stored API keys.
    Returns a transient User object if valid, raises 401 otherwise.
    """
    if not _api_key_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Too many invalid API key attempts. Please try again later.")

    key_hash = ApiKey.hash_key(token)
    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        _api_key_limiter.record(client_ip)
        raise HTTPException(status_code=401, detail="Invalid API key")

    if api_key.expires_at and api_key.expires_at < utcnow():
        _api_key_limiter.record(client_ip)
        raise HTTPException(status_code=401, detail="API key has expired")

    now = utcnow()
    if not api_key.last_used_at or (now - api_key.last_used_at) > timedelta(minutes=5):
        api_key.last_used_at = now
        await db.commit()

    # Sentinel ID can never match a real DB row, preventing false
    # positives in user self-protection guards (e.g. "cannot delete yourself")
    user = User(
        id=API_KEY_USER_SENTINEL_ID,
        username=f"api-key:{api_key.name}",
        is_admin=api_key.is_admin,
        is_active=True,
    )
    return user


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    FastAPI dependency to get the current authenticated user.
    If an Authorization: Bearer header is present, only API key auth is
    attempted (no fallback to session cookie). Otherwise checks session cookie.
    Raises 401 if not authenticated.
    """
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        return await _get_user_from_api_key(token, db, get_client_ip(request))

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
# Rate Limiting
# ============================================================================

class InMemoryRateLimiter:
    """Simple in-memory rate limiter by key (e.g. IP address).
    For production with multiple instances, use Redis."""

    def __init__(self, max_attempts: int, window_seconds: int):
        self._attempts: Dict[str, list[datetime]] = {}
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def check(self, key: str) -> bool:
        """Returns True if allowed, False if rate limited."""
        cutoff = utcnow() - timedelta(seconds=self.window_seconds)
        attempts = self._attempts.get(key, [])
        recent = [t for t in attempts if t > cutoff]
        if recent:
            self._attempts[key] = recent
        elif key in self._attempts:
            del self._attempts[key]
        return len(recent) < self.max_attempts

    def record(self, key: str) -> None:
        """Record a failed attempt."""
        now = utcnow()
        if key not in self._attempts:
            self._attempts[key] = []
        self._attempts[key].append(now)
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        if len(self._attempts) > 100:
            self._cleanup()

    def _cleanup(self) -> None:
        """Remove keys whose attempts have all expired."""
        cutoff = utcnow() - timedelta(seconds=self.window_seconds)
        expired = [k for k, v in self._attempts.items() if not any(t > cutoff for t in v)]
        for k in expired:
            self._attempts.pop(k, None)


_login_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=60)
_api_key_limiter = InMemoryRateLimiter(max_attempts=10, window_seconds=60)


# Backwards-compatible aliases used by routes/auth.py
def check_login_rate_limit(ip_address: str) -> bool:
    return _login_limiter.check(ip_address)


def record_login_attempt(ip_address: str) -> None:
    _login_limiter.record(ip_address)


def generate_oidc_state() -> str:
    """Generate a cryptographically secure state parameter for OIDC."""
    return secrets.token_urlsafe(32)


def store_oidc_state(state: str, provider_name: str, redirect_uri: str) -> None:
    """Store OIDC state for validation during callback."""
    cleanup_oidc_states()
    if len(_oidc_states) >= 10000:
        oldest_key = next(iter(_oidc_states))
        _oidc_states.pop(oldest_key, None)
    _oidc_states[state] = {
        'provider_name': provider_name,
        'redirect_uri': redirect_uri,
        'created_at': utcnow(),
    }


def get_oidc_state(state: str) -> Optional[Dict[str, Any]]:
    """Retrieve and remove OIDC state (one-time use)."""
    data = _oidc_states.pop(state, None)
    if not data:
        return None
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
    safety_err = await async_validate_url_safety(issuer_url)
    if safety_err:
        raise ValueError(f"Blocked OIDC issuer URL: {safety_err}")
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


async def _fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    """Fetch JSON Web Key Set from provider."""
    safety_err = await async_validate_url_safety(jwks_uri)
    if safety_err:
        raise ValueError(f"Blocked jwks_uri: {safety_err}")
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_uri, timeout=10.0)
        response.raise_for_status()
        return response.json()


async def _decode_id_token(
    id_token: str,
    oidc_config: Dict[str, Any],
    provider: OIDCProvider
) -> Dict[str, Any]:
    """Decode and verify an OIDC ID token.

    Attempts signature verification via the provider's JWKS endpoint.
    If the provider has no jwks_uri, falls back to unverified decode with a warning.
    """
    jwks_uri = oidc_config.get('jwks_uri')

    # Try verified decode first
    if jwks_uri:
        try:
            from jose import jwt as jose_jwt, JWTError
            from jose.exceptions import JWKError

            jwks = await _fetch_jwks(jwks_uri)
            claims = jose_jwt.decode(
                id_token,
                jwks,
                algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
                audience=provider.client_id,
                issuer=provider.issuer_url,
            )
            logger.info(f"ID token verified for OIDC provider {provider.name}")
            return claims
        except (JWTError, JWKError) as e:
            logger.error(f"ID token signature rejected for {provider.name}: {e}")
            raise ValueError(f"ID token verification failed") from e
        except Exception as e:
            logger.error(f"Failed to fetch JWKS for {provider.name}: {e}")
            raise ValueError(f"Unable to verify ID token") from e

    # No jwks_uri — fall back to unverified decode with warning
    logger.warning(
        f"OIDC provider {provider.name} has no jwks_uri in discovery document; "
        f"ID token claims cannot be verified"
    )
    try:
        import base64
        import json
        payload = id_token.split('.')[1]
        payload += '=' * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        logger.error(f"Failed to decode id_token for {provider.name}: {e}")
        raise ValueError(f"ID token decode failed") from e


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

    # Validate endpoints from discovery document against SSRF
    for ep_name, ep_url in [('token_endpoint', token_endpoint), ('userinfo_endpoint', userinfo_endpoint)]:
        if ep_url:
            safety_err = await async_validate_url_safety(ep_url)
            if safety_err:
                logger.error(f"OIDC {ep_name} blocked for {provider.name}: {safety_err}")
                raise HTTPException(status_code=502, detail=f"OIDC provider returned unsafe {ep_name}")

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
            logger.error(f"Token exchange failed for {provider.name}: HTTP {token_response.status_code}")
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

        # If no userinfo, decode ID token with signature verification
        if not user_info and 'id_token' in tokens:
            user_info = await _decode_id_token(
                tokens['id_token'], config, provider
            )

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

    async def _link_and_return(user_to_link: User, link_oidc: bool = False, log_msg: str = "") -> User:
        """Update claims on a user, optionally link OIDC, commit, and return."""
        if link_oidc:
            user_to_link.oidc_provider = provider.name
            user_to_link.oidc_subject = sub
        if claims.get('email'):
            if not user_to_link.email or not link_oidc:
                user_to_link.email = claims['email'].lower()
        if claims.get('display_name'):
            if not user_to_link.display_name or not link_oidc:
                user_to_link.display_name = claims['display_name']
        if provider.admin_group:
            user_to_link.is_admin = claims.get('is_admin', False)
        user_to_link.last_login_at = utcnow()
        await db.commit()
        await db.refresh(user_to_link)
        if log_msg:
            logger.info(log_msg)
        return user_to_link

    if user:
        return await _link_and_return(user)

    # Auto-link by email only (not username — usernames across identity boundaries are unreliable).
    # Only link to accounts without a local password to prevent account takeover.
    email = claims.get('email')
    if email:
        stmt = select(User).where(User.email == email.lower())
        result = await db.execute(stmt)
        existing_user = result.scalar_one_or_none()
        if existing_user:
            if not existing_user.password_hash:
                return await _link_and_return(
                    existing_user, link_oidc=True,
                    log_msg=f"Linked OIDC {provider.name} to existing user {existing_user.username} by email",
                )
            logger.warning(f"OIDC {provider.name}: skipped auto-link to {existing_user.username} (has local password)")

    username = claims.get('username')
    base_username = (username or sub).lower()
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
