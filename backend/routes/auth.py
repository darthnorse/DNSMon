"""
Authentication routes - login, logout, setup, OIDC flow
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from urllib.parse import quote
import logging

from ..database import get_db
from ..models import User, OIDCProvider, AppSetting
from ..schemas import (
    LoginRequest, SetupRequest, UserResponse, AuthCheckResponse,
    OIDCProviderPublic
)
from ..auth import (
    hash_password, verify_password, create_session, delete_session,
    set_session_cookie, clear_session_cookie, get_current_user,
    get_current_user_optional, require_setup_incomplete,
    is_setup_complete, get_session_id_from_request, get_client_ip,
    check_login_rate_limit, record_login_attempt,
    generate_oidc_state, store_oidc_state, get_oidc_state, get_oidc_provider,
    create_oidc_authorization_url, exchange_oidc_code,
    extract_oidc_claims, find_or_create_oidc_user
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.get("/check")
async def check_auth(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> AuthCheckResponse:
    """Check authentication status - used on app load"""
    setup_complete = await is_setup_complete(db)
    user = await get_current_user_optional(request, db)

    # Transient API key users (id=-1) are authenticated but lack full profile fields
    user_response = None
    if user is not None:
        user_response = UserResponse(**user.to_dict())

    return AuthCheckResponse(
        authenticated=user is not None,
        user=user_response,
        setup_complete=setup_complete
    )


@router.post("/setup")
async def setup_admin(
    data: SetupRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_setup_incomplete)
):
    """Initial setup - create first admin user. Only works when no users exist."""
    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        is_active=True,
        is_admin=True
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    session = await create_session(db, user, request)
    set_session_cookie(response, session)

    logger.info(f"Setup complete: created admin user '{data.username}'")
    return {"message": "Setup complete", "user": user.to_dict()}


@router.post("/login")
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Login with username and password"""
    stmt = select(AppSetting).where(AppSetting.key == 'disable_local_auth')
    result = await db.execute(stmt)
    setting = result.scalar_one_or_none()
    if setting and setting.get_typed_value() is True:
        raise HTTPException(
            status_code=403,
            detail="Local password authentication is disabled. Please use SSO/OIDC."
        )

    client_ip = get_client_ip(request)
    if not check_login_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    if not await is_setup_complete(db):
        raise HTTPException(status_code=400, detail="Setup not complete. Please create an admin account first.")

    stmt = select(User).where(User.username == data.username.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.password_hash:
        record_login_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        record_login_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password(data.password, user.password_hash):
        record_login_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session = await create_session(db, user, request)
    set_session_cookie(response, session)

    logger.info(f"User '{user.username}' logged in from {client_ip}")
    return {"message": "Login successful", "user": user.to_dict()}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Logout - clear session"""
    session_id = get_session_id_from_request(request)
    if session_id:
        await delete_session(db, session_id)

    clear_session_cookie(response)
    return {"message": "Logged out"}


@router.get("/me")
async def get_me(
    user: User = Depends(get_current_user)
) -> UserResponse:
    """Get current authenticated user"""
    return UserResponse(**user.to_dict())


# OIDC Authentication Endpoints

@router.get("/oidc/providers")
async def list_oidc_providers_public(
    db: AsyncSession = Depends(get_db)
) -> List[OIDCProviderPublic]:
    """List enabled OIDC providers for login page (public)"""
    stmt = select(OIDCProvider).where(OIDCProvider.enabled == True).order_by(OIDCProvider.display_order)
    result = await db.execute(stmt)
    providers = result.scalars().all()
    return [OIDCProviderPublic(name=p.name, display_name=p.display_name) for p in providers]


@router.get("/oidc/{provider_name}/authorize")
async def oidc_authorize(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Start OIDC authorization flow - redirects to provider"""
    provider = await get_oidc_provider(db, provider_name)
    if not provider:
        raise HTTPException(status_code=404, detail="OIDC provider not found")

    callback_url = str(request.base_url).rstrip('/') + f"/api/auth/oidc/{provider_name}/callback"

    state = generate_oidc_state()
    store_oidc_state(state, provider_name, callback_url)

    auth_url = await create_oidc_authorization_url(provider, callback_url, state)

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oidc/{provider_name}/callback")
async def oidc_callback(
    provider_name: str,
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Handle OIDC callback - exchanges code for tokens and creates session"""
    if error:
        logger.warning(f"OIDC error from {provider_name}: {error} - {error_description}")
        error_msg = quote(error_description or error, safe='')
        return RedirectResponse(url=f"/login?error={error_msg}", status_code=302)

    if not code or not state:
        return RedirectResponse(url="/login?error=Invalid+callback+parameters", status_code=302)

    state_data = get_oidc_state(state)
    if not state_data:
        return RedirectResponse(url="/login?error=Invalid+or+expired+state", status_code=302)

    if state_data['provider_name'] != provider_name:
        return RedirectResponse(url="/login?error=State+provider+mismatch", status_code=302)

    provider = await get_oidc_provider(db, provider_name)
    if not provider:
        return RedirectResponse(url="/login?error=Provider+not+found", status_code=302)

    try:
        token_data = await exchange_oidc_code(provider, code, state_data['redirect_uri'])
        claims = extract_oidc_claims(provider, token_data['user_info'])
        user = await find_or_create_oidc_user(db, provider, claims)

        if not user.is_active:
            return RedirectResponse(url="/login?error=Account+is+disabled", status_code=302)

        session = await create_session(db, user, request)
        redirect_response = RedirectResponse(url="/", status_code=302)
        set_session_cookie(redirect_response, session)
        return redirect_response

    except HTTPException as e:
        logger.error(f"OIDC callback error: {e.detail}")
        error_msg = quote(str(e.detail), safe='')
        return RedirectResponse(url=f"/login?error={error_msg}", status_code=302)
    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        return RedirectResponse(url="/login?error=Authentication+failed", status_code=302)
