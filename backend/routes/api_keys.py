"""
API Key management routes for DNSMon.
All endpoints require admin privileges.
"""

import secrets
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import ApiKey, KEY_PREFIX_LENGTH, User
from ..schemas import ApiKeyCreate
from ..auth import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])


@router.get("")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    """List all API keys (never returns raw key)."""
    stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
    result = await db.execute(stmt)
    return [key.to_dict() for key in result.scalars()]


@router.post("", status_code=201)
async def create_api_key(
    data: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a new API key. Returns the raw key once."""
    raw_key = f"dnsmon_{secrets.token_urlsafe(32)}"

    api_key = ApiKey(
        name=data.name,
        key_hash=ApiKey.hash_key(raw_key),
        key_prefix=raw_key[:KEY_PREFIX_LENGTH],
        is_admin=data.is_admin,
        expires_at=data.expires_at,
    )
    db.add(api_key)
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        error_info = str(e.orig) if e.orig else str(e)
        if "name" in error_info:
            raise HTTPException(status_code=400, detail="An API key with this name already exists")
        raise HTTPException(status_code=400, detail="Failed to create API key (duplicate value)")
    await db.refresh(api_key)

    logger.info(f"API key '{data.name}' created by {admin.username}")

    response = api_key.to_dict()
    response['raw_key'] = raw_key
    return response


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Revoke (delete) an API key."""
    stmt = select(ApiKey).where(ApiKey.id == key_id)
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    key_name = api_key.name
    await db.delete(api_key)
    await db.commit()

    logger.info(f"API key '{key_name}' revoked by {admin.username}")
    return {"message": f"API key '{key_name}' revoked"}
