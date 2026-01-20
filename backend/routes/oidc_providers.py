"""
OIDC Provider management routes (admin only)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import logging

from ..database import get_db
from ..models import User, OIDCProvider
from ..schemas import OIDCProviderCreate, OIDCProviderUpdate, OIDCProviderResponse
from ..auth import require_admin, discover_oidc_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/oidc-providers", tags=["oidc-providers"])


@router.get("")
async def list_oidc_providers(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
) -> List[OIDCProviderResponse]:
    """List all OIDC providers (admin only)"""
    stmt = select(OIDCProvider).order_by(OIDCProvider.display_order)
    result = await db.execute(stmt)
    providers = result.scalars().all()
    return [OIDCProviderResponse(**p.to_dict(mask_secret=True)) for p in providers]


@router.post("")
async def create_oidc_provider(
    data: OIDCProviderCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
) -> OIDCProviderResponse:
    """Create a new OIDC provider (admin only)"""
    # Check if name exists
    stmt = select(OIDCProvider).where(OIDCProvider.name == data.name)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Provider name already exists")

    provider = OIDCProvider(
        name=data.name,
        display_name=data.display_name,
        issuer_url=data.issuer_url,
        client_id=data.client_id,
        client_secret=data.client_secret,
        scopes=data.scopes,
        username_claim=data.username_claim,
        email_claim=data.email_claim,
        display_name_claim=data.display_name_claim,
        groups_claim=data.groups_claim,
        admin_group=data.admin_group,
        enabled=data.enabled,
        display_order=data.display_order,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)

    logger.info(f"Admin '{admin.username}' created OIDC provider '{provider.name}'")
    return OIDCProviderResponse(**provider.to_dict(mask_secret=True))


@router.put("/{provider_id}")
async def update_oidc_provider(
    provider_id: int,
    data: OIDCProviderUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
) -> OIDCProviderResponse:
    """Update an OIDC provider (admin only)"""
    stmt = select(OIDCProvider).where(OIDCProvider.id == provider_id)
    result = await db.execute(stmt)
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(status_code=404, detail="OIDC provider not found")

    if data.display_name is not None:
        provider.display_name = data.display_name
    if data.issuer_url is not None:
        provider.issuer_url = data.issuer_url.rstrip('/')
    if data.client_id is not None:
        provider.client_id = data.client_id
    if data.client_secret:  # Only update if provided (not empty)
        provider.client_secret = data.client_secret
    if data.scopes is not None:
        provider.scopes = data.scopes
    if data.username_claim is not None:
        provider.username_claim = data.username_claim
    if data.email_claim is not None:
        provider.email_claim = data.email_claim
    if data.display_name_claim is not None:
        provider.display_name_claim = data.display_name_claim
    if data.groups_claim is not None:
        provider.groups_claim = data.groups_claim or None
    if data.admin_group is not None:
        provider.admin_group = data.admin_group or None
    if data.enabled is not None:
        provider.enabled = data.enabled
    if data.display_order is not None:
        provider.display_order = data.display_order

    await db.commit()
    await db.refresh(provider)

    logger.info(f"Admin '{admin.username}' updated OIDC provider '{provider.name}'")
    return OIDCProviderResponse(**provider.to_dict(mask_secret=True))


@router.delete("/{provider_id}")
async def delete_oidc_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Delete an OIDC provider (admin only)"""
    stmt = select(OIDCProvider).where(OIDCProvider.id == provider_id)
    result = await db.execute(stmt)
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(status_code=404, detail="OIDC provider not found")

    provider_name = provider.name
    await db.delete(provider)
    await db.commit()

    logger.info(f"Admin '{admin.username}' deleted OIDC provider '{provider_name}'")
    return {"message": f"OIDC provider '{provider_name}' deleted"}


@router.post("/test")
async def test_oidc_provider(
    data: OIDCProviderCreate,
    _: User = Depends(require_admin)
):
    """Test OIDC provider configuration by fetching discovery document"""
    try:
        config = await discover_oidc_config(data.issuer_url)
        return {
            "success": True,
            "message": "Successfully connected to OIDC provider",
            "endpoints": {
                "authorization": config.get('authorization_endpoint'),
                "token": config.get('token_endpoint'),
                "userinfo": config.get('userinfo_endpoint'),
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to connect: {str(e)}"
        }


@router.post("/{provider_id}/test")
async def test_existing_oidc_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Test an existing OIDC provider using saved credentials"""
    stmt = select(OIDCProvider).where(OIDCProvider.id == provider_id)
    result = await db.execute(stmt)
    provider = result.scalar_one_or_none()

    if not provider:
        raise HTTPException(status_code=404, detail="OIDC provider not found")

    try:
        config = await discover_oidc_config(provider.issuer_url)
        return {
            "success": True,
            "message": "Successfully connected to OIDC provider",
            "endpoints": {
                "authorization": config.get('authorization_endpoint'),
                "token": config.get('token_endpoint'),
                "userinfo": config.get('userinfo_endpoint'),
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to connect: {str(e)}"
        }
