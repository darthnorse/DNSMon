import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, delete, insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, AppDefinition, AppDomain, DomainLabel
from ..schemas import AppDefinitionCreate, AppDefinitionUpdate, AppDefinitionResponse, FeedStatusResponse
from ..auth import get_current_user, require_admin
from ..config import get_settings_sync
from ..service import get_service

router = APIRouter(prefix="/api/app-definitions", tags=["app-definitions"])


async def _domains_for(db: AsyncSession, app_id: int) -> List[str]:
    rows = await db.execute(select(AppDomain.domain).where(AppDomain.app_id == app_id))
    return list(rows.scalars())


async def _slugify_unique(db: AsyncSession, name: str) -> str:
    base = ''.join(c if c.isalnum() else '-' for c in name.lower()).strip('-')[:90] or 'app'
    slug = base
    n = 1
    while await db.scalar(select(AppDefinition.id).where(
            AppDefinition.source == 'manual', AppDefinition.slug == slug)):
        n += 1
        slug = f"{base}-{n}"
    return slug


async def _reclassify_async():
    """Rebuild domain_labels after a definition change."""
    from ..database import async_session_maker
    svc = get_service().classification_service
    async with async_session_maker() as db:
        await svc.reclassify(db)


@router.get("", response_model=List[AppDefinitionResponse])
async def list_definitions(source: Optional[str] = None,
                           db: AsyncSession = Depends(get_db),
                           _: User = Depends(get_current_user)):
    stmt = select(AppDefinition).order_by(AppDefinition.name)
    if source:
        stmt = stmt.where(AppDefinition.source == source)
    defs = (await db.execute(stmt)).scalars().all()
    out = []
    for d in defs:
        out.append(AppDefinitionResponse.model_validate(
            {**d.to_dict(domains=await _domains_for(db, d.id))}))
    return out


@router.post("", response_model=AppDefinitionResponse)
async def create_definition(payload: AppDefinitionCreate,
                            db: AsyncSession = Depends(get_db),
                            _: User = Depends(require_admin)):
    slug = await _slugify_unique(db, payload.name)
    ad = AppDefinition(slug=slug, name=payload.name, category=payload.category,
                       source='manual', enabled=payload.enabled)
    db.add(ad)
    await db.flush()
    domains = [d.strip().lower() for d in payload.domains if d.strip()]
    if domains:
        await db.execute(insert(AppDomain),
                         [{'domain': d, 'app_id': ad.id, 'is_wildcard': '*' in d} for d in domains])
    await db.commit()
    await db.refresh(ad)
    await _reclassify_async()
    return AppDefinitionResponse.model_validate({**ad.to_dict(domains=domains)})


@router.put("/{def_id}", response_model=AppDefinitionResponse)
async def update_definition(def_id: int, payload: AppDefinitionUpdate,
                            db: AsyncSession = Depends(get_db),
                            _: User = Depends(require_admin)):
    ad = await db.get(AppDefinition, def_id)
    if not ad:
        raise HTTPException(status_code=404, detail="App definition not found")

    data = payload.model_dump(exclude_unset=True)
    # `enabled` can be toggled on any source; other edits are manual-only.
    if ad.source != 'manual' and (set(data.keys()) - {'enabled'}):
        raise HTTPException(status_code=400,
                            detail="Only the 'enabled' flag can be changed on feed/supplement apps")

    if 'name' in data and data['name'] is not None:
        ad.name = data['name']
    if 'category' in data:
        ad.category = data['category']
    if 'enabled' in data and data['enabled'] is not None:
        ad.enabled = data['enabled']
    if 'domains' in data and data['domains'] is not None:
        await db.execute(delete(AppDomain).where(AppDomain.app_id == ad.id))
        domains = [d.strip().lower() for d in data['domains'] if d.strip()]
        if domains:
            await db.execute(insert(AppDomain),
                             [{'domain': d, 'app_id': ad.id, 'is_wildcard': '*' in d} for d in domains])
    await db.commit()
    await db.refresh(ad)
    await _reclassify_async()
    return AppDefinitionResponse.model_validate({**ad.to_dict(domains=await _domains_for(db, ad.id))})


@router.delete("/{def_id}")
async def delete_definition(def_id: int, db: AsyncSession = Depends(get_db),
                            _: User = Depends(require_admin)):
    ad = await db.get(AppDefinition, def_id)
    if not ad:
        raise HTTPException(status_code=404, detail="App definition not found")
    if ad.source != 'manual':
        raise HTTPException(status_code=400, detail="Only manual app definitions can be deleted")
    await db.delete(ad)
    await db.commit()
    await _reclassify_async()
    return {"message": "App definition deleted"}


@router.get("/feed-status", response_model=FeedStatusResponse)
async def feed_status(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    async def count(src):
        return await db.scalar(select(func.count()).select_from(AppDefinition).where(AppDefinition.source == src)) or 0
    last = await db.scalar(select(func.max(AppDefinition.updated_at)).where(AppDefinition.source == 'adguard'))
    labeled = await db.scalar(select(func.count()).select_from(DomainLabel).where(DomainLabel.app_id.isnot(None))) or 0
    s = get_settings_sync()
    return FeedStatusResponse(
        feed_enabled=s.classification_feed_enabled, feed_url=s.classification_feed_url,
        supplement_enabled=s.classification_supplement_enabled,
        adguard_app_count=await count('adguard'), supplement_app_count=await count('supplement'),
        manual_app_count=await count('manual'), labeled_domain_count=labeled, last_refreshed_at=last,
    )


@router.post("/refresh")
async def refresh_feed(_: User = Depends(require_admin)):
    """Trigger a feed refresh + reclassify (admin)."""
    s = get_settings_sync()
    svc = get_service().classification_service
    asyncio.create_task(svc.run_full(
        feed_enabled=s.classification_feed_enabled,
        supplement_enabled=s.classification_supplement_enabled,
        url=s.classification_feed_url))
    return {"message": "Refresh started"}
