import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, delete, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, AppDefinition, AppDomain, DomainLabel
from ..schemas import AppDefinitionCreate, AppDefinitionUpdate, AppDefinitionResponse, FeedStatusResponse
from ..auth import get_current_user, require_admin
from ..config import get_settings_sync
from ..service import get_service
from ..constants import VALID_SOURCES

router = APIRouter(prefix="/api/app-definitions", tags=["app-definitions"])

# Hold strong references to background tasks so asyncio doesn't GC them mid-run.
_background_tasks: set = set()


def _run_in_background(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


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
    if source and source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail=f"Invalid source. Must be one of: {sorted(VALID_SOURCES)}")
    # 'blocklist' is engine-only (absent from VALID_SOURCES, so ?source=blocklist is
    # rejected above) and its pseudo-app carries ~546k domains — keep it out of this list.
    stmt = select(AppDefinition).where(AppDefinition.source != 'blocklist').order_by(AppDefinition.name)
    if source:
        stmt = stmt.where(AppDefinition.source == source)
    defs = (await db.execute(stmt)).scalars().all()
    ids = [d.id for d in defs]
    domain_map: dict[int, list[str]] = {}
    if ids:
        rows = await db.execute(select(AppDomain.app_id, AppDomain.domain).where(AppDomain.app_id.in_(ids)))
        for app_id, domain in rows:
            domain_map.setdefault(app_id, []).append(domain)
    out = [AppDefinitionResponse.model_validate(d.to_dict(domains=domain_map.get(d.id, []))) for d in defs]
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
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="An app with this name already exists")
    await db.refresh(ad)
    _run_in_background(_reclassify_async())
    return AppDefinitionResponse.model_validate(ad.to_dict(domains=domains))


@router.put("/{def_id}", response_model=AppDefinitionResponse)
async def update_definition(def_id: int, payload: AppDefinitionUpdate,
                            db: AsyncSession = Depends(get_db),
                            _: User = Depends(require_admin)):
    ad = await db.get(AppDefinition, def_id)
    # blocklist pseudo-apps are managed via /api/blocklist-sources, not here —
    # treat them as absent so this endpoint can't toggle them or serialize ~547k domains.
    if not ad or ad.source == 'blocklist':
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
    _run_in_background(_reclassify_async())
    return AppDefinitionResponse.model_validate(ad.to_dict(domains=await _domains_for(db, ad.id)))


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
    _run_in_background(_reclassify_async())
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
    _run_in_background(svc.run_full(
        feed_enabled=s.classification_feed_enabled,
        supplement_enabled=s.classification_supplement_enabled,
        url=s.classification_feed_url))
    return {"message": "Refresh started"}
