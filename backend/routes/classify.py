from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, AppDefinition, AppDomain, DomainLabel
from ..schemas import ClassifyRequest
from ..auth import get_current_user, require_admin
from ..utils import registrable_domain
from ..classification_service import _slugify
from .app_definitions import _slugify_unique, _reclassify_async
from ._background import run_in_background

router = APIRouter(prefix="/api/classify", tags=["classify"])


def _resolve(domain: str, scope: str) -> str:
    return registrable_domain(domain) if scope == 'registrable' else domain.strip().rstrip('.').lower()


@router.post("")
async def classify(payload: ClassifyRequest, db: AsyncSession = Depends(get_db),
                   _: User = Depends(require_admin)):
    target = _resolve(payload.domain, payload.scope)
    if not target or '.' not in target:
        raise HTTPException(status_code=400, detail="Could not resolve a classifiable domain")
    app_name = (payload.app_name or '').strip() or None
    category = (payload.category or '').strip() or None

    if app_name:
        ad = (await db.execute(select(AppDefinition).where(
            AppDefinition.source == 'manual', AppDefinition.name == app_name,
            AppDefinition.is_category_only == False))).scalars().first()
        if ad is None:
            ad = AppDefinition(slug=await _slugify_unique(db, app_name), name=app_name,
                               category=category, source='manual', enabled=True,
                               is_category_only=False)
            db.add(ad)
            await db.flush()
        elif category is not None:
            ad.category = category
    else:
        slug = f"manual-cat-{_slugify(category)}"
        ad = (await db.execute(select(AppDefinition).where(
            AppDefinition.source == 'manual', AppDefinition.slug == slug,
            AppDefinition.is_category_only == True))).scalars().first()
        if ad is None:
            ad = AppDefinition(slug=slug, name=category, category=category,
                               source='manual', enabled=True, is_category_only=True)
            db.add(ad)
            await db.flush()

    exists = await db.scalar(select(AppDomain.id).where(
        AppDomain.app_id == ad.id, AppDomain.domain == target))
    if not exists:
        db.add(AppDomain(domain=target, app_id=ad.id, is_wildcard=False))
    await db.commit()
    run_in_background(_reclassify_async())
    return {"domain": target, "app_name": app_name, "category": category, "scope": payload.scope}


@router.delete("")
async def unclassify(domain: str, scope: str = 'registrable',
                     db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    if scope not in ('registrable', 'exact'):
        raise HTTPException(status_code=400, detail="scope must be 'registrable' or 'exact'")
    target = _resolve(domain, scope)
    manual_ids = (await db.execute(
        select(AppDefinition.id).where(AppDefinition.source == 'manual'))).scalars().all()
    if manual_ids:
        await db.execute(delete(AppDomain).where(
            AppDomain.domain == target, AppDomain.app_id.in_(manual_ids)))
        await db.flush()
        counts = (await db.execute(
            select(AppDefinition.id, func.count(AppDomain.id))
            .outerjoin(AppDomain, AppDomain.app_id == AppDefinition.id)
            .where(AppDefinition.source == 'manual').group_by(AppDefinition.id))).all()
        empty = [aid for aid, c in counts if c == 0]
        if empty:
            await db.execute(delete(AppDefinition).where(AppDefinition.id.in_(empty)))
    await db.commit()
    run_in_background(_reclassify_async())
    return {"domain": target, "removed": True}
