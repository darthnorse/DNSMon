from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, InsightSource
from ..schemas import InsightSourceResponse, InsightSourceUpdate
from ..auth import get_current_user, require_admin
from ..service import get_service
from ._background import run_in_background

router = APIRouter(prefix="/api/blocklist-sources", tags=["blocklist-sources"])


def _trigger_refresh():
    svc = get_service().classification_service
    run_in_background(svc.refresh_and_reclassify_blocklists())


@router.get("", response_model=List[InsightSourceResponse])
async def list_sources(db: AsyncSession = Depends(get_db),
                       _: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(InsightSource).order_by(InsightSource.name))).scalars().all()
    return [InsightSourceResponse.model_validate(r) for r in rows]


@router.patch("/{source_id}", response_model=InsightSourceResponse)
async def update_source(source_id: int, payload: InsightSourceUpdate,
                        db: AsyncSession = Depends(get_db),
                        _: User = Depends(require_admin)):
    src = await db.get(InsightSource, source_id)
    if not src:
        raise HTTPException(status_code=404, detail="Insight source not found")
    changed = src.enabled != payload.enabled
    src.enabled = payload.enabled
    await db.commit()
    await db.refresh(src)
    if changed:  # a no-op toggle shouldn't kick off an HTTP fetch + reclassify
        _trigger_refresh()
    return InsightSourceResponse.model_validate(src)


@router.post("/refresh")
async def refresh_sources(_: User = Depends(require_admin)):
    _trigger_refresh()
    return {"message": "Refresh started"}
