from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, InsightSource, SettingsChangelog
from ..schemas import InsightSourceResponse, InsightSourceUpdate
from ..auth import get_current_user, require_admin
from ..constants import THREAT_SOURCES
from ..service import get_service
from ._background import run_in_background

router = APIRouter(prefix="/api/insight-sources", tags=["insight-sources"])

MAX_API_KEY_LENGTH = 512


def _trigger_full_refresh():
    svc = get_service().classification_service
    run_in_background(svc.run_full())


def _trigger_kind_refresh(kind: str):
    svc = get_service().classification_service
    run_in_background(svc.refresh_and_reclassify_kind(kind))


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

    fields = payload.model_dump(exclude_unset=True)
    key_changed = False
    if 'api_key' in fields:
        new_key = (fields['api_key'] or '').strip() or None
        if new_key and len(new_key) > MAX_API_KEY_LENGTH:
            raise HTTPException(status_code=400, detail="API key is too long")
        key_changed = src.api_key != new_key
        if key_changed:
            # Presence only, never the value. Nothing surfaces this table today;
            # it is queryable via psql, matching how server changes are recorded.
            db.add(SettingsChangelog(
                setting_key=f"insight_source.{src.kind}.api_key",
                old_value='set' if src.api_key else 'unset',
                new_value='set' if new_key else 'unset',
                change_type='insight_source',
                requires_restart=False))
        src.api_key = new_key

    enabled = fields.get('enabled', src.enabled)
    toggled = src.enabled != enabled

    if enabled and src.kind in THREAT_SOURCES and not src.api_key:
        raise HTTPException(
            status_code=400,
            detail=("API key required before enabling this source" if toggled
                    else "Disable this source before clearing its API key"))

    src.enabled = enabled
    if toggled and not enabled:
        # Otherwise the panel keeps showing the last failure of a feed the admin
        # has deliberately turned off. Dropping the high-water mark also gives
        # them an immediate way to accept a legitimately smaller feed.
        src.last_status = None
        src.last_error = None
        src.domain_count_high_water = None
        src.shrink_candidate_count = None
        src.shrink_streak = None

    await db.commit()
    await db.refresh(src)
    # A no-op save shouldn't kick off an HTTP fetch + reclassify.
    if toggled or (key_changed and src.enabled):
        _trigger_kind_refresh(src.kind)
    return InsightSourceResponse.model_validate(src)


@router.post("/refresh")
async def refresh_sources(_: User = Depends(require_admin)):
    _trigger_full_refresh()
    return {"message": "Refresh started"}
