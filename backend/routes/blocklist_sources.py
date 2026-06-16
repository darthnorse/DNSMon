import asyncio
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, BlocklistSource
from ..schemas import BlocklistSourceResponse, BlocklistSourceUpdate
from ..auth import get_current_user, require_admin
from ..service import get_service

router = APIRouter(prefix="/api/blocklist-sources", tags=["blocklist-sources"])

# Hold strong references so asyncio doesn't GC background tasks mid-run.
_background_tasks: set = set()


def _run_in_background(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def _trigger_refresh():
    svc = get_service().classification_service
    _run_in_background(svc.refresh_and_reclassify_blocklists())


@router.get("", response_model=List[BlocklistSourceResponse])
async def list_sources(db: AsyncSession = Depends(get_db),
                       _: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(BlocklistSource).order_by(BlocklistSource.name))).scalars().all()
    return [BlocklistSourceResponse.model_validate(r) for r in rows]


@router.patch("/{source_id}", response_model=BlocklistSourceResponse)
async def update_source(source_id: int, payload: BlocklistSourceUpdate,
                        db: AsyncSession = Depends(get_db),
                        _: User = Depends(require_admin)):
    src = await db.get(BlocklistSource, source_id)
    if not src:
        raise HTTPException(status_code=404, detail="Blocklist source not found")
    changed = src.enabled != payload.enabled
    src.enabled = payload.enabled
    await db.commit()
    await db.refresh(src)
    if changed:  # a no-op toggle shouldn't kick off an HTTP fetch + reclassify
        _trigger_refresh()
    return BlocklistSourceResponse.model_validate(src)


@router.post("/refresh")
async def refresh_sources(_: User = Depends(require_admin)):
    _trigger_refresh()
    return {"message": "Refresh started"}
