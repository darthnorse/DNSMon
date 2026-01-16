"""
Pi-hole sync routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query as QueryParam

from ..models import User
from ..auth import get_current_user

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.get("/preview")
async def get_sync_preview(_: User = Depends(get_current_user)):
    """Preview what would be synced from source to targets"""
    from ..sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    preview = await sync_service.get_sync_preview()

    if not preview:
        raise HTTPException(
            status_code=400,
            detail="No source server configured or unable to fetch configuration"
        )

    return preview


@router.post("/execute")
async def execute_sync(_: User = Depends(get_current_user)):
    """Execute configuration sync from source to targets"""
    from ..sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    sync_history_id = await sync_service.execute_sync(sync_type='manual')

    if not sync_history_id:
        raise HTTPException(
            status_code=400,
            detail="Sync failed. Check logs for details."
        )

    return {
        "message": "Sync completed",
        "sync_history_id": sync_history_id
    }


@router.get("/history")
async def get_sync_history(
    limit: int = QueryParam(20, ge=1, le=100),
    _: User = Depends(get_current_user)
):
    """Get recent sync history"""
    from ..sync_service import PiholeSyncService

    sync_service = PiholeSyncService()
    history = await sync_service.get_sync_history(limit=limit)

    return {"history": history}
