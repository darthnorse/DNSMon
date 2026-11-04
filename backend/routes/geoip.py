from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, GeoipSettings, SettingsChangelog
from ..schemas import GeoipStatus, GeoipUpdate, GeoipUpdateResult
from ..auth import get_current_user, require_admin
from ..geoip import GEOIP_ROW_ID, start_clear, start_refresh

router = APIRouter(prefix="/api/geoip", tags=["geoip"])

MAX_LICENSE_KEY_LENGTH = 100
MIN_LENGTH_FOR_LAST4 = 16
MASK = '********'
STATUS_COLUMNS = ('last_checked_at', 'last_updated_at', 'city_build',
                  'asn_build', 'last_status', 'last_error')


def _to_status(row: GeoipSettings | None, *, is_admin: bool) -> GeoipStatus:
    if row is None:
        return GeoipStatus(configured=False, has_license_key=False)
    key = row.license_key
    return GeoipStatus(
        configured=row.configured,
        account_id=row.account_id if is_admin else None,
        has_license_key=bool(key),
        # The form never shows the saved key, so a browser autofilling the field went
        # unnoticed until MaxMind answered 401. These let an admin recognise their key.
        license_key_length=len(key) if is_admin and key else None,
        license_key_last4=key[-4:] if is_admin and key and len(key) >= MIN_LENGTH_FOR_LAST4 else None,
        **{column: getattr(row, column) for column in STATUS_COLUMNS},
    )


def _clean_license_key(value: str | None) -> str | None:
    key = (value or '').strip()
    if not key:
        return None
    if len(key) > MAX_LICENSE_KEY_LENGTH or not key.isprintable() or any(c.isspace() for c in key):
        raise HTTPException(status_code=400, detail="License key is invalid")
    return key


@router.get("", response_model=GeoipStatus)
async def get_geoip(db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)):
    return _to_status(await db.get(GeoipSettings, GEOIP_ROW_ID), is_admin=bool(user.is_admin))


@router.put("", response_model=GeoipUpdateResult)
async def update_geoip(payload: GeoipUpdate,
                       db: AsyncSession = Depends(get_db),
                       _: User = Depends(require_admin)):
    new_key = _clean_license_key(payload.license_key)
    await db.execute(insert(GeoipSettings).values(id=GEOIP_ROW_ID).on_conflict_do_nothing())
    # Locked so a refresh recording its outcome can't land between this read and the commit:
    # the ORM skips None-to-None columns, so a clear would leave that status behind.
    row = await db.get(GeoipSettings, GEOIP_ROW_ID, with_for_update=True)

    old = (row.account_id, row.license_key)

    if payload.clear:
        row.account_id = None
        row.license_key = None
        for column in STATUS_COLUMNS:
            setattr(row, column, None)
    else:
        if payload.account_id is not None:
            row.account_id = payload.account_id
        if new_key is not None:
            row.license_key = new_key

    new = (row.account_id, row.license_key)
    if new != old:
        db.add(SettingsChangelog(
            setting_key='maxmind_credentials',
            old_value=MASK if any(old) else None,
            new_value=MASK if any(new) else None,
            change_type='geoip',
            requires_restart=False))

    await db.commit()
    await db.refresh(row)
    refresh_started = not payload.clear and new != old and row.configured
    if payload.clear:
        start_clear()
    elif refresh_started:
        start_refresh()
    return GeoipUpdateResult(**_to_status(row, is_admin=True).model_dump(), refresh_started=refresh_started)


@router.post("/refresh", status_code=202)
async def refresh_geoip(db: AsyncSession = Depends(get_db),
                        _: User = Depends(require_admin)):
    row = await db.get(GeoipSettings, GEOIP_ROW_ID)
    if row is None or not row.configured:
        raise HTTPException(status_code=400, detail="MaxMind credentials are not configured")
    start_refresh()
    return {"message": "GeoIP refresh started"}
