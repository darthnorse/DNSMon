from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, GeoipSettings, SettingsChangelog
from ..schemas import GeoipStatus, GeoipUpdate
from ..auth import get_current_user, require_admin
from ..geoip import GEOIP_ROW_ID, start_clear, start_refresh

router = APIRouter(prefix="/api/geoip", tags=["geoip"])

MAX_LICENSE_KEY_LENGTH = 100
MASK = '********'
STATUS_COLUMNS = ('last_checked_at', 'last_updated_at', 'city_build',
                  'asn_build', 'last_status', 'last_error')


def _to_status(row: GeoipSettings | None) -> GeoipStatus:
    if row is None:
        return GeoipStatus(configured=False, has_license_key=False)
    return GeoipStatus(
        configured=row.configured,
        account_id=row.account_id,
        has_license_key=bool(row.license_key),
        last_checked_at=row.last_checked_at,
        last_updated_at=row.last_updated_at,
        city_build=row.city_build,
        asn_build=row.asn_build,
        last_status=row.last_status,
        last_error=row.last_error,
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
                    _: User = Depends(get_current_user)):
    return _to_status(await db.get(GeoipSettings, GEOIP_ROW_ID))


@router.put("", response_model=GeoipStatus)
async def update_geoip(payload: GeoipUpdate,
                       db: AsyncSession = Depends(get_db),
                       _: User = Depends(require_admin)):
    new_key = _clean_license_key(payload.license_key)
    # Locked so a refresh recording its outcome can't land between this read and the commit:
    # the ORM skips None-to-None columns, so a clear would leave that status behind.
    row = await db.get(GeoipSettings, GEOIP_ROW_ID, with_for_update=True)
    if row is None:
        row = GeoipSettings(id=GEOIP_ROW_ID)
        db.add(row)

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
    if payload.clear:
        start_clear()
    elif new != old and row.configured:
        start_refresh()
    return _to_status(row)


@router.post("/refresh", status_code=202)
async def refresh_geoip(db: AsyncSession = Depends(get_db),
                        _: User = Depends(require_admin)):
    row = await db.get(GeoipSettings, GEOIP_ROW_ID)
    if row is None or not row.configured:
        raise HTTPException(status_code=400, detail="MaxMind credentials are not configured")
    start_refresh()
    return {"message": "GeoIP refresh started"}
