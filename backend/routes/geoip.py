from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, GeoipSettings, SettingsChangelog
from ..schemas import GeoipStatus, GeoipUpdate
from ..auth import get_current_user, require_admin

router = APIRouter(prefix="/api/geoip", tags=["geoip"])

MAX_LICENSE_KEY_LENGTH = 100
GEOIP_ROW_ID = 1
MASK = '********'
STATUS_COLUMNS = ('last_checked_at', 'last_updated_at', 'city_build',
                  'asn_build', 'last_status', 'last_error')


def _to_status(row: GeoipSettings | None) -> GeoipStatus:
    if row is None:
        return GeoipStatus(configured=False, has_license_key=False)
    return GeoipStatus(
        configured=bool(row.account_id and row.license_key),
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
    row = await db.get(GeoipSettings, GEOIP_ROW_ID)
    if row is None:
        row = GeoipSettings(id=GEOIP_ROW_ID)
        db.add(row)

    had_credentials = bool(row.account_id or row.license_key)
    old_account, old_key = row.account_id, row.license_key

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

    if (row.account_id, row.license_key) != (old_account, old_key):
        db.add(SettingsChangelog(
            setting_key='maxmind_credentials',
            old_value=MASK if had_credentials else None,
            new_value=MASK if (row.account_id or row.license_key) else None,
            change_type='geoip',
            requires_restart=False))

    await db.commit()
    await db.refresh(row)
    return _to_status(row)
