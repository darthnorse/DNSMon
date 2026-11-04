import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from backend import geoip as geoip_module
from backend.geoip import ASN_EDITION, CITY_EDITION
from backend.models import GeoipSettings, SettingsChangelog

KEY = "abcSECRETkey123"
DATA = Path(__file__).parent / "data"


async def _seed(db_session, **fields):
    db_session.add(GeoipSettings(id=1, **fields))
    await db_session.commit()


async def _stored(db_session) -> GeoipSettings:
    db_session.expire_all()
    return await db_session.get(GeoipSettings, 1)


async def test_get_unconfigured_needs_no_row(async_admin_client: AsyncClient, db_session):
    r = await async_admin_client.get("/api/geoip")

    assert r.status_code == 200, r.text
    assert r.json() == {
        "configured": False, "account_id": None, "has_license_key": False,
        "last_checked_at": None, "last_updated_at": None, "city_build": None,
        "asn_build": None, "last_status": None, "last_error": None,
    }
    assert await db_session.get(GeoipSettings, 1) is None


async def test_readonly_get_never_contains_key(async_readonly_client: AsyncClient, db_session):
    await _seed(db_session, account_id="12345", license_key=KEY, city_build=1700000000,
                last_status="ok", last_updated_at=datetime.now(timezone.utc))

    r = await async_readonly_client.get("/api/geoip")

    assert r.status_code == 200, r.text
    body = r.json()
    assert "license_key" not in body
    assert "abc" not in r.text
    assert body["configured"] is True
    assert body["has_license_key"] is True
    assert body["account_id"] == "12345"
    assert body["city_build"] == 1700000000
    assert body["last_updated_at"] is not None


async def test_account_id_alone_is_not_configured(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="12345")

    r = await async_admin_client.get("/api/geoip")

    assert r.json()["configured"] is False
    assert r.json()["has_license_key"] is False


async def test_readonly_put_is_forbidden(async_readonly_client: AsyncClient, db_session):
    r = await async_readonly_client.put("/api/geoip", json={"account_id": "1", "license_key": KEY})

    assert r.status_code == 403
    assert await db_session.get(GeoipSettings, 1) is None


async def test_put_creates_row_and_trims(async_admin_client: AsyncClient, db_session):
    r = await async_admin_client.put(
        "/api/geoip", json={"account_id": " 12345 ", "license_key": f"  {KEY}\n"})

    assert r.status_code == 200, r.text
    assert r.json()["configured"] is True
    assert KEY not in r.text
    row = await _stored(db_session)
    assert (row.account_id, row.license_key) == ("12345", KEY)


async def test_put_without_license_key_keeps_it(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.put("/api/geoip", json={"account_id": "222"})

    assert r.status_code == 200, r.text
    row = await _stored(db_session)
    assert (row.account_id, row.license_key) == ("222", KEY)


async def test_put_blank_license_key_keeps_it(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": "  "})

    assert r.status_code == 200, r.text
    assert (await _stored(db_session)).license_key == KEY


async def test_clear_wipes_credentials_and_status(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="111", license_key=KEY, city_build=5, asn_build=6,
                last_status="error", last_error="boom",
                last_checked_at=datetime.now(timezone.utc),
                last_updated_at=datetime.now(timezone.utc))

    r = await async_admin_client.put("/api/geoip", json={"clear": True})

    assert r.status_code == 200, r.text
    assert r.json()["configured"] is False
    row = await _stored(db_session)
    assert [getattr(row, c) for c in (
        "account_id", "license_key", "last_checked_at", "last_updated_at",
        "city_build", "asn_build", "last_status", "last_error")] == [None] * 8


async def test_changelog_is_masked(async_admin_client: AsyncClient, db_session):
    await async_admin_client.put("/api/geoip", json={"account_id": "98765", "license_key": KEY})
    await async_admin_client.put("/api/geoip", json={"account_id": "98766"})

    rows = (await db_session.execute(
        select(SettingsChangelog).where(SettingsChangelog.setting_key == "maxmind_credentials")
        .order_by(SettingsChangelog.id))).scalars().all()

    assert [(r.old_value, r.new_value) for r in rows] == [(None, "********"), ("********", "********")]
    dump = repr([r.to_dict() for r in rows])
    assert KEY not in dump and "98765" not in dump and "98766" not in dump


async def test_noop_put_writes_no_changelog(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})

    assert (await db_session.execute(select(SettingsChangelog))).scalars().all() == []


async def test_clear_changelog_new_value_is_null(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"clear": True})

    row = (await db_session.execute(select(SettingsChangelog))).scalars().one()
    assert (row.old_value, row.new_value) == ("********", None)


async def test_rejects_bad_account_id(async_admin_client: AsyncClient):
    for bad in ("12a45", "1" * 21, "١٢٣"):
        r = await async_admin_client.put("/api/geoip", json={"account_id": bad})
        assert r.status_code == 422, bad


async def test_rejects_bad_license_key_without_echoing_it(async_admin_client: AsyncClient):
    for bad in ("has space", "tab\tin", "x" * 101):
        r = await async_admin_client.put("/api/geoip", json={"account_id": "1", "license_key": bad})
        assert r.status_code == 400, bad
        assert bad not in r.text


@pytest.fixture
def refresh_job(monkeypatch):
    job = AsyncMock()
    monkeypatch.setattr(geoip_module, "refresh_from_settings", job)
    return job


@pytest.fixture(autouse=True)
def no_real_refresh(refresh_job):
    return refresh_job


async def _background_settled():
    await asyncio.gather(*geoip_module._background_refreshes)


async def test_post_refresh_starts_the_job(async_admin_client: AsyncClient, db_session, refresh_job):
    await _seed(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.post("/api/geoip/refresh")
    await _background_settled()

    assert r.status_code == 202, r.text
    refresh_job.assert_awaited_once()


async def test_post_refresh_without_credentials_is_400(async_admin_client: AsyncClient, db_session, refresh_job):
    await _seed(db_session, account_id="111")

    no_key = await async_admin_client.post("/api/geoip/refresh")
    await _background_settled()

    assert no_key.status_code == 400
    refresh_job.assert_not_awaited()


async def test_post_refresh_with_no_row_is_400(async_admin_client: AsyncClient, refresh_job):
    r = await async_admin_client.post("/api/geoip/refresh")

    assert r.status_code == 400
    refresh_job.assert_not_awaited()


async def test_post_refresh_requires_admin(async_readonly_client: AsyncClient, db_session, refresh_job):
    await _seed(db_session, account_id="111", license_key=KEY)

    r = await async_readonly_client.post("/api/geoip/refresh")

    assert r.status_code == 403
    refresh_job.assert_not_awaited()


async def test_post_refresh_requires_authentication(async_client: AsyncClient, refresh_job):
    r = await async_client.post("/api/geoip/refresh")

    assert r.status_code == 401


async def test_put_new_credentials_starts_refresh(async_admin_client: AsyncClient, refresh_job):
    r = await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})
    await _background_settled()

    assert r.status_code == 200, r.text
    refresh_job.assert_awaited_once()


async def test_put_changed_key_starts_refresh(async_admin_client: AsyncClient, db_session, refresh_job):
    await _seed(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"license_key": "newKEY"})
    await _background_settled()

    refresh_job.assert_awaited_once()


async def test_put_unchanged_credentials_starts_no_refresh(async_admin_client: AsyncClient, db_session, refresh_job):
    await _seed(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})
    await _background_settled()

    refresh_job.assert_not_awaited()


async def test_put_partial_credentials_starts_no_refresh(async_admin_client: AsyncClient, refresh_job):
    await async_admin_client.put("/api/geoip", json={"account_id": "111"})
    await _background_settled()

    refresh_job.assert_not_awaited()


async def test_clear_unloads_reader_and_deletes_files(async_admin_client: AsyncClient, db_session,
                                                      isolated_geoip, refresh_job):
    await _seed(db_session, account_id="111", license_key=KEY)
    isolated_geoip.directory.mkdir(parents=True)
    for edition, name in ((CITY_EDITION, "GeoIP2-City-Test.mmdb"), (ASN_EDITION, "GeoLite2-ASN-Test.mmdb")):
        shutil.copy(DATA / name, isolated_geoip.directory / f"{edition}.mmdb")
        (isolated_geoip.directory / f"{edition}.mmdb.last-modified").write_text("x")
    assert isolated_geoip.load() is True
    assert isolated_geoip.lookup("89.160.20.130") is not None

    r = await async_admin_client.put("/api/geoip", json={"clear": True})
    await _background_settled()

    assert r.status_code == 200, r.text
    assert isolated_geoip.lookup("89.160.20.130") is None
    assert list(isolated_geoip.directory.iterdir()) == []
    refresh_job.assert_not_awaited()


async def test_clear_survives_a_delete_failure(async_admin_client: AsyncClient, db_session, isolated_geoip, monkeypatch):
    await _seed(db_session, account_id="111", license_key=KEY)
    isolated_geoip.directory.mkdir(parents=True)
    (isolated_geoip.directory / f"{CITY_EDITION}.mmdb").write_bytes(b"x")

    def refuse(self, missing_ok=False):
        raise PermissionError("nope")

    monkeypatch.setattr(Path, "unlink", refuse)

    r = await async_admin_client.put("/api/geoip", json={"clear": True})

    assert r.status_code == 200, r.text
    assert (await _stored(db_session)).license_key is None
