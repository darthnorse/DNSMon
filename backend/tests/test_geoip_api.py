import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from backend.geoip import CITY_EDITION, EDITIONS
from backend.models import GeoipSettings, SettingsChangelog
from backend.tests.geoip_helpers import KEY, background_settled, install_fixtures, refuse_unlink, seed_geoip, stored_geoip

pytestmark = pytest.mark.usefixtures("refresh_job")


async def test_get_unconfigured_needs_no_row(async_admin_client: AsyncClient, db_session):
    r = await async_admin_client.get("/api/geoip")

    assert r.status_code == 200, r.text
    assert r.json() == {
        "configured": False, "account_id": None, "has_license_key": False,
        "license_key_length": None, "license_key_last4": None,
        "last_checked_at": None, "last_updated_at": None, "city_build": None,
        "asn_build": None, "last_status": None, "last_error": None,
    }
    assert await db_session.get(GeoipSettings, 1) is None


async def test_last_error_is_admin_only(async_readonly_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345", license_key=KEY, last_status="error",
                     last_error="GeoLite2-City: HTTP 401")

    body = (await async_readonly_client.get("/api/geoip")).json()

    assert body["last_error"] is None
    assert body["last_status"] == "error"


async def test_admin_sees_last_error(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345", license_key=KEY, last_status="error",
                     last_error="GeoLite2-City: HTTP 401")

    body = (await async_admin_client.get("/api/geoip")).json()

    assert body["last_error"] == "GeoLite2-City: HTTP 401"


async def test_readonly_get_never_contains_key(async_readonly_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345", license_key=KEY, city_build=1700000000,
                last_status="ok", last_updated_at=datetime.now(timezone.utc))

    r = await async_readonly_client.get("/api/geoip")

    assert r.status_code == 200, r.text
    body = r.json()
    assert "license_key" not in body
    assert "abc" not in r.text
    assert body["configured"] is True
    assert body["has_license_key"] is True
    assert body["account_id"] is None
    assert "12345" not in r.text
    assert body["city_build"] == 1700000000
    assert body["last_updated_at"] is not None
    assert body["license_key_length"] is None
    assert body["license_key_last4"] is None


async def test_admin_get_identifies_the_saved_key_without_revealing_it(async_admin_client: AsyncClient, db_session):
    long_key = "abcdef_0123456789SECRETwxyz"
    await seed_geoip(db_session, account_id="12345", license_key=long_key)

    r = await async_admin_client.get("/api/geoip")

    assert r.status_code == 200, r.text
    assert r.json()["account_id"] == "12345"
    assert r.json()["license_key_length"] == len(long_key)
    assert r.json()["license_key_last4"] == "wxyz"
    assert long_key[:-4] not in r.text


async def test_put_response_identifies_the_saved_key(async_admin_client: AsyncClient):
    long_key = "abcdef_0123456789SECRETwxyz"

    r = await async_admin_client.put("/api/geoip", json={"license_key": long_key})

    assert r.status_code == 200, r.text
    assert r.json()["license_key_length"] == len(long_key)
    assert r.json()["license_key_last4"] == "wxyz"
    assert long_key[:-4] not in r.text


async def test_short_key_shows_length_only(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345", license_key="short")

    body = (await async_admin_client.get("/api/geoip")).json()

    assert body["license_key_length"] == 5
    assert body["license_key_last4"] is None


async def test_cleared_key_has_no_hint(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345", license_key="abcdef_0123456789SECRETwxyz")

    body = (await async_admin_client.put("/api/geoip", json={"clear": True})).json()

    assert body["license_key_length"] is None
    assert body["license_key_last4"] is None


async def test_account_id_alone_is_not_configured(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="12345")

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
    row = await stored_geoip(db_session)
    assert (row.account_id, row.license_key) == ("12345", KEY)


async def test_put_without_license_key_keeps_it(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.put("/api/geoip", json={"account_id": "222"})

    assert r.status_code == 200, r.text
    row = await stored_geoip(db_session)
    assert (row.account_id, row.license_key) == ("222", KEY)


async def test_put_blank_license_key_keeps_it(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": "  "})

    assert r.status_code == 200, r.text
    assert (await stored_geoip(db_session)).license_key == KEY


async def test_clear_wipes_credentials_and_status(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="111", license_key=KEY, city_build=5, asn_build=6,
                last_status="error", last_error="boom",
                last_checked_at=datetime.now(timezone.utc),
                last_updated_at=datetime.now(timezone.utc))

    r = await async_admin_client.put("/api/geoip", json={"clear": True})

    assert r.status_code == 200, r.text
    assert r.json()["configured"] is False
    row = await stored_geoip(db_session)
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
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})

    assert (await db_session.execute(select(SettingsChangelog))).scalars().all() == []


async def test_clear_changelog_new_value_is_null(async_admin_client: AsyncClient, db_session):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

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


async def test_post_refresh_starts_the_job(async_admin_client: AsyncClient, db_session, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.post("/api/geoip/refresh")
    await background_settled()

    assert r.status_code == 202, r.text
    refresh_job.assert_awaited_once()


async def test_post_refresh_without_credentials_is_400(async_admin_client: AsyncClient, db_session, refresh_job):
    await seed_geoip(db_session, account_id="111")

    no_key = await async_admin_client.post("/api/geoip/refresh")
    await background_settled()

    assert no_key.status_code == 400
    refresh_job.assert_not_awaited()


async def test_post_refresh_with_no_row_is_400(async_admin_client: AsyncClient, refresh_job):
    r = await async_admin_client.post("/api/geoip/refresh")

    assert r.status_code == 400
    refresh_job.assert_not_awaited()


async def test_post_refresh_requires_admin(async_readonly_client: AsyncClient, db_session, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    r = await async_readonly_client.post("/api/geoip/refresh")

    assert r.status_code == 403
    refresh_job.assert_not_awaited()


async def test_post_refresh_requires_authentication(async_client: AsyncClient, refresh_job):
    r = await async_client.post("/api/geoip/refresh")

    assert r.status_code == 401


async def test_put_new_credentials_starts_refresh(async_admin_client: AsyncClient, refresh_job):
    r = await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})
    await background_settled()

    assert r.status_code == 200, r.text
    refresh_job.assert_awaited_once()


async def test_put_changed_key_starts_refresh(async_admin_client: AsyncClient, db_session, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"license_key": "newKEY"})
    await background_settled()

    refresh_job.assert_awaited_once()


async def test_put_unchanged_credentials_starts_no_refresh(async_admin_client: AsyncClient, db_session, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    await async_admin_client.put("/api/geoip", json={"account_id": "111", "license_key": KEY})
    await background_settled()

    refresh_job.assert_not_awaited()


async def test_put_partial_credentials_starts_no_refresh(async_admin_client: AsyncClient, refresh_job):
    await async_admin_client.put("/api/geoip", json={"account_id": "111"})
    await background_settled()

    refresh_job.assert_not_awaited()


async def test_clear_unloads_reader_and_deletes_files(async_admin_client: AsyncClient, db_session,
                                                      isolated_geoip, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)
    install_fixtures(isolated_geoip, *EDITIONS)
    for edition in EDITIONS:
        (isolated_geoip.directory / f"{edition}.mmdb.last-modified").write_text("x")
    assert isolated_geoip.load() is True
    assert isolated_geoip.lookup("89.160.20.130") is not None

    r = await async_admin_client.put("/api/geoip", json={"clear": True})
    await background_settled()

    assert r.status_code == 200, r.text
    assert isolated_geoip.lookup("89.160.20.130") is None
    assert list(isolated_geoip.directory.iterdir()) == []
    refresh_job.assert_not_awaited()


async def test_clear_survives_a_delete_failure(async_admin_client: AsyncClient, db_session, isolated_geoip, monkeypatch):
    await seed_geoip(db_session, account_id="111", license_key=KEY)
    isolated_geoip.directory.mkdir(parents=True)
    (isolated_geoip.directory / f"{CITY_EDITION}.mmdb").write_bytes(b"x")

    monkeypatch.setattr(Path, "unlink", refuse_unlink)

    r = await async_admin_client.put("/api/geoip", json={"clear": True})
    await background_settled()

    assert r.status_code == 200, r.text
    assert (await stored_geoip(db_session)).license_key is None


async def test_clear_answers_without_waiting_for_a_running_refresh(
        async_admin_client: AsyncClient, db_session, isolated_geoip):
    await seed_geoip(db_session, account_id="111", license_key=KEY)
    install_fixtures(isolated_geoip, CITY_EDITION)

    async with isolated_geoip._lock:
        r = await asyncio.wait_for(async_admin_client.put("/api/geoip", json={"clear": True}), timeout=5)
        assert r.status_code == 200, r.text
        assert r.json()["configured"] is False
        assert list(isolated_geoip.directory.iterdir()) != []

    await background_settled()
    assert list(isolated_geoip.directory.iterdir()) == []


async def test_credentials_saved_after_a_queued_clear_keep_their_databases(
        async_admin_client: AsyncClient, db_session, isolated_geoip, refresh_job):
    await seed_geoip(db_session, account_id="111", license_key=KEY)
    install_fixtures(isolated_geoip, *EDITIONS)

    async with isolated_geoip._lock:
        await async_admin_client.put("/api/geoip", json={"clear": True})
        r = await async_admin_client.put("/api/geoip", json={"account_id": "222", "license_key": "newKEY"})
    await background_settled()

    assert r.json()["refresh_started"] is True
    refresh_job.assert_awaited_once()
    assert (isolated_geoip.directory / f"{CITY_EDITION}.mmdb").exists()


async def test_concurrent_first_saves_both_succeed(async_admin_client: AsyncClient, db_session):
    first, second = await asyncio.gather(
        async_admin_client.put("/api/geoip", json={"account_id": "111"}),
        async_admin_client.put("/api/geoip", json={"license_key": KEY}),
    )

    assert (first.status_code, second.status_code) == (200, 200)
    assert (await stored_geoip(db_session)).configured


@pytest.mark.parametrize("payload, started", [
    ({"account_id": "111", "license_key": KEY}, False),
    ({"license_key": "newKEY"}, True),
    ({"clear": True}, False),
])
async def test_put_says_whether_a_refresh_started(async_admin_client: AsyncClient, db_session, payload, started):
    await seed_geoip(db_session, account_id="111", license_key=KEY)

    r = await async_admin_client.put("/api/geoip", json=payload)
    await background_settled()

    assert r.json()["refresh_started"] is started
