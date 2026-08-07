"""End-to-end tests for /api/insight-sources and blocklist exclusion."""
from httpx import AsyncClient

from backend.models import InsightSource, AppDefinition


async def _seed_source(db):
    src = InsightSource(
        name="Test List", url="https://example.com/list.txt", kind="hosts",
        category="Ads & Tracking", format="domains", license="GPL-3.0", enabled=True)
    db.add(src)
    await db.commit()
    await db.refresh(src)
    return src


async def test_list_requires_auth(async_client: AsyncClient):
    r = await async_client.get("/api/insight-sources")
    assert r.status_code == 401


async def test_list_returns_sources(async_admin_client: AsyncClient, db_session):
    await _seed_source(db_session)
    r = await async_admin_client.get("/api/insight-sources")
    assert r.status_code == 200, r.text
    assert any(s["name"] == "Test List" and s["category"] == "Ads & Tracking"
               for s in r.json())


async def test_toggle_requires_admin(async_readonly_client: AsyncClient, db_session):
    src = await _seed_source(db_session)
    r = await async_readonly_client.patch(
        f"/api/insight-sources/{src.id}", json={"enabled": False})
    assert r.status_code == 403


async def test_toggle_updates_enabled(async_admin_client: AsyncClient, db_session, monkeypatch):
    # Keep the test hermetic: the toggle would otherwise spawn a fire-and-forget
    # refresh that opens its own session and fetches list URLs.
    monkeypatch.setattr("backend.routes.insight_sources._trigger_kind_refresh", lambda kind: None)
    src = await _seed_source(db_session)
    r = await async_admin_client.patch(
        f"/api/insight-sources/{src.id}", json={"enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False


async def test_toggle_unknown_id_404(async_admin_client: AsyncClient):
    r = await async_admin_client.patch("/api/insight-sources/999999", json={"enabled": False})
    assert r.status_code == 404


async def test_app_definitions_update_rejects_blocklist(async_admin_client: AsyncClient, db_session):
    ad = AppDefinition(slug="blocklist-ads-tracking", name="Ads & Tracking",
                       category="Ads & Tracking", source="blocklist", enabled=True)
    db_session.add(ad)
    await db_session.commit()
    await db_session.refresh(ad)
    r = await async_admin_client.put(f"/api/app-definitions/{ad.id}", json={"enabled": False})
    assert r.status_code == 404


async def test_app_definitions_list_excludes_blocklist(async_admin_client: AsyncClient, db_session):
    db_session.add(AppDefinition(slug="blocklist-ads-tracking", name="Ads & Tracking",
                                 category="Ads & Tracking", source="blocklist", enabled=True))
    db_session.add(AppDefinition(slug="acme", name="Acme", category="Software",
                                 source="manual", enabled=True))
    await db_session.commit()
    r = await async_admin_client.get("/api/app-definitions")
    assert r.status_code == 200
    names = [d["name"] for d in r.json()]
    assert "Acme" in names
    assert "Ads & Tracking" not in names


async def test_app_definitions_source_filter_accepts_v2fly(async_admin_client: AsyncClient, db_session):
    db_session.add(AppDefinition(slug="netflix", name="Netflix", category="Streaming",
                                 source="v2fly", enabled=True))
    db_session.add(AppDefinition(slug="acme", name="Acme", category="Software",
                                 source="manual", enabled=True))
    await db_session.commit()
    r = await async_admin_client.get("/api/app-definitions", params={"source": "v2fly"})
    assert r.status_code == 200, r.text
    assert [d["slug"] for d in r.json()] == ["netflix"]
    r = await async_admin_client.get("/api/app-definitions", params={"source": "blocklist"})
    assert r.status_code == 400


async def test_app_definitions_feed_domains_previewed_with_count(async_admin_client: AsyncClient, db_session):
    from sqlalchemy import insert as sa_insert
    from backend.models import AppDomain
    feed = AppDefinition(slug="bigapp", name="BigApp", category="X", source="v2fly", enabled=True)
    manual = AppDefinition(slug="manapp", name="ManApp", category="X", source="manual", enabled=True)
    db_session.add_all([feed, manual])
    await db_session.flush()
    await db_session.execute(sa_insert(AppDomain), [
        {"domain": f"d{i}.example.com", "app_id": feed.id, "is_wildcard": False} for i in range(8)])
    await db_session.execute(sa_insert(AppDomain), [
        {"domain": f"m{i}.example.com", "app_id": manual.id, "is_wildcard": False} for i in range(8)])
    await db_session.commit()

    r = await async_admin_client.get("/api/app-definitions")
    assert r.status_code == 200, r.text
    by_slug = {d["slug"]: d for d in r.json()}
    assert by_slug["bigapp"]["domain_count"] == 8
    assert len(by_slug["bigapp"]["domains"]) == 5  # previewed, not the full tier
    assert by_slug["manapp"]["domain_count"] == 8
    assert len(by_slug["manapp"]["domains"]) == 8  # manual apps keep full lists


import pytest

from backend.constants import QFEEDS_FEED_URL


@pytest.fixture
def no_refresh(monkeypatch):
    """PATCH would otherwise spawn a real fetch against the live Q-Feeds API."""
    monkeypatch.setattr(
        "backend.routes.insight_sources._trigger_kind_refresh", lambda kind: None)


async def _qfeeds_row(db, api_key=None, enabled=False):
    row = InsightSource(
        name="Q-Feeds Malware Domains", url=QFEEDS_FEED_URL, kind="qfeeds",
        category=None, format="domains", license="Q-Feeds Community",
        enabled=enabled, api_key=api_key)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def test_api_key_is_never_returned_to_a_readonly_user(
        async_readonly_client: AsyncClient, db_session):
    """The real exposure boundary is InsightSourceResponse's field allowlist.
    This fails loudly if anyone ever adds api_key to that schema."""
    await _qfeeds_row(db_session, api_key="tip_supersecret")

    r = await async_readonly_client.get("/api/insight-sources")
    assert r.status_code == 200
    assert "tip_supersecret" not in r.text
    row = next(s for s in r.json() if s["kind"] == "qfeeds")
    assert "api_key" not in row
    assert row["has_api_key"] is True


async def test_has_api_key_is_false_without_one(async_admin_client: AsyncClient, db_session):
    await _qfeeds_row(db_session)
    r = await async_admin_client.get("/api/insight-sources")
    assert next(s for s in r.json() if s["kind"] == "qfeeds")["has_api_key"] is False


async def test_enabling_without_a_key_is_rejected(
        async_admin_client: AsyncClient, db_session, no_refresh):
    row = await _qfeeds_row(db_session)
    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"enabled": True})
    assert r.status_code == 400
    assert "API key" in r.json()["detail"]


async def test_saving_a_key_then_enabling_works(
        async_admin_client: AsyncClient, db_session, no_refresh):
    row = await _qfeeds_row(db_session)

    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"api_key": "tip_abc"})
    assert r.status_code == 200, r.text
    assert r.json()["has_api_key"] is True
    assert "tip_abc" not in r.text

    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True


async def test_key_and_enable_in_one_request(
        async_admin_client: AsyncClient, db_session, no_refresh):
    row = await _qfeeds_row(db_session)
    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"api_key": "tip_abc", "enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True


async def test_blank_api_key_clears_it(
        async_admin_client: AsyncClient, db_session, no_refresh):
    row = await _qfeeds_row(db_session, api_key="tip_abc")
    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"api_key": ""})
    assert r.status_code == 200, r.text
    assert r.json()["has_api_key"] is False


async def test_omitting_enabled_preserves_it(
        async_admin_client: AsyncClient, db_session, no_refresh):
    row = await _qfeeds_row(db_session, api_key="tip_abc", enabled=True)
    r = await async_admin_client.patch(
        f"/api/insight-sources/{row.id}", json={"api_key": "tip_new"})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True


async def test_readonly_cannot_patch_a_key(async_readonly_client: AsyncClient, db_session):
    row = await _qfeeds_row(db_session)
    r = await async_readonly_client.patch(
        f"/api/insight-sources/{row.id}", json={"api_key": "tip_abc"})
    assert r.status_code == 403


async def test_last_error_is_exposed(async_admin_client: AsyncClient, db_session):
    row = await _qfeeds_row(db_session)
    row.last_error = "HTTP 403 from feed"
    db_session.add(row)
    await db_session.commit()

    r = await async_admin_client.get("/api/insight-sources")
    assert next(s for s in r.json() if s["kind"] == "qfeeds")["last_error"] == "HTTP 403 from feed"
