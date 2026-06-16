"""End-to-end tests for /api/blocklist-sources and blocklist exclusion."""
from httpx import AsyncClient

from backend.models import BlocklistSource, AppDefinition


async def _seed_source(db):
    src = BlocklistSource(
        name="Test List", url="https://example.com/list.txt",
        category="Ads & Tracking", format="domains", license="GPL-3.0", enabled=True)
    db.add(src)
    await db.commit()
    await db.refresh(src)
    return src


async def test_list_requires_auth(async_client: AsyncClient):
    r = await async_client.get("/api/blocklist-sources")
    assert r.status_code == 401


async def test_list_returns_sources(async_admin_client: AsyncClient, db_session):
    await _seed_source(db_session)
    r = await async_admin_client.get("/api/blocklist-sources")
    assert r.status_code == 200, r.text
    assert any(s["name"] == "Test List" and s["category"] == "Ads & Tracking"
               for s in r.json())


async def test_toggle_requires_admin(async_readonly_client: AsyncClient, db_session):
    src = await _seed_source(db_session)
    r = await async_readonly_client.patch(
        f"/api/blocklist-sources/{src.id}", json={"enabled": False})
    assert r.status_code == 403


async def test_toggle_updates_enabled(async_admin_client: AsyncClient, db_session, monkeypatch):
    # Keep the test hermetic: the toggle would otherwise spawn a fire-and-forget
    # refresh that opens its own session and fetches list URLs.
    monkeypatch.setattr("backend.routes.blocklist_sources._trigger_refresh", lambda: None)
    src = await _seed_source(db_session)
    r = await async_admin_client.patch(
        f"/api/blocklist-sources/{src.id}", json={"enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False


async def test_toggle_unknown_id_404(async_admin_client: AsyncClient):
    r = await async_admin_client.patch("/api/blocklist-sources/999999", json={"enabled": False})
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
