from httpx import AsyncClient


async def test_create_manual_definition(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/app-definitions", json={
        "name": "Acme VPN", "category": "Privacy / VPN", "domains": ["acmevpn.com", "acme-vpn.net"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "manual"
    assert set(body["domains"]) == {"acmevpn.com", "acme-vpn.net"}


async def test_list_and_delete_manual(async_admin_client: AsyncClient):
    rid = (await async_admin_client.post("/api/app-definitions",
           json={"name": "Tmp", "domains": ["tmp.test"]})).json()["id"]
    r = await async_admin_client.get("/api/app-definitions")
    assert any(d["id"] == rid for d in r.json())
    assert (await async_admin_client.delete(f"/api/app-definitions/{rid}")).status_code == 200


async def test_cannot_delete_non_manual(async_admin_client: AsyncClient, db_session):
    from backend.models import AppDefinition
    ad = AppDefinition(slug="netflix", name="Netflix", source="adguard", enabled=True)
    db_session.add(ad)
    await db_session.commit()
    await db_session.refresh(ad)
    r = await async_admin_client.delete(f"/api/app-definitions/{ad.id}")
    assert r.status_code == 400


async def test_readonly_cannot_create(async_readonly_client: AsyncClient):
    r = await async_readonly_client.post("/api/app-definitions",
                                         json={"name": "x", "domains": ["x.test"]})
    assert r.status_code == 403


async def test_anonymous_list_401(async_client: AsyncClient):
    assert (await async_client.get("/api/app-definitions")).status_code == 401


async def test_feed_status(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/app-definitions/feed-status")
    assert r.status_code == 200, r.text
    assert "adguard_app_count" in r.json()
