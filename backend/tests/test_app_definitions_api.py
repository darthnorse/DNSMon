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
    assert "manual_app_count" in r.json()


async def test_create_rejects_invalid_domain(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/app-definitions", json={
        "name": "Bad", "domains": ["has space.com"]})
    assert r.status_code == 422
    r2 = await async_admin_client.post("/api/app-definitions", json={
        "name": "Bad2", "domains": ["no-dot"]})
    assert r2.status_code == 422
    r3 = await async_admin_client.post("/api/app-definitions", json={
        "name": "Bad3", "domains": ["*.wildcard.com"]})
    assert r3.status_code == 422


async def test_list_rejects_invalid_source(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/app-definitions?source=bogus")
    assert r.status_code == 400
    r2 = await async_admin_client.get("/api/app-definitions?source=manual")
    assert r2.status_code == 200


async def test_list_returns_correct_domains_per_app(async_admin_client: AsyncClient):
    await async_admin_client.post("/api/app-definitions", json={"name": "App One", "domains": ["one-a.com", "one-b.com"]})
    await async_admin_client.post("/api/app-definitions", json={"name": "App Two", "domains": ["two-a.com"]})
    r = await async_admin_client.get("/api/app-definitions?source=manual")
    assert r.status_code == 200
    by_name = {d["name"]: set(d["domains"]) for d in r.json()}
    assert by_name["App One"] == {"one-a.com", "one-b.com"}
    assert by_name["App Two"] == {"two-a.com"}
