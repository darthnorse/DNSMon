"""End-to-end tests for the /api/alert-rules endpoints.

API client fixtures (`async_client` / `async_admin_client` /
`async_readonly_client`) live in conftest.py.
"""

from httpx import AsyncClient


# ---------------------------------------------------------------------------
# CRUD roundtrip
# ---------------------------------------------------------------------------

async def test_create_get_update_delete_roundtrip(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/alert-rules", json={
        "name": "rule-1", "domain_pattern": "google",
        "match_status": "blocked", "cooldown_minutes": 10,
    })
    assert r.status_code == 200, r.text
    rule = r.json()
    rule_id = rule["id"]
    assert rule["match_status"] == "blocked"

    r = await async_admin_client.get("/api/alert-rules")
    assert r.status_code == 200
    assert any(x["id"] == rule_id for x in r.json())

    r = await async_admin_client.put(f"/api/alert-rules/{rule_id}", json={
        "match_status": "allowed", "cooldown_minutes": 30,
    })
    assert r.status_code == 200, r.text
    assert r.json()["match_status"] == "allowed"
    assert r.json()["cooldown_minutes"] == 30

    r = await async_admin_client.delete(f"/api/alert-rules/{rule_id}")
    assert r.status_code == 200

    r = await async_admin_client.get("/api/alert-rules")
    assert all(x["id"] != rule_id for x in r.json())


# ---------------------------------------------------------------------------
# Null-rejection on PUT (fix a, exercised end-to-end)
# ---------------------------------------------------------------------------

async def _create_a_rule(client: AsyncClient) -> int:
    r = await client.post("/api/alert-rules", json={"name": "x", "domain_pattern": "g"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def test_put_with_null_match_status_returns_422(async_admin_client: AsyncClient):
    rid = await _create_a_rule(async_admin_client)
    r = await async_admin_client.put(f"/api/alert-rules/{rid}", json={"match_status": None})
    assert r.status_code == 422
    assert "match_status" in r.text


async def test_put_with_null_name_returns_422(async_admin_client: AsyncClient):
    rid = await _create_a_rule(async_admin_client)
    r = await async_admin_client.put(f"/api/alert-rules/{rid}", json={"name": None})
    assert r.status_code == 422


async def test_put_with_null_enabled_returns_422(async_admin_client: AsyncClient):
    # `enabled` is in _NOT_NULL_FIELDS — writing null would break response
    # serialization (Optional[bool] is not in the response schema).
    rid = await _create_a_rule(async_admin_client)
    r = await async_admin_client.put(f"/api/alert-rules/{rid}", json={"enabled": None})
    assert r.status_code == 422


async def test_put_with_bogus_match_status_returns_422(async_admin_client: AsyncClient):
    rid = await _create_a_rule(async_admin_client)
    r = await async_admin_client.put(f"/api/alert-rules/{rid}", json={"match_status": "bogus"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Auth / RBAC
# ---------------------------------------------------------------------------

async def test_anonymous_get_returns_401(async_client: AsyncClient):
    r = await async_client.get("/api/alert-rules")
    assert r.status_code == 401


async def test_anonymous_post_returns_401(async_client: AsyncClient):
    r = await async_client.post("/api/alert-rules", json={"name": "x"})
    assert r.status_code == 401


async def test_readonly_user_can_list(async_readonly_client: AsyncClient):
    r = await async_readonly_client.get("/api/alert-rules")
    assert r.status_code == 200


async def test_readonly_user_cannot_create(async_readonly_client: AsyncClient):
    r = await async_readonly_client.post("/api/alert-rules",
                                          json={"name": "x", "domain_pattern": "g"})
    assert r.status_code == 403


async def test_readonly_user_cannot_delete(async_readonly_client: AsyncClient,
                                            db_session):
    # Insert directly via DB so we don't need a separate admin client fixture
    # (using both clients at once leaks dependency_overrides across them).
    from backend.models import AlertRule
    rule = AlertRule(name="x", domain_pattern="g", match_status="any", enabled=True)
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    r = await async_readonly_client.delete(f"/api/alert-rules/{rule.id}")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Validation boundaries
# ---------------------------------------------------------------------------

async def test_create_rejects_cooldown_over_max(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/alert-rules", json={
        "name": "x", "domain_pattern": "g", "cooldown_minutes": 10081,
    })
    assert r.status_code == 422


async def test_create_returns_iso_datetime_strings(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/alert-rules",
                                       json={"name": "x", "domain_pattern": "g"})
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["created_at"].endswith("Z") or "+00:00" in payload["created_at"]
