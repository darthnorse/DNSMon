from datetime import datetime, timedelta, timezone

from httpx import AsyncClient

from backend.models import Query


async def _seed(db_session, servers: list[str]):
    now = datetime.now(timezone.utc)
    for i, server in enumerate(servers):
        db_session.add(Query(
            timestamp=now - timedelta(seconds=i),
            domain=f"d{i}.example.com",
            client_ip="192.168.1.20",
            server=server,
        ))
    await db_session.commit()


async def test_servers_filter_is_exact_match(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, ["pi", "pi2", "adguard"])

    r = await async_admin_client.get("/api/queries", params={"servers": "pi"})

    assert r.status_code == 200, r.text
    assert {q["server"] for q in r.json()} == {"pi"}


async def test_servers_filter_applies_before_limit(async_admin_client: AsyncClient, db_session):
    # Newest rows belong to an unselected server; the selected ones must still come back.
    await _seed(db_session, ["noisy"] * 5 + ["pi", "adguard"])

    r = await async_admin_client.get("/api/queries", params={"servers": "pi, adguard", "limit": 2})

    assert r.status_code == 200, r.text
    assert sorted(q["server"] for q in r.json()) == ["adguard", "pi"]


async def test_count_honours_servers_filter(async_admin_client: AsyncClient, db_session):
    await _seed(db_session, ["pi", "pi2", "adguard"])
    params = {"servers": "pi,adguard"}

    rows = await async_admin_client.get("/api/queries", params=params)
    count = await async_admin_client.get("/api/queries/count", params=params)

    assert count.status_code == 200, count.text
    assert count.json()["count"] == len(rows.json()) == 2
