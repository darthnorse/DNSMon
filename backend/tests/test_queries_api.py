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


async def _seed_answers(db_session) -> dict[str, Query]:
    now = datetime.now(timezone.utc)
    rows = {
        "v6": Query(timestamp=now, domain="v6.example.com", client_ip="192.168.1.20", server="adguard",
                    answer_ips=["2001:db8::1"], answer_cnames=[]),
        "cdn": Query(timestamp=now - timedelta(seconds=1), domain="weatherkit.apple.com", client_ip="192.168.1.20",
                     server="adguard", answer_ips=["23.217.9.57"], answer_cnames=["a2047.dscapi9.akamai.net"]),
        "client": Query(timestamp=now - timedelta(seconds=2), domain="nas.lan", client_ip="192.168.1.9",
                        server="adguard", answer_ips=[], answer_cnames=[]),
        "resolved": Query(timestamp=now - timedelta(seconds=3), domain="printer.lan", client_ip="192.168.1.20",
                          server="adguard", answer_ips=["192.168.1.9"], answer_cnames=[]),
        "pihole": Query(timestamp=now - timedelta(seconds=4), domain="old.example.com", client_ip="192.168.1.20",
                        server="pi"),
    }
    db_session.add_all(rows.values())
    await db_session.commit()
    return rows


async def test_answer_filter_by_ip_matches_any_ipv6_spelling(async_admin_client: AsyncClient, db_session):
    await _seed_answers(db_session)

    r = await async_admin_client.get("/api/queries", params={"answer": "2001:DB8:0::1"})

    assert r.status_code == 200, r.text
    assert [q["domain"] for q in r.json()] == ["v6.example.com"]


async def test_answer_filter_by_cname(async_admin_client: AsyncClient, db_session):
    await _seed_answers(db_session)

    r = await async_admin_client.get("/api/queries", params={"answer": "A2047.dscapi9.akamai.net."})

    assert [q["domain"] for q in r.json()] == ["weatherkit.apple.com"]


async def test_search_ip_finds_client_and_resolved_rows(async_admin_client: AsyncClient, db_session):
    rows = await _seed_answers(db_session)

    r = await async_admin_client.get("/api/queries", params={"search": "192.168.1.9"})

    assert {q["id"] for q in r.json()} == {rows["client"].id, rows["resolved"].id}


async def test_response_carries_answers_and_null_for_pihole(async_admin_client: AsyncClient, db_session):
    await _seed_answers(db_session)

    by_domain = {q["domain"]: q for q in (await async_admin_client.get("/api/queries")).json()}

    assert by_domain["weatherkit.apple.com"]["answer_ips"] == ["23.217.9.57"]
    assert by_domain["weatherkit.apple.com"]["answer_cnames"] == ["a2047.dscapi9.akamai.net"]
    assert by_domain["nas.lan"]["answer_ips"] == []
    assert by_domain["old.example.com"]["answer_ips"] is None


async def test_count_honours_answer_filter(async_admin_client: AsyncClient, db_session):
    await _seed_answers(db_session)

    r = await async_admin_client.get("/api/queries/count", params={"answer": "192.168.1.9"})

    assert r.json()["count"] == 1
