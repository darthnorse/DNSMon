from datetime import datetime, timedelta, timezone

from httpx import AsyncClient

from backend.models import Query

NOW = datetime.now(timezone.utc).replace(microsecond=0)


async def _seed(db_session) -> None:
    db_session.add_all([
        Query(timestamp=NOW - timedelta(hours=2), domain="weatherkit.apple.com", client_ip="192.168.1.67",
              client_hostname="phone", server="adguard1", answer_ips=["23.217.9.57", "23.217.9.56"],
              answer_cnames=["a2047.dscapi9.akamai.net"]),
        Query(timestamp=NOW - timedelta(hours=1), domain="weatherkit.apple.com", client_ip="192.168.1.67",
              client_hostname="phone", server="adguard2", answer_ips=["23.217.9.57"],
              answer_cnames=["a2047.dscapi9.akamai.net"]),
        Query(timestamp=NOW - timedelta(minutes=5), domain="other.akamai.example", client_ip="192.168.1.80",
              server="adguard1", answer_ips=["23.217.9.57"], answer_cnames=[]),
        Query(timestamp=NOW - timedelta(minutes=1), domain="weatherkit.apple.com", client_ip="192.168.1.67",
              server="adguard1", answer_ips=[], answer_cnames=[], status="BLOCKED"),
        Query(timestamp=NOW, domain="old.pihole.example", client_ip="192.168.1.67", server="pi"),
    ])
    await db_session.commit()


async def test_domain_lists_ips_with_first_last_seen_and_count(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)

    r = await async_admin_client.get("/api/pdns/domain/WeatherKit.apple.com.")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_answer_data"] is True
    ips = {row["ip"]: row for row in body["ips"]}
    assert ips["23.217.9.57"]["count"] == 2
    assert datetime.fromisoformat(ips["23.217.9.57"]["first_seen"]) == NOW - timedelta(hours=2)
    assert datetime.fromisoformat(ips["23.217.9.57"]["last_seen"]) == NOW - timedelta(hours=1)
    assert ips["23.217.9.56"]["count"] == 1
    assert [row["ip"] for row in body["ips"]] == ["23.217.9.57", "23.217.9.56"]
    assert [(c["cname"], c["count"]) for c in body["cnames"]] == [("a2047.dscapi9.akamai.net", 2)]


async def test_ip_lists_domains_and_devices(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)

    body = (await async_admin_client.get("/api/pdns/ip/23.217.9.57")).json()

    domains = {d["domain"]: d for d in body["domains"]}
    assert domains["weatherkit.apple.com"]["count"] == 2
    assert sorted(domains["weatherkit.apple.com"]["servers"]) == ["adguard1", "adguard2"]
    assert [d["domain"] for d in body["domains"]] == ["other.akamai.example", "weatherkit.apple.com"]
    clients = {c["client_ip"]: c for c in body["clients"]}
    assert clients["192.168.1.67"]["count"] == 2 and clients["192.168.1.67"]["client_hostname"] == "phone"
    assert clients["192.168.1.80"]["count"] == 1
    assert body["geo"] is None


async def test_ip_lookup_accepts_any_ipv6_spelling(async_admin_client: AsyncClient, db_session):
    db_session.add(Query(timestamp=NOW, domain="v6.example.com", client_ip="192.168.1.5", server="a",
                         answer_ips=["2001:db8::1"], answer_cnames=[]))
    await db_session.commit()

    body = (await async_admin_client.get("/api/pdns/ip/2001:DB8:0:0::1")).json()

    assert body["ip"] == "2001:db8::1"
    assert [d["domain"] for d in body["domains"]] == ["v6.example.com"]


async def test_date_range_limits_the_lookup(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)

    body = (await async_admin_client.get("/api/pdns/ip/23.217.9.57", params={
        "from_date": (NOW - timedelta(minutes=30)).isoformat()})).json()

    assert [d["domain"] for d in body["domains"]] == ["other.akamai.example"]


async def test_pihole_only_domain_has_no_answer_data(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)

    body = (await async_admin_client.get("/api/pdns/domain/old.pihole.example")).json()

    assert body == {"domain": "old.pihole.example", "ips": [], "cnames": [], "has_answer_data": False}


async def test_bad_ip_is_400(async_admin_client: AsyncClient):
    assert (await async_admin_client.get("/api/pdns/ip/not-an-ip")).status_code == 400


async def test_overlong_domain_is_400(async_admin_client: AsyncClient):
    assert (await async_admin_client.get("/api/pdns/domain/" + "a" * 256)).status_code == 400


async def test_readonly_user_can_look_up(async_readonly_client: AsyncClient):
    assert (await async_readonly_client.get("/api/pdns/ip/1.1.1.1")).status_code == 200


async def test_lookup_requires_login(async_client: AsyncClient):
    assert (await async_client.get("/api/pdns/domain/example.com")).status_code == 401


async def _seed_resolve(db_session) -> None:
    db_session.add_all([
        Query(timestamp=NOW - timedelta(minutes=10), domain="mine.example.com", client_ip="192.168.1.67",
              server="adguard1", answer_ips=["47.1.2.3"], answer_cnames=["mine.cdn.example", "edge.cdn.example"]),
        Query(timestamp=NOW - timedelta(minutes=1), domain="theirs.example.com", client_ip="192.168.1.80",
              server="adguard1", answer_ips=["47.1.2.3"], answer_cnames=[]),
        Query(timestamp=NOW - timedelta(days=10), domain="ancient.example.com", client_ip="192.168.1.67",
              server="adguard1", answer_ips=["8.8.4.4"], answer_cnames=[]),
        Query(timestamp=NOW + timedelta(minutes=1), domain="later.example.com", client_ip="192.168.1.67",
              server="adguard1", answer_ips=["47.1.2.3"], answer_cnames=[]),
    ])
    await db_session.commit()


async def test_resolve_prefers_the_clients_own_lookup(async_admin_client: AsyncClient, db_session):
    await _seed_resolve(db_session)

    r = await async_admin_client.get("/api/pdns/resolve", params={
        "client": "192.168.1.67", "ip": "47.1.2.3", "at": NOW.isoformat()})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["match"] == "client"
    assert body["domain"] == "mine.example.com"
    assert body["cname_chain"] == ["mine.cdn.example", "edge.cdn.example"]
    assert body["age_seconds"] == 600


async def test_resolve_falls_back_to_any_device(async_admin_client: AsyncClient, db_session):
    await _seed_resolve(db_session)

    body = (await async_admin_client.get("/api/pdns/resolve", params={
        "client": "192.168.1.99", "ip": "47.1.2.3", "at": NOW.isoformat()})).json()

    assert body["match"] == "any" and body["domain"] == "theirs.example.com" and body["client_ip"] == "192.168.1.80"


async def test_resolve_has_no_time_cutoff(async_admin_client: AsyncClient, db_session):
    await _seed_resolve(db_session)

    body = (await async_admin_client.get("/api/pdns/resolve", params={
        "client": "192.168.1.67", "ip": "8.8.4.4", "at": NOW.isoformat()})).json()

    assert body["domain"] == "ancient.example.com" and body["age_seconds"] == 864000


async def test_resolve_with_no_match(async_admin_client: AsyncClient, db_session):
    await _seed_resolve(db_session)

    body = (await async_admin_client.get("/api/pdns/resolve", params={"ip": "203.0.113.9"})).json()

    assert body["match"] == "none" and body["domain"] is None and body["age_seconds"] is None


async def test_resolve_far_future_at_is_400(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/pdns/resolve", params={
        "ip": "1.1.1.1", "at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})

    assert r.status_code == 400


async def test_resolve_bad_ip_is_400(async_admin_client: AsyncClient):
    assert (await async_admin_client.get("/api/pdns/resolve", params={"ip": "nope"})).status_code == 400


async def test_resolve_batch_keeps_order(async_admin_client: AsyncClient, db_session):
    await _seed_resolve(db_session)
    at = NOW.isoformat()

    r = await async_admin_client.post("/api/pdns/resolve", json={"items": [
        {"client": "192.168.1.67", "ip": "8.8.4.4", "at": at},
        {"client": "192.168.1.67", "ip": "203.0.113.9", "at": at},
        {"client": "192.168.1.67", "ip": "47.1.2.3", "at": at},
    ]})

    assert r.status_code == 200, r.text
    assert [x["domain"] for x in r.json()["results"]] == ["ancient.example.com", None, "mine.example.com"]


async def test_resolve_batch_is_capped(async_admin_client: AsyncClient):
    items = [{"ip": "1.1.1.1"}] * 201

    assert (await async_admin_client.post("/api/pdns/resolve", json={"items": items})).status_code == 422


async def test_resolve_batch_rejects_bad_ip(async_admin_client: AsyncClient):
    assert (await async_admin_client.post("/api/pdns/resolve", json={"items": [{"ip": "x"}]})).status_code == 422


async def test_resolve_open_to_readonly_users(async_readonly_client: AsyncClient):
    assert (await async_readonly_client.post("/api/pdns/resolve", json={"items": []})).status_code == 200
