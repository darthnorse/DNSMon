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
