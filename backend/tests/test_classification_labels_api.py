"""Endpoint tests: app_name/category are surfaced inline on the query list
and the statistics top-domain lists via a LEFT JOIN to domain_labels."""
from backend.models import Query, DomainStatsHourly, DomainLabel, utcnow


async def test_queries_include_classification_labels(db_session, async_admin_client):
    db_session.add(Query(
        timestamp=utcnow(), domain="i.instagram.com", client_ip="10.0.0.5",
        client_hostname="phone", query_type="A", status="allowed", server="pi1",
    ))
    db_session.add(Query(
        timestamp=utcnow(), domain="edge-cdn.example.net", client_ip="10.0.0.6",
        client_hostname=None, query_type="A", status="allowed", server="pi1",
    ))
    db_session.add(DomainLabel(
        domain="i.instagram.com", app_name="Instagram",
        category="Social", matched_source="manual",
    ))
    await db_session.commit()

    r = await async_admin_client.get("/api/queries")
    assert r.status_code == 200
    by_domain = {row["domain"]: row for row in r.json()}

    assert by_domain["i.instagram.com"]["app_name"] == "Instagram"
    assert by_domain["i.instagram.com"]["category"] == "Social"
    # Unmatched domain -> nulls, never absent keys.
    assert by_domain["edge-cdn.example.net"]["app_name"] is None
    assert by_domain["edge-cdn.example.net"]["category"] is None


async def test_statistics_top_domains_include_labels(db_session, async_admin_client):
    hour = utcnow()
    db_session.add(DomainStatsHourly(hour=hour, server="pi1", domain="i.instagram.com", total=100, blocked=0))
    db_session.add(DomainStatsHourly(hour=hour, server="pi1", domain="edge-cdn.example.net", total=50, blocked=0))
    db_session.add(DomainStatsHourly(hour=hour, server="pi1", domain="ads.example.com", total=30, blocked=30))
    db_session.add(DomainLabel(
        domain="i.instagram.com", app_name="Instagram",
        category="Social", matched_source="manual",
    ))
    db_session.add(DomainLabel(
        domain="ads.example.com", app_name=None,
        category="Advertising", matched_source="blocklist",
    ))
    await db_session.commit()

    r = await async_admin_client.get("/api/statistics?period=24h")
    assert r.status_code == 200
    body = r.json()

    top = {d["domain"]: d for d in body["top_domains"]}
    assert top["i.instagram.com"]["app_name"] == "Instagram"
    assert top["i.instagram.com"]["category"] == "Social"
    # Category-only match: app_name null, category present.
    assert top["ads.example.com"]["app_name"] is None
    assert top["ads.example.com"]["category"] == "Advertising"
    # Unmatched.
    assert top["edge-cdn.example.net"]["app_name"] is None
    assert top["edge-cdn.example.net"]["category"] is None
    # Ranking preserved (by count desc) even though labels are joined after the LIMIT.
    assert [d["domain"] for d in body["top_domains"]] == [
        "i.instagram.com", "edge-cdn.example.net", "ads.example.com",
    ]

    blocked = {d["domain"]: d for d in body["top_blocked_domains"]}
    assert blocked["ads.example.com"]["category"] == "Advertising"
    assert [d["domain"] for d in body["top_blocked_domains"]] == ["ads.example.com"]


async def test_statistics_top_domains_raw_path_includes_labels(db_session, async_admin_client):
    """When a client filter is applied, top domains come from _run_top_domains_raw
    (raw queries table) — verify it also carries app_name/category."""
    db_session.add(Query(
        timestamp=utcnow(), domain="i.instagram.com", client_ip="10.0.0.5",
        client_hostname=None, query_type="A", status="allowed", server="pi1",
    ))
    db_session.add(DomainLabel(
        domain="i.instagram.com", app_name="Instagram",
        category="Social", matched_source="manual",
    ))
    await db_session.commit()

    r = await async_admin_client.get("/api/statistics?period=24h&clients=10.0.0.5")
    assert r.status_code == 200
    top = {d["domain"]: d for d in r.json()["top_domains"]}
    assert top["i.instagram.com"]["app_name"] == "Instagram"
    assert top["i.instagram.com"]["category"] == "Social"
