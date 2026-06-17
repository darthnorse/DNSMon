from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from backend.models import DomainLabel, DomainStatsHourly


async def _seed(db_session):
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db_session.add_all([
        DomainLabel(domain='a.netflix.com', app_name='Netflix', category='Streaming',
                    app_id=None, matched_source='adguard'),
        DomainLabel(domain='unknown.test', app_name=None, category=None,
                    app_id=None, matched_source=None),
        DomainStatsHourly(hour=hour, server='s1', domain='a.netflix.com', total=100, blocked=2),
        DomainStatsHourly(hour=hour, server='s1', domain='unknown.test', total=50, blocked=0),
    ])
    await db_session.commit()


async def test_apps_endpoint_returns_known_app(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)
    r = await async_admin_client.get("/api/insights/apps?period=24h")
    assert r.status_code == 200, r.text
    apps = r.json()
    netflix = next((a for a in apps if a['app_name'] == 'Netflix'), None)
    assert netflix and netflix['total'] == 100


async def test_categories_include_uncategorized(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)
    r = await async_admin_client.get("/api/insights/categories?period=24h")
    assert r.status_code == 200, r.text
    cats = {c['category']: c['total'] for c in r.json()}
    assert cats.get('Streaming') == 100
    assert cats.get('Uncategorized') == 50


async def test_app_domains_drilldown(async_admin_client: AsyncClient, db_session):
    await _seed(db_session)
    r = await async_admin_client.get("/api/insights/apps/domains?app_name=Netflix&period=24h")
    assert r.status_code == 200, r.text
    assert r.json()[0]['domain'] == 'a.netflix.com'


async def test_insights_requires_auth(async_client: AsyncClient):
    r = await async_client.get("/api/insights/apps")
    assert r.status_code == 401


async def test_categories_counts_domains_without_label_row(async_admin_client: AsyncClient, db_session):
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    # A rollup row whose domain has NO matching domain_labels entry at all.
    db_session.add(DomainStatsHourly(hour=hour, server='s1', domain='never-classified.test', total=7, blocked=0))
    await db_session.commit()
    r = await async_admin_client.get("/api/insights/categories?period=24h")
    assert r.status_code == 200, r.text
    cats = {c['category']: c['total'] for c in r.json()}
    assert cats.get('Uncategorized', 0) >= 7


async def test_uncategorized_domains_lists_only_null_category(async_admin_client, db_session):
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db_session.add_all([
        DomainStatsHourly(hour=hour, server='s1', domain='big-uncat.com', total=1000, blocked=0),
        DomainStatsHourly(hour=hour, server='s1', domain='small-uncat.com', total=5, blocked=0),
        DomainStatsHourly(hour=hour, server='s1', domain='categorized.com', total=900, blocked=0),
        DomainLabel(domain='categorized.com', category='Streaming', app_name='X', matched_source='manual'),
        DomainLabel(domain='big-uncat.com', category=None, app_name=None, matched_source=None),
    ])
    await db_session.commit()
    r = await async_admin_client.get("/api/insights/uncategorized-domains", params={"period": "24h"})
    assert r.status_code == 200, r.text
    domains = [row["domain"] for row in r.json()]
    assert "categorized.com" not in domains
    assert domains[0] == "big-uncat.com"           # volume-sorted desc
    assert "small-uncat.com" in domains


async def test_uncategorized_domains_respects_custom_range_upper_bound(async_admin_client, db_session):
    # _resolve_period takes the custom branch whenever BOTH from_date and to_date
    # are supplied (period value is ignored). Dates parse as ISO 8601, so a bare
    # YYYY-MM-DD is that day at 00:00:00 UTC, and to_date is an EXACT exclusive-ish
    # ceiling (T.hour <= to_date_midnight), NOT inclusive end-of-day.
    midnight_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    in_range = midnight_today - timedelta(days=2)   # 2 days ago, inside [3d ago, 1d ago midnight]
    out_of_range = midnight_today                   # today's midnight, after the to_date ceiling
    db_session.add_all([
        DomainStatsHourly(hour=in_range, server='s1', domain='inrange-uncat.com', total=100, blocked=0),
        DomainStatsHourly(hour=out_of_range, server='s1', domain='today-uncat.com', total=500, blocked=0),
    ])
    await db_session.commit()
    frm = (midnight_today - timedelta(days=3)).strftime('%Y-%m-%d')
    to = (midnight_today - timedelta(days=1)).strftime('%Y-%m-%d')
    r = await async_admin_client.get("/api/insights/uncategorized-domains",
                                     params={"period": "custom", "from_date": frm, "to_date": to})
    assert r.status_code == 200, r.text
    domains = [row["domain"] for row in r.json()]
    assert "inrange-uncat.com" in domains
    assert "today-uncat.com" not in domains   # excluded by the to_date upper bound
