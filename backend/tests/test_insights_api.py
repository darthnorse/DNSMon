from datetime import datetime, timezone
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
