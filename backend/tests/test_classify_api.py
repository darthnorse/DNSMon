"""End-to-end tests for /api/classify (user-defined classification)."""
from httpx import AsyncClient
from sqlalchemy import select, func

from backend.models import AppDefinition, AppDomain


async def test_classify_requires_admin(async_readonly_client: AsyncClient):
    r = await async_readonly_client.post("/api/classify",
                                         json={"domain": "foo.com", "category": "CDN"})
    assert r.status_code == 403


async def test_classify_requires_a_label(async_admin_client: AsyncClient):
    r = await async_admin_client.post("/api/classify", json={"domain": "foo.com"})
    assert r.status_code == 422  # neither app_name nor category


async def test_classify_app_registrable(async_admin_client: AsyncClient, db_session):
    r = await async_admin_client.post("/api/classify", json={
        "domain": "dev-nat20.lumasurveillance.com", "app_name": "Luma",
        "category": "Security Cameras", "scope": "registrable"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["domain"] == "lumasurveillance.com"  # resolved to registrable parent
    ad = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.source == 'manual', AppDefinition.name == 'Luma'))
    assert ad is not None and ad.is_category_only is False
    assert ad.category == "Security Cameras"
    dom = await db_session.scalar(select(AppDomain).where(
        AppDomain.app_id == ad.id, AppDomain.domain == "lumasurveillance.com"))
    assert dom is not None


async def test_classify_category_only_bucket(async_admin_client: AsyncClient, db_session):
    r = await async_admin_client.post("/api/classify", json={
        "domain": "cdn.example.com", "category": "CDN", "scope": "exact"})
    assert r.status_code == 200, r.text
    assert r.json()["domain"] == "cdn.example.com"
    ad = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.source == 'manual', AppDefinition.is_category_only == True,
        AppDefinition.category == 'CDN'))
    assert ad is not None
    assert ad.slug == "manual-cat-cdn"


async def test_classify_appends_to_existing_app(async_admin_client: AsyncClient, db_session):
    await async_admin_client.post("/api/classify", json={
        "domain": "notion.so", "app_name": "Notion", "category": "Productivity", "scope": "exact"})
    await async_admin_client.post("/api/classify", json={
        "domain": "notion.com", "app_name": "Notion", "category": "Productivity", "scope": "exact"})
    defs = (await db_session.execute(select(AppDefinition).where(
        AppDefinition.source == 'manual', AppDefinition.name == 'Notion'))).scalars().all()
    assert len(defs) == 1  # one Notion def, not two
    cnt = await db_session.scalar(select(func.count()).select_from(AppDomain).where(
        AppDomain.app_id == defs[0].id))
    assert cnt == 2


async def test_unclassify_removes_and_empties(async_admin_client: AsyncClient, db_session):
    await async_admin_client.post("/api/classify", json={
        "domain": "solo.example.org", "category": "CDN", "scope": "exact"})
    # one category-only bucket now holds solo.example.org
    r = await async_admin_client.delete("/api/classify",
                                        params={"domain": "solo.example.org", "scope": "exact"})
    assert r.status_code == 200, r.text
    dom = await db_session.scalar(select(AppDomain).where(AppDomain.domain == "solo.example.org"))
    assert dom is None  # mapping removed
    # the bucket had only that domain -> def deleted
    ad = await db_session.scalar(select(AppDefinition).where(AppDefinition.slug == "manual-cat-cdn"))
    assert ad is None


async def test_unclassify_keeps_def_with_other_domains(async_admin_client: AsyncClient, db_session):
    await async_admin_client.post("/api/classify", json={
        "domain": "a.example.net", "app_name": "Acme", "scope": "exact"})
    await async_admin_client.post("/api/classify", json={
        "domain": "b.example.net", "app_name": "Acme", "scope": "exact"})
    await async_admin_client.delete("/api/classify",
                                    params={"domain": "a.example.net", "scope": "exact"})
    ad = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.source == 'manual', AppDefinition.name == 'Acme'))
    assert ad is not None  # still has b.example.net
    cnt = await db_session.scalar(select(func.count()).select_from(AppDomain).where(
        AppDomain.app_id == ad.id))
    assert cnt == 1


async def test_label_unlabeled_returns_registrable(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/classify/label",
                                     params={"domain": "sub.unknownhost.com"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["registrable"] == "unknownhost.com"
    assert body["matched"] is False


async def test_label_reflects_manual_classification(async_admin_client: AsyncClient):
    await async_admin_client.post("/api/classify", json={
        "domain": "mapped.example.com", "app_name": "Mapped", "category": "Tools", "scope": "exact"})
    # reclassify runs in the background after POST; force it deterministically.
    # reclassify only labels domains observed in domain_stats_hourly, so seed one.
    from backend.service import get_service
    from backend.database import async_session_maker
    from backend.models import DomainStatsHourly, utcnow
    async with async_session_maker() as s:
        s.add(DomainStatsHourly(hour=utcnow(), server="t", domain="mapped.example.com",
                                total=1, blocked=0))
        await s.commit()
        await get_service().classification_service.reclassify(s)
    r = await async_admin_client.get("/api/classify/label", params={"domain": "mapped.example.com"})
    body = r.json()
    assert body["matched"] is True
    assert body["app_name"] == "Mapped"
    assert body["matched_source"] == "manual"
