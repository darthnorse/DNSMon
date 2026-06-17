import json
import httpx
from datetime import datetime, timezone

from sqlalchemy import select, func
from backend.classification_service import ClassificationService
from backend.models import AppDefinition, AppDomain, DomainLabel, DomainStatsHourly, Query


async def test_load_supplement_populates_definitions(db_session):
    svc = ClassificationService()
    await svc.load_supplement(db_session)

    count = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.source == 'supplement')
    )
    assert count >= 10

    teamviewer = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'teamviewer', AppDefinition.source == 'supplement')
    )
    assert teamviewer.category == 'Remote Access'

    dom_count = await db_session.scalar(
        select(func.count()).select_from(AppDomain).where(AppDomain.app_id == teamviewer.id)
    )
    assert dom_count >= 1


async def test_load_supplement_is_idempotent(db_session):
    svc = ClassificationService()
    await svc.load_supplement(db_session)
    await svc.load_supplement(db_session)  # second run must not duplicate

    count = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.slug == 'teamviewer')
    )
    assert count == 1


async def _seed_query(db_session, domain):
    db_session.add(Query(
        timestamp=datetime.now(timezone.utc), domain=domain,
        client_ip='10.0.0.5', status='OK', server='s1', query_type='A',
    ))
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db_session.add(DomainStatsHourly(hour=hour, server='s1', domain=domain, total=1, blocked=0))
    await db_session.commit()


async def test_reclassify_labels_known_and_unknown(db_session):
    svc = ClassificationService()
    await svc.load_supplement(db_session)
    await _seed_query(db_session, 'files.github.com')
    await _seed_query(db_session, 'totally-unknown-host.test')

    await svc.reclassify(db_session)

    gh = await db_session.get(DomainLabel, 'files.github.com')
    assert gh.app_name == 'GitHub'
    assert gh.category == 'Development'
    assert gh.matched_source == 'supplement'

    unknown = await db_session.get(DomainLabel, 'totally-unknown-host.test')
    assert unknown is not None          # row stored so we don't re-attempt
    assert unknown.app_name is None     # honest 'uncategorized'


async def test_reclassify_is_idempotent_and_updates(db_session):
    svc = ClassificationService()
    await svc.load_supplement(db_session)
    await _seed_query(db_session, 'notion.so')
    await svc.reclassify(db_session)
    await svc.reclassify(db_session)  # rerun must not error or duplicate (PK domain)

    label = await db_session.get(DomainLabel, 'notion.so')
    assert label.app_name == 'Notion'


async def test_replace_source_preserves_disabled_flag(db_session):
    svc = ClassificationService()
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'foo', 'name': 'Foo', 'category': 'X', 'domains': [('foo.com', False)]},
    ])
    foo = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'foo', AppDefinition.source == 'adguard')
    )
    foo.enabled = False
    await db_session.commit()
    # refresh the source again (same slug)
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'foo', 'name': 'Foo', 'category': 'X', 'domains': [('foo.com', False)]},
    ])
    foo2 = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'foo', AppDefinition.source == 'adguard')
    )
    assert foo2.enabled is False  # admin's disable survived the refresh


async def test_run_full_disabled_sources_are_cleared(db_session):
    svc = ClassificationService()
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'a1', 'name': 'A1', 'category': 'X', 'domains': [('a1.com', False)]}])
    await svc._replace_source(db_session, 'supplement', [
        {'slug': 's1', 'name': 'S1', 'category': 'Y', 'domains': [('s1.com', False)]}])
    # run_full opens its own session; feed+supplement disabled => both sources cleared, no network
    await svc.run_full(feed_enabled=False, supplement_enabled=False)
    # verify via a fresh query (run_full committed in its own session)
    remaining = await db_session.scalar(select(func.count()).select_from(AppDefinition))
    assert remaining == 0


async def _allow_ssrf(monkeypatch):
    async def ok(url):
        return None
    monkeypatch.setattr("backend.classification_service.async_validate_url_safety", ok)


async def test_load_dnsmon_remote_success(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    async def fake(self, url):
        return json.dumps([{"slug": "acme", "name": "Acme", "category": "Software",
                            "domains": ["acme.com"]}])
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)

    svc = ClassificationService()
    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n == 1
    acme = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "acme", AppDefinition.source == "supplement"))
    assert acme.name == "Acme"
    assert acme.is_category_only is False


async def test_load_dnsmon_fetch_fail_keeps_existing(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    await svc._replace_source(db_session, "supplement", [
        {"slug": "old", "name": "Old", "category": "X", "domains": [("old.com", False)]}])
    async def boom(self, url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", boom)

    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n == -1
    cnt = await db_session.scalar(select(func.count()).select_from(AppDefinition).where(
        AppDefinition.source == "supplement"))
    assert cnt == 1  # existing tier preserved, not regressed to bundled


async def test_load_dnsmon_fetch_fail_first_boot_uses_bundled(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    async def boom(self, url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", boom)

    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n >= 10  # bundled dnsmon.json loaded on first boot
    tv = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "teamviewer", AppDefinition.source == "supplement"))
    assert tv is not None
