from datetime import datetime, timezone

from sqlalchemy import select, func
from backend.classification_service import ClassificationService
from backend.models import AppDefinition, AppDomain, DomainLabel, Query


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
