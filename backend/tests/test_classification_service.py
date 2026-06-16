from sqlalchemy import select, func
from backend.classification_service import ClassificationService
from backend.models import AppDefinition, AppDomain


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
