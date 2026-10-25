from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from backend import api


async def test_lifespan_starts_and_stops_background_service(monkeypatch):
    service = MagicMock(startup=AsyncMock(), shutdown=AsyncMock())
    monkeypatch.setattr(api, 'init_db', AsyncMock())
    monkeypatch.setattr(api, 'get_settings', AsyncMock(return_value=SimpleNamespace(poll_interval_seconds=60)))
    monkeypatch.setattr(api, 'get_service', lambda: service)

    async with api.app.router.lifespan_context(api.app):
        api.init_db.assert_awaited_once()
        service.startup.assert_awaited_once()
        service.shutdown.assert_not_awaited()

    service.shutdown.assert_awaited_once()
