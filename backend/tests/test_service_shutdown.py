import asyncio
from unittest.mock import AsyncMock, MagicMock

from backend.service import DNSMonService


async def test_shutdown_cancels_a_running_answer_index_build():
    service = DNSMonService()
    service.scheduler = MagicMock()
    service.alert_engine = MagicMock(invalidate_cache=AsyncMock())
    build = asyncio.create_task(asyncio.sleep(3600))
    service._answer_index_task = build

    await service.shutdown()

    assert build.cancelled()
