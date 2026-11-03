import logging

import httpx
import pytest

from backend import ingestion
from backend.adguard_client import AdGuardHomeClient
from backend.ingestion import QueryIngestionService
from backend.pihole_client import PiholeClient
from backend.tests.test_ingestion_gaps import FakeClient, _server

LOG_ON = {"enabled": True, "anonymize_client_ip": False, "interval": 604800000, "ignored": [], "ignored_enabled": False}


def _adguard(querylog_config: dict | None) -> AdGuardHomeClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if querylog_config is None:
            return httpx.Response(500)
        return httpx.Response(200, json=querylog_config)
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


@pytest.mark.parametrize("config, fragment", [
    ({**LOG_ON, "enabled": False}, "disabled"),
    ({**LOG_ON, "anonymize_client_ip": True}, "anonymi"),
])
async def test_adguard_warns_when_query_log_is_unusable(config, fragment):
    warning = await _adguard(config).query_log_warning()
    assert warning is not None and fragment in warning


async def test_adguard_healthy_log_has_no_warning():
    assert await _adguard(LOG_ON).query_log_warning() is None


async def test_unreadable_log_config_is_not_a_warning():
    assert await _adguard(None).query_log_warning() is None


async def test_pihole_never_warns():
    assert await PiholeClient("http://p", "pw", "p").query_log_warning() is None


async def test_connection_test_reports_the_warning(async_admin_client, monkeypatch):
    from backend import utils

    class Warned(FakeClient):
        async def query_log_warning(self):
            return "Query log anonymises client IPs"

    async def safe(url):
        return None
    monkeypatch.setattr(utils, "create_client_from_server", lambda s: Warned([]))
    monkeypatch.setattr(utils, "async_validate_url_safety", safe)

    r = await async_admin_client.post("/api/settings/pihole-servers/test", json={
        "name": "adguard1", "url": "http://192.168.1.11", "password": "pw", "server_type": "adguard"})

    assert r.json()["success"] is True
    assert "anonymises client IPs" in r.json()["message"]


async def test_ingestion_logs_the_warning_at_most_once_per_interval(db_session, monkeypatch, caplog):
    calls = []

    class Warned(FakeClient):
        async def query_log_warning(self):
            calls.append(1)
            return "Query log is disabled"

    server = await _server(db_session, None)
    monkeypatch.setattr(ingestion, "create_client_from_server", lambda s: Warned([[]]))
    service = QueryIngestionService()

    with caplog.at_level(logging.WARNING, logger="backend.ingestion"):
        await service.ingest_from_server(server)
        await service.ingest_from_server(server)

    assert len(calls) == 1
    assert caplog.text.count("Query log is disabled") == 1
