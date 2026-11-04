import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend import ingestion
from backend.config import PiholeServer
from backend.dns_client import QueryFetchError, QueryRangeTruncated
from backend.ingestion import RESUME_OVERLAP_SECONDS, QueryIngestionService
from backend.models import PiholeServerModel, Query, QueryStatsHourly


class FakeClient:
    def __init__(self, pages: list, gap_recovery: bool = True):
        self.pages = pages
        self.supports_gap_recovery = gap_recovery
        self.requested: tuple[int, int] | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def authenticate(self) -> bool:
        return True

    async def query_log_warning(self):
        return None

    async def iter_query_pages(self, from_timestamp: int, until_timestamp: int):
        self.requested = (from_timestamp, until_timestamp)
        for page in self.pages:
            if isinstance(page, Exception):
                raise page
            yield page


def _q(ts: datetime, domain: str) -> dict:
    return {"timestamp": ts, "domain": domain, "client": {"ip": "192.168.1.5", "name": ""},
            "type": "A", "status": "ALLOWED"}


async def _server(db_session, cursor: datetime | None, server_type: str = "adguard") -> PiholeServer:
    row = PiholeServerModel(name="adguard1", url="http://adguard.test", password="pw",
                            server_type=server_type, ingested_until=cursor)
    db_session.add(row)
    await db_session.commit()
    return PiholeServer(id=row.id, name=row.name, url=row.url, password="pw", server_type=server_type)


async def _cursor(db_session, server_id: int) -> datetime | None:
    db_session.expire_all()
    return (await db_session.execute(
        select(PiholeServerModel.ingested_until).where(PiholeServerModel.id == server_id))).scalar_one()


@pytest.fixture
def fake_client(monkeypatch):
    def install(client: FakeClient) -> FakeClient:
        monkeypatch.setattr(ingestion, "create_client_from_server", lambda server: client)
        return client
    return install


async def test_gap_recovery_stores_whole_backlog_but_alerts_only_recent(db_session, fake_client):
    now = datetime.now(timezone.utc)
    server = await _server(db_session, now - timedelta(days=3))
    old = [_q(now - timedelta(days=3) + timedelta(seconds=i), f"old{i}.example.com") for i in range(3)]
    recent = [_q(now - timedelta(seconds=30 + i), f"new{i}.example.com") for i in range(2)]
    client = fake_client(FakeClient([recent, old]))

    count, alertable = await QueryIngestionService().ingest_from_server(server)

    assert count == 5
    assert {q.domain for q in alertable} == {"new0.example.com", "new1.example.com"}
    assert client.requested[0] == int((now - timedelta(days=3)).timestamp()) - RESUME_OVERLAP_SECONDS


async def test_cursor_follows_the_servers_clock(db_session, fake_client):
    server_now = datetime.now(timezone.utc) - timedelta(seconds=60)
    server = await _server(db_session, server_now - timedelta(minutes=1))
    fake_client(FakeClient([[_q(server_now, "late.example.com")]]))

    await QueryIngestionService().ingest_from_server(server)

    assert await _cursor(db_session, server.id) == server_now


async def test_empty_poll_keeps_the_cursor(db_session, fake_client):
    original = datetime.now(timezone.utc) - timedelta(minutes=1)
    server = await _server(db_session, original)
    fake_client(FakeClient([[]]))

    await QueryIngestionService().ingest_from_server(server)

    assert await _cursor(db_session, server.id) == original


async def test_store_failure_does_not_advance_cursor(db_session, fake_client, monkeypatch):
    original = datetime.now(timezone.utc) - timedelta(minutes=10)
    server = await _server(db_session, original)
    fake_client(FakeClient([[_q(original + timedelta(minutes=5), "a.example.com")]]))

    def broken_insert(*args, **kwargs):
        raise RuntimeError("connection reset")
    monkeypatch.setattr(ingestion, "insert", broken_insert)

    await QueryIngestionService().ingest_from_server(server)

    assert await _cursor(db_session, server.id) == original


async def test_failed_first_fetch_retries_from_the_original_start(db_session, fake_client):
    server = await _server(db_session, None)
    recent = datetime.now(timezone.utc) - timedelta(seconds=10)
    client = fake_client(FakeClient([[_q(recent, "new.example.com")], QueryFetchError("boom")]))
    service = QueryIngestionService()

    await service.ingest_from_server(server)

    assert await service._resume_point(server, True, int(time.time())) == client.requested[0]


async def test_truncated_range_advances_to_newest_fetched(db_session, fake_client):
    server = await _server(db_session, datetime.now(timezone.utc) - timedelta(days=5))
    newest = datetime.now(timezone.utc) - timedelta(days=4)
    fake_client(FakeClient([[_q(newest - timedelta(seconds=1), "a.example.com"), _q(newest, "b.example.com")],
                            QueryRangeTruncated("too many pages")]))

    await QueryIngestionService().ingest_from_server(server)

    assert await _cursor(db_session, server.id) == newest


async def test_unexpected_error_mid_walk_still_alerts_stored_pages(db_session, fake_client):
    server = await _server(db_session, datetime.now(timezone.utc) - timedelta(minutes=1))
    fake_client(FakeClient([[_q(datetime.now(timezone.utc) - timedelta(seconds=5), "a.example.com")],
                            ValueError("not json")]))

    count, alertable = await QueryIngestionService().ingest_from_server(server)

    assert count == 1
    assert [q.domain for q in alertable] == ["a.example.com"]


async def test_cursor_not_advanced_when_a_page_fails(db_session, fake_client):
    original = datetime.now(timezone.utc) - timedelta(days=2)
    server = await _server(db_session, original)
    fake_client(FakeClient([[_q(original + timedelta(seconds=1), "a.example.com")], QueryFetchError("boom")]))

    await QueryIngestionService().ingest_from_server(server)

    assert await _cursor(db_session, server.id) == original


async def test_pihole_resume_is_still_capped(db_session):
    now = int(time.time())
    server = await _server(db_session, datetime.now(timezone.utc) - timedelta(days=1), server_type="pihole")
    service = QueryIngestionService()

    assert await service._resume_point(server, False, now) == now - service.settings.max_catchup_seconds


async def test_resume_falls_back_to_newest_stored_query(db_session):
    server = await _server(db_session, None)
    db_session.add(Query(timestamp=datetime(2026, 11, 3, 19, 46, 48, 900000, tzinfo=timezone.utc),
                         domain="example.com", client_ip="192.168.1.5", server="adguard1"))
    await db_session.commit()
    service = QueryIngestionService()

    expected = int(datetime(2026, 11, 3, 19, 46, 48, tzinfo=timezone.utc).timestamp()) - RESUME_OVERLAP_SECONDS
    assert await service._resume_point(server, True, int(time.time())) == expected


async def test_backlog_counts_in_hourly_stats(db_session, fake_client):
    now = datetime.now(timezone.utc)
    old_ts = now - timedelta(days=3)
    server = await _server(db_session, old_ts - timedelta(minutes=1))
    fake_client(FakeClient([[_q(old_ts, "old.example.com")]]))

    await QueryIngestionService().ingest_from_server(server)

    hour = old_ts.replace(minute=0, second=0, microsecond=0)
    row = (await db_session.execute(select(QueryStatsHourly).where(QueryStatsHourly.hour == hour))).scalar_one()
    assert row.total == 1


async def test_failure_after_storing_still_returns_the_alerts(db_session, fake_client, monkeypatch):
    server = await _server(db_session, datetime.now(timezone.utc) - timedelta(minutes=1))
    fake_client(FakeClient([[_q(datetime.now(timezone.utc) - timedelta(seconds=5), "a.example.com")]]))
    service = QueryIngestionService()
    advance = service._advance_cursor

    async def fail_final_advance(server, to, only_if_unset=False):
        if not only_if_unset:
            raise RuntimeError("database went away")
        await advance(server, to, only_if_unset=True)
    monkeypatch.setattr(service, "_advance_cursor", fail_final_advance)

    count, alertable = await service.ingest_from_server(server)

    assert count == 1
    assert [q.domain for q in alertable] == ["a.example.com"]


async def test_polling_does_not_touch_the_server_config_timestamp(db_session, fake_client):
    server = await _server(db_session, None)
    db_session.expire_all()
    before = (await db_session.execute(
        select(PiholeServerModel.updated_at).where(PiholeServerModel.id == server.id))).scalar_one()
    fake_client(FakeClient([[_q(datetime.now(timezone.utc) - timedelta(seconds=5), "a.example.com")]]))

    await QueryIngestionService().ingest_from_server(server)

    db_session.expire_all()
    after = (await db_session.execute(
        select(PiholeServerModel.updated_at).where(PiholeServerModel.id == server.id))).scalar_one()
    assert after == before
