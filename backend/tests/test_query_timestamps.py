from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from backend.adguard_client import AdGuardHomeClient
from backend.ingestion import QueryIngestionService
from backend.models import Query
from backend.pihole_client import PiholeClient
from backend.technitium_client import TechnitiumClient


def _json_transport(path: str, payload: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == path:
            return httpx.Response(200, json=payload)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _adguard_entry(time: str, qtype: str) -> dict:
    return {
        "time": time,
        "question": {"class": "IN", "name": "ocsp2.apple.com", "type": qtype},
        "client": "192.168.1.67",
        "client_info": {"name": ""},
        "reason": "NotFilteredNotFound",
        "status": "NOERROR",
    }


def test_adguard_keeps_sub_second_time():
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    q = client._transform_query(_adguard_entry("2026-11-03T12:46:48.767032154-07:00", "A"))
    assert q["timestamp"] == datetime(2026, 11, 3, 19, 46, 48, 767032, tzinfo=timezone.utc)


async def test_adguard_same_second_queries_get_distinct_times():
    when = int(datetime(2026, 11, 3, 19, 46, 48, tzinfo=timezone.utc).timestamp())
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    client.client = httpx.AsyncClient(transport=_json_transport("/control/querylog", {"data": [
        _adguard_entry("2026-11-03T12:46:48.412920678-07:00", "A"),
        _adguard_entry("2026-11-03T12:46:48.412830163-07:00", "HTTPS"),
    ]}))

    queries = await client.get_queries(when - 1, when + 1)

    assert [q["type"] for q in queries] == ["A", "HTTPS"]
    assert queries[0]["timestamp"] != queries[1]["timestamp"]


def test_technitium_keeps_sub_second_time():
    client = TechnitiumClient("http://technitium.test", "token", "tech1")
    q = client._transform_query({
        "timestamp": "2026-11-03T10:00:00.1234567Z",
        "qname": "example.com",
        "clientIpAddress": "192.168.1.5",
        "qtype": "A",
        "responseType": "Recursive",
    })
    assert q["timestamp"] == datetime(2026, 11, 3, 10, 0, 0, 123456, tzinfo=timezone.utc)


async def test_pihole_queries_carry_ftl_query_time():
    client = PiholeClient("http://pihole.test", "pw", "pihole1")
    client.client = httpx.AsyncClient(transport=_json_transport("/api/queries", {"queries": [
        {"time": 1793734757.4692724, "domain": "example.com", "type": "A", "status": "FORWARDED",
         "client": {"ip": "192.168.1.5", "name": None}},
    ]}))

    queries = await client.get_queries(1793734700, 1793734800)

    assert queries[0]["timestamp"] == datetime.fromtimestamp(1793734757.4692724, tz=timezone.utc)


def _ingested(ts: datetime | None, qtype: str = "A") -> dict:
    return {"timestamp": ts, "domain": "ocsp2.apple.com", "client": {"ip": "192.168.1.67", "name": ""},
            "type": qtype, "status": "ALLOWED"}


async def test_same_second_queries_are_both_stored(db_session):
    a = datetime(2026, 11, 3, 19, 46, 48, 412920, tzinfo=timezone.utc)
    https = datetime(2026, 11, 3, 19, 46, 48, 412830, tzinfo=timezone.utc)

    count, _ = await QueryIngestionService()._store_queries([_ingested(a), _ingested(https, "HTTPS")], "adguard1")

    rows = (await db_session.execute(select(Query.timestamp, Query.query_type).order_by(Query.timestamp))).all()
    assert count == 2
    assert rows == [(https, "HTTPS"), (a, "A")]


async def test_query_without_time_is_skipped_not_stamped_now(db_session):
    count, _ = await QueryIngestionService()._store_queries([_ingested(None)], "pihole1")

    assert count == 0
    assert (await db_session.execute(select(Query))).first() is None


async def test_resume_point_rounds_down_to_whole_second(db_session):
    db_session.add(Query(timestamp=datetime(2026, 11, 3, 19, 46, 48, 900000, tzinfo=timezone.utc),
                         domain="example.com", client_ip="192.168.1.5", server="pihole1"))
    await db_session.commit()

    service = QueryIngestionService()
    service.settings.max_catchup_seconds = 10**9

    assert await service._get_last_query_timestamp("pihole1") == int(
        datetime(2026, 11, 3, 19, 46, 48, tzinfo=timezone.utc).timestamp())
