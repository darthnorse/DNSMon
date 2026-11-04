from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from backend.adguard_client import AdGuardHomeClient
from backend import adguard_client, technitium_client
from backend.dns_client import QueryFetchError, QueryRangeTruncated
from backend.pihole_client import PiholeClient
from backend.technitium_client import TechnitiumClient

T0 = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _entry(i: int) -> dict:
    """The i-th newest entry: one second older per step."""
    return {
        "time": _iso(T0 - timedelta(seconds=i)),
        "question": {"class": "IN", "name": f"d{i}.example.com", "type": "A"},
        "client": "192.168.1.5", "client_info": {"name": ""},
        "reason": "NotFilteredNotFound", "status": "NOERROR",
    }


class FakeQueryLog:
    """AdGuard /control/querylog over `total` entries, newest first, honouring older_than + limit."""

    def __init__(self, total: int, fail_on_request: int | None = None, oldest_override: dict[int, str] | None = None):
        self.entries = [_entry(i) for i in range(total)]
        self.fail_on_request = fail_on_request
        self.oldest_override = oldest_override or {}
        self.older_than_seen: list[str | None] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        n = len(self.older_than_seen)
        older_than = request.url.params.get("older_than")
        self.older_than_seen.append(older_than)
        if self.fail_on_request == n:
            return httpx.Response(500)
        limit = int(request.url.params["limit"])
        rows = [e for e in self.entries if older_than is None or e["time"] < older_than][:limit]
        oldest = self.oldest_override.get(n, rows[-1]["time"] if rows else "")
        return httpx.Response(200, json={"data": rows, "oldest": oldest})


def _adguard(fake: FakeQueryLog) -> AdGuardHomeClient:
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    return client


async def _pages(client, frm: int, until: int) -> list[list[dict]]:
    return [page async for page in client.iter_query_pages(frm, until)]


async def test_adguard_pages_back_until_from_timestamp():
    fake = FakeQueryLog(total=3500)
    frm = int((T0 - timedelta(seconds=2499)).timestamp())

    pages = await _pages(_adguard(fake), frm, int(T0.timestamp()))

    assert sum(map(len, pages)) == 2500
    assert fake.older_than_seen == [None, _iso(T0 - timedelta(seconds=999)), _iso(T0 - timedelta(seconds=1999))]


async def test_adguard_stops_at_end_of_log():
    fake = FakeQueryLog(total=1500)

    pages = await _pages(_adguard(fake), 0, int(T0.timestamp()))

    assert sum(map(len, pages)) == 1500
    assert len(fake.older_than_seen) <= 3


@pytest.mark.parametrize("override", [{0: ""}, {1: _iso(T0 - timedelta(seconds=999))}])
async def test_adguard_paging_stops_on_empty_or_stuck_cursor(override):
    fake = FakeQueryLog(total=5000, oldest_override=override)

    await _pages(_adguard(fake), 0, int(T0.timestamp()))

    assert len(fake.older_than_seen) <= 3


async def test_adguard_page_error_raises():
    fake = FakeQueryLog(total=3000, fail_on_request=1)

    with pytest.raises(QueryFetchError):
        await _pages(_adguard(fake), 0, int(T0.timestamp()))


async def test_adguard_walk_is_capped(monkeypatch):
    monkeypatch.setattr(adguard_client, "MAX_QUERYLOG_PAGES", 2)
    fake = FakeQueryLog(total=5000)

    with pytest.raises(QueryRangeTruncated):
        await _pages(_adguard(fake), 0, int(T0.timestamp()))

    assert len(fake.older_than_seen) == 2


async def test_adguard_non_json_page_raises_fetch_error():
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, text="<html>proxy login</html>")))

    with pytest.raises(QueryFetchError):
        await _pages(client, 0, int(T0.timestamp()))


def _technitium_handler(pages: dict[int, list[dict] | None]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = pages.get(int(request.url.params["pageNumber"]))
        if body is None:
            return httpx.Response(500)
        return httpx.Response(200, json={"status": "ok", "response": {"entries": body}})
    return handler


def _tech_entry(i: int) -> dict:
    return {"timestamp": _iso(T0 + timedelta(seconds=i)), "qname": f"t{i}.example.com",
            "clientIpAddress": "192.168.1.5", "qtype": "A", "responseType": "Recursive"}


async def test_technitium_page_failure_after_first_raises():
    client = TechnitiumClient("http://tech.test", "token", "tech1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(
        _technitium_handler({1: [_tech_entry(i) for i in range(5000)], 2: None})))

    with pytest.raises(QueryFetchError):
        await _pages(client, 0, 2**31)


async def test_technitium_requests_oldest_first_and_caps_the_walk(monkeypatch):
    monkeypatch.setattr(technitium_client, "MAX_LOG_PAGES", 1)
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("descendingOrder"))
        return httpx.Response(200, json={"status": "ok", "response": {"entries": [_tech_entry(i) for i in range(5000)]}})
    client = TechnitiumClient("http://tech.test", "token", "tech1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    with pytest.raises(QueryRangeTruncated):
        await _pages(client, 0, 2**31)

    assert seen == ["false"]


async def test_technitium_null_response_is_an_empty_page():
    client = TechnitiumClient("http://tech.test", "token", "tech1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"status": "ok", "response": None})))

    assert await _pages(client, 0, 2**31) == [[]]


def test_gap_recovery_capability():
    assert AdGuardHomeClient("http://a", "pw", "a").supports_gap_recovery is True
    assert TechnitiumClient("http://t", "tok", "t").supports_gap_recovery is True
    assert PiholeClient("http://p", "pw", "p").supports_gap_recovery is False


async def test_pihole_yields_its_queries_as_one_page():
    client = PiholeClient("http://pihole.test", "pw", "pihole1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"queries": [{"time": 1793734757.5, "domain": "x.com"}]})))

    pages = await _pages(client, 1793734700, 1793734800)

    assert [len(p) for p in pages] == [1]


def _clock_client(handler) -> AdGuardHomeClient:
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def test_clock_drift_reads_the_date_header():
    behind = format_datetime(datetime.now(timezone.utc) - timedelta(minutes=10), usegmt=True)

    drift = await _clock_client(lambda r: httpx.Response(200, headers={"Date": behind})).clock_drift_seconds()

    assert -605 <= drift <= -595


@pytest.mark.parametrize("headers", [{}, {"Date": "not a date"}])
async def test_clock_drift_is_unknown_without_a_usable_date(headers):
    assert await _clock_client(lambda r: httpx.Response(200, headers=headers)).clock_drift_seconds() is None


async def test_clock_drift_is_unknown_when_the_server_is_unreachable():
    def refuse(request):
        raise httpx.ConnectError("refused")

    assert await _clock_client(refuse).clock_drift_seconds() is None

