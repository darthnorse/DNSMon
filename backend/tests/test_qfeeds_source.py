"""Tests for the Q-Feeds threat source: secret scrubbing, URL building, loader."""

import httpx

from backend.classification_service import (
    ClassificationService,
    build_qfeeds_url,
    _scrub_secrets,
)
from backend.constants import QFEEDS_FEED_URL
from backend.models import InsightSource


def test_scrubs_token_in_url():
    out = _scrub_secrets("Failed: https://api.qfeeds.com/api?api_token=tip_deadbeef")
    assert 'tip_deadbeef' not in out
    assert 'api_token=***' in out


def test_scrubs_token_with_trailing_params():
    out = _scrub_secrets("https://api.qfeeds.com/api?api_token=tip_deadbeef&feed_type=x")
    assert 'tip_deadbeef' not in out
    assert 'feed_type=x' in out


def test_scrubs_token_followed_by_whitespace():
    out = _scrub_secrets("url=https://a/b?api_token=tip_deadbeef and then some text")
    assert 'tip_deadbeef' not in out
    assert 'and then some text' in out


def test_scrubs_every_occurrence():
    out = _scrub_secrets("a?api_token=tok_one b?api_token=tok_two")
    assert 'tok_one' not in out and 'tok_two' not in out
    assert out.count('api_token=***') == 2


def test_message_without_token_is_unchanged():
    msg = "Failed to fetch v2fly list: connection reset"
    assert _scrub_secrets(msg) == msg


def test_handles_empty_string():
    assert _scrub_secrets('') == ''


def test_build_url_merges_token_into_existing_query():
    out = build_qfeeds_url(QFEEDS_FEED_URL, 'tip_abc')
    params = dict(httpx.URL(out).params)
    assert params['api_token'] == 'tip_abc'
    assert params['feed_type'] == 'malware_domains'
    assert params['download'] == '0'
    assert out.count('?') == 1


def test_build_url_replaces_an_existing_token():
    out = build_qfeeds_url('https://api.qfeeds.com/api?api_token=old', 'new')
    assert dict(httpx.URL(out).params)['api_token'] == 'new'
    assert 'old' not in out


def test_build_url_on_a_bare_url():
    out = build_qfeeds_url('https://api.qfeeds.com/api', 'tip_abc')
    assert dict(httpx.URL(out).params) == {'api_token': 'tip_abc'}


def test_build_url_escapes_the_token():
    out = build_qfeeds_url('https://api.qfeeds.com/api', 'a b&c')
    assert dict(httpx.URL(out).params)['api_token'] == 'a b&c'
    assert '&c=' not in out


class _Row:
    def __init__(self, url=QFEEDS_FEED_URL, api_key='tip_test'):
        self.url = url
        self.api_key = api_key
        self.kind = 'qfeeds'
        self.name = 'Q-Feeds Malware Domains'
        self.domain_count_high_water = None


async def _returns(value):
    return value


async def test_load_qfeeds_without_a_key_returns_error(db_session):
    assert await ClassificationService().load_qfeeds(db_session, _Row(api_key=None)) == -1


async def test_load_qfeeds_writes_definitions(db_session, monkeypatch):
    from sqlalchemy import select
    from backend.models import AppDefinition, AppDomain

    svc = ClassificationService()
    seen = {}

    feed = "evil.com\nbad.example\n" + "\n".join(f"x{i}.example" for i in range(150))

    async def fake_fetch(url, what):
        seen['url'] = url
        return feed

    monkeypatch.setattr(svc, '_safe_fetch', fake_fetch)
    assert await svc.load_qfeeds(db_session, _Row()) == 1
    assert 'api_token=tip_test' in seen['url']

    ad = (await db_session.execute(select(AppDefinition).where(
        AppDefinition.source == 'qfeeds'))).scalars().one()
    assert ad.slug == 'malware'
    assert ad.category is None

    domains = set((await db_session.execute(
        select(AppDomain.domain).where(AppDomain.app_id == ad.id))).scalars())
    assert {'evil.com', 'bad.example'} <= domains


async def test_load_qfeeds_empty_body_keeps_existing_tier(db_session, monkeypatch):
    """A 200 serving an error page must never wipe the tier."""
    from sqlalchemy import select, func
    from backend.models import AppDefinition

    svc = ClassificationService()
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(
        "\n".join(f"evil{i}.example" for i in range(150))))
    await svc.load_qfeeds(db_session, _Row())

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns("Access forbidden."))
    assert await svc.load_qfeeds(db_session, _Row()) == -1

    assert await db_session.scalar(select(func.count()).select_from(AppDefinition).where(
        AppDefinition.source == 'qfeeds')) == 1


async def test_load_qfeeds_fetch_failure_keeps_existing_tier(db_session, monkeypatch):
    svc = ClassificationService()
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(None))
    assert await svc.load_qfeeds(db_session, _Row()) == -1


async def test_load_qfeeds_refuses_an_implausibly_small_feed(db_session, monkeypatch):
    """A 200 maintenance page containing one domain-shaped token must not
    replace the whole malware tier while reporting success."""
    from sqlalchemy import select, func
    from backend.models import AppDomain

    svc = ClassificationService()
    full = "\n".join(f"evil{i}.example" for i in range(200))
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(full))
    assert await svc.load_qfeeds(db_session, _Row()) == 1

    monkeypatch.setattr(svc, '_safe_fetch',
                        lambda url, what: _returns("www.qfeeds.com"))
    assert await svc.load_qfeeds(db_session, _Row()) == -1
    assert 'implausible' in (svc._last_fetch_error or '')

    assert await db_session.scalar(
        select(func.count()).select_from(AppDomain)) == 200


async def test_load_qfeeds_refuses_a_halved_feed(db_session, monkeypatch):
    from sqlalchemy import select, func
    from backend.models import AppDomain

    svc = ClassificationService()
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(
        "\n".join(f"evil{i}.example" for i in range(1000))))
    await svc.load_qfeeds(db_session, _Row())

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(
        "\n".join(f"evil{i}.example" for i in range(400))))
    assert await svc.load_qfeeds(db_session, _Row()) == -1
    assert await db_session.scalar(
        select(func.count()).select_from(AppDomain)) == 1000


async def test_first_load_accepts_a_feed_above_the_floor(db_session, monkeypatch):
    """The floor must not block a legitimate first fetch."""
    svc = ClassificationService()
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(
        "\n".join(f"evil{i}.example" for i in range(150))))
    assert await svc.load_qfeeds(db_session, _Row()) == 1


def test_describe_fetch_error_summarises_a_status_error():
    from backend.classification_service import _describe_fetch_error
    resp = httpx.Response(401, request=httpx.Request(
        'GET', 'https://172.67.73.170/api?api_token=tip_secret'))
    e = httpx.HTTPStatusError('boom', request=resp.request, response=resp)
    out = _describe_fetch_error(e)
    assert out == 'HTTP 401 Unauthorized'
    assert 'tip_secret' not in out
    assert '172.67' not in out


def test_describe_fetch_error_handles_timeout_and_transport():
    from backend.classification_service import _describe_fetch_error
    req = httpx.Request('GET', 'https://x/y')
    assert 'Timed out' in _describe_fetch_error(httpx.ConnectTimeout('t', request=req))
    assert 'Could not reach' in _describe_fetch_error(httpx.ConnectError('c', request=req))


def test_describe_fetch_error_passes_through_value_errors():
    from backend.classification_service import _describe_fetch_error
    assert _describe_fetch_error(ValueError('unsafe fetch target: loopback')) == \
        'unsafe fetch target: loopback'


async def test_singleton_refresh_records_a_scrubbed_last_error(db_session, monkeypatch):
    row = InsightSource(name='Q-Feeds', url=QFEEDS_FEED_URL, kind='qfeeds',
                        format='domains', enabled=True, api_key='tip_abc')
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()

    async def failing_fetch(url, what):
        svc._last_fetch_error = f"403 for {url}"
        return None

    monkeypatch.setattr(svc, '_safe_fetch', failing_fetch)
    await svc._refresh_singleton_row(db_session, row)

    assert row.last_status == 'error'
    assert row.last_error
    assert 'tip_abc' not in row.last_error
    assert 'api_token=***' in row.last_error


async def test_successful_refresh_clears_last_error(db_session, monkeypatch):
    row = InsightSource(name='Q-Feeds', url=QFEEDS_FEED_URL, kind='qfeeds',
                        format='domains', enabled=True, api_key='tip_abc',
                        last_error='stale failure')
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()
    feed = "\n".join(f"evil{i}.example" for i in range(150))
    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed))
    await svc._refresh_singleton_row(db_session, row)

    assert row.last_status == 'ok'
    assert row.last_error is None


async def test_last_error_is_bounded_to_the_column_width(db_session, monkeypatch):
    """last_error is VARCHAR(200); an unbounded httpx string would abort the commit."""
    row = InsightSource(name='Q-Feeds', url=QFEEDS_FEED_URL, kind='qfeeds',
                        format='domains', enabled=True, api_key='tip_abc')
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()

    async def failing_fetch(url, what):
        svc._last_fetch_error = 'x' * 5000
        return None

    monkeypatch.setattr(svc, '_safe_fetch', failing_fetch)
    await svc._refresh_singleton_row(db_session, row)
    await db_session.commit()

    assert len(row.last_error) == 200


def test_describe_fetch_error_ignores_the_upstream_reason_phrase():
    """reason_phrase is attacker-influenced text bound for a column readonly
    users can read, and _scrub_secrets only masks `api_token=`-prefixed values."""
    from backend.classification_service import _describe_fetch_error
    resp = httpx.Response(401, request=httpx.Request('GET', 'https://x/y'))
    resp.extensions['reason_phrase'] = b'leaked tip_fake_leaked_token'
    e = httpx.HTTPStatusError('boom', request=resp.request, response=resp)
    out = _describe_fetch_error(e)
    assert out == 'HTTP 401 Unauthorized'
    assert 'tip_fake_leaked' not in out


def test_describe_fetch_error_handles_an_unknown_status_code():
    from backend.classification_service import _describe_fetch_error
    resp = httpx.Response(599, request=httpx.Request('GET', 'https://x/y'))
    e = httpx.HTTPStatusError('boom', request=resp.request, response=resp)
    assert _describe_fetch_error(e) == 'HTTP 599'


async def test_v2fly_missing_map_does_not_inherit_another_sources_error(
        db_session, monkeypatch):
    """load_v2fly returns -1 without calling _safe_fetch, so a per-fetch reset
    alone would stamp it with the previous source's failure."""
    from backend.classification_service import ClassificationService
    from backend.constants import V2FLY_FEED_URL

    row = InsightSource(name='v2fly', url=V2FLY_FEED_URL, kind='v2fly',
                        format='yaml', enabled=True)
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()
    svc._last_fetch_error = "HTTP 401 Unauthorized"
    monkeypatch.setattr('backend.classification_service._load_v2fly_map', lambda: {})

    await svc._refresh_singleton_row(db_session, row)
    assert row.last_status == 'error'
    assert '401' not in (row.last_error or '')
    assert 'v2fly mapping' in row.last_error


async def test_repeated_halving_cannot_drain_the_tier(db_session, monkeypatch):
    """Anchoring the guard to the current count makes it a ratchet: each accepted
    refresh lowers the bar for the next, so serving exactly the maximum tolerated
    shrink every time walks the tier to nothing while every step reports ok."""
    from sqlalchemy import select, func
    from backend.models import AppDomain
    from backend.classification_service import ClassificationService

    row = InsightSource(name='Q-Feeds', url=QFEEDS_FEED_URL + '&t=ratchet',
                        kind='qfeeds', format='domains', enabled=True,
                        api_key='tip_abc')
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()

    def feed(n):
        return "\n".join(f"evil{i}.example" for i in range(n))

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed(4000)))
    assert await svc.load_qfeeds(db_session, row) == 1
    assert row.domain_count_high_water == 4000

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed(2000)))
    assert await svc.load_qfeeds(db_session, row) == -1

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed(1000)))
    assert await svc.load_qfeeds(db_session, row) == -1

    assert await db_session.scalar(
        select(func.count()).select_from(AppDomain)) == 4000


async def test_a_modest_shrink_is_still_accepted(db_session, monkeypatch):
    from backend.classification_service import ClassificationService

    row = InsightSource(name='Q-Feeds', url=QFEEDS_FEED_URL + '&t=shrink',
                        kind='qfeeds', format='domains', enabled=True,
                        api_key='tip_abc')
    db_session.add(row)
    await db_session.commit()

    svc = ClassificationService()

    def feed(n):
        return "\n".join(f"evil{i}.example" for i in range(n))

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed(4000)))
    await svc.load_qfeeds(db_session, row)

    monkeypatch.setattr(svc, '_safe_fetch', lambda url, what: _returns(feed(3600)))
    assert await svc.load_qfeeds(db_session, row) == 1
    assert row.domain_count_high_water == 4000
