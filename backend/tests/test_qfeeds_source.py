"""Tests for the Q-Feeds threat source: secret scrubbing, URL building, loader."""

import httpx

from backend.classification_service import (
    ClassificationService,
    build_qfeeds_url,
    _scrub_secrets,
)
from backend.constants import QFEEDS_FEED_URL


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
