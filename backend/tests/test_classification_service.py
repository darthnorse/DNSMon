import json
import httpx
import pytest
from datetime import datetime, timezone

from sqlalchemy import select, func, delete
from backend.classification_service import ClassificationService, resolve_redirect_target, pin_url_to_ip
from backend.models import AppDefinition, AppDomain, DomainLabel, DomainStatsHourly, Query, InsightSource


async def test_load_dnsmon_bundled_populates_definitions(db_session):
    svc = ClassificationService()
    await svc.load_dnsmon_bundled(db_session)

    count = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.source == 'dnsmon')
    )
    assert count >= 10

    teamviewer = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'teamviewer', AppDefinition.source == 'dnsmon')
    )
    assert teamviewer.category == 'Remote Access'

    dom_count = await db_session.scalar(
        select(func.count()).select_from(AppDomain).where(AppDomain.app_id == teamviewer.id)
    )
    assert dom_count >= 1


async def test_load_dnsmon_bundled_is_idempotent(db_session):
    svc = ClassificationService()
    await svc.load_dnsmon_bundled(db_session)
    await svc.load_dnsmon_bundled(db_session)  # second run must not duplicate

    count = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.slug == 'teamviewer')
    )
    assert count == 1


async def _seed_query(db_session, domain):
    db_session.add(Query(
        timestamp=datetime.now(timezone.utc), domain=domain,
        client_ip='10.0.0.5', status='OK', server='s1', query_type='A',
    ))
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db_session.add(DomainStatsHourly(hour=hour, server='s1', domain=domain, total=1, blocked=0))
    await db_session.commit()


async def test_reclassify_labels_known_and_unknown(db_session):
    svc = ClassificationService()
    await svc.load_dnsmon_bundled(db_session)
    await _seed_query(db_session, 'files.github.com')
    await _seed_query(db_session, 'totally-unknown-host.test')

    await svc.reclassify(db_session)

    gh = await db_session.get(DomainLabel, 'files.github.com')
    assert gh.app_name == 'GitHub'
    assert gh.category == 'Development'
    assert gh.matched_source == 'dnsmon'

    unknown = await db_session.get(DomainLabel, 'totally-unknown-host.test')
    assert unknown is not None          # row stored so we don't re-attempt
    assert unknown.app_name is None     # honest 'uncategorized'


async def test_reclassify_is_idempotent_and_updates(db_session):
    svc = ClassificationService()
    await svc.load_dnsmon_bundled(db_session)
    await _seed_query(db_session, 'notion.so')
    await svc.reclassify(db_session)
    await svc.reclassify(db_session)  # rerun must not error or duplicate (PK domain)

    label = await db_session.get(DomainLabel, 'notion.so')
    assert label.app_name == 'Notion'


async def test_replace_source_preserves_disabled_flag(db_session):
    svc = ClassificationService()
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'foo', 'name': 'Foo', 'category': 'X', 'domains': [('foo.com', False)]},
    ])
    foo = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'foo', AppDefinition.source == 'adguard')
    )
    foo.enabled = False
    await db_session.commit()
    # refresh the source again (same slug)
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'foo', 'name': 'Foo', 'category': 'X', 'domains': [('foo.com', False)]},
    ])
    foo2 = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.slug == 'foo', AppDefinition.source == 'adguard')
    )
    assert foo2.enabled is False  # admin's disable survived the refresh


async def test_run_full_no_enabled_sources_clears_all(db_session):
    svc = ClassificationService()
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'a1', 'name': 'A1', 'category': 'X', 'domains': [('a1.com', False)]}])
    await svc._replace_source(db_session, 'dnsmon', [
        {'slug': 's1', 'name': 'S1', 'category': 'Y', 'domains': [('s1.com', False)]}])
    # Wipe any seeded insight_sources so run_full sees zero enabled rows.
    await db_session.execute(delete(InsightSource))
    await db_session.commit()
    # No insight_sources rows → every tier is cleared, no network.
    await svc.run_full()
    remaining = await db_session.scalar(select(func.count()).select_from(AppDefinition))
    assert remaining == 0


async def test_run_full_dispatches_dnsmon_row(db_session, monkeypatch):
    from backend.models import InsightSource
    await _allow_ssrf(monkeypatch)
    async def fake(self, url):
        return json.dumps([{"slug": "acme", "name": "Acme", "category": "Software",
                            "domains": ["acme.com"]}])
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)
    db_session.add(InsightSource(name="DNSMon", url="https://example.com/dnsmon.json",
                                 kind="dnsmon", format="json", enabled=True))
    await db_session.commit()

    await ClassificationService().run_full()
    acme = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "acme", AppDefinition.source == "dnsmon"))
    assert acme is not None and acme.name == "Acme"


async def _allow_ssrf(monkeypatch):
    async def ok(url):
        return None, None
    monkeypatch.setattr("backend.classification_service.async_resolve_url_safety", ok)


async def test_load_dnsmon_remote_success(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    async def fake(self, url):
        return json.dumps([{"slug": "acme", "name": "Acme", "category": "Software",
                            "domains": ["acme.com"]}])
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)

    svc = ClassificationService()
    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n == 1
    acme = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "acme", AppDefinition.source == "dnsmon"))
    assert acme.name == "Acme"
    assert acme.is_category_only is False


async def test_load_dnsmon_fetch_fail_keeps_existing(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    await svc._replace_source(db_session, "dnsmon", [
        {"slug": "old", "name": "Old", "category": "X", "domains": [("old.com", False)]}])
    async def boom(self, url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", boom)

    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n == -1
    cnt = await db_session.scalar(select(func.count()).select_from(AppDefinition).where(
        AppDefinition.source == "dnsmon"))
    assert cnt == 1  # existing tier preserved, not regressed to bundled


async def test_load_dnsmon_fetch_fail_first_boot_uses_bundled(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    async def boom(self, url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", boom)

    n = await svc.load_dnsmon(db_session, "https://example.com/dnsmon.json")
    assert n >= 10  # bundled dnsmon.json loaded on first boot
    tv = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "teamviewer", AppDefinition.source == "dnsmon"))
    assert tv is not None


async def test_refresh_and_reclassify_kind_only_touches_that_kind(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    # Pre-seed an adguard tier that a FULL refresh (no adguard row) would clear.
    await svc._replace_source(db_session, 'adguard', [
        {'slug': 'a1', 'name': 'A1', 'category': 'X', 'domains': [('a1.com', False)]}])
    async def fake(self, url):
        return json.dumps([{"slug": "acme", "name": "Acme", "category": "Software",
                            "domains": ["acme.com"]}])
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)
    db_session.add(InsightSource(name="DNSMon", url="https://example.com/dnsmon.json",
                                 kind="dnsmon", format="json", enabled=True))
    await db_session.commit()

    await svc.refresh_and_reclassify_kind('dnsmon')
    acme = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.source == 'dnsmon', AppDefinition.slug == 'acme'))
    assert acme is not None
    # The adguard tier was NOT touched (a full refresh would have cleared it).
    a1 = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.source == 'adguard', AppDefinition.slug == 'a1'))
    assert a1 is not None


def test_resolve_redirect_target_absolute():
    assert resolve_redirect_target(
        "https://github.com/a/releases/latest/download/f.yml",
        "https://objects.githubusercontent.com/x/y",
    ) == "https://objects.githubusercontent.com/x/y"


def test_resolve_redirect_target_relative():
    assert resolve_redirect_target(
        "https://example.com/a/b?x=1", "/c/d") == "https://example.com/c/d"


def _mock_http(monkeypatch, handler):
    real_client = httpx.AsyncClient
    def factory(**kwargs):
        kwargs['transport'] = httpx.MockTransport(handler)
        return real_client(**kwargs)
    monkeypatch.setattr("backend.classification_service.httpx.AsyncClient", factory)


async def test_fetch_follows_redirect(monkeypatch):
    await _allow_ssrf(monkeypatch)
    calls = []
    def handler(request):
        calls.append(str(request.url))
        if str(request.url) == "https://a.example/file":
            return httpx.Response(302, headers={"location": "https://b.example/real"})
        return httpx.Response(200, text="hello")
    _mock_http(monkeypatch, handler)

    text = await ClassificationService()._fetch_capped_text("https://a.example/file")
    assert text == "hello"
    assert calls == ["https://a.example/file", "https://b.example/real"]


async def test_fetch_rejects_unsafe_redirect_hop(monkeypatch):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/meta"})
    _mock_http(monkeypatch, handler)
    async def resolver(url):
        if "169.254" in url:
            return "link-local address", None
        return None, None
    monkeypatch.setattr(
        "backend.classification_service.async_resolve_url_safety", resolver)

    with pytest.raises(ValueError, match="unsafe fetch target"):
        await ClassificationService()._fetch_capped_text("https://a.example/file")
    assert calls == ["https://a.example/file"]  # the unsafe hop is never requested


def test_pin_url_to_ip_https():
    url, headers, ext = pin_url_to_ip("https://example.com/a/b?x=1", "93.184.216.34")
    assert url == "https://93.184.216.34/a/b?x=1"
    assert headers == {"Host": "example.com"}
    assert ext == {"sni_hostname": "example.com"}


def test_pin_url_to_ip_http_port_and_ipv6():
    url, headers, ext = pin_url_to_ip("http://example.com:8080/x", "2606:2800::1946")
    assert url == "http://[2606:2800::1946]:8080/x"
    assert headers == {"Host": "example.com:8080"}
    assert ext == {}


def test_pin_url_to_ip_none_is_passthrough():
    assert pin_url_to_ip("https://example.com/", None) == ("https://example.com/", {}, {})


async def test_fetch_connects_to_pinned_ip(monkeypatch):
    seen = []
    def handler(request):
        seen.append((request.url.host, request.headers.get("host")))
        return httpx.Response(200, text="pinned")
    _mock_http(monkeypatch, handler)
    async def resolver(url):
        return None, "93.184.216.34"
    monkeypatch.setattr(
        "backend.classification_service.async_resolve_url_safety", resolver)

    text = await ClassificationService()._fetch_capped_text("https://a.example/file")
    assert text == "pinned"
    assert seen == [("93.184.216.34", "a.example")]


async def test_fetch_caps_redirect_hops(monkeypatch):
    await _allow_ssrf(monkeypatch)
    def handler(request):
        return httpx.Response(302, headers={"location": "https://a.example/loop"})
    _mock_http(monkeypatch, handler)

    with pytest.raises(ValueError, match="too many redirects"):
        await ClassificationService()._fetch_capped_text("https://a.example/file")


V2FLY_SAMPLE_TEXT = '''lists:
  - name: netflix
    length: 2
    rules:
      - "domain:netflix.com"
      - "domain:nflxvideo.net"
  - name: not-in-map
    length: 1
    rules:
      - "domain:ignored.example"
'''


async def test_load_v2fly_remote_success(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    async def fake(self, url):
        return V2FLY_SAMPLE_TEXT
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)

    svc = ClassificationService()
    n = await svc.load_v2fly(db_session, "https://example.com/dlc.yml")
    assert n == 1  # only 'netflix' is in the real bundled mapping
    netflix = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "netflix", AppDefinition.source == "v2fly"))
    assert netflix.name == "Netflix"
    assert netflix.category == "Streaming"
    assert netflix.is_category_only is False
    dom_count = await db_session.scalar(select(func.count()).select_from(AppDomain)
                                        .where(AppDomain.app_id == netflix.id))
    assert dom_count == 2


async def test_load_v2fly_fetch_fail_keeps_existing(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    await svc._replace_source(db_session, "v2fly", [
        {"slug": "old", "name": "Old", "category": "X", "domains": [("old.com", False)]}])
    async def boom(self, url):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", boom)

    n = await svc.load_v2fly(db_session, "https://example.com/dlc.yml")
    assert n == -1
    cnt = await db_session.scalar(select(func.count()).select_from(AppDefinition).where(
        AppDefinition.source == "v2fly"))
    assert cnt == 1


async def test_load_v2fly_garbage_body_keeps_existing(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    svc = ClassificationService()
    await svc._replace_source(db_session, "v2fly", [
        {"slug": "old", "name": "Old", "category": "X", "domains": [("old.com", False)]}])
    async def fake(self, url):
        return "<html>rate limited</html>"
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)

    n = await svc.load_v2fly(db_session, "https://example.com/dlc.yml")
    assert n == -1
    cnt = await db_session.scalar(select(func.count()).select_from(AppDefinition).where(
        AppDefinition.source == "v2fly"))
    assert cnt == 1


async def test_run_full_dispatches_v2fly_row(db_session, monkeypatch):
    await _allow_ssrf(monkeypatch)
    async def fake(self, url):
        return V2FLY_SAMPLE_TEXT
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake)
    db_session.add(InsightSource(name="v2fly Community", url="https://example.com/dlc.yml",
                                 kind="v2fly", format="yaml", enabled=True))
    await db_session.commit()

    await ClassificationService().run_full()
    netflix = await db_session.scalar(select(AppDefinition).where(
        AppDefinition.slug == "netflix", AppDefinition.source == "v2fly"))
    assert netflix is not None
    src = await db_session.scalar(select(InsightSource).where(InsightSource.kind == "v2fly"))
    assert src.last_status == "ok"
    assert src.domain_count == 2
