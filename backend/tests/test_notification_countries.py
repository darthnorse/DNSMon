"""Matched countries and answer IPs in batch alert notifications."""

from datetime import datetime, timezone

import pytest

from backend import notifications
from backend.schemas import GeoInfo
from backend.ingestion import IngestedQuery
from backend.models import AlertRule
from backend.notifications import AlertContext, NotificationService, render_template


class _FakeGeoIP:
    def __init__(self, countries):
        self.countries = countries

    def lookup(self, ip):
        code = self.countries.get(ip)
        return GeoInfo(country=code) if code else None


@pytest.fixture
def geoip(monkeypatch):
    fake = _FakeGeoIP({"1.2.3.4": "CN", "5.6.7.8": "US", "9.9.9.9": "RU"})
    monkeypatch.setattr(notifications, "get_geoip", lambda: fake)
    return fake


class AlertChannel:
    def __init__(self, config):
        self.config = config


def _q(domain, ips, countries, client="laptop"):
    return IngestedQuery(
        id=0, domain=domain, client_ip="10.0.0.1", client_hostname=client,
        timestamp=datetime.now(timezone.utc), query_type="A", status="OK",
        server="s", answer_ips=ips, answer_countries=countries)


def _rule(match_countries):
    return AlertRule(id=1, name="geo", match_countries=match_countries)


def _context(queries, rule, dedupe=False):
    service = NotificationService()
    return service._build_batch_context(queries, rule, service._matches_per_query(queries, rule), dedupe=dedupe)


def test_query_list_shows_matched_country_and_ip(geoip):
    ctx = _context(
        [_q("example.cn", ["1.2.3.4", "5.6.7.8"], ["CN", "US"])], _rule("CN,RU"))
    assert ctx.query_list == "example.cn - laptop (CN: 1.2.3.4)"
    assert ctx.countries == "CN"
    assert ctx.answer_ips == "1.2.3.4"


def test_batch_unions_countries_and_ips_without_duplicates(geoip):
    queries = [_q("a.cn", ["1.2.3.4"], ["CN"]), _q("a.cn", ["1.2.3.4"], ["CN"]),
               _q("b.ru", ["9.9.9.9"], ["RU"])]
    for dedupe in (False, True):
        ctx = _context(queries, _rule("RU,CN"), dedupe=dedupe)
        assert ctx.countries == "CN, RU"
        assert ctx.answer_ips == "1.2.3.4, 9.9.9.9"
    assert ctx.query_list.splitlines() == ["a.cn - laptop (CN: 1.2.3.4)", "b.ru - laptop (RU: 9.9.9.9)"]


def test_unresolvable_ips_still_show_the_country(geoip):
    ctx = _context(
        [_q("gone.cn", ["8.8.4.4"], ["CN"])], _rule("CN"))
    assert ctx.query_list == "gone.cn - laptop (CN)"
    assert ctx.countries == "CN"
    assert ctx.answer_ips == ""


def test_rules_without_match_countries_keep_plain_lines(geoip):
    ctx = _context(
        [_q("example.cn", ["1.2.3.4"], ["CN"])], _rule(None))
    assert ctx.query_list == "example.cn - laptop"
    assert ctx.countries == "" and ctx.answer_ips == ""


def test_template_renders_countries_and_answer_ips():
    ctx = AlertContext(domain="d", client_ip="c", client_hostname=None, rule_name="r",
                       server_name="s", timestamp="", query_type="A", status="OK", count=1,
                       countries="CN", answer_ips="1.2.3.4")
    assert render_template("{countries} {answer_ips}", ctx) == "CN 1.2.3.4"


def test_dedupe_line_carries_every_match_of_a_repeated_pair(geoip):
    queries = [_q("a.com", ["1.2.3.4"], ["CN"]), _q("a.com", ["9.9.9.9"], ["RU"]),
               _q("a.com", ["1.2.3.4"], ["CN"])]
    ctx = _context(queries, _rule("CN,RU"), dedupe=True)
    assert ctx.query_list == "a.com - laptop (CN: 1.2.3.4; RU: 9.9.9.9)"


def test_repeated_answer_ip_is_listed_and_looked_up_once(geoip, monkeypatch):
    lookups = []
    real = geoip.lookup
    monkeypatch.setattr(geoip, "lookup", lambda ip: (lookups.append(ip), real(ip))[1])
    ctx = _context(
        [_q("a.cn", ["1.2.3.4", "1.2.3.4"], ["CN"])], _rule("CN"))
    assert ctx.answer_ips == "1.2.3.4"
    assert lookups == ["1.2.3.4"]


async def test_send_batch_alert_looks_up_answers_once_across_channels(geoip, monkeypatch):
    lookups = []
    real = geoip.lookup
    monkeypatch.setattr(geoip, "lookup", lambda ip: (lookups.append(ip), real(ip))[1])
    contexts = []

    async def two_channels(build_context, _label):
        contexts.extend(build_context(AlertChannel(config=config)) for config in ({}, {"dedupe_domains": True}))
        return {}

    service = NotificationService()
    monkeypatch.setattr(service, "_send_to_all_channels", two_channels)
    await service.send_batch_alert([_q("a.cn", ["1.2.3.4"], ["CN"])], _rule("CN"))

    assert lookups == ["1.2.3.4"]
    assert [c.answer_ips for c in contexts] == ["1.2.3.4", "1.2.3.4"]
