import pytest
from sqlalchemy import select, func, delete
from backend.classification import parse_adguard_rule, parse_blocklist_line, DomainMatcher, MatchResult
from backend.classification_service import (
    ClassificationService, _blocklist_slug, build_blocklist_defs,
    parse_blocklist_text, parse_dnsmon_entries,
)
from backend.models import AppDefinition, AppDomain, InsightSource
from backend.constants import (
    CLASSIFICATION_FEED_URL,
    SOURCE_PRECEDENCE,
    ADGUARD_GROUP_TO_CATEGORY,
)


def test_source_precedence_orders_manual_highest():
    assert SOURCE_PRECEDENCE['manual'] > SOURCE_PRECEDENCE['supplement']
    assert SOURCE_PRECEDENCE['supplement'] > SOURCE_PRECEDENCE['adguard']


def test_feed_url_is_adguard_https():
    assert CLASSIFICATION_FEED_URL.startswith('https://')
    assert 'AdguardTeam/HostlistsRegistry' in CLASSIFICATION_FEED_URL


def test_group_remap_covers_ai():
    assert ADGUARD_GROUP_TO_CATEGORY['ai'] == 'AI'


def test_parse_simple_rule():
    assert parse_adguard_rule('||chatgpt.com^') == ('chatgpt.com', False)


def test_parse_strips_modifier():
    assert parse_adguard_rule('||amazonaws.com^$dnstype=~CNAME') == ('amazonaws.com', False)


def test_parse_flags_wildcard():
    assert parse_adguard_rule('||awsdns-*.com^') == ('awsdns-*.com', True)


def test_parse_trims_internal_whitespace():
    assert parse_adguard_rule('||slack-files.com ^') == ('slack-files.com', False)


def test_parse_lowercases():
    assert parse_adguard_rule('||ChatGPT.COM^') == ('chatgpt.com', False)


def test_parse_rejects_non_domain_rules():
    assert parse_adguard_rule('/some-regex/') is None
    assert parse_adguard_rule('@@||allow.com^') is None
    assert parse_adguard_rule('') is None
    assert parse_adguard_rule('||^') is None


def _matcher():
    m = DomainMatcher()
    m.add('netflix.com', app_id=1, app_name='Netflix', category='Streaming', source='adguard')
    m.add('example.com', app_id=2, app_name='ExampleFeed', category='Software', source='adguard')
    return m


def test_matches_subdomain_by_suffix():
    m = _matcher()
    hit = m.match('ipv4-c001.nflxvideo.netflix.com')
    assert hit.app_name == 'Netflix'


def test_no_match_returns_none():
    assert _matcher().match('unknown-domain.test') is None


def test_manual_overrides_adguard_at_same_domain():
    m = _matcher()
    m.add('example.com', app_id=9, app_name='My Override', category='Productivity', source='manual')
    hit = m.match('www.example.com')
    assert hit.app_name == 'My Override'
    assert hit.matched_source == 'manual'


def test_manual_less_specific_still_wins_over_adguard():
    # User intent: manual/supplement always override the feed.
    m = DomainMatcher()
    m.add('cdn.vendor.com', app_id=1, app_name='VendorCDN', category='CDN', source='adguard')
    m.add('vendor.com', app_id=2, app_name='Vendor (manual)', category='Software', source='manual')
    hit = m.match('cdn.vendor.com')
    assert hit.matched_source == 'manual'


def test_more_specific_wins_within_same_source():
    m = DomainMatcher()
    m.add('vendor.com', app_id=1, app_name='Vendor', category='Software', source='adguard')
    m.add('mail.vendor.com', app_id=2, app_name='VendorMail', category='Software', source='adguard')
    assert m.match('mail.vendor.com').app_name == 'VendorMail'


@pytest.mark.parametrize("line,expected", [
    ("0.0.0.0 ads.example.com", "ads.example.com"),
    ("0.0.0.0 ads.example.com # blocked", "ads.example.com"),
    ("127.0.0.1 track.example.com", "track.example.com"),
    ("plain.example.com", "plain.example.com"),
    ("*.wild.example.com", "wild.example.com"),
    ("||adguard.example.com^", "adguard.example.com"),
    ("UPPER.Example.COM", "upper.example.com"),
    ("  spaced.example.com  ", "spaced.example.com"),
    ("# a comment", None),
    ("! adblock comment", None),
    ("", None),
    ("   ", None),
    ("0.0.0.0 localhost", None),
    ("0.0.0.0", None),
    ("notadomain", None),
    ("bad_*_glob.com", None),
])
def test_parse_blocklist_line(line, expected):
    assert parse_blocklist_line(line) == expected


def test_parse_blocklist_text_dedups():
    s = parse_blocklist_text("0.0.0.0 a.com\nb.com\na.com\n# c\n")
    assert s == {"a.com", "b.com"}


def test_build_blocklist_defs_groups_and_sorts():
    defs = build_blocklist_defs([
        ("Ads & Tracking", "0.0.0.0 a.com\nb.com\na.com\n"),
        ("Ads & Tracking", "c.com\n"),
    ])
    assert len(defs) == 1
    d = defs[0]
    assert d["slug"] == "blocklist-ads-tracking"
    assert d["name"] == "Ads & Tracking"
    assert d["category"] == "Ads & Tracking"
    assert [dom for dom, _ in d["domains"]] == ["a.com", "b.com", "c.com"]
    assert all(wild is False for _, wild in d["domains"])


def test_build_blocklist_defs_skips_empty_category():
    defs = build_blocklist_defs([("Empty", "# only comments\n")])
    assert defs == []


@pytest.mark.parametrize("category,expected", [
    ("Ads & Tracking", "blocklist-ads-tracking"),
    ("Malware", "blocklist-malware"),
    ("", "blocklist-misc"),
    ("---", "blocklist-misc"),
    ("!!!", "blocklist-misc"),
])
def test_blocklist_slug(category, expected):
    assert _blocklist_slug(category) == expected


async def test_blocklist_match_is_category_only(db_session):
    ad = AppDefinition(slug="blocklist-ads-tracking", name="Ads & Tracking",
                       category="Ads & Tracking", source="blocklist", enabled=True,
                       is_category_only=True)
    db_session.add(ad)
    await db_session.flush()
    db_session.add(AppDomain(domain="tracker.com", app_id=ad.id, is_wildcard=False))
    await db_session.commit()

    matcher = await ClassificationService().build_matcher(db_session)
    hit = matcher.match("sub.tracker.com")
    assert hit is not None
    assert hit.app_id == ad.id
    assert hit.app_name is None
    assert hit.category == "Ads & Tracking"
    assert hit.matched_source == "blocklist"


async def test_real_app_beats_blocklist(db_session):
    block = AppDefinition(slug="blocklist-ads-tracking", name="Ads & Tracking",
                          category="Ads & Tracking", source="blocklist", enabled=True,
                          is_category_only=True)
    app = AppDefinition(slug="acme", name="Acme", category="Software",
                        source="manual", enabled=True)
    db_session.add_all([block, app])
    await db_session.flush()
    db_session.add(AppDomain(domain="acme.com", app_id=block.id, is_wildcard=False))
    db_session.add(AppDomain(domain="acme.com", app_id=app.id, is_wildcard=False))
    await db_session.commit()

    matcher = await ClassificationService().build_matcher(db_session)
    hit = matcher.match("acme.com")
    assert hit.app_name == "Acme"
    assert hit.category == "Software"
    assert hit.matched_source == "manual"


async def test_build_matcher_uses_is_category_only_flag(db_session):
    # A definition flagged is_category_only renders app_name=None regardless of source.
    ad = AppDefinition(slug="dnsmon-cat-cdn", name="CDN", category="CDN",
                       source="supplement", enabled=True, is_category_only=True)
    db_session.add(ad)
    await db_session.flush()
    db_session.add(AppDomain(domain="cdn.example.com", app_id=ad.id, is_wildcard=False))
    await db_session.commit()

    matcher = await ClassificationService().build_matcher(db_session)
    hit = matcher.match("img.cdn.example.com")
    assert hit is not None
    assert hit.app_name is None          # category bucket, not an app
    assert hit.category == "CDN"
    assert hit.matched_source == "supplement"


async def test_replace_source_blocklist_batches(db_session):
    svc = ClassificationService()
    defs = [{
        "slug": "blocklist-ads-tracking", "name": "Ads & Tracking",
        "category": "Ads & Tracking", "is_category_only": True,
        "domains": [(f"d{i}.com", False) for i in range(10500)],
    }]
    n = await svc._replace_source(db_session, "blocklist", defs)
    assert n == 1

    ad = await db_session.scalar(
        select(AppDefinition).where(AppDefinition.source == "blocklist"))
    assert ad.is_category_only is True  # _replace_source persisted the flag
    cnt = await db_session.scalar(
        select(func.count()).select_from(AppDomain).where(AppDomain.app_id == ad.id))
    assert cnt == 10500


async def test_refresh_blocklists_no_enabled_clears(db_session):
    svc = ClassificationService()
    await svc._replace_source(db_session, "blocklist", [{
        "slug": "blocklist-ads-tracking", "name": "Ads & Tracking",
        "category": "Ads & Tracking", "domains": [("x.com", False)],
    }])
    # Ensure no enabled InsightSource rows exist (seed may have run).
    await db_session.execute(delete(InsightSource))
    await db_session.commit()
    # No enabled InsightSource rows exist → tier should be cleared.
    n = await svc.refresh_blocklists(db_session)
    assert n == 0
    cnt = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.source == "blocklist"))
    assert cnt == 0


def test_app_beats_category_bucket_from_higher_source():
    # A category-only bucket (app_name=None) from a HIGHER-ranked source must NOT
    # shadow a real app from a lower-ranked source. Apps win across the board.
    m = DomainMatcher()
    m.add('foo.com', app_id=1, app_name=None, category='Ads & Tracking', source='supplement')
    m.add('foo.com', app_id=2, app_name='FooApp', category='Software', source='adguard')
    hit = m.match('foo.com')
    assert hit.app_name == 'FooApp'


def test_app_beats_category_bucket_across_suffixes():
    m = DomainMatcher()
    m.add('sub.foo.com', app_id=1, app_name=None, category='Ads & Tracking', source='supplement')
    m.add('foo.com', app_id=2, app_name='FooApp', category='Software', source='adguard')
    assert m.match('sub.foo.com').app_name == 'FooApp'


def test_category_bucket_higher_source_wins_over_lower_bucket():
    m = DomainMatcher()
    m.add('bar.com', app_id=1, app_name=None, category='Ads & Tracking', source='blocklist')
    m.add('bar.com', app_id=2, app_name=None, category='Telemetry', source='supplement')
    assert m.match('bar.com').category == 'Telemetry'


async def test_refresh_blocklists_empty_body_keeps_tier(db_session, monkeypatch):
    """A 200 that parses to 0 domains must NOT wipe the existing tier."""
    svc = ClassificationService()
    await svc._replace_source(db_session, "blocklist", [{
        "slug": "blocklist-ads-tracking", "name": "Ads & Tracking",
        "category": "Ads & Tracking", "domains": [("x.com", False)],
    }])
    await db_session.execute(delete(InsightSource))
    db_session.add(InsightSource(name="Bad", url="https://e.com/bad.txt", kind="hosts",
                                 category="Ads & Tracking", format="domains", enabled=True))
    await db_session.commit()

    async def fake_fetch(self, url):  # 200 with no parseable domains
        return "# upstream error page\nNot Found\n"
    monkeypatch.setattr(ClassificationService, "_fetch_capped_text", fake_fetch)

    n = await svc.refresh_blocklists(db_session)
    assert n == -1  # nothing yielded → keep existing tier
    cnt = await db_session.scalar(
        select(func.count()).select_from(AppDefinition).where(AppDefinition.source == "blocklist"))
    assert cnt == 1  # prior "Ads & Tracking" def preserved
    src = (await db_session.execute(
        select(InsightSource).where(InsightSource.name == "Bad"))).scalar_one()
    assert src.last_status == "error"


def test_parse_dnsmon_app_entry():
    defs = parse_dnsmon_entries([
        {"slug": "notion", "name": "Notion", "category": "Productivity",
         "domains": ["Notion.so", "notion.com"]},
    ])
    assert len(defs) == 1
    d = defs[0]
    assert d["slug"] == "notion"
    assert d["name"] == "Notion"
    assert d["category"] == "Productivity"
    assert d["is_category_only"] is False
    assert ("notion.so", False) in d["domains"]   # lowercased


def test_parse_dnsmon_category_bucket_entry():
    defs = parse_dnsmon_entries([{"category": "CDN", "domains": ["cdn.example.com"]}])
    assert len(defs) == 1
    d = defs[0]
    assert d["is_category_only"] is True
    assert d["slug"] == "dnsmon-cat-cdn"
    assert d["name"] == "CDN"          # name falls back to the category for display


def test_parse_dnsmon_skips_no_domains():
    assert parse_dnsmon_entries([{"name": "X", "category": "Y", "domains": []}]) == []


def test_parse_dnsmon_skips_no_name_no_category():
    assert parse_dnsmon_entries([{"domains": ["a.com"]}]) == []
