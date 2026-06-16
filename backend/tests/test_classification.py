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


from backend.classification import parse_adguard_rule


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


from backend.classification import DomainMatcher


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
