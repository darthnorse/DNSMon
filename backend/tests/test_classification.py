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
