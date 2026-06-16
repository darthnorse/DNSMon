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
