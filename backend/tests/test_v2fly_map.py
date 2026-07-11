import json
from pathlib import Path

MAP_PATH = Path(__file__).resolve().parents[1] / 'data' / 'v2fly_map.json'

ALLOWED_CATEGORIES = {
    'Streaming', 'Social', 'Gaming', 'Messaging', 'Shopping', 'AI',
    'Cloud / Hosting', 'Gambling', 'Privacy / VPN', 'Dating', 'Software', 'CDN',
    'Remote Access', 'Productivity', 'Development', 'Cloud Storage',
    'File Transfer', 'News', 'Finance', 'Smart Home', 'Education',
    'Health & Fitness', 'Travel', 'Adult', 'Torrents / File Sharing',
    'Automotive',
}
FORBIDDEN_EXACT = {'cn', 'private', 'gfw', 'greatfire'}
FORBIDDEN_PREFIXES = ('geolocation-', 'tld-', 'win-')
# Region-targeted lists are excluded; global "!cn" variants are allowed.
FORBIDDEN_SUFFIXES = ('-cn', '-ir', '-ru', '-jp', '-mm')


def _load():
    return json.loads(MAP_PATH.read_text())


def test_map_parses_and_is_nonempty():
    m = _load()
    assert isinstance(m, dict)
    assert len(m) >= 250


def test_every_entry_matches_schema():
    for key, entry in _load().items():
        assert isinstance(entry, dict), key
        assert entry.get('category') in ALLOWED_CATEGORIES, key
        if entry.get('category_only'):
            assert entry['category_only'] is True, key
            assert 'name' not in entry, key
        else:
            name = entry.get('name')
            assert isinstance(name, str) and 0 < len(name) <= 150, key
        assert set(entry) <= {'name', 'category', 'category_only'}, key


def test_no_forbidden_aggregate_keys():
    for key in _load():
        assert key not in FORBIDDEN_EXACT, key
        assert not key.startswith(FORBIDDEN_PREFIXES), key
        if not key.endswith('-!cn'):
            assert not key.endswith(FORBIDDEN_SUFFIXES), key


def test_no_conflicting_display_names():
    seen = {}
    for key, entry in _load().items():
        name = entry.get('name')
        if not name:
            continue
        if name in seen:
            assert seen[name] == entry['category'], (
                f"{name}: {seen[name]} vs {entry['category']}")
        seen[name] = entry['category']
