from backend.sync_service import (
    SYNC_CONFIG_DENYLIST,
    _build_target_patch,
    _is_denied,
    _nest,
    _syncable_leaves,
    _teleporter_import_options,
)


def _leaf(value, env_var=False):
    return {'value': value, 'flags': {'restart_dnsmasq': False, 'session_reset': False, 'env_var': env_var}}


def test_denylist_matches_path_and_descendants_only():
    assert _is_denied('dhcp')
    assert _is_denied('dhcp.active')
    assert _is_denied('webserver.api.pwhash')
    assert _is_denied('dns.reply.host.IPv4')
    assert _is_denied('dns.reply.blocking.IPv4')
    assert not _is_denied('dns.replyWhenBusy')
    assert not _is_denied('dns.interfaceX')
    assert not _is_denied('dns.rateLimit.count')


def test_raw_dnsmasq_passthrough_is_denied():
    assert _is_denied('misc.dnsmasq_lines')
    assert _is_denied('misc.etc_dnsmasq_d')
    assert not _is_denied('misc.privacylevel')


def test_pihole_teleporter_keeps_default_import_options():
    assert _teleporter_import_options('pihole') is None
    assert _teleporter_import_options('technitium') == {'deleteExistingFiles': True}


def test_target_patch_is_none_when_target_has_no_detailed_settings():
    source = {'dns.rateLimit.count': 10000}
    assert _build_target_patch(source, {}) is None
    assert _build_target_patch(source, {'dns': {'rateLimit': {'count': 1000}}}) is None


def test_syncable_leaves_includes_new_keys_and_drops_denied_and_null():
    config = {
        'dns': {
            'upstreams': ['192.168.1.1'],
            'rateLimit': {'count': 10000, 'interval': 60},
            'interface': 'eth0',
            'blocking': {'active': False, 'mode': 'NULL'},
            'someFutureKey': True,
            'localise': None,
        },
        'webserver': {'api': {'pwhash': 'secret'}},
        'misc': {'readOnly': False, 'privacylevel': 0},
    }
    assert _syncable_leaves(config) == {
        'dns.upstreams': ['192.168.1.1'],
        'dns.rateLimit.count': 10000,
        'dns.rateLimit.interval': 60,
        'dns.blocking.mode': 'NULL',
        'dns.someFutureKey': True,
        'misc.privacylevel': 0,
    }


def test_target_patch_sends_only_differing_known_unlocked_keys():
    source = {
        'dns.rateLimit.count': 10000,
        'dns.rateLimit.interval': 60,
        'dns.domain.name': 'lan',
        'dns.cache.size': 20000,
        'misc.privacylevel': 0,
    }
    target = {
        'dns': {
            'rateLimit': {'count': _leaf(1000), 'interval': _leaf(60)},
            'domain': _leaf('lan'),
            'cache': {'size': _leaf(10000, env_var=True)},
        },
        'misc': {'privacylevel': _leaf(2)},
    }
    assert _build_target_patch(source, target) == {
        'dns.rateLimit.count': 10000,
        'misc.privacylevel': 0,
    }


def test_target_patch_compares_lists_by_value():
    source = {'dns.upstreams': ['1.1.1.1', '9.9.9.9']}
    assert _build_target_patch(source, {'dns': {'upstreams': _leaf(['1.1.1.1', '9.9.9.9'])}}) == {}
    assert _build_target_patch(source, {'dns': {'upstreams': _leaf(['9.9.9.9', '1.1.1.1'])}}) == source


def test_nest_rebuilds_patch_body():
    assert _nest({'dns.rateLimit.count': 10000, 'dns.rateLimit.interval': 30, 'misc.privacylevel': 0}) == {
        'dns': {'rateLimit': {'count': 10000, 'interval': 30}},
        'misc': {'privacylevel': 0},
    }


def test_denylist_entries_are_dotted_paths():
    for entry in SYNC_CONFIG_DENYLIST:
        assert entry and not entry.startswith('.') and not entry.endswith('.')
