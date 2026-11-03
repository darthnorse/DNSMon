import json

import httpx

from backend.adguard_client import ADGUARD_DNS_SYNC_DENYLIST, AdGuardHomeClient
from backend.sync_service import PiholeSyncService

DNS_INFO = {
    "upstream_dns": ["192.168.1.1"], "upstream_dns_file": "/opt/upstreams.txt",
    "bootstrap_dns": ["9.9.9.10"], "fallback_dns": [], "protection_enabled": True,
    "ratelimit": 0, "ratelimit_subnet_len_ipv4": 24, "ratelimit_subnet_len_ipv6": 56,
    "upstream_timeout": 10, "ratelimit_whitelist": [], "blocking_mode": "custom_ip",
    "edns_cs_enabled": False, "edns_cs_use_custom": False, "dnssec_enabled": True,
    "disable_ipv6": False, "upstream_mode": "", "blocked_response_ttl": 10,
    "cache_size": 4194304, "cache_ttl_min": 0, "cache_ttl_max": 0, "cache_enabled": True,
    "cache_optimistic": False, "resolve_clients": True, "use_private_ptr_resolvers": True,
    "local_ptr_upstreams": ["192.168.1.1"], "blocking_ipv4": "10.0.0.1", "blocking_ipv6": "",
    "protection_disabled_until": None, "edns_cs_custom_ip": "",
    "default_local_ptr_upstreams": ["192.168.1.2:53"],
}
QUERYLOG_CONFIG = {"ignored": [], "interval": 604800000, "enabled": True,
                   "ignored_enabled": False, "anonymize_client_ip": False}
STATS_CONFIG = {"ignored": [], "interval": 86400000, "enabled": True, "ignored_enabled": False}


class FakeAdGuard:
    def __init__(self, fail: frozenset[str] = frozenset()):
        self.fail = fail
        self.writes: dict[str, object] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in self.fail:
            return httpx.Response(500)
        if request.method in ("POST", "PUT"):
            self.writes[path] = json.loads(request.content) if request.content else None
            return httpx.Response(200)
        bodies = {
            "/control/filtering/status": {"enabled": True, "interval": 0, "user_rules": [],
                                          "filters": [], "whitelist_filters": []},
            "/control/dns_info": DNS_INFO,
            "/control/rewrite/list": [],
            "/control/clients": {"clients": []},
            "/control/querylog/config": QUERYLOG_CONFIG,
            "/control/stats/config": STATS_CONFIG,
        }
        return httpx.Response(200, json=bodies[path]) if path in bodies else httpx.Response(404)


def _client(fake: FakeAdGuard) -> AdGuardHomeClient:
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    return client


async def test_dns_settings_copy_everything_but_identity():
    cfg = await _client(FakeAdGuard()).get_config()

    assert cfg['dns']['local_ptr_upstreams'] == ['192.168.1.1']
    assert cfg['dns']['use_private_ptr_resolvers'] is True
    assert cfg['dns']['blocking_ipv4'] == '10.0.0.1'
    assert cfg['dns']['cache_optimistic'] is False
    assert not set(cfg['dns']) & ADGUARD_DNS_SYNC_DENYLIST


async def test_filter_update_interval_zero_survives():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard()

    await _client(target).patch_config(cfg)

    assert target.writes['/control/filtering/config'] == {'enabled': True, 'interval': 0}


async def test_querylog_and_stats_config_are_synced():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard()

    assert await _client(target).patch_config(cfg) is True

    assert target.writes['/control/querylog/config/update'] == QUERYLOG_CONFIG
    assert target.writes['/control/stats/config/update'] == STATS_CONFIG


async def test_querylog_config_failure_marks_sync_failed():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard(fail=frozenset({'/control/querylog/config/update'}))

    assert await _client(target).patch_config(cfg) is False


def _summary(querylog_config: dict) -> dict:
    return PiholeSyncService()._get_config_summary({'querylog_config': querylog_config}, 'adguard')


def test_sync_summary_reports_querylog_retention_in_hours():
    assert _summary(QUERYLOG_CONFIG)['querylog_retention_hours'] == 168
    assert _summary({**QUERYLOG_CONFIG, 'interval': 21_600_000})['querylog_retention_hours'] == 6


def test_sync_summary_omits_retention_when_query_log_disabled():
    assert 'querylog_retention_hours' not in _summary({**QUERYLOG_CONFIG, 'enabled': False})
