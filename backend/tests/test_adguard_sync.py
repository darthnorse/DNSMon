import json

import httpx
import pytest

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
BLOCKED_SERVICES = {"schedule": {"time_zone": "Local"}, "ids": ["icloud_private_relay"]}
SAFESEARCH = {"enabled": True, "bing": True, "duckduckgo": False, "ecosia": True, "google": True,
              "pixabay": True, "yandex": False, "youtube": True}


class FakeAdGuard:
    def __init__(self, fail: frozenset[str] = frozenset(), overrides: dict | None = None):
        self.fail = fail
        self.overrides = overrides or {}
        self.writes: dict[str, object] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in self.fail:
            return httpx.Response(500)
        if request.method in ("POST", "PUT"):
            if request.headers.get("content-type") != "application/json":
                return httpx.Response(415)
            self.writes[path] = json.loads(request.content)
            return httpx.Response(200)
        bodies = {
            "/control/filtering/status": {"enabled": True, "interval": 0, "user_rules": [],
                                          "filters": [], "whitelist_filters": []},
            "/control/dns_info": DNS_INFO,
            "/control/rewrite/list": [],
            "/control/clients": {"clients": []},
            "/control/querylog/config": QUERYLOG_CONFIG,
            "/control/stats/config": STATS_CONFIG,
            "/control/blocked_services/get": BLOCKED_SERVICES,
            "/control/safesearch/status": SAFESEARCH,
            "/control/safebrowsing/status": {"enabled": True},
            "/control/parental/status": {"enabled": False},
        }
        bodies.update(self.overrides)
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


async def test_blocked_services_sync_with_their_schedule():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard()

    assert await _client(target).patch_config(cfg) is True

    assert target.writes['/control/blocked_services/update'] == BLOCKED_SERVICES


async def test_clearing_blocked_services_on_the_source_clears_the_target():
    target = FakeAdGuard()

    await _client(target).patch_config({'blocked_services': {'schedule': {'time_zone': 'Local'}, 'ids': []}})

    assert target.writes['/control/blocked_services/update']['ids'] == []


async def test_safe_search_syncs_every_engine():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard()

    await _client(target).patch_config(cfg)

    assert target.writes['/control/safesearch/settings'] == SAFESEARCH


async def test_safe_browsing_and_parental_control_follow_the_source_either_way():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard()

    await _client(target).patch_config(cfg)

    assert '/control/safebrowsing/enable' in target.writes
    assert '/control/parental/disable' in target.writes
    assert '/control/safebrowsing/disable' not in target.writes
    assert '/control/parental/enable' not in target.writes


@pytest.mark.parametrize("status", [{}, {"enabled": None}, {"enabled": "false"}, []])
async def test_toggle_status_without_a_real_answer_leaves_targets_alone(status):
    source = FakeAdGuard(overrides={"/control/safebrowsing/status": status})
    cfg = await _client(source).get_config()
    target = FakeAdGuard()

    await _client(target).patch_config(cfg)

    assert 'safebrowsing_enabled' not in cfg
    assert '/control/safebrowsing/disable' not in target.writes
    assert '/control/safebrowsing/enable' not in target.writes


async def test_setting_the_source_could_not_report_is_left_alone():
    source = FakeAdGuard(fail=frozenset({"/control/blocked_services/get", "/control/parental/status"}))
    cfg = await _client(source).get_config()
    target = FakeAdGuard()

    await _client(target).patch_config(cfg)

    assert 'blocked_services' not in cfg
    assert 'parental_enabled' not in cfg
    assert '/control/blocked_services/update' not in target.writes
    assert '/control/parental/enable' not in target.writes
    assert '/control/parental/disable' not in target.writes


async def test_failed_blocked_services_write_marks_sync_failed():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard(fail=frozenset({"/control/blocked_services/update"}))

    assert await _client(target).patch_config(cfg) is False


async def test_failed_toggle_write_marks_sync_failed():
    cfg = await _client(FakeAdGuard()).get_config()
    target = FakeAdGuard(fail=frozenset({"/control/safebrowsing/enable"}))

    assert await _client(target).patch_config(cfg) is False


def test_sync_summary_omits_blocked_services_the_source_could_not_report():
    summary = PiholeSyncService()._get_config_summary({'user_rules': []}, 'adguard')

    assert 'blocked_services' not in summary


def test_sync_summary_counts_blocked_services():
    summary = PiholeSyncService()._get_config_summary({'blocked_services': BLOCKED_SERVICES}, 'adguard')

    assert summary['blocked_services'] == 1


def test_sync_summary_reports_querylog_retention_in_hours():
    assert _summary(QUERYLOG_CONFIG)['querylog_retention_hours'] == 168
    assert _summary({**QUERYLOG_CONFIG, 'interval': 21_600_000})['querylog_retention_hours'] == 6


def test_sync_summary_omits_retention_when_query_log_disabled():
    assert 'querylog_retention_hours' not in _summary({**QUERYLOG_CONFIG, 'enabled': False})
