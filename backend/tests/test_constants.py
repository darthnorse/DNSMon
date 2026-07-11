"""Tests for backend.constants — small enough to verify the pytest pipeline works."""

from backend.constants import (
    BLOCKED_STATUSES,
    BLOCKED_SQL_IN,
    CACHE_STATUSES,
    CACHE_SQL_IN,
    DEFAULT_INSIGHT_SOURCES,
    SINGLETON_SOURCE_KINDS,
    SOURCE_PRECEDENCE,
    VALID_SOURCES,
)


def test_status_sets_are_frozensets():
    # frozensets prevent accidental mutation at runtime; if someone converts
    # them to lists/sets, this regression test fires.
    assert isinstance(BLOCKED_STATUSES, frozenset)
    assert isinstance(CACHE_STATUSES, frozenset)


def test_blocked_and_cache_are_disjoint():
    assert BLOCKED_STATUSES.isdisjoint(CACHE_STATUSES)


def test_blocked_statuses_contain_known_codes():
    # Spot-check codes from both Pi-hole and AdGuard family.
    for code in ("GRAVITY", "GRAVITY_CNAME", "BLACKLIST", "BLOCKED",
                 "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA"):
        assert code in BLOCKED_STATUSES, f"{code} should be classified as blocked"


def test_sql_in_strings_are_quoted_sorted_csv():
    # Format: 'A','B','C' with members sorted lexicographically so the
    # generated SQL is stable across runs.
    expected_blocked = ",".join(f"'{s}'" for s in sorted(BLOCKED_STATUSES))
    assert BLOCKED_SQL_IN == expected_blocked
    expected_cache = ",".join(f"'{s}'" for s in sorted(CACHE_STATUSES))
    assert CACHE_SQL_IN == expected_cache
    # And no whitespace, no SQL keywords — they're meant to drop straight into IN(...)
    assert " " not in BLOCKED_SQL_IN
    assert BLOCKED_SQL_IN.startswith("'")
    assert BLOCKED_SQL_IN.endswith("'")


def test_blocklist_precedence_is_lowest():
    assert SOURCE_PRECEDENCE["blocklist"] == 0
    assert SOURCE_PRECEDENCE["blocklist"] < SOURCE_PRECEDENCE["adguard"]
    assert min(SOURCE_PRECEDENCE.values()) == SOURCE_PRECEDENCE["blocklist"]


def test_valid_sources_excludes_blocklist():
    assert "blocklist" not in VALID_SOURCES
    assert VALID_SOURCES == frozenset({"adguard", "dnsmon", "manual"})


def test_default_insight_sources_cover_all_kinds():
    kinds = {src["kind"] for src in DEFAULT_INSIGHT_SOURCES}
    assert kinds == {"adguard", "dnsmon", "hosts", "v2fly"}


def test_default_insight_seed_includes_hagezi_pro_plus():
    src = next(s for s in DEFAULT_INSIGHT_SOURCES if s["kind"] == "hosts")
    assert src["name"] == "Hagezi Pro.Plus"
    assert src["category"] == "Ads & Tracking"
    assert src["format"] == "domains"
    assert src["license"] == "GPL-3.0"
    assert src["url"].endswith("/domains/pro.plus.txt")


def test_precedence_order_is_blocklist_v2fly_adguard_dnsmon_manual():
    assert (SOURCE_PRECEDENCE["blocklist"] < SOURCE_PRECEDENCE["v2fly"]
            < SOURCE_PRECEDENCE["adguard"] < SOURCE_PRECEDENCE["dnsmon"]
            < SOURCE_PRECEDENCE["manual"])


def test_default_insight_seed_includes_v2fly():
    src = next(s for s in DEFAULT_INSIGHT_SOURCES if s["kind"] == "v2fly")
    assert src["name"] == "v2fly Community"
    assert src["url"] == ("https://github.com/v2fly/domain-list-community"
                          "/releases/latest/download/dlc.dat_plain.yml")
    assert src["format"] == "yaml"
    assert src["license"] == "MIT"
    assert src["category"] is None


def test_singleton_kinds_are_the_non_hosts_kinds():
    assert set(SINGLETON_SOURCE_KINDS) == {"adguard", "dnsmon", "v2fly"}
    assert "hosts" not in SINGLETON_SOURCE_KINDS
