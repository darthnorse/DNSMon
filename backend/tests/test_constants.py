"""Tests for backend.constants — small enough to verify the pytest pipeline works."""

from backend.constants import (
    BLOCKED_STATUSES,
    BLOCKED_SQL_IN,
    CACHE_STATUSES,
    CACHE_SQL_IN,
    DEFAULT_INSIGHT_SOURCES,
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
    assert VALID_SOURCES == frozenset({"adguard", "supplement", "manual"})


def test_default_insight_sources_cover_all_kinds():
    kinds = {src["kind"] for src in DEFAULT_INSIGHT_SOURCES}
    assert kinds == {"adguard", "dnsmon", "hosts"}


def test_default_insight_seed_includes_hagezi_pro_plus():
    src = next(s for s in DEFAULT_INSIGHT_SOURCES if s["kind"] == "hosts")
    assert src["name"] == "Hagezi Pro.Plus"
    assert src["category"] == "Ads & Tracking"
    assert src["format"] == "domains"
    assert src["license"] == "GPL-3.0"
    assert src["url"].endswith("/domains/pro.plus.txt")
