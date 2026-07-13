"""Tests for backend.alerts.AlertEngine."""

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from backend.alerts import AlertEngine
from backend.ingestion import IngestedQuery
from backend.models import AlertRule, Query


def _q(domain="example.com", status="OK", client_ip="192.168.1.10",
       client_hostname="laptop", server="pihole1",
       timestamp=None) -> IngestedQuery:
    return IngestedQuery(
        id=0,
        domain=domain,
        client_ip=client_ip,
        client_hostname=client_hostname,
        timestamp=timestamp or datetime.now(timezone.utc),
        query_type="A",
        status=status,
        server=server,
    )


def _rule(id=1, name="r", domain_pattern=None, client_ip_pattern=None,
          client_hostname_pattern=None, exclude_domains=None,
          exclude_client_ips=None,
          match_status="any", cooldown_minutes=5, enabled=True) -> AlertRule:
    return AlertRule(
        id=id, name=name,
        domain_pattern=domain_pattern,
        client_ip_pattern=client_ip_pattern,
        client_hostname_pattern=client_hostname_pattern,
        exclude_domains=exclude_domains,
        exclude_client_ips=exclude_client_ips,
        cooldown_minutes=cooldown_minutes,
        match_status=match_status,
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# Pattern normalization & compilation
# ---------------------------------------------------------------------------

def test_pattern_normalization_adds_wildcards_for_bare_keyword():
    e = AlertEngine()
    assert e._normalize_pattern("google") == "*google*"


def test_pattern_normalization_leaves_explicit_wildcards():
    e = AlertEngine()
    assert e._normalize_pattern("*.adult.*") == "*.adult.*"
    assert e._normalize_pattern("*google") == "*google"  # already has wildcard, untouched


def test_compile_patterns_redos_protection_too_many_wildcards():
    # >10 wildcards must be rejected (logged + skipped).
    e = AlertEngine()
    nasty = "*" * 11 + "x"
    compiled = e._compile_patterns(nasty)
    assert compiled == []


def test_compile_patterns_empty_returns_empty():
    assert AlertEngine()._compile_patterns(None) == []
    assert AlertEngine()._compile_patterns("") == []
    assert AlertEngine()._compile_patterns("   ") == []


def test_compile_patterns_comma_separated_produces_multiple():
    e = AlertEngine()
    compiled = e._compile_patterns("google, facebook")
    assert len(compiled) == 2


# ---------------------------------------------------------------------------
# Match logic (pure — no DB)
# ---------------------------------------------------------------------------

async def test_domain_pattern_matches():
    e = AlertEngine()
    rule = _rule(domain_pattern="google")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    matches = e._evaluate_query_against_rules(_q(domain="ads.google.com"), [rule], cached)
    assert matches == [rule.id]


async def test_domain_pattern_no_match():
    e = AlertEngine()
    rule = _rule(domain_pattern="google")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    matches = e._evaluate_query_against_rules(_q(domain="example.com"), [rule], cached)
    assert matches == []


async def test_client_ip_pattern_match():
    e = AlertEngine()
    rule = _rule(client_ip_pattern="192.168.1.*", domain_pattern=None)
    cached = {rule.id: await e._get_cached_patterns(rule)}
    matches = e._evaluate_query_against_rules(_q(client_ip="192.168.1.42"), [rule], cached)
    assert matches == [rule.id]


async def test_all_patterns_must_match_when_set():
    # Combined: rule has all three patterns. AND across them.
    e = AlertEngine()
    rule = _rule(domain_pattern="google", client_ip_pattern="192.168.1.*",
                 client_hostname_pattern="laptop")
    cached = {rule.id: await e._get_cached_patterns(rule)}

    # All three match
    assert e._evaluate_query_against_rules(
        _q(domain="ads.google.com", client_ip="192.168.1.10", client_hostname="my-laptop"),
        [rule], cached) == [rule.id]

    # Hostname mismatches → no match
    assert e._evaluate_query_against_rules(
        _q(domain="ads.google.com", client_ip="192.168.1.10", client_hostname="desktop"),
        [rule], cached) == []


async def test_exclusion_patterns_comma_separated():
    e = AlertEngine()
    rule = _rule(domain_pattern="ads", exclude_domains="trusted.com, partner.com")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    # Domain matches "ads" but is excluded → no match
    assert e._evaluate_query_against_rules(_q(domain="ads.partner.com"), [rule], cached) == []
    # Different domain, still matches
    assert e._evaluate_query_against_rules(_q(domain="ads.example.org"), [rule], cached) == [rule.id]


async def test_exclusion_patterns_legacy_json():
    # Backwards-compat: older rules may have JSON-array exclude_domains.
    import json
    e = AlertEngine()
    rule = _rule(domain_pattern="ads", exclude_domains=json.dumps(["trusted.com"]))
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(_q(domain="ads.trusted.com"), [rule], cached) == []


# ---------------------------------------------------------------------------
# match_status filter (the feature this whole arc was built around)
# ---------------------------------------------------------------------------

async def test_match_status_blocked_skips_allowed_queries():
    e = AlertEngine()
    rule = _rule(domain_pattern="google", match_status="blocked")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    # status="OK" is not in BLOCKED_STATUSES → treated as allowed → skipped
    assert e._evaluate_query_against_rules(
        _q(domain="google.com", status="OK"), [rule], cached) == []


async def test_match_status_blocked_matches_blocked_queries():
    e = AlertEngine()
    rule = _rule(domain_pattern="google", match_status="blocked")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    for blocked_status in ("GRAVITY", "BLOCKED", "REGEX", "EXTERNAL_BLOCKED_NULL"):
        assert e._evaluate_query_against_rules(
            _q(domain="google.com", status=blocked_status), [rule], cached) == [rule.id]


async def test_match_status_allowed_skips_blocked_queries():
    e = AlertEngine()
    rule = _rule(domain_pattern="google", match_status="allowed")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(domain="google.com", status="GRAVITY"), [rule], cached) == []


async def test_match_status_allowed_matches_unknown_status():
    # Unknown status codes (any string not in BLOCKED_STATUSES) count as allowed.
    e = AlertEngine()
    rule = _rule(domain_pattern="google", match_status="allowed")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(domain="google.com", status="WEIRD_FUTURE_STATUS"), [rule], cached) == [rule.id]


async def test_match_status_any_ignores_status():
    e = AlertEngine()
    rule = _rule(domain_pattern="google", match_status="any")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    for status in ("OK", "GRAVITY", "REGEX", "anything"):
        assert e._evaluate_query_against_rules(
            _q(domain="google.com", status=status), [rule], cached) == [rule.id]


# ---------------------------------------------------------------------------
# LRU cache eviction
# ---------------------------------------------------------------------------

async def test_pattern_cache_lru_eviction():
    e = AlertEngine()
    e._max_pattern_cache = 3  # shrink for the test
    rules = [_rule(id=i, domain_pattern=f"d{i}") for i in range(1, 5)]
    # Prime 4 rules → cache should hold only 3, oldest evicted.
    for r in rules:
        await e._get_cached_patterns(r)
    assert len(e._pattern_cache) == 3
    assert 1 not in e._pattern_cache  # oldest evicted
    assert {2, 3, 4} <= set(e._pattern_cache.keys())


async def test_pattern_cache_lru_promotes_on_reuse():
    e = AlertEngine()
    e._max_pattern_cache = 3
    rules = [_rule(id=i, domain_pattern=f"d{i}") for i in range(1, 4)]
    for r in rules:
        await e._get_cached_patterns(r)
    # Access rule 1 again → moves to MRU end.
    await e._get_cached_patterns(rules[0])
    # Now add rule 4 → rule 2 should be evicted (was now the LRU).
    await e._get_cached_patterns(_rule(id=4, domain_pattern="d4"))
    assert 2 not in e._pattern_cache
    assert 1 in e._pattern_cache


async def test_rule_lock_lru_eviction():
    e = AlertEngine()
    e._max_locks = 2
    await e._get_rule_lock(1)
    await e._get_rule_lock(2)
    await e._get_rule_lock(3)
    assert len(e._rule_locks) == 2
    assert 1 not in e._rule_locks


async def test_invalidate_cache_clears_specific_rule():
    e = AlertEngine()
    rule = _rule(domain_pattern="google")
    await e._get_cached_patterns(rule)
    assert rule.id in e._pattern_cache
    await e.invalidate_cache(rule.id)
    assert rule.id not in e._pattern_cache


async def test_invalidate_cache_clears_all():
    e = AlertEngine()
    for r in (_rule(id=1, domain_pattern="a"), _rule(id=2, domain_pattern="b")):
        await e._get_cached_patterns(r)
    await e.invalidate_cache()
    assert len(e._pattern_cache) == 0


# ---------------------------------------------------------------------------
# DB-bound: cooldown via try_record_alert
# ---------------------------------------------------------------------------

async def test_try_record_alert_respects_cooldown(db_session: AsyncSession):
    """First call records the alert; immediate second call returns None (cooldown)."""
    # Persist a query so query_id FK is satisfied
    q = Query(
        timestamp=datetime.now(timezone.utc),
        domain="ads.google.com",
        client_ip="192.168.1.10",
        server="pihole1",
        status="GRAVITY",
    )
    db_session.add(q)
    await db_session.commit()
    await db_session.refresh(q)

    e = AlertEngine()
    first = await e.try_record_alert(query_id=q.id, rule_id=1, cooldown_minutes=5)
    assert first is not None

    second = await e.try_record_alert(query_id=q.id, rule_id=1, cooldown_minutes=5)
    assert second is None  # in cooldown


async def test_try_record_alert_no_cooldown_always_records(db_session: AsyncSession):
    q = Query(
        timestamp=datetime.now(timezone.utc),
        domain="x", client_ip="1.1.1.1", server="s", status="OK",
    )
    db_session.add(q)
    await db_session.commit()
    await db_session.refresh(q)

    e = AlertEngine()
    a = await e.try_record_alert(query_id=q.id, rule_id=99, cooldown_minutes=0)
    b = await e.try_record_alert(query_id=q.id, rule_id=99, cooldown_minutes=0)
    assert a is not None and b is not None and a != b


async def test_evaluate_queries_empty_list():
    e = AlertEngine()
    assert await e.evaluate_queries([]) == []


# ---------------------------------------------------------------------------
# Client-IP exclusion matcher (pure)
# ---------------------------------------------------------------------------

def test_ip_exclude_exact_match_only():
    e = AlertEngine()
    m = e._compile_ip_excludes("10.0.0.5")
    assert m.matches("10.0.0.5")
    assert not m.matches("10.0.0.55")   # bare IP is exact, not substring
    assert not m.matches("110.0.0.5")


def test_ip_exclude_wildcard_match():
    e = AlertEngine()
    m = e._compile_ip_excludes("172.16.*")
    assert m.matches("172.16.4.9")
    assert not m.matches("172.17.0.1")


def test_ip_exclude_cidr_match():
    e = AlertEngine()
    m = e._compile_ip_excludes("192.168.1.0/24")
    assert m.matches("192.168.1.42")
    assert not m.matches("192.168.2.42")


def test_ip_exclude_ipv6_exact_and_cidr():
    e = AlertEngine()
    m = e._compile_ip_excludes("::1, fd00::/8")
    assert m.matches("::1")
    assert m.matches("fd12:3456::1")
    assert not m.matches("2001:db8::1")


def test_ip_exclude_mixed_list():
    e = AlertEngine()
    m = e._compile_ip_excludes("192.168.1.0/24, 10.0.0.5, 172.16.*")
    assert m.matches("192.168.1.7")
    assert m.matches("10.0.0.5")
    assert m.matches("172.16.9.9")
    assert not m.matches("8.8.8.8")


def test_ip_exclude_empty_is_noop():
    e = AlertEngine()
    assert e._compile_ip_excludes(None).is_empty
    assert e._compile_ip_excludes("").is_empty
    assert e._compile_ip_excludes("  ,  ").is_empty
    assert not e._compile_ip_excludes(None).matches("1.2.3.4")


def test_ip_exclude_malformed_entry_skipped_not_fatal():
    e = AlertEngine()
    # Bad CIDR is skipped; the valid exact entry still works (rule not disabled).
    m = e._compile_ip_excludes("not-an-ip/33, 10.0.0.5")
    assert m.matches("10.0.0.5")
    assert not m.matches("0.0.0.0")


def test_ip_exclude_unparseable_client_ip_no_match():
    e = AlertEngine()
    m = e._compile_ip_excludes("192.168.1.0/24")
    assert not m.matches("not-an-ip")
    assert not m.matches(None)
    assert not m.matches("")


# ---------------------------------------------------------------------------
# Client-IP exclusion — engine integration
# ---------------------------------------------------------------------------

async def test_exclude_client_ip_suppresses_match():
    e = AlertEngine()
    rule = _rule(domain_pattern="ads", exclude_client_ips="10.0.0.5")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(domain="ads.example.com", client_ip="10.0.0.5"), [rule], cached) == []
    assert e._evaluate_query_against_rules(
        _q(domain="ads.example.com", client_ip="10.0.0.6"), [rule], cached) == [rule.id]


async def test_exclude_client_ip_cidr_suppresses():
    e = AlertEngine()
    rule = _rule(domain_pattern="ads", exclude_client_ips="192.168.1.0/24")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(domain="ads.x.com", client_ip="192.168.1.99"), [rule], cached) == []
    assert e._evaluate_query_against_rules(
        _q(domain="ads.x.com", client_ip="192.168.2.99"), [rule], cached) == [rule.id]


async def test_exclude_client_ip_overrides_include_pattern():
    # Include client_ip_pattern matches, but the exclusion wins.
    e = AlertEngine()
    rule = _rule(domain_pattern=None, client_ip_pattern="10.0.0.*",
                 exclude_client_ips="10.0.0.5")
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(client_ip="10.0.0.5"), [rule], cached) == []
    assert e._evaluate_query_against_rules(
        _q(client_ip="10.0.0.9"), [rule], cached) == [rule.id]


async def test_exclude_client_ip_none_is_noop():
    e = AlertEngine()
    rule = _rule(domain_pattern="ads", exclude_client_ips=None)
    cached = {rule.id: await e._get_cached_patterns(rule)}
    assert e._evaluate_query_against_rules(
        _q(domain="ads.example.com", client_ip="10.0.0.5"), [rule], cached) == [rule.id]
