"""Tests for backend.classification.ThreatMatcher."""

from backend.classification import ThreatMatcher
from backend.constants import THREAT_SOURCES, SOURCE_PRECEDENCE, VALID_SOURCES


def _m(*domains: str) -> ThreatMatcher:
    tm = ThreatMatcher()
    for d in domains:
        tm.add(d, 'malware', 'qfeeds')
    return tm


def test_exact_hit():
    assert _m('evil.com').match('evil.com') == ('malware', 'qfeeds')


def test_subdomain_suffix_hit():
    assert _m('evil.com').match('cdn.evil.com') == ('malware', 'qfeeds')


def test_miss_returns_none():
    assert _m('evil.com').match('google.com') is None


def test_sibling_domain_is_not_a_hit():
    # notevil.com must not match against evil.com — suffix walk is label-wise.
    assert _m('evil.com').match('notevil.com') is None


def test_empty_matcher_misses():
    assert ThreatMatcher().match('evil.com') is None


def test_empty_fqdn_returns_none():
    assert _m('evil.com').match('') is None


def test_most_specific_suffix_wins():
    tm = ThreatMatcher()
    tm.add('evil.com', 'malware', 'qfeeds')
    tm.add('bad.evil.com', 'phishing', 'qfeeds')
    assert tm.match('x.bad.evil.com') == ('phishing', 'qfeeds')


def test_normalises_case_and_trailing_dot():
    tm = _m('Evil.COM.')
    assert tm.match('CDN.Evil.com.') == ('malware', 'qfeeds')
    assert len(tm) == 1


def test_add_ignores_blank_domain():
    tm = ThreatMatcher()
    tm.add('  ', 'malware', 'qfeeds')
    tm.add('.', 'malware', 'qfeeds')
    assert len(tm) == 0


def test_bare_tld_never_matches():
    # A single-label entry must not tag every domain under that TLD.
    tm = _m('com')
    assert tm.match('google.com') is None


def test_threat_sources_are_engine_only():
    for src in THREAT_SOURCES:
        assert src not in SOURCE_PRECEDENCE, f"{src} must not compete for the app slot"
        assert src not in VALID_SOURCES, f"{src} must not be settable on a manual definition"
