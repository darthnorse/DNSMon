"""Tests for the Q-Feeds threat source: secret scrubbing, URL building, loader."""

from backend.classification_service import _scrub_secrets


def test_scrubs_token_in_url():
    out = _scrub_secrets("Failed: https://api.qfeeds.com/api?api_token=tip_deadbeef")
    assert 'tip_deadbeef' not in out
    assert 'api_token=***' in out


def test_scrubs_token_with_trailing_params():
    out = _scrub_secrets("https://api.qfeeds.com/api?api_token=tip_deadbeef&feed_type=x")
    assert 'tip_deadbeef' not in out
    assert 'feed_type=x' in out


def test_scrubs_token_followed_by_whitespace():
    out = _scrub_secrets("url=https://a/b?api_token=tip_deadbeef and then some text")
    assert 'tip_deadbeef' not in out
    assert 'and then some text' in out


def test_scrubs_every_occurrence():
    out = _scrub_secrets("a?api_token=tok_one b?api_token=tok_two")
    assert 'tok_one' not in out and 'tok_two' not in out
    assert out.count('api_token=***') == 2


def test_message_without_token_is_unchanged():
    msg = "Failed to fetch v2fly list: connection reset"
    assert _scrub_secrets(msg) == msg


def test_handles_empty_string():
    assert _scrub_secrets('') == ''
