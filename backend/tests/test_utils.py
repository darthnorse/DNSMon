"""Tests for backend.utils."""

from datetime import datetime, timezone
from unittest.mock import patch

from backend.utils import (
    async_validate_url_safety,
    ensure_utc,
    validate_url_safety,
)


def test_ensure_utc_none_returns_none():
    assert ensure_utc(None) is None


def test_ensure_utc_naive_datetime_is_coerced_to_utc_iso():
    naive = datetime(2026, 5, 17, 12, 0, 0)
    result = ensure_utc(naive)
    assert result is not None
    assert result == "2026-05-17T12:00:00+00:00"


def test_ensure_utc_aware_datetime_passes_through():
    aware = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    result = ensure_utc(aware)
    assert result == "2026-05-17T12:00:00+00:00"


def test_validate_url_safety_rejects_loopback():
    # 127.0.0.1 must be blocked — SSRF protection for outbound HTTP from this app.
    with patch("backend.utils.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(0, 0, 0, "", ("127.0.0.1", 0))]
        result = validate_url_safety("http://attacker.example/")
        assert result is not None
        assert "blocked" in result.lower()


def test_validate_url_safety_rejects_link_local():
    # 169.254.169.254 is the cloud metadata endpoint — must be blocked.
    with patch("backend.utils.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(0, 0, 0, "", ("169.254.169.254", 0))]
        result = validate_url_safety("http://attacker.example/")
        assert result is not None
        assert "blocked" in result.lower()


def test_validate_url_safety_allows_rfc1918():
    # 192.168.x.x is intentionally allowed — this app talks to LAN services.
    with patch("backend.utils.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(0, 0, 0, "", ("192.168.1.10", 0))]
        result = validate_url_safety("http://pihole.lan/")
        assert result is None


def test_validate_url_safety_rejects_invalid_url():
    # No hostname at all → should fail fast, not raise.
    result = validate_url_safety("not-a-url")
    assert result is not None


def test_validate_url_safety_handles_dns_failure():
    with patch("backend.utils.socket.getaddrinfo") as mock_gai:
        import socket
        mock_gai.side_effect = socket.gaierror("no such host")
        result = validate_url_safety("http://nx.example/")
        assert result is not None
        assert "resolve" in result.lower()


async def test_async_validate_url_safety_delegates_to_sync():
    # async wrapper just runs the sync version in a thread pool.
    with patch("backend.utils.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(0, 0, 0, "", ("192.168.1.10", 0))]
        result = await async_validate_url_safety("http://pihole.lan/")
        assert result is None
