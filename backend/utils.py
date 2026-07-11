"""
Shared utility functions for DNSMon.
"""
import asyncio
import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)

# Offline PSL snapshot: suffix_list_urls=() forces the bundled list so the first
# call never makes a network request (avoids runtime latency + SSRF surface).
# cache_dir=None disables on-disk caching — the container runs as appuser with a
# non-writable HOME, so a disk cache write would fail and log a confusing warning.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Networks that are never legitimate targets for outbound HTTP from this app.
# RFC 1918 private ranges are intentionally NOT blocked — this app commonly
# runs on LANs alongside the services it contacts (Pi-hole, AdGuard, ntfy, etc.).
_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    ipaddress.ip_network('::1/128'),            # IPv6 loopback
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local / cloud metadata
    ipaddress.ip_network('fe80::/10'),          # IPv6 link-local
    ipaddress.ip_network('0.0.0.0/8'),          # "This" network
]


def resolve_url_safety(url: str) -> tuple[Optional[str], Optional[str]]:
    """Check that a URL does not resolve to a blocked address range, and return
    one validated IP so callers can pin the connection to it (a second DNS
    resolution at connect time could otherwise be rebound to a blocked range).

    Returns (unsafe_reason, pinned_ip): reason is None when safe; the pinned
    IP prefers IPv4 when both families resolve."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return "Invalid URL: no hostname", None

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}", None

    ips = []
    for info in addr_infos:
        ip = ipaddress.ip_address(info[4][0])
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                return "URL resolves to a blocked address (loopback or link-local)", None
        ips.append(ip)

    ips.sort(key=lambda ip: ip.version)
    return None, (str(ips[0]) if ips else None)


async def async_resolve_url_safety(url: str) -> tuple[Optional[str], Optional[str]]:
    """Async resolve_url_safety — DNS resolution runs in a thread pool."""
    return await asyncio.get_running_loop().run_in_executor(None, resolve_url_safety, url)


def validate_url_safety(url: str) -> Optional[str]:
    """Sync version — check that a URL does not resolve to a blocked address range.

    Use this in synchronous contexts (e.g., Pydantic validators, validate_config).
    For async contexts (send methods, OIDC flows), use async_validate_url_safety.
    """
    return resolve_url_safety(url)[0]


async def async_validate_url_safety(url: str) -> Optional[str]:
    """Async version — runs DNS resolution in a thread pool to avoid blocking the event loop."""
    return await asyncio.get_running_loop().run_in_executor(None, validate_url_safety, url)


def registrable_domain(fqdn: str) -> str:
    """Resolve a hostname to its registrable domain (e.g. a.b.example.co.uk ->
    example.co.uk). Falls back to the cleaned input for internal/unknown TLDs."""
    fqdn = (fqdn or "").strip().rstrip(".").lower()
    if not fqdn:
        return ""
    ext = _TLD_EXTRACT(fqdn)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return fqdn


def ensure_utc(dt: Optional[datetime]) -> Optional[str]:
    """Ensure datetime is timezone-aware (UTC) and return ISO format"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def create_client_from_server(server):
    """Create a DNS client from a server model"""
    from .dns_client_factory import create_dns_client
    return create_dns_client(
        server_type=server.server_type or 'pihole',
        url=server.url,
        password=server.password,
        server_name=server.name,
        username=server.username,
        skip_ssl_verify=server.skip_ssl_verify or False,
        extra_config=server.extra_config or {}
    )
