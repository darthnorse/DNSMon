"""
Shared utility functions for DNSMon.
"""
import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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


def validate_url_safety(url: str) -> Optional[str]:
    """Check that a URL does not resolve to a blocked address range.

    Returns an error message string if the URL is unsafe, or None if OK.
    Blocks loopback and link-local (cloud metadata) addresses.
    Allows RFC 1918 private ranges since DNSMon typically runs on a LAN.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return "Invalid URL: no hostname"

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}"

    for info in addr_infos:
        ip = ipaddress.ip_address(info[4][0])
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                return "URL resolves to a blocked address (loopback or link-local)"

    return None


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
