"""
Shared utility functions for DNSMon.
"""
from datetime import datetime, timezone
from typing import Optional


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
