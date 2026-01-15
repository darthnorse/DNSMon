"""
Factory function to create DNS blocker clients based on server type.
"""

from typing import Optional
from .dns_client import DNSBlockerClient


def create_dns_client(
    server_type: str,
    url: str,
    password: str,
    server_name: str,
    username: Optional[str] = None,
    skip_ssl_verify: bool = False,
    **kwargs
) -> DNSBlockerClient:
    """
    Factory function to create the appropriate DNS blocker client.

    Args:
        server_type: Type of DNS blocker ('pihole' or 'adguard')
        url: Server URL
        password: Authentication password
        server_name: Display name for logging
        username: Username for authentication (required for AdGuard, ignored for Pi-hole)
        skip_ssl_verify: If True, skip SSL certificate verification (for self-signed certs)
        **kwargs: Additional client-specific arguments

    Returns:
        Appropriate DNSBlockerClient implementation

    Raises:
        ValueError: If server_type is not supported
    """
    if server_type == 'pihole':
        from .pihole_client import PiholeClient
        return PiholeClient(url, password, server_name, skip_ssl_verify=skip_ssl_verify, **kwargs)

    elif server_type == 'adguard':
        from .adguard_client import AdGuardHomeClient
        # AdGuard uses username (default: "admin") + password
        adguard_username = username or 'admin'
        return AdGuardHomeClient(url, password, server_name, username=adguard_username, skip_ssl_verify=skip_ssl_verify, **kwargs)

    else:
        raise ValueError(f"Unsupported server type: {server_type}. Supported types: 'pihole', 'adguard'")
