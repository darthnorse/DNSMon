"""
Factory function to create DNS blocker clients based on server type.
"""

from typing import Any, Dict, Optional
from .dns_client import DNSBlockerClient


def create_dns_client(
    server_type: str,
    url: str,
    password: str,
    server_name: str,
    username: Optional[str] = None,
    skip_ssl_verify: bool = False,
    extra_config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> DNSBlockerClient:
    """
    Factory function to create the appropriate DNS blocker client.

    Args:
        server_type: Type of DNS blocker ('pihole', 'adguard', or 'technitium')
        url: Server URL
        password: Authentication password (or API token for Technitium)
        server_name: Display name for logging
        username: Username for authentication (required for AdGuard, ignored for others)
        skip_ssl_verify: If True, skip SSL certificate verification (for self-signed certs)
        extra_config: Type-specific configuration (e.g., Technitium log app settings)
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
        adguard_username = username or 'admin'
        return AdGuardHomeClient(url, password, server_name, username=adguard_username, skip_ssl_verify=skip_ssl_verify, **kwargs)

    elif server_type == 'technitium':
        from .technitium_client import TechnitiumClient
        cfg = extra_config or {}
        return TechnitiumClient(
            url, password, server_name,
            skip_ssl_verify=skip_ssl_verify,
            log_app_name=cfg.get('log_app_name') or 'QueryLogsSqlite',
            log_app_class_path=cfg.get('log_app_class_path') or 'QueryLogsSqlite.App',
            **kwargs
        )

    else:
        raise ValueError(f"Unsupported server type: {server_type}. Supported types: 'pihole', 'adguard', 'technitium'")
