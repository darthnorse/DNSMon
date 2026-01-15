"""
Abstract base class for DNS ad-blocker clients.

This module defines the interface that all DNS blocker clients must implement,
enabling support for multiple DNS ad-blocking solutions (Pi-hole, AdGuard Home, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Any


class DNSBlockerClient(ABC):
    """
    Abstract base class for DNS ad-blocker clients.

    All DNS blocker implementations (Pi-hole, AdGuard Home, etc.) must extend
    this class and implement the required abstract methods.
    """

    def __init__(self, url: str, password: str, server_name: str, skip_ssl_verify: bool = False, **kwargs):
        """
        Initialize the DNS blocker client.

        Args:
            url: Base URL of the DNS blocker server
            password: Authentication password
            server_name: Display name for logging purposes
            skip_ssl_verify: If True, skip SSL certificate verification (for self-signed certs)
            **kwargs: Additional client-specific arguments
        """
        self.url = url.rstrip('/')
        self.password = password
        self.server_name = server_name
        self.skip_ssl_verify = skip_ssl_verify

    @abstractmethod
    async def __aenter__(self):
        """Async context manager entry."""
        pass

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup."""
        pass

    # =========================================================================
    # Required Methods - All clients must implement these
    # =========================================================================

    @abstractmethod
    async def authenticate(self) -> bool:
        """
        Authenticate with the DNS blocker server.

        Returns:
            True if authentication successful, False otherwise.
        """
        pass

    @abstractmethod
    async def get_queries(self, from_timestamp: int, until_timestamp: int) -> Optional[List[Dict[str, Any]]]:
        """
        Get DNS queries from the server within a time range.

        Args:
            from_timestamp: Unix timestamp for start of range
            until_timestamp: Unix timestamp for end of range

        Returns:
            List of query dictionaries in normalized format, or None on error.
            Each query dict should contain:
            - timestamp: Unix timestamp (int)
            - domain: Domain name (str)
            - client: Dict with 'ip' and optional 'name' keys
            - type: Query type (A, AAAA, etc.)
            - status: Normalized status string
        """
        pass

    @abstractmethod
    async def get_blocking_status(self) -> Optional[bool]:
        """
        Get the current blocking status.

        Returns:
            True if blocking is enabled, False if disabled, None on error.
        """
        pass

    @abstractmethod
    async def set_blocking(self, enabled: bool, timer: Optional[int] = None) -> bool:
        """
        Enable or disable blocking.

        Args:
            enabled: True to enable blocking, False to disable
            timer: Optional seconds until auto-re-enable (only when disabling)

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def get_whitelist(self) -> List[Dict[str, Any]]:
        """
        Get all whitelist (allow list) entries.

        Returns:
            List of domain entries, each containing at least 'domain' and 'enabled' keys.
        """
        pass

    @abstractmethod
    async def get_blacklist(self) -> List[Dict[str, Any]]:
        """
        Get all blacklist (block list) entries.

        Returns:
            List of domain entries, each containing at least 'domain' and 'enabled' keys.
        """
        pass

    @abstractmethod
    async def add_to_whitelist(self, domain: str) -> bool:
        """
        Add a domain to the whitelist.

        Args:
            domain: Domain to add

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def add_to_blacklist(self, domain: str) -> bool:
        """
        Add a domain to the blacklist.

        Args:
            domain: Domain to add

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def remove_from_whitelist(self, domain: str) -> bool:
        """
        Remove a domain from the whitelist.

        Args:
            domain: Domain to remove

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    async def remove_from_blacklist(self, domain: str) -> bool:
        """
        Remove a domain from the blacklist.

        Args:
            domain: Domain to remove

        Returns:
            True if successful, False otherwise.
        """
        pass

    # =========================================================================
    # Optional Methods - Default implementations provided, override as needed
    # =========================================================================

    async def get_regex_whitelist(self) -> List[Dict[str, Any]]:
        """
        Get regex whitelist entries.

        Default: Returns empty list (not all blockers support regex lists).
        """
        return []

    async def get_regex_blacklist(self) -> List[Dict[str, Any]]:
        """
        Get regex blacklist entries.

        Default: Returns empty list (not all blockers support regex lists).
        """
        return []

    async def remove_from_regex_whitelist(self, pattern_id: int) -> bool:
        """
        Remove a pattern from the regex whitelist.

        Default: Returns False (not supported).
        """
        return False

    async def remove_from_regex_blacklist(self, pattern_id: int) -> bool:
        """
        Remove a pattern from the regex blacklist.

        Default: Returns False (not supported).
        """
        return False

    async def get_teleporter(self) -> Optional[bytes]:
        """
        Get backup data (Pi-hole teleporter format).

        Default: Returns None (not supported).
        """
        return None

    async def post_teleporter(self, backup_data: bytes, import_options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Restore backup data.

        Default: Returns False (not supported).
        """
        return False

    async def get_config(self) -> Optional[Dict[str, Any]]:
        """
        Get full server configuration.

        Default: Returns None (not supported).
        """
        return None

    async def patch_config(self, config: Dict[str, Any]) -> bool:
        """
        Update server configuration.

        Default: Returns False (not supported).
        """
        return False

    async def run_gravity(self) -> bool:
        """
        Trigger blocklist update (gravity for Pi-hole).

        Default: Returns False (not supported).
        """
        return False

    # =========================================================================
    # Capability Properties - Override to indicate supported features
    # =========================================================================

    @property
    def supports_regex_lists(self) -> bool:
        """Whether this blocker supports regex-based lists."""
        return False

    @property
    def supports_teleporter(self) -> bool:
        """Whether this blocker supports backup/restore (teleporter)."""
        return False

    @property
    def supports_sync(self) -> bool:
        """Whether this blocker supports cross-instance configuration sync."""
        return False
