"""
AdGuard Home client for DNS monitoring.

This module implements the DNSBlockerClient interface for AdGuard Home,
allowing DNSMon to monitor and manage AdGuard Home instances.
"""

import httpx
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
from base64 import b64encode

from .dns_client import DNSBlockerClient

logger = logging.getLogger(__name__)


class AdGuardHomeClient(DNSBlockerClient):
    """Client for interacting with AdGuard Home REST API"""

    def __init__(self, url: str, password: str, server_name: str, username: str = "admin", skip_ssl_verify: bool = False, **kwargs):
        """
        Initialize the AdGuard Home client.

        Args:
            url: Base URL of the AdGuard Home server
            password: Authentication password
            server_name: Display name for logging
            username: Username for Basic Auth (default: 'admin')
            skip_ssl_verify: If True, skip SSL certificate verification (for self-signed certs)
        """
        super().__init__(url, password, server_name, skip_ssl_verify=skip_ssl_verify, **kwargs)
        self.username = username
        self.client = httpx.AsyncClient(timeout=30.0, verify=not skip_ssl_verify)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    def _get_auth_header(self) -> Dict[str, str]:
        """Get Basic Auth header for API requests."""
        credentials = f"{self.username}:{self.password}"
        encoded = b64encode(credentials.encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json"
        }

    # ========== Required Methods ==========

    async def authenticate(self) -> bool:
        """Test authentication by making a simple API call."""
        try:
            response = await self.client.get(
                f"{self.url}/control/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                logger.info(f"Authentication successful for {self.server_name}")
                return True
            logger.error(f"Authentication failed for {self.server_name}: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error during authentication for {self.server_name}: {e}")
            return False

    async def get_queries(self, from_timestamp: int, until_timestamp: int) -> Optional[List[Dict[str, Any]]]:
        """
        Get queries from AdGuard Home query log.

        Note: AdGuard Home's query log API returns queries in reverse chronological order
        and uses a different pagination approach than Pi-hole.
        """
        try:
            # AdGuard Home query log endpoint
            # The limit parameter controls how many entries to fetch
            params = {
                "limit": 5000,
            }

            response = await self.client.get(
                f"{self.url}/control/querylog",
                params=params,
                headers=self._get_auth_header()
            )

            if response.status_code == 200:
                data = response.json()
                queries = data.get("data", [])

                # Filter by timestamp range and transform to common format
                filtered = []
                for q in queries:
                    # AdGuard uses ISO format timestamps
                    ts = q.get("time", "")
                    if ts:
                        try:
                            # Parse ISO timestamp
                            query_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            query_timestamp = int(query_time.timestamp())

                            # Filter by time range
                            if from_timestamp <= query_timestamp <= until_timestamp:
                                filtered.append(self._transform_query(q))
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Failed to parse timestamp {ts}: {e}")
                            continue

                logger.info(f"Retrieved {len(filtered)} queries from {self.server_name}")
                return filtered

            logger.error(f"Failed to get queries from {self.server_name}: {response.status_code}")
            return None

        except Exception as e:
            logger.error(f"Error getting queries from {self.server_name}: {e}")
            return None

    def _transform_query(self, raw_query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform AdGuard query format to Pi-hole-compatible format.

        This allows the ingestion service to process queries from both
        Pi-hole and AdGuard Home using the same logic.
        """
        # Map AdGuard status to common status
        reason = raw_query.get("reason", "")
        status = self._map_status(reason)

        # Parse timestamp
        ts = raw_query.get("time", "")
        try:
            timestamp = int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except (ValueError, TypeError):
            timestamp = 0

        # Extract question data
        question = raw_query.get("question", {})
        domain = question.get("name", "").rstrip(".")
        query_type = question.get("type", "")

        # Extract client info
        client_ip = raw_query.get("client", "")
        client_info = raw_query.get("client_info", {})
        client_name = client_info.get("name", "") if isinstance(client_info, dict) else ""

        return {
            "timestamp": timestamp,
            "domain": domain,
            "client": {
                "ip": client_ip,
                "name": client_name
            },
            "type": query_type,
            "status": status
        }

    def _map_status(self, reason: str) -> str:
        """
        Map AdGuard reason to normalized status.

        AdGuard reasons include:
        - NotFilteredNotFound: Query allowed, not in any filter
        - NotFilteredWhiteList: Query allowed by whitelist
        - FilteredBlackList: Blocked by blacklist
        - FilteredSafeBrowsing: Blocked by safe browsing
        - FilteredParental: Blocked by parental control
        - FilteredBlockedService: Blocked service
        - Rewrite: DNS rewrite applied
        - RewriteEtcHosts: Rewritten via /etc/hosts
        """
        reason_lower = reason.lower() if reason else ""

        if "notfiltered" in reason_lower:
            return "ALLOWED"
        elif any(x in reason_lower for x in ["filtered", "blocked"]):
            return "BLOCKED"
        elif "rewrite" in reason_lower:
            return "ALLOWED"
        elif "cached" in reason_lower:
            return "CACHED"
        return "UNKNOWN"

    async def get_blocking_status(self) -> Optional[bool]:
        """Get current protection (blocking) status."""
        try:
            response = await self.client.get(
                f"{self.url}/control/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("protection_enabled", False)
            logger.error(f"Failed to get blocking status from {self.server_name}: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error getting blocking status from {self.server_name}: {e}")
            return None

    async def set_blocking(self, enabled: bool, timer: Optional[int] = None) -> bool:
        """
        Enable or disable protection.

        Args:
            enabled: True to enable, False to disable
            timer: Optional duration in seconds for temporary disable
        """
        try:
            # AdGuard Home uses /control/protection endpoint
            # It accepts protection_enabled and optionally duration in milliseconds
            payload: Dict[str, Any] = {"protection_enabled": enabled}

            if timer is not None and not enabled:
                # AdGuard expects duration in milliseconds
                payload["duration"] = timer * 1000

            response = await self.client.post(
                f"{self.url}/control/protection",
                json=payload,
                headers=self._get_auth_header()
            )

            if response.status_code == 200:
                action = "enabled" if enabled else "disabled"
                timer_msg = f" for {timer}s" if timer and not enabled else ""
                logger.info(f"Blocking {action}{timer_msg} on {self.server_name}")
                return True

            logger.error(f"Failed to set blocking on {self.server_name}: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Error setting blocking on {self.server_name}: {e}")
            return False

    async def get_whitelist(self) -> List[Dict[str, Any]]:
        """
        Get whitelist entries from AdGuard Home.

        AdGuard stores whitelist rules as user rules with @@|| prefix.
        """
        try:
            response = await self.client.get(
                f"{self.url}/control/filtering/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                data = response.json()
                rules = data.get("user_rules", [])

                whitelist = []
                for i, rule in enumerate(rules):
                    # Whitelist rules: @@||domain^
                    if rule.startswith("@@||") and rule.endswith("^"):
                        domain = rule[4:-1]  # Strip @@|| and ^
                        whitelist.append({
                            "id": i,
                            "domain": domain,
                            "enabled": True
                        })
                return whitelist

            logger.error(f"Failed to get whitelist from {self.server_name}: {response.status_code}")
            return []

        except Exception as e:
            logger.error(f"Error getting whitelist from {self.server_name}: {e}")
            return []

    async def get_blacklist(self) -> List[Dict[str, Any]]:
        """
        Get blacklist entries from AdGuard Home.

        AdGuard stores blacklist rules as user rules with || prefix.
        """
        try:
            response = await self.client.get(
                f"{self.url}/control/filtering/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                data = response.json()
                rules = data.get("user_rules", [])

                blacklist = []
                for i, rule in enumerate(rules):
                    # Blacklist rules: ||domain^ (but not starting with @@)
                    if rule.startswith("||") and rule.endswith("^") and not rule.startswith("@@"):
                        domain = rule[2:-1]  # Strip || and ^
                        blacklist.append({
                            "id": i,
                            "domain": domain,
                            "enabled": True
                        })
                return blacklist

            logger.error(f"Failed to get blacklist from {self.server_name}: {response.status_code}")
            return []

        except Exception as e:
            logger.error(f"Error getting blacklist from {self.server_name}: {e}")
            return []

    async def _get_user_rules(self) -> Optional[List[str]]:
        """Helper to get current user rules."""
        try:
            response = await self.client.get(
                f"{self.url}/control/filtering/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("user_rules", [])
            return None
        except Exception:
            return None

    async def _set_user_rules(self, rules: List[str]) -> bool:
        """Helper to set user rules."""
        try:
            response = await self.client.post(
                f"{self.url}/control/filtering/set_rules",
                json={"rules": rules},
                headers=self._get_auth_header()
            )
            return response.status_code == 200
        except Exception:
            return False

    async def add_to_whitelist(self, domain: str) -> bool:
        """Add a domain to whitelist using AdGuard filter rule format."""
        try:
            # AdGuard whitelist format: @@||domain^
            rule = f"@@||{domain}^"

            rules = await self._get_user_rules()
            if rules is None:
                return False

            if rule not in rules:
                rules.append(rule)
                if await self._set_user_rules(rules):
                    logger.info(f"Added {domain} to whitelist on {self.server_name}")
                    return True
                return False

            logger.info(f"Domain {domain} already in whitelist on {self.server_name}")
            return True  # Already exists

        except Exception as e:
            logger.error(f"Error adding {domain} to whitelist on {self.server_name}: {e}")
            return False

    async def add_to_blacklist(self, domain: str) -> bool:
        """Add a domain to blacklist using AdGuard filter rule format."""
        try:
            # AdGuard blacklist format: ||domain^
            rule = f"||{domain}^"

            rules = await self._get_user_rules()
            if rules is None:
                return False

            if rule not in rules:
                rules.append(rule)
                if await self._set_user_rules(rules):
                    logger.info(f"Added {domain} to blacklist on {self.server_name}")
                    return True
                return False

            logger.info(f"Domain {domain} already in blacklist on {self.server_name}")
            return True  # Already exists

        except Exception as e:
            logger.error(f"Error adding {domain} to blacklist on {self.server_name}: {e}")
            return False

    async def remove_from_whitelist(self, domain: str) -> bool:
        """Remove a domain from whitelist."""
        try:
            rule = f"@@||{domain}^"

            rules = await self._get_user_rules()
            if rules is None:
                return False

            if rule in rules:
                rules.remove(rule)
                if await self._set_user_rules(rules):
                    logger.info(f"Removed {domain} from whitelist on {self.server_name}")
                    return True
                return False

            logger.info(f"Domain {domain} not in whitelist on {self.server_name}")
            return True  # Already removed

        except Exception as e:
            logger.error(f"Error removing {domain} from whitelist on {self.server_name}: {e}")
            return False

    async def remove_from_blacklist(self, domain: str) -> bool:
        """Remove a domain from blacklist."""
        try:
            rule = f"||{domain}^"

            rules = await self._get_user_rules()
            if rules is None:
                return False

            if rule in rules:
                rules.remove(rule)
                if await self._set_user_rules(rules):
                    logger.info(f"Removed {domain} from blacklist on {self.server_name}")
                    return True
                return False

            logger.info(f"Domain {domain} not in blacklist on {self.server_name}")
            return True  # Already removed

        except Exception as e:
            logger.error(f"Error removing {domain} from blacklist on {self.server_name}: {e}")
            return False

    # ========== Config/Sync Methods ==========

    async def get_config(self) -> Optional[Dict[str, Any]]:
        """
        Get AdGuard Home configuration for sync.

        Returns a dict with:
        - user_rules: List of filter rules (whitelist/blacklist)
        - dns: DNS configuration (upstreams, etc.)
        - filtering: Filtering settings
        """
        try:
            config = {}

            # Get filtering status (includes user_rules)
            response = await self.client.get(
                f"{self.url}/control/filtering/status",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                data = response.json()
                config['user_rules'] = data.get('user_rules', [])
                config['filtering_enabled'] = data.get('enabled', True)
                config['filtering_interval'] = data.get('interval', 24)

            # Get DNS config
            response = await self.client.get(
                f"{self.url}/control/dns_info",
                headers=self._get_auth_header()
            )
            if response.status_code == 200:
                dns_data = response.json()
                # Only sync specific DNS settings, not device-specific ones
                config['dns'] = {
                    'upstream_dns': dns_data.get('upstream_dns', []),
                    'bootstrap_dns': dns_data.get('bootstrap_dns', []),
                    'ratelimit': dns_data.get('ratelimit', 0),
                    'blocking_mode': dns_data.get('blocking_mode', 'default'),
                    'edns_cs_enabled': dns_data.get('edns_cs_enabled', False),
                    'dnssec_enabled': dns_data.get('dnssec_enabled', False),
                    'disable_ipv6': dns_data.get('disable_ipv6', False),
                }

            logger.info(f"Retrieved config from {self.server_name}")
            return config

        except Exception as e:
            logger.error(f"Error getting config from {self.server_name}: {e}")
            return None

    async def patch_config(self, config: Dict[str, Any]) -> bool:
        """
        Apply configuration to AdGuard Home.

        Args:
            config: Dict with user_rules, dns, and/or filtering settings
        """
        try:
            success = True

            # Apply user rules
            if 'user_rules' in config:
                if not await self._set_user_rules(config['user_rules']):
                    logger.error(f"Failed to set user rules on {self.server_name}")
                    success = False
                else:
                    logger.info(f"Applied {len(config['user_rules'])} user rules to {self.server_name}")

            # Apply DNS config
            if 'dns' in config:
                response = await self.client.post(
                    f"{self.url}/control/dns_config",
                    json=config['dns'],
                    headers=self._get_auth_header()
                )
                if response.status_code != 200:
                    logger.error(f"Failed to set DNS config on {self.server_name}: {response.status_code}")
                    success = False
                else:
                    logger.info(f"Applied DNS config to {self.server_name}")

            # Apply filtering settings
            if 'filtering_enabled' in config:
                response = await self.client.post(
                    f"{self.url}/control/filtering/config",
                    json={
                        'enabled': config.get('filtering_enabled', True),
                        'interval': config.get('filtering_interval', 24)
                    },
                    headers=self._get_auth_header()
                )
                if response.status_code != 200:
                    logger.warning(f"Failed to set filtering config on {self.server_name}: {response.status_code}")
                    # Don't fail the whole sync for this

            return success

        except Exception as e:
            logger.error(f"Error patching config on {self.server_name}: {e}")
            return False

    # ========== Capability Properties ==========

    @property
    def supports_regex_lists(self) -> bool:
        """AdGuard supports regex in rules but not as separate lists."""
        return False

    @property
    def supports_teleporter(self) -> bool:
        """AdGuard does not use teleporter format."""
        return False

    @property
    def supports_sync(self) -> bool:
        """AdGuard supports config-based sync to other AdGuard instances."""
        return True
