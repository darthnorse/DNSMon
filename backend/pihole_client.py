import httpx
import hashlib
import time
import json
from typing import Optional, Dict, List, Any
from urllib.parse import quote
import logging

from .dns_client import DNSBlockerClient

logger = logging.getLogger(__name__)


class PiholeClient(DNSBlockerClient):
    """Client for interacting with Pi-hole v6 REST API"""

    def __init__(self, url: str, password: str, server_name: str, skip_ssl_verify: bool = False, **kwargs):
        super().__init__(url, password, server_name, skip_ssl_verify=skip_ssl_verify, **kwargs)
        self.session_info = {"sid": None, "csrf": None, "auth_time": None}
        self.client = httpx.AsyncClient(timeout=30.0, verify=not skip_ssl_verify)

    # ========== Capability Properties ==========

    @property
    def supports_regex_lists(self) -> bool:
        """Pi-hole supports regex-based lists."""
        return True

    @property
    def supports_teleporter(self) -> bool:
        """Pi-hole supports backup/restore via teleporter."""
        return True

    @property
    def supports_sync(self) -> bool:
        """Pi-hole supports cross-instance configuration sync."""
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.logout()
        await self.client.aclose()

    async def authenticate(self) -> bool:
        """Authenticate with Pi-hole v6 API"""
        try:
            auth_url = f"{self.url}/api/auth"

            # First, check current session status
            response = await self.client.get(auth_url)

            if response.status_code not in [200, 401]:
                logger.error(f"Unexpected response code: {response.status_code}")
                return False

            auth_data = response.json()

            # Check if already authenticated
            if auth_data.get("session", {}).get("valid", False):
                logger.info(f"Already authenticated to {self.server_name}")
                return True

            # Not authenticated, send password
            auth_payload = {"password": self.password}
            response = await self.client.post(auth_url, json=auth_payload)

            if response.status_code == 200:
                auth_result = response.json()
                if auth_result.get("session", {}).get("valid", False):
                    logger.info(f"Authentication successful for {self.server_name}")

                    # Store session info
                    session_data = auth_result.get("session", {})
                    self.session_info["sid"] = session_data.get("sid")
                    self.session_info["csrf"] = session_data.get("csrf")
                    self.session_info["auth_time"] = time.time()

                    # Set session cookie
                    if self.session_info["sid"]:
                        self.client.cookies.set('sid', self.session_info["sid"])

                    # Set CSRF header if provided
                    if self.session_info["csrf"]:
                        self.client.headers['X-FTL-CSRF'] = self.session_info["csrf"]

                    return True
                else:
                    logger.error(f"Authentication failed for {self.server_name}")
                    return False
            else:
                # Try challenge-response method
                if "challenge" in response.text or response.status_code == 400:
                    logger.info(f"Trying challenge-response authentication for {self.server_name}")
                    return await self._authenticate_challenge_response()
                return False

        except Exception as e:
            logger.error(f"Error during authentication for {self.server_name}: {e}")
            return False

    async def _authenticate_challenge_response(self) -> bool:
        """Alternative authentication using challenge-response"""
        try:
            auth_url = f"{self.url}/api/auth"

            # POST empty to get challenge
            response = await self.client.post(auth_url, json={})

            if response.status_code != 200:
                logger.error(f"Failed to get challenge: {response.status_code}")
                return False

            auth_data = response.json()
            challenge = auth_data.get("challenge", "")

            if not challenge:
                logger.error("No challenge received")
                return False

            # Create response hash: SHA256(SHA256(password) + challenge)
            password_hash = hashlib.sha256(self.password.encode()).hexdigest()
            response_hash = hashlib.sha256((password_hash + challenge).encode()).hexdigest()

            # Send authentication response
            auth_payload = {"response": response_hash}
            response = await self.client.post(auth_url, json=auth_payload)

            if response.status_code == 200:
                auth_result = response.json()
                if auth_result.get("session", {}).get("valid", False):
                    logger.info(f"Challenge-response authentication successful for {self.server_name}")

                    # Store session info (was missing!)
                    session_data = auth_result.get("session", {})
                    self.session_info["sid"] = session_data.get("sid")
                    self.session_info["csrf"] = session_data.get("csrf")
                    self.session_info["auth_time"] = time.time()

                    # Set session cookie
                    if self.session_info["sid"]:
                        self.client.cookies.set('sid', self.session_info["sid"])

                    # Set CSRF header if provided
                    if self.session_info["csrf"]:
                        self.client.headers['X-FTL-CSRF'] = self.session_info["csrf"]

                    return True

            logger.error(f"Challenge-response authentication failed: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Error in challenge-response auth for {self.server_name}: {e}")
            return False

    async def get_queries(self, from_timestamp: int, until_timestamp: int) -> Optional[List[Dict[str, Any]]]:
        """Get queries from Pi-hole API"""
        try:
            # Check if session is older than 3 minutes and re-auth if needed
            if self.session_info["auth_time"] and (time.time() - self.session_info["auth_time"]) > 180:
                logger.info(f"Session is {int(time.time() - self.session_info['auth_time'])} seconds old for {self.server_name}, re-authenticating...")
                if not await self.authenticate():
                    logger.error(f"Failed to re-authenticate for {self.server_name}")
                    return None

            endpoint = f"{self.url}/api/queries"

            params = {
                "from": from_timestamp,
                "until": until_timestamp,
                # Don't filter by blocked status - import all queries (allowed + blocked)
                "length": 5000,  # Increase limit to retrieve more queries
            }

            # Add SID to headers
            headers = {}
            if self.session_info["sid"]:
                headers["sid"] = self.session_info["sid"]
                headers["accept"] = "application/json"

            response = await self.client.get(endpoint, params=params, headers=headers)

            if response.status_code == 200:
                data = response.json()
                queries = data.get("queries", [])
                query_count = len(queries)
                logger.info(f"Successfully retrieved {query_count} queries from {self.server_name}")

                # Warn if we hit the limit
                if query_count >= 5000:
                    logger.warning(f"Retrieved maximum number of queries (5000) from {self.server_name}. Some queries might be missed.")

                return queries
            elif response.status_code == 401:
                # Try to re-authenticate
                logger.warning(f"Got 401 for {self.server_name}, re-authenticating...")
                if await self.authenticate():
                    # Update headers
                    if self.session_info["sid"]:
                        headers["sid"] = self.session_info["sid"]
                    # Retry request
                    response = await self.client.get(endpoint, params=params, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        queries = data.get("queries", [])
                        query_count = len(queries)
                        logger.info(f"Successfully retrieved {query_count} queries from {self.server_name} (after re-auth)")

                        # Warn if we hit the limit
                        if query_count >= 5000:
                            logger.warning(f"Retrieved maximum number of queries (5000) from {self.server_name}. Some queries might be missed.")

                        return queries

                logger.error(f"Still getting 401 after re-authentication for {self.server_name}")
                return None
            else:
                logger.error(f"Error accessing Pi-hole API for {self.server_name}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error connecting to Pi-hole API for {self.server_name}: {e}")
            return None

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication info for API requests"""
        headers = {"accept": "application/json"}
        if self.session_info["sid"]:
            headers["sid"] = self.session_info["sid"]
        return headers

    # ========== Domain Management Methods ==========

    async def get_whitelist(self) -> List[Dict[str, Any]]:
        """Get all whitelist entries"""
        try:
            response = await self.client.get(
                f"{self.url}/api/domains/allow/exact",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('domains', [])
            logger.warning(f"Failed to get whitelist from {self.server_name}: {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error getting whitelist from {self.server_name}: {e}")
            return []

    async def get_blacklist(self) -> List[Dict[str, Any]]:
        """Get all blacklist entries"""
        try:
            response = await self.client.get(
                f"{self.url}/api/domains/deny/exact",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('domains', [])
            logger.warning(f"Failed to get blacklist from {self.server_name}: {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error getting blacklist from {self.server_name}: {e}")
            return []

    async def get_regex_whitelist(self) -> List[Dict[str, Any]]:
        """Get all regex whitelist entries"""
        try:
            response = await self.client.get(
                f"{self.url}/api/domains/allow/regex",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Regex whitelist response from {self.server_name}: {data}")
                return data.get('domains', [])
            logger.warning(f"Failed to get regex whitelist from {self.server_name}: {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error getting regex whitelist from {self.server_name}: {e}")
            return []

    async def get_regex_blacklist(self) -> List[Dict[str, Any]]:
        """Get all regex blacklist entries"""
        try:
            response = await self.client.get(
                f"{self.url}/api/domains/deny/regex",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('domains', [])
            logger.warning(f"Failed to get regex blacklist from {self.server_name}: {response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error getting regex blacklist from {self.server_name}: {e}")
            return []

    async def add_to_whitelist(self, domain: str) -> bool:
        """Add a domain to whitelist"""
        try:
            response = await self.client.post(
                f"{self.url}/api/domains/allow/exact",
                json={"domain": domain},
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 201]:
                logger.info(f"Added {domain} to whitelist on {self.server_name}")
                return True
            logger.warning(f"Failed to add {domain} to whitelist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error adding {domain} to whitelist on {self.server_name}: {e}")
            return False

    async def add_to_blacklist(self, domain: str) -> bool:
        """Add a domain to blacklist"""
        try:
            response = await self.client.post(
                f"{self.url}/api/domains/deny/exact",
                json={"domain": domain},
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 201]:
                logger.info(f"Added {domain} to blacklist on {self.server_name}")
                return True
            logger.warning(f"Failed to add {domain} to blacklist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error adding {domain} to blacklist on {self.server_name}: {e}")
            return False

    async def remove_from_whitelist(self, domain: str) -> bool:
        """Remove a domain from whitelist"""
        try:
            response = await self.client.delete(
                f"{self.url}/api/domains/allow/exact/{domain}",
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 204]:
                logger.info(f"Removed {domain} from whitelist on {self.server_name}")
                return True
            logger.warning(f"Failed to remove {domain} from whitelist on {self.server_name}: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error removing {domain} from whitelist on {self.server_name}: {e}")
            return False

    async def remove_from_blacklist(self, domain: str) -> bool:
        """Remove a domain from blacklist"""
        try:
            response = await self.client.delete(
                f"{self.url}/api/domains/deny/exact/{domain}",
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 204]:
                logger.info(f"Removed {domain} from blacklist on {self.server_name}")
                return True
            logger.warning(f"Failed to remove {domain} from blacklist on {self.server_name}: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error removing {domain} from blacklist on {self.server_name}: {e}")
            return False

    async def add_to_regex_whitelist(self, pattern: str) -> bool:
        """Add a regex pattern to whitelist"""
        try:
            response = await self.client.post(
                f"{self.url}/api/domains/allow/regex",
                json={"domain": pattern},
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 201]:
                logger.info(f"Added regex '{pattern}' to whitelist on {self.server_name}")
                return True
            logger.warning(f"Failed to add regex '{pattern}' to whitelist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error adding regex '{pattern}' to whitelist on {self.server_name}: {e}")
            return False

    async def add_to_regex_blacklist(self, pattern: str) -> bool:
        """Add a regex pattern to blacklist"""
        try:
            response = await self.client.post(
                f"{self.url}/api/domains/deny/regex",
                json={"domain": pattern},
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 201]:
                logger.info(f"Added regex '{pattern}' to blacklist on {self.server_name}")
                return True
            logger.warning(f"Failed to add regex '{pattern}' to blacklist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error adding regex '{pattern}' to blacklist on {self.server_name}: {e}")
            return False

    async def remove_from_regex_whitelist(self, pattern: str) -> bool:
        """Remove a pattern from regex whitelist"""
        try:
            encoded_pattern = quote(pattern, safe='')
            response = await self.client.delete(
                f"{self.url}/api/domains/allow/regex/{encoded_pattern}",
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 204]:
                logger.info(f"Removed regex '{pattern}' from whitelist on {self.server_name}")
                return True
            logger.warning(f"Failed to remove regex '{pattern}' from whitelist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error removing regex '{pattern}' from whitelist on {self.server_name}: {e}")
            return False

    async def remove_from_regex_blacklist(self, pattern: str) -> bool:
        """Remove a pattern from regex blacklist"""
        try:
            encoded_pattern = quote(pattern, safe='')
            response = await self.client.delete(
                f"{self.url}/api/domains/deny/regex/{encoded_pattern}",
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 204]:
                logger.info(f"Removed regex '{pattern}' from blacklist on {self.server_name}")
                return True
            logger.warning(f"Failed to remove regex '{pattern}' from blacklist on {self.server_name}: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error removing regex '{pattern}' from blacklist on {self.server_name}: {e}")
            return False

    async def logout(self):
        """Logout from Pi-hole API"""
        try:
            response = await self.client.delete(f"{self.url}/api/auth")
            if response.status_code == 200:
                logger.info(f"Successfully logged out from {self.server_name}")
            else:
                logger.warning(f"Logout returned {response.status_code} for {self.server_name}")
        except Exception as e:
            logger.warning(f"Logout failed for {self.server_name}: {e}")

    # ========== Teleporter Methods (Backup/Restore) ==========

    async def get_teleporter(self) -> Optional[bytes]:
        """Download teleporter backup (zip file) from Pi-hole"""
        try:
            response = await self.client.get(
                f"{self.url}/api/teleporter",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                logger.info(f"Downloaded teleporter backup from {self.server_name} ({len(response.content)} bytes)")
                return response.content
            logger.error(f"Failed to get teleporter from {self.server_name}: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error getting teleporter from {self.server_name}: {e}")
            return None

    async def post_teleporter(self, backup_data: bytes, import_options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Upload teleporter backup to Pi-hole.

        import_options controls what gets imported:
        {
            "config": false,  # Don't import config (we use PATCH /api/config instead)
            "dhcp_leases": false,
            "gravity": {
                "group": true,
                "adlist": true,
                "adlist_by_group": true,
                "domainlist": true,
                "domainlist_by_group": true,
                "client": true,
                "client_by_group": true
            }
        }
        """
        try:
            # Build multipart form data
            files = {
                'file': ('backup.zip', backup_data, 'application/zip')
            }

            # Default import options - sync everything in gravity, skip config
            if import_options is None:
                import_options = {
                    "config": False,
                    "dhcp_leases": False,
                    "gravity": {
                        "group": True,
                        "adlist": True,
                        "adlist_by_group": True,
                        "domainlist": True,
                        "domainlist_by_group": True,
                        "client": True,
                        "client_by_group": True
                    }
                }

            data = {
                'import': json.dumps(import_options)
            }

            headers = self.get_auth_headers()
            # Remove content-type for multipart
            headers.pop('Content-Type', None)

            response = await self.client.post(
                f"{self.url}/api/teleporter",
                files=files,
                data=data,
                headers=headers
            )

            if response.status_code in [200, 201]:
                logger.info(f"Successfully uploaded teleporter backup to {self.server_name}")
                return True
            logger.error(f"Failed to upload teleporter to {self.server_name}: {response.status_code} - {response.text[:200]}")
            return False
        except Exception as e:
            logger.error(f"Error uploading teleporter to {self.server_name}: {e}")
            return False

    # ========== Config Methods ==========

    async def get_config(self) -> Optional[Dict[str, Any]]:
        """Get full Pi-hole configuration"""
        try:
            response = await self.client.get(
                f"{self.url}/api/config",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Fetched config from {self.server_name}")
                return data.get('config', {})
            logger.error(f"Failed to get config from {self.server_name}: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error getting config from {self.server_name}: {e}")
            return None

    async def patch_config(self, config: Dict[str, Any]) -> bool:
        """
        Update Pi-hole configuration via PATCH.

        config should be structured like:
        {
            "config": {
                "dns": { ... },
                "dhcp": { ... },
                ...
            }
        }
        """
        try:
            headers = self.get_auth_headers()
            headers['Content-Type'] = 'application/json'

            response = await self.client.patch(
                f"{self.url}/api/config",
                json={"config": config},
                headers=headers
            )

            if response.status_code in [200, 201]:
                logger.info(f"Successfully patched config on {self.server_name}")
                return True
            logger.error(f"Failed to patch config on {self.server_name}: {response.status_code} - {response.text[:200]}")
            return False
        except Exception as e:
            logger.error(f"Error patching config on {self.server_name}: {e}")
            return False

    async def run_gravity(self) -> bool:
        """Run gravity update via /api/action/gravity endpoint"""
        try:
            response = await self.client.post(
                f"{self.url}/api/action/gravity",
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 202]:
                logger.info(f"Started gravity update on {self.server_name}")
                return True
            logger.error(f"Failed to run gravity on {self.server_name}: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error running gravity on {self.server_name}: {e}")
            return False

    # ========== Blocking Control Methods ==========

    async def get_blocking_status(self) -> Optional[bool]:
        """
        Get current blocking status from Pi-hole.
        Returns True if blocking is enabled, False if disabled, None on error.
        """
        try:
            response = await self.client.get(
                f"{self.url}/api/dns/blocking",
                headers=self.get_auth_headers()
            )
            if response.status_code == 200:
                data = response.json()
                blocking = data.get('blocking')
                logger.debug(f"Blocking status on {self.server_name}: {blocking}")
                # Normalize to boolean - Pi-hole can return "enabled"/"disabled" strings or booleans
                if isinstance(blocking, bool):
                    return blocking
                elif isinstance(blocking, str):
                    return blocking.lower() == 'enabled'
                return None
            logger.error(f"Failed to get blocking status from {self.server_name}: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error getting blocking status from {self.server_name}: {e}")
            return None

    async def set_blocking(self, enabled: bool, timer: Optional[int] = None) -> bool:
        """
        Enable or disable blocking on Pi-hole.

        Args:
            enabled: True to enable blocking, False to disable
            timer: Optional duration in seconds. If provided and enabled=False,
                   Pi-hole will auto-re-enable after this many seconds.

        Returns:
            True if successful, False otherwise.
        """
        try:
            payload: Dict[str, Any] = {"blocking": enabled}
            if timer is not None and not enabled:
                # Timer only makes sense when disabling
                payload["timer"] = timer

            response = await self.client.post(
                f"{self.url}/api/dns/blocking",
                json=payload,
                headers=self.get_auth_headers()
            )
            if response.status_code in [200, 201]:
                action = "enabled" if enabled else "disabled"
                timer_msg = f" for {timer}s" if timer and not enabled else ""
                logger.info(f"Blocking {action}{timer_msg} on {self.server_name}")
                return True
            logger.error(f"Failed to set blocking on {self.server_name}: {response.status_code} - {response.text[:200]}")
            return False
        except Exception as e:
            logger.error(f"Error setting blocking on {self.server_name}: {e}")
            return False
