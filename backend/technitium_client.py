"""
Technitium DNS Server client for DNS monitoring.

Prerequisites:
  - A Technitium API token created via Administration > Create API Token.
  - The "Query Logs (Sqlite)" DNS App installed for query log retrieval.

Security note: The Technitium API authenticates via a ``token`` query parameter,
so the API token appears in request URLs. Ensure proxy/debug logs are secured.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

import httpx

from .dns_client import DNSBlockerClient

logger = logging.getLogger(__name__)

_BLOCKED_TYPES = {'Blocked', 'UpstreamBlocked', 'CacheBlocked'}
_CACHED_TYPES = {'Cached'}
_ALLOWED_TYPES = {'Authoritative', 'Recursive', 'Forwarder', 'Resolved'}


class TechnitiumClient(DNSBlockerClient):
    """Client for interacting with Technitium DNS Server API."""

    def __init__(
        self,
        url: str,
        password: str,
        server_name: str,
        skip_ssl_verify: bool = False,
        log_app_name: str = 'QueryLogsSqlite',
        log_app_class_path: str = 'QueryLogsSqlite.App',
        **kwargs,
    ):
        super().__init__(url, password, server_name, skip_ssl_verify=skip_ssl_verify, **kwargs)
        self.log_app_name = log_app_name
        self.log_app_class_path = log_app_class_path
        self.client = httpx.AsyncClient(timeout=30.0, verify=not skip_ssl_verify)

    @property
    def supports_regex_lists(self) -> bool:
        return False

    @property
    def supports_teleporter(self) -> bool:
        return True

    @property
    def supports_sync(self) -> bool:
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    # ========== Internal Helpers ==========

    def _auth_params(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build query params with auth token."""
        params: Dict[str, Any] = {'token': self.password}
        if extra:
            params.update(extra)
        return params

    def _check_response(self, response: httpx.Response, path: str, method: str = 'GET') -> Optional[Dict[str, Any]]:
        """Validate HTTP response and parse JSON envelope. Returns parsed data or None."""
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                return data
            logger.error(f"API error on {method} {path} for {self.server_name}: {data.get('errorMessage', data.get('status'))}")
            return None
        logger.error(f"{method} {path} failed for {self.server_name}: HTTP {response.status_code}")
        return None

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """GET helper; returns parsed JSON response dict or None."""
        try:
            response = await self.client.get(f"{self.url}{path}", params=self._auth_params(params))
            return self._check_response(response, path)
        except Exception as e:
            logger.error(f"GET {path} error for {self.server_name}: {e}")
        return None

    async def _post(self, path: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> bool:
        """POST helper; returns True on success."""
        try:
            response = await self.client.post(f"{self.url}{path}", params=self._auth_params(params), **kwargs)
            return self._check_response(response, path, 'POST') is not None
        except Exception as e:
            logger.error(f"POST {path} error for {self.server_name}: {e}")
        return False

    # ========== Authentication ==========

    async def authenticate(self) -> bool:
        """Verify the API token by fetching dashboard stats."""
        data = await self._get('/api/dashboard/stats/get', {'type': 'LastHour'})
        if data:
            logger.info(f"Authentication successful for {self.server_name}")
            return True
        logger.error(f"Authentication failed for {self.server_name}")
        return False

    # ========== Query Logs ==========

    def _map_status(self, response_type: str) -> str:
        if response_type in _BLOCKED_TYPES:
            return 'BLOCKED'
        if response_type in _CACHED_TYPES:
            return 'CACHED'
        if response_type in _ALLOWED_TYPES:
            return 'ALLOWED'
        return 'UNKNOWN'

    def _transform_query(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ts_str = raw.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            timestamp = int(ts.timestamp())
        except (ValueError, TypeError):
            logger.warning(f"Unparseable timestamp {ts_str!r} from {self.server_name}, skipping entry")
            return None

        return {
            'timestamp': timestamp,
            'domain': raw.get('qname', '').rstrip('.'),
            'client': {'ip': raw.get('clientIpAddress', ''), 'name': ''},
            'type': raw.get('qtype', ''),
            'status': self._map_status(raw.get('responseType', '')),
        }

    async def get_queries(self, from_timestamp: int, until_timestamp: int) -> Optional[List[Dict[str, Any]]]:
        """Fetch query logs from the Technitium Query Logs DNS App."""
        try:
            start_dt = datetime.fromtimestamp(from_timestamp, tz=timezone.utc)
            end_dt = datetime.fromtimestamp(until_timestamp, tz=timezone.utc)

            results: List[Dict[str, Any]] = []
            page = 1
            per_page = 5000
            max_pages = 200

            while page <= max_pages:
                data = await self._get('/api/logs/query', {
                    'name': self.log_app_name,
                    'classPath': self.log_app_class_path,
                    'pageNumber': page,
                    'entriesPerPage': per_page,
                    'start': start_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                    'end': end_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                })

                if not data:
                    if page == 1:
                        logger.error(f"Failed to fetch query logs from {self.server_name}")
                        return None
                    logger.warning(f"Failed to fetch page {page} from {self.server_name}, returning {len(results)} queries (results may be incomplete)")
                    break

                entries = data.get('response', {}).get('entries', [])
                if not entries:
                    break

                for entry in entries:
                    transformed = self._transform_query(entry)
                    if transformed is not None:
                        results.append(transformed)

                if len(entries) < per_page:
                    break
                page += 1

            if page > max_pages:
                logger.warning(f"Hit max page limit ({max_pages}) for {self.server_name}, results truncated")

            logger.info(f"Retrieved {len(results)} queries from {self.server_name}")
            return results

        except Exception as e:
            logger.error(f"Error fetching queries from {self.server_name}: {e}")
            return None

    # ========== Blocking Control ==========

    async def get_blocking_status(self) -> Optional[bool]:
        data = await self._get('/api/settings/get')
        if data:
            return bool(data.get('response', {}).get('enableBlocking', False))
        return None

    async def set_blocking(self, enabled: bool, timer: Optional[int] = None) -> bool:
        try:
            if not enabled and timer is not None:
                minutes = max(1, (timer + 59) // 60)
                data = await self._get('/api/settings/temporaryDisableBlocking', {'minutes': minutes})
                if data:
                    logger.info(f"Blocking temporarily disabled for {minutes} min on {self.server_name}")
                    return True
                return False

            data = await self._get('/api/settings/set', {'enableBlocking': str(enabled).lower()})
            if data:
                action = 'enabled' if enabled else 'disabled'
                logger.info(f"Blocking {action} on {self.server_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error setting blocking on {self.server_name}: {e}")
            return False

    # ========== Domain Lists (Blocked/Allowed Zones) ==========

    async def get_whitelist(self) -> List[Dict[str, Any]]:
        return await self._get_zone_list('/api/zones/allowed/list')

    async def get_blacklist(self) -> List[Dict[str, Any]]:
        return await self._get_zone_list('/api/zones/blocked/list')

    async def _get_zone_list(self, endpoint: str) -> List[Dict[str, Any]]:
        data = await self._get(endpoint)
        if data:
            zones = data.get('response', {}).get('zones', [])
            return [
                {'domain': z['name'], 'enabled': not z.get('disabled', False)}
                for z in zones if z.get('name')
            ]
        return []

    async def add_to_whitelist(self, domain: str) -> bool:
        data = await self._get('/api/zones/allowed/add', {'zone': domain})
        if data:
            logger.info(f"Added {domain} to allowed zones on {self.server_name}")
            return True
        return False

    async def add_to_blacklist(self, domain: str) -> bool:
        data = await self._get('/api/zones/blocked/add', {'zone': domain})
        if data:
            logger.info(f"Added {domain} to blocked zones on {self.server_name}")
            return True
        return False

    async def remove_from_whitelist(self, domain: str) -> bool:
        data = await self._get('/api/zones/allowed/delete', {'zone': domain})
        if data:
            logger.info(f"Removed {domain} from allowed zones on {self.server_name}")
            return True
        return False

    async def remove_from_blacklist(self, domain: str) -> bool:
        data = await self._get('/api/zones/blocked/delete', {'zone': domain})
        if data:
            logger.info(f"Removed {domain} from blocked zones on {self.server_name}")
            return True
        return False

    # ========== Backup / Restore (Sync) ==========

    async def get_teleporter(self) -> Optional[bytes]:
        """Download full Technitium backup as a zip file."""
        try:
            response = await self.client.get(
                f"{self.url}/api/settings/backup",
                params=self._auth_params()
            )
            if response.status_code == 200:
                logger.info(f"Downloaded backup from {self.server_name} ({len(response.content)} bytes)")
                return response.content
            logger.error(f"Failed to get backup from {self.server_name}: HTTP {response.status_code} - {response.text[:200]}")
            return None
        except Exception as e:
            logger.error(f"Error getting backup from {self.server_name}: {e}")
            return None

    async def post_teleporter(self, backup_data: bytes, import_options: Optional[Dict[str, Any]] = None) -> bool:
        """Restore a Technitium backup zip."""
        try:
            response = await self.client.post(
                f"{self.url}/api/settings/restore",
                params=self._auth_params(),
                files={'file': ('backup.zip', backup_data, 'application/zip')}
            )
            if response.status_code == 200 and response.json().get('status') == 'ok':
                logger.info(f"Restored backup to {self.server_name}")
                return True
            logger.error(f"Failed to restore backup to {self.server_name}: HTTP {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error restoring backup to {self.server_name}: {e}")
            return False

    # ========== Config (for sync summary) ==========

    async def get_config(self) -> Optional[Dict[str, Any]]:
        """Get Technitium settings for sync summary."""
        data = await self._get('/api/settings/get')
        if data:
            return data.get('response', {})
        return None

    async def patch_config(self, config: Dict[str, Any]) -> bool:
        """No-op — Technitium sync uses backup/restore, not config patching."""
        return True

    async def run_gravity(self) -> bool:
        """Force-update Technitium blocklists."""
        data = await self._get('/api/settings/forceUpdateBlockLists')
        if data:
            logger.info(f"Triggered blocklist update on {self.server_name}")
            return True
        return False
