import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from .models import SyncHistory, PiholeServerModel
from .database import async_session_maker
from .dns_client_factory import create_dns_client
import json

logger = logging.getLogger(__name__)


def _create_client_from_server(server: PiholeServerModel):
    """Create a DNS client from a server model"""
    return create_dns_client(
        server_type=server.server_type or 'pihole',
        url=server.url,
        password=server.password,
        server_name=server.name,
        username=server.username,
        skip_ssl_verify=server.skip_ssl_verify or False
    )


# Config keys to sync per section (only sync specific safe keys, not entire sections)
# This avoids issues with null values or device-specific settings
SYNC_CONFIG_KEYS = {
    'dns': ['hosts', 'cnameRecords', 'upstreams', 'revServers'],
    # Add more sections/keys as needed:
    # 'dhcp': ['...'],
}


class PiholeSyncService:
    """
    Service for syncing Pi-hole configurations from source to targets.

    Uses Pi-hole's Teleporter API for gravity data (lists, domains, groups, clients)
    and Config API for settings (DNS, DHCP, etc.).
    """

    def _filter_config_for_sync(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter config to only include specific keys we want to sync.
        Only syncs safe keys like dns.hosts, dns.cnameRecords, etc.
        Avoids syncing null values or device-specific settings.
        """
        filtered = {}
        for section, keys in SYNC_CONFIG_KEYS.items():
            if section in config and isinstance(config[section], dict):
                section_data = {}
                for key in keys:
                    if key in config[section]:
                        value = config[section][key]
                        # Only include non-null values
                        if value is not None:
                            section_data[key] = value
                if section_data:
                    filtered[section] = section_data
        return filtered

    def _get_config_summary(self, config: Dict[str, Any], server_type: str) -> Dict[str, Any]:
        """Get a summary of config sections for preview/history"""
        summary = {}

        if server_type == 'adguard':
            # AdGuard config summary
            if 'user_rules' in config:
                summary['user_rules'] = len(config['user_rules'])
            if 'dns' in config:
                dns = config['dns']
                if 'upstream_dns' in dns:
                    summary['upstream_dns'] = len(dns['upstream_dns'])
        else:
            # Pi-hole config summary
            for section, keys in SYNC_CONFIG_KEYS.items():
                if section in config and isinstance(config[section], dict):
                    section_data = config[section]
                    for key in keys:
                        if key in section_data:
                            value = section_data[key]
                            if isinstance(value, list):
                                summary[f'{section}_{key}'] = len(value)

        return summary

    async def _get_preview_for_source(self, source: PiholeServerModel, targets: List[PiholeServerModel]) -> Dict[str, Any]:
        """Get sync preview for a single source and its targets."""
        source_type = source.server_type or 'pihole'

        if not targets:
            return {
                'source': source.to_dict(),
                'targets': [],
                'teleporter': {},
                'config': {},
                'message': f'No {source_type} target servers configured for sync'
            }

        # Connect to source and get preview data
        async with _create_client_from_server(source) as client:
            if not client.supports_sync:
                return {'source': source.to_dict(), 'error': f'Server {source.name} does not support sync'}

            if not await client.authenticate():
                logger.error(f"Failed to authenticate with source {source.name}")
                return {'source': source.to_dict(), 'error': f'Failed to authenticate with source {source.name}'}

            # Get teleporter backup size (Pi-hole only)
            teleporter_data = None
            teleporter_size = 0
            if client.supports_teleporter:
                teleporter_data = await client.get_teleporter()
                teleporter_size = len(teleporter_data) if teleporter_data else 0

            # Get config
            config = await client.get_config()
            config_summary = self._get_config_summary(config, source_type) if config else {}

        preview = {
            'source': source.to_dict(),
            'targets': [t.to_dict() for t in targets],
            'config': {
                'summary': config_summary
            }
        }

        # Add teleporter info for Pi-hole
        if source_type == 'pihole':
            preview['teleporter'] = {
                'backup_size_bytes': teleporter_size,
                'includes': [
                    'groups', 'adlists', 'adlist_by_group',
                    'domainlist', 'domainlist_by_group',
                    'clients', 'client_by_group'
                ]
            }
            preview['config']['keys'] = SYNC_CONFIG_KEYS

        return preview

    async def get_sync_preview(self) -> Optional[Dict[str, Any]]:
        """
        Preview what would be synced without actually syncing.
        Supports multiple sources (one per server type).
        Returns previews for all configured source servers.
        """
        try:
            async with async_session_maker() as session:
                # Get ALL source servers (can be one per server type)
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.is_source == True,
                    PiholeServerModel.enabled == True
                )
                result = await session.execute(stmt)
                sources = result.scalars().all()

                if not sources:
                    logger.warning("No source server configured")
                    return {'error': 'No source server configured. Mark a server as "Source" in Settings.'}

                # Get all sync-enabled servers for target matching
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.sync_enabled == True,
                    PiholeServerModel.enabled == True,
                    PiholeServerModel.is_source == False
                )
                result = await session.execute(stmt)
                all_targets = result.scalars().all()

                # Group targets by server type
                targets_by_type: Dict[str, List[PiholeServerModel]] = {}
                for target in all_targets:
                    target_type = target.server_type or 'pihole'
                    if target_type not in targets_by_type:
                        targets_by_type[target_type] = []
                    targets_by_type[target_type].append(target)

                # Build preview for each source
                previews = []
                for source in sources:
                    source_type = source.server_type or 'pihole'
                    matching_targets = targets_by_type.get(source_type, [])
                    preview = await self._get_preview_for_source(source, matching_targets)
                    previews.append(preview)

                # Return in a format that supports both single and multi-source
                # For backwards compatibility, if only one source, also include top-level fields
                if len(previews) == 1:
                    # Use spread to create new dict to avoid circular reference
                    return {**previews[0], 'sources': previews}
                else:
                    return {
                        'sources': previews,
                        'message': f'{len(previews)} source servers configured'
                    }

        except Exception as e:
            logger.error(f"Error previewing sync: {e}", exc_info=True)
            return {'error': str(e)}

    async def _execute_sync_for_source(
        self,
        session,
        source: PiholeServerModel,
        targets: List[PiholeServerModel],
        sync_type: str,
        run_gravity: bool
    ) -> Optional[int]:
        """Execute sync from a single source to its targets. Returns sync_history_id."""
        started_at = datetime.now(timezone.utc)
        all_errors = []
        max_errors = 100
        source_type = source.server_type or 'pihole'

        logger.info(f"Starting {sync_type} sync from {source.name} ({source_type}) to {len(targets)} targets")

        # === Phase 1: Get data from source ===
        teleporter_data = None
        source_config = None

        async with _create_client_from_server(source) as client:
            if not client.supports_sync:
                logger.error(f"Source server {source.name} does not support sync")
                return None

            if not await client.authenticate():
                logger.error(f"Failed to authenticate with source {source.name}")
                return None

            # Get teleporter backup (Pi-hole only)
            if client.supports_teleporter:
                teleporter_data = await client.get_teleporter()
                if not teleporter_data:
                    logger.error(f"Failed to get teleporter backup from {source.name}")
                    all_errors.append("Failed to get teleporter backup from source")

            # Get config (both Pi-hole and AdGuard)
            source_config = await client.get_config()
            if not source_config:
                logger.error(f"Failed to get config from {source.name}")
                all_errors.append("Failed to get config from source")

        # For Pi-hole, we need either teleporter or config. For AdGuard, just config.
        if source_type == 'pihole' and not teleporter_data and not source_config:
            logger.error("Failed to get any data from Pi-hole source")
            return None
        elif source_type == 'adguard' and not source_config:
            logger.error("Failed to get config from AdGuard source")
            return None

        # Filter config to syncable sections (Pi-hole only, AdGuard sends full config)
        if source_type == 'pihole':
            sync_config = self._filter_config_for_sync(source_config) if source_config else {}
        else:
            sync_config = source_config

        # === Phase 2: Push to targets ===
        successful_syncs = 0
        target_server_ids = [t.id for t in targets]

        for target in targets:
            logger.info(f"Syncing to {target.name}...")
            target_success = True

            try:
                async with _create_client_from_server(target) as client:
                    if not await client.authenticate():
                        error_msg = f"Failed to authenticate with {target.name}"
                        logger.error(error_msg)
                        all_errors.append(error_msg)
                        continue

                    # Push teleporter backup (Pi-hole only)
                    if teleporter_data and client.supports_teleporter:
                        if not await client.post_teleporter(teleporter_data):
                            error_msg = f"{target.name}: Failed to upload teleporter backup"
                            logger.error(error_msg)
                            if len(all_errors) < max_errors:
                                all_errors.append(error_msg)
                            target_success = False

                    # Push config
                    if sync_config:
                        if not await client.patch_config(sync_config):
                            error_msg = f"{target.name}: Failed to apply config"
                            logger.error(error_msg)
                            if len(all_errors) < max_errors:
                                all_errors.append(error_msg)
                            target_success = False

                    # Run gravity update
                    if run_gravity:
                        if not await client.run_gravity():
                            error_msg = f"{target.name}: Failed to run gravity"
                            logger.warning(error_msg)
                            if len(all_errors) < max_errors:
                                all_errors.append(error_msg)
                            # Don't fail the whole sync for gravity failure

                    if target_success:
                        logger.info(f"Successfully synced to {target.name}")
                        successful_syncs += 1
                        target.last_synced_at = datetime.now(timezone.utc)

            except Exception as e:
                error_msg = f"Error syncing to {target.name}: {str(e)[:500]}"
                logger.error(error_msg, exc_info=True)
                if len(all_errors) < max_errors:
                    all_errors.append(error_msg)

        # === Phase 3: Record history ===
        if successful_syncs == len(targets) and not all_errors:
            status = 'success'
        elif successful_syncs > 0:
            status = 'partial'
        else:
            status = 'failed'

        # Build items_synced summary (counts only, for display)
        items_synced = {}
        if source_config:
            items_synced.update(self._get_config_summary(source_config, source_type))
        # Add metadata separately (not counted in "items" total)
        items_synced['_teleporter_size_bytes'] = len(teleporter_data) if teleporter_data else 0
        items_synced['_config_sections'] = list(sync_config.keys()) if sync_config else []
        items_synced['_server_type'] = source_type

        sync_history = SyncHistory(
            sync_type=sync_type,
            source_server_id=source.id,
            target_server_ids=json.dumps(target_server_ids),
            status=status,
            items_synced=json.dumps(items_synced),
            errors=json.dumps(all_errors) if all_errors else None,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc)
        )
        session.add(sync_history)
        await session.flush()

        logger.info(f"Sync from {source.name} completed with status: {status} ({successful_syncs}/{len(targets)} successful)")

        return sync_history.id

    async def execute_sync(self, sync_type: str = 'manual', run_gravity: bool = False) -> Optional[List[int]]:
        """
        Execute configuration sync from all sources to their respective targets.
        Supports multiple sources (one per server type).

        For Pi-hole:
        1. Teleporter - syncs gravity database (lists, domains, groups, clients)
        2. Config PATCH - syncs settings (DNS including hosts, DHCP, etc.)

        For AdGuard Home:
        1. Config sync - syncs user rules, DNS settings, filtering config

        Args:
            sync_type: 'manual' or 'scheduled'
            run_gravity: If True, runs gravity update on Pi-hole targets after sync.

        Returns list of sync_history_ids if any successful, None if all failed.
        """
        try:
            async with async_session_maker() as session:
                # Get ALL source servers (can be one per server type)
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.is_source == True,
                    PiholeServerModel.enabled == True
                )
                result = await session.execute(stmt)
                sources = result.scalars().all()

                if not sources:
                    logger.error("No source server configured")
                    return None

                # Get all sync-enabled target servers
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.sync_enabled == True,
                    PiholeServerModel.enabled == True,
                    PiholeServerModel.is_source == False
                )
                result = await session.execute(stmt)
                all_targets = result.scalars().all()

                # Group targets by server type
                targets_by_type: Dict[str, List[PiholeServerModel]] = {}
                for target in all_targets:
                    target_type = target.server_type or 'pihole'
                    if target_type not in targets_by_type:
                        targets_by_type[target_type] = []
                    targets_by_type[target_type].append(target)

                # Execute sync for each source
                sync_history_ids = []
                for source in sources:
                    source_type = source.server_type or 'pihole'
                    matching_targets = targets_by_type.get(source_type, [])

                    if not matching_targets:
                        logger.info(f"No {source_type} target servers to sync to from {source.name}")
                        continue

                    history_id = await self._execute_sync_for_source(
                        session, source, matching_targets, sync_type, run_gravity
                    )
                    if history_id:
                        sync_history_ids.append(history_id)

                await session.commit()

                if sync_history_ids:
                    logger.info(f"Completed {len(sync_history_ids)} sync operation(s)")
                    return sync_history_ids
                else:
                    logger.warning("No sync operations completed successfully")
                    return None

        except Exception as e:
            logger.error(f"Error executing sync: {e}", exc_info=True)
            return None

    async def get_sync_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent sync history"""
        try:
            async with async_session_maker() as session:
                stmt = (
                    select(SyncHistory)
                    .order_by(SyncHistory.started_at.desc())
                    .limit(limit)
                )
                result = await session.execute(stmt)
                history = result.scalars().all()

                return [h.to_dict() for h in history]

        except Exception as e:
            logger.error(f"Error fetching sync history: {e}", exc_info=True)
            return []
