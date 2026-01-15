import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from .models import SyncHistory, PiholeServerModel
from .database import async_session_maker
from .pihole_client import PiholeClient
import json

logger = logging.getLogger(__name__)

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

    def _get_config_summary(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Get a summary of config sections for preview/history"""
        summary = {}
        for section, keys in SYNC_CONFIG_KEYS.items():
            if section in config and isinstance(config[section], dict):
                section_data = config[section]
                for key in keys:
                    if key in section_data:
                        value = section_data[key]
                        if isinstance(value, list):
                            summary[f'{section}_{key}'] = len(value)
        return summary

    async def get_sync_preview(self) -> Optional[Dict[str, Any]]:
        """
        Preview what would be synced without actually syncing.
        Returns source info, targets, and summary of data to sync.
        """
        try:
            async with async_session_maker() as session:
                # Get source server
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.is_source == True,
                    PiholeServerModel.enabled == True
                )
                result = await session.execute(stmt)
                source = result.scalar_one_or_none()

                if not source:
                    logger.warning("No source Pi-hole server configured")
                    return {'error': 'No source Pi-hole server configured'}

                # Get target servers
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.sync_enabled == True,
                    PiholeServerModel.enabled == True,
                    PiholeServerModel.is_source == False
                )
                result = await session.execute(stmt)
                targets = result.scalars().all()

                if not targets:
                    return {
                        'source': source.to_dict(),
                        'targets': [],
                        'teleporter': {},
                        'config': {}
                    }

                # Connect to source and get preview data
                async with PiholeClient(source.url, source.password, source.name) as client:
                    if not await client.authenticate():
                        logger.error(f"Failed to authenticate with source {source.name}")
                        return {'error': f'Failed to authenticate with source {source.name}'}

                    # Get teleporter backup size
                    teleporter_data = await client.get_teleporter()
                    teleporter_size = len(teleporter_data) if teleporter_data else 0

                    # Get config
                    config = await client.get_config()
                    config_summary = self._get_config_summary(config) if config else {}

                return {
                    'source': source.to_dict(),
                    'targets': [t.to_dict() for t in targets],
                    'teleporter': {
                        'backup_size_bytes': teleporter_size,
                        'includes': [
                            'groups', 'adlists', 'adlist_by_group',
                            'domainlist', 'domainlist_by_group',
                            'clients', 'client_by_group'
                        ]
                    },
                    'config': {
                        'keys': SYNC_CONFIG_KEYS,
                        'summary': config_summary
                    }
                }

        except Exception as e:
            logger.error(f"Error previewing sync: {e}", exc_info=True)
            return {'error': str(e)}

    async def execute_sync(self, sync_type: str = 'manual', run_gravity: bool = False) -> Optional[int]:
        """
        Execute configuration sync from source to all targets.

        Uses two-phase sync like nebula-sync:
        1. Teleporter - syncs gravity database (lists, domains, groups, clients)
        2. Config PATCH - syncs settings (DNS including hosts, DHCP, etc.)

        Args:
            sync_type: 'manual' or 'scheduled'
            run_gravity: If True, runs gravity update on targets after sync.
                         Usually not needed since Teleporter includes processed gravity data.

        Returns sync_history_id if successful, None if failed.
        """
        started_at = datetime.now(timezone.utc)
        all_errors = []
        max_errors = 100

        try:
            async with async_session_maker() as session:
                # Get source server
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.is_source == True,
                    PiholeServerModel.enabled == True
                )
                result = await session.execute(stmt)
                source = result.scalar_one_or_none()

                if not source:
                    logger.error("No source Pi-hole server configured")
                    return None

                # Get target servers
                stmt = select(PiholeServerModel).where(
                    PiholeServerModel.sync_enabled == True,
                    PiholeServerModel.enabled == True,
                    PiholeServerModel.is_source == False
                )
                result = await session.execute(stmt)
                targets = result.scalars().all()

                if not targets:
                    logger.info("No target servers to sync to")
                    return None

                logger.info(f"Starting {sync_type} sync from {source.name} to {len(targets)} targets")

                # === Phase 1: Get data from source ===
                teleporter_data = None
                source_config = None

                async with PiholeClient(source.url, source.password, source.name) as client:
                    if not await client.authenticate():
                        logger.error(f"Failed to authenticate with source {source.name}")
                        return None

                    # Get teleporter backup
                    teleporter_data = await client.get_teleporter()
                    if not teleporter_data:
                        logger.error(f"Failed to get teleporter backup from {source.name}")
                        all_errors.append(f"Failed to get teleporter backup from source")

                    # Get config
                    source_config = await client.get_config()
                    if not source_config:
                        logger.error(f"Failed to get config from {source.name}")
                        all_errors.append(f"Failed to get config from source")

                if not teleporter_data and not source_config:
                    logger.error("Failed to get any data from source")
                    return None

                # Filter config to syncable sections
                sync_config = self._filter_config_for_sync(source_config) if source_config else {}

                # === Phase 2: Push to targets ===
                successful_syncs = 0
                target_server_ids = [t.id for t in targets]

                for target in targets:
                    logger.info(f"Syncing to {target.name}...")
                    target_success = True

                    try:
                        async with PiholeClient(target.url, target.password, target.name) as client:
                            if not await client.authenticate():
                                error_msg = f"Failed to authenticate with {target.name}"
                                logger.error(error_msg)
                                all_errors.append(error_msg)
                                continue

                            # Push teleporter backup
                            if teleporter_data:
                                if not await client.post_teleporter(teleporter_data):
                                    error_msg = f"{target.name}: Failed to upload teleporter backup"
                                    logger.error(error_msg)
                                    if len(all_errors) < max_errors:
                                        all_errors.append(error_msg)
                                    target_success = False

                            # Push config
                            if sync_config:
                                if not await client.patch_config(sync_config):
                                    error_msg = f"{target.name}: Failed to patch config"
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
                    items_synced.update(self._get_config_summary(source_config))
                # Add metadata separately (not counted in "items" total)
                items_synced['_teleporter_size_bytes'] = len(teleporter_data) if teleporter_data else 0
                items_synced['_config_sections'] = list(sync_config.keys()) if sync_config else []

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
                await session.commit()
                await session.refresh(sync_history)

                logger.info(f"Sync completed with status: {status} ({successful_syncs}/{len(targets)} successful)")

                return sync_history.id

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
