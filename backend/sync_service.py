import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy import select

from .models import SyncHistory, PiholeServerModel
from .database import async_session_maker
from .utils import create_client_from_server as _create_client_from_server

logger = logging.getLogger(__name__)

_sync_lock = asyncio.Lock()


# Pi-hole config paths that are never synced. Everything else is, so settings added
# in new FTL releases sync by default. Entries match the path itself and anything below it.
SYNC_CONFIG_DENYLIST = (
    # The target's own network identity
    'dns.interface',
    'dns.listeningMode',
    'dns.port',
    'dns.hostRecord',
    'dns.reply.host',
    'dns.reply.blocking',
    # DNSMon toggles blocking per server; a timed disable on the source must not propagate
    'dns.blocking.active',
    # Two DHCP servers handing out the same range on one LAN conflict
    'dhcp',
    'ntp',
    # How DNSMon reaches and authenticates to the target: a copied port, ACL, TLS
    # setting or password hash would cut the target off from DNSMon
    'webserver',
    'files',
    # Would make the target reject every later PATCH
    'misc.readOnly',
    # Raw dnsmasq directives could re-add anything above (dhcp-range, interface=, ...)
    'misc.dnsmasq_lines',
    'misc.etc_dnsmasq_d',
    'debug',
)


def _is_denied(path: str) -> bool:
    return any(path == p or path.startswith(p + '.') for p in SYNC_CONFIG_DENYLIST)


def _flatten(config: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    """Flatten a plain Pi-hole config into {dotted.path: value}."""
    leaves = {}
    for key, value in config.items():
        path = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            leaves.update(_flatten(value, path))
        else:
            leaves[path] = value
    return leaves


def _flatten_detailed(config: Dict[str, Any], prefix: str = '') -> Dict[str, Dict[str, Any]]:
    """Flatten a detailed Pi-hole config (leaves carry 'value' and 'flags') into {dotted.path: leaf}."""
    leaves = {}
    for key, node in config.items():
        path = f'{prefix}.{key}' if prefix else key
        if isinstance(node, dict) and 'flags' in node:
            leaves[path] = node
        elif isinstance(node, dict):
            leaves.update(_flatten_detailed(node, path))
    return leaves


def _nest(leaves: Dict[str, Any]) -> Dict[str, Any]:
    nested: Dict[str, Any] = {}
    for path, value in leaves.items():
        *parents, last = path.split('.')
        node = nested
        for part in parents:
            node = node.setdefault(part, {})
        node[last] = value
    return nested


def _syncable_leaves(source_config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        path: value for path, value in _flatten(source_config).items()
        if value is not None and not _is_denied(path)
    }


def _teleporter_import_options(server_type: str) -> Optional[Dict[str, Any]]:
    # deleteExistingFiles is a Technitium restore flag. Pi-hole must get None so the client's
    # default import object applies: FTL skips every category an import object doesn't name,
    # so {'deleteExistingFiles': True} made Pi-hole import neither gravity nor config.
    return {'deleteExistingFiles': True} if server_type == 'technitium' else None


def _build_target_patch(source_leaves: Dict[str, Any], target_detailed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Pick the source settings the target should receive, as flat {path: value}.

    Skips keys the target's FTL version doesn't know (the PATCH would be rejected
    whole), keys locked by an environment variable on the target (same), and keys
    already equal (avoids needless dnsmasq restarts). Returns None when the target
    reported no detailed settings, so nothing could be compared.
    """
    target_leaves = _flatten_detailed(target_detailed)
    if not target_leaves:
        return None
    changes = {}
    for path, value in source_leaves.items():
        leaf = target_leaves.get(path)
        if leaf is None or leaf['flags'].get('env_var'):
            continue
        if leaf.get('value') != value:
            changes[path] = value
    return changes


async def _get_sources_and_targets(session) -> tuple:
    """Fetch enabled source servers and sync-target servers, grouped by type."""
    stmt = select(PiholeServerModel).where(
        PiholeServerModel.is_source == True,
        PiholeServerModel.enabled == True
    )
    result = await session.execute(stmt)
    sources = result.scalars().all()

    stmt = select(PiholeServerModel).where(
        PiholeServerModel.sync_enabled == True,
        PiholeServerModel.enabled == True,
        PiholeServerModel.is_source == False
    )
    result = await session.execute(stmt)
    all_targets = result.scalars().all()

    targets_by_type: Dict[str, List[PiholeServerModel]] = {}
    for target in all_targets:
        target_type = target.server_type or 'pihole'
        targets_by_type.setdefault(target_type, []).append(target)

    return sources, targets_by_type


class PiholeSyncService:
    """
    Service for syncing Pi-hole configurations from source to targets.

    Uses Pi-hole's Teleporter API for gravity data (lists, domains, groups, clients)
    and Config API for settings (everything outside SYNC_CONFIG_DENYLIST).
    """

    def _get_config_summary(self, config: Dict[str, Any], server_type: str) -> Dict[str, Any]:
        """Get a summary of config sections for preview/history"""
        summary = {}

        if server_type == 'adguard':
            for key in ('user_rules', 'rewrites', 'filters', 'whitelist_filters', 'clients'):
                if key in config:
                    summary[key] = len(config[key]) if config[key] else 0
            if 'dns' in config and config['dns']:
                dns = config['dns']
                if 'upstream_dns' in dns and dns['upstream_dns']:
                    summary['upstream_dns'] = len(dns['upstream_dns'])
        elif server_type == 'technitium':
            if config.get('blockListUrls'):
                summary['block_lists'] = len(config['blockListUrls'])
            if config.get('forwarders'):
                summary['forwarders'] = len(config['forwarders']) if isinstance(config['forwarders'], list) else 1
            summary['blocking_enabled'] = config.get('enableBlocking', False)
        else:
            for path, value in _syncable_leaves(config).items():
                if isinstance(value, list):
                    summary[path.replace('.', '_')] = len(value)

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

        async with _create_client_from_server(source) as client:
            if not client.supports_sync:
                return {'source': source.to_dict(), 'error': f'Server {source.name} does not support sync'}

            if not await client.authenticate():
                logger.error(f"Failed to authenticate with source {source.name}")
                return {'source': source.to_dict(), 'error': f'Failed to authenticate with source {source.name}'}

            teleporter_data = None
            teleporter_size = 0
            if client.supports_teleporter:
                teleporter_data = await client.get_teleporter()
                teleporter_size = len(teleporter_data) if teleporter_data else 0

            config = await client.get_config()
            config_summary = self._get_config_summary(config, source_type) if config else {}

        preview = {
            'source': source.to_dict(),
            'targets': [t.to_dict() for t in targets],
            'config': {
                'summary': config_summary
            }
        }

        if source_type in ('pihole', 'technitium'):
            preview['teleporter'] = {
                'backup_size_bytes': teleporter_size,
                'includes': ['full_backup'] if source_type == 'technitium' else [
                    'groups', 'adlists', 'adlist_by_group',
                    'domainlist', 'domainlist_by_group',
                    'clients', 'client_by_group'
                ]
            }
            if source_type == 'pihole' and config:
                leaves = _syncable_leaves(config)
                preview['config']['summary']['config_settings'] = len(leaves)
                preview['config']['keys'] = {section: list(keys) for section, keys in _nest(leaves).items()}
                preview['config']['excluded'] = list(SYNC_CONFIG_DENYLIST)

        return preview

    async def get_sync_preview(self) -> Optional[Dict[str, Any]]:
        """
        Preview what would be synced without actually syncing.
        Supports multiple sources (one per server type).
        Returns previews for all configured source servers.
        """
        try:
            async with async_session_maker() as session:
                sources, targets_by_type = await _get_sources_and_targets(session)

                if not sources:
                    logger.warning("No source server configured")
                    return {'error': 'No source server configured. Mark a server as "Source" in Settings.'}

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
            return {'error': 'Failed to generate sync preview'}

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

        teleporter_data = None
        source_config = None

        async with _create_client_from_server(source) as client:
            if not client.supports_sync:
                logger.error(f"Source server {source.name} does not support sync")
                return None

            if not await client.authenticate():
                logger.error(f"Failed to authenticate with source {source.name}")
                return None

            if client.supports_teleporter:
                teleporter_data = await client.get_teleporter()
                if not teleporter_data:
                    logger.error(f"Failed to get teleporter backup from {source.name}")
                    all_errors.append("Failed to get teleporter backup from source")

            source_config = await client.get_config()
            if not source_config:
                if source_type == 'technitium':
                    logger.warning(f"Could not fetch config summary from {source.name} (non-fatal, sync uses backup/restore)")
                else:
                    logger.error(f"Failed to get config from {source.name}")
                    all_errors.append("Failed to get config from source")

        if source_type in ('pihole', 'technitium') and not teleporter_data:
            logger.error(f"Failed to get teleporter backup from {source_type} source")
            return None
        elif source_type == 'adguard' and not source_config:
            logger.error("Failed to get config from AdGuard source")
            return None

        # Technitium syncs by backup/restore only; Pi-hole patches per target from source_leaves
        sync_config = source_config if source_type == 'adguard' else {}
        source_leaves = _syncable_leaves(source_config) if source_type == 'pihole' and source_config else {}
        config_changes: Dict[str, List[str]] = {}
        teleporter_options = _teleporter_import_options(source_type)

        def record_failure(msg: str) -> None:
            logger.error(msg)
            if len(all_errors) < max_errors:
                all_errors.append(msg)

        successful_syncs = 0
        gravity_errors: List[str] = []
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

                    if teleporter_data and client.supports_teleporter:
                        if not await client.post_teleporter(teleporter_data, import_options=teleporter_options):
                            record_failure(f"{target.name}: Failed to upload teleporter backup")
                            target_success = False

                    if source_leaves:
                        target_detailed = await client.get_config(detailed=True)
                        changes = _build_target_patch(source_leaves, target_detailed) if target_detailed else None
                        if changes is None:
                            record_failure(f"{target.name}: Failed to read config")
                            target_success = False
                        elif changes:
                            if await client.patch_config(_nest(changes)):
                                config_changes[target.name] = sorted(changes)
                            else:
                                record_failure(f"{target.name}: Failed to apply config")
                                target_success = False

                    if sync_config:
                        if not await client.patch_config(sync_config):
                            record_failure(f"{target.name}: Failed to apply config")
                            target_success = False

                    if run_gravity:
                        if not await client.run_gravity():
                            error_msg = f"{target.name}: Failed to run gravity"
                            logger.warning(error_msg)
                            gravity_errors.append(error_msg)

                    if target_success:
                        logger.info(f"Successfully synced to {target.name}")
                        successful_syncs += 1
                        target.last_synced_at = datetime.now(timezone.utc)

            except Exception as e:
                error_msg = f"Error syncing to {target.name}: {str(e)[:500]}"
                logger.error(error_msg, exc_info=True)
                if len(all_errors) < max_errors:
                    all_errors.append(error_msg)

        if successful_syncs == len(targets) and not all_errors:
            status = 'success'
        elif successful_syncs > 0:
            status = 'partial'
        else:
            status = 'failed'

        all_errors.extend(gravity_errors)

        items_synced = {}
        if source_config:
            items_synced.update(self._get_config_summary(source_config, source_type))
        items_synced['_teleporter_size_bytes'] = len(teleporter_data) if teleporter_data else 0
        if source_leaves:
            items_synced['_config_sections'] = sorted(_nest(source_leaves))
            items_synced['_config_changes'] = config_changes
        else:
            items_synced['_config_sections'] = list(sync_config.keys()) if sync_config else []
        items_synced['_server_type'] = source_type
        items_synced['_source_server_name'] = source.name
        items_synced['_target_server_names'] = [t.name for t in targets]

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
        2. Config PATCH - syncs settings outside SYNC_CONFIG_DENYLIST, only keys that differ

        For AdGuard Home:
        1. Config sync - syncs user rules, DNS settings, filtering config

        Args:
            sync_type: 'manual' or 'scheduled'
            run_gravity: If True, runs gravity update on Pi-hole targets after sync.

        Returns list of sync_history_ids if any successful, None if all failed.
        """
        if _sync_lock.locked():
            logger.warning("Sync already in progress, skipping")
            return None
        async with _sync_lock:
            try:
                async with async_session_maker() as session:
                    sources, targets_by_type = await _get_sources_and_targets(session)

                    if not sources:
                        logger.error("No source server configured")
                        return None

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

                entries = [h.to_dict() for h in history]

                server_ids_needed: set = set()
                for entry in entries:
                    if not entry.get('items_synced', {}).get('_source_server_name'):
                        server_ids_needed.add(entry['source_server_id'])
                        for tid in entry.get('target_server_ids', []):
                            server_ids_needed.add(tid)

                if server_ids_needed:
                    stmt = select(PiholeServerModel).where(PiholeServerModel.id.in_(server_ids_needed))
                    result = await session.execute(stmt)
                    name_map = {s.id: s.name for s in result.scalars()}

                    for entry in entries:
                        items = entry.get('items_synced', {})
                        if not items.get('_source_server_name'):
                            source_name = name_map.get(entry['source_server_id'])
                            if source_name:
                                items['_source_server_name'] = source_name
                                items['_target_server_names'] = [
                                    name_map[tid] for tid in entry.get('target_server_ids', [])
                                    if tid in name_map
                                ]

                return entries

        except Exception as e:
            logger.error(f"Error fetching sync history: {e}", exc_info=True)
            return []
