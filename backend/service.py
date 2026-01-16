import asyncio
import logging
import resource
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .config import get_settings_sync
from .ingestion import QueryIngestionService
from .alerts import AlertEngine
from .notifications import NotificationService, AlertContext
from .sync_service import PiholeSyncService
from .auth import cleanup_expired_sessions
from .database import async_session_maker

logger = logging.getLogger(__name__)
memory_logger = logging.getLogger('dnsmon.memory')


class DNSMonService:
    """Main service orchestrator"""

    def __init__(self):
        self.settings = get_settings_sync()
        self.scheduler = AsyncIOScheduler()
        self.ingestion_service = QueryIngestionService()
        self.alert_engine = AlertEngine()
        self.notification_service = NotificationService()
        self.sync_service = PiholeSyncService()
        self._started = False  # Track if service has been started
        self._initial_ingestion_task = None  # Track initial ingestion task

    async def ingest_and_alert(self):
        """Poll Pihole servers and check for alerts"""
        try:
            logger.info("Starting ingestion and alert check...")

            # Ingest queries from all servers
            count, ingested_queries = await self.ingestion_service.ingest_from_all_servers()
            logger.info(f"Ingested {count} queries")

            # Check ingested queries directly against alert rules (no extra DB query)
            matches = await self.alert_engine.evaluate_queries(ingested_queries)

            if matches:
                logger.info(f"Found {len(matches)} query matches for alert rules")

                # Group matches by rule_id for batching
                from collections import defaultdict
                matches_by_rule = defaultdict(list)
                for query, rule_ids in matches:
                    for rule_id in rule_ids:
                        matches_by_rule[rule_id].append(query)

                # Process each rule's matches as a batch
                async def process_rule_batch(rule_id, queries):
                    """Process all matches for a rule as a batch"""
                    try:
                        rule = await self.alert_engine.get_rule_by_id(rule_id)
                        if not rule:
                            return

                        # Check cooldown (only once per rule, not per query)
                        if await self.alert_engine._is_in_cooldown(rule_id, rule.cooldown_minutes):
                            logger.debug(f"Rule {rule.name} is in cooldown, skipping batch")
                            return

                        # Get query ID for alert history (lookup if using IngestedQuery with id=0)
                        first_query = queries[0]
                        query_id = first_query.id
                        if query_id == 0:
                            query_id = await self.alert_engine.lookup_query_id(first_query)
                            if not query_id:
                                logger.warning(f"Could not find query ID for alert history")
                                query_id = 0  # Proceed anyway, alert history will have 0

                        # Record alert for first query in batch (for history tracking)
                        alert_history_id = await self.alert_engine.try_record_alert(
                            query_id=query_id,
                            rule_id=rule_id,
                            cooldown_minutes=rule.cooldown_minutes
                        )

                        if alert_history_id:
                            # Send batched notification to all enabled channels
                            results = await self.notification_service.send_batch_alert(queries, rule)
                            # Consider notification successful if at least one channel succeeded
                            success = any(results.values()) if results else False

                            # Update alert status
                            await self.alert_engine.update_alert_status(
                                alert_history_id=alert_history_id,
                                notification_sent=success
                            )
                    except Exception as e:
                        logger.error(f"Error processing batch alert for rule {rule_id}: {e}", exc_info=True)

                # Process all rule batches in parallel
                tasks = [process_rule_batch(rule_id, queries) for rule_id, queries in matches_by_rule.items()]
                await asyncio.gather(*tasks, return_exceptions=True)

            # Log memory usage to dedicated file (persists across container restarts)
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            memory_logger.info(f"RSS: {rusage.ru_maxrss / 1024:.1f} MB | queries_ingested: {count}")

        except Exception as e:
            logger.error(f"Error in ingest_and_alert: {e}", exc_info=True)
            # Still log memory on error
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            memory_logger.info(f"RSS: {rusage.ru_maxrss / 1024:.1f} MB | error: {str(e)[:100]}")

    async def cleanup_task(self):
        """Periodic cleanup of old data"""
        try:
            logger.info("Running cleanup task...")
            deleted = await self.ingestion_service.cleanup_old_data()
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old queries")
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}", exc_info=True)

    async def sync_task(self):
        """Periodic sync from source to target Pi-holes"""
        try:
            logger.info("Running Pi-hole configuration sync...")
            sync_history_id = await self.sync_service.execute_sync(sync_type='automatic')
            if sync_history_id:
                logger.info(f"Sync completed successfully (history ID: {sync_history_id})")
            else:
                logger.debug("No sync performed (no source or targets configured)")
        except Exception as e:
            logger.error(f"Error in sync task: {e}", exc_info=True)

    async def session_cleanup_task(self):
        """Periodic cleanup of expired sessions"""
        try:
            async with async_session_maker() as db:
                deleted = await cleanup_expired_sessions(db)
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} expired sessions")
        except Exception as e:
            logger.error(f"Error in session cleanup task: {e}", exc_info=True)

    def start_scheduler(self):
        """Start background scheduler"""
        # Schedule ingestion and alerting
        self.scheduler.add_job(
            self.ingest_and_alert,
            trigger=IntervalTrigger(seconds=self.settings.poll_interval_seconds),
            id='ingest_and_alert',
            name='Ingest queries and check alerts',
            replace_existing=True,
            max_instances=1,  # Prevent job overlap if previous run is slow
            coalesce=True,    # Combine missed runs into one
            misfire_grace_time=30  # Skip if more than 30s late
        )

        # Schedule daily cleanup
        self.scheduler.add_job(
            self.cleanup_task,
            trigger=IntervalTrigger(hours=24),
            id='cleanup',
            name='Cleanup old queries',
            replace_existing=True,
            max_instances=1,
            coalesce=True
        )

        # Schedule Pi-hole configuration sync (separate from query ingestion)
        self.scheduler.add_job(
            self.sync_task,
            trigger=IntervalTrigger(seconds=self.settings.sync_interval_seconds),
            id='sync',
            name='Sync Pi-hole configurations',
            replace_existing=True,
            max_instances=1,
            coalesce=True
        )

        # Schedule session cleanup (hourly)
        self.scheduler.add_job(
            self.session_cleanup_task,
            trigger=IntervalTrigger(hours=1),
            id='session_cleanup',
            name='Cleanup expired sessions',
            replace_existing=True,
            max_instances=1,
            coalesce=True
        )

        self.scheduler.start()
        logger.info(f"Scheduler started (poll: {self.settings.poll_interval_seconds}s, sync: {self.settings.sync_interval_seconds}s)")

    async def _run_initial_ingestion(self):
        """Run initial ingestion with error handling"""
        try:
            await self.ingest_and_alert()
        except Exception as e:
            logger.error(f"Error in initial ingestion: {e}", exc_info=True)

    async def startup(self):
        """Run on application startup (idempotent)"""
        if self._started:
            logger.warning("Service already started, ignoring duplicate startup call")
            return

        logger.info("Starting DNSMon service...")

        # Start scheduler
        self.start_scheduler()

        # Run initial ingestion with error handling and task tracking
        self._initial_ingestion_task = asyncio.create_task(self._run_initial_ingestion())

        # Add callback to log any unhandled exceptions
        def _handle_initial_ingestion_done(task):
            try:
                # This will raise if the task failed
                task.result()
            except Exception as e:
                logger.error(f"Initial ingestion task failed: {e}", exc_info=True)

        self._initial_ingestion_task.add_done_callback(_handle_initial_ingestion_done)

        self._started = True
        logger.info("DNSMon service started successfully")

    async def shutdown(self):
        """Run on application shutdown"""
        logger.info("Shutting down DNSMon service...")

        # Cancel initial ingestion task if still running
        if self._initial_ingestion_task and not self._initial_ingestion_task.done():
            self._initial_ingestion_task.cancel()
            try:
                await self._initial_ingestion_task
            except asyncio.CancelledError:
                logger.info("Initial ingestion task cancelled")

        # Shutdown scheduler
        self.scheduler.shutdown()

        # Clear alert engine caches to free memory
        await self.alert_engine.invalidate_cache()

        self._started = False
        logger.info("DNSMon service shut down")


# Global service instance
_service = None


def get_service() -> DNSMonService:
    """Get or create the global service instance"""
    global _service
    if _service is None:
        _service = DNSMonService()
    return _service
