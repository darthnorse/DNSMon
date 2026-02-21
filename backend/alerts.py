import logging
import json
import re
import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict
from sqlalchemy import select, and_
from .models import Query, AlertRule, AlertHistory
from .database import async_session_maker

logger = logging.getLogger(__name__)


class AlertEngine:
    """Engine for evaluating alert rules and triggering notifications"""

    def __init__(self):
        # Per-rule locks to prevent race conditions in alert recording
        # Using a bounded cache to prevent unbounded memory growth
        self._rule_locks: OrderedDict[int, asyncio.Lock] = OrderedDict()
        self._locks_lock = asyncio.Lock()  # Protects the _rule_locks dict itself
        self._max_locks = 1000  # Max number of locks to keep in memory

        # Regex pattern cache: rule_id -> {field: compiled_patterns}
        # Using OrderedDict with LRU eviction to prevent unbounded memory growth
        self._pattern_cache: OrderedDict[int, Dict[str, List[re.Pattern]]] = OrderedDict()
        self._cache_lock = asyncio.Lock()  # Protects pattern cache
        self._max_pattern_cache = 500  # Max number of rules to cache patterns for

    async def _get_rule_lock(self, rule_id: int) -> asyncio.Lock:
        """Get or create a lock for a specific rule ID"""
        async with self._locks_lock:
            # Move to end if exists (LRU behavior)
            if rule_id in self._rule_locks:
                self._rule_locks.move_to_end(rule_id)
                return self._rule_locks[rule_id]

            lock = asyncio.Lock()
            self._rule_locks[rule_id] = lock

            if len(self._rule_locks) > self._max_locks:
                oldest_id, _ = self._rule_locks.popitem(last=False)
                logger.debug(f"Evicted lock for rule_id {oldest_id} (LRU cache full)")

            return lock

    def _normalize_pattern(self, pattern: str) -> str:
        """
        Normalize a pattern by adding wildcards if not present.
        - "google" -> "*google*"
        - "*google" -> "*google*"
        - "*.google.com" -> "*.google.com" (already has wildcards)
        """
        pattern = pattern.strip()
        if not pattern:
            return pattern

        # Only add wildcards if none exist
        if '*' not in pattern and '?' not in pattern:
            pattern = f'*{pattern}*'

        return pattern

    def _compile_patterns(self, pattern_string: Optional[str]) -> List[re.Pattern]:
        """
        Compile comma-separated patterns into regex objects.
        Each pattern is normalized (auto-wildcard) and compiled.
        Returns list of compiled regex patterns.
        """
        if not pattern_string:
            return []

        patterns = []
        for pattern in pattern_string.split(','):
            pattern = pattern.strip()
            if not pattern:
                continue

            pattern = self._normalize_pattern(pattern)

            # ReDoS protection: limit wildcards and pattern complexity
            wildcard_count = pattern.count('*') + pattern.count('?')
            if wildcard_count > 10:
                logger.warning(f"Pattern '{pattern}' has too many wildcards ({wildcard_count}), limiting to prevent ReDoS")
                continue

            if len(pattern) > 1000:
                logger.warning(f"Pattern '{pattern}' is too long ({len(pattern)} chars), limiting to prevent ReDoS")
                pattern = pattern[:1000]

            regex_pattern = re.escape(pattern)
            regex_pattern = regex_pattern.replace(r'\*', '.*?')  # Use non-greedy matching
            regex_pattern = regex_pattern.replace(r'\?', '.')
            regex_pattern = f'^{regex_pattern}$'

            try:
                compiled = re.compile(regex_pattern, re.IGNORECASE)
                patterns.append(compiled)
            except re.error as e:
                logger.error(f"Invalid pattern '{pattern}': {e}")
                continue

        return patterns

    async def _get_cached_patterns(self, rule: AlertRule) -> Dict[str, List[re.Pattern]]:
        """
        Get or compile patterns for a rule.
        Returns dict with 'domain', 'client_ip', 'client_hostname' keys.
        Uses LRU eviction to prevent unbounded memory growth.
        """
        async with self._cache_lock:
            # Check cache - move to end if exists (LRU behavior)
            if rule.id in self._pattern_cache:
                self._pattern_cache.move_to_end(rule.id)
                return self._pattern_cache[rule.id]

            cached = {
                'domain': self._compile_patterns(rule.domain_pattern),
                'client_ip': self._compile_patterns(rule.client_ip_pattern),
                'client_hostname': self._compile_patterns(rule.client_hostname_pattern),
            }
            self._pattern_cache[rule.id] = cached

            if len(self._pattern_cache) > self._max_pattern_cache:
                oldest_id, _ = self._pattern_cache.popitem(last=False)
                logger.debug(f"Evicted pattern cache for rule_id {oldest_id} (LRU cache full)")

            return cached

    def _should_exclude(self, domain: str, exclude_domains: Optional[str]) -> bool:
        """
        Check if domain should be excluded.
        Now accepts comma-separated patterns (legacy JSON still supported).
        Each exclusion pattern does substring matching.
        """
        if not exclude_domains:
            return False

        excludes = []

        # Try JSON first for backwards compatibility
        if exclude_domains.strip().startswith('['):
            try:
                excludes = json.loads(exclude_domains)
                if not isinstance(excludes, list):
                    return False
            except json.JSONDecodeError:
                logger.error(f"Invalid exclude_domains JSON: {exclude_domains}")
                return False
        else:
            # Comma-separated format (new default)
            excludes = [e.strip() for e in exclude_domains.split(',') if e.strip()]

        domain_lower = domain.lower()
        for exclude in excludes:
            if str(exclude).lower() in domain_lower:
                return True

        return False

    def _matches_compiled_patterns(self, value: Optional[str], patterns: List[re.Pattern]) -> bool:
        """Check if value matches any of the compiled regex patterns"""
        if not patterns or not value:
            return not patterns  # No patterns = match all

        for pattern in patterns:
            if pattern.fullmatch(value):
                return True
        return False

    def _evaluate_query_against_rules(
        self,
        query: Query,
        rules: List[AlertRule],
        cached_patterns: Dict[int, Dict[str, List[re.Pattern]]]
    ) -> List[int]:
        """
        Evaluate a query against a list of alert rules (no DB access).
        Uses pre-compiled cached patterns for performance.
        Returns list of matching rule IDs.
        """
        matching_rules = []

        for rule in rules:
            # Check exclusions first
            if self._should_exclude(query.domain, rule.exclude_domains):
                continue

            # Get cached patterns for this rule
            patterns = cached_patterns.get(rule.id, {})

            # Check if query matches rule patterns
            matches = True

            domain_patterns = patterns.get('domain', [])
            if domain_patterns:
                if not self._matches_compiled_patterns(query.domain, domain_patterns):
                    matches = False

            if matches:
                ip_patterns = patterns.get('client_ip', [])
                if ip_patterns:
                    if not self._matches_compiled_patterns(query.client_ip, ip_patterns):
                        matches = False

            if matches:
                hostname_patterns = patterns.get('client_hostname', [])
                if hostname_patterns:
                    if not self._matches_compiled_patterns(query.client_hostname, hostname_patterns):
                        matches = False

            if matches:
                matching_rules.append(rule.id)

        return matching_rules

    async def _is_in_cooldown(self, rule_id: int, cooldown_minutes: int) -> bool:
        """Check if a rule is in cooldown period"""
        if cooldown_minutes <= 0:
            return False

        cooldown_start = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)

        try:
            async with async_session_maker() as session:
                stmt = select(AlertHistory).where(
                    and_(
                        AlertHistory.alert_rule_id == rule_id,
                        AlertHistory.triggered_at >= cooldown_start
                    )
                ).limit(1)

                result = await session.execute(stmt)
                last_alert = result.scalar_one_or_none()

                return last_alert is not None
        except Exception as e:
            logger.error(f"Error checking cooldown for rule {rule_id}: {e}", exc_info=True)
            # In case of error, assume not in cooldown to avoid missing alerts
            return False

    async def try_record_alert(self, query_id: int, rule_id: int, cooldown_minutes: int) -> Optional[int]:
        """
        Try to record an alert atomically.
        Returns alert_history_id if successful, None if in cooldown.
        Uses per-rule locking to prevent race conditions.
        """
        # Get rule-specific lock to prevent concurrent checks for the same rule
        rule_lock = await self._get_rule_lock(rule_id)

        async with rule_lock:
            # Now we have exclusive access for this rule
            try:
                async with async_session_maker() as session:
                    if cooldown_minutes > 0:
                        cooldown_start = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
                        stmt = select(AlertHistory).where(
                            and_(
                                AlertHistory.alert_rule_id == rule_id,
                                AlertHistory.triggered_at >= cooldown_start
                            )
                        ).limit(1)

                        result = await session.execute(stmt)
                        last_alert = result.scalar_one_or_none()

                        if last_alert is not None:
                            return None  # In cooldown

                    alert_history = AlertHistory(
                        alert_rule_id=rule_id,
                        query_id=query_id,
                        notification_sent=False,  # Will be updated after sending
                        notification_error=None,
                    )
                    session.add(alert_history)
                    await session.commit()
                    await session.refresh(alert_history)

                    return alert_history.id
            except Exception as e:
                logger.error(f"Error recording alert for query {query_id}, rule {rule_id}: {e}", exc_info=True)
                return None

    async def update_alert_status(self, alert_history_id: int, notification_sent: bool, error: Optional[str] = None):
        """Update alert notification status after attempting to send"""
        try:
            async with async_session_maker() as session:
                stmt = select(AlertHistory).where(AlertHistory.id == alert_history_id)
                result = await session.execute(stmt)
                alert = result.scalar_one_or_none()

                if alert:
                    alert.notification_sent = notification_sent
                    alert.notification_error = error
                    await session.commit()
        except Exception as e:
            logger.error(f"Error updating alert status for alert_history_id {alert_history_id}: {e}", exc_info=True)

    async def check_recent_queries(self, minutes: int = 5):
        """
        Check recent queries for alert matches.
        Returns list of (query, rule_ids) tuples.
        Optimized with regex caching and batch processing.
        Memory-bounded with limits on both queries processed and matches returned.
        """
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        # Memory limits
        batch_size = 500  # Smaller batches to reduce peak memory
        max_queries = 10000  # Max queries to process
        max_matches = 1000  # Max matches to return (prevents unbounded growth)

        try:
            async with async_session_maker() as session:
                rules_stmt = select(AlertRule).where(AlertRule.enabled == True)
                rules_result = await session.execute(rules_stmt)
                rules = rules_result.scalars().all()

                if not rules:
                    return []  # No rules to check

                cached_patterns = {}
                for rule in rules:
                    cached_patterns[rule.id] = await self._get_cached_patterns(rule)

                matches = []
                offset = 0
                queries_processed = 0

                while queries_processed < max_queries and len(matches) < max_matches:
                    stmt = (
                        select(Query)
                        .where(Query.timestamp >= since)
                        .order_by(Query.timestamp.desc())
                        .limit(batch_size)
                        .offset(offset)
                    )
                    result = await session.execute(stmt)
                    queries = result.scalars().all()

                    if not queries:
                        break  # No more queries

                    for query in queries:
                        rule_ids = self._evaluate_query_against_rules(query, rules, cached_patterns)
                        if rule_ids:
                            matches.append((query, rule_ids))
                            if len(matches) >= max_matches:
                                logger.warning(f"Reached matches limit ({max_matches}), stopping evaluation")
                                break

                    queries_processed += len(queries)
                    offset += batch_size

                if queries_processed >= max_queries:
                    logger.warning(f"Reached query processing limit ({max_queries} queries)")

                # Expunge matched queries so they remain usable after session closes
                # This detaches them from the session while preserving their loaded attributes
                for query, _ in matches:
                    session.expunge(query)

                return matches
        except Exception as e:
            logger.error(f"Error checking recent queries: {e}", exc_info=True)
            return []

    async def evaluate_queries(self, queries: List) -> List[tuple]:
        """
        Evaluate provided queries against alert rules (no DB query for queries).
        Takes IngestedQuery objects from ingestion.
        Returns list of (query, rule_ids) tuples for matches.
        """
        if not queries:
            return []

        max_matches = 1000  # Prevent unbounded growth

        try:
            async with async_session_maker() as session:
                # Get all enabled alert rules
                rules_stmt = select(AlertRule).where(AlertRule.enabled == True)
                rules_result = await session.execute(rules_stmt)
                rules = rules_result.scalars().all()

                if not rules:
                    return []

                # Compile patterns for all rules (cached)
                cached_patterns = {}
                for rule in rules:
                    cached_patterns[rule.id] = await self._get_cached_patterns(rule)

                matches = []

                # Evaluate each query against all rules
                for query in queries:
                    if len(matches) >= max_matches:
                        logger.warning(f"Reached matches limit ({max_matches}), stopping evaluation")
                        break

                    rule_ids = self._evaluate_query_against_rules(query, rules, cached_patterns)
                    if rule_ids:
                        matches.append((query, rule_ids))

                return matches

        except Exception as e:
            logger.error(f"Error evaluating queries: {e}", exc_info=True)
            return []

    async def invalidate_cache(self, rule_id: Optional[int] = None):
        """
        Invalidate pattern cache for a specific rule or all rules.
        Call this when rules are created/updated/deleted.
        """
        async with self._cache_lock:
            if rule_id is None:
                # Clear entire cache
                self._pattern_cache.clear()
                logger.debug("Cleared entire pattern cache")
            else:
                # Clear specific rule
                if rule_id in self._pattern_cache:
                    del self._pattern_cache[rule_id]
                    logger.debug(f"Cleared pattern cache for rule {rule_id}")

    async def get_rule_by_id(self, rule_id: int) -> Optional[AlertRule]:
        """Get alert rule by ID"""
        async with async_session_maker() as session:
            stmt = select(AlertRule).where(AlertRule.id == rule_id)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def lookup_query_id(self, query) -> Optional[int]:
        """Look up a query's database ID by its unique fields.
        Works with both Query objects and IngestedQuery dataclass instances.
        """
        try:
            async with async_session_maker() as session:
                stmt = select(Query.id).where(
                    and_(
                        Query.timestamp == query.timestamp,
                        Query.domain == query.domain,
                        Query.client_ip == query.client_ip,
                        Query.server == query.server
                    )
                ).limit(1)
                result = await session.execute(stmt)
                return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error looking up query ID: {e}", exc_info=True)
            return None
