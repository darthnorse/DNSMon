"""Shared constants for DNSMon."""

import re

BLOCKED_STATUSES = frozenset({
    'GRAVITY', 'GRAVITY_CNAME',
    'REGEX', 'REGEX_CNAME',
    'BLACKLIST', 'BLACKLIST_CNAME', 'REGEX_BLACKLIST',
    'EXTERNAL_BLOCKED_IP', 'EXTERNAL_BLOCKED_NULL', 'EXTERNAL_BLOCKED_NXRA',
    'BLOCKED',
})

CACHE_STATUSES = frozenset({'CACHE', 'CACHE_STALE', 'CACHED'})


def _sql_in(values: frozenset[str]) -> str:
    """Render a frozenset of identifiers as a SQL `IN (...)` body."""
    return ','.join(f"'{s}'" for s in sorted(values))


# Pre-rendered SQL `IN (...)` fragments for raw-SQL contexts (e.g., backfill).
# Sorted for stable output. Values are hardcoded identifiers — no user input.
BLOCKED_SQL_IN = _sql_in(BLOCKED_STATUSES)
CACHE_SQL_IN = _sql_in(CACHE_STATUSES)

# Defensive: if anyone ever moves the source sets to user-controlled storage,
# the rendered SQL fragments stop being safe to interpolate. This assert fails
# loudly at import time if the strings ever contain anything but uppercase
# identifiers — drift becomes an immediate boot failure, not a SQL injection.
_SQL_IN_SAFE = re.compile(r"^'[A-Z_][A-Z0-9_]*'(,'[A-Z_][A-Z0-9_]*')*$")
assert _SQL_IN_SAFE.match(BLOCKED_SQL_IN), f"BLOCKED_SQL_IN not safe: {BLOCKED_SQL_IN}"
assert _SQL_IN_SAFE.match(CACHE_SQL_IN), f"CACHE_SQL_IN not safe: {CACHE_SQL_IN}"
