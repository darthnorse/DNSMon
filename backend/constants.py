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

# ---------------------------------------------------------------------------
# Domain classification (apps / categories)
# ---------------------------------------------------------------------------

# AdGuard's blocked-services list (GPL-3.0). Fetched at runtime, never bundled.
CLASSIFICATION_FEED_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry"
    "/main/assets/services.json"
)

# Our own curated shadow-IT app list (MIT), hosted in this repo and fetched at
# runtime so it updates without a redeploy. The bundled copy is the offline fallback.
DNSMON_LIST_URL = (
    "https://raw.githubusercontent.com/darthnorse/DNSMon"
    "/main/backend/data/dnsmon.json"
)

# Higher number wins when more than one source claims a domain.
SOURCE_PRECEDENCE = {'blocklist': 0, 'adguard': 1, 'dnsmon': 2, 'manual': 3}

# Sources a user/admin may set on a manual app definition. 'blocklist' is engine-only.
VALID_SOURCES = frozenset({'adguard', 'dnsmon', 'manual'})

DEFAULT_INSIGHT_SOURCES = [
    {'name': 'AdGuard', 'url': CLASSIFICATION_FEED_URL, 'kind': 'adguard',
     'category': None, 'format': 'adguard', 'license': 'GPL-3.0'},
    {'name': 'DNSMon', 'url': DNSMON_LIST_URL, 'kind': 'dnsmon',
     'category': None, 'format': 'json', 'license': 'MIT'},
    {'name': 'Hagezi Pro.Plus',
     'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt',
     'kind': 'hosts', 'category': 'Ads & Tracking', 'format': 'domains', 'license': 'GPL-3.0'},
]

# AdGuard's `group` values remapped to DNSMon's display taxonomy.
ADGUARD_GROUP_TO_CATEGORY = {
    'streaming': 'Streaming',
    'social_network': 'Social',
    'gaming': 'Gaming',
    'messenger': 'Messaging',
    'shopping': 'Shopping',
    'ai': 'AI',
    'hosting': 'Cloud / Hosting',
    'gambling': 'Gambling',
    'privacy': 'Privacy / VPN',
    'dating': 'Dating',
    'software': 'Software',
    'cdn': 'CDN',
}

UNCATEGORIZED_LABEL = 'Uncategorized'
