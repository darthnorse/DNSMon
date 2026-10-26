import asyncio
import json
import logging
import re
import sys
from http import HTTPStatus
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import select, delete, insert, update, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .classification import (
    parse_adguard_rule, parse_blocklist_line, parse_v2fly_entries,
    DomainMatcher, ThreatMatcher,
)
from .constants import (
    CLASSIFICATION_FEED_URL,
    ADGUARD_GROUP_TO_CATEGORY,
    SINGLETON_SOURCE_KINDS,
    THREAT_SOURCES,
)
from .database import async_session_maker
from .models import (AppDefinition, AppDomain, InsightSource, DomainLabel,
                     DomainStatsHourly, Query, utcnow)
from .utils import async_resolve_url_safety, is_public_suffix

logger = logging.getLogger(__name__)

_DNSMON_BUNDLED_PATH = Path(__file__).parent / 'data' / 'dnsmon.json'

_V2FLY_MAP_PATH = Path(__file__).parent / 'data' / 'v2fly_map.json'


def _load_v2fly_map() -> dict:
    try:
        return json.loads(_V2FLY_MAP_PATH.read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Could not read v2fly mapping: {e}")
        return {}


# Chunk app_domains inserts so a large blocklist (pro.plus ~546k rows) stays well
# under PostgreSQL's ~32k bind-parameter cap (3 cols * 5000 = 15k params/statement).
_DOMAIN_INSERT_BATCH = 5000

# Cap the fetched blocklist body to bound memory (pro.plus is ~13 MiB today).
_MAX_BLOCKLIST_BYTES = 64 * 1024 * 1024

# threat_type is VARCHAR(20) but its source, slug, is VARCHAR(100).
_THREAT_TYPE_MAX = 20

# 4 bind params per row against PostgreSQL's ~32k cap, matching the sibling
# bulk writers.
_LABEL_INSERT_BATCH = 2000

# The real feed carries tens of thousands of domains; anything near this is an
# error page.
_QFEEDS_MIN_DOMAINS = 100

# Bounds memory: every accepted domain is held in the resident matcher and
# materialised again during insert.
_QFEEDS_MAX_DOMAINS = 2_000_000

# A halving guard would still admit an upstream serving exactly half each
# time; 80% leaves no such step, while tolerating real feed churn.
_QFEEDS_MIN_RETAINED_PCT = 80

# A truncated download or outage page rarely repeats at the same size, while an
# upstream cleanup does. A drop below the retained floor is accepted once this
# many consecutive refreshes return a count within the tolerance of each other.
_QFEEDS_STABLE_SHRINK_REFRESHES = 3
_QFEEDS_STABLE_SHRINK_TOLERANCE_PCT = 2

_NO_DOMAINS_ERROR = 'Feed returned no usable domains'

# httpx errors stringify with the full request URL, so an API-key query param
# would otherwise land in the logs verbatim on any fetch failure.
_SECRET_PARAM_RE = re.compile(r'(api_token=)[^&\s]+')


def _scrub_secrets(msg: str) -> str:
    """Mask credential query params in a message bound for logs or the DB."""
    return _SECRET_PARAM_RE.sub(r'\1***', msg)


def _describe_fetch_error(e: Exception) -> str:
    """Short operator-facing reason for a failed fetch.

    httpx stringifies with the SSRF-pinned request IP and an MDN link, which is
    noise in a 200-char column an admin reads to fix their config.
    """
    if isinstance(e, httpx.HTTPStatusError):
        # Canonical phrase, not e.response.reason_phrase: that is upstream-
        # controlled text landing in a column readonly users can read.
        code = e.response.status_code
        try:
            return f"HTTP {code} {HTTPStatus(code).phrase}"
        except ValueError:
            return f"HTTP {code}"

    if isinstance(e, httpx.TimeoutException):
        return "Timed out contacting the feed"
    if isinstance(e, httpx.TransportError):
        return f"Could not reach the feed ({type(e).__name__})"
    return str(e) or type(e).__name__


def build_qfeeds_url(base_url: str, api_key: str) -> str:
    """Merge the API token into the stored (token-free) feed URL.

    Uses httpx's URL builder rather than string concatenation so a stored URL
    that already carries a query string stays well-formed and the token is
    percent-encoded.
    """
    return str(httpx.URL(base_url).copy_merge_params({'api_token': api_key}))


# GitHub release-asset URLs 302 to objects.githubusercontent.com; follow a
# bounded number of hops, re-validating each target against the SSRF guard.
_MAX_REDIRECTS = 3
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def resolve_redirect_target(base_url: str, location: str) -> str:
    """Absolute URL for a Location header value relative to the requested URL."""
    return str(httpx.URL(base_url).join(location))


def pin_url_to_ip(url: str, ip: Optional[str]) -> tuple[str, dict, dict]:
    """Rewrite `url`'s host to the already-validated IP so the connection cannot
    be re-routed by a second DNS resolution (rebinding TOCTOU); the real
    hostname still travels in the Host header and, for https, TLS SNI — so
    certificate verification is unaffected. Returns (request_url, headers,
    extensions); a None ip is a passthrough (used when resolution is mocked)."""
    if not ip:
        return url, {}, {}
    u = httpx.URL(url)
    host_header = u.host if u.port is None else f"{u.host}:{u.port}"
    extensions = {'sni_hostname': u.host} if u.scheme == 'https' else {}
    return str(u.copy_with(host=ip)), {'Host': host_header}, extensions


def parse_blocklist_text(text: str) -> set[str]:
    """Parse raw blocklist text to a set of bare domains."""
    domains = set()
    for line in text.splitlines():
        dom = parse_blocklist_line(line)
        if dom:
            domains.add(dom)
    return domains


def _slugify(value: str) -> str:
    base = re.sub(r'-+', '-', ''.join(c if c.isalnum() else '-' for c in (value or '').lower())).strip('-')
    return base or 'misc'


def _blocklist_slug(category: str) -> str:
    return f"blocklist-{_slugify(category)}"


def parse_dnsmon_entries(raw: list) -> list[dict]:
    """Build _replace_source defs from DNSMon JSON entries.

    Entry WITH a 'name' → app def (is_category_only=False). Entry WITHOUT a name
    but WITH a category → category-only bucket (is_category_only=True, synthetic
    slug). Entries with no usable domains, or with neither name nor category, are
    skipped. Domains are lowercased; '*' marks a wildcard.
    """
    defs: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        raw_domains = entry.get('domains')
        if not isinstance(raw_domains, list):
            continue
        domains = [(d.strip().lower(), '*' in d) for d in raw_domains
                   if isinstance(d, str) and d.strip()]
        if not domains:
            continue
        name = (entry.get('name') or '').strip()
        category = entry.get('category')
        if name:
            defs.append({
                'slug': (entry.get('slug') or '').strip() or _slugify(name),
                'name': name, 'category': category,
                'domains': domains, 'is_category_only': False,
            })
        elif category:
            defs.append({
                'slug': (entry.get('slug') or '').strip() or f"dnsmon-cat-{_slugify(category)}",
                'name': category, 'category': category,
                'domains': domains, 'is_category_only': True,
            })
    return defs


def build_blocklist_defs_from_sets(fetched: list[tuple[str, set[str]]]) -> list[dict]:
    """Turn [(category, domain_set), ...] into _replace_source-shaped defs.

    Merges + dedups domains per category; one category-only def per category
    (sorted domains, all non-wildcard). Categories with no domains are dropped.
    """
    by_cat: dict[str, set[str]] = {}
    for category, domains in fetched:
        by_cat.setdefault(category, set()).update(domains)
    return [
        {
            'slug': _blocklist_slug(category),
            'name': category,
            'category': category,
            'is_category_only': True,
            'domains': [(d, False) for d in sorted(domains)],
        }
        for category, domains in by_cat.items() if domains
    ]


def build_blocklist_defs(fetched: list[tuple[str, str]]) -> list[dict]:
    """Text-input convenience wrapper over build_blocklist_defs_from_sets."""
    return build_blocklist_defs_from_sets(
        [(category, parse_blocklist_text(text)) for category, text in fetched])


class ClassificationService:
    """Builds and maintains the app/category knowledge base and the
    resolved domain_labels cache."""

    def __init__(self):
        self._lock = asyncio.Lock()
        # Resident so the alert engine can match newly-seen domains with no DB read.
        self._threat_matcher = ThreatMatcher()
        self._last_fetch_error: Optional[str] = None

    async def _replace_source(self, db: AsyncSession, source: str, defs: list[dict]) -> int:
        """Delete all definitions for `source` and re-insert `defs`.

        Each def: {slug, name, category, icon_svg?, domains: [(domain, is_wildcard)]}.
        CASCADE removes the old app_domains. Returns count of definitions written.
        Preserves admin disable-toggles: slugs that were enabled=False before the
        refresh are restored to enabled=False after re-insertion.
        """
        disabled_slugs = set((await db.execute(
            select(AppDefinition.slug).where(
                AppDefinition.source == source, AppDefinition.enabled == False
            )
        )).scalars().all())

        old_ids = (await db.execute(
            select(AppDefinition.id).where(AppDefinition.source == source)
        )).scalars().all()
        if old_ids:
            await db.execute(delete(AppDefinition).where(AppDefinition.id.in_(old_ids)))

        for d in defs:
            ad = AppDefinition(
                slug=d['slug'], name=d['name'], category=d.get('category'),
                source=source, icon_svg=d.get('icon_svg'), enabled=True,
                is_category_only=d.get('is_category_only', False),
            )
            db.add(ad)
            await db.flush()  # assign ad.id
            doms = d['domains']
            for i in range(0, len(doms), _DOMAIN_INSERT_BATCH):
                await db.execute(insert(AppDomain), [
                    {'domain': dom, 'app_id': ad.id, 'is_wildcard': wild}
                    for (dom, wild) in doms[i:i + _DOMAIN_INSERT_BATCH]
                ])

        if disabled_slugs:
            await db.execute(update(AppDefinition).where(
                AppDefinition.source == source, AppDefinition.slug.in_(disabled_slugs)
            ).values(enabled=False))

        await db.commit()
        return len(defs)

    async def load_dnsmon_bundled(self, db: AsyncSession) -> int:
        try:
            raw = json.loads(_DNSMON_BUNDLED_PATH.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read bundled DNSMon list: {e}")
            return 0
        defs = parse_dnsmon_entries(raw)
        n = await self._replace_source(db, 'dnsmon', defs)
        logger.info(f"Loaded {n} DNSMon definitions from bundled file")
        return n

    async def _safe_fetch(self, url: str, what: str) -> Optional[str]:
        """Fetch `url` (SSRF-validated and IP-pinned per hop by
        _fetch_capped_text); None on any failure (already logged)."""
        self._last_fetch_error = None
        try:
            return await self._fetch_capped_text(url)
        except (httpx.HTTPError, ValueError) as e:
            self._last_fetch_error = _describe_fetch_error(e)
            logger.error(_scrub_secrets(f"Failed to fetch {what}: {e}"))
            return None

    def _failure_message(self) -> str:
        """Scrubbed and bounded, for a last_error column readable by any user."""
        return _scrub_secrets(self._last_fetch_error or 'Refresh failed')[:200]

    async def load_dnsmon(self, db: AsyncSession, row) -> int:
        """Fetch the remote DNSMon curated list and replace the 'dnsmon' source.

        Remote success → replace from remote. Remote failure → keep existing defs
        if any (don't regress a known-good fetch to the older bundled copy on a
        transient blip), else fall back to the bundled dnsmon.json (first boot)."""
        raw = None
        text = await self._safe_fetch(row.url, 'DNSMon list')
        if text is not None:
            try:
                parsed = json.loads(text)
                if not isinstance(parsed, list):
                    raise ValueError("DNSMon list is not a JSON array")
                raw = parsed
            except (ValueError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse DNSMon list: {e}")

        if raw is not None:
            defs = parse_dnsmon_entries(raw)
            if defs:
                n = await self._replace_source(db, 'dnsmon', defs)
                logger.info(f"Loaded {n} DNSMon definitions from remote")
                return n
            logger.error("DNSMon remote list yielded 0 definitions; falling back")

        existing = await db.scalar(select(func.count()).select_from(AppDefinition).where(
            AppDefinition.source == 'dnsmon'))
        if existing:
            logger.warning("DNSMon refresh yielded no usable list; keeping existing dnsmon tier")
            return -1
        return await self.load_dnsmon_bundled(db)

    async def load_v2fly(self, db: AsyncSession, row) -> int:
        """Fetch the v2fly community list and replace the 'v2fly' source.

        Only slugs present in the bundled v2fly_map.json are imported. Any
        failure (unsafe URL, fetch error, unparseable/empty body, missing
        mapping) keeps the existing tier and returns -1."""
        mapping = _load_v2fly_map()
        if not mapping:
            self._last_fetch_error = "Bundled v2fly mapping is missing or unreadable"
            return -1
        text = await self._safe_fetch(row.url, 'v2fly list')
        if text is None:
            return -1
        defs = parse_v2fly_entries(text, mapping)
        if not defs:
            logger.error("v2fly list yielded 0 definitions; keeping existing tier")
            return -1
        n = await self._replace_source(db, 'v2fly', defs)
        logger.info(f"Loaded {n} v2fly definitions")
        return n

    async def load_qfeeds(self, db: AsyncSession, row) -> int:
        """Fetch the Q-Feeds malware list and replace the 'qfeeds' source.

        Any failure — no key, fetch error, empty or implausible body — keeps the
        existing tier and returns -1."""
        if not row.api_key:
            logger.error("Q-Feeds source has no API key; skipping refresh")
            self._last_fetch_error = "API key required"
            return -1
        text = await self._safe_fetch(
            build_qfeeds_url(row.url, row.api_key), 'Q-Feeds threat list')
        if text is None:
            return -1
        domains = parse_blocklist_text(text)
        # A public-suffix entry (ru.net, co.uk, duckdns.org) would tag every domain
        # beneath it via the matcher's suffix walk. The live feed already carries one.
        dropped = {d for d in domains if is_public_suffix(d)}
        if dropped:
            logger.warning(
                f"Q-Feeds: dropping {len(dropped)} public-suffix entries: "
                f"{sorted(dropped)[:5]}")
            domains -= dropped
        if not domains:
            logger.error("Q-Feeds list yielded 0 domains; keeping existing tier")
            self._last_fetch_error = _NO_DOMAINS_ERROR
            return -1
        if len(domains) > _QFEEDS_MAX_DOMAINS:
            logger.error(f"Q-Feeds returned {len(domains)} domains; refusing")
            self._last_fetch_error = "Feed implausibly large; refused"
            return -1
        # A 200 maintenance page can still contain one domain-shaped token; without
        # this floor it would replace the whole tier and still report ok. Anchored
        # to the high-water mark, not the current count, so an upstream serving
        # half each time cannot walk the tier down one accepted refresh at a time.
        count = len(domains)
        if count < _QFEEDS_MIN_DOMAINS:
            row.shrink_candidate_count = None
            row.shrink_streak = None
            logger.error(f"Q-Feeds returned {count} domains; implausible, keeping existing tier")
            self._last_fetch_error = f"Feed returned only {count} domains; refused as implausible."
            return -1
        existing = await self._source_domain_count(db, 'qfeeds')
        anchor = max(existing, row.domain_count_high_water or 0)
        if count * 100 < anchor * _QFEEDS_MIN_RETAINED_PCT:
            streak = self._shrink_streak(row, count)
            if streak < _QFEEDS_STABLE_SHRINK_REFRESHES:
                remaining = _QFEEDS_STABLE_SHRINK_REFRESHES - streak
                logger.error(
                    f"Q-Feeds returned {count} domains (peak {anchor}); keeping existing "
                    f"tier unless the next {remaining} refresh(es) agree")
                self._last_fetch_error = (
                    f"Feed returned {count} domains vs a peak of {anchor}; accepted if "
                    f"the next {remaining} refresh(es) return the same size.")
                return -1
            logger.warning(
                f"Q-Feeds held at ~{count} domains (peak {anchor}) for {streak} "
                "refreshes; accepting it as the new baseline")
            anchor = count
        n = await self._replace_source(db, 'qfeeds', [{
            'slug': 'malware', 'name': 'Malware', 'category': None,
            'is_category_only': False,
            'domains': [(d, False) for d in sorted(domains)],
        }])
        row.domain_count_high_water = max(anchor, count)
        row.shrink_candidate_count = None
        row.shrink_streak = None
        logger.info(f"Loaded {len(domains)} Q-Feeds malware domains")
        return n

    @staticmethod
    def _shrink_streak(row, count: int) -> int:
        """Record a refused smaller count and return how many consecutive refreshes
        have now returned roughly that size."""
        candidate = row.shrink_candidate_count
        holds = candidate is not None and (
            abs(count - candidate) * 100 <= candidate * _QFEEDS_STABLE_SHRINK_TOLERANCE_PCT)
        streak = (row.shrink_streak or 0) + 1 if holds else 1
        row.shrink_candidate_count = count
        row.shrink_streak = streak
        return streak

    async def refresh_feed(self, db: AsyncSession, row) -> int:
        """Fetch AdGuard services.json and replace the 'adguard' definitions.

        Skips wildcard rules (a handful of infra domains). Returns app count,
        or -1 on fetch/parse failure (leaves existing data untouched)."""
        text = await self._safe_fetch(row.url, 'classification feed')
        if text is None:
            return -1
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse classification feed: {e}")
            return -1

        defs = []
        for svc in payload.get('blocked_services', []):
            domains = []
            for rule in svc.get('rules', []):
                parsed = parse_adguard_rule(rule)
                if parsed is None or parsed[1]:  # skip unparseable + wildcard
                    continue
                domains.append((parsed[0], False))
            if not domains:
                continue
            defs.append({
                'slug': svc['id'], 'name': svc.get('name', svc['id']),
                'category': ADGUARD_GROUP_TO_CATEGORY.get(svc.get('group'), None),
                'icon_svg': svc.get('icon_svg'),
                'domains': domains,
            })
        n = await self._replace_source(db, 'adguard', defs)
        logger.info(f"Refreshed AdGuard feed: {n} app definitions")
        return n

    async def _fetch_capped_text(self, url: str) -> str:
        """GET a body, streaming with a byte cap to bound memory.

        Every hop (initial URL and each redirect target) is SSRF-validated and
        the connection pinned to the validated IP via pin_url_to_ip. Raises
        ValueError if the body exceeds the cap or a hop is unsafe/looping,
        httpx.HTTPError on transport/status failures."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                unsafe, ip = await async_resolve_url_safety(url)
                if unsafe:
                    raise ValueError(f"unsafe fetch target: {unsafe}")
                req_url, headers, extensions = pin_url_to_ip(url, ip)
                async with client.stream("GET", req_url, headers=headers,
                                         extensions=extensions) as resp:
                    if resp.status_code in _REDIRECT_STATUSES:
                        location = resp.headers.get('location')
                        if not location:
                            raise ValueError("redirect without a Location header")
                        url = resolve_redirect_target(url, location)
                        continue
                    resp.raise_for_status()
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > _MAX_BLOCKLIST_BYTES:
                            raise ValueError(
                                f"blocklist body exceeds {_MAX_BLOCKLIST_BYTES} byte cap")
                        chunks.append(chunk)
                    return b''.join(chunks).decode('utf-8', errors='replace')
        raise ValueError(f"too many redirects (>{_MAX_REDIRECTS})")

    async def refresh_blocklists(self, db: AsyncSession) -> int:
        """Fetch each enabled blocklist source and replace the 'blocklist' tier.

        No enabled sources → clears the tier (returns 0). No source yielding any
        domains (every fetch failed, or returned an unparseable/empty body) →
        leaves existing data untouched (returns -1). Not lock-protected: callers
        run_full holds the lock."""
        sources = (await db.execute(
            select(InsightSource).where(
                InsightSource.enabled == True, InsightSource.kind == 'hosts')
        )).scalars().all()
        if not sources:
            n = await self._replace_source(db, 'blocklist', [])
            logger.info("No enabled blocklist sources; cleared blocklist tier")
            return n

        # parse_blocklist_line is tolerant of hosts/plain/wildcard/adguard formats,
        # so src.format is advisory metadata today (no per-format branching needed).
        fetched: list[tuple[str, set[str]]] = []
        for src in sources:
            self._last_fetch_error = None
            text = await self._safe_fetch(src.url, f"blocklist {src.name}")
            if text is None:
                src.last_status = 'error'
                src.last_error = self._failure_message()
                continue
            domains = parse_blocklist_text(text)
            if not domains:
                # A 200 with no parseable domains (error page, empty/changed file)
                # must not wipe the tier — mark it an error and keep prior data.
                logger.error(f"Blocklist {src.name} yielded 0 domains; treating as error")
                src.last_status = 'error'
                src.last_error = _NO_DOMAINS_ERROR
                continue
            src.last_status = 'ok'
            src.last_error = None
            src.last_fetched_at = utcnow()
            src.domain_count = len(domains)
            fetched.append((src.category, domains))

        await db.commit()  # persist last_* even when nothing is replaced
        if not fetched:
            logger.error("No blocklist source yielded domains; keeping existing tier")
            return -1
        defs = build_blocklist_defs_from_sets(fetched)
        n = await self._replace_source(db, 'blocklist', defs)
        logger.info(f"Loaded {n} blocklist category definitions")
        return n

    async def build_matcher(self, db: AsyncSession) -> DomainMatcher:
        rows = await db.execute(
            select(AppDomain.domain, AppDefinition.id, AppDefinition.name,
                   AppDefinition.category, AppDefinition.source,
                   AppDefinition.is_category_only)
            .join(AppDefinition, AppDomain.app_id == AppDefinition.id)
            .where(AppDefinition.enabled == True, AppDomain.is_wildcard == False,
                   AppDefinition.source.notin_(THREAT_SOURCES))
        )
        matcher = DomainMatcher()
        for domain, app_id, name, category, source, is_category_only in rows:
            app_name = None if is_category_only else name
            matcher.add(domain, app_id=app_id, app_name=app_name, category=category, source=source)
        return matcher

    async def build_threat_matcher(self, db: AsyncSession) -> ThreatMatcher:
        """The complement of build_matcher. A definition's slug is its threat
        type, which generalises if a paid tier later adds phishing."""
        enabled_kinds = select(InsightSource.kind).where(InsightSource.enabled == True)
        rows = await db.execute(
            select(AppDomain.domain, AppDefinition.slug, AppDefinition.source)
            .join(AppDefinition, AppDomain.app_id == AppDefinition.id)
            # Also gated on the InsightSource row: a crash between disabling the
            # source and clearing its definitions must not resurrect the tier.
            .where(AppDefinition.enabled == True, AppDomain.is_wildcard == False,
                   AppDefinition.source.in_(THREAT_SOURCES),
                   AppDefinition.source.in_(enabled_kinds))
            # add() is first-wins; unordered, a doubly-claimed domain would flip type.
            .order_by(AppDefinition.source, AppDefinition.slug)
        )
        matcher = ThreatMatcher()
        # One shared tuple per (slug, source): a per-row tuple of fresh strings
        # costs ~30 MB resident on a 127k-domain feed.
        values: dict[tuple[str, str], tuple[str, str]] = {}
        for domain, slug, source in rows:
            key = (slug, source)
            value = values.get(key)
            if value is None:
                value = values[key] = (sys.intern(slug[:_THREAT_TYPE_MAX]),
                                       sys.intern(source))
            matcher.add(domain, threat_type=value[0], threat_source=value[1])
        return matcher

    def match_threat(self, fqdn: str) -> Optional[tuple[str, str]]:
        """Threat status from the resident matcher, or None. Safe before the
        first build — an empty matcher simply misses."""
        return self._threat_matcher.match(fqdn)

    async def record_threat_labels(
            self, db: AsyncSession, hits: dict[str, tuple[str, str]]) -> int:
        """Persist threat tags for domains the alert path just matched.

        The alert engine reads the live matcher while every UI surface reads
        domain_labels, which only _do_reclassify writes (every
        classification_refresh_hours, default 24h). Without this an operator
        paged about a domain would open the Dashboard and see it unflagged.

        `hits` was matched against whatever matcher was resident when the poll
        started, so it is re-validated here under the lock: a reclassify may
        have cleared those tags in the meantime, and writing the snapshot back
        would resurrect them. Touches only the threat columns, so it cannot
        clobber the app/category label reclassify owns.
        """
        if not hits:
            return 0

        async with self._lock:
            # Re-matched inside the lock; a domain the current matcher no longer
            # flags is dropped rather than written back stale.
            items = sorted(
                (d, hit) for d in hits if (hit := self._threat_matcher.match(d)))
            if not items:
                return 0
            now = utcnow()
            for i in range(0, len(items), _LABEL_INSERT_BATCH):
                stmt = pg_insert(DomainLabel).values([
                    {'domain': d, 'threat_type': t, 'threat_source': src,
                     'classified_at': now}
                    for d, (t, src) in items[i:i + _LABEL_INSERT_BATCH]
                ])
                await db.execute(stmt.on_conflict_do_update(
                    index_elements=['domain'],
                    set_={'threat_type': stmt.excluded.threat_type,
                          'threat_source': stmt.excluded.threat_source,
                          'classified_at': stmt.excluded.classified_at}))
            await db.commit()
        return len(items)

    async def prime_threat_matcher(self, db: AsyncSession) -> int:
        """Load the persisted threat tier into the resident matcher (no network).

        Needed because the first alert pass runs before the first reclassify,
        and queries evaluated then are never re-evaluated."""
        self._threat_matcher = await self.build_threat_matcher(db)
        return len(self._threat_matcher)

    async def _do_reclassify(self, db: AsyncSession) -> int:
        """Resolve every distinct observed domain into domain_labels.

        Stores a row for every distinct domain (matched or not). Idempotent —
        upserts on the `domain` primary key. Returns rows written."""
        matcher = await self.build_matcher(db)
        threat_matcher = await self.build_threat_matcher(db)
        distinct_domains = (await db.execute(
            select(DomainStatsHourly.domain).distinct()
        )).scalars().all()

        now = utcnow()
        values = []
        for fqdn in distinct_domains:
            hit = matcher.match(fqdn)
            threat = threat_matcher.match(fqdn)
            values.append({
                'domain': fqdn,
                'app_id': hit.app_id if hit else None,
                'app_name': hit.app_name if hit else None,
                'category': hit.category if hit else None,
                'matched_source': hit.matched_source if hit else None,
                'threat_type': threat[0] if threat else None,
                'threat_source': threat[1] if threat else None,
                'classified_at': now,
            })

        for i in range(0, len(values), 2000):
            batch = values[i:i + 2000]
            stmt = pg_insert(DomainLabel).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=['domain'],
                set_={
                    'app_id': stmt.excluded.app_id,
                    'app_name': stmt.excluded.app_name,
                    'category': stmt.excluded.category,
                    'matched_source': stmt.excluded.matched_source,
                    'threat_type': stmt.excluded.threat_type,
                    'threat_source': stmt.excluded.threat_source,
                    'classified_at': stmt.excluded.classified_at,
                },
            )
            await db.execute(stmt)
        await db.commit()
        # Swapped only after the commit, so a failed upsert cannot leave the
        # matcher disagreeing with the labels every UI surface reads.
        self._threat_matcher = threat_matcher
        logger.info(f"Reclassified {len(values)} distinct domains")
        return len(values)

    async def reclassify(self, db: AsyncSession) -> int:
        async with self._lock:
            return await self._do_reclassify(db)

    async def refresh_and_reclassify_kind(self, kind: str) -> None:
        """Refresh only the given kind's tier + reclassify (ad-hoc, e.g. a per-row toggle)."""
        async with self._lock:
            async with async_session_maker() as db:
                if kind == 'hosts':
                    await self.refresh_blocklists(db)
                else:
                    row = (await db.execute(select(InsightSource).where(
                        InsightSource.enabled == True, InsightSource.kind == kind))).scalars().first()
                    if row:
                        await self._refresh_singleton_row(db, row)
                        await db.commit()
                    else:
                        await self._replace_source(db, kind, [])
                await self._do_reclassify(db)

    async def _source_domain_count(self, db: AsyncSession, source: str) -> int:
        return await db.scalar(
            select(func.count()).select_from(AppDomain)
            .join(AppDefinition, AppDomain.app_id == AppDefinition.id)
            .where(AppDefinition.source == source)) or 0

    async def _refresh_singleton_row(self, db: AsyncSession, row) -> None:
        """Fetch one enabled singleton-kind row and record its status + real domain count."""
        loaders = {'adguard': self.refresh_feed, 'dnsmon': self.load_dnsmon,
                   'v2fly': self.load_v2fly, 'qfeeds': self.load_qfeeds}
        refresh = loaders[row.kind]
        self._last_fetch_error = None
        n = await refresh(db, row)
        row.last_status = 'ok' if n >= 0 else 'error'
        if n >= 0:
            row.last_fetched_at = utcnow()
            row.domain_count = await self._source_domain_count(db, row.kind)
            row.last_error = None
        else:
            row.last_error = self._failure_message()

    async def _refresh_all_sources(self, db: AsyncSession) -> None:
        """Fetch every enabled insight_sources row, dispatch by kind, replace each
        target app_definitions source. Tiers with no enabled row are cleared."""
        for kind in SINGLETON_SOURCE_KINDS:
            row = None
            try:
                # Re-selected per iteration rather than hoisted: a rollback in the
                # handler below expires every loaded instance, and reading .kind
                # off an expired object outside a greenlet raises MissingGreenlet
                # — which would escape this loop and skip the remaining sources,
                # refresh_blocklists and the reclassify, i.e. exactly what this
                # isolation exists to prevent.
                row = (await db.execute(select(InsightSource).where(
                    InsightSource.enabled == True, InsightSource.kind == kind
                ))).scalars().first()
                if row:
                    await self._refresh_singleton_row(db, row)
                else:
                    await self._replace_source(db, kind, [])
                await db.commit()
            except Exception as e:
                await db.rollback()
                logger.error(_scrub_secrets(f"Refresh of {kind} failed: {e}"), exc_info=True)
                if row is not None:
                    # Inner guard: these calls can raise too (a deleted row, or
                    # the same connection failure that caused the outer error),
                    # and escaping here would skip every remaining source.
                    try:
                        row.last_status = 'error'
                        row.last_error = _scrub_secrets(str(e))[:200]
                        # Committed now; a later iteration's rollback would
                        # otherwise discard this status along with its own.
                        await db.commit()
                    except Exception:
                        await db.rollback()
                        logger.exception(f"Could not record error status for {kind}")
        await self.refresh_blocklists(db)
        await db.commit()

    async def run_full(self) -> None:
        """Top-level job: refresh every enabled source then reclassify all domains."""
        async with self._lock:
            async with async_session_maker() as db:
                await self._refresh_all_sources(db)
                await self._do_reclassify(db)
