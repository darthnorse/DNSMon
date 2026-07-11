import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import select, delete, insert, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from .classification import parse_adguard_rule, parse_blocklist_line, parse_v2fly_entries, DomainMatcher
from .constants import (
    CLASSIFICATION_FEED_URL,
    ADGUARD_GROUP_TO_CATEGORY,
    SINGLETON_SOURCE_KINDS,
)
from .database import async_session_maker
from .models import AppDefinition, AppDomain, InsightSource, DomainLabel, DomainStatsHourly, Query
from .utils import async_resolve_url_safety

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
            domain_rows = [
                {'domain': dom, 'app_id': ad.id, 'is_wildcard': wild}
                for (dom, wild) in d['domains']
            ]
            for i in range(0, len(domain_rows), _DOMAIN_INSERT_BATCH):
                await db.execute(insert(AppDomain), domain_rows[i:i + _DOMAIN_INSERT_BATCH])

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
        try:
            return await self._fetch_capped_text(url)
        except (httpx.HTTPError, ValueError) as e:
            logger.error(f"Failed to fetch {what}: {e}")
            return None

    async def load_dnsmon(self, db: AsyncSession, url: str) -> int:
        """Fetch the remote DNSMon curated list and replace the 'dnsmon' source.

        Remote success → replace from remote. Remote failure → keep existing defs
        if any (don't regress a known-good fetch to the older bundled copy on a
        transient blip), else fall back to the bundled dnsmon.json (first boot)."""
        raw = None
        text = await self._safe_fetch(url, 'DNSMon list')
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

    async def load_v2fly(self, db: AsyncSession, url: str) -> int:
        """Fetch the v2fly community list and replace the 'v2fly' source.

        Only slugs present in the bundled v2fly_map.json are imported. Any
        failure (unsafe URL, fetch error, unparseable/empty body, missing
        mapping) keeps the existing tier and returns -1."""
        mapping = _load_v2fly_map()
        if not mapping:
            return -1
        text = await self._safe_fetch(url, 'v2fly list')
        if text is None:
            return -1
        defs = parse_v2fly_entries(text, mapping)
        if not defs:
            logger.error("v2fly list yielded 0 definitions; keeping existing tier")
            return -1
        n = await self._replace_source(db, 'v2fly', defs)
        logger.info(f"Loaded {n} v2fly definitions")
        return n

    async def refresh_feed(self, db: AsyncSession, url: str = CLASSIFICATION_FEED_URL) -> int:
        """Fetch AdGuard services.json and replace the 'adguard' definitions.

        Skips wildcard rules (a handful of infra domains). Returns app count,
        or -1 on fetch/parse failure (leaves existing data untouched)."""
        text = await self._safe_fetch(url, 'classification feed')
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
        from .models import utcnow
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
            text = await self._safe_fetch(src.url, f"blocklist {src.name}")
            if text is None:
                src.last_status = 'error'
                continue
            domains = parse_blocklist_text(text)
            if not domains:
                # A 200 with no parseable domains (error page, empty/changed file)
                # must not wipe the tier — mark it an error and keep prior data.
                logger.error(f"Blocklist {src.name} yielded 0 domains; treating as error")
                src.last_status = 'error'
                continue
            src.last_status = 'ok'
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
            .where(AppDefinition.enabled == True, AppDomain.is_wildcard == False)
        )
        matcher = DomainMatcher()
        for domain, app_id, name, category, source, is_category_only in rows:
            app_name = None if is_category_only else name
            matcher.add(domain, app_id=app_id, app_name=app_name, category=category, source=source)
        return matcher

    async def _do_reclassify(self, db: AsyncSession) -> int:
        """Resolve every distinct observed domain into domain_labels.

        Stores a row for every distinct domain (matched or not). Idempotent —
        upserts on the `domain` primary key. Returns rows written."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from .models import utcnow

        matcher = await self.build_matcher(db)
        distinct_domains = (await db.execute(
            select(DomainStatsHourly.domain).distinct()
        )).scalars().all()

        now = utcnow()
        values = []
        for fqdn in distinct_domains:
            hit = matcher.match(fqdn)
            values.append({
                'domain': fqdn,
                'app_id': hit.app_id if hit else None,
                'app_name': hit.app_name if hit else None,
                'category': hit.category if hit else None,
                'matched_source': hit.matched_source if hit else None,
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
                    'classified_at': stmt.excluded.classified_at,
                },
            )
            await db.execute(stmt)
        await db.commit()
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
        from .models import utcnow
        loaders = {'adguard': self.refresh_feed, 'dnsmon': self.load_dnsmon,
                   'v2fly': self.load_v2fly}
        refresh = loaders[row.kind]
        n = await refresh(db, row.url)
        row.last_status = 'ok' if n >= 0 else 'error'
        if n >= 0:
            row.last_fetched_at = utcnow()
            row.domain_count = await self._source_domain_count(db, row.kind)

    async def _refresh_all_sources(self, db: AsyncSession) -> None:
        """Fetch every enabled insight_sources row, dispatch by kind, replace each
        target app_definitions source. Tiers with no enabled row are cleared."""
        sources = (await db.execute(
            select(InsightSource).where(InsightSource.enabled == True)
        )).scalars().all()
        for kind in SINGLETON_SOURCE_KINDS:
            row = next((s for s in sources if s.kind == kind), None)
            if row:
                await self._refresh_singleton_row(db, row)
            else:
                await self._replace_source(db, kind, [])
        await self.refresh_blocklists(db)
        await db.commit()

    async def run_full(self) -> None:
        """Top-level job: refresh every enabled source then reclassify all domains."""
        async with self._lock:
            async with async_session_maker() as db:
                await self._refresh_all_sources(db)
                await self._do_reclassify(db)
