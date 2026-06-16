import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import select, delete, insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from .classification import parse_adguard_rule, parse_blocklist_line, DomainMatcher
from .constants import (
    CLASSIFICATION_FEED_URL,
    ADGUARD_GROUP_TO_CATEGORY,
)
from .database import async_session_maker
from .models import AppDefinition, AppDomain, DomainLabel, DomainStatsHourly, Query
from .utils import async_validate_url_safety

logger = logging.getLogger(__name__)

_SUPPLEMENT_PATH = Path(__file__).parent / 'data' / 'shadow_it_supplement.json'


def parse_blocklist_text(text: str) -> set[str]:
    """Parse raw blocklist text to a set of bare domains."""
    domains = set()
    for line in text.splitlines():
        dom = parse_blocklist_line(line)
        if dom:
            domains.add(dom)
    return domains


def _blocklist_slug(category: str) -> str:
    base = re.sub(r'-+', '-', ''.join(c if c.isalnum() else '-' for c in category.lower())).strip('-')
    return f"blocklist-{base or 'misc'}"


def build_blocklist_defs(fetched: list[tuple[str, str]]) -> list[dict]:
    """Turn [(category, raw_text), ...] into _replace_source-shaped defs.

    Merges + dedups domains per category; one category-only def per category
    (sorted domains, all non-wildcard). Categories with no parseable domains
    are dropped.
    """
    by_cat: dict[str, set[str]] = {}
    for category, text in fetched:
        by_cat.setdefault(category, set()).update(parse_blocklist_text(text))
    return [
        {
            'slug': _blocklist_slug(category),
            'name': category,
            'category': category,
            'domains': [(d, False) for d in sorted(domains)],
        }
        for category, domains in by_cat.items() if domains
    ]


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
            )
            db.add(ad)
            await db.flush()  # assign ad.id
            domain_rows = [
                {'domain': dom, 'app_id': ad.id, 'is_wildcard': wild}
                for (dom, wild) in d['domains']
            ]
            if domain_rows:
                await db.execute(insert(AppDomain), domain_rows)

        if disabled_slugs:
            await db.execute(update(AppDefinition).where(
                AppDefinition.source == source, AppDefinition.slug.in_(disabled_slugs)
            ).values(enabled=False))

        await db.commit()
        return len(defs)

    async def load_supplement(self, db: AsyncSession) -> int:
        try:
            raw = json.loads(_SUPPLEMENT_PATH.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read supplement file: {e}")
            return 0
        defs = []
        for entry in raw:
            domains = [(d.strip().lower(), '*' in d) for d in entry.get('domains', []) if d.strip()]
            if not domains:
                continue
            defs.append({
                'slug': entry['slug'], 'name': entry['name'],
                'category': entry.get('category'), 'domains': domains,
            })
        n = await self._replace_source(db, 'supplement', defs)
        logger.info(f"Loaded {n} supplement app definitions")
        return n

    async def refresh_feed(self, db: AsyncSession, url: str = CLASSIFICATION_FEED_URL) -> int:
        """Fetch AdGuard services.json and replace the 'adguard' definitions.

        Skips wildcard rules (a handful of infra domains). Returns app count,
        or -1 on fetch/parse failure (leaves existing data untouched)."""
        unsafe = await async_validate_url_safety(url)
        if unsafe:
            logger.error(f"Refusing to fetch classification feed: {unsafe}")
            return -1
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                payload = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.error(f"Failed to fetch classification feed: {e}")
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

    async def build_matcher(self, db: AsyncSession) -> DomainMatcher:
        rows = await db.execute(
            select(AppDomain.domain, AppDefinition.id, AppDefinition.name,
                   AppDefinition.category, AppDefinition.source)
            .join(AppDefinition, AppDomain.app_id == AppDefinition.id)
            .where(AppDefinition.enabled == True, AppDomain.is_wildcard == False)
        )
        matcher = DomainMatcher()
        for domain, app_id, name, category, source in rows:
            matcher.add(domain, app_id=app_id, app_name=name, category=category, source=source)
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

    async def run_full(self, *, feed_enabled: bool = True,
                       supplement_enabled: bool = True,
                       url: str = CLASSIFICATION_FEED_URL) -> None:
        """Top-level job: refresh sources then reclassify all domains."""
        async with self._lock:
            async with async_session_maker() as db:
                if feed_enabled:
                    await self.refresh_feed(db, url)
                else:
                    await self._replace_source(db, 'adguard', [])
                if supplement_enabled:
                    await self.load_supplement(db)
                else:
                    await self._replace_source(db, 'supplement', [])
                await self._do_reclassify(db)
