import json
import logging
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import select, delete, insert
from sqlalchemy.ext.asyncio import AsyncSession

from .classification import parse_adguard_rule, DomainMatcher
from .constants import (
    CLASSIFICATION_FEED_URL,
    ADGUARD_GROUP_TO_CATEGORY,
)
from .database import async_session_maker
from .models import AppDefinition, AppDomain, DomainLabel, Query
from .utils import async_validate_url_safety

logger = logging.getLogger(__name__)

_SUPPLEMENT_PATH = Path(__file__).parent / 'data' / 'shadow_it_supplement.json'


class ClassificationService:
    """Builds and maintains the app/category knowledge base and the
    resolved domain_labels cache."""

    async def _replace_source(self, db: AsyncSession, source: str, defs: list[dict]) -> int:
        """Delete all definitions for `source` and re-insert `defs`.

        Each def: {slug, name, category, icon_svg?, domains: [(domain, is_wildcard)]}.
        CASCADE removes the old app_domains. Returns count of definitions written.
        """
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
