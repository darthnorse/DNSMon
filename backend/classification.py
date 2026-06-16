"""Pure logic for classifying domains into apps/categories.

No database or network access lives here — see classification_service.py.
"""
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from .constants import SOURCE_PRECEDENCE

_DOMAIN_RE = re.compile(r'^[a-z0-9.*-]+$')


def parse_adguard_rule(rule: str) -> Optional[Tuple[str, bool]]:
    """Normalize an AdGuard ``||domain^`` rule to ``(bare_domain, is_wildcard)``.

    Returns None for rules that are not a plain domain rule (regex, allow
    rules, empty). Strips ``$`` modifiers and a trailing ``^``, removes
    whitespace, and lowercases. ``is_wildcard`` is True when a ``*`` remains.
    """
    if not rule:
        return None
    s = rule.strip()
    if not s.startswith('||'):
        return None
    s = s[2:]
    if '$' in s:
        s = s.split('$', 1)[0]
    if s.endswith('^'):
        s = s[:-1]
    s = s.replace(' ', '').rstrip('.').lower()
    if not s or '.' not in s or not _DOMAIN_RE.match(s):
        return None
    return s, ('*' in s)


@dataclass
class MatchResult:
    app_id: int
    app_name: str
    category: Optional[str]
    matched_source: str


class DomainMatcher:
    """In-memory suffix matcher. Resolution: manual > supplement > adguard
    (source precedence dominates), then most-specific suffix wins."""

    def __init__(self):
        self._entries: dict[str, MatchResult] = {}

    def add(self, domain: str, app_id: int, app_name: str,
            category: Optional[str], source: str) -> None:
        domain = domain.strip().rstrip('.').lower()
        if not domain:
            return
        existing = self._entries.get(domain)
        rank = SOURCE_PRECEDENCE.get(source, 0)
        if existing is None or rank > SOURCE_PRECEDENCE.get(existing.matched_source, 0):
            self._entries[domain] = MatchResult(app_id, app_name, category, source)

    def match(self, fqdn: str) -> Optional[MatchResult]:
        if not fqdn:
            return None
        labels = fqdn.strip().rstrip('.').lower().split('.')
        best: Optional[MatchResult] = None
        best_key = (-1, -1)  # (source_rank, specificity)
        for i in range(len(labels) - 1):
            specificity = len(labels) - i
            candidate = '.'.join(labels[i:])
            hit = self._entries.get(candidate)
            if hit is None:
                continue
            key = (SOURCE_PRECEDENCE.get(hit.matched_source, 0), specificity)
            if key > best_key:
                best_key = key
                best = hit
        return best

    def __len__(self) -> int:
        return len(self._entries)
