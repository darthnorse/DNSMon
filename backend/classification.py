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


_BLOCKLIST_NOISE = frozenset({
    'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
    'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix',
    'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0',
})
_HOSTS_IPS = ('0.0.0.0', '127.0.0.1', '::1')


def parse_blocklist_line(line: str) -> Optional[str]:
    """Normalize one blocklist line to a bare domain, or None to skip.

    Tolerant of hosts (``0.0.0.0 domain``), plain domains, ``*.`` wildcard
    prefixes, and AdGuard ``||domain^`` rules. Drops comments, loopback noise,
    and anything that is not a clean domain. Returned domains are stored
    non-wildcard; the matcher's suffix walk supplies subdomain semantics.
    """
    if not line:
        return None
    s = line.strip()
    if not s or s[0] in '#!':
        return None
    if s.startswith('||'):
        parsed = parse_adguard_rule(s)
        return parsed[0] if (parsed and not parsed[1]) else None
    parts = s.split()
    tok = parts[1] if (len(parts) >= 2 and parts[0] in _HOSTS_IPS) else parts[0]
    tok = tok.lower()
    if tok.startswith('*.'):
        tok = tok[2:]
    tok = tok.strip('.')
    if (not tok or '.' not in tok or '*' in tok
            or tok in _BLOCKLIST_NOISE or not _DOMAIN_RE.match(tok)):
        return None
    return tok


_V2FLY_NAME_RE = re.compile(r'^  - name: (\S+)$')
_V2FLY_RULE_RE = re.compile(r'^      - "(domain|full|regexp|keyword):([^"]*)"$')


def parse_v2fly_entries(text: str, mapping: dict) -> list[dict]:
    """Build _replace_source defs from v2fly's dlc.dat_plain.yml text.

    Line-oriented on purpose: the artifact is machine-generated with a rigid
    shape, and a real YAML parse of ~110k scalars would stall the event loop.
    Only lists named in `mapping` are imported. `domain:` and `full:` rules are
    both stored non-wildcard (the matcher's suffix walk supplies subdomain
    semantics); `regexp:`/`keyword:` rules are skipped; rules tagged `@ads`
    (attributes are colon-attached in the artifact, e.g.
    `domain:example.com:@ads`) are dropped so ad domains inside app lists
    stay with the Ads & Tracking tier.
    """
    domains_by_list: dict[str, set[str]] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        m = _V2FLY_NAME_RE.match(line)
        if m:
            current = m.group(1) if m.group(1) in mapping else None
            continue
        if current is None:
            continue
        m = _V2FLY_RULE_RE.match(line)
        if not m:
            continue
        rtype, value = m.group(1), m.group(2)
        if rtype in ('regexp', 'keyword'):
            continue
        parts = value.replace(':@', ' @').split()
        if not parts:
            continue
        domain, attrs = parts[0], parts[1:]
        if '@ads' in attrs:
            continue
        domain = domain.strip('.').lower()
        if '.' not in domain or '*' in domain or not _DOMAIN_RE.match(domain):
            continue
        domains_by_list.setdefault(current, set()).add(domain)

    defs = []
    for list_name in sorted(domains_by_list):
        entry = mapping[list_name]
        category = entry.get('category')
        if entry.get('category_only'):
            name, is_cat = category, True
        else:
            name, is_cat = entry.get('name'), False
        if not name:
            continue
        defs.append({
            'slug': list_name, 'name': name, 'category': category,
            'is_category_only': is_cat,
            'domains': [(d, False) for d in sorted(domains_by_list[list_name])],
        })
    return defs


@dataclass
class MatchResult:
    app_id: int
    app_name: Optional[str]
    category: Optional[str]
    matched_source: str


class DomainMatcher:
    """In-memory suffix matcher. Resolution: any app match > any category-only
    bucket, then source precedence (manual > dnsmon > adguard > blocklist),
    then most-specific suffix."""

    def __init__(self):
        self._entries: dict[str, MatchResult] = {}

    def add(self, domain: str, app_id: int, app_name: Optional[str],
            category: Optional[str], source: str) -> None:
        domain = domain.strip().strip('.').lower()
        if not domain:
            return
        existing = self._entries.get(domain)
        key = (app_name is not None, SOURCE_PRECEDENCE.get(source, 0))
        if existing is None:
            self._entries[domain] = MatchResult(app_id, app_name, category, source)
            return
        existing_key = (existing.app_name is not None,
                        SOURCE_PRECEDENCE.get(existing.matched_source, 0))
        if key > existing_key:
            self._entries[domain] = MatchResult(app_id, app_name, category, source)

    def match(self, fqdn: str) -> Optional[MatchResult]:
        if not fqdn:
            return None
        labels = fqdn.strip().rstrip('.').lower().split('.')
        best: Optional[MatchResult] = None
        best_key = (-1, -1, -1)  # (is_app, source_rank, specificity)
        for i in range(len(labels) - 1):
            specificity = len(labels) - i
            candidate = '.'.join(labels[i:])
            hit = self._entries.get(candidate)
            if hit is None:
                continue
            key = (1 if hit.app_name is not None else 0,
                   SOURCE_PRECEDENCE.get(hit.matched_source, 0), specificity)
            if key > best_key:
                best_key = key
                best = hit
        return best

    def __len__(self) -> int:
        return len(self._entries)
