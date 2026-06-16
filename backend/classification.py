"""Pure logic for classifying domains into apps/categories.

No database or network access lives here — see classification_service.py.
"""
import re
from typing import Optional, Tuple

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
