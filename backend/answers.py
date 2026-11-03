"""DNS answers as passive DNS stores them: the addresses a query resolved to and the
CNAME targets on the way, nothing else (no TTLs, no other record types)."""

import ipaddress
import re
from typing import Iterable, List, NamedTuple, Optional

from .constants import BLOCKED_STATUSES


class Answers(NamedTuple):
    ips: List[str]
    cnames: List[str]


EMPTY = Answers([], [])

_HINT = re.compile(r'ipv[46]hint="?([^"\s]+)"?')
_TECHNITIUM_PLACEHOLDERS = {"[TRUNCATED]", "[ZONE TRANSFER]"}


def _ip(value: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return None if addr.is_unspecified else str(addr)


def _hint_ips(svcb_value: str) -> List[str]:
    return [ip for group in _HINT.findall(svcb_value) for ip in group.split(",")]


def _collect(records: Iterable[tuple[str, str]]) -> Answers:
    ips: List[str] = []
    cnames: List[str] = []
    for rtype, value in records:
        rtype = rtype.upper()
        if rtype in ("A", "AAAA"):
            candidates = [value]
        elif rtype in ("HTTPS", "SVCB"):
            candidates = _hint_ips(value)
        elif rtype == "CNAME":
            name = value.strip().rstrip(".").lower()
            if name and name not in cnames:
                cnames.append(name)
            continue
        else:
            continue
        for candidate in candidates:
            ip = _ip(candidate)
            if ip and ip not in ips:
                ips.append(ip)
    return Answers(ips, cnames)


def adguard_answers(entry: dict, status: str) -> Answers:
    """Answers from an AdGuard query-log entry. A blocked query gets none: neither the
    block response nor original_answer, because the device received neither."""
    if status in BLOCKED_STATUSES:
        return EMPTY
    return _collect((r.get("type") or "", r.get("value") or "") for r in entry.get("answer") or [])


def technitium_answers(answer: Optional[str], status: str) -> Answers:
    """Answers from a Technitium Query Logs `answer` string: "<TYPE> <RDATA>" records joined by ", "."""
    if status in BLOCKED_STATUSES or not answer or answer in _TECHNITIUM_PLACEHOLDERS:
        return EMPTY
    records = (record.split(" ", 1) for record in answer.split(", "))
    return _collect((parts[0], parts[1]) for parts in records if len(parts) == 2)
