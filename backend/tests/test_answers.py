import pytest

from backend.answers import Answers, adguard_answers, technitium_answers

EMPTY = Answers([], [])

WEATHERKIT_IPS = ["23.217.9.57", "23.217.9.56", "23.217.9.37", "23.217.9.47", "23.217.9.50", "23.217.9.58",
                  "23.217.9.52", "23.217.9.39", "23.217.9.40", "23.217.9.41", "23.217.9.48", "23.217.9.49"]
WEATHERKIT_ENTRY = {
    "question": {"class": "IN", "name": "weatherkit.apple.com", "type": "A"},
    "answer": [
        {"type": "CNAME", "value": "weatherkit.apple.com.akadns.net.", "ttl": 2472},
        {"type": "CNAME", "value": "weather-data.apple.com.akamaized.net.", "ttl": 43},
        {"type": "CNAME", "value": "a2047.dscapi9.akamai.net.", "ttl": 21583},
        *({"type": "A", "value": ip, "ttl": 6} for ip in WEATHERKIT_IPS),
    ],
}
MINERVA_BLOCKED_ENTRY = {
    "question": {"class": "IN", "name": "x.minerva.devices.a2z.com", "type": "A"},
    "reason": "FilteredBlackList",
    "answer": [{"type": "A", "value": "0.0.0.0", "ttl": 10}],
}


def _https_entry(value: str) -> dict:
    return {"question": {"type": "HTTPS"}, "answer": [{"type": "HTTPS", "value": value, "ttl": 60}]}


def test_cdn_answer_kept_whole_and_ordered():
    a = adguard_answers(WEATHERKIT_ENTRY, "ALLOWED")

    assert a.cnames == ["weatherkit.apple.com.akadns.net", "weather-data.apple.com.akamaized.net",
                        "a2047.dscapi9.akamai.net"]
    assert a.ips == WEATHERKIT_IPS


def test_blocked_stores_nothing():
    real = [{"type": "A", "value": "93.184.216.34", "ttl": 60}]

    assert adguard_answers(MINERVA_BLOCKED_ENTRY, "BLOCKED") == EMPTY
    assert adguard_answers({**MINERVA_BLOCKED_ENTRY, "original_answer": real}, "BLOCKED") == EMPTY


def test_https_hints_become_ips():
    a = adguard_answers(_https_entry('1 . alpn="h2,h3" ipv4hint="1.2.3.4,1.2.3.5" ipv6hint="2001:DB8::1"'), "ALLOWED")

    assert a.ips == ["1.2.3.4", "1.2.3.5", "2001:db8::1"]


def test_unquoted_https_hints():
    assert adguard_answers(_https_entry("1 . ipv4hint=9.9.9.9 port=443"), "ALLOWED").ips == ["9.9.9.9"]


def test_https_without_hints_has_no_ips():
    assert adguard_answers(_https_entry('1 . alpn="h3"'), "ALLOWED") == EMPTY


def test_unspecified_garbage_and_duplicate_ips_dropped():
    entry = {"answer": [{"type": "A", "value": v} for v in ("0.0.0.0", "not-an-ip", "1.1.1.1", "1.1.1.1")]
             + [{"type": "AAAA", "value": "::"}]}

    assert adguard_answers(entry, "ALLOWED").ips == ["1.1.1.1"]


def test_other_record_types_ignored():
    entry = {"answer": [{"type": "TXT", "value": '"v=spf1 -all"'}, {"type": "PTR", "value": "host.lan."},
                        {"type": "MX", "value": "10 mx.example."}]}

    assert adguard_answers(entry, "ALLOWED") == EMPTY


def test_entry_without_answer_is_empty():
    assert adguard_answers({"question": {"type": "A"}}, "ALLOWED") == EMPTY
    assert adguard_answers({"answer": None}, "ALLOWED") == EMPTY


def test_technitium_string_format():
    a = technitium_answers("CNAME edge.cdn.net., A 93.184.216.34, AAAA 2001:db8::5", "ALLOWED")

    assert a == Answers(["93.184.216.34", "2001:db8::5"], ["edge.cdn.net"])


@pytest.mark.parametrize("value", [None, "", "[TRUNCATED]", "[ZONE TRANSFER]"])
def test_technitium_special_values_are_empty(value):
    assert technitium_answers(value, "ALLOWED") == EMPTY


def test_technitium_blocked_any_address_stores_nothing():
    assert technitium_answers("A 0.0.0.0", "BLOCKED") == EMPTY


def test_technitium_quoted_txt_cannot_forge_answers():
    a = technitium_answers('TXT "prefix, A 1.2.3.4, CNAME evil.example., suffix", A 5.6.7.8', "ALLOWED")

    assert a == Answers(["5.6.7.8"], [])


def test_technitium_escaped_quote_inside_txt():
    assert technitium_answers('TXT "say \\"hi, A 1.2.3.4\\"", A 9.9.9.9', "ALLOWED").ips == ["9.9.9.9"]


def test_empty_answers_are_not_shared():
    adguard_answers({}, "BLOCKED").ips.append("1.1.1.1")

    assert adguard_answers({}, "BLOCKED") == Answers([], [])
    assert technitium_answers(None, "ALLOWED") == Answers([], [])
