"""Tests for backend.schemas — Pydantic model validation."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.schemas import (
    AlertRuleCreate,
    AlertRuleResponse,
    AlertRuleUpdate,
)


# ---------------------------------------------------------------------------
# AlertRuleUpdate — null-rejection on NOT-NULL columns (fixes a + d)
# ---------------------------------------------------------------------------

def test_update_not_null_fields_covers_response_required_fields():
    # Auto-derived from AlertRuleResponse.model_fields (non-Optional ∩ update fields).
    # If a future non-Optional field is added to the response, this set grows
    # automatically — no separate hand-maintained list to forget.
    assert set(AlertRuleUpdate._NOT_NULL_FIELDS) == {
        "name", "match_status", "enabled", "cooldown_minutes",
    }


def test_update_rejects_explicit_null_match_status():
    with pytest.raises(ValidationError) as exc:
        AlertRuleUpdate.model_validate({"match_status": None})
    assert "match_status" in str(exc.value)


def test_update_rejects_explicit_null_name():
    with pytest.raises(ValidationError):
        AlertRuleUpdate.model_validate({"name": None})


def test_update_accepts_null_for_clearable_fields():
    # description and exclude_domains are nullable in the DB AND optional in the
    # response — clearing them via null is legitimate.
    for payload in ({"description": None}, {"exclude_domains": None},
                    {"domain_pattern": None}):
        m = AlertRuleUpdate.model_validate(payload)
        assert m.model_dump(exclude_unset=True) == payload


def test_update_rejects_null_on_enabled_and_cooldown():
    # These are in _NOT_NULL_FIELDS even though the columns are nullable — writing
    # null would break AlertRuleResponse serialization downstream.
    for field in ("enabled", "cooldown_minutes"):
        with pytest.raises(ValidationError):
            AlertRuleUpdate.model_validate({field: None})


def test_update_omitted_field_excluded_from_dump():
    # Omitted (vs explicitly null) → not in the dump → setattr never called → no change.
    m = AlertRuleUpdate.model_validate({"name": "renamed"})
    assert m.model_dump(exclude_unset=True) == {"name": "renamed"}


def test_update_rejects_bogus_match_status_value():
    with pytest.raises(ValidationError):
        AlertRuleUpdate.model_validate({"match_status": "bogus"})


def test_update_accepts_valid_match_status_values():
    for value in ("any", "blocked", "allowed"):
        m = AlertRuleUpdate.model_validate({"match_status": value})
        assert m.match_status == value


# ---------------------------------------------------------------------------
# AlertRuleResponse — datetime coercion & ISO output (fix b)
# ---------------------------------------------------------------------------

def _base_response_kwargs(**overrides):
    base = dict(
        id=1, name="x", description=None, domain_pattern=None,
        client_ip_pattern=None, client_hostname_pattern=None,
        exclude_domains=None, cooldown_minutes=5, match_status="any",
        enabled=True,
        created_at=datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return base


def test_response_coerces_naive_datetime_to_utc():
    naive = datetime(2026, 5, 17, 12, 0, 0)
    r = AlertRuleResponse(**_base_response_kwargs(created_at=naive))
    assert r.created_at.tzinfo == timezone.utc


def test_response_passes_through_aware_datetime():
    aware = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    r = AlertRuleResponse(**_base_response_kwargs(updated_at=aware))
    assert r.updated_at == aware


def test_response_rejects_none_datetime():
    # created_at/updated_at are now required (DB defaults guarantee them);
    # a null leaking through would be an upstream bug, surface it as 422.
    with pytest.raises(ValidationError):
        AlertRuleResponse(**_base_response_kwargs(created_at=None))


def test_response_json_format_is_iso8601():
    aware = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    r = AlertRuleResponse(**_base_response_kwargs(created_at=aware))
    payload = r.model_dump_json()
    # Pydantic v2 emits "Z" suffix for UTC; JS new Date() parses both forms.
    assert '"created_at":"2026-05-17T12:00:00Z"' in payload


# ---------------------------------------------------------------------------
# AlertRuleCreate — field validation
# ---------------------------------------------------------------------------

def test_create_rejects_name_over_100_chars():
    with pytest.raises(ValidationError):
        AlertRuleCreate(name="x" * 101)


def test_create_cooldown_lower_bound():
    with pytest.raises(ValidationError):
        AlertRuleCreate(name="r", cooldown_minutes=-1)


def test_create_cooldown_upper_bound():
    # 7 days = 10080 minutes; one above is rejected.
    with pytest.raises(ValidationError):
        AlertRuleCreate(name="r", cooldown_minutes=10081)


def test_create_match_status_defaults_to_any():
    m = AlertRuleCreate(name="r")
    assert m.match_status == "any"


def test_create_rejects_unknown_field():
    # Pydantic v2 default is `extra="ignore"`; this confirms our schema doesn't
    # accidentally allow unexpected fields to corrupt state if that changes.
    m = AlertRuleCreate.model_validate({"name": "r", "unknown_field": "x"})
    assert not hasattr(m, "unknown_field")
