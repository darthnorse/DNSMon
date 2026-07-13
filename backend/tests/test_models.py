"""Tests for backend.models.AlertRule serialization."""

from backend.models import AlertRule


def test_alert_rule_exclude_client_ips_defaults_none():
    rule = AlertRule(id=1, name="r")
    assert rule.exclude_client_ips is None
    assert rule.to_dict()["exclude_client_ips"] is None


def test_alert_rule_to_dict_includes_exclude_client_ips():
    rule = AlertRule(id=1, name="r", exclude_client_ips="192.168.1.0/24, 10.0.0.5")
    assert rule.to_dict()["exclude_client_ips"] == "192.168.1.0/24, 10.0.0.5"
