"""Tests for backend.models.AlertRule serialization."""

from backend.models import AlertRule


def test_alert_rule_exclude_client_ips_defaults_none():
    rule = AlertRule(id=1, name="r")
    assert rule.exclude_client_ips is None
    assert rule.to_dict()["exclude_client_ips"] is None


def test_alert_rule_to_dict_includes_exclude_client_ips():
    rule = AlertRule(id=1, name="r", exclude_client_ips="192.168.1.0/24, 10.0.0.5")
    assert rule.to_dict()["exclude_client_ips"] == "192.168.1.0/24, 10.0.0.5"


def test_domain_label_to_dict_carries_threat_fields():
    from backend.models import DomainLabel
    d = DomainLabel(domain='evil.com', threat_type='malware', threat_source='qfeeds')
    out = d.to_dict()
    assert out['threat_type'] == 'malware'
    assert out['threat_source'] == 'qfeeds'


def test_insight_source_to_dict_never_exposes_api_key():
    from backend.models import InsightSource
    s = InsightSource(name='Q-Feeds', url='https://api.qfeeds.com/api',
                      kind='qfeeds', format='domains', api_key='tip_secret',
                      last_error='boom')
    out = s.to_dict()
    assert 'api_key' not in out
    assert out['has_api_key'] is True
    assert out['last_error'] == 'boom'
    assert 'tip_secret' not in str(out)


def test_insight_source_has_api_key_is_false_when_unset():
    from backend.models import InsightSource
    s = InsightSource(name='AdGuard', url='https://x/y', kind='adguard', format='adguard')
    assert s.has_api_key is False
