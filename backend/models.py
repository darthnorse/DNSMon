from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Index, BigInteger, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


def utcnow():
    """Helper function for default timezone-aware timestamps"""
    return datetime.now(timezone.utc)


class Query(Base):
    """DNS Query log entry"""
    __tablename__ = "queries"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    client_ip = Column(String(45), nullable=False, index=True)  # IPv6 can be up to 45 chars
    client_hostname = Column(String(255), nullable=True, index=True)
    query_type = Column(String(10), nullable=True)  # A, AAAA, PTR, etc.
    status = Column(String(50), nullable=True)  # blocked, allowed, etc.
    pihole_server = Column(String(100), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Composite indexes for common query patterns
    __table_args__ = (
        Index('idx_queries_timestamp_domain', 'timestamp', 'domain'),
        Index('idx_queries_timestamp_client', 'timestamp', 'client_ip'),
        Index('idx_queries_domain_client', 'domain', 'client_ip'),
        Index('idx_queries_pihole_timestamp', 'pihole_server', 'timestamp'),
        Index('idx_queries_client_ip_timestamp', 'client_ip', 'timestamp'),  # For top clients stats query
        # Unique constraint to prevent duplicates
        Index('idx_queries_unique', 'timestamp', 'domain', 'client_ip', 'pihole_server', unique=True),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'domain': self.domain,
            'client_ip': self.client_ip,
            'client_hostname': self.client_hostname,
            'query_type': self.query_type,
            'status': self.status,
            'pihole_server': self.pihole_server,
        }


class AlertRule(Base):
    """Alert rule configuration"""
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Pattern matching - supports wildcards like *porn*, *.adult.*, etc.
    # Using Text to support long comma-separated lists
    domain_pattern = Column(Text, nullable=True)
    client_ip_pattern = Column(Text, nullable=True)
    client_hostname_pattern = Column(Text, nullable=True)

    # Exclusion patterns
    exclude_domains = Column(Text, nullable=True)  # JSON array of domains to exclude

    # Notification settings
    notify_telegram = Column(Boolean, default=True)
    telegram_chat_id = Column(String(100), nullable=True)  # Override default chat

    # Alert throttling
    cooldown_minutes = Column(Integer, default=5)  # Min time between batch alerts for same rule

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'domain_pattern': self.domain_pattern,
            'client_ip_pattern': self.client_ip_pattern,
            'client_hostname_pattern': self.client_hostname_pattern,
            'exclude_domains': self.exclude_domains,
            'notify_telegram': self.notify_telegram,
            'telegram_chat_id': self.telegram_chat_id,
            'cooldown_minutes': self.cooldown_minutes,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class AlertHistory(Base):
    """Track when alerts were sent to prevent spam"""
    __tablename__ = "alert_history"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_rule_id = Column(Integer, nullable=False, index=True)
    query_id = Column(BigInteger, nullable=False)
    triggered_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    notification_sent = Column(Boolean, default=False)
    notification_error = Column(Text, nullable=True)

    __table_args__ = (
        Index('idx_alert_history_rule_time', 'alert_rule_id', 'triggered_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'alert_rule_id': self.alert_rule_id,
            'query_id': self.query_id,
            'triggered_at': self.triggered_at.isoformat() if self.triggered_at else None,
            'notification_sent': self.notification_sent,
            'notification_error': self.notification_error,
        }


class AppSetting(Base):
    """Application settings stored in database"""
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
    value_type = Column(String(20), default='string')  # string, int, bool, json
    description = Column(Text, nullable=True)
    requires_restart = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def get_typed_value(self):
        """Convert value to appropriate Python type with error handling"""
        import json
        import logging

        logger = logging.getLogger(__name__)

        # Handle None or empty values
        if self.value is None or self.value == '':
            if self.value_type == 'int':
                return 0
            elif self.value_type == 'bool':
                return False
            elif self.value_type == 'json':
                return None
            return ''

        try:
            if self.value_type == 'int':
                return int(self.value)
            elif self.value_type == 'bool':
                return self.value.lower() in ('true', '1', 'yes')
            elif self.value_type == 'json':
                parsed = json.loads(self.value)
                # Validate JSON structure for known settings
                if self.key == 'cors_origins':
                    if not isinstance(parsed, list):
                        raise ValueError(f"cors_origins must be a list, got {type(parsed)}")
                    if not all(isinstance(origin, str) for origin in parsed):
                        raise ValueError("cors_origins must be a list of strings")
                return parsed
            return self.value
        except (ValueError, AttributeError, json.JSONDecodeError) as e:
            logger.error(f"Error converting setting {self.key} (type={self.value_type}, value={self.value}): {e}")
            # Return safe defaults on error
            if self.value_type == 'int':
                return 0
            elif self.value_type == 'bool':
                return False
            elif self.value_type == 'json':
                return None
            return self.value  # Return string as-is for string type

    def to_dict(self):
        return {
            'key': self.key,
            'value': self.get_typed_value(),
            'value_type': self.value_type,
            'description': self.description,
            'requires_restart': self.requires_restart,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class PiholeServerModel(Base):
    """DNS ad-blocker server configuration stored in database"""
    __tablename__ = "pihole_servers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    url = Column(String(255), nullable=False)
    password = Column(Text, nullable=False)
    username = Column(String(100), nullable=True)  # For AdGuard Home (default: 'admin')
    server_type = Column(String(20), default='pihole')  # 'pihole' or 'adguard'
    skip_ssl_verify = Column(Boolean, default=False)  # Skip SSL certificate verification for self-signed certs
    enabled = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)

    # Sync configuration
    is_source = Column(Boolean, default=False)  # Only one server should be the sync source
    sync_enabled = Column(Boolean, default=False)  # Whether to receive syncs (sync target)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)  # When last synced

    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index('idx_pihole_servers_enabled', 'enabled', 'display_order'),
        Index('idx_pihole_servers_source', 'is_source'),  # For source server queries
        Index('idx_pihole_servers_sync', 'sync_enabled', 'enabled'),  # For target server queries
    )

    def to_dict(self, mask_password: bool = True):
        """
        Serialize to dictionary.

        Args:
            mask_password: If True (default), replace password with asterisks for security.
                          Set to False only for internal use (e.g., ingestion service).
        """
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'password': '********' if mask_password else self.password,
            'username': self.username,
            'server_type': self.server_type or 'pihole',
            'skip_ssl_verify': self.skip_ssl_verify or False,
            'enabled': self.enabled,
            'display_order': self.display_order,
            'is_source': self.is_source,
            'sync_enabled': self.sync_enabled,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class SettingsChangelog(Base):
    """Track settings changes for audit and restart detection"""
    __tablename__ = "settings_changelog"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    setting_key = Column(String(100), nullable=True, index=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    change_type = Column(String(20), nullable=False)  # 'app_setting', 'pihole_server'
    requires_restart = Column(Boolean, default=False)
    changed_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'setting_key': self.setting_key,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'change_type': self.change_type,
            'requires_restart': self.requires_restart,
            'changed_at': self.changed_at.isoformat() if self.changed_at else None,
        }


class SyncHistory(Base):
    """Track Pi-hole configuration sync operations"""
    __tablename__ = "sync_history"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sync_type = Column(String(20), nullable=False)  # 'manual' or 'automatic'
    source_server_id = Column(Integer, nullable=False, index=True)
    target_server_ids = Column(Text, nullable=False)  # JSON array of server IDs
    status = Column(String(20), nullable=False)  # 'success', 'partial', 'failed'
    items_synced = Column(Text, nullable=True)  # JSON object with counts {adlists: 5, whitelist: 10, ...}
    errors = Column(Text, nullable=True)  # JSON array of error messages
    started_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index('idx_sync_history_source_time', 'source_server_id', 'started_at'),
    )

    def to_dict(self):
        import json
        import logging

        logger = logging.getLogger(__name__)

        # Helper function to safely parse JSON with fallback
        def safe_json_parse(value, default):
            if not value:
                return default
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError) as e:
                logger.error(f"Failed to parse JSON in SyncHistory.to_dict(): {e}, value: {value}")
                return default

        return {
            'id': self.id,
            'sync_type': self.sync_type,
            'source_server_id': self.source_server_id,
            'target_server_ids': safe_json_parse(self.target_server_ids, []),
            'status': self.status,
            'items_synced': safe_json_parse(self.items_synced, {}),
            'errors': safe_json_parse(self.errors, []),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


class BlockingOverride(Base):
    """Track blocking disable events for auto-re-enable functionality"""
    __tablename__ = "blocking_overrides"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey('pihole_servers.id', ondelete='CASCADE'), nullable=False, index=True)
    disabled_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    auto_enable_at = Column(DateTime(timezone=True), nullable=True)  # null = manual re-enable only
    enabled_at = Column(DateTime(timezone=True), nullable=True)  # null = still disabled
    disabled_by = Column(String(50), default='user')  # 'user' or 'api'

    __table_args__ = (
        Index('idx_blocking_overrides_pending', 'auto_enable_at', 'enabled_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'server_id': self.server_id,
            'disabled_at': self.disabled_at.isoformat() if self.disabled_at else None,
            'auto_enable_at': self.auto_enable_at.isoformat() if self.auto_enable_at else None,
            'enabled_at': self.enabled_at.isoformat() if self.enabled_at else None,
            'disabled_by': self.disabled_by,
        }


class User(Base):
    """User account for authentication"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identity
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    display_name = Column(String(255), nullable=True)

    # Local authentication (null for OIDC-only users)
    password_hash = Column(String(255), nullable=True)

    # OIDC linking
    oidc_provider = Column(String(100), nullable=True, index=True)  # e.g., 'authentik'
    oidc_subject = Column(String(255), nullable=True)  # 'sub' claim from OIDC

    # Status
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index('idx_users_oidc', 'oidc_provider', 'oidc_subject', unique=True,
              postgresql_where=Column('oidc_provider').isnot(None)),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'display_name': self.display_name,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'oidc_provider': self.oidc_provider,
            'has_local_password': self.password_hash is not None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
        }


class Session(Base):
    """User session for authentication state"""
    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True)  # Random session token
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Session metadata
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_activity_at = Column(DateTime(timezone=True), default=utcnow)

    # Security tracking
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)

    __table_args__ = (
        Index('idx_sessions_expires', 'expires_at'),
        Index('idx_sessions_user_activity', 'user_id', 'last_activity_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_activity_at': self.last_activity_at.isoformat() if self.last_activity_at else None,
            'ip_address': self.ip_address,
        }


class OIDCProvider(Base):
    """OIDC provider configuration"""
    __tablename__ = "oidc_providers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)  # e.g., 'authentik'
    display_name = Column(String(255), nullable=False)  # e.g., 'Login with Authentik'

    # OIDC configuration
    issuer_url = Column(String(500), nullable=False)  # e.g., https://auth.example.com
    client_id = Column(String(255), nullable=False)
    client_secret = Column(Text, nullable=False)
    scopes = Column(String(500), default='openid profile email')

    # Claim mappings
    username_claim = Column(String(100), default='preferred_username')
    email_claim = Column(String(100), default='email')
    display_name_claim = Column(String(100), default='name')
    groups_claim = Column(String(100), nullable=True)  # e.g., 'groups'
    admin_group = Column(String(255), nullable=True)  # Group name that grants admin

    # Status
    enabled = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def to_dict(self, mask_secret: bool = True):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'issuer_url': self.issuer_url,
            'client_id': self.client_id,
            'client_secret': '********' if mask_secret else self.client_secret,
            'scopes': self.scopes,
            'username_claim': self.username_claim,
            'email_claim': self.email_claim,
            'display_name_claim': self.display_name_claim,
            'groups_claim': self.groups_claim,
            'admin_group': self.admin_group,
            'enabled': self.enabled,
            'display_order': self.display_order,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
