"""
Pydantic schemas for DNSMon API.
Shared across all route modules.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import ClassVar, Literal, Optional, List, Tuple, Union, get_args, get_origin

from pydantic import BaseModel, Field as PydanticField, field_validator, model_validator


MatchStatus = Literal['any', 'blocked', 'allowed']


# ============================================================================
# Query Schemas
# ============================================================================

class QueryResponse(BaseModel):
    id: int
    timestamp: str
    domain: str
    client_ip: str
    client_hostname: Optional[str]
    query_type: Optional[str]
    status: Optional[str]
    server: str

    class Config:
        from_attributes = True


class QuerySearchParams(BaseModel):
    domain: Optional[str] = None
    client_ip: Optional[str] = None
    client_hostname: Optional[str] = None
    server: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


# ============================================================================
# Alert Rule Schemas
# ============================================================================

class AlertRuleCreate(BaseModel):
    name: str = PydanticField(max_length=100)
    description: Optional[str] = PydanticField(default=None, max_length=500)
    domain_pattern: Optional[str] = PydanticField(default=None, max_length=5000)
    client_ip_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    client_hostname_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    exclude_domains: Optional[str] = PydanticField(default=None, max_length=5000)
    cooldown_minutes: int = PydanticField(default=5, ge=0, le=10080)  # 0 to 7 days
    match_status: MatchStatus = 'any'
    enabled: bool = True


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = PydanticField(default=None, max_length=100)
    description: Optional[str] = PydanticField(default=None, max_length=500)
    domain_pattern: Optional[str] = PydanticField(default=None, max_length=5000)
    client_ip_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    client_hostname_pattern: Optional[str] = PydanticField(default=None, max_length=500)
    exclude_domains: Optional[str] = PydanticField(default=None, max_length=5000)
    cooldown_minutes: Optional[int] = PydanticField(default=None, ge=0, le=10080)
    match_status: Optional[MatchStatus] = None
    enabled: Optional[bool] = None

    # Populated below from AlertRuleResponse.model_fields. Any field that the
    # response declares as non-Optional cannot be set to JSON null on update
    # without breaking serialization downstream.
    _NOT_NULL_FIELDS: ClassVar[Tuple[str, ...]] = ()

    @model_validator(mode='before')
    @classmethod
    def reject_explicit_null_for_required(cls, data):
        if isinstance(data, dict):
            for key in cls._NOT_NULL_FIELDS:
                if key in data and data[key] is None:
                    raise ValueError(f"{key} cannot be null; omit the field to leave it unchanged")
        return data


class AlertRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    domain_pattern: Optional[str]
    client_ip_pattern: Optional[str]
    client_hostname_pattern: Optional[str]
    exclude_domains: Optional[str]
    cooldown_minutes: int
    match_status: MatchStatus
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

    @field_validator('created_at', 'updated_at', mode='after')
    @classmethod
    def coerce_to_utc(cls, v: datetime) -> datetime:
        # DateTime(timezone=True) columns return tz-aware datetimes from PG; this
        # guards against naive datetimes leaking in from other call sites.
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


def _response_required_field_names(response_cls: type) -> Tuple[str, ...]:
    """Names of fields whose annotation does not accept None."""
    out = []
    for name, field in response_cls.model_fields.items():
        ann = field.annotation
        # Detect Optional[X] / Union[..., None] by checking the type args.
        if get_origin(ann) is Union and type(None) in get_args(ann):
            continue
        out.append(name)
    return tuple(out)


# Auto-sync the null-rejection set with whatever AlertRuleResponse considers
# required, intersected with what AlertRuleUpdate accepts. Adding a new
# non-Optional field to the response automatically extends protection.
_RESPONSE_REQUIRED = set(_response_required_field_names(AlertRuleResponse))
_UPDATE_FIELDS = set(AlertRuleUpdate.model_fields.keys())
AlertRuleUpdate._NOT_NULL_FIELDS = tuple(sorted(_RESPONSE_REQUIRED & _UPDATE_FIELDS))


# ============================================================================
# Stats Schemas
# ============================================================================

class StatsResponse(BaseModel):
    queries_last_24h: int
    blocks_last_24h: int


class StatisticsResponse(BaseModel):
    """Comprehensive statistics response"""
    # Query Overview
    queries_today: int
    queries_week: int
    queries_month: int
    queries_total: int
    queries_period: int  # Total queries for the active period/custom range
    blocked_period: int
    blocked_percentage: float

    # Time Series
    queries_hourly: List[dict]
    queries_daily: List[dict]

    # Top Lists
    top_domains: List[dict]
    top_blocked_domains: List[dict]
    top_clients: List[dict]

    # Per Server
    queries_by_server: List[dict]

    # Client Insights
    unique_clients: int
    most_active_client: Optional[dict]
    new_clients_24h: int


# ============================================================================
# Authentication Schemas
# ============================================================================

class LoginRequest(BaseModel):
    username: str = PydanticField(min_length=1, max_length=100)
    password: str = PydanticField(min_length=1, max_length=255)


class SetupRequest(BaseModel):
    username: str = PydanticField(min_length=3, max_length=100)
    password: str = PydanticField(min_length=8, max_length=255)
    email: Optional[str] = PydanticField(default=None, max_length=255)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        return v.lower()

    @field_validator('email')
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == '':
            return None
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
            raise ValueError("Invalid email format")
        return v.lower()


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str]
    display_name: Optional[str]
    is_active: bool
    is_admin: bool
    oidc_provider: Optional[str]
    oidc_provider_display: Optional[str] = None
    has_local_password: bool
    created_at: Optional[str]
    last_login_at: Optional[str]


class AuthCheckResponse(BaseModel):
    authenticated: bool
    user: Optional[UserResponse]
    setup_complete: bool


class UserCreate(BaseModel):
    username: str = PydanticField(min_length=3, max_length=100)
    password: Optional[str] = PydanticField(default=None, min_length=8, max_length=255)
    email: Optional[str] = PydanticField(default=None, max_length=255)
    display_name: Optional[str] = PydanticField(default=None, max_length=255)
    is_admin: bool = False

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        return v.lower()


class UserUpdate(BaseModel):
    email: Optional[str] = PydanticField(default=None, max_length=255)
    display_name: Optional[str] = PydanticField(default=None, max_length=255)
    password: Optional[str] = PydanticField(default=None, min_length=8, max_length=255)
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None


# ============================================================================
# OIDC Provider Schemas
# ============================================================================

class OIDCProviderPublic(BaseModel):
    """Public OIDC provider info for login page"""
    name: str
    display_name: str


class OIDCProviderResponse(BaseModel):
    """Full OIDC provider info (admin)"""
    id: int
    name: str
    display_name: str
    issuer_url: str
    client_id: str
    client_secret: str  # Will be masked
    scopes: str
    username_claim: str
    email_claim: str
    display_name_claim: str
    groups_claim: Optional[str]
    admin_group: Optional[str]
    enabled: bool
    display_order: int
    created_at: Optional[str]
    updated_at: Optional[str]


class OIDCProviderCreate(BaseModel):
    name: str = PydanticField(min_length=1, max_length=100)
    display_name: str = PydanticField(min_length=1, max_length=255)
    issuer_url: str = PydanticField(min_length=1, max_length=500)
    client_id: str = PydanticField(min_length=1, max_length=255)
    client_secret: str = PydanticField(min_length=1, max_length=10000)
    scopes: str = 'openid profile email'
    username_claim: str = 'preferred_username'
    email_claim: str = 'email'
    display_name_claim: str = 'name'
    groups_claim: Optional[str] = None
    admin_group: Optional[str] = None
    enabled: bool = True
    display_order: int = 0

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Name can only contain lowercase letters, numbers, underscores, and hyphens")
        return v.lower()

    @field_validator('issuer_url')
    @classmethod
    def validate_issuer_url(cls, v: str) -> str:
        if not v.startswith('http://') and not v.startswith('https://'):
            raise ValueError("Issuer URL must start with http:// or https://")
        return v.rstrip('/')


class OIDCProviderUpdate(BaseModel):
    display_name: Optional[str] = PydanticField(default=None, max_length=255)
    issuer_url: Optional[str] = PydanticField(default=None, max_length=500)
    client_id: Optional[str] = PydanticField(default=None, max_length=255)
    client_secret: Optional[str] = PydanticField(default=None, max_length=10000)
    scopes: Optional[str] = None
    username_claim: Optional[str] = None
    email_claim: Optional[str] = None
    display_name_claim: Optional[str] = None
    groups_claim: Optional[str] = None
    admin_group: Optional[str] = None
    enabled: Optional[bool] = None
    display_order: Optional[int] = None


# ============================================================================
# Settings Schemas
# ============================================================================

class AppSettingUpdate(BaseModel):
    value: str = PydanticField(max_length=65536)


VALID_SERVER_TYPES = {'pihole', 'adguard', 'technitium'}
VALID_EXTRA_CONFIG_KEYS = {'log_app_name', 'log_app_class_path'}


def _check_server_type(v: Optional[str]) -> Optional[str]:
    if v is not None and v not in VALID_SERVER_TYPES:
        raise ValueError(f"server_type must be one of: {', '.join(sorted(VALID_SERVER_TYPES))}")
    return v


def _check_extra_config(v: Optional[dict]) -> Optional[dict]:
    if v is not None:
        unknown = set(v.keys()) - VALID_EXTRA_CONFIG_KEYS
        if unknown:
            raise ValueError(f"Unknown extra_config keys: {unknown}")
        cleaned = {}
        for key, val in v.items():
            if not isinstance(val, str):
                raise ValueError(f"extra_config values must be strings, got {type(val).__name__} for '{key}'")
            if val.strip():
                cleaned[key] = val.strip()
        return cleaned or None
    return v


def _check_url(v: Optional[str]) -> Optional[str]:
    if v is not None:
        if not v.startswith('http://') and not v.startswith('https://'):
            raise ValueError("URL must start with http:// or https://")
        v = v.rstrip('/')
    return v


class PiholeServerCreate(BaseModel):
    name: str = PydanticField(max_length=100)
    url: str = PydanticField(max_length=255)
    password: str = PydanticField(max_length=10000)
    username: Optional[str] = PydanticField(default=None, max_length=100)
    server_type: str = 'pihole'
    skip_ssl_verify: bool = False
    extra_config: Optional[dict] = None
    enabled: bool = True
    is_source: bool = False
    sync_enabled: bool = False

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith('http://') and not v.startswith('https://'):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip('/')

    validate_server_type = field_validator('server_type')(_check_server_type)
    validate_extra_config = field_validator('extra_config')(_check_extra_config)


class PiholeServerUpdate(BaseModel):
    name: Optional[str] = PydanticField(default=None, max_length=100)
    url: Optional[str] = PydanticField(default=None, max_length=255)
    password: Optional[str] = PydanticField(default=None, max_length=10000)
    username: Optional[str] = None
    server_type: Optional[str] = None
    skip_ssl_verify: Optional[bool] = None
    extra_config: Optional[dict] = None
    enabled: Optional[bool] = None
    display_order: Optional[int] = None
    is_source: Optional[bool] = None
    sync_enabled: Optional[bool] = None

    validate_url = field_validator('url')(_check_url)
    validate_server_type = field_validator('server_type')(_check_server_type)
    validate_extra_config = field_validator('extra_config')(_check_extra_config)


class SettingsResponse(BaseModel):
    app_settings: dict
    servers: List[dict]


# ============================================================================
# Domain Schemas
# ============================================================================

class DomainRequest(BaseModel):
    domain: str = PydanticField(min_length=1, max_length=255)

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain is not empty and strip whitespace"""
        v = v.strip()
        if not v:
            raise ValueError("Domain cannot be empty")
        return v


# ============================================================================
# Blocking Schemas
# ============================================================================

class BlockingSetRequest(BaseModel):
    enabled: bool
    duration_minutes: Optional[int] = PydanticField(default=None, ge=1, le=1440)


# ============================================================================
# API Key Schemas
# ============================================================================

class ApiKeyCreate(BaseModel):
    name: str = PydanticField(min_length=1, max_length=100)
    is_admin: bool = False
    expires_at: Optional[datetime] = None

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be blank")
        if not re.match(r'^[a-zA-Z0-9 _-]+$', v):
            raise ValueError("Name can only contain letters, numbers, spaces, underscores, and hyphens")
        return v

    @field_validator('expires_at')
    @classmethod
    def validate_expires_at(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None:
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            if v <= datetime.now(timezone.utc) + timedelta(minutes=1):
                raise ValueError("Expiration date must be at least 1 minute in the future")
        return v


# ============================================================================
# Classification / Insights Schemas
# ============================================================================

class AppUsage(BaseModel):
    app_name: str
    category: Optional[str]
    total: int
    blocked: int


class CategoryUsage(BaseModel):
    category: str
    total: int
    blocked: int


class DomainUsage(BaseModel):
    domain: str
    total: int
    blocked: int


class AppDefinitionCreate(BaseModel):
    name: str = PydanticField(max_length=150)
    category: Optional[str] = PydanticField(default=None, max_length=50)
    domains: List[str] = PydanticField(min_length=1)
    enabled: bool = True


class AppDefinitionUpdate(BaseModel):
    name: Optional[str] = PydanticField(default=None, max_length=150)
    category: Optional[str] = PydanticField(default=None, max_length=50)
    domains: Optional[List[str]] = None
    enabled: Optional[bool] = None


class AppDefinitionResponse(BaseModel):
    id: int
    slug: str
    name: str
    category: Optional[str]
    source: str
    icon_svg: Optional[str]
    enabled: bool
    domains: List[str]
    created_at: datetime
    updated_at: datetime

    @field_validator('created_at', 'updated_at', mode='after')
    @classmethod
    def coerce_to_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class FeedStatusResponse(BaseModel):
    feed_enabled: bool
    feed_url: str
    supplement_enabled: bool
    adguard_app_count: int
    supplement_app_count: int
    manual_app_count: int
    labeled_domain_count: int
    last_refreshed_at: Optional[datetime]
