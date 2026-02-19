"""
Pydantic schemas for DNSMon API.
Shared across all route modules.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from pydantic import BaseModel, Field as PydanticField, field_validator


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
    enabled: bool = True


class AlertRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    domain_pattern: Optional[str]
    client_ip_pattern: Optional[str]
    client_hostname_pattern: Optional[str]
    exclude_domains: Optional[str]
    cooldown_minutes: int
    enabled: bool
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


# ============================================================================
# Stats Schemas
# ============================================================================

class StatsResponse(BaseModel):
    total_queries: int
    queries_last_24h: int
    blocks_last_24h: int
    queries_last_7d: int
    top_domains: List[dict]
    top_clients: List[dict]
    queries_by_server: List[dict]


class StatisticsResponse(BaseModel):
    """Comprehensive statistics response"""
    # Query Overview
    queries_today: int
    queries_week: int
    queries_month: int
    queries_total: int
    blocked_today: int
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
    client_secret: str = PydanticField(min_length=1)
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
    client_secret: Optional[str] = None
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
    value: str


class PiholeServerCreate(BaseModel):
    name: str = PydanticField(max_length=100)
    url: str = PydanticField(max_length=255)
    password: str
    username: Optional[str] = PydanticField(default=None, max_length=100)
    server_type: str = 'pihole'
    skip_ssl_verify: bool = False
    enabled: bool = True
    is_source: bool = False
    sync_enabled: bool = False

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith('http://') and not v.startswith('https://'):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip('/')


class PiholeServerUpdate(BaseModel):
    name: Optional[str] = PydanticField(default=None, max_length=100)
    url: Optional[str] = PydanticField(default=None, max_length=255)
    password: Optional[str] = None
    username: Optional[str] = None
    server_type: Optional[str] = None
    skip_ssl_verify: Optional[bool] = None
    enabled: Optional[bool] = None
    display_order: Optional[int] = None
    is_source: Optional[bool] = None
    sync_enabled: Optional[bool] = None


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
