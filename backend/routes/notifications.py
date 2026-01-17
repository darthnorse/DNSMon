"""
Notification channels routes - CRUD operations for notification channels
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, NotificationChannel
from ..notifications import SENDERS, render_template, truncate_message, AlertContext, DEFAULT_TEMPLATE
from ..auth import get_current_user, require_admin

router = APIRouter(prefix="/api/notification-channels", tags=["notifications"])


class NotificationChannelCreate(BaseModel):
    name: str = Field(max_length=100)
    channel_type: str  # telegram, pushover, ntfy, webhook, discord
    config: Dict[str, Any]
    message_template: Optional[str] = None
    enabled: bool = True


class NotificationChannelUpdate(BaseModel):
    name: Optional[str] = Field(max_length=100, default=None)
    config: Optional[Dict[str, Any]] = None
    message_template: Optional[str] = None
    enabled: Optional[bool] = None


# NOTE: Static routes must come before /{channel_id} to avoid path conflict
@router.get("/template-variables")
async def get_template_variables(_: User = Depends(get_current_user)):
    """Get list of available template variables"""
    return {
        "variables": [
            {"name": "{rule_name}", "description": "Alert rule name", "example": "Block Adult Content"},
            {"name": "{count}", "description": "Number of matching queries", "example": "5"},
            {"name": "{query_list}", "description": "All queries, one per line (domain - client)", "example": "ads.com - 192.168.1.50\\ntracker.com - 192.168.1.51"},
            {"name": "{domains}", "description": "All domains (comma-separated)", "example": "ads.google.com, tracker.fb.com"},
            {"name": "{clients}", "description": "All clients (comma-separated)", "example": "johns-iphone, 192.168.1.50"},
            {"name": "{domain}", "description": "First queried domain", "example": "ads.google.com"},
            {"name": "{client_ip}", "description": "First client IP address", "example": "192.168.1.100"},
            {"name": "{client_hostname}", "description": "First client hostname", "example": "johns-iphone.local"},
            {"name": "{server_name}", "description": "DNS server name", "example": "pihole1"},
            {"name": "{timestamp}", "description": "First query timestamp", "example": "2026-01-16 09:30:45"},
            {"name": "{query_type}", "description": "First DNS query type", "example": "A"},
            {"name": "{status}", "description": "First query status", "example": "Blocked"},
            {"name": "{answer}", "description": "First DNS answer", "example": "93.184.216.34"},
        ],
        "default_template": DEFAULT_TEMPLATE,
    }


@router.get("/channel-types")
async def get_channel_types(_: User = Depends(get_current_user)):
    """Get list of supported channel types with their configuration requirements"""
    # Common option for all channel types
    dedupe_option = {"name": "dedupe_domains", "label": "Deduplicate domains", "type": "checkbox", "required": False, "description": "Show only unique domains instead of all matches"}

    return {
        "channel_types": [
            {
                "type": "telegram",
                "name": "Telegram",
                "icon": "telegram",
                "config_fields": [
                    {"name": "bot_token", "label": "Bot Token", "type": "password", "required": True},
                    {"name": "chat_id", "label": "Chat ID", "type": "text", "required": True},
                    dedupe_option,
                ]
            },
            {
                "type": "pushover",
                "name": "Pushover",
                "icon": "bell",
                "config_fields": [
                    {"name": "app_token", "label": "App Token", "type": "password", "required": True},
                    {"name": "user_key", "label": "User Key", "type": "password", "required": True},
                    {"name": "title", "label": "Title", "type": "text", "required": False, "placeholder": "DNSMon Alert"},
                    {"name": "priority", "label": "Priority (-2 to 2)", "type": "number", "required": False, "placeholder": "0"},
                    {"name": "sound", "label": "Sound", "type": "text", "required": False, "placeholder": "pushover"},
                    dedupe_option,
                ]
            },
            {
                "type": "ntfy",
                "name": "Ntfy",
                "icon": "broadcast",
                "config_fields": [
                    {"name": "server_url", "label": "Server URL", "type": "text", "required": False, "placeholder": "https://ntfy.sh"},
                    {"name": "topic", "label": "Topic", "type": "text", "required": True},
                    {"name": "title", "label": "Title", "type": "text", "required": False, "placeholder": "DNSMon Alert"},
                    {"name": "priority", "label": "Priority (1-5)", "type": "number", "required": False, "placeholder": "3"},
                    {"name": "auth_token", "label": "Auth Token", "type": "password", "required": False},
                    dedupe_option,
                ]
            },
            {
                "type": "discord",
                "name": "Discord",
                "icon": "discord",
                "config_fields": [
                    {"name": "webhook_url", "label": "Webhook URL", "type": "password", "required": True},
                    dedupe_option,
                ]
            },
            {
                "type": "webhook",
                "name": "Webhook",
                "icon": "link",
                "config_fields": [
                    {"name": "url", "label": "URL", "type": "text", "required": True},
                    {"name": "method", "label": "Method", "type": "select", "required": False, "options": ["POST", "PUT", "GET"], "placeholder": "POST"},
                    dedupe_option,
                ]
            },
        ]
    }


@router.get("")
async def list_channels(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """List all notification channels"""
    stmt = select(NotificationChannel).order_by(NotificationChannel.name)
    result = await db.execute(stmt)
    return [c.to_dict(mask_secrets=True) for c in result.scalars()]


@router.post("")
async def create_channel(
    data: NotificationChannelCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Create a new notification channel"""
    # Validate channel type
    if data.channel_type not in SENDERS:
        raise HTTPException(400, f"Invalid channel_type. Must be one of: {list(SENDERS.keys())}")

    # Validate config
    sender = SENDERS[data.channel_type]
    errors = sender.validate_config(data.config)
    if errors:
        raise HTTPException(400, f"Invalid config: {', '.join(errors)}")

    channel = NotificationChannel(**data.model_dump())
    db.add(channel)
    await db.commit()
    await db.refresh(channel)
    return channel.to_dict(mask_secrets=True)


@router.get("/{channel_id}")
async def get_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get a notification channel by ID"""
    stmt = select(NotificationChannel).where(NotificationChannel.id == channel_id)
    result = await db.execute(stmt)
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(404, "Channel not found")
    return channel.to_dict(mask_secrets=True)


@router.put("/{channel_id}")
async def update_channel(
    channel_id: int,
    data: NotificationChannelUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Update a notification channel"""
    stmt = select(NotificationChannel).where(NotificationChannel.id == channel_id)
    result = await db.execute(stmt)
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(404, "Channel not found")

    update_data = data.model_dump(exclude_unset=True)

    # If config is being updated, validate it
    if 'config' in update_data and update_data['config']:
        # Merge with existing config, but skip masked values
        new_config = channel.config.copy() if channel.config else {}
        for key, value in update_data['config'].items():
            # Skip masked values - keep existing value
            if value != '********':
                new_config[key] = value

        sender = SENDERS[channel.channel_type]
        errors = sender.validate_config(new_config)
        if errors:
            raise HTTPException(400, f"Invalid config: {', '.join(errors)}")
        update_data['config'] = new_config

    for key, value in update_data.items():
        setattr(channel, key, value)

    channel.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(channel)
    return channel.to_dict(mask_secrets=True)


@router.delete("/{channel_id}")
async def delete_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Delete a notification channel"""
    stmt = select(NotificationChannel).where(NotificationChannel.id == channel_id)
    result = await db.execute(stmt)
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(404, "Channel not found")

    await db.delete(channel)
    await db.commit()
    return {"message": "Channel deleted"}


@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Send a test notification to a channel"""
    stmt = select(NotificationChannel).where(NotificationChannel.id == channel_id)
    result = await db.execute(stmt)
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(404, "Channel not found")

    # Create test context with sample batch data
    context = AlertContext(
        domain="test.example.com",
        client_ip="192.168.1.100",
        client_hostname="test-device.local",
        rule_name="Test Alert",
        server_name="pihole1",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        query_type="A",
        status="Blocked",
        count=3,
        query_list="test.example.com - test-device.local\nads.tracker.com - 192.168.1.50\nanalytics.test.org - test-device.local",
        domains="test.example.com, ads.tracker.com, analytics.test.org",
        clients="test-device.local, 192.168.1.50",
    )

    sender = SENDERS.get(channel.channel_type)
    if not sender:
        raise HTTPException(400, f"Unknown channel type: {channel.channel_type}")

    try:
        message = render_template(channel.message_template, context)
        message = truncate_message(message, channel.channel_type)
        success, error = await sender.send(message, channel.config)

        # Update channel status
        now = datetime.now(timezone.utc)
        if success:
            channel.last_success_at = now
            channel.last_error = None
            channel.last_error_at = None
            channel.consecutive_failures = 0
            await db.commit()
            return {"success": True, "message": "Test notification sent successfully"}
        else:
            channel.last_error = error
            channel.last_error_at = now
            channel.consecutive_failures += 1
            await db.commit()
            return {"success": False, "message": f"Failed to send test notification: {error}"}
    except Exception as e:
        channel.last_error = str(e)
        channel.last_error_at = datetime.now(timezone.utc)
        channel.consecutive_failures += 1
        await db.commit()
        return {"success": False, "message": f"Error sending test notification: {str(e)}"}
