import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
import httpx

from .models import Query, AlertRule

logger = logging.getLogger(__name__)

# HTTP timeout for all notification requests (seconds)
HTTP_TIMEOUT = 10.0

# Message length limits per channel
MESSAGE_LIMITS = {
    'telegram': 4096,
    'discord': 2000,
    'pushover': 1024,
    'ntfy': 4096,
    'webhook': None,  # No limit
}

DEFAULT_TEMPLATE = """Alert: {rule_name} ({count} queries)
{query_list}"""


@dataclass
class AlertContext:
    """Context for rendering alert templates"""
    domain: str
    client_ip: str
    client_hostname: Optional[str]
    rule_name: str
    server_name: str
    timestamp: str
    query_type: str
    status: str
    count: int
    answer: Optional[str] = None
    # Batch fields
    query_list: str = ""  # One query per line: "domain - client"
    domains: str = ""  # Comma-separated list of domains
    clients: str = ""  # Comma-separated list of clients (IP or hostname)


class NotificationSender(ABC):
    """Base class for notification senders"""

    channel_type: str = ""

    @abstractmethod
    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        """Send notification. Returns (success, error_message)"""
        pass

    @abstractmethod
    def validate_config(self, config: dict) -> List[str]:
        """Returns list of validation errors, empty if valid"""
        pass


class TelegramSender(NotificationSender):
    """Telegram notification sender using HTTP API"""
    channel_type = "telegram"

    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        bot_token = config.get('bot_token')
        chat_id = config.get('chat_id')

        if not bot_token or not chat_id:
            return False, "Missing bot_token or chat_id"

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={"chat_id": chat_id, "text": message}
                )
                if response.status_code == 200:
                    return True, None
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.TimeoutException:
            return False, "Request timed out"
        except Exception as e:
            return False, str(e)

    def validate_config(self, config: dict) -> List[str]:
        errors = []
        if not config.get('bot_token'):
            errors.append('bot_token is required')
        if not config.get('chat_id'):
            errors.append('chat_id is required')
        return errors


class PushoverSender(NotificationSender):
    """Pushover notification sender"""
    channel_type = "pushover"

    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        app_token = config.get('app_token')
        user_key = config.get('user_key')

        if not app_token or not user_key:
            return False, "Missing app_token or user_key"

        try:
            data = {
                "token": app_token,
                "user": user_key,
                "message": message,
            }
            if config.get('priority') not in (None, ''):
                data["priority"] = int(config['priority'])
            if config.get('sound'):
                data["sound"] = config['sound']
            if config.get('title'):
                data["title"] = config['title']

            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.post(
                    "https://api.pushover.net/1/messages.json",
                    data=data
                )
                if response.status_code == 200:
                    return True, None
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.TimeoutException:
            return False, "Request timed out"
        except Exception as e:
            return False, str(e)

    def validate_config(self, config: dict) -> List[str]:
        errors = []
        if not config.get('app_token'):
            errors.append('app_token is required')
        if not config.get('user_key'):
            errors.append('user_key is required')
        priority = config.get('priority')
        if priority is not None and priority != '':
            try:
                if not (-2 <= int(priority) <= 2):
                    errors.append('priority must be between -2 and 2')
            except (ValueError, TypeError):
                errors.append('priority must be a number between -2 and 2')
        return errors


class NtfySender(NotificationSender):
    """Ntfy notification sender"""
    channel_type = "ntfy"

    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        server_url = config.get('server_url', 'https://ntfy.sh').rstrip('/')
        topic = config.get('topic')

        if not topic:
            return False, "Missing topic"

        headers = {}
        if config.get('priority'):
            headers["Priority"] = str(config['priority'])
        if config.get('title'):
            headers["Title"] = config['title']
        if config.get('auth_token'):
            headers["Authorization"] = f"Bearer {config['auth_token']}"

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.post(
                    f"{server_url}/{topic}",
                    content=message,
                    headers=headers
                )
                if response.status_code == 200:
                    return True, None
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.TimeoutException:
            return False, "Request timed out"
        except Exception as e:
            return False, str(e)

    def validate_config(self, config: dict) -> List[str]:
        errors = []
        if not config.get('topic'):
            errors.append('topic is required')
        priority = config.get('priority')
        if priority is not None and priority != '':
            try:
                if not (1 <= int(priority) <= 5):
                    errors.append('priority must be between 1 and 5')
            except (ValueError, TypeError):
                errors.append('priority must be a number between 1 and 5')
        return errors


class DiscordSender(NotificationSender):
    """Discord webhook notification sender"""
    channel_type = "discord"

    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        webhook_url = config.get('webhook_url')
        if not webhook_url:
            return False, "Missing webhook_url"

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.post(
                    webhook_url,
                    json={"content": message}
                )
                if response.status_code in (200, 204):
                    return True, None
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.TimeoutException:
            return False, "Request timed out"
        except Exception as e:
            return False, str(e)

    def validate_config(self, config: dict) -> List[str]:
        errors = []
        webhook_url = config.get('webhook_url', '')
        if not webhook_url:
            errors.append('webhook_url is required')
        elif not (webhook_url.startswith('https://discord.com/api/webhooks/') or
                  webhook_url.startswith('https://discordapp.com/api/webhooks/')):
            errors.append('Invalid Discord webhook URL')
        return errors


class WebhookSender(NotificationSender):
    """Generic webhook notification sender"""
    channel_type = "webhook"

    async def send(self, message: str, config: dict) -> Tuple[bool, Optional[str]]:
        url = config.get('url')
        if not url:
            return False, "Missing url"

        method = config.get('method', 'POST').upper()
        headers = config.get('headers', {}).copy()
        headers.setdefault('Content-Type', 'application/json')

        body = {
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "dnsmon"
        }

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                if method == 'GET':
                    response = await client.get(url, headers=headers, params={"message": message})
                else:
                    response = await client.request(method, url, json=body, headers=headers)

                if response.status_code < 400:
                    return True, None
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.TimeoutException:
            return False, "Request timed out"
        except Exception as e:
            return False, str(e)

    def validate_config(self, config: dict) -> List[str]:
        errors = []
        url = config.get('url', '')
        if not url:
            errors.append('url is required')
        elif not url.startswith(('http://', 'https://')):
            errors.append('url must start with http:// or https://')
        method = config.get('method', 'POST').upper()
        if method not in ('GET', 'POST', 'PUT'):
            errors.append('method must be GET, POST, or PUT')
        return errors


# Registry of senders
SENDERS: Dict[str, NotificationSender] = {
    'telegram': TelegramSender(),
    'pushover': PushoverSender(),
    'ntfy': NtfySender(),
    'discord': DiscordSender(),
    'webhook': WebhookSender(),
}


def render_template(template: Optional[str], context: AlertContext) -> str:
    """Render a message template with the given context"""
    if not template:
        template = DEFAULT_TEMPLATE

    # Replace all variables with safe defaults for None values
    replacements = {
        '{domain}': context.domain or '',
        '{client_ip}': context.client_ip or '',
        '{client_hostname}': context.client_hostname or 'unknown',
        '{rule_name}': context.rule_name or '',
        '{server_name}': context.server_name or '',
        '{timestamp}': context.timestamp or '',
        '{query_type}': context.query_type or '',
        '{status}': context.status or '',
        '{count}': str(context.count),
        '{answer}': context.answer or '',
        # Batch fields
        '{query_list}': context.query_list or f"{context.domain} - {context.client_ip}",
        '{domains}': context.domains or context.domain or '',
        '{clients}': context.clients or context.client_ip or '',
    }

    message = template
    for var, value in replacements.items():
        message = message.replace(var, value)

    return message


def truncate_message(message: str, channel_type: str) -> str:
    """Truncate message to fit channel limits"""
    limit = MESSAGE_LIMITS.get(channel_type)
    if limit and len(message) > limit:
        return message[:limit - 15] + "... [truncated]"
    return message


class NotificationService:
    """Service for sending notifications to all enabled channels"""

    async def send_alert(self, context: AlertContext) -> Dict[int, bool]:
        """Send alert to all enabled notification channels.
        Returns dict of {channel_id: success}"""
        from .database import async_session_maker
        from .models import NotificationChannel
        from sqlalchemy import select

        results = {}

        async with async_session_maker() as session:
            stmt = select(NotificationChannel).where(NotificationChannel.enabled == True)
            result = await session.execute(stmt)
            channels = result.scalars().all()

            for channel in channels:
                sender = SENDERS.get(channel.channel_type)
                if not sender:
                    logger.warning(f"Unknown channel type: {channel.channel_type}")
                    results[channel.id] = False
                    continue

                try:
                    message = render_template(channel.message_template, context)
                    message = truncate_message(message, channel.channel_type)

                    success, error = await sender.send(message, channel.config)
                    results[channel.id] = success

                    # Update channel status
                    now = datetime.now(timezone.utc)
                    if success:
                        channel.last_success_at = now
                        channel.last_error = None
                        channel.last_error_at = None
                        channel.consecutive_failures = 0
                        logger.info(f"Sent notification to channel {channel.name}")
                    else:
                        channel.last_error = error
                        channel.last_error_at = now
                        channel.consecutive_failures += 1
                        logger.warning(f"Failed to send to channel {channel.name}: {error}")

                except Exception as e:
                    logger.error(f"Error sending to channel {channel.name}: {e}")
                    channel.last_error = str(e)
                    channel.last_error_at = datetime.now(timezone.utc)
                    channel.consecutive_failures += 1
                    results[channel.id] = False

            await session.commit()

        return results

    def _build_batch_context(self, queries: List, rule: AlertRule, dedupe: bool = False) -> AlertContext:
        """Build alert context from a batch of queries.

        Args:
            queries: List of matching queries
            rule: The alert rule that matched
            dedupe: If True, only include unique domain-client pairs. If False, include all.
        """
        first_query = queries[0]

        if dedupe:
            # Collect unique domain-client pairs
            query_lines = []
            seen_pairs = set()
            domains = []
            clients = []
            seen_domains = set()
            seen_clients = set()

            for q in queries:
                client_display = q.client_hostname or q.client_ip
                pair = (q.domain, client_display)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    query_lines.append(f"{q.domain} - {client_display}")

                if q.domain and q.domain not in seen_domains:
                    seen_domains.add(q.domain)
                    domains.append(q.domain)
                if client_display and client_display not in seen_clients:
                    seen_clients.add(client_display)
                    clients.append(client_display)
        else:
            # Include all queries (with duplicates)
            query_lines = []
            domains = []
            clients = []
            for q in queries:
                client_display = q.client_hostname or q.client_ip
                query_lines.append(f"{q.domain} - {client_display}")
                if q.domain:
                    domains.append(q.domain)
                clients.append(client_display)

        return AlertContext(
            domain=first_query.domain,
            client_ip=first_query.client_ip,
            client_hostname=first_query.client_hostname,
            rule_name=rule.name,
            server_name=first_query.server,
            timestamp=first_query.timestamp.strftime("%Y-%m-%d %H:%M:%S") if first_query.timestamp else "",
            query_type=first_query.query_type or "",
            status=first_query.status or "",
            count=len(queries),
            query_list="\n".join(query_lines),
            domains=", ".join(domains),
            clients=", ".join(clients),
        )

    async def send_batch_alert(self, queries: List, rule: AlertRule) -> Dict[int, bool]:
        """Send batched alert for multiple queries to all enabled channels.
        Returns dict of {channel_id: success}"""
        from .database import async_session_maker
        from .models import NotificationChannel
        from sqlalchemy import select

        if not queries:
            return {}

        results = {}

        async with async_session_maker() as session:
            stmt = select(NotificationChannel).where(NotificationChannel.enabled == True)
            result = await session.execute(stmt)
            channels = result.scalars().all()

            for channel in channels:
                sender = SENDERS.get(channel.channel_type)
                if not sender:
                    logger.warning(f"Unknown channel type: {channel.channel_type}")
                    results[channel.id] = False
                    continue

                try:
                    # Check if this channel wants deduplication (default: False = show all)
                    dedupe = channel.config.get('dedupe_domains', False) if channel.config else False
                    context = self._build_batch_context(queries, rule, dedupe=dedupe)

                    message = render_template(channel.message_template, context)
                    message = truncate_message(message, channel.channel_type)

                    success, error = await sender.send(message, channel.config)
                    results[channel.id] = success

                    # Update channel status
                    now = datetime.now(timezone.utc)
                    if success:
                        channel.last_success_at = now
                        channel.last_error = None
                        channel.last_error_at = None
                        channel.consecutive_failures = 0
                        logger.info(f"Sent batch notification ({len(queries)} queries) to channel {channel.name}")
                    else:
                        channel.last_error = error
                        channel.last_error_at = now
                        channel.consecutive_failures += 1
                        logger.warning(f"Failed to send to channel {channel.name}: {error}")

                except Exception as e:
                    logger.error(f"Error sending to channel {channel.name}: {e}")
                    channel.last_error = str(e)
                    channel.last_error_at = datetime.now(timezone.utc)
                    channel.consecutive_failures += 1
                    results[channel.id] = False

            await session.commit()

        return results

    async def send_to_channel(self, channel_id: int, context: AlertContext) -> Tuple[bool, Optional[str]]:
        """Send alert to a specific channel. Returns (success, error_message)"""
        from .database import async_session_maker
        from .models import NotificationChannel
        from sqlalchemy import select

        async with async_session_maker() as session:
            stmt = select(NotificationChannel).where(NotificationChannel.id == channel_id)
            result = await session.execute(stmt)
            channel = result.scalar_one_or_none()

            if not channel:
                return False, "Channel not found"

            sender = SENDERS.get(channel.channel_type)
            if not sender:
                return False, f"Unknown channel type: {channel.channel_type}"

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
            else:
                channel.last_error = error
                channel.last_error_at = now
                channel.consecutive_failures += 1

            await session.commit()

            return success, error
