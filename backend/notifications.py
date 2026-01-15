import logging
from typing import Optional, List
from datetime import datetime
from telegram import Bot
from telegram.error import TelegramError
from .models import Query, AlertRule
from .config import get_settings_sync

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Service for sending Telegram notifications"""

    def __init__(self):
        self.settings = get_settings_sync()
        self.bot: Optional[Bot] = None

        if self.settings.telegram_bot_token:
            try:
                self.bot = Bot(token=self.settings.telegram_bot_token)
            except Exception as e:
                logger.error(f"Failed to initialize Telegram bot: {e}")

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters for Telegram"""
        # Only need to escape: < > &
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text

    async def send_alert(self, query: Query, rule: AlertRule) -> bool:
        """Send alert notification for a matched query"""
        if not self.bot:
            logger.warning("Telegram bot not configured, skipping notification")
            return False

        if not rule.notify_telegram:
            return True  # Rule doesn't want Telegram notifications

        # Determine chat ID
        chat_id = rule.telegram_chat_id or self.settings.telegram_chat_id
        if not chat_id:
            logger.error("No Telegram chat ID configured")
            return False

        try:
            # Convert chat_id to integer (Telegram API requires int)
            try:
                chat_id_int = int(chat_id)
            except (ValueError, TypeError):
                logger.error(f"Invalid chat_id format: {chat_id}")
                return False

            # Format message
            message = self._format_alert_message(query, rule)

            # Send message
            await self.bot.send_message(
                chat_id=chat_id_int,
                text=message,
                parse_mode='HTML'
            )

            logger.info(f"Sent Telegram alert for rule '{rule.name}'")
            return True

        except TelegramError as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Telegram message: {e}")
            return False

    def _format_alert_message(self, query: Query, rule: AlertRule) -> str:
        """Format alert message for Telegram"""
        timestamp = query.timestamp.strftime("%b %d, %Y %H:%M:%S")

        # Build client info
        client_info = query.client_ip
        if query.client_hostname:
            client_info = f"{query.client_ip} ({query.client_hostname})"

        # Escape HTML characters
        domain = self._escape_html(query.domain)
        client_info = self._escape_html(client_info)
        rule_name = self._escape_html(rule.name)

        message = f"🚨 <b>Alert: {rule_name}</b>\n\n"
        message += f"<b>Time:</b> {timestamp}\n"
        message += f"<b>Domain:</b> <code>{domain}</code>\n"
        message += f"<b>Client:</b> <code>{client_info}</code>\n"
        message += f"<b>Server:</b> {query.pihole_server}\n"

        if rule.description:
            desc = self._escape_html(rule.description)
            message += f"\n<i>{desc}</i>"

        # Telegram has 4096 character limit
        if len(message) > 4096:
            message = message[:4090] + "\n...[truncated]"

        return message

    async def send_batch_alert(self, queries: List, rule: AlertRule) -> bool:
        """Send a batched alert for multiple matches"""
        if not self.bot or not queries:
            return False

        if not rule.notify_telegram:
            return True

        chat_id = rule.telegram_chat_id or self.settings.telegram_chat_id
        if not chat_id:
            return False

        try:
            # Convert chat_id to integer (Telegram API requires int)
            try:
                chat_id_int = int(chat_id)
            except (ValueError, TypeError):
                logger.error(f"Invalid chat_id format: {chat_id}")
                return False

            # Format batch message
            message = self._format_batch_message(queries, rule)

            await self.bot.send_message(
                chat_id=chat_id_int,
                text=message,
                parse_mode='HTML'
            )

            logger.info(f"Sent batch Telegram alert for rule '{rule.name}' ({len(queries)} matches)")
            return True

        except TelegramError as e:
            logger.error(f"Failed to send batch Telegram message: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending batch message: {e}")
            return False

    def _format_batch_message(self, queries: List, rule: AlertRule) -> str:
        """Format batch alert message matching pihole.png format"""
        from datetime import datetime, timezone

        # Get first query's timestamp and server for header
        first_query = queries[0]
        timestamp = first_query.timestamp.strftime("%b %d, %Y %H:%M:%S")
        server = first_query.pihole_server

        # Header with timestamp
        message = f"{timestamp} ({server})\n\n"

        # List all domain-client pairs (like the screenshot)
        for query in queries:
            domain = self._escape_html(query.domain)
            client_info = query.client_ip
            if query.client_hostname:
                client_info = f"{query.client_ip} ({query.client_hostname})"
            client_info = self._escape_html(client_info)

            message += f"{domain} - {client_info}\n"

        # Telegram has 4096 character limit
        if len(message) > 4096:
            truncate_at = 4050
            message = message[:truncate_at]
            # Count how many we're truncating
            remaining = len(queries) - message.count('\n') + 2
            message += f"\n...and {remaining} more"

        return message

    async def test_connection(self) -> bool:
        """Test Telegram bot connection"""
        if not self.bot:
            return False

        try:
            me = await self.bot.get_me()
            logger.info(f"Connected to Telegram bot: @{me.username}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Telegram: {e}")
            return False

    async def shutdown(self):
        """Clean up Telegram bot resources"""
        if self.bot:
            try:
                await self.bot.shutdown()
                logger.info("Telegram bot shutdown complete")
            except Exception as e:
                logger.error(f"Error shutting down Telegram bot: {e}")
