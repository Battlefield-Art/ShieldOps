"""Notification configuration."""

from pydantic import BaseModel


class NotificationsConfig(BaseModel):
    """Slack, PagerDuty, webhook, and email notification settings."""

    # Slack
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_approval_channel: str = "#shieldops-approvals"

    # PagerDuty
    pagerduty_routing_key: str = ""
    pagerduty_api_key: str = ""
    pagerduty_service_ids: str = ""

    # Webhooks
    webhook_url: str = ""
    webhook_secret: str = ""
    webhook_timeout: float = 10.0

    # Email / SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_address: str = "shieldops@localhost"
    smtp_to_addresses: list[str] = []

    # Chat session
    chat_session_ttl_seconds: int = 86400
    chat_max_messages_per_session: int = 50
