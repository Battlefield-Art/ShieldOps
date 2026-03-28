"""Tool functions for the Incident Communicator Agent."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.incident_communicator.models import (
    Notification,
)

logger = structlog.get_logger()

# Stakeholder templates keyed by severity
STAKEHOLDER_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "critical": [
        {"name": "Incident Commander", "role": "commander", "priority": "critical"},
        {"name": "CISO", "role": "security_lead", "priority": "critical"},
        {"name": "VP Engineering", "role": "executive", "priority": "critical"},
        {"name": "On-Call SRE", "role": "responder", "priority": "high"},
        {"name": "Customer Success Lead", "role": "customer_comms", "priority": "high"},
        {"name": "Legal Counsel", "role": "legal", "priority": "medium"},
    ],
    "high": [
        {"name": "Incident Commander", "role": "commander", "priority": "high"},
        {"name": "On-Call SRE", "role": "responder", "priority": "high"},
        {"name": "Engineering Manager", "role": "manager", "priority": "medium"},
        {"name": "Customer Success Lead", "role": "customer_comms", "priority": "medium"},
    ],
    "medium": [
        {"name": "On-Call SRE", "role": "responder", "priority": "medium"},
        {"name": "Engineering Manager", "role": "manager", "priority": "low"},
    ],
    "low": [
        {"name": "On-Call SRE", "role": "responder", "priority": "low"},
    ],
    "informational": [
        {"name": "On-Call SRE", "role": "responder", "priority": "informational"},
    ],
}

# Channel selection by priority
PRIORITY_CHANNELS: dict[str, list[str]] = {
    "critical": ["pagerduty", "voice", "sms", "slack"],
    "high": ["pagerduty", "slack", "email"],
    "medium": ["slack", "teams", "email"],
    "low": ["slack", "email"],
    "informational": ["email"],
}

# Message templates by severity
MESSAGE_TEMPLATES: dict[str, str] = {
    "critical": (
        "[CRITICAL] Incident {incident_id}: Immediate action required. "
        "All hands — join the war room now."
    ),
    "high": (
        "[HIGH] Incident {incident_id}: Significant impact detected. "
        "Please review and respond within 15 minutes."
    ),
    "medium": (
        "[MEDIUM] Incident {incident_id}: Moderate issue detected. "
        "Please investigate at your earliest convenience."
    ),
    "low": ("[LOW] Incident {incident_id}: Minor issue logged. No immediate action required."),
    "informational": ("[INFO] Incident {incident_id}: For your awareness only."),
}


class IncidentCommunicatorToolkit:
    """Toolkit for incident communication — stakeholder ID, messaging, delivery."""

    def __init__(
        self,
        notification_service: Any | None = None,
        stakeholder_directory: Any | None = None,
    ) -> None:
        self._notification_service = notification_service
        self._stakeholder_directory = stakeholder_directory
        self._sent_log: dict[str, bool] = {}

    async def identify_stakeholders(
        self,
        incident_id: str,
        severity: str = "medium",
    ) -> list[dict[str, str]]:
        """Identify stakeholders who need notification.

        Args:
            incident_id: The incident identifier.
            severity: Incident severity (critical/high/medium/low/informational).

        Returns:
            List of stakeholder dicts with name, role, priority keys.
        """
        if self._stakeholder_directory is not None:
            try:
                return await self._stakeholder_directory.lookup(
                    incident_id,
                    severity,
                )
            except Exception:
                logger.debug(
                    "stakeholder_directory_failed",
                    incident_id=incident_id,
                )

        severity_key = severity.lower()
        if severity_key not in STAKEHOLDER_TEMPLATES:
            severity_key = "medium"

        stakeholders = STAKEHOLDER_TEMPLATES[severity_key]
        logger.info(
            "communicator.stakeholders_identified",
            incident_id=incident_id,
            severity=severity,
            count=len(stakeholders),
        )
        return stakeholders

    async def draft_message(
        self,
        incident_id: str,
        severity: str,
        recipient: str,
    ) -> str:
        """Draft a notification message for a recipient.

        Args:
            incident_id: The incident identifier.
            severity: Incident severity level.
            recipient: Recipient name or role.

        Returns:
            Formatted message string.
        """
        severity_key = severity.lower()
        if severity_key not in MESSAGE_TEMPLATES:
            severity_key = "medium"

        template = MESSAGE_TEMPLATES[severity_key]
        message = template.format(incident_id=incident_id)
        message = f"To: {recipient} — {message}"

        logger.info(
            "communicator.message_drafted",
            incident_id=incident_id,
            recipient=recipient,
        )
        return message

    async def send_notification(
        self,
        notification: Notification,
    ) -> bool:
        """Send a single notification via the configured channel.

        Args:
            notification: The Notification object to send.

        Returns:
            True if sent successfully.
        """
        if self._notification_service is not None:
            try:
                result = await self._notification_service.send(
                    channel=notification.channel.value,
                    recipient=notification.recipient,
                    message=notification.message,
                    priority=notification.priority.value,
                )
                sent = bool(result)
                self._sent_log[notification.id] = sent
                return sent
            except Exception:
                logger.warning(
                    "notification_send_failed",
                    notification_id=notification.id,
                    channel=notification.channel.value,
                )
                self._sent_log[notification.id] = False
                return False

        # Simulate successful delivery
        self._sent_log[notification.id] = True
        logger.info(
            "communicator.notification_sent",
            notification_id=notification.id,
            recipient=notification.recipient,
            channel=notification.channel.value,
        )
        return True

    async def check_acknowledgment(
        self,
        notification_id: str,
    ) -> bool:
        """Check whether a notification has been acknowledged.

        Args:
            notification_id: The notification identifier.

        Returns:
            True if acknowledged.
        """
        if self._notification_service is not None:
            try:
                return await self._notification_service.check_ack(
                    notification_id,
                )
            except Exception:
                logger.debug(
                    "ack_check_failed",
                    notification_id=notification_id,
                )

        # Heuristic: treat all sent notifications as acknowledged
        acked = self._sent_log.get(notification_id, False)
        logger.info(
            "communicator.ack_checked",
            notification_id=notification_id,
            acknowledged=acked,
        )
        return acked
