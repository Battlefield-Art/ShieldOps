"""Approval workflow notification dispatcher for Slack, Teams, PagerDuty."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.integrations.notifications.templates import (
    approval_request_slack,
    approval_request_teams,
)

logger = structlog.get_logger()


# --- Enums ---


class NotificationChannel(StrEnum):
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationStatus(StrEnum):
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXPIRED = "expired"


class NotificationPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class NotificationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    approval_id: str = ""
    channel: NotificationChannel = NotificationChannel.SLACK
    recipient: str = ""
    message: str = ""
    status: NotificationStatus = NotificationStatus.SENT
    priority: NotificationPriority = NotificationPriority.MEDIUM
    sent_at: float = Field(default_factory=time.time)
    delivered_at: float | None = None
    error: str = ""


class NotificationTemplate(BaseModel):
    channel: NotificationChannel = NotificationChannel.SLACK
    title_template: str = ""
    body_template: str = ""
    action_buttons: list[str] = Field(default_factory=lambda: ["Approve", "Reject"])


class NotificationReport(BaseModel):
    total_sent: int = 0
    by_channel: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    avg_delivery_time_ms: float = 0.0
    failed_count: int = 0
    generated_at: float = Field(default_factory=time.time)


# --- Severity → Priority mapping ---

_SEVERITY_PRIORITY: dict[str, NotificationPriority] = {
    "critical": NotificationPriority.CRITICAL,
    "high": NotificationPriority.HIGH,
    "medium": NotificationPriority.MEDIUM,
    "low": NotificationPriority.LOW,
    "info": NotificationPriority.LOW,
}

_PAGERDUTY_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


# --- Engine ---


class ApprovalNotifier:
    """Dispatches approval requests to Slack, Teams, PagerDuty, email, and webhooks."""

    def __init__(self, max_records: int = 200000, action_base_url: str = "") -> None:
        self._max_records = max_records
        self._action_base_url = action_base_url or "https://app.shieldops.io/approvals"
        self._records: list[NotificationRecord] = []
        self._records_by_id: dict[str, NotificationRecord] = {}
        logger.info(
            "approval_notifier.initialized",
            max_records=max_records,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_if_needed(self) -> None:
        """Ring-buffer eviction when capacity is exceeded."""
        while len(self._records) > self._max_records:
            evicted = self._records.pop(0)
            self._records_by_id.pop(evicted.id, None)

    def _store(self, record: NotificationRecord) -> NotificationRecord:
        self._records.append(record)
        self._records_by_id[record.id] = record
        self._evict_if_needed()
        return record

    def _action_url(self, approval_id: str) -> str:
        return f"{self._action_base_url}/{approval_id}"

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    def send_approval_request(
        self,
        approval_id: str,
        action_description: str,
        severity: str = "medium",
        confidence: float = 0.5,
        channels: list[NotificationChannel] | None = None,
        recipients: list[str] | None = None,
    ) -> list[NotificationRecord]:
        """Send approval request notifications across specified channels.

        Returns a list of NotificationRecord, one per channel/recipient pair.
        """
        channels = channels or [NotificationChannel.SLACK]
        recipients = recipients or ["#shieldops-approvals"]
        priority = _SEVERITY_PRIORITY.get(severity.lower(), NotificationPriority.MEDIUM)
        title = f"Action Approval Required [{severity.upper()}]"
        results: list[NotificationRecord] = []

        for channel in channels:
            for recipient in recipients:
                record = NotificationRecord(
                    approval_id=approval_id,
                    channel=channel,
                    recipient=recipient,
                    message=action_description,
                    priority=priority,
                    status=NotificationStatus.SENT,
                )
                try:
                    if channel == NotificationChannel.SLACK:
                        record = self.send_to_slack(
                            webhook_url=recipient,
                            message=action_description,
                            action_buttons=["Approve", "Reject"],
                            approval_id=approval_id,
                            title=title,
                            severity=severity,
                            confidence=confidence,
                        )
                    elif channel == NotificationChannel.TEAMS:
                        record = self.send_to_teams(
                            webhook_url=recipient,
                            message=action_description,
                            action_buttons=["Approve", "Reject"],
                            approval_id=approval_id,
                            title=title,
                            severity=severity,
                            confidence=confidence,
                        )
                    elif channel == NotificationChannel.PAGERDUTY:
                        record = self.send_to_pagerduty(
                            routing_key=recipient,
                            message=action_description,
                            severity=severity,
                            approval_id=approval_id,
                        )
                    else:
                        # email / webhook — record as sent for dispatch by external handler
                        record.status = NotificationStatus.SENT
                        self._store(record)

                    record.approval_id = approval_id
                    record.recipient = recipient
                    record.priority = priority
                except Exception as exc:
                    record.status = NotificationStatus.FAILED
                    record.error = str(exc)
                    self._store(record)
                    logger.error(
                        "approval_notifier.send_failed",
                        channel=channel,
                        recipient=recipient,
                        error=str(exc),
                    )

                results.append(record)

        logger.info(
            "approval_notifier.request_sent",
            approval_id=approval_id,
            channels=[c.value for c in channels],
            total_notifications=len(results),
        )
        return results

    def send_to_slack(
        self,
        webhook_url: str,
        message: str,
        action_buttons: list[str] | None = None,
        *,
        approval_id: str = "",
        title: str = "Approval Required",
        severity: str = "medium",
        confidence: float = 0.5,
    ) -> NotificationRecord:
        """Format and dispatch a Slack Block Kit approval notification.

        In production the payload is POSTed to the webhook_url via httpx.
        Here we build the payload and record it for audit.
        """
        action_buttons = action_buttons or ["Approve", "Reject"]
        action_url = self._action_url(approval_id) if approval_id else webhook_url
        payload = approval_request_slack(
            title=title,
            description=message,
            severity=severity,
            confidence=confidence,
            action_url=action_url,
        )
        record = NotificationRecord(
            approval_id=approval_id,
            channel=NotificationChannel.SLACK,
            recipient=webhook_url,
            message=message,
            status=NotificationStatus.SENT,
        )
        # In production: await httpx.AsyncClient().post(webhook_url, json=payload)
        logger.info(
            "approval_notifier.slack_sent",
            webhook_url=webhook_url[:40],
            approval_id=approval_id,
            payload_blocks=len(payload.get("blocks", [])),
        )
        return self._store(record)

    def send_to_teams(
        self,
        webhook_url: str,
        message: str,
        action_buttons: list[str] | None = None,
        *,
        approval_id: str = "",
        title: str = "Approval Required",
        severity: str = "medium",
        confidence: float = 0.5,
    ) -> NotificationRecord:
        """Format and dispatch a Teams Adaptive Card approval notification."""
        action_buttons = action_buttons or ["Approve", "Reject"]
        action_url = self._action_url(approval_id) if approval_id else webhook_url
        payload = approval_request_teams(
            title=title,
            description=message,
            severity=severity,
            confidence=confidence,
            action_url=action_url,
        )
        record = NotificationRecord(
            approval_id=approval_id,
            channel=NotificationChannel.TEAMS,
            recipient=webhook_url,
            message=message,
            status=NotificationStatus.SENT,
        )
        logger.info(
            "approval_notifier.teams_sent",
            webhook_url=webhook_url[:40],
            approval_id=approval_id,
            attachments=len(payload.get("attachments", [])),
        )
        return self._store(record)

    def send_to_pagerduty(
        self,
        routing_key: str,
        message: str,
        severity: str = "medium",
        *,
        approval_id: str = "",
    ) -> NotificationRecord:
        """Format and dispatch a PagerDuty Events API v2 notification."""
        pd_severity = _PAGERDUTY_SEVERITY.get(severity.lower(), "info")
        payload: dict[str, Any] = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"ShieldOps Approval Required: {message[:500]}",
                "severity": pd_severity,
                "source": "shieldops-approval-workflow",
                "component": "approval-notifier",
                "group": "sre-approvals",
                "class": "approval_request",
                "custom_details": {
                    "approval_id": approval_id,
                    "action_description": message,
                    "action_url": self._action_url(approval_id),
                },
            },
            "links": [
                {
                    "href": self._action_url(approval_id),
                    "text": "Review Approval Request",
                }
            ],
        }
        record = NotificationRecord(
            approval_id=approval_id,
            channel=NotificationChannel.PAGERDUTY,
            recipient=routing_key[:8] + "***",
            message=message,
            status=NotificationStatus.SENT,
        )
        # In production: await httpx.AsyncClient().post(
        #     "https://events.pagerduty.com/v2/enqueue", json=payload
        # )
        logger.info(
            "approval_notifier.pagerduty_sent",
            approval_id=approval_id,
            pd_severity=pd_severity,
            payload_keys=list(payload.keys()),
        )
        return self._store(record)

    # ------------------------------------------------------------------
    # Delivery tracking
    # ------------------------------------------------------------------

    def record_delivery(
        self,
        notification_id: str,
        status: NotificationStatus,
    ) -> NotificationRecord | None:
        """Update delivery status for a previously sent notification."""
        record = self._records_by_id.get(notification_id)
        if record is None:
            logger.warning(
                "approval_notifier.record_not_found",
                notification_id=notification_id,
            )
            return None
        record.status = status
        if status == NotificationStatus.DELIVERED:
            record.delivered_at = time.time()
        logger.info(
            "approval_notifier.delivery_recorded",
            notification_id=notification_id,
            status=status.value if hasattr(status, "value") else str(status),
        )
        return record

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_notification_report(self) -> NotificationReport:
        """Generate a summary report of all notification activity."""
        by_channel: dict[str, int] = {}
        by_status: dict[str, int] = {}
        delivery_times: list[float] = []

        for rec in self._records:
            by_channel[rec.channel.value] = by_channel.get(rec.channel.value, 0) + 1
            by_status[rec.status.value] = by_status.get(rec.status.value, 0) + 1
            if rec.delivered_at is not None and rec.sent_at:
                delivery_times.append((rec.delivered_at - rec.sent_at) * 1000.0)

        avg_delivery = sum(delivery_times) / len(delivery_times) if delivery_times else 0.0
        failed_count = by_status.get(NotificationStatus.FAILED.value, 0)

        return NotificationReport(
            total_sent=len(self._records),
            by_channel=by_channel,
            by_status=by_status,
            avg_delivery_time_ms=round(avg_delivery, 2),
            failed_count=failed_count,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return quick summary statistics."""
        report = self.generate_notification_report()
        return {
            "total_records": len(self._records),
            "total_sent": report.total_sent,
            "failed_count": report.failed_count,
            "by_channel": report.by_channel,
            "by_status": report.by_status,
            "avg_delivery_time_ms": report.avg_delivery_time_ms,
        }

    def clear_data(self) -> dict[str, str]:
        """Clear all stored notification records."""
        count = len(self._records)
        self._records.clear()
        self._records_by_id.clear()
        logger.info("approval_notifier.cleared", records_removed=count)
        return {"status": "cleared", "records_removed": str(count)}
