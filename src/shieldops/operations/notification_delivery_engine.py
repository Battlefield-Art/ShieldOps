"""Notification Delivery Engine — track notification delivery and acks."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

NotificationDeliveryEngine = engine(
    "NotificationDeliveryEngine",
    module="operations",  # uses record_item
    description="Track notification delivery and acks.",
    enums={
        "channel": EnumDef(
            "DeliveryChannel",
            {
                "SLACK": "slack",
                "EMAIL": "email",
                "PAGERDUTY": "pagerduty",
                "SMS": "sms",
                "TEAMS": "teams",
            },
        ),
        "status": EnumDef(
            "DeliveryStatus",
            {
                "PENDING": "pending",
                "SENT": "sent",
                "DELIVERED": "delivered",
                "FAILED": "failed",
                "BOUNCED": "bounced",
            },
        ),
        "ack_type": EnumDef(
            "AcknowledgmentType",
            {
                "MANUAL": "manual",
                "AUTO": "auto",
                "ESCALATED": "escalated",
                "TIMED_OUT": "timed_out",
                "SUPPRESSED": "suppressed",
            },
        ),
    },
    record_fields=[
        FieldDef("recipient", str, ""),
        FieldDef("ack_time_sec", float, 0.0),
        FieldDef("retry_count", int, 0),
    ],
    key_field="notification_id",
)

# Backward-compatible re-exports
DeliveryChannel = NotificationDeliveryEngine.DeliveryChannel
DeliveryStatus = NotificationDeliveryEngine.DeliveryStatus
AcknowledgmentType = NotificationDeliveryEngine.AcknowledgmentType
DeliveryRecord = NotificationDeliveryEngine.Record
DeliveryAnalysis = NotificationDeliveryEngine.Analysis
DeliveryReport = NotificationDeliveryEngine.Report
