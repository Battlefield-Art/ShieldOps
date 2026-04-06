"""Notification Channel Effectiveness rank channels by response rate, detect degradation, reco..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

NotificationChannelEffectiveness = engine(
    "NotificationChannelEffectiveness",
    description="Rank channels by response rate, detect degradation, recommend optimization.",
    enums={
        "channel_type": EnumDef(
            "ChannelType",
            {
                "SLACK": "slack",
                "PAGERDUTY": "pagerduty",
                "SMS": "sms",
                "EMAIL": "email",
            },
        ),
        "effectiveness": EnumDef(
            "EffectivenessRating",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "delivery_status": EnumDef(
            "DeliveryStatus",
            {
                "DELIVERED": "delivered",
                "DELAYED": "delayed",
                "FAILED": "failed",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("response_time_ms", float, 0.0),
        FieldDef("acknowledged", bool, False),
        FieldDef("incident_id", str, ""),
    ],
    key_field="recipient_id",
)

# Backward-compatible re-exports
ChannelType = NotificationChannelEffectiveness.ChannelType
EffectivenessRating = NotificationChannelEffectiveness.EffectivenessRating
DeliveryStatus = NotificationChannelEffectiveness.DeliveryStatus
NotificationChannelRecord = NotificationChannelEffectiveness.Record
NotificationChannelAnalysis = NotificationChannelEffectiveness.Analysis
NotificationChannelReport = NotificationChannelEffectiveness.Report
