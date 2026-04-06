"""Notification Fatigue Detector detect fatigue patterns, calculate fatigue risk scores, recom..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

NotificationFatigueDetector = engine(
    "NotificationFatigueDetector",
    description="Detect fatigue patterns, calculate fatigue risk scores, recommend load redi...",
    enums={
        "fatigue_level": EnumDef(
            "FatigueLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "notification_type": EnumDef(
            "NotificationType",
            {
                "PAGE": "page",
                "ALERT": "alert",
                "WARNING": "warning",
                "INFO": "info",
            },
        ),
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "VOLUME_BASED": "volume_based",
                "LATENCY_BASED": "latency_based",
                "ENGAGEMENT_BASED": "engagement_based",
                "COMPOSITE": "composite",
            },
        ),
    },
    record_fields=[
        FieldDef("volume", int, 0),
        FieldDef("response_time_ms", float, 0.0),
        FieldDef("acknowledged", bool, False),
        FieldDef("source", str, ""),
    ],
    key_field="recipient_id",
)

# Backward-compatible re-exports
FatigueLevel = NotificationFatigueDetector.FatigueLevel
NotificationType = NotificationFatigueDetector.NotificationType
DetectionMethod = NotificationFatigueDetector.DetectionMethod
NotificationFatigueRecord = NotificationFatigueDetector.Record
NotificationFatigueAnalysis = NotificationFatigueDetector.Analysis
NotificationFatigueReport = NotificationFatigueDetector.Report
