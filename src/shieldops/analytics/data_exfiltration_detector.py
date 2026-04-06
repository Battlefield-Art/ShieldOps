"""Data Exfiltration Detector — detect data exfiltration attempts and channels."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DataExfiltrationDetector = engine(
    "DataExfiltrationDetector",
    description="Detect data exfiltration attempts across multiple channels and indicators.",
    enums={
        "exfil_channel": EnumDef(
            "ExfilChannel",
            {
                "EMAIL": "email",
                "CLOUD_STORAGE": "cloud_storage",
                "USB": "usb",
                "DNS_TUNNEL": "dns_tunnel",
                "ENCRYPTED_CHANNEL": "encrypted_channel",
            },
        ),
        "exfil_indicator": EnumDef(
            "ExfilIndicator",
            {
                "VOLUME_SPIKE": "volume_spike",
                "UNUSUAL_DESTINATION": "unusual_destination",
                "OFF_HOURS_TRANSFER": "off_hours_transfer",
                "SENSITIVE_DATA": "sensitive_data",
                "REPEATED_PATTERN": "repeated_pattern",
            },
        ),
        "detection_confidence": EnumDef(
            "DetectionConfidence",
            {
                "CONFIRMED": "confirmed",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SUSPECTED": "suspected",
            },
        ),
    },
    score_field="exfil_score",
    key_field="entity_name",
)

# Backward-compatible re-exports
ExfilChannel = DataExfiltrationDetector.ExfilChannel
ExfilIndicator = DataExfiltrationDetector.ExfilIndicator
DetectionConfidence = DataExfiltrationDetector.DetectionConfidence
ExfilRecord = DataExfiltrationDetector.Record
ExfilAnalysis = DataExfiltrationDetector.Analysis
DataExfiltrationReport = DataExfiltrationDetector.Report
