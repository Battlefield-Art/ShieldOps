"""API Abuse Detector Engine — detect and track API abuse patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

APIAbuseDetectorEngine = engine(
    "APIAbuseDetectorEngine",
    description="Detect and track API abuse patterns.",
    enums={
        "abuse_pattern": EnumDef(
            "AbusePattern",
            {
                "CREDENTIAL_STUFFING": "credential_stuffing",
                "SCRAPING": "scraping",
                "ENUMERATION": "enumeration",
                "RATE_ABUSE": "rate_abuse",
                "DATA_HARVESTING": "data_harvesting",
            },
        ),
        "endpoint_category": EnumDef(
            "EndpointCategory",
            {
                "AUTH": "auth",
                "DATA": "data",
                "ADMIN": "admin",
                "PUBLIC": "public",
                "INTERNAL": "internal",
            },
        ),
        "mitigation_action": EnumDef(
            "MitigationAction",
            {
                "RATE_LIMIT": "rate_limit",
                "BLOCK_IP": "block_ip",
                "CHALLENGE": "challenge",
                "ALERT": "alert",
                "QUARANTINE": "quarantine",
            },
        ),
    },
    record_fields=[
        FieldDef("source_ip", str, ""),
        FieldDef("request_count", int, 0),
        FieldDef("time_window_min", int, 0),
        FieldDef("blocked", bool, False),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
AbusePattern = APIAbuseDetectorEngine.AbusePattern
EndpointCategory = APIAbuseDetectorEngine.EndpointCategory
MitigationAction = APIAbuseDetectorEngine.MitigationAction
APIAbuseRecord = APIAbuseDetectorEngine.Record
APIAbuseAnalysis = APIAbuseDetectorEngine.Analysis
APIAbuseReport = APIAbuseDetectorEngine.Report
