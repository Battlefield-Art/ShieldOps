"""Adversary Infrastructure Tracker — track and monitor adversary infrastructure."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdversaryInfrastructureTracker = engine(
    "AdversaryInfrastructureTracker",
    description="Track and monitor adversary infrastructure across the threat landscape.",
    enums={
        "infra_type": EnumDef(
            "InfraType",
            {
                "C2_SERVER": "c2_server",
                "PHISHING_DOMAIN": "phishing_domain",
                "MALWARE_HOST": "malware_host",
                "PROXY_NODE": "proxy_node",
                "EXFIL_POINT": "exfil_point",
            },
        ),
        "infra_status": EnumDef(
            "InfraStatus",
            {
                "ACTIVE": "active",
                "INACTIVE": "inactive",
                "SEIZED": "seized",
                "SINKHOLED": "sinkholed",
                "UNKNOWN": "unknown",
            },
        ),
        "tracking_priority": EnumDef(
            "TrackingPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MONITORING": "monitoring",
            },
        ),
    },
    score_field="threat_score",
    key_field="infra_name",
)

# Backward-compatible re-exports
InfraType = AdversaryInfrastructureTracker.InfraType
InfraStatus = AdversaryInfrastructureTracker.InfraStatus
TrackingPriority = AdversaryInfrastructureTracker.TrackingPriority
InfraRecord = AdversaryInfrastructureTracker.Record
InfraAnalysis = AdversaryInfrastructureTracker.Analysis
InfraTrackingReport = AdversaryInfrastructureTracker.Report
