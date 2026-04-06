"""Adversary Tracking Engine — track adversary groups, map campaigns, predict targets."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdversaryTrackingEngine = engine(
    "AdversaryTrackingEngine",
    description="Track adversary groups, map campaign activity, predict next targets.",
    enums={
        "adversary_group": EnumDef(
            "AdversaryGroup",
            {
                "APT28": "apt28",
                "APT29": "apt29",
                "LAZARUS": "lazarus",
                "FIN7": "fin7",
                "UNKNOWN": "unknown",
            },
        ),
        "ttp_focus": EnumDef(
            "TTPFocus",
            {
                "INITIAL_ACCESS": "initial_access",
                "PERSISTENCE": "persistence",
                "PRIVILEGE_ESCALATION": "privilege_escalation",
                "LATERAL_MOVEMENT": "lateral_movement",
                "EXFILTRATION": "exfiltration",
            },
        ),
        "tracking_status": EnumDef(
            "TrackingStatus",
            {
                "ACTIVE": "active",
                "DORMANT": "dormant",
                "EMERGING": "emerging",
                "RETIRED": "retired",
                "UNKNOWN": "unknown",
            },
        ),
    },
    score_field="threat_score",
    key_field="adversary_name",
)

# Backward-compatible re-exports
AdversaryGroup = AdversaryTrackingEngine.AdversaryGroup
TTPFocus = AdversaryTrackingEngine.TTPFocus
TrackingStatus = AdversaryTrackingEngine.TrackingStatus
AdversaryRecord = AdversaryTrackingEngine.Record
AdversaryAnalysis = AdversaryTrackingEngine.Analysis
AdversaryReport = AdversaryTrackingEngine.Report
