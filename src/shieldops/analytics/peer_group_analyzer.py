"""Peer Group Analyzer — analyze peer group deviations and behavioral outliers."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PeerGroupAnalyzer = engine(
    "PeerGroupAnalyzer",
    description="Analyze peer group deviations, detect behavioral outliers, and track group...",
    enums={
        "grouping_criteria": EnumDef(
            "GroupingCriteria",
            {
                "ROLE": "role",
                "DEPARTMENT": "department",
                "LOCATION": "location",
                "ACCESS_LEVEL": "access_level",
                "BEHAVIOR_PATTERN": "behavior_pattern",
            },
        ),
        "deviation_type": EnumDef(
            "DeviationType",
            {
                "ACCESS_ANOMALY": "access_anomaly",
                "TIME_ANOMALY": "time_anomaly",
                "VOLUME_ANOMALY": "volume_anomaly",
                "PATTERN_ANOMALY": "pattern_anomaly",
                "RESOURCE_ANOMALY": "resource_anomaly",
            },
        ),
        "deviation_severity": EnumDef(
            "DeviationSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NORMAL": "normal",
            },
        ),
    },
    score_field="deviation_score",
    key_field="group_name",
)

# Backward-compatible re-exports
GroupingCriteria = PeerGroupAnalyzer.GroupingCriteria
DeviationType = PeerGroupAnalyzer.DeviationType
DeviationSeverity = PeerGroupAnalyzer.DeviationSeverity
PeerGroupRecord = PeerGroupAnalyzer.Record
PeerGroupAnalysis = PeerGroupAnalyzer.Analysis
PeerGroupReport = PeerGroupAnalyzer.Report
