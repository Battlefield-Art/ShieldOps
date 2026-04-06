"""Session Anomaly Detector — detect anomalous session behaviors and patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SessionAnomalyDetector = engine(
    "SessionAnomalyDetector",
    description="Detect anomalous session behaviors, impossible travel, and suspicious patte...",
    enums={
        "session_type": EnumDef(
            "SessionType",
            {
                "INTERACTIVE": "interactive",
                "API": "api",
                "SERVICE": "service",
                "VPN": "vpn",
                "REMOTE_DESKTOP": "remote_desktop",
            },
        ),
        "anomaly_type": EnumDef(
            "AnomalyType",
            {
                "IMPOSSIBLE_TRAVEL": "impossible_travel",
                "UNUSUAL_TIME": "unusual_time",
                "EXCESSIVE_DURATION": "excessive_duration",
                "SUSPICIOUS_ACTIVITY": "suspicious_activity",
                "CONCURRENT_SESSION": "concurrent_session",
            },
        ),
        "detection_method": EnumDef(
            "DetectionMethod",
            {
                "STATISTICAL": "statistical",
                "ML_BASED": "ml_based",
                "RULE_BASED": "rule_based",
                "BEHAVIORAL": "behavioral",
                "HYBRID": "hybrid",
            },
        ),
    },
    score_field="anomaly_score",
    key_field="session_name",
)

# Backward-compatible re-exports
SessionType = SessionAnomalyDetector.SessionType
AnomalyType = SessionAnomalyDetector.AnomalyType
DetectionMethod = SessionAnomalyDetector.DetectionMethod
SessionRecord = SessionAnomalyDetector.Record
SessionAnalysis = SessionAnomalyDetector.Analysis
SessionAnomalyReport = SessionAnomalyDetector.Report
