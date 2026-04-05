"""Application Behavior Risk Engine v2 — analyze advanced application behavior risk, detect at..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApplicationBehaviorRiskEngineV2 = engine(
    "ApplicationBehaviorRiskEngineV2",
    description="Analyze advanced application behavior risk, detect attack patterns, and ran...",
    enums={
        "behavior_type": EnumDef(
            "BehaviorType",
            {
                "INJECTION_ATTEMPT": "injection_attempt",
                "AUTH_BYPASS": "auth_bypass",
                "API_ABUSE": "api_abuse",
                "RESOURCE_ABUSE": "resource_abuse",
            },
        ),
        "detection_layer": EnumDef(
            "DetectionLayer",
            {
                "WAF": "waf",
                "RUNTIME": "runtime",
                "CODE": "code",
                "NETWORK": "network",
            },
        ),
        "risk_score_level": EnumDef(
            "RiskScore",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("request_count", int, 0),
        FieldDef("error_rate", float, 0.0),
        FieldDef("endpoint", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="application_id",
)

# Backward-compatible re-exports
BehaviorType = ApplicationBehaviorRiskEngineV2.BehaviorType
DetectionLayer = ApplicationBehaviorRiskEngineV2.DetectionLayer
RiskScore = ApplicationBehaviorRiskEngineV2.RiskScore
AppBehaviorRecord = ApplicationBehaviorRiskEngineV2.Record
AppBehaviorAnalysis = ApplicationBehaviorRiskEngineV2.Analysis
AppBehaviorReport = ApplicationBehaviorRiskEngineV2.Report
