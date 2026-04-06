"""Device Trust Scorer — score device trust based on compliance and security posture."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DeviceTrustScorer = engine(
    "DeviceTrustScorer",
    description="Score device trust based on compliance status, security posture, and device...",
    enums={
        "device_type": EnumDef(
            "DeviceType",
            {
                "MANAGED": "managed",
                "UNMANAGED": "unmanaged",
                "BYOD": "byod",
                "IOT": "iot",
                "VIRTUAL": "virtual",
            },
        ),
        "compliance_status": EnumDef(
            "ComplianceStatus",
            {
                "COMPLIANT": "compliant",
                "NON_COMPLIANT": "non_compliant",
                "PARTIAL": "partial",
                "UNKNOWN": "unknown",
                "EXEMPT": "exempt",
            },
        ),
        "trust_level": EnumDef(
            "TrustLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNTRUSTED": "untrusted",
                "BLOCKED": "blocked",
            },
        ),
    },
    score_field="trust_score",
    key_field="device_name",
)

# Backward-compatible re-exports
DeviceType = DeviceTrustScorer.DeviceType
ComplianceStatus = DeviceTrustScorer.ComplianceStatus
TrustLevel = DeviceTrustScorer.TrustLevel
DeviceTrustRecord = DeviceTrustScorer.Record
DeviceTrustAnalysis = DeviceTrustScorer.Analysis
DeviceTrustReport = DeviceTrustScorer.Report
