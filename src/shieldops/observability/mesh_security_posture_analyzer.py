"""Mesh Security Posture Analyzer. Assess mTLS coverage, detect authorization gaps, and monito..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MeshSecurityPostureAnalyzer = engine(
    "MeshSecurityPostureAnalyzer",
    description="Assess mTLS coverage, detect authorization gaps, monitor certificate health.",
    enums={
        "mtls_status": EnumDef(
            "MtlsStatus",
            {
                "ENFORCED": "enforced",
                "PERMISSIVE": "permissive",
                "DISABLED": "disabled",
                "MIXED": "mixed",
            },
        ),
        "authz_gap_severity": EnumDef(
            "AuthzGapSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "cert_health": EnumDef(
            "CertHealth",
            {
                "VALID": "valid",
                "EXPIRING_SOON": "expiring_soon",
                "EXPIRED": "expired",
                "INVALID": "invalid",
            },
        ),
    },
    record_fields=[
        FieldDef("policy_count", int, 0),
        FieldDef("days_to_expiry", int, 365),
        FieldDef("open_ports", int, 0),
    ],
    key_field="mesh_name",
)

# Backward-compatible re-exports
MtlsStatus = MeshSecurityPostureAnalyzer.MtlsStatus
AuthzGapSeverity = MeshSecurityPostureAnalyzer.AuthzGapSeverity
CertHealth = MeshSecurityPostureAnalyzer.CertHealth
SecurityPostureRecord = MeshSecurityPostureAnalyzer.Record
SecurityPostureAnalysis = MeshSecurityPostureAnalyzer.Analysis
SecurityPostureReport = MeshSecurityPostureAnalyzer.Report
