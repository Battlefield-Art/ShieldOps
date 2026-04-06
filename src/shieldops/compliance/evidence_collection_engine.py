"""Evidence Collection Engine — manage audit evidence lifecycle, track freshness and completen..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EvidenceCollectionEngine = engine(
    "EvidenceCollectionEngine",
    description="Manage audit evidence lifecycle, track freshness and completeness, ensure a...",
    enums={
        "evidence_method": EnumDef(
            "EvidenceMethod",
            {
                "AUTOMATED": "automated",
                "SEMI_AUTOMATED": "semi_automated",
                "MANUAL": "manual",
                "API_PULL": "api_pull",
                "LOG_EXPORT": "log_export",
            },
        ),
        "evidence_freshness": EnumDef(
            "EvidenceFreshness",
            {
                "CURRENT": "current",
                "STALE": "stale",
                "EXPIRED": "expired",
                "MISSING": "missing",
                "PENDING": "pending",
            },
        ),
        "audit_readiness": EnumDef(
            "AuditReadiness",
            {
                "READY": "ready",
                "NEEDS_REVIEW": "needs_review",
                "INCOMPLETE": "incomplete",
                "OVERDUE": "overdue",
                "EXEMPT": "exempt",
            },
        ),
    },
    record_fields=[
        FieldDef("control_id", str, ""),
        FieldDef("framework", str, ""),
        FieldDef("days_since_collected", float, 0.0),
        FieldDef("file_size_kb", float, 0.0),
        FieldDef("collector_name", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="evidence_id",
)

# Backward-compatible re-exports
EvidenceMethod = EvidenceCollectionEngine.EvidenceMethod
EvidenceFreshness = EvidenceCollectionEngine.EvidenceFreshness
AuditReadiness = EvidenceCollectionEngine.AuditReadiness
EvidenceCollectionRecord = EvidenceCollectionEngine.Record
EvidenceCollectionAnalysis = EvidenceCollectionEngine.Analysis
EvidenceCollectionReport = EvidenceCollectionEngine.Report
