"""Continuous Evidence Freshness Engine compute evidence freshness scores, detect stale eviden..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ContinuousEvidenceFreshnessEngine = engine(
    "ContinuousEvidenceFreshnessEngine",
    description="Compute evidence freshness scores, detect stale evidence, rank controls by...",
    enums={
        "freshness_status": EnumDef(
            "FreshnessStatus",
            {
                "CURRENT": "current",
                "AGING": "aging",
                "STALE": "stale",
                "EXPIRED": "expired",
            },
        ),
        "evidence_type": EnumDef(
            "EvidenceType",
            {
                "AUTOMATED": "automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "EXTERNAL": "external",
            },
        ),
        "control_category": EnumDef(
            "ControlCategory",
            {
                "ACCESS": "access",
                "ENCRYPTION": "encryption",
                "MONITORING": "monitoring",
                "GOVERNANCE": "governance",
            },
        ),
    },
    record_fields=[
        FieldDef("age_days", float, 0.0),
        FieldDef("control_id", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="freshness_score",
    key_field="evidence_id",
)

# Backward-compatible re-exports
FreshnessStatus = ContinuousEvidenceFreshnessEngine.FreshnessStatus
EvidenceType = ContinuousEvidenceFreshnessEngine.EvidenceType
ControlCategory = ContinuousEvidenceFreshnessEngine.ControlCategory
EvidenceFreshnessRecord = ContinuousEvidenceFreshnessEngine.Record
EvidenceFreshnessAnalysis = ContinuousEvidenceFreshnessEngine.Analysis
EvidenceFreshnessReport = ContinuousEvidenceFreshnessEngine.Report
