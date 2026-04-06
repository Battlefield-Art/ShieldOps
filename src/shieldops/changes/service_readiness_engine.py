"""ServiceReadinessEngine Service production readiness assessment, checklist scoring, launch g..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ServiceReadinessEngine = engine(
    "ServiceReadinessEngine",
    module="operations",  # uses record_item
    description="Service production readiness assessment and launch gating.",
    enums={
        "readiness_category": EnumDef(
            "ReadinessCategory",
            {
                "OBSERVABILITY": "observability",
                "SECURITY": "security",
                "RELIABILITY": "reliability",
                "DOCUMENTATION": "documentation",
                "TESTING": "testing",
            },
        ),
        "readiness_level": EnumDef(
            "ReadinessLevel",
            {
                "PRODUCTION_READY": "production_ready",
                "NEARLY_READY": "nearly_ready",
                "IN_PROGRESS": "in_progress",
                "NOT_STARTED": "not_started",
                "BLOCKED": "blocked",
            },
        ),
        "gate_decision": EnumDef(
            "GateDecision",
            {
                "APPROVED": "approved",
                "CONDITIONAL": "conditional",
                "DEFERRED": "deferred",
                "REJECTED": "rejected",
                "PENDING": "pending",
            },
        ),
    },
)

# Backward-compatible re-exports
ReadinessCategory = ServiceReadinessEngine.ReadinessCategory
ReadinessLevel = ServiceReadinessEngine.ReadinessLevel
GateDecision = ServiceReadinessEngine.GateDecision
ServiceReadinessRecord = ServiceReadinessEngine.Record
ServiceReadinessAnalysis = ServiceReadinessEngine.Analysis
ServiceReadinessReport = ServiceReadinessEngine.Report
