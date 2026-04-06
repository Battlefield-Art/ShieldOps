"""Audit Scope Coverage Engine compute scope coverage ratio, detect untested controls, rank au..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AuditScopeCoverageEngine = engine(
    "AuditScopeCoverageEngine",
    description="Compute scope coverage ratio, detect untested controls, rank audit cycles b...",
    enums={
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "COMPLETE": "complete",
                "SUBSTANTIAL": "substantial",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
            },
        ),
        "audit_type": EnumDef(
            "AuditType",
            {
                "INTERNAL": "internal",
                "EXTERNAL": "external",
                "REGULATORY": "regulatory",
                "CERTIFICATION": "certification",
            },
        ),
        "scope_area": EnumDef(
            "ScopeArea",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "DATA": "data",
                "PROCESS": "process",
            },
        ),
    },
    record_fields=[
        FieldDef("coverage_ratio", float, 0.0),
        FieldDef("total_controls", int, 0),
        FieldDef("tested_controls", int, 0),
        FieldDef("control_id", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="audit_id",
)

# Backward-compatible re-exports
CoverageLevel = AuditScopeCoverageEngine.CoverageLevel
AuditType = AuditScopeCoverageEngine.AuditType
ScopeArea = AuditScopeCoverageEngine.ScopeArea
AuditScopeRecord = AuditScopeCoverageEngine.Record
AuditScopeAnalysis = AuditScopeCoverageEngine.Analysis
AuditScopeReport = AuditScopeCoverageEngine.Report
