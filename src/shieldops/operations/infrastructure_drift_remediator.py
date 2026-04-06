"""Infrastructure Drift Remediator classify drift severity, compute remediation priority, rank..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureDriftRemediator = engine(
    "InfrastructureDriftRemediator",
    module="operations",  # uses record_item
    description="Classify drift severity, compute remediation priority, rank resources by dr...",
    enums={
        "drift_type": EnumDef(
            "DriftType",
            {
                "CONFIGURATION": "configuration",
                "STATE": "state",
                "VERSION": "version",
                "PERMISSION": "permission",
            },
        ),
        "remediation_action": EnumDef(
            "RemediationAction",
            {
                "RECONCILE": "reconcile",
                "OVERRIDE": "override",
                "IGNORE": "ignore",
                "ESCALATE": "escalate",
            },
        ),
        "drift_origin": EnumDef(
            "DriftOrigin",
            {
                "MANUAL_CHANGE": "manual_change",
                "FAILED_APPLY": "failed_apply",
                "EXTERNAL_UPDATE": "external_update",
                "PROVIDER_UPDATE": "provider_update",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_name", str, ""),
        FieldDef("drift_detected_at", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="severity_score",
    key_field="resource_id",
)

# Backward-compatible re-exports
DriftType = InfrastructureDriftRemediator.DriftType
RemediationAction = InfrastructureDriftRemediator.RemediationAction
DriftOrigin = InfrastructureDriftRemediator.DriftOrigin
DriftRemediationRecord = InfrastructureDriftRemediator.Record
DriftRemediationAnalysis = InfrastructureDriftRemediator.Analysis
DriftRemediationReport = InfrastructureDriftRemediator.Report
