"""NISTAIRMFEngine — NIST AI Risk Management Framework compliance tracking."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

NISTAIRMFEngine = engine(
    "NISTAIRMFEngine",
    description="NIST AI Risk Management Framework compliance tracking.",
    enums={
        "function": EnumDef(
            "RMFFunction",
            {
                "GOVERN": "govern",
                "MAP": "map",
                "MEASURE": "measure",
                "MANAGE": "manage",
            },
        ),
        "category": EnumDef(
            "RMFCategory",
            {
                "GOVERNANCE": "governance",
                "RISK_MAPPING": "risk_mapping",
                "MEASUREMENT": "measurement",
                "RISK_MANAGEMENT": "risk_management",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "INITIAL": "initial",
                "DEVELOPING": "developing",
                "DEFINED": "defined",
                "MANAGED": "managed",
                "OPTIMIZING": "optimizing",
            },
        ),
    },
    record_fields=[
        FieldDef("control_ref", str, ""),
        FieldDef("evidence_ref", str, ""),
        FieldDef("assessor", str, ""),
    ],
    key_field="system_id",
)

# Backward-compatible re-exports
RMFFunction = NISTAIRMFEngine.RMFFunction
RMFCategory = NISTAIRMFEngine.RMFCategory
MaturityLevel = NISTAIRMFEngine.MaturityLevel
RMFRecord = NISTAIRMFEngine.Record
RMFAnalysis = NISTAIRMFEngine.Analysis
RMFReport = NISTAIRMFEngine.Report
