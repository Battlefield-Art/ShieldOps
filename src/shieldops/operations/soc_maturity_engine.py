"""SOC Maturity Engine — assess SOC maturity dimensions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SocMaturityEngine = engine(
    "SocMaturityEngine",
    description="Assess SOC maturity across dimensions.",
    enums={
        "dimension": EnumDef(
            "MaturityDimension",
            {
                "DETECTION": "detection",
                "RESPONSE": "response",
                "AUTOMATION": "automation",
                "THREAT_INTEL": "threat_intel",
                "GOVERNANCE": "governance",
            },
        ),
        "level": EnumDef(
            "MaturityLevel",
            {
                "INITIAL": "initial",
                "MANAGED": "managed",
                "DEFINED": "defined",
                "MEASURED": "measured",
                "OPTIMIZED": "optimized",
            },
        ),
        "phase": EnumDef(
            "TransformationPhase",
            {
                "ASSESSMENT": "assessment",
                "PLANNING": "planning",
                "IMPLEMENTATION": "implementation",
                "VALIDATION": "validation",
                "OPTIMIZATION": "optimization",
            },
        ),
    },
    record_fields=[
        FieldDef("target_score", float, 0.0),
    ],
    key_field="assessor",
)

# Backward-compatible re-exports
MaturityDimension = SocMaturityEngine.MaturityDimension
MaturityLevel = SocMaturityEngine.MaturityLevel
TransformationPhase = SocMaturityEngine.TransformationPhase
MaturityRecord = SocMaturityEngine.Record
MaturityAnalysis = SocMaturityEngine.Analysis
MaturityReport = SocMaturityEngine.Report
