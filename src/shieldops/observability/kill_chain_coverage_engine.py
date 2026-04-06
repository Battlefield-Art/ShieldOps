"""KillChainCoverageEngine — Track detection coverage across kill chain phases."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

KillChainCoverageEngine = engine(
    "KillChainCoverageEngine",
    description="Track detection coverage across kill chain phases.",
    enums={
        "kill_chain_phase": EnumDef(
            "KillChainPhase",
            {
                "RECONNAISSANCE": "reconnaissance",
                "INITIAL_ACCESS": "initial_access",
                "EXECUTION": "execution",
                "PERSISTENCE": "persistence",
                "LATERAL_MOVEMENT": "lateral_movement",
                "EXFILTRATION": "exfiltration",
                "IMPACT": "impact",
            },
        ),
        "detection_coverage": EnumDef(
            "DetectionCoverage",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "NONE": "none",
                "ALERT_ONLY": "alert_only",
                "LOG_ONLY": "log_only",
            },
        ),
        "coverage_gap": EnumDef(
            "CoverageGap",
            {
                "NO_DETECTION": "no_detection",
                "NO_PREVENTION": "no_prevention",
                "NO_RESPONSE": "no_response",
                "DELAYED_DETECTION": "delayed_detection",
                "BLIND_SPOT": "blind_spot",
            },
        ),
    },
    record_fields=[
        FieldDef("detection_count", int, 0),
        FieldDef("technique_id", str, ""),
    ],
)

# Backward-compatible re-exports
KillChainPhase = KillChainCoverageEngine.KillChainPhase
DetectionCoverage = KillChainCoverageEngine.DetectionCoverage
CoverageGap = KillChainCoverageEngine.CoverageGap
KillChainCoverageRecord = KillChainCoverageEngine.Record
KillChainCoverageAnalysis = KillChainCoverageEngine.Analysis
KillChainCoverageReport = KillChainCoverageEngine.Report
