"""RecoveryPatternEngine — recovery pattern engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RecoveryPatternEngine = engine(
    "RecoveryPatternEngine",
    description="Recovery Pattern Engine.",
    enums={
        "recovery_type": EnumDef(
            "RecoveryType",
            {
                "AUTOMATED": "automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "ROLLBACK": "rollback",
                "FAILOVER": "failover",
            },
        ),
        "pattern_confidence": EnumDef(
            "PatternConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
                "VALIDATED": "validated",
            },
        ),
        "recovery_speed": EnumDef(
            "RecoverySpeed",
            {
                "INSTANT": "instant",
                "FAST": "fast",
                "MODERATE": "moderate",
                "SLOW": "slow",
                "EXTENDED": "extended",
            },
        ),
    },
)

# Backward-compatible re-exports
RecoveryType = RecoveryPatternEngine.RecoveryType
PatternConfidence = RecoveryPatternEngine.PatternConfidence
RecoverySpeed = RecoveryPatternEngine.RecoverySpeed
RecoveryPatternRecord = RecoveryPatternEngine.Record
RecoveryPatternAnalysis = RecoveryPatternEngine.Analysis
RecoveryPatternReport = RecoveryPatternEngine.Report
