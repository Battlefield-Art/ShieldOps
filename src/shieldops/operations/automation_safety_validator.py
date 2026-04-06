"""Automation Safety Validator — automation safety validation and blast radius control."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomationSafetyValidator = engine(
    "AutomationSafetyValidator",
    description="Automation Safety Validator — automation safety validation and blast radius...",
    enums={
        "safety_check": EnumDef(
            "SafetyCheck",
            {
                "BLAST_RADIUS": "blast_radius",
                "ROLLBACK_PLAN": "rollback_plan",
                "DEPENDENCY_CHECK": "dependency_check",
                "APPROVAL_GATE": "approval_gate",
                "CANARY": "canary",
            },
        ),
        "safety_source": EnumDef(
            "SafetySource",
            {
                "POLICY_ENGINE": "policy_engine",
                "HISTORICAL_DATA": "historical_data",
                "SIMULATION": "simulation",
                "PEER_REVIEW": "peer_review",
                "AUTOMATED": "automated",
            },
        ),
        "safety_verdict": EnumDef(
            "SafetyVerdict",
            {
                "SAFE": "safe",
                "CONDITIONAL": "conditional",
                "RISKY": "risky",
                "BLOCKED": "blocked",
                "OVERRIDE_REQUIRED": "override_required",
            },
        ),
    },
)

# Backward-compatible re-exports
SafetyCheck = AutomationSafetyValidator.SafetyCheck
SafetySource = AutomationSafetyValidator.SafetySource
SafetyVerdict = AutomationSafetyValidator.SafetyVerdict
SafetyRecord = AutomationSafetyValidator.Record
SafetyAnalysis = AutomationSafetyValidator.Analysis
AutomationSafetyReport = AutomationSafetyValidator.Report
