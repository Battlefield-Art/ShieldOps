"""AdaptiveAccessController — adaptive access controller."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdaptiveAccessController = engine(
    "AdaptiveAccessController",
    module="operations",  # uses record_item
    description="Adaptive Access Controller.",
    enums={
        "access_decision": EnumDef(
            "AccessDecision",
            {
                "ALLOW": "allow",
                "DENY": "deny",
                "CHALLENGE": "challenge",
                "STEP_UP": "step_up",
                "MONITOR": "monitor",
            },
        ),
        "risk_factor": EnumDef(
            "RiskFactor",
            {
                "LOCATION": "location",
                "DEVICE": "device",
                "BEHAVIOR": "behavior",
                "TIME": "time",
                "RESOURCE": "resource",
            },
        ),
        "authentication_level": EnumDef(
            "AuthenticationLevel",
            {
                "PASSWORDLESS": "passwordless",
                "MFA": "mfa",
                "BIOMETRIC": "biometric",
                "CERTIFICATE": "certificate",
                "CONDITIONAL": "conditional",
            },
        ),
    },
)

# Backward-compatible re-exports
AccessDecision = AdaptiveAccessController.AccessDecision
RiskFactor = AdaptiveAccessController.RiskFactor
AuthenticationLevel = AdaptiveAccessController.AuthenticationLevel
AdaptiveAccessControllerRecord = AdaptiveAccessController.Record
AdaptiveAccessControllerAnalysis = AdaptiveAccessController.Analysis
AdaptiveAccessControllerReport = AdaptiveAccessController.Report
