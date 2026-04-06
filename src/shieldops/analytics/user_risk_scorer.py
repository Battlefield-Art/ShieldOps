"""User Risk Scorer — score and track user risk based on multiple factors."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

UserRiskScorer = engine(
    "UserRiskScorer",
    description="Score and track user risk based on multiple factors and scoring models.",
    enums={
        "risk_factor": EnumDef(
            "RiskFactor",
            {
                "ACCESS_PATTERN": "access_pattern",
                "DATA_HANDLING": "data_handling",
                "AUTHENTICATION_ANOMALY": "authentication_anomaly",
                "POLICY_VIOLATION": "policy_violation",
                "BEHAVIORAL_CHANGE": "behavioral_change",
            },
        ),
        "risk_level": EnumDef(
            "RiskLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "scoring_model": EnumDef(
            "ScoringModel",
            {
                "RULE_BASED": "rule_based",
                "ML_BASED": "ml_based",
                "HYBRID": "hybrid",
                "PEER_COMPARISON": "peer_comparison",
                "CONTEXTUAL": "contextual",
            },
        ),
    },
    score_field="risk_score",
    key_field="user_name",
)

# Backward-compatible re-exports
RiskFactor = UserRiskScorer.RiskFactor
RiskLevel = UserRiskScorer.RiskLevel
ScoringModel = UserRiskScorer.ScoringModel
UserRiskRecord = UserRiskScorer.Record
UserRiskAnalysis = UserRiskScorer.Analysis
UserRiskReport = UserRiskScorer.Report
