"""Insider Risk Scorer Agent — LLM prompt templates
and structured output schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class BehaviorAnalysisOutput(BaseModel):
    """Structured output for behavioral analysis."""

    summary: str = Field(
        description="Brief summary of behavioral patterns",
    )
    anomalous_users: list[str] = Field(
        description="User IDs exhibiting anomalous behavior",
    )
    patterns: list[str] = Field(
        description="Identified behavioral patterns",
    )
    peer_deviations: int = Field(
        description="Number of peer group deviations found",
    )
    confidence: float = Field(
        description="Overall analysis confidence 0-1",
    )


class RiskScoringOutput(BaseModel):
    """Structured output for risk scoring."""

    summary: str = Field(
        description="Brief summary of risk scoring results",
    )
    critical_users: list[str] = Field(
        description="User IDs with critical risk scores",
    )
    risk_distribution: dict[str, int] = Field(
        description="Count of users per risk tier",
    )
    top_risk_factors: list[str] = Field(
        description="Most common contributing risk factors",
    )
    confidence: float = Field(
        description="Scoring confidence 0-1",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    summary: str = Field(
        description="Summary of detected anomalies",
    )
    anomaly_count: int = Field(
        description="Total anomalies detected",
    )
    categories: list[str] = Field(
        description="Anomaly categories observed",
    )
    severity_breakdown: dict[str, int] = Field(
        description="Anomaly count by severity level",
    )
    recommendations: list[str] = Field(
        description="Recommended follow-up actions",
    )


class InsiderRiskReportOutput(BaseModel):
    """Structured output for final risk report."""

    executive_summary: str = Field(
        description="Executive summary of insider risk posture",
    )
    threat_level: str = Field(
        description="Overall: none, low, medium, high, critical",
    )
    key_findings: list[str] = Field(
        description="Key findings from risk scoring",
    )
    recommendations: list[str] = Field(
        description="Strategic recommendations",
    )
    risk_trend: str = Field(
        description="Risk trend: improving, stable, degrading",
    )


# --- System prompts ---

SYSTEM_BEHAVIOR_ANALYSIS = """\
You are an insider risk analyst specializing in user \
behavioral analytics (UEBA).

Given behavioral signals from multiple identity sources:
1. Identify anomalous access patterns deviating from \
peer group norms
2. Detect data movement patterns indicating exfiltration \
risk
3. Correlate temporal anomalies with HR and access events
4. Assess privilege usage relative to role requirements
5. Flag communication pattern changes suggesting intent"""

SYSTEM_RISK_SCORING = """\
You are an insider risk scoring expert computing \
composite risk scores.

Given behavioral profiles and detected anomalies:
1. Weight risk factors by category: access (0.25), \
data movement (0.30), peer deviation (0.20), \
privilege (0.15), temporal (0.10)
2. Classify users into risk tiers: critical, high, \
medium, low, minimal
3. Identify the top contributing factors per user
4. Recommend proportionate response actions per tier
5. Assess confidence based on signal coverage"""

SYSTEM_ANOMALY_DETECTION = """\
You are a behavioral anomaly detection specialist \
for insider threat programs.

Given user behavior profiles and peer baselines:
1. Detect statistical outliers across all behavior \
categories
2. Distinguish genuine anomalies from seasonal or \
role-based variations
3. Score severity based on deviation magnitude and \
historical patterns
4. Correlate anomalies across categories for compound \
risk indicators
5. Recommend investigation priorities"""

SYSTEM_REPORT = """\
You are an insider risk analyst producing executive \
risk posture reports.

Given scoring results, anomalies, and alerts:
1. Produce an executive summary of organizational \
insider risk posture
2. Highlight the highest-risk users and departments
3. Identify risk trends compared to prior periods
4. Provide strategic recommendations for risk reduction
5. Note coverage gaps and monitoring blind spots"""
