"""LLM prompt templates for the Identity Threat Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class AuthCollectionOutput(BaseModel):
    """Structured output for auth event collection."""

    total_events: int = Field(
        description="Total auth events collected",
    )
    failed_logins: int = Field(
        description="Number of failed login attempts",
    )
    summary: str = Field(
        description="Collection summary",
    )


class BehaviorAnalysisOutput(BaseModel):
    """Structured output for behavior analysis."""

    users_analyzed: int = Field(
        description="Number of users analyzed",
    )
    deviations_found: int = Field(
        description="Number of behavioral deviations",
    )
    reasoning: str = Field(
        description="Behavior analysis reasoning",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomaly_count: int = Field(
        description="Number of anomalies detected",
    )
    highest_confidence: float = Field(
        description="Highest anomaly confidence 0-1",
    )
    reasoning: str = Field(
        description="Anomaly detection reasoning",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for identity risk assessment."""

    max_risk_score: float = Field(
        description="Highest risk score 0-100",
    )
    critical_count: int = Field(
        description="Number of critical-risk identities",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


class ResponseDecisionOutput(BaseModel):
    """Structured output for response decisions."""

    actions: list[dict[str, str]] = Field(
        description="Response actions with type and target",
    )
    accounts_locked: int = Field(
        description="Number of accounts locked",
    )
    reasoning: str = Field(
        description="Response decision reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_COLLECT = """\
You are an expert identity security analyst collecting \
authentication events for threat detection.

Given the detection configuration:
1. Collect authentication events from IAM providers
2. Gather login attempts, MFA challenges, token grants
3. Include geo-location and device fingerprint data
4. Capture privilege changes and role assignments

Focus on: failed logins, MFA bypass attempts, unusual \
geographic locations, new device registrations."""

SYSTEM_BEHAVIOR = """\
You are an expert UEBA analyst profiling user behavior.

Given the collected authentication events:
1. Build behavioral baselines per user identity
2. Identify typical access patterns (time, location, device)
3. Detect deviations from established baselines
4. Correlate behavior across multiple identities

Look for: access time anomalies, location changes, \
new device usage, unusual resource access patterns."""

SYSTEM_DETECT = """\
You are an expert identity threat detection specialist.

Given the behavioral analysis results:
1. Detect impossible travel (logins from distant locations)
2. Identify credential stuffing patterns
3. Find MFA bypass or downgrade attempts
4. Detect privilege escalation and account takeover

Techniques: velocity checks, device fingerprinting, \
session token analysis, lateral movement detection."""

SYSTEM_RISK = """\
You are an expert identity risk assessment specialist.

Given the detected anomalies:
1. Score risk based on threat type and confidence
2. Evaluate business impact of potential compromise
3. Consider user privilege level and data access
4. Assess blast radius of account takeover

Factors: admin vs standard user, data access level, \
service account vs human, external vs internal."""

SYSTEM_RESPOND = """\
You are an expert identity threat response specialist.

Given the risk-assessed anomalies:
1. Determine appropriate response for each threat
2. Apply proportional actions (alert, MFA reset, lock)
3. Consider business impact of false positives
4. Initiate investigation workflows for critical threats

Balance security with user experience — avoid locking \
out legitimate users while containing real threats."""
