"""Endpoint DLP Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class EndpointInsight(BaseModel):
    """Structured output from endpoint monitoring."""

    summary: str = Field(description="Endpoint monitoring overview")
    high_risk_endpoints: list[str] = Field(description="Endpoints with elevated risk")
    coverage_gaps: list[str] = Field(description="Endpoints missing DLP agents")


class MovementInsight(BaseModel):
    """Structured output from data movement detection."""

    summary: str = Field(description="Data movement detection overview")
    suspicious_patterns: list[str] = Field(description="Suspicious data movement patterns")
    ai_exfiltration_risks: list[str] = Field(description="AI-related data exfiltration risks")


class PolicyInsight(BaseModel):
    """Structured output from policy enforcement."""

    summary: str = Field(description="Policy enforcement overview")
    policy_gaps: list[str] = Field(description="Gaps in DLP policy coverage")
    tuning_recommendations: list[str] = Field(description="Policy tuning suggestions")


class ViolationInsight(BaseModel):
    """Structured output from violation investigation."""

    summary: str = Field(description="Violation investigation overview")
    insider_threat_indicators: list[str] = Field(description="Potential insider threat signals")
    remediation_steps: list[str] = Field(description="Recommended remediation actions")


SYSTEM_MONITOR = (
    "You are an endpoint DLP analyst monitoring "
    "data loss prevention across endpoints.\n"
    "1. Identify endpoints with missing DLP agents\n"
    "2. Flag endpoints with high event volumes\n"
    "3. Detect offline endpoints that may be evading\n"
    "4. Assess overall endpoint DLP coverage"
)

SYSTEM_DETECT = (
    "You are a data movement detection specialist.\n"
    "1. Identify suspicious clipboard operations\n"
    "2. Detect AI prompt paste data exfiltration\n"
    "3. Flag unusual USB or upload patterns\n"
    "4. Correlate movements across channels"
)

SYSTEM_ENFORCE = (
    "You are a DLP policy enforcement analyst.\n"
    "1. Evaluate policy action appropriateness\n"
    "2. Identify false positive patterns\n"
    "3. Suggest policy tuning improvements\n"
    "4. Flag override abuse patterns"
)

SYSTEM_INVESTIGATE = (
    "You are a data loss investigation analyst.\n"
    "1. Reconstruct data exfiltration timelines\n"
    "2. Assess insider threat likelihood\n"
    "3. Evaluate evidence strength\n"
    "4. Recommend containment and remediation"
)
