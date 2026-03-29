"""Cloud Audit Logger Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class AnomalyAnalysisOutput(BaseModel):
    """LLM output for audit anomaly analysis."""

    summary: str = Field(description="Summary of anomalous activities")
    threat_level: str = Field(description="Overall threat: critical/high/medium/low")
    key_findings: list[str] = Field(description="Top anomalous findings")
    attack_patterns: list[str] = Field(description="Identified attack patterns")


class CorrelationOutput(BaseModel):
    """LLM output for activity correlation."""

    summary: str = Field(description="Summary of correlated activity chains")
    chain_count: int = Field(description="Number of attack chains found")
    recommendations: list[str] = Field(description="Response recommendations")


class RiskAssessmentOutput(BaseModel):
    """LLM output for risk assessment."""

    summary: str = Field(description="Risk assessment summary")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low")
    priority_actions: list[str] = Field(description="Priority response actions")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques")


SYSTEM_ANOMALY_DETECTION = (
    "You are a cloud audit log security analyst.\n"
    "Analyze cloud audit events to detect suspicious activity:\n"
    "1. Identify privilege escalation attempts via IAM changes\n"
    "2. Detect resource deletion patterns (mass delete, unusual hours)\n"
    "3. Flag suspicious API calls (credential exposure, data exfil)\n"
    "4. Map activities to MITRE ATT&CK techniques"
)

SYSTEM_CORRELATION = (
    "You are a security event correlation specialist.\n"
    "Correlate suspicious audit events into attack chains:\n"
    "1. Link events by principal, time window, and resource scope\n"
    "2. Identify multi-stage attack patterns\n"
    "3. Assess blast radius of correlated activity\n"
    "4. Determine confidence level of correlation"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a cloud security risk assessor.\n"
    "Assess risk from audit log findings:\n"
    "1. Score overall risk considering severity and blast radius\n"
    "2. Identify highest-priority response actions\n"
    "3. Map findings to compliance frameworks\n"
    "4. Recommend containment and remediation steps"
)
