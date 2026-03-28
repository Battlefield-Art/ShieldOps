"""Privilege Escalation Detector Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class EscalationClassificationOutput(BaseModel):
    """Structured output from LLM-assisted escalation classification."""

    summary: str = Field(description="Brief summary of classified escalation events")
    confirmed_escalations: int = Field(description="Number of confirmed privilege escalations")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    escalation_patterns: list[str] = Field(description="Patterns with MITRE technique IDs")
    false_positive_indicators: list[str] = Field(
        description="Indicators suggesting false positives"
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output from LLM-assisted risk assessment."""

    summary: str = Field(description="Brief summary of risk assessment findings")
    total_resources_at_risk: int = Field(description="Total resources potentially affected")
    critical_assets: list[str] = Field(description="Critical assets in the blast radius")
    privilege_exposure: str = Field(description="Exposure level: none, low, medium, high, critical")
    containment_priority: list[str] = Field(description="Prioritized containment actions")


class ResponsePlanOutput(BaseModel):
    """Structured output from LLM-assisted response planning."""

    summary: str = Field(description="Brief summary of recommended response actions")
    immediate_actions: list[str] = Field(description="Actions to execute immediately")
    investigation_steps: list[str] = Field(description="Follow-up investigation steps")
    auto_execute_safe: bool = Field(description="Whether automated response is safe")
    confidence: float = Field(description="Confidence in response plan 0.0-1.0")


class DetectionSummaryOutput(BaseModel):
    """Structured output from LLM-assisted detection summary."""

    executive_summary: str = Field(description="Executive summary of escalation findings")
    threat_level: str = Field(description="Overall threat level: none-critical")
    key_findings: list[str] = Field(description="Key findings from the detection run")
    recommendations: list[str] = Field(description="Recommendations to prevent escalation")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques observed")


SYSTEM_ESCALATION_CLASSIFICATION = (
    "You are a security analyst specializing in privilege escalation"
    " detection.\n"
    "Analyze the following events and classify escalation attempts.\n"
    "For each event:\n"
    "1. Determine if it represents genuine privilege escalation or"
    " benign admin activity\n"
    "2. Map to MITRE ATT&CK techniques (T1548, T1078, T1098,"
    " T1134)\n"
    "3. Identify patterns: sudo abuse, unexpected role changes,"
    " IAM policy mods,\n"
    "   service account elevation, privilege boundary bypass\n"
    "4. Assess temporal patterns — rapid successive escalations"
    " are suspicious\n"
    "5. Estimate false positive probability for each finding"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a security risk analyst assessing privilege escalation"
    " impact.\n"
    "Given the detected escalation findings:\n"
    "1. Identify all resources reachable via escalated privileges\n"
    "2. Assess data exposure risk (PII, secrets, financial,"
    " infrastructure)\n"
    "3. Determine if escalation enables further lateral movement\n"
    "4. Prioritize containment actions by impact and urgency\n"
    "5. Consider cross-system blast radius amplification"
)

SYSTEM_RESPONSE_PLANNING = (
    "You are an incident response planner for privilege escalation"
    " attacks.\n"
    "Given the escalation findings and risk assessments:\n"
    "1. Recommend immediate containment (revoke, downgrade,"
    " disable)\n"
    "2. Assess whether automated response is safe for"
    " production\n"
    "3. Plan investigation steps for full scope determination\n"
    "4. Consider impact on legitimate workloads\n"
    "5. Ensure response covers all affected systems and"
    " identities"
)

SYSTEM_DETECTION_SUMMARY = (
    "You are a threat intelligence analyst writing an executive"
    " summary.\n"
    "Summarize privilege escalation findings for security"
    " leadership:\n"
    "1. Describe overall threat level and key escalation"
    " patterns\n"
    "2. Highlight most critical findings and their impact\n"
    "3. Map all findings to MITRE ATT&CK framework\n"
    "4. Provide strategic recommendations to harden privilege"
    " controls\n"
    "5. Identify gaps in monitoring coverage"
)
