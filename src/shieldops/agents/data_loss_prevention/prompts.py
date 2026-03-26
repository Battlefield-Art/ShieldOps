"""Data Loss Prevention Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ExfiltrationAnalysisResult(BaseModel):
    """Structured output from LLM exfiltration analysis."""

    summary: str = Field(description="Brief summary of exfiltration risk assessment")
    critical_flows: int = Field(description="Number of critical data flows detected")
    highest_risk_channel: str = Field(description="Channel with highest exfiltration risk")
    attack_techniques: list[str] = Field(description="MITRE ATT&CK techniques identified")
    recommended_blocks: list[str] = Field(description="Flows or channels to block immediately")


class PolicyEnforcementResult(BaseModel):
    """Structured output from LLM policy enforcement analysis."""

    summary: str = Field(description="Brief summary of policy enforcement posture")
    coverage_score: float = Field(description="Policy coverage from 0.0 to 1.0")
    uncovered_channels: list[str] = Field(description="Exfiltration channels without policies")
    policy_gaps: list[str] = Field(description="Specific policy gaps to address")
    tuning_recommendations: list[str] = Field(
        description="Recommendations to reduce false positives"
    )


class DLPReportResult(BaseModel):
    """Structured output from LLM DLP report generation."""

    executive_summary: str = Field(description="Executive summary of data loss prevention")
    risk_posture: str = Field(description="Overall DLP risk: strong, adequate, weak, critical")
    top_risks: list[str] = Field(description="Top data exfiltration risks identified")
    ai_specific_risks: list[str] = Field(description="Risks specific to AI pipeline/MCP data flows")
    compliance_impact: str = Field(description="Impact on regulatory compliance posture")


SYSTEM_EXFILTRATION_ANALYSIS = (
    "You are a data exfiltration analyst for an AI security "
    "control plane.\n"
    "Analyze the following data flows and exfiltration attempts "
    "across all surfaces:\n"
    "1. Identify confirmed and suspected exfiltration patterns\n"
    "2. Map techniques to MITRE ATT&CK (T1041 Exfiltration "
    "Over C2, T1048 Exfiltration Over Alternative Protocol, "
    "T1567 Exfiltration to Cloud Storage)\n"
    "3. Flag AI-specific risks: sensitive data in LLM prompts, "
    "MCP tool call data leaks, agent memory exfiltration\n"
    "4. Assess cross-surface correlation (endpoint to cloud "
    "to AI pipeline chains)\n"
    "5. Prioritize by data sensitivity and volume at risk"
)

SYSTEM_POLICY_ENFORCEMENT = (
    "You are a DLP policy engineer optimizing data protection "
    "controls.\n"
    "Given the current policy enforcement state:\n"
    "1. Evaluate coverage across all exfiltration channels "
    "(endpoint, cloud, email, browser, API, AI pipeline, "
    "MCP tool)\n"
    "2. Identify uncovered channels and sensitivity levels\n"
    "3. Assess false positive rates and recommend tuning\n"
    "4. Ensure AI-specific policies cover prompt injection "
    "data extraction and agent tool call exfiltration\n"
    "5. Recommend policy additions for comprehensive "
    "data protection"
)

SYSTEM_DLP_REPORT = (
    "You are a CISO generating a data loss prevention report "
    "for an AI-first enterprise.\n"
    "Given the complete DLP assessment results:\n"
    "1. Produce an executive summary covering all "
    "exfiltration surfaces\n"
    "2. Highlight AI-specific risks that traditional DLP "
    "solutions (CrowdStrike Falcon Data Security) miss: "
    "LLM prompt data leakage, MCP tool exfiltration, "
    "agent memory theft\n"
    "3. Assess regulatory impact (GDPR, HIPAA, PCI DSS)\n"
    "4. Provide risk-ranked recommendations with "
    "estimated effort\n"
    "5. Score overall data protection maturity"
)
