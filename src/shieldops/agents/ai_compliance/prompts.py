"""AI Compliance Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RiskClassificationResult(BaseModel):
    """Structured output from LLM-assisted risk classification."""

    summary: str = Field(description="Brief summary of risk classification rationale")
    classifications: list[dict[str, str]] = Field(
        description="List of {system_id, risk_level, rationale} classifications"
    )
    high_risk_indicators: list[str] = Field(
        description="Indicators that triggered high-risk classification"
    )
    unacceptable_flags: list[str] = Field(
        description="Any uses flagged as unacceptable under EU AI Act Article 5"
    )


class ComplianceReportResult(BaseModel):
    """Structured output from LLM-assisted compliance report generation."""

    executive_summary: str = Field(description="Executive summary of compliance posture")
    critical_gaps: list[str] = Field(
        description="Critical compliance gaps requiring immediate attention"
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations for compliance improvement"
    )
    timeline_estimate: str = Field(description="Estimated timeline to achieve full compliance")


SYSTEM_CLASSIFY = (
    "You are an AI governance specialist classifying AI systems under the EU AI Act, "
    "NIST AI RMF, and ISO 42001.\n"
    "For each AI system:\n"
    "1. Evaluate against EU AI Act Article 6 Annex III high-risk categories: "
    "biometric identification, critical infrastructure, education/vocational access, "
    "employment/worker management, essential services access, law enforcement, "
    "migration/border control, justice/democratic processes\n"
    "2. Check for unacceptable risk per Article 5: social scoring, exploitation of "
    "vulnerabilities, real-time remote biometric identification in public spaces\n"
    "3. Assess limited risk (transparency obligations) vs minimal risk\n"
    "4. Map to NIST AI RMF risk categories: GOVERN, MAP, MEASURE, MANAGE\n"
    "5. Classify per ISO 42001 AI management system scope"
)

SYSTEM_REPORT = (
    "You are an AI compliance auditor generating a comprehensive compliance report.\n"
    "Based on the assessment results:\n"
    "1. Summarize overall compliance posture per framework (EU AI Act, NIST AI RMF, "
    "ISO 42001)\n"
    "2. Identify critical gaps where controls are missing for high-risk systems\n"
    "3. Provide prioritized remediation recommendations with effort estimates\n"
    "4. Highlight any systems classified as unacceptable risk that must be "
    "decommissioned or redesigned\n"
    "5. Estimate timeline and resources needed to achieve full compliance"
)

SYSTEM_ASSESS = (
    "You are an AI compliance analyst evaluating controls against regulatory requirements.\n"
    "For each requirement-system pair:\n"
    "1. Evaluate whether existing controls satisfy the requirement fully, partially, "
    "or not at all\n"
    "2. Identify specific evidence needed to demonstrate compliance\n"
    "3. Provide concrete remediation steps for any gaps found\n"
    "4. Score the control implementation from 0-100"
)
