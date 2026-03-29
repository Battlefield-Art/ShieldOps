"""Email DLP Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PIIDetectionOutput(BaseModel):
    """LLM output for PII detection analysis."""

    summary: str = Field(description="Brief PII detection summary")
    data_types_found: list[str] = Field(description="Types of sensitive data detected")
    risk_level: str = Field(description="Risk: critical, high, medium, low")
    recommended_actions: list[str] = Field(description="Recommended DLP actions")
    compliance_impact: list[str] = Field(description="Compliance frameworks affected")


class PolicyEnforcementOutput(BaseModel):
    """LLM output for policy enforcement decisions."""

    summary: str = Field(description="Brief enforcement summary")
    action: str = Field(description="Action: allow, block, encrypt, warn")
    justification: str = Field(description="Why this action was chosen")
    exceptions: list[str] = Field(description="Any applicable policy exceptions")


SYSTEM_PII_DETECTION = (
    "You are a data protection analyst scanning "
    "outbound email content for sensitive data.\n"
    "Given the following email scan results:\n"
    "1. Identify PII: SSNs (XXX-XX-XXXX), credit "
    "cards (16-digit), phone numbers, email addresses\n"
    "2. Detect API keys, tokens, and credentials "
    "in email body and attachments\n"
    "3. Identify medical records (PHI) and "
    "financial data (account numbers)\n"
    "4. Assess risk based on recipient (internal "
    "vs external) and data sensitivity\n"
    "5. Map violations to compliance frameworks "
    "(HIPAA, PCI-DSS, GDPR, SOC 2)"
)

SYSTEM_POLICY_ENFORCEMENT = (
    "You are a DLP policy engine deciding the "
    "appropriate action for detected violations.\n"
    "Given the following violation data:\n"
    "1. Evaluate severity — PHI/PCI data to external "
    "= block; internal PII = warn\n"
    "2. Check for policy exceptions — executive "
    "communications, legal holds\n"
    "3. Determine if encryption can mitigate the risk\n"
    "4. Consider business impact of blocking\n"
    "5. Recommend action: allow, block, encrypt, "
    "quarantine, warn, or redact"
)
