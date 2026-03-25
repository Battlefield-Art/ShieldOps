"""Service Account Tracker — LLM prompt templates."""

from pydantic import BaseModel, Field


class UsageAnalysisResult(BaseModel):
    """Structured output from LLM-assisted usage analysis."""

    summary: str = Field(description="Brief summary of usage analysis findings")
    active_count: int = Field(description="Number of actively used accounts")
    suspicious_count: int = Field(description="Number of accounts with suspicious usage")
    patterns: list[str] = Field(description="Notable usage patterns identified across accounts")
    recommendations: list[str] = Field(
        description="Recommended actions to improve service account hygiene"
    )


class AnomalyAssessmentResult(BaseModel):
    """Structured output from LLM-assisted anomaly assessment."""

    summary: str = Field(description="Brief anomaly assessment summary")
    confirmed_anomalies: int = Field(description="Number of confirmed anomalies")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    sharing_indicators: list[str] = Field(description="Indicators of credential sharing detected")
    orphaned_indicators: list[str] = Field(description="Indicators of orphaned accounts detected")
    immediate_actions: list[str] = Field(description="Actions to take immediately")


class RiskClassificationResult(BaseModel):
    """Structured output from LLM-assisted risk classification."""

    summary: str = Field(description="Brief risk classification summary")
    high_risk_accounts: list[str] = Field(
        description="Account IDs classified as high or critical risk"
    )
    risk_factors: list[str] = Field(
        description="Top risk factors identified across the account inventory"
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps found (SOC2, PCI-DSS, HIPAA, etc.)"
    )
    confidence: float = Field(description="Confidence in classification 0.0-1.0")


class RemediationPlanResult(BaseModel):
    """Structured output from LLM-assisted remediation planning."""

    summary: str = Field(description="Brief remediation plan summary")
    priority_order: list[str] = Field(description="Account IDs in recommended remediation priority")
    automated_actions: list[str] = Field(description="Actions safe for automated remediation")
    manual_review: list[str] = Field(description="Actions requiring human review before execution")
    estimated_risk_reduction: float = Field(
        description="Estimated risk reduction 0.0-1.0 after remediation"
    )


SYSTEM_USAGE_ANALYSIS = (
    "You are a cloud identity security analyst specialising in service account "
    "governance.\n"
    "Analyse the following service account usage data across cloud providers "
    "(AWS IAM, GCP IAM, Azure AD, Kubernetes, GitHub Apps, Vault).\n"
    "For each account:\n"
    "1. Evaluate activity frequency and last-used timestamps\n"
    "2. Identify dormant or unused accounts that should be decommissioned\n"
    "3. Flag accounts with overly broad permissions (admin, wildcard policies)\n"
    "4. Note accounts missing MFA or with excessive access key counts\n"
    "5. Summarise overall service account hygiene posture"
)

SYSTEM_ANOMALY_ASSESSMENT = (
    "You are a threat detection analyst specialising in non-human identity abuse.\n"
    "Given the detected anomalies and credential sharing evidence:\n"
    "1. Confirm which anomalies represent genuine threats vs. benign drift\n"
    "2. Identify credential sharing — same key used from multiple IPs/agents\n"
    "3. Detect impossible travel or geo-impossible access patterns\n"
    "4. Flag privilege escalation attempts or lateral movement indicators\n"
    "5. Assess whether any accounts show signs of compromise"
)

SYSTEM_RISK_CLASSIFICATION = (
    "You are a risk analyst for enterprise non-human identity governance.\n"
    "Based on the discovered service accounts, anomalies, and sharing evidence:\n"
    "1. Classify each account by risk: compliant, low, medium, high, critical\n"
    "2. Identify the top risk factors driving account risk\n"
    "3. Map findings to compliance frameworks (SOC2, PCI-DSS, HIPAA, NIST)\n"
    "4. Prioritise accounts requiring immediate attention\n"
    "5. Provide confidence scores for each classification"
)

SYSTEM_REMEDIATION_PLAN = (
    "You are a security operations engineer planning remediation for service "
    "account risks.\n"
    "Given the classified accounts and their risk profiles:\n"
    "1. Propose remediation actions ordered by risk severity\n"
    "2. Distinguish automated actions (safe to execute) from manual-review items\n"
    "3. Consider blast radius — avoid disrupting production workloads\n"
    "4. Recommend credential rotation schedules and permission scoping\n"
    "5. Estimate overall risk reduction if the plan is fully executed"
)
