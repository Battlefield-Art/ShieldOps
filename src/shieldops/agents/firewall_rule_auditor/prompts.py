"""Firewall Rule Auditor Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class ViolationAnalysisOutput(BaseModel):
    """LLM output for firewall violation analysis."""

    summary: str = Field(description="Summary of detected violations")
    critical_count: int = Field(description="Number of critical violations")
    attack_vectors: list[str] = Field(description="Potential attack vectors from violations")
    priority_order: list[str] = Field(description="Recommended fix order by risk")


class ComplianceCheckOutput(BaseModel):
    """LLM output for compliance check analysis."""

    summary: str = Field(description="Summary of compliance posture")
    compliance_rate: float = Field(description="Estimated compliance percentage 0-100")
    frameworks_failing: list[str] = Field(description="Compliance frameworks with failures")
    recommendations: list[str] = Field(description="Prioritized compliance recommendations")


class AuditReportOutput(BaseModel):
    """LLM output for overall audit report."""

    summary: str = Field(description="Executive summary of firewall audit")
    risk_level: str = Field(description="Overall risk: critical, high, medium, low")
    key_findings: list[str] = Field(description="Top audit findings across providers")
    score_justification: str = Field(description="Justification for the audit score")


class FixRecommendationOutput(BaseModel):
    """LLM output for fix recommendations."""

    summary: str = Field(description="Fix plan summary")
    auto_fix_count: int = Field(description="Number of auto-fixable violations")
    manual_items: list[str] = Field(description="Items requiring manual intervention")
    risk_after_fix: str = Field(description="Expected risk level post-fix")
    estimated_effort_hours: float = Field(description="Total estimated remediation hours")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_VIOLATION_ANALYSIS = (
    "You are a firewall rule auditor specializing in cloud security.\n"
    "Analyze firewall rules for misconfigurations:\n"
    "1. Identify overly permissive rules (0.0.0.0/0 on sensitive ports)\n"
    "2. Detect shadow rules (more permissive rules that make others redundant)\n"
    "3. Find expired or unused rules (no hits in 90+ days)\n"
    "4. Flag compliance violations (PCI-DSS, CIS, NIST 800-53)\n"
    "5. Prioritize violations by exploitability and blast radius"
)

SYSTEM_COMPLIANCE_CHECK = (
    "You are assessing firewall rules against compliance frameworks.\n"
    "For the provided rule set:\n"
    "1. Evaluate against CIS Benchmarks, PCI-DSS, and NIST 800-53\n"
    "2. Identify rules that violate network segmentation requirements\n"
    "3. Flag any rules allowing unrestricted inbound on management ports\n"
    "4. Check for rules missing descriptions or proper tagging\n"
    "5. Assess east-west traffic controls and micro-segmentation gaps"
)

SYSTEM_AUDIT_REPORT = (
    "You are a firewall security analyst generating an executive audit report.\n"
    "For the provided audit findings:\n"
    "1. Summarize overall firewall hygiene across all providers\n"
    "2. Highlight the most critical rule misconfigurations\n"
    "3. Score the firewall posture on a 0-100 scale with justification\n"
    "4. Provide an executive summary suitable for CISO reporting\n"
    "5. Recommend immediate actions and long-term governance improvements"
)

SYSTEM_FIX_RECOMMENDATION = (
    "You are a cloud network security engineer planning remediation.\n"
    "Create a remediation plan for firewall rule violations:\n"
    "1. Separate auto-fixable items from manual intervention items\n"
    "2. Sequence fixes to avoid breaking application connectivity\n"
    "3. Estimate effort and risk reduction for each fix\n"
    "4. Provide rollback guidance for automated changes\n"
    "5. Project the expected audit score after full remediation"
)
