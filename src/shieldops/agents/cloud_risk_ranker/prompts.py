"""Cloud Risk Ranker Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# -------------------------------------------------------------------
# Structured output schemas
# -------------------------------------------------------------------


class TacticCorrelationOutput(BaseModel):
    """LLM output for attacker tactic correlation."""

    summary: str = Field(description="Summary of correlated attacker tactics")
    top_techniques: list[str] = Field(description="Most relevant ATT&CK techniques")
    active_campaigns: list[str] = Field(
        description="Known threat campaigns targeting these findings"
    )
    confidence: float = Field(description="Overall correlation confidence 0-1")


class ExploitabilityOutput(BaseModel):
    """LLM output for exploitability ranking."""

    summary: str = Field(description="Exploitability assessment summary")
    actively_exploited_count: int = Field(description="Findings actively exploited in the wild")
    high_risk_cves: list[str] = Field(description="CVEs with highest exploitability")
    recommendations: list[str] = Field(description="Urgent recommendations based on EPSS/KEV")


class AttackPathOutput(BaseModel):
    """LLM output for attack path generation."""

    summary: str = Field(description="Attack path analysis summary")
    critical_paths: int = Field(description="Number of critical attack paths")
    highest_impact: str = Field(description="Highest impact scenario description")
    lateral_movement_risk: str = Field(description="Assessment of lateral movement risk")


class RemediationRankOutput(BaseModel):
    """LLM output for remediation prioritization."""

    summary: str = Field(description="Remediation prioritization summary")
    top_actions: list[str] = Field(description="Top remediation actions in priority order")
    estimated_risk_reduction: float = Field(description="Expected risk reduction percentage 0-100")
    quick_wins: list[str] = Field(description="Low-effort high-impact fixes")


class RiskRankerReportOutput(BaseModel):
    """LLM output for final risk ranking report."""

    summary: str = Field(description="Executive risk ranking summary")
    risk_level: str = Field(description="Overall risk: critical, high, medium, low")
    key_findings: list[str] = Field(description="Top risk findings for executive review")
    comparison_note: str = Field(description=("How this compares to industry baselines"))


# -------------------------------------------------------------------
# System prompts
# -------------------------------------------------------------------

SYSTEM_TACTIC_CORRELATION = (
    "You are a cyber threat intelligence analyst.\n"
    "Correlate cloud security findings with MITRE ATT&CK "
    "tactics and techniques:\n"
    "1. Map each finding to relevant ATT&CK techniques "
    "(initial access, persistence, privilege escalation, "
    "lateral movement, exfiltration)\n"
    "2. Identify known threat campaigns exploiting these "
    "weaknesses (APT groups, ransomware operators)\n"
    "3. Assess confidence of each correlation based on "
    "finding specificity and threat intel recency\n"
    "4. Highlight findings that chain together for "
    "multi-stage attacks"
)

SYSTEM_EXPLOITABILITY_ASSESSMENT = (
    "You are an exploit intelligence specialist.\n"
    "Assess the exploitability of cloud security findings "
    "using EPSS and CISA KEV data:\n"
    "1. Classify findings: actively exploited, exploit "
    "available, proof-of-concept, or theoretical\n"
    "2. Score each by EPSS probability and weapon readiness\n"
    "3. Flag findings on the CISA Known Exploited "
    "Vulnerabilities catalog\n"
    "4. Prioritize findings where exploit maturity is high "
    "and exposure is internet-facing"
)

SYSTEM_ATTACK_PATH_GENERATION = (
    "You are an attack path modeling expert.\n"
    "Generate realistic attack paths from cloud findings:\n"
    "1. Chain findings to build multi-step attack "
    "scenarios (entry -> escalation -> impact)\n"
    "2. Assess blast radius for each path (single "
    "resource, account, cross-account, cross-cloud)\n"
    "3. Estimate likelihood based on exploitability "
    "and exposure\n"
    "4. Map paths to business-critical assets and "
    "data classifications"
)

SYSTEM_REMEDIATION_PRIORITIZATION = (
    "You are a cloud security remediation strategist.\n"
    "Prioritize remediation actions by business impact:\n"
    "1. Rank remediations by risk-reduction-to-effort "
    "ratio\n"
    "2. Identify quick wins (low effort, high risk "
    "reduction)\n"
    "3. Group related remediations to minimize change "
    "windows\n"
    "4. Estimate mean-time-to-remediate and project "
    "residual risk after fixes"
)

SYSTEM_RISK_REPORT = (
    "You are a cloud security risk analyst producing "
    "an executive report.\n"
    "Summarize the risk ranking results:\n"
    "1. Provide an executive summary with overall risk "
    "level and trend\n"
    "2. Highlight the top 5 risks with business context\n"
    "3. Compare against industry baselines (CIS, NIST)\n"
    "4. Recommend strategic security investments based "
    "on the attack path and exploitability analysis"
)
