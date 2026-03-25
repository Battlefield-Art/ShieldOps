"""Cloud Posture Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class PostureAnalysisOutput(BaseModel):
    """LLM output for overall posture analysis."""

    summary: str = Field(description="Executive summary of cloud posture")
    risk_level: str = Field(description="Overall risk: critical, high, medium, low")
    key_findings: list[str] = Field(description="Top posture findings across providers")
    score_justification: str = Field(description="Justification for the posture score")


class BenchmarkOutput(BaseModel):
    """LLM output for benchmark assessment analysis."""

    summary: str = Field(description="Summary of benchmark compliance status")
    compliance_rate: float = Field(description="Estimated compliance percentage 0-100")
    worst_controls: list[str] = Field(description="Controls with highest failure rates")
    recommendations: list[str] = Field(description="Prioritized compliance recommendations")


class MisconfigOutput(BaseModel):
    """LLM output for misconfiguration detection analysis."""

    summary: str = Field(description="Summary of misconfigurations detected")
    critical_count: int = Field(description="Number of critical misconfigurations")
    attack_vectors: list[str] = Field(description="Potential attack vectors from misconfigs")
    priority_order: list[str] = Field(description="Recommended fix order by risk")


class RemediationPlanOutput(BaseModel):
    """LLM output for remediation planning."""

    summary: str = Field(description="Remediation plan summary")
    auto_fix_count: int = Field(description="Number of auto-remediable issues")
    manual_items: list[str] = Field(description="Items requiring manual intervention")
    risk_after_remediation: str = Field(description="Expected risk level post-remediation")
    estimated_effort_hours: float = Field(description="Total estimated remediation hours")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_POSTURE_ANALYSIS = (
    "You are a Cloud Security Posture Management (CSPM) analyst.\n"
    "Analyze cloud resource inventories and assess overall security posture.\n"
    "For each provider:\n"
    "1. Evaluate resource configuration hygiene (encryption, access controls, logging)\n"
    "2. Identify high-risk resource patterns (public exposure, missing encryption)\n"
    "3. Score the overall posture on a 0-100 scale with clear justification\n"
    "4. Provide an executive summary suitable for CISO reporting"
)

SYSTEM_BENCHMARK_ASSESSMENT = (
    "You are assessing cloud configurations against CIS Benchmarks and NIST 800-53.\n"
    "For the provided benchmark results:\n"
    "1. Calculate compliance rates per framework and per provider\n"
    "2. Identify the worst-performing controls with highest failure rates\n"
    "3. Map failures to potential compliance gaps (SOC 2, PCI-DSS, HIPAA)\n"
    "4. Recommend prioritized actions to improve compliance posture"
)

SYSTEM_MISCONFIG_DETECTION = (
    "You are a cloud misconfiguration detection specialist.\n"
    "Analyze failing benchmark controls to identify security misconfigurations:\n"
    "1. Classify each misconfiguration by attack vector and blast radius\n"
    "2. Assign risk scores considering severity, exploitability, and data exposure\n"
    "3. Identify misconfigurations that chain together for elevated risk\n"
    "4. Prioritize fixes by risk-to-effort ratio for maximum posture improvement"
)

SYSTEM_REMEDIATION_PLANNING = (
    "You are a cloud security remediation planner.\n"
    "Create a remediation plan for detected misconfigurations:\n"
    "1. Separate auto-remediable items from those requiring manual intervention\n"
    "2. Sequence remediations to avoid breaking dependencies\n"
    "3. Estimate effort and risk reduction for each remediation action\n"
    "4. Provide rollback guidance for automated remediations\n"
    "5. Project the expected posture score after full remediation"
)
