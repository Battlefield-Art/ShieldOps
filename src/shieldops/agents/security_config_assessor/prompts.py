"""Security Config Assessor Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class InventoryAnalysisOutput(BaseModel):
    """LLM output for system inventory analysis."""

    summary: str = Field(
        description="Summary of discovered systems",
    )
    risk_level: str = Field(
        description="Overall risk: critical, high, medium, low",
    )
    platform_breakdown: list[str] = Field(
        description="Breakdown of systems by platform",
    )
    recommendations: list[str] = Field(
        description="Inventory coverage recommendations",
    )


class BenchmarkAnalysisOutput(BaseModel):
    """LLM output for benchmark compliance analysis."""

    summary: str = Field(
        description="Summary of CIS benchmark compliance",
    )
    compliance_rate: float = Field(
        description="Estimated compliance percentage 0-100",
    )
    worst_controls: list[str] = Field(
        description="Controls with highest failure rates",
    )
    priority_fixes: list[str] = Field(
        description="Prioritized remediation recommendations",
    )


class DriftAnalysisOutput(BaseModel):
    """LLM output for configuration drift analysis."""

    summary: str = Field(
        description="Summary of configuration drift detected",
    )
    critical_drifts: int = Field(
        description="Number of critical drift items",
    )
    root_causes: list[str] = Field(
        description="Likely root causes for detected drift",
    )
    prevention_tips: list[str] = Field(
        description="Tips to prevent future drift",
    )


class RemediationPlanOutput(BaseModel):
    """LLM output for remediation script generation."""

    summary: str = Field(
        description="Remediation plan summary",
    )
    auto_fix_count: int = Field(
        description="Number of auto-fixable controls",
    )
    manual_items: list[str] = Field(
        description="Items requiring manual intervention",
    )
    estimated_effort_hours: float = Field(
        description="Total estimated remediation hours",
    )


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_INVENTORY_ANALYSIS = (
    "You are an infrastructure inventory analyst.\n"
    "Analyze the discovered systems and assess coverage:\n"
    "1. Identify platform distribution and exposure\n"
    "2. Flag systems missing from inventory\n"
    "3. Evaluate reachability and scan readiness\n"
    "4. Provide an executive summary for security teams"
)

SYSTEM_BENCHMARK_ANALYSIS = (
    "You are a CIS Benchmark compliance analyst.\n"
    "Analyze benchmark evaluation results:\n"
    "1. Calculate pass/fail rates per benchmark\n"
    "2. Identify the worst-performing controls\n"
    "3. Map failures to compliance frameworks\n"
    "4. Recommend prioritized hardening actions"
)

SYSTEM_DRIFT_ANALYSIS = (
    "You are a configuration drift detection specialist.\n"
    "Analyze detected configuration drifts:\n"
    "1. Classify drifts by severity and blast radius\n"
    "2. Identify root causes (manual change, deploy)\n"
    "3. Determine which drifts chain for elevated risk\n"
    "4. Recommend prevention and detection controls"
)

SYSTEM_REMEDIATION_PLANNING = (
    "You are a security remediation engineer.\n"
    "Plan remediation scripts for failing controls:\n"
    "1. Separate auto-fixable from manual items\n"
    "2. Sequence fixes to avoid breaking deps\n"
    "3. Estimate effort and risk reduction per fix\n"
    "4. Provide rollback guidance for each script"
)
