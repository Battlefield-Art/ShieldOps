"""Multi-Cloud Compliance Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field


class BenchmarkEvalOutput(BaseModel):
    """LLM output for benchmark evaluation."""

    summary: str = Field(description="Benchmark evaluation summary")
    compliance_rate: float = Field(description="Overall compliance rate 0-100")
    worst_areas: list[str] = Field(description="Worst compliance areas")
    recommendations: list[str] = Field(description="Top recommendations")


class GapAnalysisOutput(BaseModel):
    """LLM output for gap analysis."""

    summary: str = Field(description="Gap analysis summary")
    critical_gaps: int = Field(description="Number of critical gaps")
    cross_cloud_gaps: list[str] = Field(description="Gaps spanning multiple clouds")
    priority_order: list[str] = Field(description="Priority remediation order")


class ComplianceReportOutput(BaseModel):
    """LLM output for compliance reporting."""

    summary: str = Field(description="Executive compliance summary")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    regulatory_impact: list[str] = Field(description="Regulatory impact areas")
    action_items: list[str] = Field(description="Immediate action items")


SYSTEM_BENCHMARK_EVAL = (
    "You are a multi-cloud compliance analyst.\n"
    "Evaluate unified CIS benchmark compliance:\n"
    "1. Assess compliance rates per provider and framework\n"
    "2. Identify controls failing across multiple clouds\n"
    "3. Map gaps to regulatory requirements (SOC 2, PCI)\n"
    "4. Recommend prioritized remediation actions"
)

SYSTEM_GAP_ANALYSIS = (
    "You are a compliance gap analysis specialist.\n"
    "Identify and analyze compliance gaps:\n"
    "1. Detect cross-cloud compliance inconsistencies\n"
    "2. Categorize gaps by severity and effort\n"
    "3. Identify gaps with regulatory violation risk\n"
    "4. Create remediation roadmap by priority"
)

SYSTEM_COMPLIANCE_REPORT = (
    "You are a compliance reporting expert.\n"
    "Generate an executive compliance report:\n"
    "1. Summarize compliance posture across all clouds\n"
    "2. Highlight regulatory compliance status\n"
    "3. Identify highest-risk areas for board reporting\n"
    "4. Provide 30/60/90-day remediation timeline"
)
