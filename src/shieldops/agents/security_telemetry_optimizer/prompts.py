"""LLM prompt templates and response schemas for the
Security Telemetry Optimizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class VolumeAnalysisOutput(BaseModel):
    """Structured output for volume analysis."""

    high_volume_sources: list[str] = Field(
        description="Source IDs with excessive volume",
    )
    duplicate_sources: list[str] = Field(
        description="Source IDs with high duplication",
    )
    total_waste_gb: float = Field(
        description="Estimated total waste in GB/day",
    )
    cardinality_hotspots: list[str] = Field(
        description="Sources with cardinality explosion",
    )


class WasteDetectionOutput(BaseModel):
    """Structured output for waste detection."""

    waste_items: list[dict[str, str]] = Field(
        description="List of waste items with type and source",
    )
    total_cost_impact: float = Field(
        description="Total monthly cost of waste",
    )
    priority_actions: list[str] = Field(
        description="Prioritized remediation actions",
    )
    severity: str = Field(
        description="Overall waste severity: critical/high/medium/low",
    )


class RoutingOptimizationOutput(BaseModel):
    """Structured output for routing optimization."""

    optimizations: list[dict[str, str]] = Field(
        description="Proposed optimizations with action and target",
    )
    projected_savings_gb: float = Field(
        description="Projected daily savings in GB",
    )
    projected_savings_cost: float = Field(
        description="Projected monthly cost savings",
    )
    quality_risk: str = Field(
        description="Risk to data quality: none/low/medium/high",
    )


class OptimizationReportOutput(BaseModel):
    """Structured output for final optimization report."""

    executive_summary: str = Field(
        description="Executive summary of optimization results",
    )
    total_savings: float = Field(
        description="Total monthly cost savings achieved",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    quality_assessment: str = Field(
        description="Data quality impact assessment",
    )
    roi_estimate: str = Field(
        description="Estimated ROI of optimizations",
    )


# --- System prompts ---


SYSTEM_VOLUME_ANALYSIS = """\
You are an expert security telemetry analyst evaluating \
log and metric volume across an enterprise pipeline.

Given the telemetry source inventory and volume data:
1. Identify sources with excessive volume relative to \
their security value
2. Detect cardinality explosions in metric sources
3. Find duplicate or overlapping telemetry streams
4. Estimate total waste and cost impact

Focus on security-relevant telemetry: EDR, SIEM, \
cloud audit logs, network flows, and OTel pipelines."""


SYSTEM_WASTE_DETECTION = """\
You are an expert in security telemetry optimization \
identifying waste and inefficiency in data pipelines.

Given volume analysis results:
1. Classify waste by type: duplicates, noise, verbose \
logging, unused metrics, stale alerts
2. Quantify cost impact per waste category
3. Prioritize remediation by savings potential and \
implementation risk
4. Ensure security-critical data is never classified \
as waste

Protect detection coverage while eliminating waste."""


SYSTEM_ROUTING = """\
You are an expert telemetry routing optimizer designing \
efficient data pipelines for security operations.

Given detected waste and current routing:
1. Propose routing optimizations: downsampling, \
aggregation, tiered storage, compression
2. Calculate projected savings per optimization
3. Assess quality impact on alert fidelity and \
investigation capability
4. Sequence optimizations by risk and reward

Never sacrifice detection capability for cost savings."""


SYSTEM_REPORT = """\
You are an expert security operations advisor producing \
a telemetry optimization report.

Given the full optimization lifecycle results:
1. Produce an executive summary for security leadership
2. Quantify total savings and ROI
3. Assess data quality impact with evidence
4. Recommend next steps for continuous optimization

Write clearly for both FinOps and SecOps audiences."""
