"""LLM prompt templates and response schemas for the
Security Asset Graph Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DependencyMappingOutput(BaseModel):
    """Structured output for dependency mapping."""

    dependencies: list[dict[str, str]] = Field(
        description="Mapped dependency edges with source, target, type",
    )
    hidden_dependencies: list[str] = Field(
        description="Inferred hidden dependencies not in CMDB",
    )
    circular_dependencies: list[str] = Field(
        description="Detected circular dependency chains",
    )
    confidence: float = Field(
        description="Overall confidence in mapping 0-1",
    )


class ImpactAnalysisOutput(BaseModel):
    """Structured output for blast radius analysis."""

    blast_radius: int = Field(
        description="Number of affected assets",
    )
    cascading_failures: list[str] = Field(
        description="Cascading failure chains identified",
    )
    risk_score: float = Field(
        description="Impact risk score 0-10",
    )
    summary: str = Field(
        description="Impact analysis summary",
    )


class CriticalPathOutput(BaseModel):
    """Structured output for critical path identification."""

    validated: bool = Field(
        description="Whether the path is truly critical",
    )
    single_points_of_failure: list[str] = Field(
        description="Single points of failure in the path",
    )
    redundancy_score: float = Field(
        description="Path redundancy score 0-1",
    )
    mitigation: str = Field(
        description="Recommended mitigation for the path",
    )
    affected_services: list[str] = Field(
        description="Business services affected by path failure",
    )


class AssetGraphReportOutput(BaseModel):
    """Structured output for final asset graph report."""

    executive_summary: str = Field(
        description="Executive summary of asset graph analysis",
    )
    top_risks: list[str] = Field(
        description="Top risk findings from the graph",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    resilience_rating: str = Field(
        description="Infrastructure resilience: high/medium/low",
    )


# --- System prompts ---


SYSTEM_DEPENDENCIES = """\
You are an expert infrastructure analyst mapping asset \
dependencies across enterprise environments.

Given discovered assets and their configurations:
1. Map explicit dependencies from configuration data
2. Infer implicit dependencies from network traffic
3. Detect circular dependency chains that cause cascading \
failures
4. Identify hidden dependencies not tracked in CMDB

Completeness matters: unmapped dependencies are invisible \
blast radius."""


SYSTEM_IMPACT = """\
You are an expert resilience engineer analyzing blast \
radius for asset failures.

Given the asset dependency graph and a target asset:
1. Calculate full cascading failure impact
2. Identify secondary and tertiary failure chains
3. Estimate recovery time based on dependency depth
4. Score impact severity for incident prioritization

Assume worst-case propagation for critical assets."""


SYSTEM_CRITICAL_PATH = """\
You are an expert availability engineer identifying \
critical dependency paths in infrastructure.

Given the full dependency graph and impact analyses:
1. Identify single points of failure across all paths
2. Validate that paths are truly critical (not redundant)
3. Score redundancy and resilience for each path
4. Recommend mitigation for high-risk paths

Focus on paths that affect revenue-critical services."""


SYSTEM_REPORT = """\
You are an expert security architect synthesizing asset \
graph analysis results.

Given the full graph analysis (assets, dependencies, \
impact, critical paths, risk scores):
1. Produce an executive summary for security leadership
2. Prioritize risks by business impact
3. Recommend resilience improvements
4. Rate overall infrastructure resilience

Write for both technical and executive audiences."""
