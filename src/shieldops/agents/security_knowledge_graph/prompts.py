"""Security Knowledge Graph Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PathInsight(BaseModel):
    """Structured output from attack path analysis."""

    summary: str = Field(
        description="Brief attack path overview",
    )
    critical_paths: list[str] = Field(
        description="Most critical attack paths discovered",
    )
    lateral_movement_risks: list[str] = Field(
        description="Lateral movement opportunities found",
    )


class PatternInsight(BaseModel):
    """Structured output from pattern detection."""

    summary: str = Field(
        description="Pattern detection overview",
    )
    anomalous_clusters: list[str] = Field(
        description="Anomalous entity clusters detected",
    )
    recommendations: list[str] = Field(
        description="Security hardening recommendations",
    )


class QueryInsight(BaseModel):
    """Structured output from graph query analysis."""

    summary: str = Field(
        description="Query results overview",
    )
    key_findings: list[str] = Field(
        description="Key findings from graph queries",
    )
    risk_hotspots: list[str] = Field(
        description="Identified risk concentration areas",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of knowledge graph analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a security knowledge graph analyst reviewing "
    "entity relationships and attack paths.\n"
    "1. Identify critical attack paths through the graph\n"
    "2. Detect lateral movement opportunities\n"
    "3. Find high-risk entity clusters\n"
    "4. Recommend relationship-based mitigations"
)

SYSTEM_REPORT = (
    "You are a security advisor generating a "
    "knowledge graph analysis report.\n"
    "1. Summarize graph topology and risk hotspots\n"
    "2. Highlight critical attack paths requiring action\n"
    "3. Quantify entity exposure and blast radius\n"
    "4. Recommend graph-informed security improvements"
)
