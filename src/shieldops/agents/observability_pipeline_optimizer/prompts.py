"""Observability Pipeline Optimizer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CardinalityInsight(BaseModel):
    """Structured output from cardinality analysis."""

    summary: str = Field(
        description="Brief cardinality overview",
    )
    hotspots: list[str] = Field(
        description="Top cardinality explosion risks",
    )
    recommendations: list[str] = Field(
        description="Cardinality reduction strategies",
    )


class SamplingInsight(BaseModel):
    """Structured output from sampling optimization."""

    summary: str = Field(
        description="Sampling optimization overview",
    )
    strategies: list[str] = Field(
        description="Recommended sampling strategies",
    )
    quality_tradeoffs: list[str] = Field(
        description="Quality tradeoff considerations",
    )


class CostInsight(BaseModel):
    """Structured output from cost reduction analysis."""

    summary: str = Field(
        description="Cost reduction overview",
    )
    quick_wins: list[str] = Field(
        description="Immediate cost reduction actions",
    )
    long_term: list[str] = Field(
        description="Long-term cost optimization ideas",
    )


class ReportInsight(BaseModel):
    """Structured output for the final report."""

    summary: str = Field(
        description="Executive summary of pipeline optimization",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_CARDINALITY = (
    "You are an observability engineer analyzing "
    "metric cardinality across telemetry pipelines.\n"
    "1. Identify metrics with unbounded label growth\n"
    "2. Flag series counts that risk storage blowout\n"
    "3. Recommend label dropping or aggregation\n"
    "4. Prioritize by cost and blast-radius impact"
)

SYSTEM_SAMPLING = (
    "You are a telemetry optimization specialist "
    "designing sampling strategies.\n"
    "1. Recommend tail sampling for traces\n"
    "2. Suggest log downsampling for verbose sources\n"
    "3. Balance signal fidelity vs cost savings\n"
    "4. Ensure error and slow-path traces are kept"
)

SYSTEM_COST = (
    "You are a FinOps analyst focused on "
    "observability pipeline costs.\n"
    "1. Identify highest-cost ingestion pipelines\n"
    "2. Compare vendor pricing per GB ingested\n"
    "3. Recommend tier downgrades or vendor switches\n"
    "4. Quantify savings from each optimization"
)

SYSTEM_REPORT = (
    "You are an observability platform advisor "
    "generating an executive optimization report.\n"
    "1. Summarize total pipeline cost and savings\n"
    "2. Highlight cardinality and sampling wins\n"
    "3. Quantify ROI of proposed optimizations\n"
    "4. Recommend next steps for telemetry governance"
)
