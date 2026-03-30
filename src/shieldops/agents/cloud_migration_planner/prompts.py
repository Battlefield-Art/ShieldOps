"""Cloud Migration Planner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ReadinessInsight(BaseModel):
    """Structured output from readiness assessment."""

    summary: str = Field(
        description="Brief readiness overview",
    )
    blockers: list[str] = Field(
        description="Critical migration blockers",
    )
    quick_wins: list[str] = Field(
        description="Workloads ready for immediate migration",
    )


class MigrationInsight(BaseModel):
    """Structured output from migration planning."""

    summary: str = Field(
        description="Migration plan overview",
    )
    risk_areas: list[str] = Field(
        description="High-risk migration areas",
    )
    cost_drivers: list[str] = Field(
        description="Primary cost drivers in the plan",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive migration summary",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ASSESS = (
    "You are a cloud migration architect reviewing "
    "workload readiness.\n"
    "1. Evaluate each workload migration readiness\n"
    "2. Identify blockers and dependencies\n"
    "3. Recommend the best migration strategy\n"
    "4. Assess risk levels for each workload"
)

SYSTEM_REPORT = (
    "You are a cloud migration advisor generating "
    "an executive migration report.\n"
    "1. Summarize total workloads and readiness\n"
    "2. Highlight highest-risk migrations\n"
    "3. Quantify estimated cost and timeline\n"
    "4. Recommend next steps for the migration"
)
