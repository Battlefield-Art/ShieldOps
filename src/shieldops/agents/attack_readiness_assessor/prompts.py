"""Attack Readiness Assessor Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PreventionAnalysisOutput(BaseModel):
    """LLM output for prevention assessment."""

    score: float = Field(
        description="Prevention score 0-100",
    )
    controls_in_place: list[str] = Field(
        description="Controls that prevent this attack",
    )
    controls_missing: list[str] = Field(
        description="Missing prevention controls",
    )
    effectiveness: str = Field(
        description="Overall prevention effectiveness",
    )


class DetectionAnalysisOutput(BaseModel):
    """LLM output for detection assessment."""

    score: float = Field(
        description="Detection score 0-100",
    )
    coverage_pct: float = Field(
        description="Detection coverage percentage",
    )
    gaps: list[str] = Field(
        description="Detection gaps for this scenario",
    )
    mean_time_to_detect: str = Field(
        description="Estimated MTTD",
    )


class ResponseAnalysisOutput(BaseModel):
    """LLM output for response assessment."""

    score: float = Field(
        description="Response score 0-100",
    )
    automation_level: str = Field(
        description="Automation: none/partial/full",
    )
    gaps: list[str] = Field(
        description="Response capability gaps",
    )
    mean_time_to_respond: str = Field(
        description="Estimated MTTR",
    )


class ReadinessReportOutput(BaseModel):
    """LLM output for readiness report."""

    executive_summary: str = Field(
        description="Executive readiness summary",
    )
    scenario_summaries: list[str] = Field(
        description="Per-scenario readiness summaries",
    )
    critical_gaps: list[str] = Field(
        description="Most critical readiness gaps",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )


SYSTEM_ASSESS_PREVENTION = (
    "You are a security architect assessing prevention "
    "capabilities against a specific attack scenario.\n"
    "Evaluate:\n"
    "1. Which controls prevent this attack type\n"
    "2. Which controls are missing\n"
    "3. Overall prevention effectiveness\n"
    "4. Score from 0-100"
)

SYSTEM_ASSESS_DETECTION = (
    "You are a SOC analyst assessing detection "
    "capabilities against a specific attack scenario.\n"
    "Evaluate:\n"
    "1. Detection rule coverage for this attack\n"
    "2. Mean time to detect\n"
    "3. Detection gaps and blind spots\n"
    "4. Score from 0-100"
)

SYSTEM_ASSESS_RESPONSE = (
    "You are an incident responder assessing response "
    "capabilities against a specific attack scenario.\n"
    "Evaluate:\n"
    "1. Runbook existence and quality\n"
    "2. Automation level\n"
    "3. Mean time to respond\n"
    "4. Response capability gaps"
)

SYSTEM_REPORT = (
    "You are a CISO writing an attack readiness "
    "assessment report.\n"
    "Produce an executive summary covering:\n"
    "1. Overall readiness posture\n"
    "2. Per-scenario readiness levels\n"
    "3. Critical gaps requiring investment\n"
    "4. Prioritized improvement roadmap"
)
