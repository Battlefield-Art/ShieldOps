"""Detection Gap Finder Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BlindSpotAnalysisOutput(BaseModel):
    """LLM output for blind spot root cause analysis."""

    root_cause: str = Field(
        description="Root cause of detection failure",
    )
    missing_data_sources: list[str] = Field(
        description="Data sources needed for detection",
    )
    recommended_fix: str = Field(
        description="Recommended fix for the blind spot",
    )


class GapPriorityOutput(BaseModel):
    """LLM output for gap prioritization."""

    risk_score: float = Field(
        description="Risk score 0-10 for this gap",
    )
    exploitability: str = Field(
        description="Exploitability: trivial/moderate/difficult",
    )
    business_impact: str = Field(
        description="Business impact description",
    )
    remediation_effort: str = Field(
        description="Effort: low/medium/high",
    )


class GapReportOutput(BaseModel):
    """LLM output for the gap finder report."""

    executive_summary: str = Field(
        description="Executive summary of gap analysis",
    )
    critical_blind_spots: list[str] = Field(
        description="Most critical blind spots found",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )


SYSTEM_SELECT_TECHNIQUES = (
    "You are a red team operator selecting MITRE ATT&CK "
    "techniques for safe detection testing.\n"
    "Select techniques that:\n"
    "1. Are commonly used by active threat groups\n"
    "2. Cover multiple kill chain stages\n"
    "3. Can be safely simulated via log replay\n"
    "4. Represent the highest risk to the org"
)

SYSTEM_ANALYZE_BLIND_SPOTS = (
    "You are a detection engineer analyzing why a "
    "simulated attack was not detected.\n"
    "For each missed detection:\n"
    "1. Identify the root cause (missing rule, data "
    "source gap, logic flaw)\n"
    "2. List data sources needed for detection\n"
    "3. Recommend a specific fix\n"
    "4. Assess difficulty of remediation"
)

SYSTEM_PRIORITIZE_GAPS = (
    "You are a security risk analyst prioritizing "
    "detection gaps by organizational risk.\n"
    "For each gap:\n"
    "1. Score risk from 0-10\n"
    "2. Assess exploitability\n"
    "3. Estimate business impact\n"
    "4. Evaluate remediation effort"
)

SYSTEM_REPORT = (
    "You are a CISO advisor summarizing detection gap "
    "analysis results.\n"
    "Produce an executive summary covering:\n"
    "1. Overall detection rate and blind spots\n"
    "2. Most critical gaps by risk\n"
    "3. Root causes of detection failures\n"
    "4. Prioritized remediation roadmap"
)
