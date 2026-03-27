"""MITRE Coverage Analyzer Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MappingAnalysisOutput(BaseModel):
    """LLM output for mapping detections to MITRE techniques."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g. T1566)",
    )
    technique_name: str = Field(
        description="MITRE ATT&CK technique name",
    )
    tactic: str = Field(
        description="MITRE ATT&CK tactic name",
    )
    coverage: str = Field(
        description="Coverage level: full, partial, or none",
    )
    confidence: float = Field(
        description="Confidence in mapping 0-1",
    )
    reasoning: str = Field(
        description="Why this detection maps to this technique",
    )


class GapAnalysisOutput(BaseModel):
    """LLM output for identifying coverage gaps."""

    high_risk_gaps: list[str] = Field(
        description="Technique IDs with highest risk from no coverage",
    )
    risk_rationale: str = Field(
        description="Rationale for risk prioritization",
    )
    quick_wins: list[str] = Field(
        description="Gaps that can be closed with existing data sources",
    )


class RuleRecommendationOutput(BaseModel):
    """LLM output for recommending detection rules."""

    rule_name: str = Field(
        description="Suggested detection rule name",
    )
    query_logic: str = Field(
        description="Detection query logic or pseudocode",
    )
    data_sources: list[str] = Field(
        description="Required data sources",
    )
    effort: str = Field(
        description="Implementation effort: low/medium/high",
    )
    priority: str = Field(
        description="Priority: critical/high/medium/low",
    )


class CoverageReportOutput(BaseModel):
    """LLM output for the final coverage report."""

    executive_summary: str = Field(
        description="Executive summary of MITRE coverage posture",
    )
    top_gaps: list[str] = Field(
        description="Top coverage gaps requiring attention",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )


SYSTEM_MAP_MITRE = (
    "You are a threat detection engineer mapping detection "
    "rules to MITRE ATT&CK techniques.\n"
    "For each detection rule:\n"
    "1. Identify the most relevant ATT&CK technique ID\n"
    "2. Determine the tactic category\n"
    "3. Assess coverage level (full/partial/none)\n"
    "4. Provide confidence score and reasoning"
)

SYSTEM_IDENTIFY_GAPS = (
    "You are a security coverage analyst identifying gaps "
    "in MITRE ATT&CK detection coverage.\n"
    "Given the current coverage matrix:\n"
    "1. Identify highest-risk uncovered techniques\n"
    "2. Prioritize by threat prevalence and impact\n"
    "3. Identify quick wins using existing data sources\n"
    "4. Consider the organization's threat profile"
)

SYSTEM_RECOMMEND_RULES = (
    "You are a detection engineering expert recommending "
    "new detection rules for uncovered ATT&CK techniques.\n"
    "For each gap:\n"
    "1. Suggest a specific detection rule with query logic\n"
    "2. List required data sources\n"
    "3. Estimate implementation effort\n"
    "4. Prioritize by risk reduction value"
)

SYSTEM_REPORT = (
    "You are a CISO advisor summarizing MITRE ATT&CK "
    "coverage analysis results.\n"
    "Produce an executive summary covering:\n"
    "1. Overall coverage percentage and trend\n"
    "2. Top gaps by risk and tactic\n"
    "3. Recommended actions with timeline\n"
    "4. Comparison to industry benchmarks"
)
