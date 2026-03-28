"""LLM prompts and schemas for Purple Team Orchestrator."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class ExercisePlanOutput(BaseModel):
    """LLM output for exercise planning."""

    name: str = Field(description="Exercise name")
    objectives: list[str] = Field(description="Exercise objectives")
    attack_scenarios: list[str] = Field(description="Attack scenarios to execute")
    expected_detections: list[str] = Field(description="Expected blue team detections")


class DetectionAnalysisOutput(BaseModel):
    """LLM output for detection analysis."""

    coverage_pct: float = Field(description="Detection coverage percentage")
    missed_attacks: list[str] = Field(description="Attacks not detected")
    false_positives: list[str] = Field(description="False positive detections")
    recommendations: list[str] = Field(description="Detection improvement recs")


class ExerciseReportOutput(BaseModel):
    """LLM output for exercise report."""

    executive_summary: str = Field(description="Executive summary")
    red_team_grade: str = Field(description="Red team grade A-F")
    blue_team_grade: str = Field(description="Blue team grade A-F")
    top_recommendations: list[str] = Field(description="Top recommendations")
    gaps_identified: list[dict[str, Any]] = Field(description="Security gaps found")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_EXERCISE_PLAN = """\
You are an expert purple team exercise planner. Design \
a coordinated red+blue exercise with specific attack \
scenarios, expected detections, and success criteria.

Include MITRE ATT&CK technique IDs and map each \
attack to expected detection rules."""

SYSTEM_DETECTION_ANALYSIS = """\
You are a detection engineering analyst reviewing \
blue team performance during a purple team exercise.

Analyze detection coverage, identify missed attacks, \
flag false positives, and recommend improvements to \
detection rules and response procedures."""

SYSTEM_EXERCISE_REPORT = """\
You are a senior security consultant writing the final \
purple team exercise report. Grade both red and blue \
teams, identify critical gaps, and provide actionable \
recommendations.

Be balanced: acknowledge what worked and what needs \
improvement on both sides."""
