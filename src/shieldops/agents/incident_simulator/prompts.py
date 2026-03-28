"""LLM prompt templates and response schemas for the Incident Simulator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExerciseDesignOutput(BaseModel):
    """Structured output for exercise design."""

    name: str = Field(description="Exercise name")
    objectives: list[str] = Field(description="Exercise objectives")
    injects_planned: int = Field(description="Number of planned injects")
    duration_min: int = Field(description="Estimated duration in minutes")
    success_criteria: dict[str, str] = Field(description="Success criteria per objective")


class ScenarioOutput(BaseModel):
    """Structured output for scenario injection."""

    title: str = Field(description="Inject scenario title")
    description: str = Field(description="Detailed scenario description")
    expected_response: str = Field(description="Expected response from team")
    severity: str = Field(description="Inject severity level")
    target_role: str = Field(description="Primary role being tested")


class ObservationOutput(BaseModel):
    """Structured output for response observation."""

    communication_quality: str = Field(description="Quality: excellent/good/adequate/poor")
    decision_quality: str = Field(description="Quality: excellent/good/adequate/poor")
    notes: str = Field(description="Observer notes on response")


class ReadinessOutput(BaseModel):
    """Structured output for readiness scoring."""

    overall_score: float = Field(description="Overall readiness 0.0-100.0")
    grade: str = Field(description="Grade: A/B/C/D/F")
    strengths: list[str] = Field(description="Team strengths identified")
    gaps: list[str] = Field(description="Gaps and weaknesses")
    recommendations: list[str] = Field(description="Improvement recommendations")


class ReportOutput(BaseModel):
    """Structured output for simulation report."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    exercises_completed: int = Field(description="Number of exercises run")
    overall_readiness: str = Field(description="Overall readiness assessment")
    key_findings: list[str] = Field(description="Key findings from simulation")
    action_items: list[str] = Field(description="Recommended action items")


SYSTEM_DESIGN_EXERCISE = """\
You are an expert incident simulation designer.

Given the scenario parameters and team composition:
1. Design exercise objectives
2. Plan inject sequence and timing
3. Define success criteria
4. Set appropriate scope and duration

Design exercises that test realistic scenarios \
without overwhelming participants."""


SYSTEM_INJECT_SCENARIO = """\
You are an expert incident simulation facilitator \
injecting scenarios.

Given the exercise design and current state:
1. Craft a realistic scenario inject
2. Define expected team response
3. Set appropriate severity
4. Target specific roles for testing

Make injects progressively challenging. \
Each should test a different capability."""


SYSTEM_OBSERVE = """\
You are an expert exercise observer evaluating \
team response.

Given the inject and team actions:
1. Assess communication quality
2. Evaluate decision quality
3. Note coordination effectiveness
4. Identify gaps in response

Be objective and constructive in observations."""


SYSTEM_SCORE_READINESS = """\
You are an expert readiness assessor scoring \
team performance.

Given all observations and measurements:
1. Calculate overall readiness score (0-100)
2. Assign letter grade (A/B/C/D/F)
3. Identify team strengths
4. Highlight gaps and weaknesses
5. Recommend targeted improvements

Score fairly against industry standards."""


SYSTEM_REPORT = """\
You are an expert simulation analyst generating \
an exercise report.

Given all exercise results:
1. Executive summary for leadership
2. Readiness assessment
3. Key findings and observations
4. Prioritized action items

Focus on actionable improvements and recognize \
team strengths."""
