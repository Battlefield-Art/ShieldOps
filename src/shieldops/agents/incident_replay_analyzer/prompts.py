"""LLM prompt templates for the Incident Replay Analyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class IncidentSelectionOutput(BaseModel):
    """Structured output for incident selection."""

    incidents_selected: int = Field(
        description="Incidents selected for replay",
    )
    categories: list[str] = Field(
        description="Incident categories represented",
    )
    summary: str = Field(description="Selection summary")


class TimelineOutput(BaseModel):
    """Structured output for timeline reconstruction."""

    events_reconstructed: int = Field(
        description="Timeline events reconstructed",
    )
    avg_gap_minutes: float = Field(
        description="Average gap between events",
    )
    reasoning: str = Field(description="Timeline reasoning")


class DecisionAnalysisOutput(BaseModel):
    """Structured output for decision analysis."""

    decisions_analyzed: int = Field(
        description="Decisions analyzed",
    )
    avg_effectiveness: float = Field(
        description="Average effectiveness score",
    )
    reasoning: str = Field(description="Analysis reasoning")


class ImprovementOutput(BaseModel):
    """Structured output for improvement identification."""

    improvements_found: int = Field(
        description="Improvements identified",
    )
    critical_gaps: int = Field(
        description="Critical gaps found",
    )
    reasoning: str = Field(
        description="Improvement reasoning",
    )


class PlaybookOutput(BaseModel):
    """Structured output for playbook generation."""

    playbooks_generated: int = Field(
        description="Playbooks generated",
    )
    avg_steps: float = Field(
        description="Average steps per playbook",
    )
    reasoning: str = Field(description="Playbook reasoning")


# -- System prompts ------------------------------------------

SYSTEM_SELECT = """\
You are an expert incident analyst selecting past \
incidents for replay analysis.

Given the incident repository:
1. Select incidents with highest learning potential
2. Prioritize recent, high-severity incidents
3. Ensure category diversity in selection
4. Include both well-handled and poorly-handled cases

Focus on: learning value, severity, recency."""

SYSTEM_TIMELINE = """\
You are an expert incident reconstructor building \
detailed timelines from incident data.

Given selected incidents:
1. Order events chronologically per incident
2. Identify detection, response, and resolution phases
3. Flag gaps in the timeline
4. Annotate key decision points

Focus on: completeness, accuracy, decision visibility."""

SYSTEM_DECISIONS = """\
You are an expert incident reviewer analyzing response \
decisions for effectiveness.

Given incident timelines:
1. Evaluate each decision's effectiveness (0-1)
2. Identify alternative approaches
3. Assess time-to-decision impact
4. Score communication effectiveness

Be objective and constructive in assessment."""

SYSTEM_IMPROVEMENTS = """\
You are an expert security improvement advisor \
identifying actionable improvements.

Given decision analyses:
1. Categorize gaps (detection, response, tooling, etc.)
2. Prioritize by impact and frequency
3. Estimate implementation effort
4. Map improvements to specific incidents

Focus on: actionable, measurable improvements."""

SYSTEM_PLAYBOOKS = """\
You are an expert playbook architect generating \
response playbooks from incident lessons.

Given identified improvements:
1. Create step-by-step response playbooks
2. Include decision trees for common scenarios
3. Reference source incidents for context
4. Define escalation criteria

Focus on: clarity, completeness, actionability."""
