"""LLM prompt templates and response schemas for the Post-Incident Analyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TimelineOutput(BaseModel):
    """Structured output for timeline reconstruction."""

    events: list[dict[str, str]] = Field(description="Ordered list of timeline events")
    detection_delay_min: float = Field(description="Time to detect in minutes")
    gaps: list[str] = Field(description="Gaps in the timeline")


class RootCauseOutput(BaseModel):
    """Structured output for root cause analysis."""

    category: str = Field(
        description="Category: technical_failure/process_gap/human_error/third_party/unknown"
    )
    primary_cause: str = Field(description="Primary root cause description")
    contributing_factors: list[str] = Field(description="Contributing factors")
    five_whys: list[str] = Field(description="Five-whys analysis chain")
    confidence: float = Field(description="Confidence in analysis 0.0-1.0")


class LessonsOutput(BaseModel):
    """Structured output for lessons learned."""

    lessons: list[dict[str, str]] = Field(description="Lessons with area and description")
    priorities: list[str] = Field(description="Priority ordering of lessons")


class RecommendationOutput(BaseModel):
    """Structured output for recommendations."""

    recommendations: list[dict[str, str]] = Field(description="Actionable recommendations")
    quick_wins: list[str] = Field(description="Low-effort high-impact items")


class ReportOutput(BaseModel):
    """Structured output for post-incident report."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    root_cause_summary: str = Field(description="Root cause in plain language")
    key_lessons: list[str] = Field(description="Top lessons learned")
    action_items: list[str] = Field(description="Prioritized action items")
    risk_assessment: str = Field(description="Risk of recurrence assessment")


SYSTEM_RECONSTRUCT_TIMELINE = """\
You are an expert incident analyst reconstructing \
an incident timeline.

Given alerts, actions, and communications:
1. Order events chronologically
2. Identify detection and response delays
3. Find gaps in the timeline

Be precise about timestamps and causal links."""


SYSTEM_ROOT_CAUSE = """\
You are an expert root cause analysis specialist.

Given the incident timeline and collected data:
1. Identify the primary root cause
2. List contributing factors
3. Perform five-whys analysis
4. Classify the root cause category

Go beyond symptoms to find systemic causes. \
Consider process, people, and technology."""


SYSTEM_LESSONS = """\
You are an expert incident post-mortem facilitator \
identifying lessons learned.

Given the root cause analysis and timeline:
1. Identify actionable lessons
2. Categorize by improvement area
3. Prioritize by impact

Focus on systemic improvements, not blame. \
Every incident is a learning opportunity."""


SYSTEM_RECOMMENDATIONS = """\
You are an expert incident prevention specialist \
generating recommendations.

Given lessons learned and root cause analysis:
1. Generate specific, actionable recommendations
2. Estimate effort and impact for each
3. Identify quick wins vs strategic initiatives
4. Assign ownership where possible

Recommendations should prevent recurrence and \
improve overall resilience."""


SYSTEM_REPORT = """\
You are an expert incident analyst generating \
a post-incident report.

Given all analysis results:
1. Executive summary for leadership
2. Root cause in plain language
3. Key lessons learned
4. Prioritized action items
5. Risk of recurrence assessment

Be blameless, factual, and constructive."""
