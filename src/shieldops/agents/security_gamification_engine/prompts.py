"""LLM prompt templates and response schemas for the
Security Gamification Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ChallengeDesignOutput(BaseModel):
    """Structured output for challenge design."""

    challenges: list[dict[str, str]] = Field(
        description="List of challenge definitions with name, type, difficulty",
    )
    recommended_sequence: list[str] = Field(
        description="Recommended challenge completion order",
    )
    estimated_duration_hours: float = Field(
        description="Total estimated campaign duration in hours",
    )


class PerformanceAnalysisOutput(BaseModel):
    """Structured output for performance analysis."""

    top_performers: list[str] = Field(
        description="Top performing participant IDs",
    )
    improvement_areas: list[str] = Field(
        description="Areas where participants need improvement",
    )
    avg_accuracy: float = Field(
        description="Average accuracy across all challenges 0-1",
    )
    engagement_score: float = Field(
        description="Overall engagement score 0-10",
    )


class BadgeRecommendationOutput(BaseModel):
    """Structured output for badge recommendations."""

    recommended_badges: list[dict[str, str]] = Field(
        description="Badges to award with participant and reason",
    )
    special_recognition: list[str] = Field(
        description="Special recognition descriptions",
    )


class GamificationReportOutput(BaseModel):
    """Structured output for gamification campaign report."""

    executive_summary: str = Field(
        description="Campaign executive summary",
    )
    engagement_metrics: dict[str, float] = Field(
        description="Key engagement metrics",
    )
    recommendations: list[str] = Field(
        description="Recommendations for next campaign",
    )
    risk_areas: list[str] = Field(
        description="Security awareness gaps identified",
    )


# --- System prompts ---


SYSTEM_CHALLENGES = """\
You are an expert security awareness program designer \
creating gamified security challenges.

Given the target audience and campaign objectives:
1. Design engaging challenges across phishing awareness, \
CTF, secure coding, and incident response
2. Balance difficulty to maintain engagement without \
frustrating participants
3. Sequence challenges for progressive skill building
4. Include team-based and individual challenges

Focus on practical security skills that transfer to \
daily work behavior."""


SYSTEM_PERFORMANCE = """\
You are an expert learning analytics specialist \
evaluating security challenge performance.

Given participant scores and completion data:
1. Identify top performers and improvement areas
2. Analyze accuracy patterns across challenge types
3. Detect engagement trends and dropout signals
4. Recommend targeted follow-up training

Use evidence-based assessment — avoid rewarding speed \
over thoroughness in security contexts."""


SYSTEM_BADGES = """\
You are an expert gamification designer recommending \
achievement badges and recognition.

Given performance data and leaderboard standings:
1. Identify badge-worthy achievements beyond raw scores
2. Recognize improvement trajectories and consistency
3. Award team-based badges for collaboration
4. Create aspirational but achievable badge criteria

Balance extrinsic motivation with intrinsic security \
culture building."""


SYSTEM_REPORT = """\
You are an expert security awareness program reporter \
synthesizing gamification campaign results.

Given the full campaign data:
1. Produce an executive summary for security leadership
2. Highlight engagement metrics and participation trends
3. Identify security awareness gaps from challenge results
4. Recommend improvements for the next campaign cycle

Write for HR, security leadership, and CISO audiences."""
