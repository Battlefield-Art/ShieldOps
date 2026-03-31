"""State models for the Security Gamification Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SGEStage(StrEnum):
    """Stages in the security gamification lifecycle."""

    DEFINE_CHALLENGES = "define_challenges"
    TRACK_PARTICIPATION = "track_participation"
    SCORE_PERFORMANCE = "score_performance"
    UPDATE_LEADERBOARD = "update_leaderboard"
    AWARD_BADGES = "award_badges"
    REPORT = "report"


class ChallengeType(StrEnum):
    """Types of security awareness challenges."""

    PHISHING_QUIZ = "phishing_quiz"
    CTF_CHALLENGE = "ctf_challenge"
    POLICY_REVIEW = "policy_review"
    INCIDENT_DRILL = "incident_drill"
    SECURE_CODING = "secure_coding"
    THREAT_HUNT = "threat_hunt"


class BadgeTier(StrEnum):
    """Badge tier classifications for achievements."""

    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"
    DIAMOND = "diamond"


# --- Domain models ---


class SecurityChallenge(BaseModel):
    """A security awareness challenge definition."""

    challenge_id: str = ""
    name: str = ""
    challenge_type: ChallengeType = ChallengeType.PHISHING_QUIZ
    difficulty: str = "medium"
    max_points: int = 100
    description: str = ""
    time_limit_minutes: int = 30
    prerequisites: list[str] = Field(default_factory=list)
    active: bool = True


class ParticipationRecord(BaseModel):
    """Record of user participation in a challenge."""

    participant_id: str = ""
    team: str = ""
    challenge_id: str = ""
    started_at: str = ""
    completed: bool = False
    time_spent_minutes: int = 0
    attempts: int = 0


class PerformanceScore(BaseModel):
    """Performance scoring for a completed challenge."""

    participant_id: str = ""
    challenge_id: str = ""
    points_earned: int = 0
    max_points: int = 100
    accuracy: float = 0.0
    speed_bonus: int = 0
    streak_multiplier: float = 1.0
    total_score: int = 0


class LeaderboardEntry(BaseModel):
    """Leaderboard entry for rankings."""

    rank: int = 0
    participant_id: str = ""
    team: str = ""
    total_points: int = 0
    challenges_completed: int = 0
    badges_earned: int = 0
    streak_days: int = 0
    tier: BadgeTier = BadgeTier.BRONZE


class BadgeAward(BaseModel):
    """Badge awarded for an achievement."""

    badge_id: str = ""
    name: str = ""
    tier: BadgeTier = BadgeTier.BRONZE
    description: str = ""
    awarded_to: str = ""
    awarded_for: str = ""
    points_value: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the gamification workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityGamificationEngineState(BaseModel):
    """Full state for a security gamification engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SGEStage = SGEStage.DEFINE_CHALLENGES

    # Inputs
    campaign_name: str = ""
    target_teams: list[str] = Field(default_factory=list)
    challenge_types: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    challenges: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    participation: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    leaderboard: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    badges: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_participants: int = 0
    avg_score: float = 0.0
    completion_rate: float = 0.0
    badges_awarded: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
