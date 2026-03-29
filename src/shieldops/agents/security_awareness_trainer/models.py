"""State models for the Security Awareness Trainer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SATStage(StrEnum):
    """Stages of the security awareness workflow."""

    ASSESS_BASELINE = "assess_baseline"
    DESIGN_CAMPAIGN = "design_campaign"
    GENERATE_CONTENT = "generate_content"
    DELIVER_TRAINING = "deliver_training"
    MEASURE_EFFECTIVENESS = "measure_effectiveness"
    REPORT = "report"


class TrainingTopic(StrEnum):
    """Security awareness training topics."""

    PHISHING = "phishing"
    PASSWORD_HYGIENE = "password_hygiene"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_HANDLING = "data_handling"
    PHYSICAL_SECURITY = "physical_security"
    INCIDENT_REPORTING = "incident_reporting"


class CompetencyLevel(StrEnum):
    """Employee competency levels for security."""

    EXPERT = "expert"
    PROFICIENT = "proficient"
    COMPETENT = "competent"
    DEVELOPING = "developing"
    NOVICE = "novice"


class SecurityAwarenessTrainerState(BaseModel):
    """Full state for security awareness workflow."""

    request_id: str = ""
    stage: SATStage = SATStage.ASSESS_BASELINE
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
