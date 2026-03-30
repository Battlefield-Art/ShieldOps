"""State models for the Postmortem Generator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PMGStage(StrEnum):
    """Stages in the postmortem workflow."""

    COLLECT_TIMELINE = "collect_timeline"
    ANALYZE_ROOT_CAUSE = "analyze_root_cause"
    IDENTIFY_ACTIONS = "identify_actions"
    DRAFT_DOCUMENT = "draft_document"
    REVIEW_QUALITY = "review_quality"
    REPORT = "report"


class IncidentCategory(StrEnum):
    """Incident category for postmortem."""

    AVAILABILITY = "availability"
    SECURITY = "security"
    PERFORMANCE = "performance"
    DATA_INTEGRITY = "data_integrity"
    COMPLIANCE = "compliance"
    CONFIGURATION = "configuration"


class ActionPriority(StrEnum):
    """Action item priority levels."""

    P0_IMMEDIATE = "p0_immediate"
    P1_WEEK = "p1_week"
    P2_SPRINT = "p2_sprint"
    P3_QUARTER = "p3_quarter"
    P4_BACKLOG = "p4_backlog"


class PostmortemGeneratorState(BaseModel):
    """Full state for the postmortem generator workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PMGStage = PMGStage.COLLECT_TIMELINE

    incident_id: str = ""
    incident_title: str = ""
    incident_severity: str = ""
    incident_description: str = ""
    affected_services: list[str] = Field(
        default_factory=list,
    )
    resolution_summary: str = ""

    timeline_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    root_cause_analysis: dict[str, Any] = Field(
        default_factory=dict,
    )
    action_items: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    document_draft: dict[str, Any] = Field(
        default_factory=dict,
    )
    quality_review: dict[str, Any] = Field(
        default_factory=dict,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    current_step: str = ""
    error: str = ""
