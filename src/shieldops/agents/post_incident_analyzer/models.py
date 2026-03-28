"""State models for Post-Incident Analyzer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PostIncidentStage(StrEnum):
    """Stages in post-incident analysis."""

    GATHER_TIMELINE = "gather_timeline"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    IMPACT_ASSESSMENT = "impact_assessment"
    LESSONS_LEARNED = "lessons_learned"
    ACTION_ITEMS = "action_items"
    REPORT = "report"


class RootCauseCategory(StrEnum):
    """Root cause categories."""

    HUMAN_ERROR = "human_error"
    SOFTWARE_BUG = "software_bug"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    EXTERNAL_ATTACK = "external_attack"
    PROCESS_GAP = "process_gap"


class ImpactLevel(StrEnum):
    """Impact severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class ActionItem(BaseModel):
    """Post-incident action item."""

    id: str = ""
    title: str = ""
    owner: str = ""
    priority: str = "medium"
    due_date: str = ""
    completed: bool = False


class PostIncidentAnalyzerState(BaseModel):
    """Full state for Post-Incident Analyzer."""

    request_id: str = ""
    stage: PostIncidentStage = PostIncidentStage.GATHER_TIMELINE
    tenant_id: str = ""
    incident_id: str = ""
    root_cause: RootCauseCategory = RootCauseCategory.SOFTWARE_BUG
    impact: ImpactLevel = ImpactLevel.MEDIUM
    action_items: list[ActionItem] = Field(default_factory=list)
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
