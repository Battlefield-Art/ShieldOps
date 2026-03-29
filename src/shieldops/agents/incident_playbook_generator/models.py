"""Incident Playbook Generator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PlaybookStage(StrEnum):
    ANALYZE_THREAT = "analyze_threat"
    MAP_TECHNIQUES = "map_techniques"
    DESIGN_WORKFLOW = "design_workflow"
    GENERATE_STEPS = "generate_steps"
    VALIDATE_PLAYBOOK = "validate_playbook"
    REPORT = "report"


class PlaybookType(StrEnum):
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    SUPPLY_CHAIN = "supply_chain"


class PlaybookComplexity(StrEnum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ADVANCED = "advanced"
    EXPERT = "expert"
    CUSTOM = "custom"


class IncidentPlaybookGeneratorState(BaseModel):
    request_id: str = ""
    stage: PlaybookStage = PlaybookStage.ANALYZE_THREAT
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
